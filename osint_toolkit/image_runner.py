from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .adapter_runner import format_command
from .engine import Finding, ScanTarget
from .entities import entities_from_findings, entities_from_targets, merge_entities
from .graph import graph_edges_from_case
from .investigation import InvestigationResult, render_investigation_markdown, run_investigation
from .search import LOCAL_TOOLS, SearchPlan, build_search_plan, classify_target, ready_adapter_repositories


@dataclass(frozen=True)
class ImageSearchExecution:
    investigation: InvestigationResult
    executed_local_tools: tuple[str, ...]
    derived_targets: tuple[ScanTarget, ...]
    executed_adapters: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "executed_local_tools": list(self.executed_local_tools),
            "derived_targets": [
                {"kind": target.kind, "value": target.value, "region": target.region}
                for target in self.derived_targets
            ],
            "executed_adapters": list(self.executed_adapters),
            "investigation": self.investigation.to_dict(),
        }


@dataclass(frozen=True)
class DerivedSeed:
    kind: str
    value: str
    source: str


def run_image_search(
    plan: SearchPlan,
    *,
    timeout: float = 60.0,
    adapter_timeout: float = 60.0,
    adapter_limit: int | None = 20,
    derived_limit: int = 20,
) -> ImageSearchExecution:
    if plan.target.kind != "image":
        raise ValueError("Image search execution requires an image target.")

    image_path = Path(plan.target.value)
    if not image_path.exists() or not image_path.is_file():
        raise ValueError(f"Image file does not exist: {plan.target.value}")

    local_findings, derived_seeds, executed_local_tools = _run_local_image_tools(plan, timeout=timeout)
    derived_targets = _derived_targets(derived_seeds, region=plan.target.region, limit=derived_limit)
    executable_adapters = _ready_adapters_for_targets(derived_targets, adapter_limit=adapter_limit)

    derived_result = None
    if derived_targets:
        derived_result = run_investigation(
            derived_targets,
            title=f"Derived image seeds: {plan.target.value}",
            live=False,
            include_adapters=bool(executable_adapters),
            execute_adapters=bool(executable_adapters),
            allow_restricted_adapters=False,
            adapter_timeout=adapter_timeout,
            adapter_limit=adapter_limit,
            adapter_repositories=executable_adapters,
        )

    targets = (plan.target, *(derived_result.targets if derived_result else ()))
    findings = (*local_findings, *(derived_result.findings if derived_result else ()))
    adapter_findings = derived_result.adapter_findings if derived_result else ()
    entities = merge_entities(
        entities_from_targets(targets),
        entities_from_findings(findings),
        entities_from_findings(adapter_findings),
    )
    edges = graph_edges_from_case(targets, (*findings, *adapter_findings), entities)

    investigation = InvestigationResult(
        title=f"Unified image search: {plan.target.value}",
        targets=targets,
        findings=findings,
        adapter_findings=adapter_findings,
        entities=entities,
        edges=edges,
        generated_at=datetime.now().astimezone().isoformat(timespec="seconds"),
    )
    return ImageSearchExecution(
        investigation=investigation,
        executed_local_tools=executed_local_tools,
        derived_targets=derived_targets,
        executed_adapters=executable_adapters,
    )


def render_image_search_execution(
    plan: SearchPlan,
    execution: ImageSearchExecution,
    *,
    output_format: str,
) -> str:
    if output_format == "json":
        import json

        return json.dumps(
            {
                "search_plan": plan.to_dict(),
                **execution.to_dict(),
            },
            ensure_ascii=False,
            indent=2,
        )

    local_lines = "\n".join(f"- `{tool}`" for tool in execution.executed_local_tools) or "- none"
    derived_lines = (
        "\n".join(f"- `{target.kind}:{target.value}`" for target in execution.derived_targets)
        or "- none"
    )
    adapter_lines = "\n".join(f"- `{repository}`" for repository in execution.executed_adapters) or "- none"
    return "\n".join(
        [
            "# Search Execution Report: image",
            "",
            f"- Target: `{plan.target.value}`",
            f"- Profile: `{plan.profile.name}`",
            "- Face recognition: disabled",
            "",
            "## Executed Local Tools",
            "",
            local_lines,
            "",
            "## Derived Seeds",
            "",
            derived_lines,
            "",
            "## Executed Adapters For Derived Seeds",
            "",
            adapter_lines,
            "",
            "## Investigation Report",
            "",
            render_investigation_markdown(execution.investigation).strip(),
            "",
        ]
    )


def _run_local_image_tools(
    plan: SearchPlan,
    *,
    timeout: float,
) -> tuple[tuple[Finding, ...], tuple[DerivedSeed, ...], tuple[str, ...]]:
    tools_by_name = {tool.name: tool for tool in LOCAL_TOOLS}
    findings: list[Finding] = []
    derived: list[DerivedSeed] = []
    executed: list[str] = []
    for step in plan.steps:
        if step.stage != "local-tool":
            continue
        tool = tools_by_name[step.source]
        command = tool.render_command(plan.target)
        command_text = format_command(command)
        executable = shutil.which(command[0])
        if not executable:
            findings.append(
                Finding(
                    module="local-image-tool",
                    source=tool.name,
                    target=plan.target.value,
                    status="missing",
                    confidence="high",
                    evidence=tool.install_note,
                    metadata={"command": command_text, "executable": command[0]},
                )
            )
            continue
        try:
            result = subprocess.run(
                [executable, *command[1:]],
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            findings.append(
                Finding(
                    module="local-image-tool",
                    source=tool.name,
                    target=plan.target.value,
                    status="timeout",
                    confidence="low",
                    evidence=f"Local image tool timed out after {timeout} seconds.",
                    metadata={
                        "command": command_text,
                        "stdout": _truncate(_redact(exc.stdout)),
                        "stderr": _truncate(_redact(exc.stderr)),
                    },
                )
            )
            continue
        except OSError as exc:
            findings.append(
                Finding(
                    module="local-image-tool",
                    source=tool.name,
                    target=plan.target.value,
                    status="error",
                    confidence="low",
                    evidence=f"Local image tool failed: {exc}",
                    metadata={"command": command_text},
                )
            )
            continue

        executed.append(tool.name)
        output = _join_output(result.stdout, result.stderr)
        status = "completed" if result.returncode == 0 else "error"
        evidence = _truncate(output) or f"Exit code {result.returncode}"
        findings.append(
            Finding(
                module="local-image-tool",
                source=tool.name,
                target=plan.target.value,
                status=status,
                confidence="medium" if status == "completed" else "low",
                evidence=evidence,
                metadata={
                    "command": command_text,
                    "returncode": str(result.returncode),
                },
            )
        )
        parsed_findings, parsed_seeds = _parse_local_tool_output(tool.name, plan.target, output)
        findings.extend(parsed_findings)
        seeds = _dedupe_seeds((*_extract_derived_seeds(output, source=tool.name), *parsed_seeds))
        derived.extend(seeds)
        findings.extend(_derived_seed_findings(plan.target, seeds))
    return tuple(findings), _dedupe_seeds(tuple(derived)), tuple(executed)


def _derived_seed_findings(target: ScanTarget, seeds: tuple[DerivedSeed, ...]) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for seed in seeds:
        metadata_key = {
            "url": "external_url",
            "domain": "domain",
            "email": "email",
            "phone": "phone",
            "username": "username",
            "telegram": "external_url",
            "instagram": "external_url",
            "social": "social_profile",
        }.get(seed.kind, seed.kind)
        findings.append(
            Finding(
                module="local-image-parser",
                source=seed.source,
                target=target.value,
                status="candidate",
                confidence="low",
                evidence=f"Derived {seed.kind} seed from image output: {seed.value}",
                metadata={metadata_key: seed.value},
            )
        )
    return tuple(findings)


def _extract_derived_seeds(text: str, *, source: str) -> tuple[DerivedSeed, ...]:
    seeds: list[DerivedSeed] = []
    for url in _urls(text):
        seeds.append(DerivedSeed(kind=classify_target(url), value=url, source=source))
        domain = _domain_from_url(url)
        if domain:
            seeds.append(DerivedSeed(kind="domain", value=domain, source=source))
    for email in _emails(text):
        seeds.append(DerivedSeed(kind="email", value=email, source=source))
    for phone in _phones(text):
        seeds.append(DerivedSeed(kind="phone", value=phone, source=source))
    for handle in _handles(text):
        seeds.append(DerivedSeed(kind="username", value=handle, source=source))
    for domain in _domains(text):
        seeds.append(DerivedSeed(kind="domain", value=domain, source=source))
    return _dedupe_seeds(tuple(seeds))


def _parse_local_tool_output(
    tool_name: str,
    target: ScanTarget,
    output: str,
) -> tuple[tuple[Finding, ...], tuple[DerivedSeed, ...]]:
    if tool_name == "exiftool":
        return _parse_exiftool_json(target, output)
    if tool_name == "tesseract-ocr":
        return _parse_tesseract_text(target, output)
    if tool_name == "zbarimg":
        return _parse_zbarimg_output(target, output)
    return (), ()


def _parse_exiftool_json(target: ScanTarget, output: str) -> tuple[tuple[Finding, ...], tuple[DerivedSeed, ...]]:
    payload = _json_payload_from_text(output)
    if payload is None:
        return (), ()

    records = payload if isinstance(payload, list) else [payload]
    findings: list[Finding] = []
    seeds: list[DerivedSeed] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        scalars = _json_scalars(record)
        if not scalars:
            continue
        scalar_text = "\n".join(value for _, value in scalars)
        record_seeds = _extract_derived_seeds(scalar_text, source="exiftool")
        seeds.extend(record_seeds)
        metadata = _exiftool_metadata(scalars, record_seeds)
        findings.append(
            Finding(
                module="local-image-parser",
                source="exiftool",
                target=target.value,
                status="completed",
                confidence="medium",
                evidence=_exiftool_evidence(metadata),
                metadata=metadata,
            )
        )
    return tuple(findings), _dedupe_seeds(tuple(seeds))


def _parse_tesseract_text(target: ScanTarget, output: str) -> tuple[tuple[Finding, ...], tuple[DerivedSeed, ...]]:
    text = output.strip()
    if not text:
        return (), ()
    seeds = _extract_derived_seeds(text, source="tesseract-ocr")
    metadata = {
        "parser": "tesseract-ocr-text",
        "text_length": str(len(text)),
        "line_count": str(len([line for line in text.splitlines() if line.strip()])),
        **_seed_metadata(seeds),
    }
    finding = Finding(
        module="local-image-parser",
        source="tesseract-ocr",
        target=target.value,
        status="completed",
        confidence="medium" if seeds else "low",
        evidence=_text_parser_evidence("Tesseract OCR text parsed", metadata),
        metadata=metadata,
    )
    return (finding,), seeds


def _parse_zbarimg_output(target: ScanTarget, output: str) -> tuple[tuple[Finding, ...], tuple[DerivedSeed, ...]]:
    payloads = _zbar_payloads(output)
    if not payloads:
        return (), ()
    text = "\n".join(payloads)
    seeds = _extract_derived_seeds(text, source="zbarimg")
    metadata = {
        "parser": "zbarimg-raw",
        "barcode_count": str(len(payloads)),
        "barcode_payloads": "|".join(payloads),
        **_seed_metadata(seeds),
    }
    finding = Finding(
        module="local-image-parser",
        source="zbarimg",
        target=target.value,
        status="completed",
        confidence="medium" if seeds else "low",
        evidence=_text_parser_evidence("zbarimg barcode payloads parsed", metadata),
        metadata=metadata,
    )
    return (finding,), seeds


def _json_payload_from_text(text: str) -> Any | None:
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char not in "[{":
            continue
        try:
            payload, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        return payload
    return None


def _json_scalars(value: Any, path: tuple[str, ...] = ()) -> tuple[tuple[tuple[str, ...], str], ...]:
    scalars: list[tuple[tuple[str, ...], str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            scalars.extend(_json_scalars(item, (*path, str(key))))
    elif isinstance(value, list):
        for item in value:
            scalars.extend(_json_scalars(item, path))
    elif value is not None:
        text = str(value).strip()
        if text:
            scalars.append((path, text))
    return tuple(scalars)


def _exiftool_metadata(
    scalars: tuple[tuple[tuple[str, ...], str], ...],
    seeds: tuple[DerivedSeed, ...],
) -> dict[str, str]:
    metadata = {
        "parser": "exiftool-json",
    }
    key_map = {
        "source_file": ("SourceFile",),
        "file_type": ("FileType",),
        "mime_type": ("MIMEType",),
        "image_width": ("ImageWidth", "ExifImageWidth"),
        "image_height": ("ImageHeight", "ExifImageHeight"),
        "camera_make": ("Make",),
        "camera_model": ("Model",),
        "lens_model": ("LensModel",),
        "software": ("Software",),
        "datetime_original": ("DateTimeOriginal",),
        "create_date": ("CreateDate",),
        "modify_date": ("ModifyDate", "FileModifyDate"),
        "gps_latitude": ("GPSLatitude",),
        "gps_longitude": ("GPSLongitude",),
        "gps_altitude": ("GPSAltitude",),
        "gps_position": ("GPSPosition",),
        "name": ("Artist", "Creator", "By-line", "Author", "OwnerName"),
        "copyright": ("Copyright",),
    }
    for metadata_key, labels in key_map.items():
        value = _first_exif_value(scalars, *labels)
        if value:
            metadata[metadata_key] = value

    latitude = metadata.get("gps_latitude", "")
    longitude = metadata.get("gps_longitude", "")
    if latitude and longitude:
        metadata["location"] = f"{latitude}, {longitude}"
    elif metadata.get("gps_position"):
        metadata["location"] = metadata["gps_position"]

    metadata.update(_seed_metadata(seeds))
    return metadata


def _seed_metadata(seeds: tuple[DerivedSeed, ...]) -> dict[str, str]:
    metadata: dict[str, str] = {}
    urls = tuple(seed.value for seed in seeds if seed.kind in {"url", "telegram", "instagram", "social"})
    emails = tuple(seed.value for seed in seeds if seed.kind == "email")
    phones = tuple(seed.value for seed in seeds if seed.kind == "phone")
    domains = tuple(seed.value for seed in seeds if seed.kind == "domain")
    usernames = tuple(seed.value for seed in seeds if seed.kind == "username")
    if urls:
        metadata["discovered_urls"] = "|".join(urls)
    if emails:
        metadata["emails"] = "|".join(emails)
    if phones:
        metadata["phones"] = "|".join(phones)
    if domains:
        metadata["domain"] = domains[0]
    if usernames:
        metadata["username"] = usernames[0]
    return metadata


def _first_exif_value(scalars: tuple[tuple[tuple[str, ...], str], ...], *labels: str) -> str:
    wanted = {_normalize_exif_label(label) for label in labels}
    for path, value in scalars:
        if not path:
            continue
        if _normalize_exif_label(path[-1]) in wanted:
            return value
    return ""


def _normalize_exif_label(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _exiftool_evidence(metadata: dict[str, str]) -> str:
    parts = ["ExifTool JSON metadata parsed"]
    for key, label in (
        ("camera_make", "make"),
        ("camera_model", "model"),
        ("datetime_original", "created"),
        ("location", "location"),
        ("discovered_urls", "urls"),
        ("emails", "emails"),
        ("phones", "phones"),
        ("username", "username"),
    ):
        value = metadata.get(key)
        if value:
            parts.append(f"{label}={value}")
    return "; ".join(parts)


def _text_parser_evidence(prefix: str, metadata: dict[str, str]) -> str:
    parts = [prefix]
    for key, label in (
        ("text_length", "chars"),
        ("line_count", "lines"),
        ("barcode_count", "payloads"),
        ("discovered_urls", "urls"),
        ("emails", "emails"),
        ("phones", "phones"),
        ("username", "username"),
        ("domain", "domain"),
    ):
        value = metadata.get(key)
        if value:
            parts.append(f"{label}={value}")
    return "; ".join(parts)


def _zbar_payloads(output: str) -> tuple[str, ...]:
    payloads: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("scanned ", "warning:", "error:", "zbarimg:")):
            continue
        if re.match(r"^[a-z][a-z0-9_-]+:", line, re.IGNORECASE) and not line.lower().startswith(("http:", "https:", "mailto:", "tel:")):
            _, value = line.split(":", 1)
            line = value.strip()
        if line:
            payloads.append(line)
    return tuple(payloads)


def _derived_targets(
    seeds: tuple[DerivedSeed, ...],
    *,
    region: str,
    limit: int,
) -> tuple[ScanTarget, ...]:
    if limit <= 0:
        return ()
    targets: list[ScanTarget] = []
    seen: set[tuple[str, str]] = set()
    for seed in seeds:
        kind = seed.kind
        value = seed.value
        if kind == "social":
            target_kind = "social"
        elif kind in {"telegram", "instagram", "url", "domain", "email", "phone", "username"}:
            target_kind = kind
        else:
            target_kind = classify_target(value)
        if target_kind == "image":
            continue
        key = (target_kind, value.lower())
        if key in seen:
            continue
        seen.add(key)
        targets.append(ScanTarget(kind=target_kind, value=value, region=region))
        if len(targets) >= limit:
            break
    return tuple(targets)


def _ready_adapters_for_targets(
    targets: tuple[ScanTarget, ...],
    *,
    adapter_limit: int | None,
) -> tuple[str, ...]:
    if adapter_limit == 0:
        return ()
    repositories: list[str] = []
    seen: set[str] = set()
    for target in targets:
        plan = build_search_plan(target.kind, target.value, profile_name="auto", region=target.region)
        for repository in ready_adapter_repositories(plan):
            key = repository.lower()
            if key in seen:
                continue
            seen.add(key)
            repositories.append(repository)
            if adapter_limit is not None and len(repositories) >= adapter_limit:
                return tuple(repositories)
    return tuple(repositories)


def _urls(text: str) -> tuple[str, ...]:
    values = []
    for match in re.findall(r"https?://[^\s<>'\")\]]+", text):
        values.append(match.rstrip(".,;:!?"))
    return tuple(values)


def _emails(text: str) -> tuple[str, ...]:
    return tuple(re.findall(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", text, re.IGNORECASE))


def _phones(text: str) -> tuple[str, ...]:
    phones: list[str] = []
    for match in re.findall(r"\+[1-9]\d[\d\s().-]{6,}\d\b", text):
        phones.append(re.sub(r"[\s().-]", "", match))
    return tuple(phones)


def _handles(text: str) -> tuple[str, ...]:
    emails = set(_emails(text))
    handles: list[str] = []
    for match in re.findall(r"(?<![\w.])@[A-Za-z0-9._]{3,30}\b", text):
        if any(match in email for email in emails):
            continue
        handles.append(match.lstrip("@"))
    return tuple(handles)


def _domains(text: str) -> tuple[str, ...]:
    values = []
    for match in re.findall(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", text):
        if "@" in match or match.lower().startswith(("http.", "https.")):
            continue
        values.append(match.lower().rstrip(".,;:!?"))
    return tuple(values)


def _domain_from_url(value: str) -> str:
    return (urlparse(value).hostname or "").lower()


def _dedupe_seeds(seeds: tuple[DerivedSeed, ...]) -> tuple[DerivedSeed, ...]:
    seen: set[tuple[str, str]] = set()
    deduped: list[DerivedSeed] = []
    for seed in seeds:
        normalized = seed.value.strip()
        key = (seed.kind, normalized.lower())
        if not normalized or key in seen:
            continue
        seen.add(key)
        deduped.append(DerivedSeed(seed.kind, normalized, seed.source))
    return tuple(deduped)


def _redact(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return re.sub(
        r"(?i)\b(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[^'\"\s]+",
        r"\1=<redacted>",
        value,
    )


def _join_output(*values: str | bytes | None) -> str:
    parts = [_redact(value) for value in values if value]
    return "\n".join(part for part in parts if part)


def _truncate(value: str, limit: int = 2000) -> str:
    compact = " ".join(value.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."
