from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
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
        seeds = _extract_derived_seeds(output, source=tool.name)
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
