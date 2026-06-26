from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path

from .adapter_runner import run_adapter_findings
from .adapters import ADAPTERS, AdapterSpec, find_adapter
from .entities import Entity, entities_from_findings, entities_from_targets, merge_entities
from .engine import Engine, Finding, RunConfig, ScanTarget
from .graph import GraphEdge, graph_edges_from_case
from .runtime import build_default_engine


@dataclass(frozen=True)
class InvestigationResult:
    title: str
    targets: tuple[ScanTarget, ...]
    findings: tuple[Finding, ...]
    adapter_findings: tuple[Finding, ...]
    entities: tuple[Entity, ...]
    edges: tuple[GraphEdge, ...]
    generated_at: str

    def all_findings(self) -> tuple[Finding, ...]:
        return (*self.findings, *self.adapter_findings)

    def to_dict(self) -> dict[str, object]:
        return {
            "title": self.title,
            "generated_at": self.generated_at,
            "targets": [
                {"kind": target.kind, "value": target.value, "region": target.region}
                for target in self.targets
            ],
            "entities": [entity.to_dict() for entity in self.entities],
            "edges": [edge.to_dict() for edge in self.edges],
            "findings": [finding.to_dict() for finding in self.findings],
            "adapter_findings": [finding.to_dict() for finding in self.adapter_findings],
        }


def run_investigation(
    targets: tuple[ScanTarget, ...],
    *,
    title: str = "OSINT investigation",
    live: bool = False,
    timeout: float = 10.0,
    include_adapters: bool = False,
    execute_adapters: bool = False,
    allow_restricted_adapters: bool = False,
    adapter_timeout: float = 60.0,
    adapter_limit: int | None = 20,
    adapter_workers: int = 1,
    http_retries: int = 1,
    http_backoff: float = 1.0,
    request_delay: float = 0.0,
    crawl_pages: int = 5,
    crawl_depth: int = 1,
    person_aliases: tuple[str, ...] = (),
    adapter_repositories: tuple[str, ...] = (),
    native_kinds: tuple[str, ...] | None = None,
) -> InvestigationResult:
    engine = build_default_engine()
    config = RunConfig(
        live=live,
        timeout=timeout,
        http_retries=http_retries,
        http_backoff=http_backoff,
        request_delay=request_delay,
        crawl_pages=crawl_pages,
        crawl_depth=crawl_depth,
        person_aliases=person_aliases,
    )
    findings: list[Finding] = []
    for target in targets:
        findings.extend(_native_scan(engine, target, config, native_kinds=native_kinds))

    person_candidate_context = _person_candidate_context(tuple(findings))
    scan_targets = _scan_targets_with_person_expansions(targets, tuple(findings))
    for target in scan_targets[len(targets) :]:
        target_findings = _native_scan(engine, target, config, native_kinds=native_kinds)
        findings.extend(_annotate_person_candidate_findings(target, target_findings, person_candidate_context))

    adapter_findings: list[Finding] = []
    if include_adapters:
        if adapter_workers < 1:
            raise ValueError("adapter_workers must be at least 1.")
        for target in scan_targets:
            target_adapter_findings = _adapter_runs(
                target,
                adapter_limit,
                execute=execute_adapters,
                allow_restricted=allow_restricted_adapters,
                timeout=adapter_timeout,
                repositories=adapter_repositories,
                workers=adapter_workers,
            )
            adapter_findings.extend(
                _annotate_person_candidate_findings(
                    target,
                    target_adapter_findings,
                    person_candidate_context,
                )
            )
    entities = merge_entities(
        entities_from_targets(targets),
        entities_from_findings(tuple(findings)),
        entities_from_findings(tuple(adapter_findings)),
    )
    edges = graph_edges_from_case(scan_targets, (*findings, *adapter_findings), entities)

    return InvestigationResult(
        title=title,
        targets=targets,
        findings=tuple(findings),
        adapter_findings=tuple(adapter_findings),
        entities=entities,
        edges=edges,
        generated_at=datetime.now().astimezone().isoformat(timespec="seconds"),
    )


def _native_scan(
    engine: Engine,
    target: ScanTarget,
    config: RunConfig,
    *,
    native_kinds: tuple[str, ...] | None,
) -> tuple[Finding, ...]:
    if native_kinds is not None and target.kind not in native_kinds:
        return ()
    return engine.scan(target, config)


def render_investigation_markdown(result: InvestigationResult) -> str:
    lines = [
        f"# {result.title}",
        "",
        f"Generated: {result.generated_at}",
        "",
        "## Targets",
        "",
        "| Kind | Value | Region |",
        "|---|---|---|",
    ]
    for target in result.targets:
        lines.append(f"| {target.kind} | {_escape(target.value)} | {target.region} |")

    lines.extend(
        [
            "",
            "## Entity Summary",
            "",
            "| Kind | Value | Confidence | Source | Note |",
            "|---|---|---|---|---|",
        ]
    )
    for entity in result.entities:
        lines.append(
            f"| {entity.kind} | {_escape(entity.value)} | {entity.confidence} | "
            f"{_escape(entity.source)} | {_escape(entity.note)} |"
        )

    lines.extend(
        [
            "",
            "## Graph Edges",
            "",
            "| Source | Relation | Target | Confidence | Evidence Source |",
            "|---|---|---|---|---|",
        ]
    )
    for edge in result.edges:
        lines.append(
            f"| {_escape(edge.source_kind + ':' + edge.source_value)} | {edge.relation} | "
            f"{_escape(edge.target_kind + ':' + edge.target_value)} | {edge.confidence} | {_escape(edge.source)} |"
        )

    lines.extend(
        [
            "",
            "## Native Findings",
            "",
            "| Module | Source | Target | Status | Confidence | URL | Evidence |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for finding in result.findings:
        lines.append(_finding_row(finding))

    if result.adapter_findings:
        adapter_heading = "Adapter Findings" if _has_executed_adapter_findings(result.adapter_findings) else "Adapter Dry Runs"
        lines.extend(
            [
                "",
                f"## {adapter_heading}",
                "",
                "| Adapter | Module | Target | Status | Confidence | Command / Evidence |",
                "|---|---|---|---|---|---|",
            ]
        )
        for finding in result.adapter_findings:
            lines.append(
                f"| {finding.source} | {finding.module} | {_escape(finding.target)} | "
                f"{finding.status} | {finding.confidence} | {_escape(finding.evidence)} |"
            )

    lines.extend(
        [
            "",
            "## Review Checklist",
            "",
            "- [ ] Remove out-of-scope personal data.",
            "- [ ] Separate confirmed facts from weak indicators.",
            "- [ ] Record source URLs, timestamps and confidence.",
            "- [ ] Re-run with `--live` only where lawful and necessary.",
            "- [ ] Execute external adapters only after license, scope and safety review.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_investigation_json(result: InvestigationResult) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)


def write_investigation(path: str | Path, content: str) -> Path:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    return output_path


def _adapter_runs(
    target: ScanTarget,
    limit: int | None,
    *,
    execute: bool,
    allow_restricted: bool,
    timeout: float,
    repositories: tuple[str, ...],
    workers: int,
) -> tuple[Finding, ...]:
    compatible = _adapters_for_target(target, repositories)
    if limit is not None:
        compatible = compatible[:limit]
    if not compatible:
        return ()
    if workers < 1:
        raise ValueError("workers must be at least 1.")

    def run_one(adapter: AdapterSpec) -> tuple[Finding, ...]:
        return run_adapter_findings(
            adapter.repository,
            target,
            execute=execute,
            allow_restricted=allow_restricted,
            timeout=timeout,
        )

    findings: list[Finding] = []
    if workers > 1 and len(compatible) > 1:
        with ThreadPoolExecutor(max_workers=min(workers, len(compatible))) as executor:
            for adapter_findings in executor.map(run_one, compatible):
                findings.extend(adapter_findings)
        return tuple(findings)

    for adapter in compatible:
        findings.extend(run_one(adapter))
    return tuple(findings)


def _adapters_for_target(target: ScanTarget, repositories: tuple[str, ...]) -> tuple[AdapterSpec, ...]:
    if repositories:
        return tuple(
            adapter
            for adapter in (find_adapter(repository) for repository in _dedupe_repositories(repositories))
            if adapter.target_kinds and target.kind in adapter.target_kinds
        )
    return tuple(
        adapter
        for adapter in ADAPTERS
        if adapter.target_kinds and target.kind in adapter.target_kinds
    )


def _dedupe_repositories(repositories: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    deduped: list[str] = []
    for repository in repositories:
        normalized = repository.strip()
        key = normalized.lower()
        if normalized and key not in seen:
            seen.add(key)
            deduped.append(normalized)
    return tuple(deduped)


def _scan_targets_with_person_expansions(
    targets: tuple[ScanTarget, ...],
    findings: tuple[Finding, ...],
) -> tuple[ScanTarget, ...]:
    target_regions = {target.value: target.region for target in targets if target.kind == "person"}
    expanded = list(targets)
    seen = {_target_key(target) for target in expanded}
    for finding in findings:
        if finding.module != "person-name-expansion" or finding.status != "candidate":
            continue
        username = finding.metadata.get("username", "").strip()
        if not username:
            continue
        target = ScanTarget(
            kind="username",
            value=username,
            region=target_regions.get(finding.target, "all"),
        )
        key = _target_key(target)
        if key not in seen:
            seen.add(key)
            expanded.append(target)
    return tuple(expanded)


def _person_candidate_context(findings: tuple[Finding, ...]) -> dict[str, dict[str, str]]:
    context: dict[str, dict[str, str]] = {}
    for finding in findings:
        if finding.module != "person-name-expansion" or finding.status != "candidate":
            continue
        username = finding.metadata.get("username", "").strip()
        if not username:
            continue
        candidate = {
            "derived_from_person": finding.target,
            "person_normalized_name": finding.metadata.get("normalized_name", ""),
            "person_candidate_rank": finding.metadata.get("candidate_rank", ""),
            "person_candidate_score": finding.metadata.get("candidate_score", ""),
            "person_candidate_strategy": finding.metadata.get("strategy", ""),
            "person_platform_hints": finding.metadata.get("platform_hints", ""),
        }
        key = username.lower()
        existing = context.get(key)
        if existing is None or _context_rank(candidate) < _context_rank(existing):
            context[key] = candidate
    return context


def _annotate_person_candidate_findings(
    target: ScanTarget,
    findings: tuple[Finding, ...],
    person_candidate_context: dict[str, dict[str, str]],
) -> tuple[Finding, ...]:
    if target.kind != "username" or not findings:
        return findings
    context = person_candidate_context.get(target.value.lower())
    if not context:
        return findings
    return tuple(
        replace(finding, metadata={**finding.metadata, **context})
        for finding in findings
    )


def _context_rank(context: dict[str, str]) -> tuple[int, int]:
    return (
        _safe_int(context.get("person_candidate_rank", ""), default=9999),
        -_safe_int(context.get("person_candidate_score", ""), default=0),
    )


def _safe_int(value: str, *, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _target_key(target: ScanTarget) -> tuple[str, str, str]:
    return target.kind, target.value.lower(), target.region


def _has_executed_adapter_findings(findings: tuple[Finding, ...]) -> bool:
    executed_statuses = {"completed", "error", "timeout", "missing"}
    return any(
        finding.module == "external-adapter-parser" or finding.status in executed_statuses
        for finding in findings
    )


def _finding_row(finding: Finding) -> str:
    return (
        f"| {finding.module} | {_escape(finding.source)} | {_escape(finding.target)} | "
        f"{finding.status} | {finding.confidence} | {_escape(finding.url)} | {_escape(finding.evidence)} |"
    )


def _escape(value: str) -> str:
    return " ".join(str(value).split()).replace("|", "\\|")
