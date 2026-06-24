from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .adapter_runner import run_adapter_findings
from .adapters import ADAPTERS, AdapterSpec, find_adapter
from .entities import Entity, entities_from_findings, entities_from_targets, merge_entities
from .engine import Finding, RunConfig, ScanTarget
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
    adapter_repositories: tuple[str, ...] = (),
) -> InvestigationResult:
    engine = build_default_engine()
    config = RunConfig(live=live, timeout=timeout)
    findings: list[Finding] = []
    for target in targets:
        findings.extend(engine.scan(target, config))

    adapter_findings: list[Finding] = []
    if include_adapters:
        for target in targets:
            adapter_findings.extend(
                _adapter_runs(
                    target,
                    adapter_limit,
                    execute=execute_adapters,
                    allow_restricted=allow_restricted_adapters,
                    timeout=adapter_timeout,
                    repositories=adapter_repositories,
                )
            )
    entities = merge_entities(
        entities_from_targets(targets),
        entities_from_findings(tuple(findings)),
        entities_from_findings(tuple(adapter_findings)),
    )
    edges = graph_edges_from_case(targets, (*findings, *adapter_findings), entities)

    return InvestigationResult(
        title=title,
        targets=targets,
        findings=tuple(findings),
        adapter_findings=tuple(adapter_findings),
        entities=entities,
        edges=edges,
        generated_at=datetime.now().astimezone().isoformat(timespec="seconds"),
    )


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
) -> tuple[Finding, ...]:
    compatible = _adapters_for_target(target, repositories)
    if limit is not None:
        compatible = compatible[:limit]
    findings: list[Finding] = []
    for adapter in compatible:
        findings.extend(
            run_adapter_findings(
                adapter.repository,
                target,
                execute=execute,
                allow_restricted=allow_restricted,
                timeout=timeout,
            )
        )
    return tuple(findings)


def _adapters_for_target(target: ScanTarget, repositories: tuple[str, ...]) -> tuple[AdapterSpec, ...]:
    if repositories:
        return tuple(find_adapter(repository) for repository in _dedupe_repositories(repositories))
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


def _has_executed_adapter_findings(findings: tuple[Finding, ...]) -> bool:
    return any(finding.status != "planned" or finding.module == "external-adapter-parser" for finding in findings)


def _finding_row(finding: Finding) -> str:
    return (
        f"| {finding.module} | {_escape(finding.source)} | {_escape(finding.target)} | "
        f"{finding.status} | {finding.confidence} | {_escape(finding.url)} | {_escape(finding.evidence)} |"
    )


def _escape(value: str) -> str:
    return " ".join(str(value).split()).replace("|", "\\|")
