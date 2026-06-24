from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .adapter_runner import run_adapter
from .adapters import ADAPTERS
from .engine import Finding, RunConfig, ScanTarget
from .runtime import build_default_engine


@dataclass(frozen=True)
class InvestigationResult:
    title: str
    targets: tuple[ScanTarget, ...]
    findings: tuple[Finding, ...]
    adapter_findings: tuple[Finding, ...]
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
    adapter_limit: int | None = 20,
) -> InvestigationResult:
    engine = build_default_engine()
    config = RunConfig(live=live, timeout=timeout)
    findings: list[Finding] = []
    for target in targets:
        findings.extend(engine.scan(target, config))

    adapter_findings: list[Finding] = []
    if include_adapters:
        for target in targets:
            adapter_findings.extend(_adapter_dry_runs(target, adapter_limit))

    return InvestigationResult(
        title=title,
        targets=targets,
        findings=tuple(findings),
        adapter_findings=tuple(adapter_findings),
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
            "## Native Findings",
            "",
            "| Module | Source | Target | Status | Confidence | URL | Evidence |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for finding in result.findings:
        lines.append(_finding_row(finding))

    if result.adapter_findings:
        lines.extend(
            [
                "",
                "## Adapter Dry Runs",
                "",
                "| Adapter | Target | Status | Command / Evidence |",
                "|---|---|---|---|",
            ]
        )
        for finding in result.adapter_findings:
            lines.append(
                f"| {finding.source} | {_escape(finding.target)} | {finding.status} | {_escape(finding.evidence)} |"
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


def _adapter_dry_runs(target: ScanTarget, limit: int | None) -> tuple[Finding, ...]:
    compatible = [
        adapter
        for adapter in ADAPTERS
        if adapter.target_kinds and target.kind in adapter.target_kinds
    ]
    if limit is not None:
        compatible = compatible[:limit]
    return tuple(
        run_adapter(adapter.repository, target, execute=False)
        for adapter in compatible
    )


def _finding_row(finding: Finding) -> str:
    return (
        f"| {finding.module} | {_escape(finding.source)} | {_escape(finding.target)} | "
        f"{finding.status} | {finding.confidence} | {_escape(finding.url)} | {_escape(finding.evidence)} |"
    )


def _escape(value: str) -> str:
    return " ".join(str(value).split()).replace("|", "\\|")
