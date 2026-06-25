from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .graph import analyze_case_graph
from .output import (
    format_case_detail,
    format_case_graph_analysis,
    format_case_source_summary,
)


@dataclass(frozen=True)
class CaseExportResult:
    case_id: str
    output_dir: Path
    files: tuple[Path, ...]
    zip_path: Path | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "output_dir": str(self.output_dir),
            "zip_path": str(self.zip_path) if self.zip_path else "",
            "files": [str(path) for path in self.files],
        }


@dataclass(frozen=True)
class CasesExportResult:
    output_dir: Path
    case_exports: tuple[CaseExportResult, ...]
    manifest_path: Path
    zip_path: Path | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "output_dir": str(self.output_dir),
            "zip_path": str(self.zip_path) if self.zip_path else "",
            "case_count": len(self.case_exports),
            "manifest_path": str(self.manifest_path),
            "cases": [case_export.to_dict() for case_export in self.case_exports],
        }


def export_case_package(
    payload: dict[str, object],
    output_dir: str | Path,
    *,
    create_zip: bool = False,
) -> CaseExportResult:
    case = payload.get("case")
    if not isinstance(case, dict):
        raise ValueError("Invalid case payload: missing case.")
    case_id = str(case.get("case_id", "") or "unknown")
    target_dir = Path(output_dir)
    if target_dir.exists() and not target_dir.is_dir():
        raise ValueError(f"Export output is not a directory: {target_dir}")
    target_dir.mkdir(parents=True, exist_ok=True)

    graph_analysis = analyze_case_graph(payload, limit=50)
    file_payloads = {
        "case.json": json.dumps(payload, ensure_ascii=False, indent=2),
        "case.md": format_case_detail(payload, output_format="markdown"),
        "findings.csv": format_case_detail(payload, output_format="csv"),
        "sources.csv": format_case_source_summary(payload, output_format="csv"),
        "targets.csv": _rows_csv(case_id, payload.get("targets"), ("kind", "value", "region")),
        "entities.csv": _rows_csv(case_id, payload.get("entities"), ("kind", "value", "confidence", "source", "note")),
        "edges.csv": _rows_csv(
            case_id,
            payload.get("edges"),
            ("source_kind", "source_value", "relation", "target_kind", "target_value", "confidence", "source", "note"),
        ),
        "metadata.json": json.dumps(payload.get("metadata", {}), ensure_ascii=False, indent=2, sort_keys=True),
        "graph.json": json.dumps(graph_analysis.to_dict(), ensure_ascii=False, indent=2),
        "graph.md": format_case_graph_analysis(graph_analysis, output_format="markdown"),
    }

    written: list[Path] = []
    for name, content in file_payloads.items():
        path = target_dir / name
        path.write_text(content + "\n", encoding="utf-8")
        written.append(path)

    manifest_path = target_dir / "manifest.json"
    manifest = _manifest(case_id, case, written)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    written.append(manifest_path)

    zip_path = None
    if create_zip:
        zip_path = target_dir.with_suffix(".zip")
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in written:
                archive.write(path, arcname=path.name)

    return CaseExportResult(case_id=case_id, output_dir=target_dir, files=tuple(written), zip_path=zip_path)


def export_cases_package(
    payloads: list[dict[str, object]] | tuple[dict[str, object], ...],
    output_dir: str | Path,
    *,
    create_zip: bool = False,
) -> CasesExportResult:
    target_dir = Path(output_dir)
    if target_dir.exists() and not target_dir.is_dir():
        raise ValueError(f"Export output is not a directory: {target_dir}")
    target_dir.mkdir(parents=True, exist_ok=True)

    case_exports: list[CaseExportResult] = []
    used_names: set[str] = set()
    for index, payload in enumerate(payloads, start=1):
        case = payload.get("case")
        if not isinstance(case, dict):
            raise ValueError("Invalid case payload: missing case.")
        case_id = str(case.get("case_id", "") or f"case-{index}")
        folder_name = _unique_name(_safe_name(case_id), used_names)
        case_exports.append(export_case_package(payload, target_dir / folder_name, create_zip=False))

    manifest_path = target_dir / "bulk_manifest.json"
    manifest = _bulk_manifest(case_exports)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    zip_path = None
    if create_zip:
        zip_path = target_dir.with_suffix(".zip")
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(target_dir.rglob("*")):
                if path.is_file():
                    archive.write(path, arcname=str(path.relative_to(target_dir)))

    return CasesExportResult(
        output_dir=target_dir,
        case_exports=tuple(case_exports),
        manifest_path=manifest_path,
        zip_path=zip_path,
    )


def format_case_export_result(result: CaseExportResult, *, output_format: str = "table") -> str:
    if output_format == "json":
        return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)
    if output_format == "markdown":
        lines = [
            f"# Case Export: {result.case_id}",
            "",
            f"- Output dir: `{result.output_dir}`",
            f"- Zip: `{result.zip_path}`" if result.zip_path else "- Zip: none",
            "",
            "## Files",
            "",
        ]
        lines.extend(f"- `{path.name}`" for path in result.files)
        return "\n".join(lines)
    if output_format == "table":
        lines = [
            f"Case ID:    {result.case_id}",
            f"Output dir: {result.output_dir}",
            f"Zip:        {result.zip_path if result.zip_path else '-'}",
            f"Files:      {len(result.files)}",
        ]
        return "\n".join(lines)
    raise ValueError(f"Unsupported output format: {output_format}")


def format_cases_export_result(result: CasesExportResult, *, output_format: str = "table") -> str:
    if output_format == "json":
        return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)
    if output_format == "markdown":
        lines = [
            "# Cases Export",
            "",
            f"- Output dir: `{result.output_dir}`",
            f"- Zip: `{result.zip_path}`" if result.zip_path else "- Zip: none",
            f"- Cases: {len(result.case_exports)}",
            f"- Manifest: `{result.manifest_path}`",
            "",
            "## Cases",
            "",
            "| Case ID | Output dir | Files |",
            "|---|---|---:|",
        ]
        for case_export in result.case_exports:
            lines.append(
                f"| {case_export.case_id} | `{case_export.output_dir}` | {len(case_export.files)} |"
            )
        return "\n".join(lines)
    if output_format == "table":
        lines = [
            f"Output dir: {result.output_dir}",
            f"Zip:        {result.zip_path if result.zip_path else '-'}",
            f"Cases:      {len(result.case_exports)}",
            f"Manifest:   {result.manifest_path}",
        ]
        return "\n".join(lines)
    raise ValueError(f"Unsupported output format: {output_format}")


def _rows_csv(case_id: str, rows: object, fields: tuple[str, ...]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=("case_id", *fields), lineterminator="\n")
    writer.writeheader()
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            writer.writerow({"case_id": case_id, **{field: row.get(field, "") for field in fields}})
    return buffer.getvalue().strip()


def _bulk_manifest(case_exports: list[CaseExportResult]) -> dict[str, object]:
    return {
        "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "case_count": len(case_exports),
        "cases": [
            {
                "case_id": case_export.case_id,
                "directory": case_export.output_dir.name,
                "file_count": len(case_export.files),
                "manifest": str((case_export.output_dir / "manifest.json").relative_to(case_export.output_dir.parent)),
            }
            for case_export in case_exports
        ],
    }


def _manifest(case_id: str, case: dict[str, object], files: list[Path]) -> dict[str, object]:
    return {
        "case_id": case_id,
        "title": str(case.get("title", "") or ""),
        "generated_at": str(case.get("generated_at", "") or ""),
        "saved_at": str(case.get("saved_at", "") or ""),
        "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "files": [
            {
                "name": path.name,
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
            for path in files
        ],
    }


def _safe_name(value: str) -> str:
    normalized = "".join(char if char.isalnum() or char in "._-" else "_" for char in value.strip())
    return normalized.strip("._-") or "case"


def _unique_name(value: str, used: set[str]) -> str:
    candidate = value
    counter = 2
    while candidate.lower() in used:
        candidate = f"{value}-{counter}"
        counter += 1
    used.add(candidate.lower())
    return candidate


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
