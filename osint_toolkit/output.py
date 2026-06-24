from __future__ import annotations

import csv
import io
import json
from typing import Iterable

from .adapters import AdapterSpec
from .engine import Finding
from .models import OsintProject


def format_projects(projects: Iterable[OsintProject], *, output_format: str, kind: str = "all") -> str:
    project_list = tuple(projects)
    if output_format == "json":
        return json.dumps([project.to_dict() for project in project_list], ensure_ascii=False, indent=2)
    if output_format == "csv":
        return _projects_csv(project_list, kind=kind)
    if output_format == "markdown":
        return _projects_markdown(project_list, kind=kind)
    if output_format == "table":
        return _projects_table(project_list, kind=kind)
    raise ValueError(f"Unsupported output format: {output_format}")


def format_project_detail(project: OsintProject, *, output_format: str = "table") -> str:
    if output_format == "json":
        return json.dumps(project.to_dict(), ensure_ascii=False, indent=2)
    if output_format == "markdown":
        lines = [
            f"# {project.full_name}",
            "",
            f"- Rank: {project.rank}",
            f"- Stars: {project.stars}",
            f"- Forks: {project.forks}",
            f"- Language: {project.language or 'unknown'}",
            f"- License: {project.license or 'unknown'}",
            f"- URL: {project.html_url}",
            f"- Description: {project.description}",
            f"- People: {project.people_level or '-'} / {project.people_focus or '-'}",
            f"- RU/UA: {project.ru_ua_level or '-'} / {project.ru_ua_focus or '-'}",
            f"- Topics: {', '.join(project.topics)}",
        ]
        return "\n".join(lines)
    lines = [
        f"Repository: {project.full_name}",
        f"Rank:       {project.rank}",
        f"Stars:      {project.stars}",
        f"Forks:      {project.forks}",
        f"Language:   {project.language or 'unknown'}",
        f"License:    {project.license or 'unknown'}",
        f"URL:        {project.html_url}",
        f"People:     {project.people_level or '-'} | {project.people_focus or '-'}",
        f"RU/UA:      {project.ru_ua_level or '-'} | {project.ru_ua_focus or '-'}",
        f"Summary:    {project.description}",
    ]
    if project.people_note:
        lines.append(f"People note: {project.people_note}")
    if project.ru_ua_note:
        lines.append(f"RU/UA note:  {project.ru_ua_note}")
    return "\n".join(lines)


def format_findings(findings: Iterable[Finding], *, output_format: str = "table") -> str:
    finding_list = tuple(findings)
    if output_format == "json":
        return json.dumps([finding.to_dict() for finding in finding_list], ensure_ascii=False, indent=2)
    if output_format == "csv":
        return _findings_csv(finding_list)
    if output_format == "markdown":
        lines = [
            "| Module | Source | Status | Confidence | HTTP | URL | Evidence |",
            "|---|---|---|---|---:|---|---|",
        ]
        for finding in finding_list:
            http_status = finding.http_status if finding.http_status is not None else ""
            lines.append(
                f"| {finding.module} | {finding.source} | {finding.status} | {finding.confidence} | "
                f"{http_status} | {_escape_md(finding.url)} | {_escape_md(finding.evidence)} |"
            )
        return "\n".join(lines)
    if output_format == "table":
        headers = ("Module", "Source", "Status", "HTTP", "Confidence", "URL")
        rows = [
            (
                finding.module,
                finding.source,
                finding.status,
                "" if finding.http_status is None else str(finding.http_status),
                finding.confidence,
                _short(finding.url, 72),
            )
            for finding in finding_list
        ]
        return _format_table(headers, rows)
    raise ValueError(f"Unsupported output format: {output_format}")


def format_adapters(adapters: Iterable[AdapterSpec], *, output_format: str = "table") -> str:
    adapter_list = tuple(adapters)
    if output_format == "json":
        return json.dumps([adapter.to_dict() for adapter in adapter_list], ensure_ascii=False, indent=2)
    if output_format == "markdown":
        lines = [
            "| Repository | Capability | Integration | Status | License | Note |",
            "|---|---|---|---|---|---|",
        ]
        for adapter in adapter_list:
            lines.append(
                f"| {adapter.repository} | {_escape_md(adapter.capability)} | {adapter.integration} | "
                f"{adapter.status} | {adapter.license} | {_escape_md(adapter.note)} |"
            )
        return "\n".join(lines)
    if output_format == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(
            buffer,
            fieldnames=("repository", "capability", "integration", "status", "license", "command_hint", "note"),
            lineterminator="\n",
        )
        writer.writeheader()
        for adapter in adapter_list:
            writer.writerow(adapter.to_dict())
        return buffer.getvalue().strip()
    if output_format == "table":
        headers = ("Repository", "Integration", "Status", "Capability")
        rows = [
            (
                adapter.repository,
                adapter.integration,
                adapter.status,
                _short(adapter.capability, 46),
            )
            for adapter in adapter_list
        ]
        return _format_table(headers, rows)
    raise ValueError(f"Unsupported output format: {output_format}")


def format_stats(stats: dict[str, object]) -> str:
    lines = [
        "OSINT Toolkit catalog stats",
        f"Data dir:     {stats['data_dir']}",
        f"Total:        {stats['total']}",
        f"People:       {stats['people']}",
        f"RU/UA:        {stats['ru_ua']}",
        f"Relevant:     {stats['relevant']}",
        f"Intersection: {stats['intersection']}",
        "",
        "People levels:",
    ]
    lines.extend(f"- {key}: {value}" for key, value in sorted(stats["people_levels"].items()))
    lines.append("")
    lines.append("RU/UA levels:")
    lines.extend(f"- {key}: {value}" for key, value in sorted(stats["ru_ua_levels"].items()))
    lines.append("")
    lines.append("Top languages:")
    languages = sorted(stats["languages"].items(), key=lambda item: (-item[1], item[0]))[:10]
    lines.extend(f"- {key}: {value}" for key, value in languages)
    return "\n".join(lines)


def _projects_table(projects: tuple[OsintProject, ...], *, kind: str) -> str:
    headers = ("Rank", "Repository", "Stars", "Level", "Focus")
    rows = []
    for project in projects:
        level = _level(project, kind)
        focus = _focus(project, kind)
        rows.append(
            (
                str(project.rank),
                project.full_name,
                str(project.stars),
                level or "-",
                _short(focus or project.description, 58),
            )
        )
    return _format_table(headers, rows)


def _projects_markdown(projects: tuple[OsintProject, ...], *, kind: str) -> str:
    lines = [
        "| Rank | Repository | Stars | Level | Focus |",
        "|---:|---|---:|---|---|",
    ]
    for project in projects:
        level = _level(project, kind)
        focus = _escape_md(_focus(project, kind) or project.description)
        lines.append(
            f"| {project.rank} | [{project.full_name}]({project.html_url}) | "
            f"{project.stars} | {level or '-'} | {focus} |"
        )
    return "\n".join(lines)


def _projects_csv(projects: tuple[OsintProject, ...], *, kind: str) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=("rank", "full_name", "stars", "level", "focus", "language", "html_url", "description"),
        lineterminator="\n",
    )
    writer.writeheader()
    for project in projects:
        writer.writerow(
            {
                "rank": project.rank,
                "full_name": project.full_name,
                "stars": project.stars,
                "level": _level(project, kind),
                "focus": _focus(project, kind),
                "language": project.language,
                "html_url": project.html_url,
                "description": project.description,
            }
        )
    return buffer.getvalue().strip()


def _findings_csv(findings: tuple[Finding, ...]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=("module", "source", "target", "status", "url", "title", "http_status", "confidence", "evidence"),
        lineterminator="\n",
    )
    writer.writeheader()
    for finding in findings:
        writer.writerow(
            {
                "module": finding.module,
                "source": finding.source,
                "target": finding.target,
                "status": finding.status,
                "url": finding.url,
                "title": finding.title,
                "http_status": finding.http_status if finding.http_status is not None else "",
                "confidence": finding.confidence,
                "evidence": finding.evidence,
            }
        )
    return buffer.getvalue().strip()


def _format_table(headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        widths = [max(width, len(cell)) for width, cell in zip(widths, row)]
    line = "  ".join(header.ljust(width) for header, width in zip(headers, widths))
    sep = "  ".join("-" * width for width in widths)
    body = ["  ".join(cell.ljust(width) for cell, width in zip(row, widths)) for row in rows]
    return "\n".join([line, sep, *body])


def _level(project: OsintProject, kind: str) -> str:
    if kind == "people":
        return project.people_level
    if kind == "ru-ua":
        return project.ru_ua_level
    return project.people_level or project.ru_ua_level


def _focus(project: OsintProject, kind: str) -> str:
    if kind == "people":
        return project.people_focus
    if kind == "ru-ua":
        return project.ru_ua_focus
    if project.people_focus and project.ru_ua_focus:
        return f"{project.people_focus}; {project.ru_ua_focus}"
    return project.people_focus or project.ru_ua_focus


def _short(value: str, limit: int) -> str:
    compact = " ".join(value.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1] + "…"


def _escape_md(value: str) -> str:
    return " ".join(value.split()).replace("|", "\\|")
