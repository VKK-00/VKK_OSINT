from __future__ import annotations

import csv
import io
import json
import shutil
from dataclasses import dataclass

from .adapter_setup import build_adapter_setup
from .adapters import expand_adapter_repositories, find_adapter
from .search import LOCAL_TOOLS, find_search_profile


@dataclass(frozen=True)
class ToolReadiness:
    kind: str
    name: str
    readiness: str
    executable: str = ""
    executable_path: str = ""
    install_kind: str = ""
    install_command: str = ""
    install_note: str = ""
    docs_url: str = ""
    required_env: tuple[str, ...] = ()
    missing_env: tuple[str, ...] = ()
    optional_env: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "name": self.name,
            "readiness": self.readiness,
            "executable": self.executable,
            "executable_path": self.executable_path,
            "install_kind": self.install_kind,
            "install_command": self.install_command,
            "install_note": self.install_note,
            "docs_url": self.docs_url,
            "required_env": list(self.required_env),
            "missing_env": list(self.missing_env),
            "optional_env": list(self.optional_env),
        }


def build_profile_tool_readiness(profile_name: str) -> tuple[ToolReadiness, ...]:
    profile = find_search_profile(profile_name)
    excluded_repositories = {repository.lower() for repository in profile.excluded_repositories}
    rows: list[ToolReadiness] = []
    for repository in _profile_repositories(profile_name):
        setup = build_adapter_setup(find_adapter(repository))
        readiness = setup.readiness
        install_note = setup.install_note
        if repository.lower() in excluded_repositories:
            readiness = "excluded"
            install_note = (
                "Excluded from this profile; use a dedicated restricted profile only after scope review."
            )
        rows.append(
            ToolReadiness(
                kind="adapter",
                name=setup.repository,
                readiness=readiness,
                executable=setup.executable,
                executable_path=setup.executable_path,
                install_kind=setup.install_kind,
                install_command=setup.install_command,
                install_note=install_note,
                docs_url=setup.docs_url,
                required_env=setup.required_env,
                missing_env=setup.missing_env,
                optional_env=setup.optional_env,
            )
        )
    local_tools_by_name = {tool.name: tool for tool in LOCAL_TOOLS}
    for tool_name in profile.local_tools:
        tool = local_tools_by_name[tool_name]
        executable_path = shutil.which(tool.executable) or ""
        rows.append(
            ToolReadiness(
                kind="local-tool",
                name=tool.name,
                readiness="ready" if executable_path else "missing",
                executable=tool.executable,
                executable_path=executable_path,
                install_kind="local",
                install_command=getattr(tool, "install_command", ""),
                install_note=tool.install_note,
                docs_url=tool.docs_url,
            )
        )
    return tuple(rows)


def format_tool_readiness(rows: tuple[ToolReadiness, ...], *, output_format: str = "table") -> str:
    if output_format == "json":
        return json.dumps([row.to_dict() for row in rows], ensure_ascii=False, indent=2)
    if output_format == "csv":
        return _rows_csv(rows)
    if output_format == "markdown":
        lines = [
            "| Kind | Name | Readiness | Executable | Missing env | Install | Docs |",
            "|---|---|---|---|---|---|---|",
        ]
        for row in rows:
            install = row.install_command or row.install_note or row.install_kind or "-"
            docs = f"[docs]({row.docs_url})" if row.docs_url else "-"
            lines.append(
                f"| {row.kind} | {_escape(row.name)} | {row.readiness} | {_escape(row.executable or '-')} | "
                f"{_escape(', '.join(row.missing_env) or '-')} | {_escape(install)} | {docs} |"
            )
        return "\n".join(lines)
    if output_format == "table":
        return _table(
            ("Kind", "Name", "Readiness", "Executable", "Missing env", "Install"),
            [
                (
                    row.kind,
                    _short(row.name, 38),
                    row.readiness,
                    _short(row.executable or "-", 18),
                    _short(", ".join(row.missing_env) or "-", 28),
                    _short(row.install_command or row.install_note or row.install_kind or "-", 54),
                )
                for row in rows
            ],
        )
    raise ValueError(f"Unsupported output format: {output_format}")


def format_install_plan(rows: tuple[ToolReadiness, ...], *, output_format: str = "table") -> str:
    install_rows = tuple(
        row for row in rows if row.readiness not in {"ready", "excluded", "restricted"}
    )
    if output_format == "json":
        return json.dumps([_install_row(row) for row in install_rows], ensure_ascii=False, indent=2)
    if output_format == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(
            buffer,
            fieldnames=("kind", "name", "readiness", "install", "required_env", "docs_url"),
            lineterminator="\n",
        )
        writer.writeheader()
        for row in install_rows:
            writer.writerow(_install_row(row))
        return buffer.getvalue().strip()
    if output_format == "markdown":
        lines = [
            "| Kind | Name | Readiness | Install / action | Required env names | Docs |",
            "|---|---|---|---|---|---|",
        ]
        for row in install_rows:
            action = row.install_command or row.install_note or row.install_kind or "Review upstream docs."
            docs = f"[docs]({row.docs_url})" if row.docs_url else "-"
            lines.append(
                f"| {row.kind} | {_escape(row.name)} | {row.readiness} | {_escape(action)} | "
                f"{_escape(', '.join(row.required_env) or '-')} | {docs} |"
            )
        return "\n".join(lines)
    if output_format == "table":
        return _table(
            ("Kind", "Name", "Readiness", "Install / action", "Required env"),
            [
                (
                    row.kind,
                    _short(row.name, 38),
                    row.readiness,
                    _short(row.install_command or row.install_note or row.install_kind or "Review upstream docs.", 72),
                    _short(", ".join(row.required_env) or "-", 28),
                )
                for row in install_rows
            ],
        )
    raise ValueError(f"Unsupported output format: {output_format}")


def format_env_plan(rows: tuple[ToolReadiness, ...], *, output_format: str = "table") -> str:
    env_rows = tuple(row for row in rows if row.required_env or row.optional_env)
    if output_format == "json":
        return json.dumps(
            [
                {
                    "kind": row.kind,
                    "name": row.name,
                    "required_env": list(row.required_env),
                    "missing_env": list(row.missing_env),
                    "optional_env": list(row.optional_env),
                }
                for row in env_rows
            ],
            ensure_ascii=False,
            indent=2,
        )
    if output_format == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(
            buffer,
            fieldnames=("kind", "name", "required_env", "missing_env", "optional_env"),
            lineterminator="\n",
        )
        writer.writeheader()
        for row in env_rows:
            writer.writerow(
                {
                    "kind": row.kind,
                    "name": row.name,
                    "required_env": ", ".join(row.required_env),
                    "missing_env": ", ".join(row.missing_env),
                    "optional_env": ", ".join(row.optional_env),
                }
            )
        return buffer.getvalue().strip()
    if output_format == "markdown":
        lines = [
            "| Kind | Name | Required env names | Missing env names | Optional env names |",
            "|---|---|---|---|---|",
        ]
        for row in env_rows:
            lines.append(
                f"| {row.kind} | {_escape(row.name)} | {_escape(', '.join(row.required_env) or '-')} | "
                f"{_escape(', '.join(row.missing_env) or '-')} | {_escape(', '.join(row.optional_env) or '-')} |"
            )
        return "\n".join(lines)
    if output_format == "table":
        return _table(
            ("Kind", "Name", "Required env", "Missing env", "Optional env"),
            [
                (
                    row.kind,
                    _short(row.name, 34),
                    _short(", ".join(row.required_env) or "-", 30),
                    _short(", ".join(row.missing_env) or "-", 30),
                    _short(", ".join(row.optional_env) or "-", 42),
                )
                for row in env_rows
            ],
        )
    raise ValueError(f"Unsupported output format: {output_format}")


def _profile_repositories(profile_name: str) -> tuple[str, ...]:
    profile = find_search_profile(profile_name)
    repositories = list(expand_adapter_repositories(profile.adapter_profiles, profile.adapter_repositories))
    repositories.extend(profile.excluded_repositories)
    seen: set[str] = set()
    deduped: list[str] = []
    for repository in repositories:
        key = repository.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(repository)
    return tuple(deduped)


def _install_row(row: ToolReadiness) -> dict[str, str]:
    return {
        "kind": row.kind,
        "name": row.name,
        "readiness": row.readiness,
        "install": row.install_command or row.install_note or row.install_kind or "Review upstream docs.",
        "required_env": ", ".join(row.required_env),
        "docs_url": row.docs_url,
    }


def _rows_csv(rows: tuple[ToolReadiness, ...]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=(
            "kind",
            "name",
            "readiness",
            "executable",
            "executable_path",
            "install_kind",
            "install_command",
            "install_note",
            "docs_url",
            "required_env",
            "missing_env",
            "optional_env",
        ),
        lineterminator="\n",
    )
    writer.writeheader()
    for row in rows:
        payload = row.to_dict()
        payload["required_env"] = ", ".join(row.required_env)
        payload["missing_env"] = ", ".join(row.missing_env)
        payload["optional_env"] = ", ".join(row.optional_env)
        writer.writerow(payload)
    return buffer.getvalue().strip()


def _table(headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        widths = [max(width, len(cell)) for width, cell in zip(widths, row)]
    line = "  ".join(header.ljust(width) for header, width in zip(headers, widths))
    sep = "  ".join("-" * width for width in widths)
    body = ["  ".join(cell.ljust(width) for cell, width in zip(row, widths)) for row in rows]
    return "\n".join([line, sep, *body])


def _short(value: str, limit: int) -> str:
    compact = " ".join(str(value).split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def _escape(value: str) -> str:
    return " ".join(str(value).split()).replace("|", "\\|")
