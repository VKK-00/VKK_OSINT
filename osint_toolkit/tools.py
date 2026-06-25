from __future__ import annotations

import csv
import io
import json
import shutil
import shlex
import subprocess
from dataclasses import dataclass

from .adapter_setup import build_adapter_setup
from .adapters import expand_adapter_repositories, find_adapter
from .search import LOCAL_TOOLS, SearchProfile, find_search_profile

INSTALLABLE_READINESS = {"missing"}
SKIPPED_READINESS = {"ready", "excluded", "restricted"}
ALLOWED_INSTALL_EXECUTABLES = {"pipx", "go", "winget", "choco"}


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
    readiness_note: str = ""
    execution_route: str = ""

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
            "readiness_note": self.readiness_note,
            "execution_route": self.execution_route,
        }


@dataclass(frozen=True)
class ToolInstallResult:
    kind: str
    name: str
    readiness: str
    action: str
    status: str
    command: str = ""
    note: str = ""
    returncode: int | None = None
    docs_url: str = ""
    required_env: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "name": self.name,
            "readiness": self.readiness,
            "action": self.action,
            "status": self.status,
            "command": self.command,
            "note": self.note,
            "returncode": self.returncode,
            "docs_url": self.docs_url,
            "required_env": list(self.required_env),
        }


def build_profile_tool_readiness(
    profile_name: str,
    *,
    custom_profiles: tuple[SearchProfile, ...] = (),
) -> tuple[ToolReadiness, ...]:
    profile = find_search_profile(profile_name, custom_profiles=custom_profiles)
    excluded_repositories = {repository.lower() for repository in profile.excluded_repositories}
    rows: list[ToolReadiness] = []
    for repository in _profile_repositories(profile_name, custom_profiles=custom_profiles):
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
                readiness_note=setup.readiness_note,
                execution_route=setup.execution_route,
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


def build_tool_install_results(
    rows: tuple[ToolReadiness, ...],
    *,
    execute: bool = False,
    timeout: float = 300.0,
) -> tuple[ToolInstallResult, ...]:
    results = tuple(_tool_install_result(row) for row in rows if row.readiness not in SKIPPED_READINESS)
    if not execute:
        return results
    executed: list[ToolInstallResult] = []
    for result in results:
        if result.status != "planned":
            executed.append(result)
            continue
        executed.append(_execute_install_result(result, timeout=timeout))
    return tuple(executed)


def format_tool_install_results(
    results: tuple[ToolInstallResult, ...],
    *,
    output_format: str = "table",
) -> str:
    if output_format == "json":
        return json.dumps([row.to_dict() for row in results], ensure_ascii=False, indent=2)
    if output_format == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(
            buffer,
            fieldnames=(
                "kind",
                "name",
                "readiness",
                "action",
                "status",
                "command",
                "note",
                "returncode",
                "required_env",
                "docs_url",
            ),
            lineterminator="\n",
        )
        writer.writeheader()
        for row in results:
            payload = row.to_dict()
            payload["required_env"] = ", ".join(row.required_env)
            writer.writerow(payload)
        return buffer.getvalue().strip()
    if output_format == "markdown":
        lines = [
            "| Kind | Name | Readiness | Action | Status | Command | Note |",
            "|---|---|---|---|---|---|---|",
        ]
        for row in results:
            lines.append(
                f"| {row.kind} | {_escape(row.name)} | {row.readiness} | {row.action} | {row.status} | "
                f"{_escape(row.command or '-')} | {_escape(row.note or '-')} |"
            )
        return "\n".join(lines)
    if output_format == "table":
        return _table(
            ("Kind", "Name", "Ready", "Action", "Status", "Command / note"),
            [
                (
                    row.kind,
                    _short(row.name, 34),
                    row.readiness,
                    row.action,
                    row.status,
                    _short(row.command or row.note or "-", 76),
                )
                for row in results
            ],
        )
    raise ValueError(f"Unsupported output format: {output_format}")


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
            action = _tool_action(row)
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
                    _short(_tool_action(row), 72),
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


def _profile_repositories(
    profile_name: str,
    *,
    custom_profiles: tuple[SearchProfile, ...] = (),
) -> tuple[str, ...]:
    profile = find_search_profile(profile_name, custom_profiles=custom_profiles)
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
        "install": _tool_action(row),
        "required_env": ", ".join(row.required_env),
        "docs_url": row.docs_url,
    }


def _tool_action(row: ToolReadiness) -> str:
    return row.readiness_note or row.install_command or row.install_note or row.install_kind or "Review upstream docs."


def _tool_install_result(row: ToolReadiness) -> ToolInstallResult:
    if row.readiness in INSTALLABLE_READINESS and row.install_command:
        command_args = _command_args(row.install_command)
        if command_args and command_args[0].lower() in ALLOWED_INSTALL_EXECUTABLES:
            return ToolInstallResult(
                kind=row.kind,
                name=row.name,
                readiness=row.readiness,
                action="install",
                status="planned",
                command=row.install_command,
                note="Dry-run. Add --execute to run this allowlisted install command.",
                docs_url=row.docs_url,
                required_env=row.required_env,
            )
        return ToolInstallResult(
            kind=row.kind,
            name=row.name,
            readiness=row.readiness,
            action="manual-install",
            status="manual",
            command=row.install_command,
            note="Install command is not in the allowlist; review upstream docs before running it.",
            docs_url=row.docs_url,
            required_env=row.required_env,
        )
    if row.readiness == "config_missing":
        return ToolInstallResult(
            kind=row.kind,
            name=row.name,
            readiness=row.readiness,
            action="configure-env",
            status="manual",
            note=f"Set required environment variable name(s): {', '.join(row.missing_env or row.required_env)}",
            docs_url=row.docs_url,
            required_env=row.required_env,
        )
    if row.readiness in {"wrong_executable", "runtime_error"}:
        note = row.readiness_note or row.install_note or "Executable is present but is not currently runnable."
        return ToolInstallResult(
            kind=row.kind,
            name=row.name,
            readiness=row.readiness,
            action="fix-runtime",
            status="skipped",
            note=_short(note, 500),
            docs_url=row.docs_url,
            required_env=row.required_env,
        )
    return ToolInstallResult(
        kind=row.kind,
        name=row.name,
        readiness=row.readiness,
        action="review",
        status="manual",
        command=row.install_command,
        note=_tool_action(row),
        docs_url=row.docs_url,
        required_env=row.required_env,
    )


def _execute_install_result(result: ToolInstallResult, *, timeout: float) -> ToolInstallResult:
    args = _command_args(result.command)
    if not args:
        return _replace_install_result(result, status="failed", note="Install command could not be parsed.", returncode=2)
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _replace_install_result(result, status="failed", note=f"Install command failed to start: {exc}", returncode=2)
    if completed.returncode == 0:
        return _replace_install_result(
            result,
            status="installed",
            note="Install command completed. Re-run tools doctor to verify readiness.",
            returncode=0,
        )
    output = _short(" ".join(part for part in (completed.stdout, completed.stderr) if part), 500)
    return _replace_install_result(
        result,
        status="failed",
        note=output or "Install command failed without output.",
        returncode=completed.returncode,
    )


def _replace_install_result(
    result: ToolInstallResult,
    *,
    status: str,
    note: str,
    returncode: int | None,
) -> ToolInstallResult:
    return ToolInstallResult(
        kind=result.kind,
        name=result.name,
        readiness=result.readiness,
        action=result.action,
        status=status,
        command=result.command,
        note=note,
        returncode=returncode,
        docs_url=result.docs_url,
        required_env=result.required_env,
    )


def _command_args(command: str) -> tuple[str, ...]:
    if not command.strip():
        return ()
    try:
        return tuple(shlex.split(command, posix=False))
    except ValueError:
        return ()


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
            "readiness_note",
            "execution_route",
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
