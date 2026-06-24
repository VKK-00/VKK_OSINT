from __future__ import annotations

import shutil
import subprocess

from .adapter_parsers import parse_adapter_output
from .adapters import find_adapter
from .engine import Finding, ScanTarget


def run_adapter(
    repository: str,
    target: ScanTarget,
    *,
    execute: bool = False,
    allow_restricted: bool = False,
    timeout: float = 60.0,
) -> Finding:
    return run_adapter_findings(
        repository,
        target,
        execute=execute,
        allow_restricted=allow_restricted,
        timeout=timeout,
    )[0]


def run_adapter_findings(
    repository: str,
    target: ScanTarget,
    *,
    execute: bool = False,
    allow_restricted: bool = False,
    timeout: float = 60.0,
) -> tuple[Finding, ...]:
    adapter = find_adapter(repository)
    if adapter.status == "restricted" and not allow_restricted:
        return (
            Finding(
                module="external-adapter",
                source=adapter.repository,
                target=target.value,
                status="restricted",
                confidence="not_checked",
                evidence="Adapter is restricted. Re-run with --allow-restricted after confirming lawful scope.",
                metadata=adapter.to_dict(),
            ),
        )

    command = adapter.render_command(target)
    if not command:
        return (
            Finding(
                module="external-adapter",
                source=adapter.repository,
                target=target.value,
                status="unsupported",
                confidence="not_checked",
                evidence="No executable command template is configured for this adapter and target kind.",
                metadata=adapter.to_dict(),
            ),
        )

    command_text = format_command(command)
    if not execute:
        return (
            Finding(
                module="external-adapter",
                source=adapter.repository,
                target=target.value,
                status="planned",
                confidence="not_checked",
                evidence=f"Dry run command: {command_text}",
                metadata={**adapter.to_dict(), "command": command_text},
            ),
        )

    executable = shutil.which(command[0])
    if not executable:
        return (
            Finding(
                module="external-adapter",
                source=adapter.repository,
                target=target.value,
                status="missing",
                confidence="high",
                evidence=f"Executable is not available on PATH: {command[0]}",
                metadata={**adapter.to_dict(), "command": command_text},
            ),
        )

    try:
        result = subprocess.run(
            [executable, *command[1:]],
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return (
            Finding(
                module="external-adapter",
                source=adapter.repository,
                target=target.value,
                status="timeout",
                confidence="low",
                evidence=f"Adapter timed out after {timeout} seconds.",
                metadata={**adapter.to_dict(), "stdout": _truncate(exc.stdout), "stderr": _truncate(exc.stderr)},
            ),
        )

    status = "completed" if result.returncode == 0 else "error"
    evidence = _truncate(result.stdout) or _truncate(result.stderr) or f"Exit code {result.returncode}"
    summary = Finding(
        module="external-adapter",
        source=adapter.repository,
        target=target.value,
        status=status,
        confidence="unknown",
        evidence=evidence,
        metadata={
            **adapter.to_dict(),
            "command": command_text,
            "returncode": str(result.returncode),
            "stderr": _truncate(result.stderr),
        },
    )
    parsed = parse_adapter_output(adapter.repository, target, result.stdout, result.stderr)
    return (summary, *parsed)


def format_command(command: tuple[str, ...]) -> str:
    return " ".join(_quote(part) for part in command)


def _quote(part: str) -> str:
    if not part or any(char.isspace() for char in part):
        return '"' + part.replace('"', '\\"') + '"'
    return part


def _truncate(value: str | bytes | None, limit: int = 1200) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    compact = " ".join(value.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1] + "…"
