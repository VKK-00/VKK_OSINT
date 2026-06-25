from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .adapter_parsers import parse_adapter_output
from .adapter_runtime import (
    render_adapter_command,
    render_adapter_output_dir_args,
    resolve_adapter_runtime,
)
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

    runtime = resolve_adapter_runtime(adapter, which=shutil.which)
    command = render_adapter_command(adapter, target, route=runtime.route)
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
    command_input = adapter.render_command_input(target)
    command_input_lines = _line_count(command_input)
    if not execute:
        return (
            Finding(
                module="external-adapter",
                source=adapter.repository,
                target=target.value,
                status="planned",
                confidence="not_checked",
                evidence=f"Dry run command: {command_text}",
                metadata={
                    **adapter.to_dict(),
                    "command": command_text,
                    "stdin_lines": str(command_input_lines),
                },
            ),
        )

    missing_env = tuple(key for key in adapter.required_env if not os.environ.get(key))
    if missing_env:
        missing = ", ".join(missing_env)
        return (
            Finding(
                module="external-adapter",
                source=adapter.repository,
                target=target.value,
                status="config_missing",
                confidence="high",
                evidence=f"Required environment variable(s) are not set: {missing}",
                metadata={
                    **adapter.to_dict(),
                    "command": command_text,
                    "missing_env": missing,
                    "stdin_lines": str(command_input_lines),
                },
            ),
        )

    executable = runtime.executable_path or shutil.which(command[0])
    if not executable:
        return (
            Finding(
                module="external-adapter",
                source=adapter.repository,
                target=target.value,
                status="missing",
                confidence="high",
                evidence=f"Executable is not available on PATH: {command[0]}",
                metadata={**adapter.to_dict(), "command": command_text, "stdin_lines": str(command_input_lines)},
            ),
        )
    if runtime.readiness != "ready":
        return (
            Finding(
                module="external-adapter",
                source=adapter.repository,
                target=target.value,
                status=runtime.readiness,
                confidence="high",
                evidence=runtime.note or f"Executable did not match expected upstream CLI: {executable}",
                metadata={
                    **adapter.to_dict(),
                    "command": command_text,
                    "executable_path": executable,
                    "execution_route": runtime.route,
                    "stdin_lines": str(command_input_lines),
                },
            ),
        )

    output_dir_context: tempfile.TemporaryDirectory[str] | None = None
    output_dir = ""
    process_cwd = None
    process_env = None
    generated_snapshot: dict[Path, tuple[int, int]] | None = None
    if adapter.working_dir_env:
        process_cwd = os.environ.get(adapter.working_dir_env) or None
    if adapter.generated_output_patterns:
        if adapter.generated_output_base_env:
            output_root = Path(os.environ[adapter.generated_output_base_env])
            if adapter.generated_output_subdir:
                output_root = output_root / adapter.generated_output_subdir
            output_dir = str(output_root)
            generated_snapshot = _snapshot_generated_outputs(output_dir, adapter.generated_output_patterns)
        else:
            output_dir_context = tempfile.TemporaryDirectory(prefix="osint-toolkit-adapter-")
            output_dir = output_dir_context.name
            if adapter.generated_output_workdir:
                process_cwd = output_dir
                process_env = os.environ.copy()
                process_env["HOME"] = output_dir
                process_env["USERPROFILE"] = output_dir
            output_file = str(Path(output_dir) / "adapter-output.json")
            command = render_adapter_command(adapter, target, route=runtime.route, output_dir=output_dir)
            command = (
                *command,
                *render_adapter_output_dir_args(adapter, output_dir, route=runtime.route),
                *adapter.render_output_file_args(output_file),
            )
            command_text = format_command(command)

    try:
        result = subprocess.run(
            [executable, *command[1:]],
            input=command_input or None,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
            cwd=process_cwd,
            env=process_env,
        )
    except subprocess.TimeoutExpired as exc:
        if output_dir_context:
            output_dir_context.cleanup()
        return (
            Finding(
                module="external-adapter",
                source=adapter.repository,
                target=target.value,
                status="timeout",
                confidence="low",
                evidence=f"Adapter timed out after {timeout} seconds.",
                metadata={
                    **adapter.to_dict(),
                    "stdout": _truncate(exc.stdout),
                    "stderr": _truncate(exc.stderr),
                    "stdin_lines": str(command_input_lines),
                },
            ),
        )
    except OSError as exc:
        if output_dir_context:
            output_dir_context.cleanup()
        return (
            Finding(
                module="external-adapter",
                source=adapter.repository,
                target=target.value,
                status="error",
                confidence="low",
                evidence=f"Adapter execution failed: {exc}",
                metadata={
                    **adapter.to_dict(),
                    "command": command_text,
                    "stdin_lines": str(command_input_lines),
                },
            ),
        )

    generated_output, generated_count = _read_generated_outputs(
        output_dir,
        adapter.generated_output_patterns,
        generated_snapshot,
    )
    if output_dir_context:
        output_dir_context.cleanup()

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
            "execution_route": runtime.route,
            "returncode": str(result.returncode),
            "stderr": _truncate(result.stderr),
            "generated_output_files": str(generated_count),
            "stdin_lines": str(command_input_lines),
        },
    )
    parsed_stdout = "\n".join(part for part in (result.stdout, generated_output) if part)
    parsed = parse_adapter_output(adapter.repository, target, parsed_stdout, result.stderr)
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


def _snapshot_generated_outputs(output_dir: str, patterns: tuple[str, ...]) -> dict[Path, tuple[int, int]]:
    if not output_dir or not patterns:
        return {}

    root = Path(output_dir)
    if not root.exists():
        return {}

    snapshot: dict[Path, tuple[int, int]] = {}
    for pattern in patterns:
        for path in root.rglob(pattern):
            if not path.is_file():
                continue
            stat = path.stat()
            snapshot[path] = (stat.st_mtime_ns, stat.st_size)
    return snapshot


def _read_generated_outputs(
    output_dir: str,
    patterns: tuple[str, ...],
    previous: dict[Path, tuple[int, int]] | None = None,
) -> tuple[str, int]:
    if not output_dir or not patterns:
        return "", 0

    root = Path(output_dir)
    if not root.exists():
        return "", 0

    parts: list[str] = []
    count = 0
    for pattern in patterns:
        for path in sorted(root.rglob(pattern)):
            if not path.is_file():
                continue
            if previous is not None:
                stat = path.stat()
                if previous.get(path) == (stat.st_mtime_ns, stat.st_size):
                    continue
            count += 1
            parts.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts), count


def _line_count(value: str) -> int:
    return len([line for line in value.splitlines() if line.strip()])
