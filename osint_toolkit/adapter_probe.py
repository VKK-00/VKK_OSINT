from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

from .adapters import AdapterSpec

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


@dataclass(frozen=True)
class ExecutableProbeResult:
    readiness: str = "ready"
    note: str = ""


def probe_adapter_executable(
    adapter: AdapterSpec,
    executable_paths: tuple[str, ...],
    *,
    timeout: float | None = None,
) -> ExecutableProbeResult:
    if not adapter.executable_probe_required:
        return ExecutableProbeResult()
    executable = next((path for path in executable_paths if path), "")
    if not executable:
        return ExecutableProbeResult()
    probe_args = adapter.executable_probe_args or ("--help",)
    probe_timeout = adapter.executable_probe_timeout if timeout is None else timeout
    try:
        completed = subprocess.run(
            (executable, *probe_args),
            capture_output=True,
            text=True,
            timeout=probe_timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ExecutableProbeResult(
            readiness="wrong_executable",
            note=f"Could not verify {adapter.repository} executable: {exc}",
        )
    output = f"{completed.stdout}\n{completed.stderr}".lower()
    missing_markers = tuple(
        marker for marker in adapter.executable_probe_required if marker.lower() not in output
    )
    if missing_markers:
        return ExecutableProbeResult(
            readiness="wrong_executable",
            note=(
                f"PATH resolves {adapter.executable_names()[0] if adapter.executable_names() else 'the executable'}, "
                f"but its probe output does not look like {adapter.repository}. "
                f"Missing expected marker(s): {', '.join(missing_markers)}."
            ),
        )
    if adapter.executable_runtime_probe_args:
        return _runtime_probe(adapter, executable, probe_timeout)
    return ExecutableProbeResult()


def _runtime_probe(adapter: AdapterSpec, executable: str, timeout: float) -> ExecutableProbeResult:
    try:
        completed = subprocess.run(
            (executable, *adapter.executable_runtime_probe_args),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ExecutableProbeResult(
            readiness="runtime_error",
            note=f"Could not start {adapter.repository} runtime probe: {exc}",
        )
    output = f"{completed.stdout}\n{completed.stderr}"
    normalized = output.lower()
    missing_markers = tuple(
        marker for marker in adapter.executable_runtime_probe_required if marker.lower() not in normalized
    )
    if completed.returncode == 0 and not missing_markers:
        return ExecutableProbeResult()
    note = _compact_output(output)
    if missing_markers:
        note = f"Runtime probe missing expected marker(s): {', '.join(missing_markers)}. {note}".strip()
    return ExecutableProbeResult(
        readiness="runtime_error",
        note=f"{adapter.repository} executable exists but failed a non-network dry-run probe. {note}".strip(),
    )


def _compact_output(value: str, *, limit: int = 500) -> str:
    compact = " ".join(ANSI_RE.sub("", value).split())
    if len(compact) <= limit:
        return compact
    head = compact[:200].rstrip()
    tail = compact[-(limit - len(head) - 5) :].lstrip()
    return f"{head} ... {tail}"
