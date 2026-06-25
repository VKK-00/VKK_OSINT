from __future__ import annotations

import subprocess
from dataclasses import dataclass

from .adapters import AdapterSpec


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
    if not missing_markers:
        return ExecutableProbeResult()
    return ExecutableProbeResult(
        readiness="wrong_executable",
        note=(
            f"PATH resolves {adapter.executable_names()[0] if adapter.executable_names() else 'the executable'}, "
            f"but its probe output does not look like {adapter.repository}. "
            f"Missing expected marker(s): {', '.join(missing_markers)}."
        ),
    )
