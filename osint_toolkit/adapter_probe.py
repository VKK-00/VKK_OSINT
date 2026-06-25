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
    timeout: float = 2.0,
) -> ExecutableProbeResult:
    if adapter.repository == "projectdiscovery/httpx":
        return _probe_projectdiscovery_httpx(executable_paths, timeout=timeout)
    return ExecutableProbeResult()


def _probe_projectdiscovery_httpx(
    executable_paths: tuple[str, ...],
    *,
    timeout: float,
) -> ExecutableProbeResult:
    executable = next((path for path in executable_paths if path), "")
    if not executable:
        return ExecutableProbeResult()
    try:
        completed = subprocess.run(
            (executable, "-h"),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ExecutableProbeResult(
            readiness="wrong_executable",
            note=f"Could not verify ProjectDiscovery httpx executable: {exc}",
        )
    output = f"{completed.stdout}\n{completed.stderr}".lower()
    if "-tech-detect" in output and "-status-code" in output:
        return ExecutableProbeResult()
    return ExecutableProbeResult(
        readiness="wrong_executable",
        note=(
            "PATH resolves httpx, but its help output does not look like ProjectDiscovery httpx "
            "with -tech-detect and -status-code flags."
        ),
    )
