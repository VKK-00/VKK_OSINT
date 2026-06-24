from __future__ import annotations

import shutil

from .adapters import ADAPTERS, AdapterSpec
from .engine import Finding


def inspect_adapters(status: str | None = None) -> tuple[Finding, ...]:
    adapters = [adapter for adapter in ADAPTERS if status is None or adapter.status == status]
    return tuple(_adapter_to_finding(adapter) for adapter in adapters)


def _adapter_to_finding(adapter: AdapterSpec) -> Finding:
    command = adapter.command_template
    if adapter.status == "restricted":
        status = "restricted"
        confidence = "not_checked"
        evidence = "Restricted adapter; execution requires explicit scope review and --allow-restricted."
    elif not command:
        status = "not_configured"
        confidence = "high"
        evidence = "No executable command template is configured yet."
    else:
        executable = shutil.which(command[0])
        if executable:
            status = "available"
            confidence = "high"
            evidence = f"Executable found: {executable}"
        else:
            status = "missing"
            confidence = "high"
            evidence = f"Executable is not available on PATH: {command[0]}"

    return Finding(
        module="adapter-doctor",
        source=adapter.repository,
        target=adapter.integration,
        status=status,
        confidence=confidence,
        evidence=evidence,
        metadata=adapter.to_dict(),
    )

