from __future__ import annotations

from .adapter_setup import build_adapter_setup
from .adapters import ADAPTERS, AdapterSpec
from .engine import Finding


def inspect_adapters(status: str | None = None) -> tuple[Finding, ...]:
    adapters = [adapter for adapter in ADAPTERS if status is None or adapter.status == status]
    return tuple(_adapter_to_finding(adapter) for adapter in adapters)


def _adapter_to_finding(adapter: AdapterSpec) -> Finding:
    setup = build_adapter_setup(adapter)
    executables = adapter.executable_names()
    if adapter.status == "restricted":
        status = "restricted"
        confidence = "not_checked"
        evidence = setup.install_note or "Restricted adapter; execution requires explicit scope review and --allow-restricted."
    elif not executables:
        status = "not_configured"
        confidence = "high"
        evidence = setup.install_note or "No executable command template is configured yet."
    elif setup.readiness in {"wrong_executable", "runtime_error"}:
        status = setup.readiness
        confidence = "high"
        setup_hint = setup.install_command or setup.install_note
        install_hint = f" Setup: {setup_hint}" if setup_hint else ""
        evidence = (
            setup.readiness_note
            or f"Executable found but did not match the expected upstream CLI: {setup.executable_path}."
        ) + install_hint
    else:
        if setup.executable_path:
            if setup.missing_env:
                status = "config_missing"
                confidence = "medium"
                evidence = f"Executable found but required environment is missing: {', '.join(setup.missing_env)}"
            else:
                status = "available"
                confidence = "high"
                evidence = f"Executable found: {setup.executable_path}"
        else:
            status = "missing"
            confidence = "high"
            setup_hint = setup.install_command or setup.install_note
            install_hint = f" Setup: {setup_hint}" if setup_hint else ""
            evidence = f"Executable is not available on PATH: {', '.join(executables)}.{install_hint}"

    return Finding(
        module="adapter-doctor",
        source=adapter.repository,
        target=adapter.integration,
        status=status,
        confidence=confidence,
        evidence=evidence,
        metadata={**adapter.to_dict(), **{f"setup_{key}": str(value) for key, value in setup.to_dict().items()}},
    )
