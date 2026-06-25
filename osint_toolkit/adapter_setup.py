from __future__ import annotations

import os
import shutil
from dataclasses import dataclass

from .adapter_runner import format_command
from .adapter_runtime import resolve_adapter_runtime
from .adapters import AdapterSpec


@dataclass(frozen=True)
class AdapterSetup:
    repository: str
    adapter_status: str
    readiness: str
    executable: str
    executable_path: str
    install_kind: str
    install_command: str
    install_note: str
    docs_url: str
    required_env: tuple[str, ...]
    missing_env: tuple[str, ...]
    optional_env: tuple[str, ...]
    command_hint: str
    readiness_note: str = ""
    execution_route: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "repository": self.repository,
            "adapter_status": self.adapter_status,
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
            "command_hint": self.command_hint,
            "readiness_note": self.readiness_note,
            "execution_route": self.execution_route,
        }


def build_adapter_setup(adapter: AdapterSpec) -> AdapterSetup:
    runtime = resolve_adapter_runtime(adapter, which=shutil.which)
    missing_env = tuple(key for key in adapter.required_env if not os.environ.get(key))
    readiness = _readiness(
        adapter,
        runtime.readiness,
        missing_env,
    )

    return AdapterSetup(
        repository=adapter.repository,
        adapter_status=adapter.status,
        readiness=readiness,
        executable=runtime.executable,
        executable_path=runtime.executable_path,
        install_kind=adapter.install_kind,
        install_command=format_command(adapter.install_command) if adapter.install_command else "",
        install_note=adapter.install_note,
        docs_url=adapter.docs_url,
        required_env=adapter.required_env,
        missing_env=missing_env,
        optional_env=adapter.optional_env,
        command_hint=adapter.command_hint,
        readiness_note=runtime.note,
        execution_route=runtime.route,
    )


def build_adapter_setups(adapters: tuple[AdapterSpec, ...]) -> tuple[AdapterSetup, ...]:
    return tuple(build_adapter_setup(adapter) for adapter in adapters)


def _readiness(
    adapter: AdapterSpec,
    runtime_readiness: str,
    missing_env: tuple[str, ...],
) -> str:
    if adapter.status == "restricted":
        return "restricted"
    if runtime_readiness != "ready":
        return runtime_readiness
    if missing_env:
        return "config_missing"
    return "ready"
