from __future__ import annotations

import os
import shutil
from dataclasses import dataclass

from .adapter_runner import format_command
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
        }


def build_adapter_setup(adapter: AdapterSpec) -> AdapterSetup:
    executables = adapter.executable_names()
    executable_paths = tuple(shutil.which(executable) or "" for executable in executables)
    executable = ", ".join(executables)
    executable_path = ", ".join(path for path in executable_paths if path)
    missing_executables = tuple(
        executable for executable, path in zip(executables, executable_paths) if not path
    )
    missing_env = tuple(key for key in adapter.required_env if not os.environ.get(key))
    readiness = _readiness(adapter, executables, missing_executables, missing_env)

    return AdapterSetup(
        repository=adapter.repository,
        adapter_status=adapter.status,
        readiness=readiness,
        executable=executable,
        executable_path=executable_path,
        install_kind=adapter.install_kind,
        install_command=format_command(adapter.install_command) if adapter.install_command else "",
        install_note=adapter.install_note,
        docs_url=adapter.docs_url,
        required_env=adapter.required_env,
        missing_env=missing_env,
        optional_env=adapter.optional_env,
        command_hint=adapter.command_hint,
    )


def build_adapter_setups(adapters: tuple[AdapterSpec, ...]) -> tuple[AdapterSetup, ...]:
    return tuple(build_adapter_setup(adapter) for adapter in adapters)


def _readiness(
    adapter: AdapterSpec,
    executables: tuple[str, ...],
    missing_executables: tuple[str, ...],
    missing_env: tuple[str, ...],
) -> str:
    if adapter.status == "restricted":
        return "restricted"
    if not executables:
        return "not_configured"
    if missing_executables:
        return "missing"
    if missing_env:
        return "config_missing"
    return "ready"
