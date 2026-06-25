from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .adapter_probe import probe_adapter_executable
from .adapters import AdapterSpec
from .engine import ScanTarget

BBOT_REPOSITORIES = {
    "blacklanternsecurity/bbot",
    "blacklanternsecurity/bbot-passive-web",
}
BBOT_DOCKER_ROUTE = "bbot-docker"
BBOT_DOCKER_IMAGE = "blacklanternsecurity/bbot:stable"
BBOT_DOCKER_OUTPUT_DIR = "/root/.bbot/scans"
BBOT_DOCKER_CONFIG_DIR = "/root/.config/bbot"


@dataclass(frozen=True)
class AdapterRuntime:
    route: str
    executable: str
    executable_path: str
    readiness: str
    note: str = ""


def resolve_adapter_runtime(
    adapter: AdapterSpec,
    *,
    which: Callable[[str], str | None] = shutil.which,
) -> AdapterRuntime:
    executables = adapter.executable_names()
    if not executables:
        return AdapterRuntime(
            route="none",
            executable="",
            executable_path="",
            readiness="not_configured",
        )

    executable_paths = tuple(which(executable) or "" for executable in executables)
    executable = ", ".join(executables)
    executable_path = ", ".join(path for path in executable_paths if path)
    missing_executables = tuple(
        executable for executable, path in zip(executables, executable_paths) if not path
    )

    if not missing_executables:
        probe = probe_adapter_executable(adapter, executable_paths)
        if probe.readiness == "ready":
            return AdapterRuntime(
                route="native",
                executable=executable,
                executable_path=executable_path,
                readiness="ready",
                note=probe.note,
            )
        docker = _bbot_docker_runtime(adapter, which=which, native_note=probe.note)
        if docker:
            return docker
        return AdapterRuntime(
            route="native",
            executable=executable,
            executable_path=executable_path,
            readiness=probe.readiness,
            note=probe.note,
        )

    docker = _bbot_docker_runtime(
        adapter,
        which=which,
        native_note=f"Native executable is missing: {', '.join(missing_executables)}.",
    )
    if docker:
        return docker
    return AdapterRuntime(
        route="native",
        executable=executable,
        executable_path=executable_path,
        readiness="missing",
        note="",
    )


def render_adapter_command(
    adapter: AdapterSpec,
    target: ScanTarget,
    *,
    route: str = "",
    output_dir: str = "",
) -> tuple[str, ...]:
    if route == BBOT_DOCKER_ROUTE and adapter.repository in BBOT_REPOSITORIES:
        return _render_bbot_docker_command(adapter, target, output_dir=output_dir)
    return adapter.render_command(target)


def render_adapter_output_dir_args(
    adapter: AdapterSpec,
    output_dir: str,
    *,
    route: str = "",
) -> tuple[str, ...]:
    if route == BBOT_DOCKER_ROUTE and adapter.repository in BBOT_REPOSITORIES:
        return adapter.render_output_dir_args(BBOT_DOCKER_OUTPUT_DIR)
    return adapter.render_output_dir_args(output_dir)


def _bbot_docker_runtime(
    adapter: AdapterSpec,
    *,
    which: Callable[[str], str | None],
    native_note: str,
) -> AdapterRuntime | None:
    if adapter.repository not in BBOT_REPOSITORIES or not _bbot_docker_enabled():
        return None
    docker_path = which("docker") or ""
    if not docker_path:
        return None
    probe = _probe_docker(docker_path)
    if probe.readiness != "ready":
        return None
    note = "Using Docker BBOT route"
    if native_note:
        note += f" because native BBOT is not runnable: {native_note}"
    return AdapterRuntime(
        route=BBOT_DOCKER_ROUTE,
        executable="docker",
        executable_path=docker_path,
        readiness="ready",
        note=note,
    )


def _bbot_docker_enabled() -> bool:
    mode = os.environ.get("BBOT_RUNNER", "auto").strip().lower()
    if mode in {"native", "local", "pipx"}:
        return False
    if mode in {"docker", "container"}:
        return True
    return os.name == "nt"


def _probe_docker(docker_path: str) -> AdapterRuntime:
    try:
        completed = subprocess.run(
            (docker_path, "--version"),
            capture_output=True,
            text=True,
            timeout=10.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return AdapterRuntime(
            route=BBOT_DOCKER_ROUTE,
            executable="docker",
            executable_path=docker_path,
            readiness="runtime_error",
            note=f"Docker executable is available but could not be verified: {exc}",
        )
    output = f"{completed.stdout}\n{completed.stderr}"
    if completed.returncode == 0 and "docker" in output.lower():
        return AdapterRuntime(
            route=BBOT_DOCKER_ROUTE,
            executable="docker",
            executable_path=docker_path,
            readiness="ready",
        )
    return AdapterRuntime(
        route=BBOT_DOCKER_ROUTE,
        executable="docker",
        executable_path=docker_path,
        readiness="wrong_executable",
        note="PATH resolves docker but its --version output did not look like Docker.",
    )


def _render_bbot_docker_command(
    adapter: AdapterSpec,
    target: ScanTarget,
    *,
    output_dir: str = "",
) -> tuple[str, ...]:
    native = adapter.render_command(target)
    if not native:
        return ()
    image = os.environ.get("BBOT_DOCKER_IMAGE", BBOT_DOCKER_IMAGE).strip() or BBOT_DOCKER_IMAGE
    mount_source = output_dir or "<output_dir>"
    config_source = _bbot_docker_config_source()
    return (
        "docker",
        "run",
        "--rm",
        "-v",
        f"{mount_source}:{BBOT_DOCKER_OUTPUT_DIR}",
        "-v",
        f"{config_source}:{BBOT_DOCKER_CONFIG_DIR}",
        image,
        *native[1:],
    )


def _bbot_docker_config_source() -> str:
    configured = os.environ.get("BBOT_DOCKER_CONFIG_DIR", "").strip()
    if configured:
        return configured
    return str(Path.home() / ".config" / "bbot")
