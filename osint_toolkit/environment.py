from __future__ import annotations

import os
from collections.abc import Iterable


OSINT_ENV_KEYS: tuple[str, ...] = (
    "AMASS_CONFIG",
    "BBOT_DOCKER_CONFIG_DIR",
    "BBOT_DOCKER_IMAGE",
    "BBOT_RUNNER",
    "BLACKBIRD_DIR",
    "BLACKBIRD_PYTHON",
    "CENSYS_API_ID",
    "CENSYS_API_SECRET",
    "DETECTDEE_DATA",
    "EMAILREP_API_KEY",
    "GOOGLE_API_KEY",
    "H8MAIL_CONFIG",
    "HIBP_API_KEY",
    "HUNTERIO_API_KEY",
    "PWNED_API_KEY",
    "SHODAN_API_KEY",
    "SOCIAL_ANALYZER_APP_JS",
    "SPIDERFOOT_PYTHON",
    "SPIDERFOOT_SF_PATH",
    "SUBFINDER_CONFIG",
    "SUBFINDER_PROVIDER_CONFIG",
    "THEHARVESTER_API_KEY",
    "VIRUSTOTAL_API_KEY",
)


def refresh_runtime_environment(
    keys: Iterable[str] = OSINT_ENV_KEYS,
    *,
    refresh_path: bool = True,
) -> tuple[str, ...]:
    """Merge Windows user/machine environment changes into this process.

    Long-running terminals and the toolbox backend do not see PATH/env updates made
    by installers until they are restarted. This keeps explicit process values as
    overrides, but pulls newly installed user-local tools and configured OSINT env
    variables from the registry when running on Windows.
    """

    if os.name != "nt":
        return ()

    applied: list[str] = []
    if refresh_path:
        current_path = os.environ.get("PATH") or os.environ.get("Path") or ""
        machine_path = _read_windows_registry_env("machine", "Path")
        user_path = _read_windows_registry_env("user", "Path")
        merged_path = _merge_path_values(machine_path, user_path, current_path)
        if merged_path and merged_path != current_path:
            os.environ["PATH"] = merged_path
            applied.append("PATH")

    for key in keys:
        if os.environ.get(key):
            continue
        value = _read_windows_registry_env("user", key) or _read_windows_registry_env("machine", key)
        if not value:
            continue
        os.environ[key] = os.path.expandvars(value)
        applied.append(key)
    return tuple(applied)


def _merge_path_values(*values: str) -> str:
    parts: list[str] = []
    seen: set[str] = set()
    for value in values:
        for raw_part in value.split(os.pathsep):
            part = os.path.expandvars(raw_part.strip().strip('"'))
            if not part:
                continue
            key = os.path.normcase(os.path.normpath(part))
            if key in seen:
                continue
            seen.add(key)
            parts.append(part)
    return os.pathsep.join(parts)


def _read_windows_registry_env(scope: str, name: str) -> str:
    try:
        import winreg
    except ImportError:
        return ""

    if scope == "user":
        root = winreg.HKEY_CURRENT_USER
        subkey = "Environment"
    elif scope == "machine":
        root = winreg.HKEY_LOCAL_MACHINE
        subkey = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
    else:
        raise ValueError(f"Unsupported environment scope: {scope}")

    try:
        with winreg.OpenKey(root, subkey) as key:
            value, _value_type = winreg.QueryValueEx(key, name)
    except OSError:
        return ""
    if not isinstance(value, str):
        return ""
    return value.strip()
