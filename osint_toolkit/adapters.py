from __future__ import annotations

from dataclasses import dataclass

from .engine import ScanTarget


@dataclass(frozen=True)
class AdapterSpec:
    repository: str
    capability: str
    integration: str
    license: str
    status: str
    command_hint: str = ""
    note: str = ""
    target_kinds: tuple[str, ...] = ()
    command_template: tuple[str, ...] = ()
    install_kind: str = ""
    install_command: tuple[str, ...] = ()
    install_note: str = ""
    docs_url: str = ""
    required_env: tuple[str, ...] = ()
    optional_env: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, str]:
        return {
            "repository": self.repository,
            "capability": self.capability,
            "integration": self.integration,
            "license": self.license,
            "status": self.status,
            "command_hint": self.command_hint,
            "note": self.note,
            "target_kinds": ", ".join(self.target_kinds),
            "command_template": " ".join(self.command_template),
            "install_kind": self.install_kind,
            "install_command": " ".join(self.install_command),
            "install_note": self.install_note,
            "docs_url": self.docs_url,
            "required_env": ", ".join(self.required_env),
            "optional_env": ", ".join(self.optional_env),
        }

    def render_command(self, target: ScanTarget) -> tuple[str, ...]:
        if self.target_kinds and target.kind not in self.target_kinds:
            return ()
        return tuple(
            part.format(target_value=target.value, target_kind=target.kind, region=target.region)
            for part in self.command_template
        )


@dataclass(frozen=True)
class AdapterProfile:
    name: str
    title: str
    description: str
    target_kinds: tuple[str, ...]
    repositories: tuple[str, ...]
    note: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "target_kinds": ", ".join(self.target_kinds),
            "repositories": ", ".join(self.repositories),
            "note": self.note,
        }


ADAPTERS: tuple[AdapterSpec, ...] = (
    AdapterSpec(
        "sherlock-project/sherlock",
        "username profile discovery",
        "native-compatible + external_cli",
        "MIT",
        "partial_native",
        "sherlock <username>",
        "Native username module covers public profile URL checks; full parity needs Sherlock site dataset/error rules.",
        ("username",),
        ("sherlock", "{target_value}"),
        "pipx",
        ("pipx", "install", "sherlock-project"),
        "Official docs also support pip, uv, Docker and distro packages.",
        "https://sherlockproject.xyz/installation",
    ),
    AdapterSpec(
        "soxoj/maigret",
        "username dossier",
        "external_cli",
        "MIT",
        "planned",
        "maigret <username>",
        "Large upstream dataset and enrichment logic should be used through adapter or imported with license notice.",
        ("username",),
        ("maigret", "{target_value}"),
        "pip",
        ("python", "-m", "pip", "install", "maigret"),
        "Optional PDF reporting needs the upstream pdf extra and system graphics libraries.",
        "https://maigret.readthedocs.io/en/latest/installation.html",
    ),
    AdapterSpec(
        "WebBreacher/WhatsMyName",
        "username site dataset",
        "dataset",
        "NOASSERTION",
        "planned",
        "",
        "Best source for expanding native username templates after license/source review.",
        install_kind="dataset",
        install_note="Import or reference the upstream site dataset after license/source review; no executable adapter is configured.",
        docs_url="https://github.com/WebBreacher/WhatsMyName",
    ),
    AdapterSpec(
        "instaloader/instaloader",
        "Instagram public media metadata",
        "external_cli",
        "MIT",
        "planned",
        "instaloader profile <profile>",
        "Use upstream CLI for full Instagram behavior instead of reimplementing platform edge cases.",
        ("username",),
        ("instaloader", "profile", "{target_value}"),
        "pip",
        ("python", "-m", "pip", "install", "instaloader"),
        "Some private Instagram workflows require upstream login/session configuration.",
        "https://instaloader.github.io/installation.html",
    ),
    AdapterSpec(
        "Owez/yark",
        "YouTube archive",
        "external_cli",
        "MIT",
        "planned",
        "yark new <channel_url>",
        "Adapter should normalize archive outputs into unified Finding records.",
        ("url",),
        ("yark", "new", "{target_value}"),
        "pip",
        ("python", "-m", "pip", "install", "yark"),
        "FFmpeg is optional upstream dependency for some archive workflows.",
        "https://github.com/owez/yark",
    ),
    AdapterSpec(
        "alpkeskin/mosint",
        "email OSINT",
        "external_cli",
        "MIT",
        "partial_native",
        "mosint <email>",
        "Native email module covers syntax/domain-resolution baseline; full parity needs upstream enrichment modules.",
        ("email",),
        ("mosint", "{target_value}"),
        "go",
        ("go", "install", "github.com/alpkeskin/mosint/v3/cmd/mosint@latest"),
        "Many enrichment services need upstream API/service configuration before results are useful.",
        "https://github.com/alpkeskin/mosint",
    ),
    AdapterSpec(
        "thewhiteh4t/pwnedOrNot",
        "compromised email lookup",
        "external_cli",
        "MIT",
        "planned",
        "pwnedornot <email>",
        "Should be opt-in and avoid printing sensitive breach payloads by default.",
        ("email",),
        ("pwnedornot", "{target_value}"),
        "manual",
        (),
        "Install from upstream README and ensure the pwnedornot executable is on PATH.",
        "https://github.com/thewhiteh4t/pwnedOrNot",
    ),
    AdapterSpec(
        "thewhiteh4t/nexfil",
        "username profile discovery",
        "external_cli",
        "MIT",
        "planned",
        "nexfil -u <username>",
        "Candidate for second native-compatible username backend.",
        ("username",),
        ("nexfil", "-u", "{target_value}"),
        "manual",
        (),
        "Install from upstream README and ensure the nexfil executable is on PATH.",
        "https://github.com/thewhiteh4t/nexfil",
    ),
    AdapterSpec(
        "martinvigo/email2phonenumber",
        "email to phone inference",
        "external_cli",
        "MIT",
        "restricted",
        "",
        "High privacy risk; keep as explicit external adapter with strict operator confirmation.",
        install_kind="manual",
        install_note="Restricted adapter: review lawful scope and upstream README before installing.",
        docs_url="https://github.com/martinvigo/email2phonenumber",
    ),
    AdapterSpec(
        "megadose/holehe",
        "email to registered accounts",
        "external_cli",
        "GPL-3.0",
        "restricted",
        "",
        "Password-recovery based account enumeration should not be copied into native code.",
        install_kind="manual",
        install_note="Restricted adapter: do not install or run without explicit lawful scope review.",
        docs_url="https://github.com/megadose/holehe",
    ),
    AdapterSpec(
        "megadose/ignorant",
        "phone to registered accounts",
        "external_cli",
        "GPL-3.0",
        "restricted",
        "",
        "Phone account enumeration should remain restricted and explicit.",
        install_kind="manual",
        install_note="Restricted adapter: do not install or run without explicit lawful scope review.",
        docs_url="https://github.com/megadose/ignorant",
    ),
    AdapterSpec(
        "sundowndev/phoneinfoga",
        "phone number intelligence",
        "external_cli",
        "GPL-3.0",
        "partial_native",
        "phoneinfoga scan -n <number>",
        "Native phone module covers normalization/prefix baseline; full parity should use external adapter.",
        ("phone",),
        ("phoneinfoga", "scan", "-n", "{target_value}"),
        "binary",
        (),
        "Download an OS-specific binary from upstream releases or build from source.",
        "https://sundowndev.github.io/phoneinfoga/getting-started/install/",
    ),
    AdapterSpec(
        "smicallef/spiderfoot",
        "multi-source OSINT framework",
        "external_api",
        "MIT",
        "planned",
        "spiderfoot -l 127.0.0.1:5001",
        "Best integrated through SpiderFoot API/web server due broad module scope.",
        install_kind="manual",
        install_note="Run upstream SpiderFoot server/API and configure a dedicated connector before executing scans.",
        docs_url="https://github.com/smicallef/spiderfoot",
    ),
    AdapterSpec(
        "snooppr/snoop",
        "username search with RU/UA country filters",
        "external_cli",
        "NOASSERTION",
        "planned",
        "snoop <username>",
        "Important RU/UA username backend; needs license confirmation before code reuse.",
        ("username",),
        ("snoop", "{target_value}"),
        "binary",
        (),
        "Download the upstream release binary for Windows or GNU/Linux and put it on PATH.",
        "https://github.com/snooppr/snoop",
    ),
    AdapterSpec(
        "Yvesssn/DetectDee",
        "username/email/phone social account checks",
        "external_cli",
        "Apache-2.0",
        "planned",
        "",
        "Candidate for native-compatible checks after reviewing service definitions.",
        install_kind="manual",
        install_note="Review upstream service definitions and CLI usage before adding an executable command template.",
        docs_url="https://github.com/Yvesssn/DetectDee",
    ),
)


ADAPTER_PROFILES: tuple[AdapterProfile, ...] = (
    AdapterProfile(
        name="username-full",
        title="Username profile discovery",
        description="Broad username discovery across global and RU/UA-aware upstream CLI adapters.",
        target_kinds=("username",),
        repositories=(
            "sherlock-project/sherlock",
            "soxoj/maigret",
            "thewhiteh4t/nexfil",
            "snooppr/snoop",
            "instaloader/instaloader",
        ),
        note="Dry-run by default. Execute only installed CLI tools after scope review.",
    ),
    AdapterProfile(
        name="username-ru-ua",
        title="RU/UA username discovery",
        description="Username discovery biased toward Russian-language and RU/UA-relevant sources.",
        target_kinds=("username",),
        repositories=(
            "snooppr/snoop",
            "soxoj/maigret",
            "sherlock-project/sherlock",
        ),
        note="Snoop is the primary RU/UA-oriented username adapter in the current manifest.",
    ),
    AdapterProfile(
        name="email-safe",
        title="Email baseline enrichment",
        description="Email enrichment adapters that avoid account-recovery enumeration by default.",
        target_kinds=("email",),
        repositories=(
            "alpkeskin/mosint",
            "thewhiteh4t/pwnedOrNot",
        ),
        note="Restricted email-to-account and email-to-phone adapters are intentionally excluded.",
    ),
    AdapterProfile(
        name="phone-safe",
        title="Phone baseline enrichment",
        description="Phone number enrichment through non-restricted configured adapters.",
        target_kinds=("phone",),
        repositories=("sundowndev/phoneinfoga",),
        note="Restricted phone-to-account adapters are intentionally excluded.",
    ),
    AdapterProfile(
        name="url-archive",
        title="URL and media archive",
        description="URL-oriented archive adapters for public media/channel collection workflows.",
        target_kinds=("url",),
        repositories=("Owez/yark",),
        note="Useful for public YouTube/channel archive style investigations.",
    ),
)


def filter_adapters(status: str | None = None) -> tuple[AdapterSpec, ...]:
    if not status:
        return ADAPTERS
    return tuple(adapter for adapter in ADAPTERS if adapter.status == status)


def find_adapter(repository: str) -> AdapterSpec:
    normalized = repository.lower()
    for adapter in ADAPTERS:
        if adapter.repository.lower() == normalized:
            return adapter
    raise ValueError(f"Unknown adapter repository: {repository}")


def list_adapter_profiles() -> tuple[AdapterProfile, ...]:
    return ADAPTER_PROFILES


def find_adapter_profile(name: str) -> AdapterProfile:
    normalized = name.strip().lower()
    for profile in ADAPTER_PROFILES:
        if profile.name.lower() == normalized:
            return profile
    raise ValueError(f"Unknown adapter profile: {name}")


def expand_adapter_repositories(
    profile_names: tuple[str, ...] = (),
    repositories: tuple[str, ...] = (),
) -> tuple[str, ...]:
    expanded: list[str] = []
    for profile_name in profile_names:
        profile = find_adapter_profile(profile_name)
        expanded.extend(profile.repositories)
    expanded.extend(repositories)
    return _dedupe_repositories(tuple(expanded))


def _dedupe_repositories(repositories: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    deduped: list[str] = []
    for repository in repositories:
        normalized = repository.strip()
        key = normalized.lower()
        if normalized and key not in seen:
            find_adapter(normalized)
            seen.add(key)
            deduped.append(normalized)
    return tuple(deduped)
