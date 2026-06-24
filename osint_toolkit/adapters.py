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
    command_templates: tuple[tuple[str, tuple[str, ...]], ...] = ()
    generated_output_dir_args: tuple[str, ...] = ()
    generated_output_file_args: tuple[str, ...] = ()
    generated_output_patterns: tuple[str, ...] = ()

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
            "command_templates": self.render_command_templates(),
            "install_kind": self.install_kind,
            "install_command": " ".join(self.install_command),
            "install_note": self.install_note,
            "docs_url": self.docs_url,
            "required_env": ", ".join(self.required_env),
            "optional_env": ", ".join(self.optional_env),
            "generated_output_dir_args": " ".join(self.generated_output_dir_args),
            "generated_output_file_args": " ".join(self.generated_output_file_args),
            "generated_output_patterns": ", ".join(self.generated_output_patterns),
        }

    def render_command(self, target: ScanTarget) -> tuple[str, ...]:
        if self.target_kinds and target.kind not in self.target_kinds:
            return ()
        command_template = self.command_template_for(target.kind)
        if not command_template:
            return ()
        context = {
            "target_value": target.value,
            "target_kind": target.kind,
            "region": target.region,
            "region_code": _region_code(target.region),
            "region_include_flag": _region_include_flag(target.region),
            "region_tag": _region_tag(target.region),
            "region_tags_flag": _region_tags_flag(target.region),
        }
        rendered: list[str] = []
        for part in command_template:
            value = part.format(**context)
            if value:
                rendered.append(value)
        return tuple(rendered)

    def command_template_for(self, target_kind: str) -> tuple[str, ...]:
        for kind, template in self.command_templates:
            if kind == target_kind:
                return template
        return self.command_template

    def executable_names(self) -> tuple[str, ...]:
        names: list[str] = []
        if self.command_template:
            names.append(self.command_template[0])
        for _, template in self.command_templates:
            if template:
                names.append(template[0])
        return _dedupe_strings(tuple(names))

    def render_command_templates(self) -> str:
        if not self.command_templates:
            return ""
        return "; ".join(f"{kind}: {' '.join(template)}" for kind, template in self.command_templates)

    def render_output_dir_args(self, output_dir: str) -> tuple[str, ...]:
        if not self.generated_output_dir_args:
            return ()
        rendered: list[str] = []
        for part in self.generated_output_dir_args:
            value = part.format(output_dir=output_dir)
            if value:
                rendered.append(value)
        return tuple(rendered)

    def render_output_file_args(self, output_file: str) -> tuple[str, ...]:
        if not self.generated_output_file_args:
            return ()
        rendered: list[str] = []
        for part in self.generated_output_file_args:
            value = part.format(output_file=output_file)
            if value:
                rendered.append(value)
        return tuple(rendered)


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
        "maigret <username> --json ndjson [--tags ru|ua]",
        "Large upstream dataset, recursive search and enrichment logic are used through adapter-generated reports.",
        ("username",),
        ("maigret", "{target_value}", "--json", "ndjson", "{region_tags_flag}", "{region_tag}"),
        "pip",
        ("python", "-m", "pip", "install", "maigret"),
        "Optional PDF reporting needs the upstream pdf extra and system graphics libraries.",
        "https://maigret.readthedocs.io/en/latest/installation.html",
        generated_output_dir_args=("--folderoutput", "{output_dir}"),
        generated_output_patterns=("*.json",),
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
        "Native email module covers syntax/domain-resolution, MX/TXT and SPF/DMARC baseline; full parity needs upstream enrichment modules.",
        ("email",),
        ("mosint", "{target_value}"),
        "go",
        ("go", "install", "github.com/alpkeskin/mosint/v3/cmd/mosint@latest"),
        "Many enrichment services need upstream API/service configuration before results are useful.",
        "https://github.com/alpkeskin/mosint",
    ),
    AdapterSpec(
        "khast3x/h8mail",
        "email breach and related email hunting",
        "external_cli",
        "BSD-3-Clause",
        "planned",
        "h8mail -t <email> --hide -j <output.json>",
        "External adapter target for h8mail breach counts, local breach search and related-email chasing through upstream JSON output.",
        ("email",),
        ("h8mail", "-t", "{target_value}", "--hide"),
        "pip",
        ("python", "-m", "pip", "install", "h8mail"),
        "API-backed checks require upstream config/API keys; local breach searches need operator-provided breach files.",
        "https://github.com/khast3x/h8mail",
        optional_env=("HIBP_API_KEY", "HUNTERIO_API_KEY", "EMAILREP_API_KEY"),
        generated_output_file_args=("-j", "{output_file}"),
        generated_output_patterns=("*.json",),
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
        "kaifcodec/user-scanner",
        "email and username account checks",
        "external_cli",
        "MIT",
        "planned",
        "user-scanner -e <email> / user-scanner -u <username>",
        "Parity target for 100+ email and 185+ username scan vectors through target-specific CLI flags.",
        ("email", "username"),
        command_templates=(
            ("email", ("user-scanner", "-e", "{target_value}", "-f", "json")),
            ("username", ("user-scanner", "-u", "{target_value}", "-f", "json")),
        ),
        install_kind="pip",
        install_command=("python", "-m", "pip", "install", "user-scanner"),
        install_note="Install from PyPI; use explicit --execute only after checking lawful scope and platform terms.",
        docs_url="https://github.com/kaifcodec/user-scanner",
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
        "snoop --no-func --found-print [--include RU|UA] <username>",
        "Important RU/UA username backend; needs license confirmation before code reuse.",
        ("username",),
        ("snoop", "--no-func", "--found-print", "{region_include_flag}", "{region_code}", "{target_value}"),
        "binary",
        (),
        "Download the upstream release binary for Windows or GNU/Linux and put it on PATH as snoop, or adjust the local wrapper name.",
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
            "kaifcodec/user-scanner",
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
            "khast3x/h8mail",
            "thewhiteh4t/pwnedOrNot",
            "kaifcodec/user-scanner",
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


def _dedupe_strings(values: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        normalized = value.strip()
        key = normalized.lower()
        if normalized and key not in seen:
            seen.add(key)
            deduped.append(normalized)
    return tuple(deduped)


def _region_code(region: str) -> str:
    return {"ru": "RU", "ua": "UA"}.get(region.lower(), "")


def _region_include_flag(region: str) -> str:
    return "--include" if _region_code(region) else ""


def _region_tag(region: str) -> str:
    return {"ru": "ru", "ua": "ua"}.get(region.lower(), "")


def _region_tags_flag(region: str) -> str:
    return "--tags" if _region_tag(region) else ""
