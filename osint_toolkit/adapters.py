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
        }

    def render_command(self, target: ScanTarget) -> tuple[str, ...]:
        if self.target_kinds and target.kind not in self.target_kinds:
            return ()
        return tuple(
            part.format(target_value=target.value, target_kind=target.kind, region=target.region)
            for part in self.command_template
        )


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
    ),
    AdapterSpec(
        "WebBreacher/WhatsMyName",
        "username site dataset",
        "dataset",
        "NOASSERTION",
        "planned",
        "",
        "Best source for expanding native username templates after license/source review.",
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
    ),
    AdapterSpec(
        "martinvigo/email2phonenumber",
        "email to phone inference",
        "external_cli",
        "MIT",
        "restricted",
        "",
        "High privacy risk; keep as explicit external adapter with strict operator confirmation.",
    ),
    AdapterSpec(
        "megadose/holehe",
        "email to registered accounts",
        "external_cli",
        "GPL-3.0",
        "restricted",
        "",
        "Password-recovery based account enumeration should not be copied into native code.",
    ),
    AdapterSpec(
        "megadose/ignorant",
        "phone to registered accounts",
        "external_cli",
        "GPL-3.0",
        "restricted",
        "",
        "Phone account enumeration should remain restricted and explicit.",
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
    ),
    AdapterSpec(
        "smicallef/spiderfoot",
        "multi-source OSINT framework",
        "external_api",
        "MIT",
        "planned",
        "spiderfoot -l 127.0.0.1:5001",
        "Best integrated through SpiderFoot API/web server due broad module scope.",
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
    ),
    AdapterSpec(
        "Yvesssn/DetectDee",
        "username/email/phone social account checks",
        "external_cli",
        "Apache-2.0",
        "planned",
        "",
        "Candidate for native-compatible checks after reviewing service definitions.",
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
