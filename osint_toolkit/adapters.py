from __future__ import annotations

import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse

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
    command_input_template: tuple[str, ...] = ()
    generated_output_dir_args: tuple[str, ...] = ()
    generated_output_file_args: tuple[str, ...] = ()
    generated_output_patterns: tuple[str, ...] = ()
    generated_output_workdir: bool = False
    working_dir_env: str = ""
    generated_output_base_env: str = ""
    generated_output_subdir: str = ""
    executable_probe_args: tuple[str, ...] = ()
    executable_probe_required: tuple[str, ...] = ()
    executable_runtime_probe_args: tuple[str, ...] = ()
    executable_runtime_probe_required: tuple[str, ...] = ()
    executable_probe_timeout: float = 2.0

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
            "command_input_template": "\\n".join(self.command_input_template),
            "install_kind": self.install_kind,
            "install_command": " ".join(self.install_command),
            "install_note": self.install_note,
            "docs_url": self.docs_url,
            "required_env": ", ".join(self.required_env),
            "optional_env": ", ".join(self.optional_env),
            "generated_output_dir_args": " ".join(self.generated_output_dir_args),
            "generated_output_file_args": " ".join(self.generated_output_file_args),
            "generated_output_patterns": ", ".join(self.generated_output_patterns),
            "generated_output_workdir": str(self.generated_output_workdir).lower(),
            "working_dir_env": self.working_dir_env,
            "generated_output_base_env": self.generated_output_base_env,
            "generated_output_subdir": self.generated_output_subdir,
            "executable_probe_args": " ".join(self.executable_probe_args),
            "executable_probe_required": ", ".join(self.executable_probe_required),
            "executable_runtime_probe_args": " ".join(self.executable_runtime_probe_args),
            "executable_runtime_probe_required": ", ".join(self.executable_runtime_probe_required),
            "executable_probe_timeout": str(self.executable_probe_timeout),
        }

    def render_command(self, target: ScanTarget) -> tuple[str, ...]:
        if self.target_kinds and target.kind not in self.target_kinds:
            return ()
        command_template = self.command_template_for(target.kind)
        if not command_template:
            return ()
        context = self.render_context(target)
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
            names.append(_static_executable_value(self.command_template[0]))
        for _, template in self.command_templates:
            if template:
                names.append(_static_executable_value(template[0]))
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

    def render_command_input(self, target: ScanTarget) -> str:
        if not self.command_input_template:
            return ""
        context = self.render_context(target)
        lines = [line.format(**context) for line in self.command_input_template]
        return "\n".join(line for line in lines if line) + "\n"

    def render_context(self, target: ScanTarget) -> dict[str, str]:
        return {
            "target_value": target.value,
            "target_kind": target.kind,
            "region": target.region,
            "region_code": _region_code(target.region),
            "region_include_flag": _region_include_flag(target.region),
            "region_tag": _region_tag(target.region),
            "region_tags_flag": _region_tags_flag(target.region),
            "social_analyzer_countries_flag": _social_analyzer_countries_flag(target.region),
            "social_analyzer_country": _social_analyzer_country(target.region),
            "social_analyzer_app": _social_analyzer_app_value(),
            "instagram_profile": _instagram_profile_value(target.value),
            "bbot_target": _bbot_target_value(target),
            "yark_archive_name": _yark_archive_name(target.value),
            "blackbird_python": _blackbird_python_value(),
            "detectdee_data": _detectdee_data_value(),
            "spiderfoot_script": _spiderfoot_script_value(),
            "spiderfoot_python": _spiderfoot_python_value(),
        }


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
        "Native username module covers baseline URL checks; execute mode ingests Sherlock stdout and CSV/TXT reports.",
        ("username",),
        ("sherlock", "{target_value}"),
        "pipx",
        ("pipx", "install", "sherlock-project"),
        "Official docs also support pip, uv, Docker and distro packages.",
        "https://sherlockproject.xyz/installation",
        generated_output_dir_args=("--no-color", "--print-all", "--csv", "--txt", "--folderoutput", "{output_dir}"),
        generated_output_patterns=("*.csv", "*.txt"),
    ),
    AdapterSpec(
        "soxoj/maigret",
        "username dossier",
        "native-compatible + external_cli",
        "MIT",
        "partial_native",
        "maigret <username> --json ndjson [--tags ru|ua]",
        "Native username layer imports sanitized GET-compatible site rules; recursive search, reports and enrichment logic are used through adapter-generated reports.",
        ("username",),
        ("maigret", "{target_value}", "--json", "ndjson", "{region_tags_flag}", "{region_tag}"),
        "pipx",
        ("pipx", "install", "maigret"),
        "Optional PDF reporting needs the upstream pdf extra and system graphics libraries.",
        "https://maigret.readthedocs.io/en/latest/installation.html",
        generated_output_dir_args=("--folderoutput", "{output_dir}"),
        generated_output_patterns=("*.json",),
    ),
    AdapterSpec(
        "WebBreacher/WhatsMyName",
        "username site dataset",
        "dataset",
        "CC BY-SA 4.0",
        "partial_native",
        "",
        "Native username layer imports GET-compatible wmn-data.json entries with headers; POST checks remain documented parity gaps.",
        install_kind="dataset",
        install_note="Dataset snapshot is bundled as osint_toolkit/resources/whatsmyname_wmn_data.json; no executable adapter is configured.",
        docs_url="https://github.com/WebBreacher/WhatsMyName",
    ),
    AdapterSpec(
        "qeeqbox/social-analyzer",
        "social profile discovery with rating and metadata",
        "external_cli",
        "AGPL-3.0",
        "planned",
        "node <SOCIAL_ANALYZER_APP_JS> --username <username> --output json --filter good,maybe --profiles detected [--countries ru|ua]",
        "High-priority person/profile upstream. Kept as an external adapter because of AGPL; execute mode ingests JSON detected/unknown/failed profiles.",
        ("username",),
        (
            "node",
            "{social_analyzer_app}",
            "--username",
            "{target_value}",
            "--output",
            "json",
            "--mode",
            "fast",
            "--method",
            "all",
            "--filter",
            "good,maybe",
            "--profiles",
            "detected",
            "{social_analyzer_countries_flag}",
            "{social_analyzer_country}",
        ),
        install_kind="manual",
        install_note="Clone upstream social-analyzer, run npm install, and set SOCIAL_ANALYZER_APP_JS to its local app.js path.",
        docs_url="https://github.com/qeeqbox/social-analyzer",
        required_env=("SOCIAL_ANALYZER_APP_JS",),
    ),
    AdapterSpec(
        "iojw/socialscan",
        "username/email availability checks",
        "external_cli",
        "MPL-2.0",
        "planned",
        "socialscan <query> --json <output.json>",
        "Checks public username/email availability signals through upstream CLI and ingests JSON PlatformResponse records.",
        ("username", "email"),
        ("socialscan", "{target_value}"),
        "pipx",
        ("pipx", "install", "socialscan"),
        "Results are availability/usage signals, not proof of identity; execute only after checking lawful scope and platform terms.",
        "https://github.com/iojw/socialscan",
        generated_output_file_args=("--json", "{output_file}"),
        generated_output_patterns=("*.json",),
    ),
    AdapterSpec(
        "p1ngul1n0/blackbird",
        "username/email account discovery with metadata exports",
        "external_cli",
        "NOASSERTION",
        "planned",
        "<BLACKBIRD_PYTHON|python> blackbird.py --username <username> --json --no-update",
        "Runs the real upstream checkout from BLACKBIRD_DIR and ingests fresh JSON exports plus stdout profile hits; no code is copied because license metadata is missing.",
        ("username", "email"),
        install_kind="manual",
        install_note="Clone upstream Blackbird, run pip install -r requirements.txt in that checkout, and set BLACKBIRD_DIR to the checkout root containing blackbird.py.",
        docs_url="https://github.com/p1ngul1n0/blackbird",
        required_env=("BLACKBIRD_DIR",),
        optional_env=("BLACKBIRD_PYTHON",),
        command_templates=(
            (
                "username",
                ("{blackbird_python}", "blackbird.py", "--username", "{target_value}", "--json", "--no-update", "--timeout", "30"),
            ),
            (
                "email",
                ("{blackbird_python}", "blackbird.py", "--email", "{target_value}", "--json", "--no-update", "--timeout", "30"),
            ),
        ),
        generated_output_patterns=("*.json",),
        working_dir_env="BLACKBIRD_DIR",
        generated_output_base_env="BLACKBIRD_DIR",
        generated_output_subdir="results",
    ),
    AdapterSpec(
        "instaloader/instaloader",
        "Instagram public media metadata",
        "external_cli",
        "MIT",
        "planned",
        "instaloader profile <profile>",
        "Native instagram target covers public web metadata; use upstream CLI for full Instagram behavior and media edge cases.",
        ("username", "instagram"),
        (),
        "pipx",
        ("pipx", "install", "instaloader"),
        "Some private Instagram workflows require upstream login/session configuration.",
        "https://instaloader.github.io/installation.html",
        command_templates=(
            ("username", ("instaloader", "profile", "{target_value}")),
            ("instagram", ("instaloader", "profile", "{instagram_profile}")),
        ),
    ),
    AdapterSpec(
        "Owez/yark",
        "YouTube archive",
        "external_cli",
        "MIT",
        "planned",
        "yark new <archive_name> <channel_url>",
        "Adapter creates a temporary Yark archive and normalizes generated yark.json output into unified Finding records.",
        ("url",),
        ("yark", "new", "{yark_archive_name}", "{target_value}"),
        "pipx",
        ("pipx", "install", "yark"),
        "FFmpeg is optional upstream dependency for some archive workflows.",
        "https://github.com/owez/yark",
        generated_output_patterns=("*/yark.json",),
        generated_output_workdir=True,
    ),
    AdapterSpec(
        "projectdiscovery/subfinder",
        "passive subdomain discovery",
        "external_cli",
        "MIT",
        "planned",
        "subfinder -d <domain> -oJ -silent",
        "Passive subdomain enumeration adapter; execute mode ingests JSONL/plain subdomain output into unified subdomain findings.",
        ("domain",),
        ("subfinder", "-d", "{target_value}", "-oJ", "-silent"),
        "go",
        ("go", "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
        "Many passive sources require provider API keys in the upstream provider config before results are complete.",
        "https://github.com/projectdiscovery/subfinder",
        optional_env=("SUBFINDER_CONFIG", "SUBFINDER_PROVIDER_CONFIG"),
        executable_probe_args=("-h",),
        executable_probe_required=("subfinder", "-d", "-silent"),
    ),
    AdapterSpec(
        "projectdiscovery/httpx",
        "HTTP service probing",
        "external_cli",
        "MIT",
        "planned",
        "httpx -u <domain-or-url> -json -silent -status-code -title -tech-detect",
        "HTTP probing adapter for alive web assets; execute mode ingests JSONL/plain URL output into unified URL/domain findings.",
        ("domain", "url"),
        command_templates=(
            (
                "domain",
                (
                    "httpx",
                    "-u",
                    "{target_value}",
                    "-json",
                    "-silent",
                    "-status-code",
                    "-title",
                    "-tech-detect",
                    "-content-type",
                    "-web-server",
                    "-response-time",
                    "-location",
                    "-cdn",
                    "-ip",
                    "-cname",
                ),
            ),
            (
                "url",
                (
                    "httpx",
                    "-u",
                    "{target_value}",
                    "-json",
                    "-silent",
                    "-status-code",
                    "-title",
                    "-tech-detect",
                    "-content-type",
                    "-web-server",
                    "-response-time",
                    "-location",
                    "-cdn",
                    "-ip",
                    "-cname",
                ),
            ),
        ),
        install_kind="go",
        install_command=("go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
        install_note="Ensure PATH resolves the ProjectDiscovery httpx binary, not the unrelated Python httpx package.",
        docs_url="https://github.com/projectdiscovery/httpx",
        executable_probe_args=("-h",),
        executable_probe_required=("-tech-detect", "-status-code"),
    ),
    AdapterSpec(
        "owasp-amass/amass",
        "attack surface subdomain enumeration",
        "external_cli",
        "Apache-2.0",
        "planned",
        "amass enum -passive -nocolor -d <domain>",
        "Passive Amass enumeration adapter; active/bruteforce modes stay operator-controlled and are not enabled by default.",
        ("domain",),
        ("amass", "enum", "-passive", "-nocolor", "-d", "{target_value}"),
        "go",
        ("go", "install", "-v", "github.com/owasp-amass/amass/v4/...@master"),
        "Use upstream config/data-source files for API keys; this adapter keeps default execution passive.",
        "https://github.com/owasp-amass/amass",
        optional_env=("AMASS_CONFIG",),
        executable_probe_args=("-h",),
        executable_probe_required=("amass", "enum"),
    ),
    AdapterSpec(
        "laramies/theHarvester",
        "domain names, emails, IPs, subdomains and URLs",
        "external_cli",
        "GPL-2.0-only",
        "planned",
        "theHarvester -d <domain> -b all -f <output.json>",
        "Broad passive domain recon adapter; execute mode ingests upstream JSON report without copying GPL code.",
        ("domain",),
        ("theHarvester", "-d", "{target_value}", "-b", "all"),
        install_kind="manual",
        install_note="Install from upstream README/wiki with Python 3.12+ and ensure theHarvester executable is on PATH.",
        docs_url="https://github.com/laramies/theHarvester",
        optional_env=("THEHARVESTER_API_KEY",),
        generated_output_file_args=("-f", "{output_file}"),
        generated_output_patterns=("*.json",),
        executable_probe_args=("-h",),
        executable_probe_required=("theharvester", "-d", "-b"),
    ),
    AdapterSpec(
        "blacklanternsecurity/bbot",
        "recursive OSINT, recon and attack surface scanner",
        "external_cli",
        "GPL-3.0",
        "planned",
        "bbot -t <target> -p subdomain-enum -rf passive -o <dir> -n osint-toolkit",
        "SpiderFoot-inspired BBOT adapter; default command keeps execution to passive subdomain-enum and ingests generated JSON events.",
        ("domain", "url", "email", "username"),
        ("bbot", "-t", "{bbot_target}", "-p", "subdomain-enum", "-rf", "passive"),
        install_kind="pipx",
        install_command=("pipx", "install", "bbot"),
        install_note="Configure third-party API keys in upstream ~/.config/bbot/bbot.yml; broader presets and deadly modules stay operator-controlled.",
        docs_url="https://www.blacklanternsecurity.com/bbot/",
        generated_output_dir_args=("-o", "{output_dir}", "-n", "osint-toolkit"),
        generated_output_patterns=("*.json",),
        executable_probe_args=("-h",),
        executable_probe_required=("bbot", "-t", "-p"),
        executable_runtime_probe_args=("-t", "example.com", "-p", "subdomain-enum", "-rf", "passive", "--dry-run", "-y"),
        executable_probe_timeout=15.0,
    ),
    AdapterSpec(
        "blacklanternsecurity/bbot-passive-web",
        "broader passive BBOT web and subdomain preset",
        "external_cli",
        "GPL-3.0",
        "planned",
        "bbot -t <target> -p subdomain-enum web-basic -rf passive -ef active aggressive deadly portscan web-screenshots -o <dir> -n osint-toolkit",
        "Explicit broader BBOT profile that combines subdomain-enum and web-basic while requiring passive modules and excluding active/aggressive/deadly/portscan/screenshot flags.",
        ("domain", "url"),
        (
            "bbot",
            "-t",
            "{bbot_target}",
            "-p",
            "subdomain-enum",
            "web-basic",
            "-rf",
            "passive",
            "-ef",
            "active",
            "aggressive",
            "deadly",
            "portscan",
            "web-screenshots",
        ),
        install_kind="pipx",
        install_command=("pipx", "install", "bbot"),
        install_note="Configure third-party API keys in upstream ~/.config/bbot/bbot.yml; this profile remains passive and excludes deadly/active modules.",
        docs_url="https://www.blacklanternsecurity.com/bbot/",
        generated_output_dir_args=("-o", "{output_dir}", "-n", "osint-toolkit"),
        generated_output_patterns=("*.json",),
        executable_probe_args=("-h",),
        executable_probe_required=("bbot", "-t", "-p", "-rf", "-ef"),
        executable_runtime_probe_args=(
            "-t",
            "example.com",
            "-p",
            "subdomain-enum",
            "web-basic",
            "-rf",
            "passive",
            "-ef",
            "active",
            "aggressive",
            "deadly",
            "portscan",
            "web-screenshots",
            "--dry-run",
            "-y",
        ),
        executable_probe_timeout=15.0,
    ),
    AdapterSpec(
        "blacklanternsecurity/bbot-passive-email",
        "passive BBOT email enumeration preset",
        "external_cli",
        "GPL-3.0",
        "planned",
        "bbot -t <target> -p email-enum -rf passive -ef active aggressive deadly portscan web-screenshots -o <dir> -n osint-toolkit",
        "Explicit BBOT email-enum profile constrained to passive modules for public email signal collection from domain/URL targets.",
        ("domain", "url"),
        (
            "bbot",
            "-t",
            "{bbot_target}",
            "-p",
            "email-enum",
            "-rf",
            "passive",
            "-ef",
            "active",
            "aggressive",
            "deadly",
            "portscan",
            "web-screenshots",
        ),
        install_kind="pipx",
        install_command=("pipx", "install", "bbot"),
        install_note="Configure third-party API keys in upstream ~/.config/bbot/bbot.yml; this profile remains passive and excludes active/deadly modules.",
        docs_url="https://www.blacklanternsecurity.com/bbot/Stable/scanning/presets_list/#email-enum",
        generated_output_dir_args=("-o", "{output_dir}", "-n", "osint-toolkit"),
        generated_output_patterns=("*.json",),
        executable_probe_args=("-h",),
        executable_probe_required=("bbot", "-t", "-p", "-rf", "-ef"),
        executable_runtime_probe_args=(
            "-t",
            "example.com",
            "-p",
            "email-enum",
            "-rf",
            "passive",
            "-ef",
            "active",
            "aggressive",
            "deadly",
            "portscan",
            "web-screenshots",
            "--dry-run",
            "-y",
        ),
        executable_probe_timeout=15.0,
    ),
    AdapterSpec(
        "alpkeskin/mosint",
        "email OSINT",
        "external_cli",
        "MIT",
        "partial_native",
        "mosint --silent --output <output.json> <email>",
        "Native email module covers syntax/domain-resolution, MX/TXT and SPF/DMARC baseline; upstream enrichment is ingested through Mosint JSON output.",
        ("email",),
        ("mosint", "--silent", "{target_value}"),
        "go",
        ("go", "install", "github.com/alpkeskin/mosint/v3/cmd/mosint@latest"),
        "Mosint requires a .mosint.yaml config file; many enrichment services need upstream API keys before results are useful.",
        "https://github.com/alpkeskin/mosint",
        generated_output_file_args=("--output", "{output_file}"),
        generated_output_patterns=("*.json",),
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
        "pipx",
        ("pipx", "install", "h8mail"),
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
        "pwnedornot -e <email> -n",
        "Should be opt-in and avoid printing sensitive breach payloads by default.",
        ("email",),
        ("pwnedornot", "-e", "{target_value}", "-n"),
        "manual",
        (),
        "Install from upstream README and ensure the pwnedornot executable is on PATH.",
        "https://github.com/thewhiteh4t/pwnedOrNot",
        optional_env=("PWNED_API_KEY",),
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
        install_kind="pipx",
        install_command=("pipx", "install", "user-scanner"),
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
        "Execute mode runs in a temporary working directory and ingests Nexfil autosaved TXT reports.",
        ("username",),
        ("nexfil", "-u", "{target_value}"),
        "pipx",
        ("pipx", "install", "nexfil"),
        "Nexfil autosaves reports below its working directory/HOME; runner isolates this in execute mode.",
        "https://github.com/thewhiteh4t/nexfil",
        generated_output_patterns=("*.txt",),
        generated_output_workdir=True,
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
        "Native phone module covers baseline signals; CLI/API output parser ingests PhoneInfoga scanner results without copying GPL code.",
        ("phone",),
        ("phoneinfoga", "scan", "-n", "{target_value}"),
        "binary",
        (),
        "Download an OS-specific binary from upstream releases or build from source.",
        "https://sundowndev.github.io/phoneinfoga/getting-started/install/",
        executable_probe_args=("--help",),
        executable_probe_required=("phoneinfoga", "scan"),
    ),
    AdapterSpec(
        "smicallef/spiderfoot",
        "multi-source OSINT framework",
        "external_cli",
        "MIT",
        "planned",
        "<SPIDERFOOT_PYTHON|python> <SPIDERFOOT_SF_PATH> -s <target> -u passive -o json -q",
        "SpiderFoot CLI adapter in passive use-case mode; execute mode ingests JSON stdout events without running the web/API server.",
        ("domain", "url", "email", "username", "phone"),
        ("{spiderfoot_python}", "{spiderfoot_script}", "-s", "{target_value}", "-u", "passive", "-o", "json", "-q"),
        install_kind="manual",
        install_note="Clone upstream SpiderFoot, install its requirements, then set SPIDERFOOT_SF_PATH to the local sf.py path.",
        docs_url="https://github.com/smicallef/spiderfoot",
        required_env=("SPIDERFOOT_SF_PATH",),
        optional_env=("SPIDERFOOT_PYTHON",),
    ),
    AdapterSpec(
        "jasonxtn/argus",
        "interactive all-in-one reconnaissance toolkit",
        "external_cli_interactive",
        "MIT",
        "planned",
        "argus << set target <target>; runall infra; viewout; exit",
        "Interactive Argus CLI adapter; execute mode feeds a conservative infra-category command script and parses stdout/cache output.",
        ("domain", "url", "email", "username", "phone"),
        ("argus",),
        install_kind="pipx",
        install_command=("pipx", "install", "argus-recon"),
        install_note="Argus is interactive. The adapter feeds commands through stdin; broader categories and API-backed modules remain operator-controlled.",
        docs_url="https://github.com/jasonxtn/argus",
        optional_env=(
            "VIRUSTOTAL_API_KEY",
            "SHODAN_API_KEY",
            "CENSYS_API_ID",
            "CENSYS_API_SECRET",
            "GOOGLE_API_KEY",
            "HIBP_API_KEY",
        ),
        command_input_template=(
            "set target {target_value}",
            "runall infra",
            "viewout",
            "exit",
        ),
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
        "DetectDee detect -n|-e|-p <value> -f <data.json> -o <output>",
        "Runs upstream detect mode only. Screenshot, ChatGPT token and credential-stuffing flows are not used by this adapter.",
        ("username", "email", "phone"),
        command_templates=(
            ("username", ("DetectDee", "detect", "-n", "{target_value}", "-f", "{detectdee_data}", "-r", "1", "--timeout", "10")),
            ("email", ("DetectDee", "detect", "-e", "{target_value}", "-f", "{detectdee_data}", "-r", "1", "--timeout", "10")),
            ("phone", ("DetectDee", "detect", "-p", "{target_value}", "-f", "{detectdee_data}", "-r", "1", "--timeout", "10")),
        ),
        install_kind="binary",
        install_note="Download an upstream release or build the Go project locally, put DetectDee on PATH, and set DETECTDEE_DATA to upstream data.json.",
        docs_url="https://github.com/Yvesssn/DetectDee",
        required_env=("DETECTDEE_DATA",),
        generated_output_file_args=("-o", "{output_file}"),
        generated_output_patterns=("*.json", "*.txt"),
        executable_probe_args=("detect", "-h"),
        executable_probe_required=("--name", "--email", "--phone", "--output"),
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
            "qeeqbox/social-analyzer",
            "iojw/socialscan",
            "p1ngul1n0/blackbird",
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
            "qeeqbox/social-analyzer",
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
            "iojw/socialscan",
            "p1ngul1n0/blackbird",
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
    AdapterProfile(
        name="domain-recon",
        title="Domain and web reconnaissance",
        description="Passive subdomain discovery and HTTP probing through upstream CLI adapters.",
        target_kinds=("domain", "url"),
        repositories=(
            "projectdiscovery/subfinder",
            "projectdiscovery/httpx",
            "owasp-amass/amass",
            "laramies/theHarvester",
            "blacklanternsecurity/bbot",
            "blacklanternsecurity/bbot-passive-email",
            "smicallef/spiderfoot",
        ),
        note="Default profile stays passive; active/bruteforce Amass, broader SpiderFoot use cases and screenshot/API endpoint scans are separate scope decisions.",
    ),
    AdapterProfile(
        name="bbot-passive-web",
        title="BBOT passive web preset",
        description="Broader BBOT subdomain and basic web preset constrained to passive modules.",
        target_kinds=("domain", "url"),
        repositories=("blacklanternsecurity/bbot-passive-web",),
        note="Uses subdomain-enum plus web-basic, requires passive modules and excludes active/aggressive/deadly/portscan/screenshot flags.",
    ),
    AdapterProfile(
        name="bbot-passive-email",
        title="BBOT passive email preset",
        description="BBOT email-enum preset constrained to passive modules for domain/URL targets.",
        target_kinds=("domain", "url"),
        repositories=("blacklanternsecurity/bbot-passive-email",),
        note="Uses email-enum with passive modules and excludes active/aggressive/deadly/portscan/screenshot flags.",
    ),
    AdapterProfile(
        name="broad-recon",
        title="Broad reconnaissance suite",
        description="Broad upstream recon frameworks that may combine passive and active modules.",
        target_kinds=("domain", "url", "email", "username", "phone"),
        repositories=(
            "blacklanternsecurity/bbot",
            "smicallef/spiderfoot",
            "jasonxtn/argus",
        ),
        note="Dry-run by default. Execute only after confirming scope because Argus runall infra and broader framework presets may be active.",
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


def _static_executable_value(value: str) -> str:
    return {
        "{blackbird_python}": _blackbird_python_value(),
        "{spiderfoot_python}": _spiderfoot_python_value(),
    }.get(value, value)


def _region_code(region: str) -> str:
    return {"ru": "RU", "ua": "UA"}.get(region.lower(), "")


def _region_include_flag(region: str) -> str:
    return "--include" if _region_code(region) else ""


def _region_tag(region: str) -> str:
    return {"ru": "ru", "ua": "ua"}.get(region.lower(), "")


def _region_tags_flag(region: str) -> str:
    return "--tags" if _region_tag(region) else ""


def _social_analyzer_country(region: str) -> str:
    return {"ru": "ru", "ua": "ua"}.get(region.lower(), "")


def _social_analyzer_countries_flag(region: str) -> str:
    return "--countries" if _social_analyzer_country(region) else ""


def _social_analyzer_app_value() -> str:
    return os.environ.get("SOCIAL_ANALYZER_APP_JS", "<SOCIAL_ANALYZER_APP_JS>").strip() or "<SOCIAL_ANALYZER_APP_JS>"


def _instagram_profile_value(value: str) -> str:
    normalized = value.strip().lstrip("@")
    parsed = urlparse(normalized if "://" in normalized else f"https://{normalized}")
    if (parsed.hostname or "").lower() in {"instagram.com", "www.instagram.com"}:
        first = parsed.path.strip("/").split("/")[0]
        if first and first not in {"p", "reel", "reels", "tv"}:
            normalized = first
    if re.fullmatch(r"[A-Za-z0-9._]{1,30}", normalized):
        return normalized
    return value.strip().lstrip("@")


def _bbot_target_value(target: ScanTarget) -> str:
    if target.kind == "username":
        return f"USER:{target.value.strip().lstrip('@')}"
    return target.value.strip()


def _yark_archive_name(value: str) -> str:
    raw = value.strip()
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    parts: list[str] = []
    host = (parsed.hostname or "archive").lower()
    if host.startswith("www."):
        host = host[4:]
    parts.append(host)
    path_parts = [part for part in parsed.path.strip("/").split("/") if part]
    parts.extend(path_parts[-2:])
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", "-".join(parts)).strip("-._").lower()
    return (normalized or "yark-archive")[:80]


def _blackbird_python_value() -> str:
    return os.environ.get("BLACKBIRD_PYTHON", "python").strip() or "python"


def _detectdee_data_value() -> str:
    return os.environ.get("DETECTDEE_DATA", "<DETECTDEE_DATA>").strip() or "<DETECTDEE_DATA>"


def _spiderfoot_script_value() -> str:
    return os.environ.get("SPIDERFOOT_SF_PATH", "<SPIDERFOOT_SF_PATH>").strip() or "<SPIDERFOOT_SF_PATH>"


def _spiderfoot_python_value() -> str:
    return os.environ.get("SPIDERFOOT_PYTHON", "python").strip() or "python"
