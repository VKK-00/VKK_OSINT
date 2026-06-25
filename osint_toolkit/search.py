from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from .adapter_runner import format_command
from .adapter_setup import AdapterSetup, build_adapter_setup
from .adapters import expand_adapter_repositories, filter_adapters, find_adapter
from .engine import ScanTarget


TARGET_KINDS: tuple[str, ...] = (
    "person",
    "username",
    "email",
    "phone",
    "domain",
    "url",
    "telegram",
    "instagram",
    "social",
    "ru-ua",
    "image",
)


@dataclass(frozen=True)
class SearchProfile:
    name: str
    title: str
    description: str
    target_kinds: tuple[str, ...]
    native_kinds: tuple[str, ...] = ()
    adapter_profiles: tuple[str, ...] = ()
    adapter_repositories: tuple[str, ...] = ()
    local_tools: tuple[str, ...] = ()
    excluded_repositories: tuple[str, ...] = ()
    include_restricted: bool = False
    note: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "target_kinds": list(self.target_kinds),
            "native_kinds": list(self.native_kinds),
            "adapter_profiles": list(self.adapter_profiles),
            "adapter_repositories": list(self.adapter_repositories),
            "local_tools": list(self.local_tools),
            "excluded_repositories": list(self.excluded_repositories),
            "include_restricted": self.include_restricted,
            "note": self.note,
        }


@dataclass(frozen=True)
class LocalToolSpec:
    name: str
    title: str
    target_kinds: tuple[str, ...]
    command_template: tuple[str, ...]
    executable: str = ""
    install_note: str = ""
    docs_url: str = ""

    def render_command(self, target: ScanTarget) -> tuple[str, ...]:
        context = {
            "target_value": target.value,
            "image_path": target.value,
        }
        return tuple(part.format(**context) for part in self.command_template)


@dataclass(frozen=True)
class PlannedStep:
    stage: str
    source: str
    title: str
    target_kind: str
    target_value: str
    status: str
    command: str = ""
    readiness: str = ""
    reason: str = ""
    install_note: str = ""
    docs_url: str = ""
    metadata: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "stage": self.stage,
            "source": self.source,
            "title": self.title,
            "target_kind": self.target_kind,
            "target_value": self.target_value,
            "status": self.status,
            "command": self.command,
            "readiness": self.readiness,
            "reason": self.reason,
            "install_note": self.install_note,
            "docs_url": self.docs_url,
            "metadata": self.metadata or {},
        }


@dataclass(frozen=True)
class SearchPlan:
    target: ScanTarget
    profile: SearchProfile
    steps: tuple[PlannedStep, ...]
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "target": {
                "kind": self.target.kind,
                "value": self.target.value,
                "region": self.target.region,
            },
            "profile": self.profile.to_dict(),
            "steps": [step.to_dict() for step in self.steps],
            "warnings": list(self.warnings),
            "summary": self.summary(),
        }

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for step in self.steps:
            counts[step.status] = counts.get(step.status, 0) + 1
        return counts


LOCAL_TOOLS: tuple[LocalToolSpec, ...] = (
    LocalToolSpec(
        name="powershell-file-baseline",
        title="PowerShell file hash and timestamps",
        target_kinds=("image",),
        command_template=(
            "powershell",
            "-NoProfile",
            "-Command",
            'Get-Item -LiteralPath "{image_path}" | Select-Object FullName,Length,CreationTimeUtc,LastWriteTimeUtc; '
            'Get-FileHash -Algorithm SHA256 -LiteralPath "{image_path}"',
        ),
        executable="powershell",
        install_note="Built into Windows PowerShell.",
    ),
    LocalToolSpec(
        name="exiftool",
        title="ExifTool metadata extraction",
        target_kinds=("image",),
        command_template=("exiftool", "-a", "-u", "-g1", "-ee", "{image_path}"),
        executable="exiftool",
        install_note="Install ExifTool and ensure exiftool is on PATH.",
        docs_url="https://exiftool.org/",
    ),
    LocalToolSpec(
        name="imagemagick-identify",
        title="ImageMagick identify metadata",
        target_kinds=("image",),
        command_template=("magick", "identify", "-verbose", "{image_path}"),
        executable="magick",
        install_note="Install ImageMagick and ensure magick is on PATH.",
        docs_url="https://imagemagick.org/",
    ),
    LocalToolSpec(
        name="tesseract-ocr",
        title="Tesseract OCR",
        target_kinds=("image",),
        command_template=("tesseract", "{image_path}", "stdout", "-l", "eng+rus+ukr"),
        executable="tesseract",
        install_note="Install Tesseract OCR with eng, rus and ukr language packs.",
        docs_url="https://github.com/tesseract-ocr/tesseract",
    ),
    LocalToolSpec(
        name="zbarimg",
        title="QR and barcode extraction",
        target_kinds=("image",),
        command_template=("zbarimg", "--raw", "{image_path}"),
        executable="zbarimg",
        install_note="Install ZBar tools and ensure zbarimg is on PATH.",
        docs_url="https://github.com/mchehab/zbar",
    ),
)


SEARCH_PROFILES: tuple[SearchProfile, ...] = (
    SearchProfile(
        name="safe",
        title="Safe default fan-out",
        description="Native checks plus non-restricted adapters compatible with the target.",
        target_kinds=TARGET_KINDS,
        native_kinds=("person", "username", "email", "phone", "domain", "url", "telegram", "instagram", "social", "ru-ua"),
        adapter_profiles=("username-full", "email-safe", "phone-safe", "domain-recon", "url-archive"),
        local_tools=("powershell-file-baseline", "exiftool", "imagemagick-identify", "tesseract-ocr", "zbarimg"),
        note="Restricted adapters are excluded.",
    ),
    SearchProfile(
        name="all-safe",
        title="All safe configured tools",
        description="All currently non-restricted native modules, adapter profiles and local image tools.",
        target_kinds=TARGET_KINDS,
        native_kinds=("person", "username", "email", "phone", "domain", "url", "telegram", "instagram", "social", "ru-ua"),
        adapter_profiles=("username-full", "username-ru-ua", "email-safe", "phone-safe", "url-archive", "domain-recon", "broad-recon"),
        local_tools=("powershell-file-baseline", "exiftool", "imagemagick-identify", "tesseract-ocr", "zbarimg"),
        note="Broad recon adapters are included but remain readiness-checked and non-restricted only.",
    ),
    SearchProfile(
        name="phone-full",
        title="Phone full fan-out",
        description="Phone baseline plus every currently compatible non-restricted phone adapter.",
        target_kinds=("phone",),
        native_kinds=("phone",),
        adapter_profiles=("phone-safe", "broad-recon"),
        adapter_repositories=("Yvesssn/DetectDee",),
        excluded_repositories=("megadose/ignorant",),
        note="Phone-to-account restricted checks are listed as excluded, not run by default.",
    ),
    SearchProfile(
        name="email-full",
        title="Email full fan-out",
        description="Email DNS/auth baseline plus safe breach, reputation and account-discovery adapters.",
        target_kinds=("email",),
        native_kinds=("email",),
        adapter_profiles=("email-safe", "broad-recon"),
        excluded_repositories=("megadose/holehe", "martinvigo/email2phonenumber"),
        note="Recovery/account-enumeration adapters are excluded from the default email fan-out.",
    ),
    SearchProfile(
        name="username-full",
        title="Username full fan-out",
        description="Native username checks plus global and RU/UA-aware username adapters.",
        target_kinds=("username",),
        native_kinds=("username",),
        adapter_profiles=("username-full", "broad-recon"),
        adapter_repositories=("Yvesssn/DetectDee",),
    ),
    SearchProfile(
        name="person-full",
        title="Person to username fan-out",
        description="Person name expansion followed by username-capable tools.",
        target_kinds=("person",),
        native_kinds=("person", "username"),
        adapter_profiles=("username-full", "username-ru-ua"),
    ),
    SearchProfile(
        name="ru-ua-full",
        title="RU/UA focused fan-out",
        description="RU/UA source pack and RU/UA-aware username/social routes.",
        target_kinds=("person", "username", "social", "telegram", "instagram", "ru-ua"),
        native_kinds=("person", "username", "social", "telegram", "instagram", "ru-ua"),
        adapter_profiles=("username-ru-ua",),
    ),
    SearchProfile(
        name="passive-recon",
        title="Passive domain and URL recon",
        description="Domain/URL native recon plus passive upstream recon adapters.",
        target_kinds=("domain", "url"),
        native_kinds=("domain", "url"),
        adapter_profiles=("domain-recon", "url-archive"),
    ),
    SearchProfile(
        name="web-full",
        title="Web and broad recon fan-out",
        description="Domain/URL native recon plus passive and broad recon adapters.",
        target_kinds=("domain", "url"),
        native_kinds=("domain", "url"),
        adapter_profiles=("domain-recon", "broad-recon", "url-archive"),
    ),
    SearchProfile(
        name="image-full",
        title="Image local analysis fan-out",
        description="Local metadata, OCR and QR/barcode tools for image-derived OSINT seeds.",
        target_kinds=("image",),
        local_tools=("powershell-file-baseline", "exiftool", "imagemagick-identify", "tesseract-ocr", "zbarimg"),
        note="Face recognition and identity-by-face matching are not part of this profile.",
    ),
    SearchProfile(
        name="social-full",
        title="Social platform fan-out",
        description="Telegram, Instagram and RU social public metadata plus compatible username adapters.",
        target_kinds=("telegram", "instagram", "social", "username"),
        native_kinds=("telegram", "instagram", "social", "username"),
        adapter_profiles=("username-full", "username-ru-ua"),
    ),
)


def list_search_profiles() -> tuple[SearchProfile, ...]:
    return SEARCH_PROFILES


def find_search_profile(name: str) -> SearchProfile:
    normalized = name.strip().lower()
    for profile in SEARCH_PROFILES:
        if profile.name.lower() == normalized:
            return profile
    raise ValueError(f"Unknown search profile: {name}")


def classify_target(value: str) -> str:
    stripped = value.strip()
    lower = stripped.lower()
    path = Path(stripped)
    if _looks_like_email(stripped):
        return "email"
    if lower.startswith(("http://", "https://")):
        return _url_kind(lower)
    if lower.startswith("vk:") or lower.startswith("ok:") or lower.startswith("mailru:") or lower.startswith("yandex:"):
        return "social"
    if lower.startswith("@"):
        return "username"
    if _looks_like_phone(stripped):
        return "phone"
    if _looks_like_image_path(path, lower):
        return "image"
    if _looks_like_domain(stripped):
        return "domain"
    if " " in stripped:
        return "person"
    return "username"


def build_search_plan(
    target_kind: str,
    target_value: str,
    *,
    profile_name: str = "safe",
    region: str = "all",
    include_restricted: bool = False,
) -> SearchPlan:
    if target_kind == "auto":
        target_kind = classify_target(target_value)
    if target_kind not in TARGET_KINDS:
        raise ValueError(f"Unsupported search target kind: {target_kind}")
    profile = _profile_for_target(profile_name, target_kind)
    target = ScanTarget(kind=target_kind, value=target_value, region=region)
    warnings = _plan_warnings(target, profile, include_restricted)
    steps: list[PlannedStep] = []
    steps.extend(_native_steps(target, profile))
    steps.extend(_adapter_steps(target, profile, include_restricted=include_restricted))
    steps.extend(_local_tool_steps(target, profile))
    if not include_restricted:
        steps.extend(_excluded_steps(target, profile))
    return SearchPlan(target=target, profile=profile, steps=tuple(_dedupe_steps(steps)), warnings=warnings)


def ready_adapter_repositories(plan: SearchPlan, *, limit: int | None = None) -> tuple[str, ...]:
    repositories: list[str] = []
    seen: set[str] = set()
    for step in plan.steps:
        if step.stage != "adapter" or step.status != "ready" or step.readiness != "ready":
            continue
        adapter_status = str((step.metadata or {}).get("adapter_status", ""))
        if adapter_status == "restricted":
            continue
        key = step.source.lower()
        if key in seen:
            continue
        seen.add(key)
        repositories.append(step.source)
        if limit is not None and len(repositories) >= limit:
            break
    return tuple(repositories)


def _profile_for_target(profile_name: str, target_kind: str) -> SearchProfile:
    if profile_name == "auto":
        profile_name = _default_profile_for_target(target_kind)
    profile = find_search_profile(profile_name)
    if target_kind not in profile.target_kinds:
        raise ValueError(f"Profile {profile.name} does not support target kind: {target_kind}")
    return profile


def _default_profile_for_target(target_kind: str) -> str:
    defaults = {
        "phone": "phone-full",
        "email": "email-full",
        "username": "username-full",
        "person": "person-full",
        "domain": "passive-recon",
        "url": "web-full",
        "image": "image-full",
        "telegram": "social-full",
        "instagram": "social-full",
        "social": "social-full",
        "ru-ua": "ru-ua-full",
    }
    return defaults.get(target_kind, "safe")


def _native_steps(target: ScanTarget, profile: SearchProfile) -> tuple[PlannedStep, ...]:
    steps: list[PlannedStep] = []
    for native_kind in profile.native_kinds:
        if target.kind == native_kind:
            value = target.value
            reason = "Direct native module for this target kind."
        elif target.kind == "person" and native_kind == "username":
            value = "<derived usernames>"
            reason = "Person expansion can produce derived username targets."
        else:
            continue
        steps.append(
            PlannedStep(
                stage="native",
                source=f"scan {native_kind}",
                title=f"Native {native_kind} scan",
                target_kind=native_kind,
                target_value=value,
                status="planned",
                command=_native_command(native_kind, value, target.region),
                readiness="built_in",
                reason=reason,
            )
        )
    return tuple(steps)


def _adapter_steps(
    target: ScanTarget,
    profile: SearchProfile,
    *,
    include_restricted: bool,
) -> tuple[PlannedStep, ...]:
    repositories = expand_adapter_repositories(profile.adapter_profiles, profile.adapter_repositories)
    if include_restricted or profile.include_restricted:
        repositories = repositories + tuple(
            adapter.repository
            for adapter in filter_adapters("restricted")
            if _restricted_adapter_matches(adapter.repository, target.kind)
        )
    steps: list[PlannedStep] = []
    for repository in repositories:
        adapter = find_adapter(repository)
        if repository in profile.excluded_repositories and not include_restricted:
            continue
        step_target = target
        if adapter.target_kinds and target.kind not in adapter.target_kinds:
            if target.kind == "person" and "username" in adapter.target_kinds:
                step_target = ScanTarget(kind="username", value="<derived usernames>", region=target.region)
            else:
                continue
        setup = build_adapter_setup(adapter)
        command = format_command(adapter.render_command(step_target))
        steps.append(_adapter_step(step_target, setup, command))
    return tuple(steps)


def _adapter_step(target: ScanTarget, setup: AdapterSetup, command: str) -> PlannedStep:
    status = "ready" if setup.readiness == "ready" else setup.readiness
    reason = _adapter_reason(setup)
    return PlannedStep(
        stage="adapter",
        source=setup.repository,
        title=setup.command_hint or setup.repository,
        target_kind=target.kind,
        target_value=target.value,
        status=status,
        command=command,
        readiness=setup.readiness,
        reason=reason,
        install_note=setup.install_command or setup.install_note or setup.install_kind,
        docs_url=setup.docs_url,
        metadata={
            "adapter_status": setup.adapter_status,
            "required_env": list(setup.required_env),
            "missing_env": list(setup.missing_env),
            "optional_env": list(setup.optional_env),
            "executable": setup.executable,
            "executable_path": setup.executable_path,
        },
    )


def _local_tool_steps(target: ScanTarget, profile: SearchProfile) -> tuple[PlannedStep, ...]:
    tools_by_name = {tool.name: tool for tool in LOCAL_TOOLS}
    steps: list[PlannedStep] = []
    for tool_name in profile.local_tools:
        tool = tools_by_name[tool_name]
        if target.kind not in tool.target_kinds:
            continue
        executable_path = shutil.which(tool.executable) if tool.executable else ""
        readiness = "ready" if executable_path else "missing"
        steps.append(
            PlannedStep(
                stage="local-tool",
                source=tool.name,
                title=tool.title,
                target_kind=target.kind,
                target_value=target.value,
                status=readiness,
                command=format_command(tool.render_command(target)),
                readiness=readiness,
                reason="Local image/file tool route.",
                install_note=tool.install_note,
                docs_url=tool.docs_url,
                metadata={
                    "executable": tool.executable,
                    "executable_path": executable_path or "",
                },
            )
        )
    return tuple(steps)


def _excluded_steps(target: ScanTarget, profile: SearchProfile) -> tuple[PlannedStep, ...]:
    steps: list[PlannedStep] = []
    for repository in profile.excluded_repositories:
        adapter = find_adapter(repository)
        steps.append(
            PlannedStep(
                stage="excluded",
                source=adapter.repository,
                title=adapter.capability,
                target_kind=target.kind,
                target_value=target.value,
                status="excluded",
                readiness="excluded",
                reason="Excluded from this profile; use a dedicated restricted profile only after scope review.",
                install_note=adapter.install_note,
                docs_url=adapter.docs_url,
                metadata={"adapter_status": adapter.status},
            )
        )
    return tuple(steps)


def _plan_warnings(
    target: ScanTarget,
    profile: SearchProfile,
    include_restricted: bool,
) -> tuple[str, ...]:
    warnings: list[str] = []
    if profile.note:
        warnings.append(profile.note)
    if target.kind == "image":
        warnings.append("Image search plan excludes face recognition and identity-by-face matching.")
    if include_restricted:
        warnings.append("Restricted adapters are included in the plan only when target-compatible and still require explicit execute safeguards.")
    return tuple(warnings)


def _native_command(native_kind: str, value: str, region: str) -> str:
    command = ("python", "-m", "osint_toolkit", "scan", native_kind, value)
    if native_kind in {"username", "person", "social", "telegram", "instagram", "ru-ua"}:
        command = command + ("--region", region)
    return format_command(command)


def _adapter_reason(setup: AdapterSetup) -> str:
    if setup.readiness == "ready":
        return "Adapter executable and required environment are available."
    if setup.readiness == "missing":
        return "Adapter executable is not on PATH."
    if setup.readiness == "config_missing":
        return "Adapter executable is available but required environment variables are missing."
    if setup.readiness == "restricted":
        return "Adapter is restricted and is not part of normal fan-out execution."
    return "Adapter has no executable command configured yet."


def _dedupe_steps(steps: list[PlannedStep]) -> tuple[PlannedStep, ...]:
    seen: set[tuple[str, str, str, str]] = set()
    deduped: list[PlannedStep] = []
    for step in steps:
        key = (step.stage, step.source, step.target_kind, step.command)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(step)
    return tuple(deduped)


def _looks_like_email(value: str) -> bool:
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value))


def _looks_like_phone(value: str) -> bool:
    compact = re.sub(r"[\s().-]", "", value)
    return bool(re.fullmatch(r"\+?\d{8,16}", compact))


def _looks_like_domain(value: str) -> bool:
    return bool(re.fullmatch(r"(?=.{1,253}$)(?!-)[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value))


def _looks_like_image_path(path: Path, lower_value: str) -> bool:
    image_suffixes = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".heic")
    return lower_value.endswith(image_suffixes) or (
        path.exists() and path.is_file() and path.suffix.lower() in image_suffixes
    )


def _restricted_adapter_matches(repository: str, target_kind: str) -> bool:
    mapping = {
        "megadose/ignorant": ("phone",),
        "megadose/holehe": ("email",),
        "martinvigo/email2phonenumber": ("email",),
    }
    return target_kind in mapping.get(repository, ())


def _url_kind(lower_url: str) -> str:
    if "instagram.com/" in lower_url:
        return "instagram"
    if "t.me/" in lower_url or "telegram.me/" in lower_url:
        return "telegram"
    if any(domain in lower_url for domain in ("vk.com/", "ok.ru/", "mail.ru/", "yandex.")):
        return "social"
    return "url"
