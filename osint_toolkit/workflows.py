from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .catalog import Catalog
from .models import OsintProject


SAFETY_BOUNDARIES = (
    "Use only public, lawfully accessible sources.",
    "Document lawful basis, consent or legitimate research purpose before collecting personal data.",
    "Do not bypass privacy controls, authentication, rate limits or platform restrictions.",
    "Do not automate password recovery, credential harvesting, phishing or social engineering.",
    "Keep source notes, timestamps and confidence levels for every finding.",
)


COMMON_STEPS = (
    "Define scope: target type, allowed sources, excluded sources and stop conditions.",
    "Record seed identifiers exactly as provided; do not infer sensitive attributes without evidence.",
    "Collect candidate open-source hits and keep raw source URLs separately from conclusions.",
    "Cross-check identity matches with at least two independent public signals before reporting.",
    "Separate confirmed facts, weak indicators and unresolved leads in the final report.",
)


@dataclass(frozen=True)
class TaskProfile:
    name: str
    title: str
    queries: tuple[str, ...]
    kind: str
    preferred_levels: tuple[str, ...]
    steps: tuple[str, ...]


TASK_PROFILES: dict[str, TaskProfile] = {
    "person": TaskProfile(
        name="person",
        title="Person OSINT planning",
        queries=("people", "person", "profile", "digital footprint", "username", "email", "phone"),
        kind="people",
        preferred_levels=("direct_tool", "framework", "platform", "dataset", "resource_collection"),
        steps=(
            "Start from known identifiers: legal name, aliases, usernames, email, phone, public profiles.",
            "Use direct person/account tools first, then broader frameworks for enrichment.",
            "Avoid collecting private or irrelevant personal data; keep only case-relevant facts.",
        ),
    ),
    "username": TaskProfile(
        name="username",
        title="Username and social-account discovery",
        queries=("username", "social account", "profile", "digital footprint"),
        kind="people",
        preferred_levels=("direct_tool", "dataset", "framework", "resource_collection"),
        steps=(
            "Normalize the username exactly; preserve case and variants as separate leads.",
            "Search social-account focused tools and datasets before broader search engines.",
            "Treat same-name hits as candidates until profile content or cross-links confirm identity.",
        ),
    ),
    "email": TaskProfile(
        name="email",
        title="Email-focused OSINT planning",
        queries=("email", "breach", "registered accounts", "pwned", "mail"),
        kind="people",
        preferred_levels=("direct_tool", "framework", "resource_collection"),
        steps=(
            "Record the email address and domain separately.",
            "Prefer breach-notification and public exposure checks over account-enumeration flows.",
            "Do not trigger password recovery or notification mechanisms on third-party services.",
        ),
    ),
    "phone": TaskProfile(
        name="phone",
        title="Phone-number OSINT planning",
        queries=("phone", "mobile", "number"),
        kind="people",
        preferred_levels=("direct_tool", "resource_collection", "framework"),
        steps=(
            "Normalize the number with country code and keep the original formatting.",
            "Check numbering plan, public reputation and voluntarily published profile links.",
            "Do not place calls, send messages or trigger recovery flows as part of passive OSINT.",
        ),
    ),
    "telegram": TaskProfile(
        name="telegram",
        title="Telegram OSINT planning",
        queries=("telegram", "tgstat", "channel", "group"),
        kind="relevant",
        preferred_levels=("resource_collection", "direct_tool", "ru_platform_or_domain", "direct_ru_ua"),
        steps=(
            "Distinguish users, public channels, groups and forwarded content.",
            "Preserve message URLs, publication times, channel IDs and archive links.",
            "For RU/UA context, separate platform-specific sources from conflict/geography sources.",
        ),
    ),
    "instagram": TaskProfile(
        name="instagram",
        title="Instagram OSINT planning",
        queries=("instagram", "profile", "social"),
        kind="people",
        preferred_levels=("direct_tool", "supporting_indirect", "resource_collection"),
        steps=(
            "Treat profile metadata, media metadata and username reuse as separate evidence types.",
            "Avoid login-only or private-content collection unless there is a clear lawful basis.",
            "Archive public posts with timestamped source notes before analysis.",
        ),
    ),
    "russia": TaskProfile(
        name="russia",
        title="Russia-related OSINT resources",
        queries=("russia", "russian", "yandex", "vk", "mail.ru", "ok.ru", "tgstat"),
        kind="ru-ua",
        preferred_levels=("direct_ru_ua", "ru_platform_or_domain", "weak_context"),
        steps=(
            "Separate country-level sources from Russian-language platform sources.",
            "Note whether a source is regional context, infrastructure, social platform or search engine.",
            "Verify claims with non-platform corroboration where possible.",
        ),
    ),
    "ukraine": TaskProfile(
        name="ukraine",
        title="Ukraine-related OSINT resources",
        queries=("ukraine", "ukrainian", "ua", "deepstate", "liveuamap"),
        kind="ru-ua",
        preferred_levels=("direct_ru_ua", "ru_platform_or_domain", "weak_context"),
        steps=(
            "Separate conflict-map, public-record, media and platform leads.",
            "Preserve map layer names, timestamps and original source URLs.",
            "Cross-check geospatial claims against independent public sources.",
        ),
    ),
    "ru-platforms": TaskProfile(
        name="ru-platforms",
        title="Russian-language platform resources",
        queries=("vk", "vkontakte", "ok.ru", "mail.ru", "yandex", "tgstat"),
        kind="ru-ua",
        preferred_levels=("ru_platform_or_domain", "direct_ru_ua", "weak_context"),
        steps=(
            "Identify the platform and data type before collecting anything.",
            "Prefer platform documentation, public pages and transparent search resources.",
            "Document platform limitations, localization issues and source volatility.",
        ),
    ),
}


def recommend_projects(
    catalog: Catalog,
    task: str,
    *,
    region: str = "all",
    limit: int = 10,
) -> tuple[TaskProfile, tuple[OsintProject, ...]]:
    profile = get_profile(task)
    candidates = list(catalog.filter(kind=profile.kind))

    if region == "ru":
        candidates = [
            project
            for project in candidates
            if project.has_ru_ua
            or _contains_any(project, ("russia", "russian", "vk", "yandex", "mail.ru", "ok.ru", "tgstat"))
        ]
    elif region == "ua":
        candidates = [
            project
            for project in candidates
            if project.has_ru_ua or _contains_any(project, ("ukraine", "ukrainian", "ua", "deepstate", "liveuamap"))
        ]

    scored = sorted(
        ((score_project(project, profile), project) for project in candidates),
        key=lambda item: (-item[0], item[1].rank),
    )
    selected = [project for score, project in scored if score > 0]
    if not selected:
        selected = [project for _, project in scored]
    return profile, tuple(selected[:limit])


def get_profile(task: str) -> TaskProfile:
    try:
        return TASK_PROFILES[task]
    except KeyError as exc:
        known = ", ".join(sorted(TASK_PROFILES))
        raise ValueError(f"Unknown task '{task}'. Known tasks: {known}") from exc


def score_project(project: OsintProject, profile: TaskProfile) -> int:
    text = project.searchable_text
    score = 0
    for query in profile.queries:
        if query.lower() in text:
            score += 5
    if project.people_level in profile.preferred_levels:
        score += 4 + _preference_bonus(project.people_level, profile.preferred_levels)
    if project.ru_ua_level in profile.preferred_levels:
        score += 4 + _preference_bonus(project.ru_ua_level, profile.preferred_levels)
    if project.full_name.lower().split("/")[-1] in text:
        score += 1
    if project.stars >= 10000:
        score += 1
    return score


def render_recommendation(
    profile: TaskProfile,
    projects: tuple[OsintProject, ...],
    *,
    region: str = "all",
) -> str:
    lines = [
        f"# {profile.title}",
        "",
        f"Region filter: `{region}`",
        "",
        "## Safety boundaries",
        "",
    ]
    lines.extend(f"- {item}" for item in SAFETY_BOUNDARIES)
    lines.extend(["", "## Workflow", ""])
    lines.extend(f"{index}. {step}" for index, step in enumerate(COMMON_STEPS + profile.steps, start=1))
    lines.extend(["", "## Recommended catalog entries", ""])
    lines.append("| Rank | Repository | Focus | Level | Stars |")
    lines.append("|---:|---|---|---|---:|")
    for project in projects:
        focus = project.people_focus or project.ru_ua_focus or project.description
        level = project.people_level or project.ru_ua_level or "top100"
        lines.append(
            f"| {project.rank} | [{project.full_name}]({project.html_url}) | "
            f"{_escape_md(focus)} | {level} | {project.stars} |"
        )
    return "\n".join(lines) + "\n"


def render_brief(
    profile: TaskProfile,
    projects: tuple[OsintProject, ...],
    *,
    target_value: str = "",
    region: str = "all",
) -> str:
    generated = datetime.now().astimezone().isoformat(timespec="seconds")
    target_display = target_value if target_value else "(not provided)"
    lines = [
        f"# OSINT brief: {profile.title}",
        "",
        f"Generated: {generated}",
        f"Task: `{profile.name}`",
        f"Region filter: `{region}`",
        f"Seed value: `{target_display}`",
        "",
        "## Scope and boundaries",
        "",
    ]
    lines.extend(f"- {item}" for item in SAFETY_BOUNDARIES)
    lines.extend(
        [
            "",
            "## Working checklist",
            "",
        ]
    )
    lines.extend(f"- [ ] {step}" for step in COMMON_STEPS + profile.steps)
    lines.extend(
        [
            "",
            "## Suggested resources",
            "",
            "| Rank | Repository | Focus | Level | Note |",
            "|---:|---|---|---|---|",
        ]
    )
    for project in projects:
        focus = project.people_focus or project.ru_ua_focus or project.description
        level = project.people_level or project.ru_ua_level or "top100"
        note = project.people_note or project.ru_ua_note or project.description
        lines.append(
            f"| {project.rank} | [{project.full_name}]({project.html_url}) | "
            f"{_escape_md(focus)} | {level} | {_escape_md(note)} |"
        )
    lines.extend(
        [
            "",
            "## Evidence log template",
            "",
            "| Time | Source URL | Claim | Evidence type | Confidence | Notes |",
            "|---|---|---|---|---|---|",
            "|  |  |  |  |  |  |",
            "",
            "## Findings",
            "",
            "- Confirmed facts:",
            "- Weak indicators:",
            "- Unresolved leads:",
            "- Excluded or out-of-scope data:",
        ]
    )
    return "\n".join(lines) + "\n"


def write_brief(path: str | Path, content: str) -> Path:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    return output_path


def _contains_any(project: OsintProject, needles: tuple[str, ...]) -> bool:
    text = project.searchable_text
    return any(needle in text for needle in needles)


def _preference_bonus(level: str, preferred: tuple[str, ...]) -> int:
    try:
        return len(preferred) - preferred.index(level)
    except ValueError:
        return 0


def _escape_md(value: str) -> str:
    return " ".join(value.split()).replace("|", "\\|")

