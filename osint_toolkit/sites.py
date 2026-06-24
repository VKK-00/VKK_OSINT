from __future__ import annotations

import json
import re
from string import Formatter
from dataclasses import dataclass, replace
from importlib import resources
from typing import Any


DEFAULT_USERNAME_PATTERN = r"(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._-]{0,62}[A-Za-z0-9])"
DEFAULT_USERNAME_RULE_NOTE = "letters, numbers, dot, underscore or dash; no leading/trailing separator"
SHERLOCK_DATA_RESOURCE = "sherlock_data.json"
SHERLOCK_SOURCE_PROJECT = "sherlock"
WHATSMYNAME_DATA_RESOURCE = "whatsmyname_wmn_data.json"
WHATSMYNAME_SOURCE_PROJECT = "whatsmyname"
MAIGRET_DATA_RESOURCE = "maigret_sites.json"
MAIGRET_SOURCE_PROJECT = "maigret"
SOURCE_NAME_SUFFIXES = {
    SHERLOCK_SOURCE_PROJECT: "Sherlock",
    WHATSMYNAME_SOURCE_PROJECT: "WhatsMyName",
    MAIGRET_SOURCE_PROJECT: "Maigret",
}


@dataclass(frozen=True)
class UsernameSite:
    name: str
    url_template: str
    profile_url_template: str = ""
    region: str = "global"
    source_projects: tuple[str, ...] = ()
    username_pattern: str = DEFAULT_USERNAME_PATTERN
    rule_note: str = DEFAULT_USERNAME_RULE_NOTE
    profile_markers: tuple[str, ...] = ()
    not_found_markers: tuple[str, ...] = ()
    candidate_status_codes: tuple[int, ...] = ()
    not_found_status_codes: tuple[int, ...] = ()
    request_headers: tuple[tuple[str, str], ...] = ()
    request_method: str = "GET"
    request_body_template: str = ""

    def url_for(self, username: str) -> str:
        return self.url_template.format(username=username)

    def profile_url_for(self, username: str) -> str:
        if not self.profile_url_template:
            return ""
        return self.profile_url_template.format(username=username)

    def request_body_for(self, username: str) -> str:
        return self.request_body_template.replace("{username}", username)

    def validate_username(self, username: str) -> str:
        if re.fullmatch(self.username_pattern, username):
            return ""
        return f"{self.name} username rule: {self.rule_note}."

    def match_content(self, username: str, title: str, body_text: str) -> tuple[str, str]:
        content = f"{title}\n{body_text}".casefold()
        if not content.strip():
            return "", ""
        for marker in self.not_found_markers:
            rendered = _render_marker(marker, username)
            if rendered.casefold() in content:
                return "not_found_marker", marker
        for marker in self.profile_markers:
            rendered = _render_marker(marker, username)
            if rendered.casefold() in content:
                return "profile_marker", marker
        return "", ""


CURATED_USERNAME_SITES: tuple[UsernameSite, ...] = (
    UsernameSite(
        "GitHub",
        "https://github.com/{username}",
        source_projects=("sherlock", "maigret", "whatsmyname"),
        username_pattern=r"(?!.*--)[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?",
        rule_note="1-39 letters, numbers or single dashes; no leading/trailing dash",
        profile_markers=("data-hovercard-type=\"user\"", "contribution activity", "repositories"),
        not_found_markers=("Not Found", "This is not the web page you are looking for"),
    ),
    UsernameSite("GitLab", "https://gitlab.com/{username}", source_projects=("sherlock", "maigret", "whatsmyname")),
    UsernameSite(
        "Bitbucket",
        "https://bitbucket.org/{username}/",
        source_projects=("sherlock", "maigret", "whatsmyname"),
    ),
    UsernameSite(
        "Reddit",
        "https://www.reddit.com/user/{username}",
        source_projects=("sherlock", "maigret"),
        username_pattern=r"[A-Za-z0-9_-]{3,20}",
        rule_note="3-20 letters, numbers, underscores or dashes",
        not_found_markers=("Sorry, nobody on Reddit goes by that name", "page not found"),
    ),
    UsernameSite(
        "X/Twitter",
        "https://x.com/{username}",
        source_projects=("sherlock", "maigret", "tinfoleak"),
        username_pattern=r"[A-Za-z0-9_]{1,15}",
        rule_note="1-15 letters, numbers or underscores",
        not_found_markers=("This account doesn’t exist", "This account doesn't exist"),
    ),
    UsernameSite(
        "Instagram",
        "https://www.instagram.com/{username}/",
        source_projects=("sherlock", "maigret", "osintgram", "instaloader"),
        username_pattern=r"[A-Za-z0-9](?:[A-Za-z0-9._]{0,28}[A-Za-z0-9])?",
        rule_note="1-30 letters, numbers, dots or underscores; no leading/trailing separator",
        not_found_markers=("Sorry, this page isn't available", "The link you followed may be broken"),
    ),
    UsernameSite(
        "Threads",
        "https://www.threads.net/@{username}",
        source_projects=("sherlock", "maigret"),
        username_pattern=r"[A-Za-z0-9](?:[A-Za-z0-9._]{0,28}[A-Za-z0-9])?",
        rule_note="1-30 letters, numbers, dots or underscores; no leading/trailing separator",
    ),
    UsernameSite(
        "Telegram",
        "https://t.me/{username}",
        source_projects=("awesome-telegram-osint", "telegram-osint"),
        username_pattern=r"[A-Za-z][A-Za-z0-9_]{4,31}",
        rule_note="5-32 characters, starts with a letter, letters/numbers/underscores only",
        profile_markers=("tgme_page_title", "tgme_page_description", "View in Telegram"),
    ),
    UsernameSite(
        "YouTube",
        "https://www.youtube.com/@{username}",
        source_projects=("yark", "maigret"),
        username_pattern=r"[A-Za-z0-9][A-Za-z0-9._-]{1,28}[A-Za-z0-9]",
        rule_note="3-30 letters, numbers, dots, underscores or dashes; no leading/trailing separator",
        not_found_markers=("This page isn't available", "404 Not Found"),
    ),
    UsernameSite(
        "TikTok",
        "https://www.tiktok.com/@{username}",
        source_projects=("sherlock", "maigret"),
        username_pattern=r"[A-Za-z0-9](?:[A-Za-z0-9._]{0,22}[A-Za-z0-9])",
        rule_note="2-24 letters, numbers, dots or underscores; no leading/trailing separator",
        not_found_markers=("Couldn't find this account", "Couldn’t find this account"),
    ),
    UsernameSite(
        "Twitch",
        "https://www.twitch.tv/{username}",
        source_projects=("sherlock", "maigret"),
        username_pattern=r"[A-Za-z0-9_]{4,25}",
        rule_note="4-25 letters, numbers or underscores",
        not_found_markers=("Sorry. Unless you’ve got a time machine", "Sorry. Unless you've got a time machine"),
    ),
    UsernameSite(
        "Medium",
        "https://medium.com/@{username}",
        source_projects=("sherlock", "maigret"),
        username_pattern=r"[A-Za-z0-9_]{1,50}",
        rule_note="letters, numbers or underscores",
    ),
    UsernameSite(
        "Pinterest",
        "https://www.pinterest.com/{username}/",
        source_projects=("sherlock", "maigret"),
        username_pattern=r"[A-Za-z0-9_]{3,30}",
        rule_note="3-30 letters, numbers or underscores",
    ),
    UsernameSite(
        "Steam",
        "https://steamcommunity.com/id/{username}",
        source_projects=("sherlock", "maigret"),
        username_pattern=r"[A-Za-z0-9_-]{2,32}",
        rule_note="2-32 letters, numbers, underscores or dashes",
    ),
    UsernameSite("Kaggle", "https://www.kaggle.com/{username}", source_projects=("sherlock", "maigret")),
    UsernameSite(
        "HackerOne",
        "https://hackerone.com/{username}",
        source_projects=("sherlock", "maigret"),
        username_pattern=r"[A-Za-z0-9_-]{3,39}",
        rule_note="3-39 letters, numbers, underscores or dashes",
    ),
    UsernameSite(
        "Keybase",
        "https://keybase.io/{username}",
        source_projects=("sherlock", "maigret"),
        username_pattern=r"[A-Za-z0-9_]{2,16}",
        rule_note="2-16 letters, numbers or underscores",
    ),
    UsernameSite(
        "LinkedIn",
        "https://www.linkedin.com/in/{username}",
        source_projects=("linkedin2username", "dorks-collections-list"),
        username_pattern=r"[A-Za-z0-9][A-Za-z0-9-]{1,98}[A-Za-z0-9]",
        rule_note="3-100 letters, numbers or dashes; no leading/trailing dash",
        not_found_markers=("This profile is not available", "Profile Not Found"),
    ),
    UsernameSite("DEV", "https://dev.to/{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("NPM", "https://www.npmjs.com/~{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("PyPI", "https://pypi.org/user/{username}/", source_projects=("sherlock", "maigret")),
    UsernameSite("RubyGems", "https://rubygems.org/profiles/{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("Docker Hub", "https://hub.docker.com/u/{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("Product Hunt", "https://www.producthunt.com/@{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("Dribbble", "https://dribbble.com/{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("Behance", "https://www.behance.net/{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("Vimeo", "https://vimeo.com/{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("SoundCloud", "https://soundcloud.com/{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("Flickr", "https://www.flickr.com/people/{username}/", source_projects=("sherlock", "maigret")),
    UsernameSite("Patreon", "https://www.patreon.com/{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("Linktree", "https://linktr.ee/{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("About.me", "https://about.me/{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("Facebook", "https://www.facebook.com/{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("Snapchat", "https://www.snapchat.com/add/{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("Quora", "https://www.quora.com/profile/{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("VK", "https://vk.com/{username}", region="ru", source_projects=("snoop", "api-s-for-osint", "osint-stuff-tool-collection")),
    UsernameSite("OK.ru", "https://ok.ru/{username}", region="ru", source_projects=("api-s-for-osint", "holehe")),
    UsernameSite(
        "Habr",
        "https://habr.com/ru/users/{username}/",
        region="ru",
        source_projects=("snoop", "maigret"),
        username_pattern=r"[A-Za-z0-9_-]{3,30}",
        rule_note="3-30 letters, numbers, underscores or dashes",
        not_found_markers=("Пользователь не найден", "Такого пользователя нет"),
    ),
)


def _load_sherlock_sites() -> tuple[UsernameSite, ...]:
    return tuple(
        site
        for name, entry in _read_sherlock_data().items()
        if (site := _sherlock_entry_to_username_site(name, entry)) is not None
    )


def _load_whatsmyname_sites() -> tuple[UsernameSite, ...]:
    data = _read_whatsmyname_data()
    sites = data.get("sites")
    if not isinstance(sites, list):
        return ()
    return tuple(
        site
        for entry in sites
        if (site := _whatsmyname_entry_to_username_site(entry)) is not None
    )


def _load_maigret_sites() -> tuple[UsernameSite, ...]:
    data = _read_maigret_data()
    sites = data.get("sites")
    if not isinstance(sites, list):
        return ()
    return tuple(
        site
        for entry in sites
        if (site := _maigret_entry_to_username_site(entry)) is not None
    )


def _render_marker(marker: str, username: str) -> str:
    try:
        return marker.format(username=username)
    except (IndexError, KeyError, ValueError):
        return marker


def _read_sherlock_data() -> dict[str, Any]:
    return _read_json_resource(SHERLOCK_DATA_RESOURCE)


def _read_whatsmyname_data() -> dict[str, Any]:
    return _read_json_resource(WHATSMYNAME_DATA_RESOURCE)


def _read_maigret_data() -> dict[str, Any]:
    return _read_json_resource(MAIGRET_DATA_RESOURCE)


def _read_json_resource(resource_name: str) -> dict[str, Any]:
    try:
        resource = resources.files(__package__).joinpath("resources", resource_name)
        raw = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return {}

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}

    if not isinstance(data, dict):
        return {}
    return data


def _sherlock_entry_to_username_site(name: str, entry: Any) -> UsernameSite | None:
    if name.startswith("$") or not isinstance(entry, dict):
        return None

    url = entry.get("url")
    if not isinstance(url, str):
        return None
    request_method = entry.get("request_method")
    request_method = request_method.upper() if isinstance(request_method, str) else "GET"
    request_body_template = _sherlock_request_body_template(entry.get("request_payload")) if request_method == "POST" else ""
    request_url = entry.get("urlProbe") if request_method == "POST" and isinstance(entry.get("urlProbe"), str) else url
    has_url_username = "{}" in request_url
    has_body_username = "{username}" in request_body_template
    if not has_url_username and not has_body_username:
        return None

    username_pattern = _valid_regex(entry.get("regexCheck")) or DEFAULT_USERNAME_PATTERN
    rule_note = "Sherlock regexCheck" if username_pattern != DEFAULT_USERNAME_PATTERN else DEFAULT_USERNAME_RULE_NOTE
    profile_url_template = url.replace("{}", "{username}") if request_method == "POST" and "{}" in url else ""
    return UsernameSite(
        name=name,
        url_template=request_url.replace("{}", "{username}"),
        profile_url_template=profile_url_template,
        source_projects=(SHERLOCK_SOURCE_PROJECT,),
        username_pattern=username_pattern,
        rule_note=rule_note,
        not_found_markers=_string_tuple(entry.get("errorMsg")),
        request_headers=_header_tuple(entry.get("headers")),
        request_method=request_method if request_method == "POST" else "GET",
        request_body_template=request_body_template,
    )


def _whatsmyname_entry_to_username_site(entry: Any) -> UsernameSite | None:
    if not isinstance(entry, dict) or entry.get("valid") is False:
        return None

    name = entry.get("name")
    url = entry.get("uri_check")
    post_body = entry.get("post_body")
    has_url_account = isinstance(url, str) and "{account}" in url
    has_body_account = isinstance(post_body, str) and "{account}" in post_body
    if not isinstance(name, str) or not name or not isinstance(url, str):
        return None
    if not has_url_account and not has_body_account:
        return None

    profile_url = entry.get("uri_pretty") if isinstance(entry.get("uri_pretty"), str) else ""
    if profile_url:
        profile_url = profile_url.replace("{account}", "{username}")
    return UsernameSite(
        name=name,
        url_template=url.replace("{account}", "{username}"),
        profile_url_template=profile_url,
        source_projects=(WHATSMYNAME_SOURCE_PROJECT,),
        profile_markers=_string_tuple(entry.get("e_string")),
        not_found_markers=_string_tuple(entry.get("m_string")),
        candidate_status_codes=_int_tuple(entry.get("e_code")),
        not_found_status_codes=_int_tuple(entry.get("m_code")),
        request_headers=_header_tuple(entry.get("headers")),
        request_method="POST" if has_body_account else "GET",
        request_body_template=post_body.replace("{account}", "{username}") if has_body_account else "",
    )


def _maigret_entry_to_username_site(entry: Any) -> UsernameSite | None:
    if not isinstance(entry, dict):
        return None

    name = entry.get("name")
    url = entry.get("url")
    if not isinstance(name, str) or not name or not isinstance(url, str) or not _template_uses_only_username(url):
        return None

    username_pattern = _valid_regex(entry.get("regexCheck")) or DEFAULT_USERNAME_PATTERN
    rule_note = "Maigret regexCheck" if username_pattern != DEFAULT_USERNAME_PATTERN else DEFAULT_USERNAME_RULE_NOTE
    profile_url = entry.get("profile_url") if isinstance(entry.get("profile_url"), str) else ""
    if profile_url and not _template_uses_only_username(profile_url):
        profile_url = ""
    return UsernameSite(
        name=name,
        url_template=url,
        profile_url_template=profile_url,
        region=_region_from_tags(entry.get("tags")),
        source_projects=(MAIGRET_SOURCE_PROJECT,),
        username_pattern=username_pattern,
        rule_note=rule_note,
        profile_markers=_string_tuple(entry.get("presenceStrs")),
        not_found_markers=_string_tuple(entry.get("absenceStrs")),
        candidate_status_codes=(200,) if entry.get("checkType") == "status_code" else (),
        not_found_status_codes=(404,) if entry.get("checkType") == "status_code" else (),
        request_headers=_header_tuple(entry.get("headers")),
    )


def _valid_regex(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return ""
    try:
        re.compile(value)
    except re.error:
        return ""
    return value


def _template_uses_only_username(value: str) -> bool:
    try:
        fields = {field_name for _, field_name, _, _ in Formatter().parse(value) if field_name}
    except ValueError:
        return False
    return bool(fields) and fields <= {"username"}


def _string_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,) if value else ()
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, str) and item)
    return ()


def _region_from_tags(value: Any) -> str:
    if not isinstance(value, list):
        return "global"
    tags = {tag for tag in value if isinstance(tag, str)}
    if "ru" in tags and "ua" in tags:
        return "ru-ua"
    if "ru" in tags:
        return "ru"
    if "ua" in tags:
        return "ua"
    return "global"


def _int_tuple(value: Any) -> tuple[int, ...]:
    return (value,) if isinstance(value, int) else ()


def _header_tuple(value: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, dict):
        return ()
    return tuple(
        (key, header_value)
        for key, header_value in value.items()
        if isinstance(key, str) and isinstance(header_value, str)
    )


def _sherlock_request_body_template(value: Any) -> str:
    if isinstance(value, str):
        return value.replace("{}", "{username}") if "{}" in value else ""
    if isinstance(value, (dict, list)):
        try:
            rendered = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError):
            return ""
        return rendered.replace("{}", "{username}") if "{}" in rendered else ""
    return ""


def _merge_username_sites(
    *site_groups: tuple[UsernameSite, ...],
) -> tuple[UsernameSite, ...]:
    merged: list[UsernameSite] = []
    seen_names: set[str] = set()
    seen_templates: set[str] = set()

    for group in site_groups:
        for site in group:
            template_key = site.url_template.casefold()
            if template_key in seen_templates:
                continue

            site = _rename_duplicate_site(site, seen_names)
            merged.append(site)
            seen_names.add(site.name.casefold())
            seen_templates.add(template_key)

    return tuple(merged)


def _rename_duplicate_site(site: UsernameSite, seen_names: set[str]) -> UsernameSite:
    name_key = site.name.casefold()
    if name_key not in seen_names:
        return site

    suffix = _source_name_suffix(site)
    base_name = f"{site.name} ({suffix})"
    candidate = base_name
    index = 2
    while candidate.casefold() in seen_names:
        candidate = f"{base_name} {index}"
        index += 1
    return replace(site, name=candidate)


def _source_name_suffix(site: UsernameSite) -> str:
    for source in site.source_projects:
        if source in SOURCE_NAME_SUFFIXES:
            return SOURCE_NAME_SUFFIXES[source]
    if site.source_projects:
        return site.source_projects[0]
    return "imported"


SHERLOCK_USERNAME_SITES = _load_sherlock_sites()
SHERLOCK_IMPORTED_SITE_COUNT = len(SHERLOCK_USERNAME_SITES)
WHATSMYNAME_USERNAME_SITES = _load_whatsmyname_sites()
WHATSMYNAME_IMPORTED_SITE_COUNT = len(WHATSMYNAME_USERNAME_SITES)
MAIGRET_USERNAME_SITES = _load_maigret_sites()
MAIGRET_IMPORTED_SITE_COUNT = len(MAIGRET_USERNAME_SITES)
USERNAME_SITES = _merge_username_sites(
    CURATED_USERNAME_SITES,
    SHERLOCK_USERNAME_SITES,
    WHATSMYNAME_USERNAME_SITES,
    MAIGRET_USERNAME_SITES,
)
