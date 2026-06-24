from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class UsernameSite:
    name: str
    url_template: str
    region: str = "global"
    source_projects: tuple[str, ...] = ()
    username_pattern: str = r"(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._-]{0,62}[A-Za-z0-9])"
    rule_note: str = "letters, numbers, dot, underscore or dash; no leading/trailing separator"
    profile_markers: tuple[str, ...] = ()
    not_found_markers: tuple[str, ...] = ()

    def url_for(self, username: str) -> str:
        return self.url_template.format(username=username)

    def validate_username(self, username: str) -> str:
        if re.fullmatch(self.username_pattern, username):
            return ""
        return f"{self.name} username rule: {self.rule_note}."

    def match_content(self, username: str, title: str, body_text: str) -> tuple[str, str]:
        content = f"{title}\n{body_text}".casefold()
        if not content.strip():
            return "", ""
        for marker in self.not_found_markers:
            rendered = marker.format(username=username)
            if rendered.casefold() in content:
                return "not_found_marker", marker
        for marker in self.profile_markers:
            rendered = marker.format(username=username)
            if rendered.casefold() in content:
                return "profile_marker", marker
        return "", ""


USERNAME_SITES: tuple[UsernameSite, ...] = (
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
