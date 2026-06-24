from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class UsernameSite:
    name: str
    url_template: str
    region: str = "global"
    source_projects: tuple[str, ...] = ()

    def url_for(self, username: str) -> str:
        return self.url_template.format(username=username)


USERNAME_SITES: tuple[UsernameSite, ...] = (
    UsernameSite("GitHub", "https://github.com/{username}", source_projects=("sherlock", "maigret", "whatsmyname")),
    UsernameSite("GitLab", "https://gitlab.com/{username}", source_projects=("sherlock", "maigret", "whatsmyname")),
    UsernameSite("Reddit", "https://www.reddit.com/user/{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("X/Twitter", "https://x.com/{username}", source_projects=("sherlock", "maigret", "tinfoleak")),
    UsernameSite("Instagram", "https://www.instagram.com/{username}/", source_projects=("sherlock", "maigret", "osintgram", "instaloader")),
    UsernameSite("Telegram", "https://t.me/{username}", source_projects=("awesome-telegram-osint", "telegram-osint")),
    UsernameSite("YouTube", "https://www.youtube.com/@{username}", source_projects=("yark", "maigret")),
    UsernameSite("TikTok", "https://www.tiktok.com/@{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("Twitch", "https://www.twitch.tv/{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("Medium", "https://medium.com/@{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("Pinterest", "https://www.pinterest.com/{username}/", source_projects=("sherlock", "maigret")),
    UsernameSite("Steam", "https://steamcommunity.com/id/{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("Kaggle", "https://www.kaggle.com/{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("HackerOne", "https://hackerone.com/{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("Keybase", "https://keybase.io/{username}", source_projects=("sherlock", "maigret")),
    UsernameSite("LinkedIn", "https://www.linkedin.com/in/{username}", source_projects=("linkedin2username", "dorks-collections-list")),
    UsernameSite("VK", "https://vk.com/{username}", region="ru", source_projects=("snoop", "api-s-for-osint", "osint-stuff-tool-collection")),
    UsernameSite("OK.ru", "https://ok.ru/{username}", region="ru", source_projects=("api-s-for-osint", "holehe")),
    UsernameSite("Habr", "https://habr.com/ru/users/{username}/", region="ru", source_projects=("snoop", "maigret")),
)

