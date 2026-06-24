from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OsintProject:
    rank: int
    full_name: str
    stars: int
    forks: int
    open_issues: int
    language: str
    license: str
    updated_at: str
    pushed_at: str
    description: str
    html_url: str
    topics: tuple[str, ...]
    people_level: str = ""
    people_focus: str = ""
    people_note: str = ""
    ru_ua_level: str = ""
    ru_ua_focus: str = ""
    ru_ua_note: str = ""

    @property
    def has_people(self) -> bool:
        return bool(self.people_level)

    @property
    def has_ru_ua(self) -> bool:
        return bool(self.ru_ua_level)

    @property
    def is_relevant(self) -> bool:
        return self.has_people or self.has_ru_ua

    @property
    def searchable_text(self) -> str:
        return " ".join(
            [
                self.full_name,
                self.description,
                self.language,
                self.license,
                " ".join(self.topics),
                self.people_level,
                self.people_focus,
                self.people_note,
                self.ru_ua_level,
                self.ru_ua_focus,
                self.ru_ua_note,
            ]
        ).lower()

    def level_for(self, kind: str) -> str:
        if kind == "people":
            return self.people_level
        if kind == "ru-ua":
            return self.ru_ua_level
        return self.people_level or self.ru_ua_level

    def focus_for(self, kind: str) -> str:
        if kind == "people":
            return self.people_focus
        if kind == "ru-ua":
            return self.ru_ua_focus
        return self.people_focus or self.ru_ua_focus

    def note_for(self, kind: str) -> str:
        if kind == "people":
            return self.people_note
        if kind == "ru-ua":
            return self.ru_ua_note
        return self.people_note or self.ru_ua_note

    def to_dict(self) -> dict[str, object]:
        return {
            "rank": self.rank,
            "full_name": self.full_name,
            "stars": self.stars,
            "forks": self.forks,
            "open_issues": self.open_issues,
            "language": self.language,
            "license": self.license,
            "updated_at": self.updated_at,
            "pushed_at": self.pushed_at,
            "description": self.description,
            "html_url": self.html_url,
            "topics": list(self.topics),
            "people_level": self.people_level,
            "people_focus": self.people_focus,
            "people_note": self.people_note,
            "ru_ua_level": self.ru_ua_level,
            "ru_ua_focus": self.ru_ua_focus,
            "ru_ua_note": self.ru_ua_note,
        }

