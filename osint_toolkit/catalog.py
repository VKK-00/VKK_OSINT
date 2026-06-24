from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path
from typing import Iterable

from .models import OsintProject

SNAPSHOT_DATE = "2026-06-24"

TOP100_FILE = f"top_100_osint_github_{SNAPSHOT_DATE}.csv"
COMBINED_FILE = f"osint_people_ru_ua_{SNAPSHOT_DATE}.csv"
PEOPLE_FILE = f"osint_people_projects_{SNAPSHOT_DATE}.csv"
RU_UA_FILE = f"osint_ru_ua_projects_{SNAPSHOT_DATE}.csv"


class CatalogError(RuntimeError):
    pass


class Catalog:
    def __init__(self, projects: Iterable[OsintProject], data_dir: Path):
        self.projects = tuple(sorted(projects, key=lambda project: project.rank))
        self.data_dir = data_dir
        self._by_name = {project.full_name.lower(): project for project in self.projects}

    @classmethod
    def load(cls, data_dir: str | Path | None = None) -> "Catalog":
        root = Path(data_dir).resolve() if data_dir else default_data_dir()
        top100 = _read_csv(root / TOP100_FILE)
        combined = {row["full_name"]: row for row in _read_csv(root / COMBINED_FILE)}
        people_notes = {row["full_name"]: row for row in _read_csv(root / PEOPLE_FILE)}
        ru_ua_notes = {row["full_name"]: row for row in _read_csv(root / RU_UA_FILE)}

        projects: list[OsintProject] = []
        for row in top100:
            name = row["full_name"]
            annotation = combined.get(name, {})
            people = people_notes.get(name, {})
            regional = ru_ua_notes.get(name, {})
            projects.append(
                OsintProject(
                    rank=_to_int(row.get("rank")),
                    full_name=name,
                    stars=_to_int(row.get("stars")),
                    forks=_to_int(row.get("forks")),
                    open_issues=_to_int(row.get("open_issues")),
                    language=row.get("language", ""),
                    license=row.get("license", ""),
                    updated_at=row.get("updated_at", ""),
                    pushed_at=row.get("pushed_at", ""),
                    description=row.get("description", ""),
                    html_url=row.get("html_url", ""),
                    topics=_split_topics(row.get("topics", "")),
                    people_level=annotation.get("people_level", ""),
                    people_focus=annotation.get("people_focus", ""),
                    people_note=people.get("note", ""),
                    ru_ua_level=annotation.get("ru_ua_level", ""),
                    ru_ua_focus=annotation.get("ru_ua_focus", ""),
                    ru_ua_note=regional.get("note", ""),
                )
            )
        return cls(projects, root)

    def get(self, full_name: str) -> OsintProject:
        project = self._by_name.get(full_name.lower())
        if not project:
            raise CatalogError(f"Repository not found in catalog: {full_name}")
        return project

    def filter(
        self,
        *,
        kind: str = "all",
        level: str | None = None,
        query: str | None = None,
        min_stars: int | None = None,
        direct_only: bool = False,
        limit: int | None = None,
    ) -> tuple[OsintProject, ...]:
        projects = list(self.projects)

        if kind == "people":
            projects = [project for project in projects if project.has_people]
        elif kind == "ru-ua":
            projects = [project for project in projects if project.has_ru_ua]
        elif kind == "relevant":
            projects = [project for project in projects if project.is_relevant]
        elif kind != "all":
            raise CatalogError(f"Unsupported catalog kind: {kind}")

        if direct_only:
            projects = [project for project in projects if _is_direct(project, kind)]

        if level:
            projects = [
                project
                for project in projects
                if project.people_level == level or project.ru_ua_level == level
            ]

        if query:
            terms = [term.lower() for term in query.split() if term.strip()]
            projects = [
                project
                for project in projects
                if all(term in project.searchable_text for term in terms)
            ]

        if min_stars is not None:
            projects = [project for project in projects if project.stars >= min_stars]

        projects.sort(key=lambda project: (project.rank, -project.stars))
        if limit is not None:
            projects = projects[:limit]
        return tuple(projects)

    def stats(self) -> dict[str, object]:
        people = [project for project in self.projects if project.has_people]
        regional = [project for project in self.projects if project.has_ru_ua]
        relevant = [project for project in self.projects if project.is_relevant]
        return {
            "total": len(self.projects),
            "people": len(people),
            "ru_ua": len(regional),
            "relevant": len(relevant),
            "intersection": len([p for p in self.projects if p.has_people and p.has_ru_ua]),
            "people_levels": dict(Counter(project.people_level for project in people)),
            "ru_ua_levels": dict(Counter(project.ru_ua_level for project in regional)),
            "languages": dict(Counter(project.language or "unknown" for project in self.projects)),
            "data_dir": str(self.data_dir),
        }


def default_data_dir() -> Path:
    return Path(__file__).resolve().parents[1]


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise CatalogError(f"Required data file is missing: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _to_int(value: object) -> int:
    try:
        return int(str(value or "0"))
    except ValueError:
        return 0


def _split_topics(value: str) -> tuple[str, ...]:
    return tuple(topic.strip() for topic in value.split(";") if topic.strip())


def _is_direct(project: OsintProject, kind: str) -> bool:
    if kind == "people":
        return project.people_level == "direct_tool"
    if kind == "ru-ua":
        return project.ru_ua_level == "direct_ru_ua"
    return project.people_level == "direct_tool" or project.ru_ua_level == "direct_ru_ua"

