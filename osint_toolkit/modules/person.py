from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

from ..engine import Finding, RunConfig, ScanTarget

TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)
HANDLE_SUFFIXES = ("official", "real", "online")
MAX_GENERATED_CANDIDATES = 64
DEFAULT_SOURCE_PROJECTS = ("maigret", "sherlock", "linkedin2username", "dorks-collections-list")
RU_UA_ALIAS_SOURCE = "osint-toolkit-ru-ua-aliases"
PERSON_ALIAS_RESOURCE = "person_aliases_ru_ua.json"
STRATEGY_BASE_SCORES = {
    "operator_alias": 98,
    "operator_alias_last_joined": 92,
    "operator_alias_dot_last": 90,
    "operator_alias_underscore_last": 88,
    "first_last_joined": 88,
    "first_dot_last": 86,
    "first_underscore_last": 84,
    "first_initial_last": 82,
    "first_dash_last": 80,
    "first_last_initial": 78,
    "last_first_joined": 76,
    "last_dot_first": 74,
    "last_underscore_first": 72,
    "last_dash_first": 70,
    "last_first_initial": 68,
    "alias_last_joined": 78,
    "alias_dot_last": 76,
    "alias_underscore_last": 74,
    "alias_initial_last": 70,
    "given_name_alias": 58,
    "full_name_joined": 82,
    "first_middle_initials_last": 80,
    "initials": 46,
    "initial_pair": 44,
    "handle_suffix": 52,
    "first": 42,
}

GIVEN_NAME_ALIASES = {
    "aleksandr": ("alex", "sasha", "san", "sanya"),
    "alexandr": ("alex", "sasha", "san", "sanya"),
    "alexander": ("alex", "sasha"),
    "alexey": ("alex", "lesha"),
    "andriy": ("andrew", "andri"),
    "andrey": ("andrew", "andri"),
    "anna": ("ania", "anya", "ann"),
    "artem": ("artyom", "tema"),
    "bohdan": ("bogdan",),
    "dmytro": ("dima", "dmitry"),
    "dmitry": ("dima",),
    "iryna": ("ira", "irina"),
    "ivan": ("vanya", "john"),
    "kateryna": ("kate", "katya", "katerina"),
    "kyrylo": ("kirill", "kiril"),
    "maksym": ("max", "maks", "maxim"),
    "mariia": ("maria", "masha", "mary"),
    "maria": ("masha", "mary"),
    "mykhailo": ("misha", "michael"),
    "nataliia": ("natalia", "natasha", "nata"),
    "nikita": ("nik", "nick"),
    "oleksandr": ("alex", "sasha", "san", "sanya"),
    "oleksandra": ("alexandra", "sasha"),
    "olena": ("elena", "lena"),
    "pavlo": ("pavel", "paul"),
    "petro": ("petr", "peter"),
    "serhii": ("sergey", "serg"),
    "sergey": ("serg",),
    "sviatoslav": ("slava",),
    "tetiana": ("tatyana", "tanya"),
    "viktor": ("victor", "vitya"),
    "volodymyr": ("vladimir", "vova", "vlad"),
    "yevhen": ("evgeny", "zhenya"),
    "yuliia": ("julia", "yulia", "jules"),
}

TRANSLITERATION_TABLE = str.maketrans(
    {
        "а": "a",
        "б": "b",
        "в": "v",
        "г": "g",
        "ґ": "g",
        "д": "d",
        "е": "e",
        "ё": "e",
        "є": "ye",
        "ж": "zh",
        "з": "z",
        "и": "i",
        "і": "i",
        "ї": "yi",
        "й": "i",
        "к": "k",
        "л": "l",
        "м": "m",
        "н": "n",
        "о": "o",
        "п": "p",
        "р": "r",
        "с": "s",
        "т": "t",
        "у": "u",
        "ф": "f",
        "х": "kh",
        "ц": "ts",
        "ч": "ch",
        "ш": "sh",
        "щ": "shch",
        "ъ": "",
        "ы": "y",
        "ь": "",
        "э": "e",
        "ю": "yu",
        "я": "ya",
    }
)


@dataclass(frozen=True)
class UsernameCandidate:
    username: str
    strategy: str
    score: int = 0
    platform_hints: tuple[str, ...] = ()
    source_projects: tuple[str, ...] = DEFAULT_SOURCE_PROJECTS


@dataclass(frozen=True)
class PersonNameScanModule:
    name: str = "person-name-expansion"
    supported_targets: tuple[str, ...] = ("person",)
    default_limit: int = 24

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        normalized_name = normalize_person_name(target.value)
        if not normalized_name:
            return (
                Finding(
                    module=self.name,
                    source="normalizer",
                    target=target.value,
                    status="invalid",
                    confidence="high",
                    evidence="Could not normalize input into person-name tokens.",
                ),
            )

        limit = config.limit if config.limit is not None else self.default_limit
        candidates = generate_username_candidates(normalized_name, extra_aliases=config.person_aliases)
        if limit is not None:
            candidates = candidates[:limit]
        if not candidates:
            return (
                Finding(
                    module=self.name,
                    source="username-candidate",
                    target=target.value,
                    status="not_found",
                    confidence="low",
                    evidence="No username candidates could be generated from the person name.",
                    metadata={"normalized_name": normalized_name},
                ),
            )

        return tuple(
            Finding(
                module=self.name,
                source="username-candidate",
                target=target.value,
                status="candidate",
                confidence="low",
                evidence=(
                    f"Candidate username: {candidate.username} "
                    f"(score {candidate.score}; hints: {', '.join(candidate.platform_hints)}). "
                    "Verify before use."
                ),
                metadata={
                    "normalized_name": normalized_name,
                    "username": candidate.username,
                    "strategy": candidate.strategy,
                    "candidate_rank": str(index),
                    "candidate_score": str(candidate.score),
                    "platform_hints": ", ".join(candidate.platform_hints),
                    "source_projects": ", ".join(candidate.source_projects),
                },
            )
            for index, candidate in enumerate(candidates, start=1)
        )


def normalize_person_name(value: str) -> str:
    tokens = _name_tokens(value)
    return " ".join(tokens)


def generate_username_candidates(
    normalized_name: str,
    *,
    extra_aliases: tuple[str, ...] = (),
) -> tuple[UsernameCandidate, ...]:
    tokens = tuple(_username_token(token) for token in _name_tokens(normalized_name))
    tokens = tuple(token for token in tokens if token)
    if not tokens:
        return ()

    first = tokens[0]
    last = tokens[-1]
    middle = tokens[1:-1]

    proposals: list[UsernameCandidate] = [UsernameCandidate(first, "first")]
    if len(tokens) == 1:
        return _dedupe_candidates(tuple(proposals))

    proposals.extend(
        [
            UsernameCandidate(first + last, "first_last_joined"),
            UsernameCandidate(f"{first}.{last}", "first_dot_last"),
            UsernameCandidate(f"{first}_{last}", "first_underscore_last"),
            UsernameCandidate(f"{first}-{last}", "first_dash_last"),
            UsernameCandidate(first[0] + last, "first_initial_last"),
            UsernameCandidate(first + last[0], "first_last_initial"),
            UsernameCandidate(last + first, "last_first_joined"),
            UsernameCandidate(f"{last}.{first}", "last_dot_first"),
            UsernameCandidate(f"{last}_{first}", "last_underscore_first"),
            UsernameCandidate(f"{last}-{first}", "last_dash_first"),
            UsernameCandidate(last + first[0], "last_first_initial"),
            UsernameCandidate(first[0] + last[0], "initial_pair"),
        ]
    )

    if middle:
        initials = "".join(token[0] for token in (first, *middle, last) if token)
        compact = "".join(tokens)
        first_middle_last = first + "".join(token[0] for token in middle) + last
        proposals.extend(
            [
                UsernameCandidate(compact, "full_name_joined"),
                UsernameCandidate(initials, "initials"),
                UsernameCandidate(first_middle_last, "first_middle_initials_last"),
            ]
        )
    proposals.extend(_operator_alias_candidates(extra_aliases, last))
    proposals.extend(_alias_candidates(first, last))
    proposals.extend(_suffix_candidates(first, last))
    return _dedupe_candidates(tuple(proposals))


def _operator_alias_candidates(aliases: tuple[str, ...], last: str) -> tuple[UsernameCandidate, ...]:
    candidates: list[UsernameCandidate] = []
    for alias in aliases:
        handle = _username_handle(alias)
        token = _username_token("".join(_name_tokens(alias)))
        if handle:
            candidates.append(UsernameCandidate(handle, "operator_alias"))
        if token and last:
            candidates.extend(
                [
                    UsernameCandidate(token + last, "operator_alias_last_joined"),
                    UsernameCandidate(f"{token}.{last}", "operator_alias_dot_last"),
                    UsernameCandidate(f"{token}_{last}", "operator_alias_underscore_last"),
                ]
            )
    return tuple(candidates)


def _alias_candidates(first: str, last: str) -> tuple[UsernameCandidate, ...]:
    candidates: list[UsernameCandidate] = []
    for alias, source_projects in _given_name_alias_entries(first):
        candidates.extend(
            [
                UsernameCandidate(alias, "given_name_alias", source_projects=source_projects),
                UsernameCandidate(alias + last, "alias_last_joined", source_projects=source_projects),
                UsernameCandidate(f"{alias}.{last}", "alias_dot_last", source_projects=source_projects),
                UsernameCandidate(f"{alias}_{last}", "alias_underscore_last", source_projects=source_projects),
                UsernameCandidate(alias[0] + last, "alias_initial_last", source_projects=source_projects),
            ]
        )
    return tuple(candidates)


def _given_name_alias_entries(first: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    sources_by_alias: dict[str, tuple[str, ...]] = {}
    for alias in GIVEN_NAME_ALIASES.get(first, ()):
        sources_by_alias[alias] = DEFAULT_SOURCE_PROJECTS
    for alias in _bundled_given_name_aliases().get(first, ()):
        current = sources_by_alias.get(alias, ())
        sources_by_alias[alias] = _dedupe_strings(current + DEFAULT_SOURCE_PROJECTS + (RU_UA_ALIAS_SOURCE,))
    return tuple((alias, sources) for alias, sources in sources_by_alias.items())


@lru_cache(maxsize=1)
def _bundled_given_name_aliases() -> dict[str, tuple[str, ...]]:
    try:
        text = resources.files("osint_toolkit").joinpath("resources", PERSON_ALIAS_RESOURCE).read_text(encoding="utf-8")
        raw = json.loads(text)
    except (FileNotFoundError, json.JSONDecodeError, ModuleNotFoundError):
        return {}
    if not isinstance(raw, dict):
        return {}

    aliases: dict[str, tuple[str, ...]] = {}
    for raw_name, raw_aliases in raw.items():
        name = _username_token(_transliterate(str(raw_name).casefold()))
        if not name or not isinstance(raw_aliases, list):
            continue
        values: list[str] = []
        for raw_alias in raw_aliases:
            alias = _username_token(_transliterate(str(raw_alias).casefold()))
            if alias and alias != name:
                values.append(alias)
        aliases[name] = _dedupe_strings(tuple(values))
    return aliases


def _suffix_candidates(first: str, last: str) -> tuple[UsernameCandidate, ...]:
    base_names = (first + last, f"{first}.{last}", f"{first}_{last}")
    return tuple(
        UsernameCandidate(f"{base}{suffix}", "handle_suffix")
        for base in base_names
        for suffix in HANDLE_SUFFIXES
    )


def _name_tokens(value: str) -> tuple[str, ...]:
    raw_tokens = TOKEN_RE.findall(value.casefold())
    return tuple(_transliterate(token) for token in raw_tokens if _transliterate(token))


def _transliterate(value: str) -> str:
    return value.translate(TRANSLITERATION_TABLE)


def _username_token(value: str) -> str:
    token = re.sub(r"[^a-z0-9]", "", value.lower())
    return token


def _username_handle(value: str) -> str:
    normalized = _transliterate(value.strip().lstrip("@").casefold())
    normalized = re.sub(r"\s+", "", normalized)
    return re.sub(r"[^a-z0-9._-]", "", normalized).strip(".-_")


def _dedupe_candidates(candidates: tuple[UsernameCandidate, ...]) -> tuple[UsernameCandidate, ...]:
    best_by_key: dict[str, tuple[UsernameCandidate, int]] = {}
    for index, candidate in enumerate(candidates):
        username = candidate.username.strip(".-_")
        if not _is_username_candidate(username):
            continue
        key = username.lower()
        enriched = _enrich_candidate(username, candidate.strategy, source_projects=candidate.source_projects)
        current = best_by_key.get(key)
        if current is None or enriched.score > current[0].score:
            best_by_key[key] = (enriched, index)
    ranked = sorted(
        best_by_key.values(),
        key=lambda item: (-item[0].score, item[1], item[0].username),
    )
    return tuple(candidate for candidate, _ in ranked[:MAX_GENERATED_CANDIDATES])


def _enrich_candidate(
    username: str,
    strategy: str,
    *,
    source_projects: tuple[str, ...] = DEFAULT_SOURCE_PROJECTS,
) -> UsernameCandidate:
    return UsernameCandidate(
        username=username,
        strategy=strategy,
        score=_candidate_score(username, strategy),
        platform_hints=_platform_hints(username, strategy),
        source_projects=source_projects,
    )


def _candidate_score(username: str, strategy: str) -> int:
    score = STRATEGY_BASE_SCORES.get(strategy, 50)
    length = len(username)
    if 8 <= length <= 24:
        score += 3
    elif length < 5:
        score -= 8
    elif length > 32:
        score -= 5
    if username.count(".") == 1 and "dot" in strategy:
        score += 2
    if username.count("_") == 1 and "underscore" in strategy:
        score += 1
    if "-" in username and "dash" not in strategy and strategy != "operator_alias":
        score -= 3
    return max(1, min(100, score))


def _platform_hints(username: str, strategy: str) -> tuple[str, ...]:
    hints: list[str] = []
    if strategy.startswith("operator_alias"):
        hints.extend(("known-alias", "instagram", "telegram", "vk"))
    elif strategy in {"first_last_joined", "full_name_joined", "first_middle_initials_last"}:
        hints.extend(("github", "gitlab", "linkedin", "facebook", "instagram"))
    elif "dot" in strategy:
        hints.extend(("linkedin", "facebook", "instagram", "telegram"))
    elif "underscore" in strategy:
        hints.extend(("instagram", "telegram", "vk", "ok.ru"))
    elif "dash" in strategy:
        hints.extend(("github", "gitlab", "linkedin", "telegram"))
    elif "initial" in strategy:
        hints.extend(("linkedin", "facebook", "github"))
    elif "alias" in strategy:
        hints.extend(("instagram", "telegram", "vk", "ok.ru"))
    elif strategy == "handle_suffix":
        hints.extend(("instagram", "telegram", "tiktok"))
    elif strategy == "first":
        hints.extend(("low-specificity", "manual-review"))
    else:
        hints.extend(("username-search", "manual-review"))

    if "." in username and "linkedin" not in hints:
        hints.insert(0, "linkedin")
    if "_" in username and "instagram" not in hints:
        hints.insert(0, "instagram")
    return _dedupe_strings(tuple(hints))


def _dedupe_strings(values: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        key = value.lower()
        if key not in seen:
            seen.add(key)
            deduped.append(value)
    return tuple(deduped)


def _is_username_candidate(value: str) -> bool:
    return 3 <= len(value) <= 64 and bool(re.fullmatch(r"[a-z0-9][a-z0-9._-]*[a-z0-9]", value))
