from __future__ import annotations

import re
from dataclasses import dataclass

from ..engine import Finding, RunConfig, ScanTarget

TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)
HANDLE_SUFFIXES = ("official", "real", "online")
MAX_GENERATED_CANDIDATES = 64

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
                evidence=f"Candidate username: {candidate.username}. Verify before use.",
                metadata={
                    "normalized_name": normalized_name,
                    "username": candidate.username,
                    "strategy": candidate.strategy,
                    "source_projects": "maigret, sherlock, linkedin2username, dorks-collections-list",
                },
            )
            for candidate in candidates
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
    aliases = GIVEN_NAME_ALIASES.get(first, ())
    candidates: list[UsernameCandidate] = []
    for alias in aliases:
        candidates.extend(
            [
                UsernameCandidate(alias, "given_name_alias"),
                UsernameCandidate(alias + last, "alias_last_joined"),
                UsernameCandidate(f"{alias}.{last}", "alias_dot_last"),
                UsernameCandidate(f"{alias}_{last}", "alias_underscore_last"),
                UsernameCandidate(alias[0] + last, "alias_initial_last"),
            ]
        )
    return tuple(candidates)


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
    seen: set[str] = set()
    deduped: list[UsernameCandidate] = []
    for candidate in candidates:
        username = candidate.username.strip(".-_")
        if not _is_username_candidate(username):
            continue
        key = username.lower()
        if key not in seen:
            seen.add(key)
            deduped.append(UsernameCandidate(username, candidate.strategy))
        if len(deduped) >= MAX_GENERATED_CANDIDATES:
            break
    return tuple(deduped)


def _is_username_candidate(value: str) -> bool:
    return 3 <= len(value) <= 64 and bool(re.fullmatch(r"[a-z0-9][a-z0-9._-]*[a-z0-9]", value))
