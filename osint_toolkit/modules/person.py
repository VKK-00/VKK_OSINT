from __future__ import annotations

import re
from dataclasses import dataclass

from ..engine import Finding, RunConfig, ScanTarget

TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)

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
    default_limit: int = 12

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
        candidates = generate_username_candidates(normalized_name)
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


def generate_username_candidates(normalized_name: str) -> tuple[UsernameCandidate, ...]:
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
    return _dedupe_candidates(tuple(proposals))


def _name_tokens(value: str) -> tuple[str, ...]:
    raw_tokens = TOKEN_RE.findall(value.casefold())
    return tuple(_transliterate(token) for token in raw_tokens if _transliterate(token))


def _transliterate(value: str) -> str:
    return value.translate(TRANSLITERATION_TABLE)


def _username_token(value: str) -> str:
    token = re.sub(r"[^a-z0-9]", "", value.lower())
    return token


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
    return tuple(deduped)


def _is_username_candidate(value: str) -> bool:
    return 3 <= len(value) <= 64 and bool(re.fullmatch(r"[a-z0-9][a-z0-9._-]*[a-z0-9]", value))
