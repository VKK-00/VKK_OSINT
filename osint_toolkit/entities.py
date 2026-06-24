from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from .engine import Finding, ScanTarget

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"\+[1-9]\d{7,14}\b")


@dataclass(frozen=True)
class Entity:
    kind: str
    value: str
    source: str
    confidence: str
    note: str = ""

    def key(self) -> tuple[str, str]:
        return self.kind, self.value.lower()

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
            "note": self.note,
        }


def entities_from_targets(targets: tuple[ScanTarget, ...]) -> tuple[Entity, ...]:
    entities: list[Entity] = []
    for target in targets:
        value = target.value
        kind = target.kind
        if kind == "ru-ua":
            kind = "source-pack-selector"
        entities.append(Entity(kind=kind, value=value, source="input", confidence="provided"))
    return tuple(entities)


def entities_from_findings(findings: tuple[Finding, ...]) -> tuple[Entity, ...]:
    entities: list[Entity] = []
    for finding in findings:
        source = f"{finding.module}:{finding.source}"
        if finding.url:
            entities.append(Entity("url", finding.url, source, finding.confidence, finding.status))
            domain = _domain_from_url(finding.url)
            if domain:
                entities.append(Entity("domain", domain, source, finding.confidence, "from URL"))
            telegram = _telegram_handle_from_url(finding.url)
            if telegram:
                entities.append(Entity("telegram", telegram, source, finding.confidence, "from t.me URL"))

        for email in EMAIL_RE.findall(finding.evidence):
            entities.append(Entity("email", email, source, "low", "from evidence text"))
        for phone in PHONE_RE.findall(finding.evidence):
            entities.append(Entity("phone", phone, source, "low", "from evidence text"))

        for key, value in finding.metadata.items():
            if key in {"subdomain", "subdomains"}:
                for subdomain in _split_metadata_values(value):
                    entities.append(Entity("subdomain", subdomain, source, finding.confidence, f"metadata:{key}"))
                continue
            entity_kind = _metadata_entity_kind(key)
            if entity_kind and value:
                if key == "email" and not EMAIL_RE.fullmatch(value):
                    continue
                if key in {"phone", "normalized"} and not PHONE_RE.fullmatch(value):
                    continue
                entity_kind = {
                    "normalized": "normalized-value",
                    "normalized_name": "normalized-name",
                    "category": "source-category",
                    "line_type": "line-type",
                    "number_range": "phone-range",
                    "zip_code": "postal-code",
                    "country_code": "country-code",
                }.get(key, entity_kind)
                entities.append(Entity(entity_kind, value, source, finding.confidence, f"metadata:{key}"))
    return dedupe_entities(tuple(entities))


def merge_entities(*groups: tuple[Entity, ...]) -> tuple[Entity, ...]:
    merged: list[Entity] = []
    for group in groups:
        merged.extend(group)
    return dedupe_entities(tuple(merged))


def dedupe_entities(entities: tuple[Entity, ...]) -> tuple[Entity, ...]:
    seen: dict[tuple[str, str], Entity] = {}
    for entity in entities:
        key = entity.key()
        if key not in seen or _confidence_rank(entity.confidence) > _confidence_rank(seen[key].confidence):
            seen[key] = entity
    return tuple(sorted(seen.values(), key=lambda item: (item.kind, item.value.lower())))


def _domain_from_url(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.hostname or "").lower()


def _telegram_handle_from_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.hostname not in {"t.me", "telegram.me", "telegram.dog"}:
        return ""
    handle = parsed.path.strip("/").split("/")[0]
    if not handle or handle.startswith("+"):
        return ""
    return "@" + handle


def _confidence_rank(confidence: str) -> int:
    ranks = {
        "provided": 5,
        "high": 4,
        "medium": 3,
        "curated": 3,
        "low": 2,
        "not_checked": 1,
        "unknown": 0,
    }
    return ranks.get(confidence, 0)


def _metadata_entity_kind(key: str) -> str:
    supported = {
        "domain",
        "normalized",
        "country",
        "category",
        "region",
        "email",
        "phone",
        "username",
        "normalized_name",
        "name",
        "carrier",
        "location",
        "line_type",
        "number_range",
        "zip_code",
        "country_code",
        "subdomain",
    }
    return key if key in supported else ""


def _split_metadata_values(value: str) -> tuple[str, ...]:
    parts = [part.strip() for part in value.replace("|", ",").split(",")]
    return tuple(part for part in parts if part)
