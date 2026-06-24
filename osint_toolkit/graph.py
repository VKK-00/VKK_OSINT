from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from .entities import Entity
from .engine import Finding, ScanTarget


@dataclass(frozen=True)
class GraphEdge:
    source_kind: str
    source_value: str
    relation: str
    target_kind: str
    target_value: str
    source: str
    confidence: str
    note: str = ""

    def key(self) -> tuple[str, str, str, str, str]:
        return (
            self.source_kind,
            self.source_value.lower(),
            self.relation,
            self.target_kind,
            self.target_value.lower(),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "source_kind": self.source_kind,
            "source_value": self.source_value,
            "relation": self.relation,
            "target_kind": self.target_kind,
            "target_value": self.target_value,
            "source": self.source,
            "confidence": self.confidence,
            "note": self.note,
        }


def graph_edges_from_case(
    targets: tuple[ScanTarget, ...],
    findings: tuple[Finding, ...],
    entities: tuple[Entity, ...],
) -> tuple[GraphEdge, ...]:
    entity_keys = {entity.key() for entity in entities}
    edges: list[GraphEdge] = []
    edges.extend(_edges_from_entities(entities, entity_keys))
    edges.extend(_edges_from_findings(targets, findings, entity_keys))
    return dedupe_edges(tuple(edges))


def dedupe_edges(edges: tuple[GraphEdge, ...]) -> tuple[GraphEdge, ...]:
    seen: dict[tuple[str, str, str, str, str], GraphEdge] = {}
    for edge in edges:
        key = edge.key()
        if key not in seen or _confidence_rank(edge.confidence) > _confidence_rank(seen[key].confidence):
            seen[key] = edge
    return tuple(
        sorted(
            seen.values(),
            key=lambda edge: (
                edge.source_kind,
                edge.source_value.lower(),
                edge.relation,
                edge.target_kind,
                edge.target_value.lower(),
            ),
        )
    )


def _edges_from_entities(entities: tuple[Entity, ...], entity_keys: set[tuple[str, str]]) -> tuple[GraphEdge, ...]:
    edges: list[GraphEdge] = []
    for entity in entities:
        if entity.kind == "email":
            domain = _domain_from_email(entity.value)
            if _has_entity(entity_keys, "domain", domain):
                edges.append(
                    _edge(entity, "email_domain", "domain", domain, "parsed from email address")
                )
        elif entity.kind == "url":
            domain = _domain_from_url(entity.value)
            if _has_entity(entity_keys, "domain", domain):
                edges.append(_edge(entity, "url_host", "domain", domain, "parsed from URL"))
            telegram = _telegram_from_url(entity.value)
            if _has_entity(entity_keys, "telegram", telegram):
                edges.append(_edge(entity, "telegram_url_for", "telegram", telegram, "parsed from t.me URL"))
    return tuple(edges)


def _edges_from_findings(
    targets: tuple[ScanTarget, ...],
    findings: tuple[Finding, ...],
    entity_keys: set[tuple[str, str]],
) -> tuple[GraphEdge, ...]:
    targets_by_value = {target.value: _target_entity(target) for target in targets}
    edges: list[GraphEdge] = []
    for finding in findings:
        source = f"{finding.module}:{finding.source}"
        target_entity = targets_by_value.get(finding.target)
        if not target_entity:
            continue
        source_kind, source_value = target_entity
        if not _has_entity(entity_keys, source_kind, source_value):
            continue

        if finding.url and _has_entity(entity_keys, "url", finding.url):
            edges.append(
                GraphEdge(
                    source_kind=source_kind,
                    source_value=source_value,
                    relation="produced_url",
                    target_kind="url",
                    target_value=finding.url,
                    source=source,
                    confidence=finding.confidence,
                    note=finding.status,
                )
            )

        for metadata_key, value in finding.metadata.items():
            mapped = _metadata_edge(metadata_key)
            if not mapped or not value:
                continue
            relation, target_kind = mapped
            if not _has_entity(entity_keys, target_kind, value):
                continue
            edges.append(
                GraphEdge(
                    source_kind=source_kind,
                    source_value=source_value,
                    relation=relation,
                    target_kind=target_kind,
                    target_value=value,
                    source=source,
                    confidence=finding.confidence,
                    note=f"metadata:{metadata_key}",
                )
            )
    return tuple(edges)


def _edge(entity: Entity, relation: str, target_kind: str, target_value: str, note: str) -> GraphEdge:
    return GraphEdge(
        source_kind=entity.kind,
        source_value=entity.value,
        relation=relation,
        target_kind=target_kind,
        target_value=target_value,
        source=entity.source,
        confidence=entity.confidence,
        note=note,
    )


def _target_entity(target: ScanTarget) -> tuple[str, str]:
    if target.kind == "ru-ua":
        return "source-pack-selector", target.value
    return target.kind, target.value


def _metadata_edge(key: str) -> tuple[str, str] | None:
    mapping = {
        "domain": ("has_domain", "domain"),
        "normalized": ("normalized_as", "normalized-value"),
        "country": ("country_hint", "country"),
        "region": ("region_hint", "region"),
        "category": ("categorized_as", "source-category"),
        "name": ("name_hint", "name"),
        "carrier": ("carrier_hint", "carrier"),
        "location": ("location_hint", "location"),
        "line_type": ("line_type_hint", "line-type"),
    }
    return mapping.get(key)


def _has_entity(entity_keys: set[tuple[str, str]], kind: str, value: str) -> bool:
    return bool(value) and (kind, value.lower()) in entity_keys


def _domain_from_email(value: str) -> str:
    if "@" not in value:
        return ""
    return value.rsplit("@", 1)[1].lower()


def _domain_from_url(value: str) -> str:
    parsed = urlparse(value)
    return (parsed.hostname or "").lower()


def _telegram_from_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.hostname not in {"t.me", "telegram.me", "telegram.dog"}:
        return ""
    handle = parsed.path.strip("/").split("/")[0]
    if not handle or handle.startswith("+"):
        return ""
    return f"@{handle}"


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
