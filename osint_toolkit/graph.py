from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Mapping
from urllib.parse import urlparse

from .entities import Entity
from .engine import Finding, ScanTarget


@dataclass(frozen=True)
class GraphNode:
    kind: str
    value: str

    def key(self) -> tuple[str, str]:
        return self.kind, self.value.lower()

    def label(self) -> str:
        return f"{self.kind}:{self.value}"

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "value": self.value,
        }


@dataclass(frozen=True)
class GraphNodeDegree:
    kind: str
    value: str
    degree: int

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "value": self.value,
            "degree": self.degree,
        }


@dataclass(frozen=True)
class GraphNeighbor:
    kind: str
    value: str
    relation: str
    direction: str
    confidence: str
    source: str
    note: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "value": self.value,
            "relation": self.relation,
            "direction": self.direction,
            "confidence": self.confidence,
            "source": self.source,
            "note": self.note,
        }


@dataclass(frozen=True)
class GraphAnalysis:
    case_id: str
    node_count: int
    edge_count: int
    relation_counts: tuple[tuple[str, int], ...]
    kind_counts: tuple[tuple[str, int], ...]
    top_nodes: tuple[GraphNodeDegree, ...]
    focus: GraphNode | None = None
    neighbors: tuple[GraphNeighbor, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "relation_counts": dict(self.relation_counts),
            "kind_counts": dict(self.kind_counts),
            "top_nodes": [node.to_dict() for node in self.top_nodes],
            "focus": self.focus.to_dict() if self.focus else None,
            "neighbors": [neighbor.to_dict() for neighbor in self.neighbors],
        }


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


def analyze_case_graph(
    payload: Mapping[str, object],
    *,
    focus_kind: str = "",
    focus_value: str = "",
    limit: int = 10,
) -> GraphAnalysis:
    if limit < 1:
        raise ValueError("limit must be greater than zero.")

    normalized_focus_kind = focus_kind.strip()
    normalized_focus_value = focus_value.strip()
    if bool(normalized_focus_kind) != bool(normalized_focus_value):
        raise ValueError("focus_kind and focus_value must be provided together.")

    edges = tuple(_edge_from_mapping(row) for row in _payload_rows(payload, "edges"))
    nodes = _nodes_from_payload(payload, edges)
    nodes_by_key = {node.key(): node for node in nodes}

    relation_counts = _count_items(edge.relation for edge in edges)
    kind_counts = _count_items(node.kind for node in nodes)
    degrees = _degree_counts(edges)
    top_nodes = tuple(
        GraphNodeDegree(kind=node.kind, value=node.value, degree=degrees[node.key()])
        for node in sorted(
            nodes,
            key=lambda item: (-degrees[item.key()], item.kind, item.value.lower()),
        )
        if degrees[node.key()] > 0
    )[:limit]

    focus = None
    neighbors: tuple[GraphNeighbor, ...] = ()
    if normalized_focus_kind and normalized_focus_value:
        focus_key = (normalized_focus_kind, normalized_focus_value.lower())
        focus = nodes_by_key.get(focus_key, GraphNode(normalized_focus_kind, normalized_focus_value))
        neighbors = _neighbors_for_focus(edges, focus_key, limit=limit)

    return GraphAnalysis(
        case_id=_case_id(payload),
        node_count=len(nodes),
        edge_count=len(edges),
        relation_counts=relation_counts,
        kind_counts=kind_counts,
        top_nodes=top_nodes,
        focus=focus,
        neighbors=neighbors,
    )


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
            for metadata_value in _metadata_values(metadata_key, value):
                if not _has_entity(entity_keys, target_kind, metadata_value):
                    continue
                if source_kind == target_kind and source_value.lower() == metadata_value.lower():
                    continue
                edges.append(
                    GraphEdge(
                        source_kind=source_kind,
                        source_value=source_value,
                        relation=relation,
                        target_kind=target_kind,
                        target_value=metadata_value,
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
        "email": ("related_email", "email"),
        "emails": ("page_contact_email", "email"),
        "phones": ("page_contact_phone", "phone"),
        "crawled_urls": ("crawled_url", "url"),
        "discovered_urls": ("discovered_url", "url"),
        "external_urls": ("linked_external_url", "url"),
        "social_urls": ("linked_social_url", "url"),
        "normalized": ("normalized_as", "normalized-value"),
        "country": ("country_hint", "country"),
        "region": ("region_hint", "region"),
        "username": ("generated_username_candidate", "username"),
        "normalized_name": ("normalized_name", "normalized-name"),
        "category": ("categorized_as", "source-category"),
        "name": ("name_hint", "name"),
        "carrier": ("carrier_hint", "carrier"),
        "location": ("location_hint", "location"),
        "line_type": ("line_type_hint", "line-type"),
        "number_range": ("phone_range_hint", "phone-range"),
        "zip_code": ("postal_code_hint", "postal-code"),
        "country_code": ("country_code_hint", "country-code"),
        "subdomain": ("discovered_subdomain", "subdomain"),
        "subdomains": ("discovered_subdomain", "subdomain"),
        "registrar": ("registered_via", "registrar"),
        "nameserver": ("uses_nameserver", "nameserver"),
        "nameservers": ("uses_nameserver", "nameserver"),
    }
    return mapping.get(key)


def _metadata_values(key: str, value: str) -> tuple[str, ...]:
    if key in {
        "emails",
        "phones",
        "crawled_urls",
        "discovered_urls",
        "external_urls",
        "social_urls",
        "subdomain",
        "subdomains",
        "nameserver",
        "nameservers",
    }:
        parts = [part.strip() for part in value.replace("|", ",").split(",")]
        return tuple(part for part in parts if part)
    return (value,)


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


def _case_id(payload: Mapping[str, object]) -> str:
    case = payload.get("case")
    if not isinstance(case, Mapping):
        raise ValueError("Invalid case payload: missing case.")
    return _field(case, "case_id")


def _payload_rows(payload: Mapping[str, object], name: str) -> tuple[Mapping[str, object], ...]:
    rows = payload.get(name)
    if not isinstance(rows, list):
        raise ValueError(f"Invalid case payload: {name} must be a list.")
    validated_rows: list[Mapping[str, object]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError(f"Invalid case payload: {name} rows must be objects.")
        validated_rows.append(row)
    return tuple(validated_rows)


def _nodes_from_payload(payload: Mapping[str, object], edges: tuple[GraphEdge, ...]) -> tuple[GraphNode, ...]:
    nodes: dict[tuple[str, str], GraphNode] = {}
    for row in _payload_rows(payload, "entities"):
        node = _node_from_mapping(row)
        if node:
            nodes.setdefault(node.key(), node)
    for edge in edges:
        source = GraphNode(edge.source_kind, edge.source_value)
        target = GraphNode(edge.target_kind, edge.target_value)
        nodes.setdefault(source.key(), source)
        nodes.setdefault(target.key(), target)
    return tuple(sorted(nodes.values(), key=lambda node: (node.kind, node.value.lower())))


def _node_from_mapping(row: Mapping[str, object]) -> GraphNode | None:
    kind = _field(row, "kind")
    value = _field(row, "value")
    if not kind or not value:
        return None
    return GraphNode(kind, value)


def _edge_from_mapping(row: Mapping[str, object]) -> GraphEdge:
    return GraphEdge(
        source_kind=_field(row, "source_kind"),
        source_value=_field(row, "source_value"),
        relation=_field(row, "relation"),
        target_kind=_field(row, "target_kind"),
        target_value=_field(row, "target_value"),
        source=_field(row, "source") or "unknown",
        confidence=_field(row, "confidence") or "unknown",
        note=_field(row, "note"),
    )


def _degree_counts(edges: tuple[GraphEdge, ...]) -> Counter[tuple[str, str]]:
    degrees: Counter[tuple[str, str]] = Counter()
    for edge in edges:
        degrees[(edge.source_kind, edge.source_value.lower())] += 1
        degrees[(edge.target_kind, edge.target_value.lower())] += 1
    return degrees


def _neighbors_for_focus(
    edges: tuple[GraphEdge, ...],
    focus_key: tuple[str, str],
    *,
    limit: int,
) -> tuple[GraphNeighbor, ...]:
    neighbors: list[GraphNeighbor] = []
    for edge in edges:
        source_key = (edge.source_kind, edge.source_value.lower())
        target_key = (edge.target_kind, edge.target_value.lower())
        if source_key == focus_key:
            neighbors.append(
                GraphNeighbor(
                    kind=edge.target_kind,
                    value=edge.target_value,
                    relation=edge.relation,
                    direction="out",
                    confidence=edge.confidence,
                    source=edge.source,
                    note=edge.note,
                )
            )
        elif target_key == focus_key:
            neighbors.append(
                GraphNeighbor(
                    kind=edge.source_kind,
                    value=edge.source_value,
                    relation=edge.relation,
                    direction="in",
                    confidence=edge.confidence,
                    source=edge.source,
                    note=edge.note,
                )
            )
    return tuple(
        sorted(
            neighbors,
            key=lambda neighbor: (
                neighbor.direction,
                neighbor.relation,
                neighbor.kind,
                neighbor.value.lower(),
            ),
        )[:limit]
    )


def _count_items(values: Iterable[object]) -> tuple[tuple[str, int], ...]:
    counts = Counter(str(value) for value in values)
    return tuple(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def _field(row: Mapping[str, object], name: str) -> str:
    value = row.get(name, "")
    if value is None:
        return ""
    return str(value).strip()
