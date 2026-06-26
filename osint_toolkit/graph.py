from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from heapq import heappop, heappush
import re
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
class CrossCasePathStep:
    case_id: str
    from_kind: str
    from_value: str
    relation: str
    to_kind: str
    to_value: str
    direction: str
    confidence: str
    source: str
    weight: float
    note: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "from": {"kind": self.from_kind, "value": self.from_value},
            "relation": self.relation,
            "to": {"kind": self.to_kind, "value": self.to_value},
            "direction": self.direction,
            "confidence": self.confidence,
            "source": self.source,
            "weight": self.weight,
            "note": self.note,
        }


@dataclass(frozen=True)
class CrossCasePathAnalysis:
    source: GraphNode
    target: GraphNode
    found: bool
    total_weight: float | None
    hop_count: int
    case_count: int
    node_count: int
    edge_count: int
    max_depth: int
    steps: tuple[CrossCasePathStep, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source.to_dict(),
            "target": self.target.to_dict(),
            "found": self.found,
            "total_weight": self.total_weight,
            "hop_count": self.hop_count,
            "case_count": self.case_count,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "max_depth": self.max_depth,
            "steps": [step.to_dict() for step in self.steps],
        }


@dataclass(frozen=True)
class CrossCaseNetworkNode:
    kind: str
    value: str
    degree: int
    case_count: int
    cases: tuple[str, ...]

    def key(self) -> tuple[str, str]:
        return self.kind, self.value.lower()

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "value": self.value,
            "degree": self.degree,
            "case_count": self.case_count,
            "cases": list(self.cases),
        }


@dataclass(frozen=True)
class CrossCaseNetworkEdge:
    source_kind: str
    source_value: str
    relation: str
    target_kind: str
    target_value: str
    count: int
    case_ids: tuple[str, ...]
    source: str
    confidence: str
    weight: float
    note: str = ""

    def key(self) -> tuple[str, str, str, str, str]:
        return (
            self.source_kind,
            self.source_value.lower(),
            self.relation,
            self.target_kind,
            self.target_value.lower(),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "source_kind": self.source_kind,
            "source_value": self.source_value,
            "relation": self.relation,
            "target_kind": self.target_kind,
            "target_value": self.target_value,
            "count": self.count,
            "case_ids": list(self.case_ids),
            "source": self.source,
            "confidence": self.confidence,
            "weight": self.weight,
            "note": self.note,
        }


@dataclass(frozen=True)
class CrossCaseNetworkAnalysis:
    case_count: int
    node_count: int
    edge_count: int
    visible_node_count: int
    visible_edge_count: int
    kind_filter: str
    relation_filter: str
    min_degree: int
    node_limit: int
    edge_limit: int
    relation_counts: tuple[tuple[str, int], ...]
    kind_counts: tuple[tuple[str, int], ...]
    nodes: tuple[CrossCaseNetworkNode, ...]
    edges: tuple[CrossCaseNetworkEdge, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "case_count": self.case_count,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "visible_node_count": self.visible_node_count,
            "visible_edge_count": self.visible_edge_count,
            "kind_filter": self.kind_filter,
            "relation_filter": self.relation_filter,
            "min_degree": self.min_degree,
            "node_limit": self.node_limit,
            "edge_limit": self.edge_limit,
            "relation_counts": dict(self.relation_counts),
            "kind_counts": dict(self.kind_counts),
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
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


@dataclass(frozen=True)
class _TraversalEdge:
    from_key: tuple[str, str]
    to_key: tuple[str, str]
    edge: GraphEdge
    case_id: str
    direction: str
    weight: float


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


def analyze_cross_case_path(
    payloads: Iterable[Mapping[str, object]],
    *,
    source_kind: str,
    source_value: str,
    target_kind: str,
    target_value: str,
    max_depth: int = 6,
) -> CrossCasePathAnalysis:
    if max_depth < 1:
        raise ValueError("max_depth must be greater than zero.")
    normalized_source_kind = source_kind.strip()
    normalized_source_value = source_value.strip()
    normalized_target_kind = target_kind.strip()
    normalized_target_value = target_value.strip()
    if not normalized_source_kind or not normalized_source_value:
        raise ValueError("source_kind and source_value are required.")
    if not normalized_target_kind or not normalized_target_value:
        raise ValueError("target_kind and target_value are required.")

    source_key = _node_key(normalized_source_kind, normalized_source_value)
    target_key = _node_key(normalized_target_kind, normalized_target_value)
    nodes: dict[tuple[str, str], GraphNode] = {}
    adjacency: dict[tuple[str, str], list[_TraversalEdge]] = {}
    case_count = 0
    edge_count = 0

    for payload in payloads:
        case_count += 1
        case_id = _case_id(payload)
        edges = tuple(_edge_from_mapping(row) for row in _payload_rows(payload, "edges"))
        for node in _nodes_from_payload(payload, edges):
            nodes.setdefault(node.key(), node)
        for edge in edges:
            edge_count += 1
            source = _node_key(edge.source_kind, edge.source_value)
            target = _node_key(edge.target_kind, edge.target_value)
            nodes.setdefault(source, GraphNode(edge.source_kind, edge.source_value))
            nodes.setdefault(target, GraphNode(edge.target_kind, edge.target_value))
            weight = _path_edge_weight(edge.confidence)
            adjacency.setdefault(source, []).append(
                _TraversalEdge(source, target, edge, case_id, "out", weight)
            )
            adjacency.setdefault(target, []).append(
                _TraversalEdge(target, source, edge, case_id, "in", weight)
            )

    source_node = nodes.get(source_key, GraphNode(normalized_source_kind, normalized_source_value))
    target_node = nodes.get(target_key, GraphNode(normalized_target_kind, normalized_target_value))
    if source_key == target_key:
        return CrossCasePathAnalysis(
            source=source_node,
            target=target_node,
            found=True,
            total_weight=0.0,
            hop_count=0,
            case_count=case_count,
            node_count=len(nodes),
            edge_count=edge_count,
            max_depth=max_depth,
        )

    distances: dict[tuple[str, str], float] = {source_key: 0.0}
    depths: dict[tuple[str, str], int] = {source_key: 0}
    previous: dict[tuple[str, str], tuple[tuple[str, str], _TraversalEdge]] = {}
    heap: list[tuple[float, int, str, str, tuple[str, str]]] = [
        (0.0, 0, source_key[0], source_key[1], source_key)
    ]

    while heap:
        distance, depth, _, _, current = heappop(heap)
        if distance != distances.get(current) or depth != depths.get(current):
            continue
        if current == target_key:
            break
        if depth >= max_depth:
            continue
        for traversal in sorted(
            adjacency.get(current, ()),
            key=lambda item: (
                item.weight,
                item.to_key[0],
                item.to_key[1],
                item.case_id,
                item.edge.relation,
            ),
        ):
            next_depth = depth + 1
            next_distance = distance + traversal.weight
            best_distance = distances.get(traversal.to_key)
            best_depth = depths.get(traversal.to_key)
            if (
                best_distance is None
                or next_distance < best_distance
                or (next_distance == best_distance and (best_depth is None or next_depth < best_depth))
            ):
                distances[traversal.to_key] = next_distance
                depths[traversal.to_key] = next_depth
                previous[traversal.to_key] = (current, traversal)
                heappush(
                    heap,
                    (
                        next_distance,
                        next_depth,
                        traversal.to_key[0],
                        traversal.to_key[1],
                        traversal.to_key,
                    ),
                )

    if target_key not in distances:
        return CrossCasePathAnalysis(
            source=source_node,
            target=target_node,
            found=False,
            total_weight=None,
            hop_count=0,
            case_count=case_count,
            node_count=len(nodes),
            edge_count=edge_count,
            max_depth=max_depth,
        )

    steps: list[CrossCasePathStep] = []
    current = target_key
    while current != source_key:
        prior, traversal = previous[current]
        steps.append(_path_step_from_traversal(traversal, prior, current, nodes))
        current = prior
    steps.reverse()
    return CrossCasePathAnalysis(
        source=source_node,
        target=target_node,
        found=True,
        total_weight=distances[target_key],
        hop_count=len(steps),
        case_count=case_count,
        node_count=len(nodes),
        edge_count=edge_count,
        max_depth=max_depth,
        steps=tuple(steps),
    )


def analyze_cross_case_network(
    payloads: Iterable[Mapping[str, object]],
    *,
    kind_filter: str = "",
    relation_filter: str = "",
    min_degree: int = 1,
    node_limit: int = 60,
    edge_limit: int = 120,
) -> CrossCaseNetworkAnalysis:
    if min_degree < 0:
        raise ValueError("min_degree cannot be negative.")
    if node_limit < 1:
        raise ValueError("node_limit must be greater than zero.")
    if edge_limit < 1:
        raise ValueError("edge_limit must be greater than zero.")

    normalized_kind_filter = kind_filter.strip()
    normalized_relation_filter = relation_filter.strip()
    node_values: dict[tuple[str, str], GraphNode] = {}
    node_cases: dict[tuple[str, str], set[str]] = {}
    edge_cases: dict[tuple[str, str, str, str, str], set[str]] = {}
    edge_counts: Counter[tuple[str, str, str, str, str]] = Counter()
    edge_values: dict[tuple[str, str, str, str, str], GraphEdge] = {}
    case_count = 0

    for payload in payloads:
        case_count += 1
        case_id = _case_id(payload)
        edges = tuple(_edge_from_mapping(row) for row in _payload_rows(payload, "edges"))
        for node in _nodes_from_payload(payload, edges):
            node_values.setdefault(node.key(), node)
            node_cases.setdefault(node.key(), set()).add(case_id)
        for edge in edges:
            if normalized_relation_filter and edge.relation != normalized_relation_filter:
                continue
            if normalized_kind_filter and normalized_kind_filter not in {edge.source_kind, edge.target_kind}:
                continue
            source_key = _node_key(edge.source_kind, edge.source_value)
            target_key = _node_key(edge.target_kind, edge.target_value)
            node_values.setdefault(source_key, GraphNode(edge.source_kind, edge.source_value))
            node_values.setdefault(target_key, GraphNode(edge.target_kind, edge.target_value))
            node_cases.setdefault(source_key, set()).add(case_id)
            node_cases.setdefault(target_key, set()).add(case_id)
            key = edge.key()
            edge_cases.setdefault(key, set()).add(case_id)
            edge_counts[key] += 1
            existing = edge_values.get(key)
            if existing is None or _confidence_rank(edge.confidence) > _confidence_rank(existing.confidence):
                edge_values[key] = edge

    degrees: Counter[tuple[str, str]] = Counter()
    for key, edge in edge_values.items():
        count = edge_counts[key]
        degrees[_node_key(edge.source_kind, edge.source_value)] += count
        degrees[_node_key(edge.target_kind, edge.target_value)] += count

    all_nodes = [
        CrossCaseNetworkNode(
            kind=node.kind,
            value=node.value,
            degree=degrees[node.key()],
            case_count=len(node_cases.get(node.key(), set())),
            cases=tuple(sorted(node_cases.get(node.key(), set()))),
        )
        for node in node_values.values()
        if degrees[node.key()] >= min_degree
    ]
    all_nodes.sort(
        key=lambda node: (
            -node.degree,
            -node.case_count,
            node.kind,
            node.value.lower(),
        )
    )
    visible_nodes = tuple(all_nodes[:node_limit])
    visible_keys = {node.key() for node in visible_nodes}

    all_edges = [
        _network_edge_from_aggregate(
            edge_values[key],
            count=edge_counts[key],
            case_ids=tuple(sorted(edge_cases.get(key, set()))),
        )
        for key in edge_values
    ]
    all_edges.sort(
        key=lambda edge: (
            edge.weight,
            -edge.count,
            edge.source_kind,
            edge.source_value.lower(),
            edge.relation,
            edge.target_kind,
            edge.target_value.lower(),
        )
    )
    visible_edges = tuple(
        edge
        for edge in all_edges
        if _node_key(edge.source_kind, edge.source_value) in visible_keys
        and _node_key(edge.target_kind, edge.target_value) in visible_keys
    )[:edge_limit]

    return CrossCaseNetworkAnalysis(
        case_count=case_count,
        node_count=len(all_nodes),
        edge_count=len(all_edges),
        visible_node_count=len(visible_nodes),
        visible_edge_count=len(visible_edges),
        kind_filter=normalized_kind_filter,
        relation_filter=normalized_relation_filter,
        min_degree=min_degree,
        node_limit=node_limit,
        edge_limit=edge_limit,
        relation_counts=_count_items(
            relation
            for edge in all_edges
            for relation in (edge.relation,) * edge.count
        ),
        kind_counts=_count_items(node.kind for node in all_nodes),
        nodes=visible_nodes,
        edges=visible_edges,
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
            instagram = _instagram_from_url(entity.value)
            if _has_entity(entity_keys, "instagram", instagram):
                edges.append(_edge(entity, "instagram_url_for", "instagram", instagram, "parsed from Instagram URL"))
            social_profile = _social_profile_from_url(entity.value)
            if _has_entity(entity_keys, "social-profile", social_profile):
                edges.append(_edge(entity, "social_url_for", "social-profile", social_profile, "parsed from social platform URL"))
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
        "phone": ("related_phone", "phone"),
        "emails": ("page_contact_email", "email"),
        "phones": ("page_contact_phone", "phone"),
        "crawled_urls": ("crawled_url", "url"),
        "discovered_urls": ("discovered_url", "url"),
        "external_urls": ("linked_external_url", "url"),
        "social_urls": ("linked_social_url", "url"),
        "robots_sitemaps": ("robots_declared_sitemap", "url"),
        "robots_disallow_paths": ("robots_disallow_path", "web-path"),
        "sitemap_sources": ("fetched_sitemap", "url"),
        "sitemap_urls": ("sitemap_url", "url"),
        "normalized": ("normalized_as", "normalized-value"),
        "country": ("country_hint", "country"),
        "region": ("region_hint", "region"),
        "username": ("generated_username_candidate", "username"),
        "related_usernames": ("related_username", "username"),
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
        "whois_server": ("queried_whois_server", "whois-server"),
        "whois_referral_server": ("referred_whois_server", "whois-server"),
        "instagram_username": ("normalized_instagram_account", "instagram"),
        "platform": ("on_platform", "platform"),
        "display_name": ("display_name_hint", "name"),
        "account_id": ("account_id_hint", "account-id"),
        "media_shortcode": ("media_shortcode_hint", "media-shortcode"),
        "canonical_url": ("canonical_url", "url"),
        "profile_image_url": ("profile_image_url", "url"),
        "media_url": ("media_url", "url"),
        "external_url": ("linked_external_url", "url"),
        "social_profile": ("normalized_social_profile", "social-profile"),
        "social_username": ("profile_username", "username"),
        "platform_domain": ("platform_domain", "domain"),
        "ip": ("resolved_ip", "ip"),
        "ip_range": ("has_ip_range", "ip-range"),
        "asn": ("has_asn", "asn"),
        "port": ("open_port", "port"),
        "technology": ("uses_technology", "technology"),
        "provider": ("uses_provider", "provider"),
        "providers": ("uses_provider", "provider"),
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
        "robots_sitemaps",
        "robots_disallow_paths",
        "sitemap_sources",
        "sitemap_urls",
        "subdomain",
        "subdomains",
        "nameserver",
        "nameservers",
        "whois_server",
        "whois_referral_server",
        "related_usernames",
        "canonical_url",
        "profile_image_url",
        "media_url",
        "external_url",
        "social_profile",
        "ip",
        "provider",
        "providers",
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


def _instagram_from_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.hostname not in {"instagram.com", "www.instagram.com"}:
        return ""
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if not parts or parts[0] in {"p", "reel", "reels", "tv"}:
        return ""
    handle = parts[0]
    if not re.fullmatch(r"[A-Za-z0-9._]{1,30}", handle):
        return ""
    return f"@{handle}"


def _social_profile_from_url(value: str) -> str:
    parsed = urlparse(value)
    hostname = (parsed.hostname or "").lower()
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if hostname in {"vk.com", "www.vk.com", "m.vk.com", "vkontakte.ru", "www.vkontakte.ru"}:
        if parts and parts[0].lower() not in {"album", "albums", "audios", "away", "feed", "friends", "groups", "im", "login", "search", "video", "videos"}:
            return f"vk:{parts[0]}"
    if hostname in {"ok.ru", "www.ok.ru", "m.ok.ru", "odnoklassniki.ru", "www.odnoklassniki.ru"}:
        if len(parts) >= 2 and parts[0].lower() in {"profile", "group"}:
            return f"ok:{parts[0].lower()}/{parts[1]}"
        if parts and parts[0].lower() not in {"dk", "feed", "groups", "login", "messages", "search"}:
            return f"ok:{parts[0]}"
    if hostname in {"my.mail.ru", "m.my.mail.ru"} and len(parts) >= 2:
        return f"mailru:{parts[0].lower()}/{parts[1]}"
    if hostname in {"yandex.ru", "www.yandex.ru"} and len(parts) >= 3 and parts[0].lower() == "q" and parts[1].lower() == "profile":
        return f"yandex:q/{parts[2]}"
    if hostname == "market.yandex.ru" and len(parts) >= 2 and parts[0].lower() == "user":
        return f"yandex:market/{parts[1]}"
    if hostname == "reviews.yandex.ru" and len(parts) >= 2 and parts[0].lower() == "user":
        return f"yandex:reviews/{parts[1]}"
    if hostname in {"zen.yandex.ru", "www.zen.yandex.ru"} and len(parts) >= 2 and parts[0].lower() == "user":
        return f"yandex:zen/{parts[1]}"
    return ""


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


def _node_key(kind: str, value: str) -> tuple[str, str]:
    return kind.strip(), value.strip().lower()


def _path_edge_weight(confidence: str) -> float:
    weights = {
        "provided": 1.0,
        "high": 1.0,
        "curated": 1.5,
        "medium": 2.0,
        "low": 3.0,
        "not_checked": 4.0,
        "unknown": 4.0,
    }
    return weights.get(confidence, 4.0)


def _path_step_from_traversal(
    traversal: _TraversalEdge,
    from_key: tuple[str, str],
    to_key: tuple[str, str],
    nodes: Mapping[tuple[str, str], GraphNode],
) -> CrossCasePathStep:
    from_node = nodes.get(from_key, GraphNode(from_key[0], from_key[1]))
    to_node = nodes.get(to_key, GraphNode(to_key[0], to_key[1]))
    return CrossCasePathStep(
        case_id=traversal.case_id,
        from_kind=from_node.kind,
        from_value=from_node.value,
        relation=traversal.edge.relation,
        to_kind=to_node.kind,
        to_value=to_node.value,
        direction=traversal.direction,
        confidence=traversal.edge.confidence,
        source=traversal.edge.source,
        weight=traversal.weight,
        note=traversal.edge.note,
    )


def _network_edge_from_aggregate(
    edge: GraphEdge,
    *,
    count: int,
    case_ids: tuple[str, ...],
) -> CrossCaseNetworkEdge:
    return CrossCaseNetworkEdge(
        source_kind=edge.source_kind,
        source_value=edge.source_value,
        relation=edge.relation,
        target_kind=edge.target_kind,
        target_value=edge.target_value,
        count=count,
        case_ids=case_ids,
        source=edge.source,
        confidence=edge.confidence,
        weight=_path_edge_weight(edge.confidence),
        note=edge.note,
    )


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
