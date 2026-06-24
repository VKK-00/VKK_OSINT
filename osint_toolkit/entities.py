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
            instagram = _instagram_handle_from_url(finding.url)
            if instagram:
                entities.append(Entity("instagram", instagram, source, finding.confidence, "from Instagram URL"))
            social_profile = _social_profile_from_url(finding.url)
            if social_profile:
                entities.append(Entity("social-profile", social_profile, source, finding.confidence, "from social platform URL"))

        for email in EMAIL_RE.findall(finding.evidence):
            entities.append(Entity("email", email, source, "low", "from evidence text"))
        for phone in PHONE_RE.findall(finding.evidence):
            entities.append(Entity("phone", phone, source, "low", "from evidence text"))

        for key, value in finding.metadata.items():
            if key == "emails":
                for email in _split_metadata_values(value):
                    if EMAIL_RE.fullmatch(email):
                        entities.append(Entity("email", email, source, finding.confidence, "metadata:emails"))
                continue
            if key == "phones":
                for phone in _split_metadata_values(value):
                    if PHONE_RE.fullmatch(phone):
                        entities.append(Entity("phone", phone, source, finding.confidence, "metadata:phones"))
                continue
            if key in {
                "crawled_urls",
                "discovered_urls",
                "external_urls",
                "social_urls",
                "robots_sitemaps",
                "sitemap_sources",
                "sitemap_urls",
                "canonical_url",
                "profile_image_url",
                "media_url",
                "external_url",
            }:
                for url in _split_metadata_values(value):
                    entities.append(Entity("url", url, source, finding.confidence, f"metadata:{key}"))
                    domain = _domain_from_url(url)
                    if domain:
                        entities.append(Entity("domain", domain, source, finding.confidence, f"metadata:{key} host"))
                    telegram = _telegram_handle_from_url(url)
                    if telegram:
                        entities.append(Entity("telegram", telegram, source, finding.confidence, f"metadata:{key} t.me URL"))
                    instagram = _instagram_handle_from_url(url)
                    if instagram:
                        entities.append(Entity("instagram", instagram, source, finding.confidence, f"metadata:{key} Instagram URL"))
                continue
            if key == "instagram_username":
                for username in _split_metadata_values(value):
                    if _looks_like_instagram_handle(username):
                        entities.append(Entity("instagram", username, source, finding.confidence, "metadata:instagram_username"))
                continue
            if key == "social_profile":
                for profile in _split_metadata_values(value):
                    entities.append(Entity("social-profile", profile, source, finding.confidence, "metadata:social_profile"))
                continue
            if key == "robots_disallow_paths":
                for path in _split_metadata_values(value):
                    entities.append(Entity("web-path", path, source, finding.confidence, "metadata:robots_disallow_paths"))
                continue
            if key in {"subdomain", "subdomains"}:
                for subdomain in _split_metadata_values(value):
                    entities.append(Entity("subdomain", subdomain, source, finding.confidence, f"metadata:{key}"))
                continue
            if key in {"nameserver", "nameservers"}:
                for nameserver in _split_metadata_values(value):
                    entities.append(Entity("nameserver", nameserver, source, finding.confidence, f"metadata:{key}"))
                continue
            if key in {"whois_server", "whois_referral_server"}:
                for server in _split_metadata_values(value):
                    entities.append(Entity("whois-server", server, source, finding.confidence, f"metadata:{key}"))
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
                    "display_name": "name",
                    "account_id": "account-id",
                    "media_shortcode": "media-shortcode",
                    "social_username": "username",
                    "platform_domain": "domain",
                    "ip": "ip",
                    "ip_range": "ip-range",
                    "asn": "asn",
                    "port": "port",
                    "technology": "technology",
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


def _instagram_handle_from_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.hostname not in {"instagram.com", "www.instagram.com"}:
        return ""
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if not parts or parts[0] in {"p", "reel", "reels", "tv"}:
        return ""
    handle = parts[0]
    if not _looks_like_instagram_handle("@" + handle):
        return ""
    return "@" + handle


def _social_profile_from_url(url: str) -> str:
    parsed = urlparse(url)
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


def _looks_like_instagram_handle(value: str) -> bool:
    handle = value.strip()
    if handle.startswith("@"):
        handle = handle[1:]
    return bool(handle) and re.fullmatch(r"[A-Za-z0-9._]{1,30}", handle) is not None


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
        "registrar",
        "nameserver",
        "whois_server",
        "whois_referral_server",
        "instagram_username",
        "platform",
        "display_name",
        "account_id",
        "media_shortcode",
        "social_profile",
        "social_username",
        "platform_domain",
        "ip",
        "ip_range",
        "asn",
        "port",
        "technology",
    }
    return key if key in supported else ""


def _split_metadata_values(value: str) -> tuple[str, ...]:
    parts = [part.strip() for part in value.replace("|", ",").split(",")]
    return tuple(part for part in parts if part)
