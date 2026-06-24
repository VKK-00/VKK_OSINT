from __future__ import annotations

from dataclasses import dataclass

from ..engine import Finding, RunConfig, ScanTarget


@dataclass(frozen=True)
class RuUaSource:
    name: str
    url: str
    category: str
    region: str
    note: str
    upstream_refs: tuple[str, ...]


RU_UA_SOURCES: tuple[RuUaSource, ...] = (
    RuUaSource(
        "DeepStateMap",
        "https://deepstatemap.live/",
        "conflict-map",
        "ua",
        "Ukraine frontline/conflict map source referenced by Shadowbroker.",
        ("BigBodyCobain/Shadowbroker",),
    ),
    RuUaSource(
        "Liveuamap Ukraine",
        "https://liveuamap.com/",
        "conflict-map",
        "ua",
        "Ukraine interactive map resource referenced by OSINT lists.",
        ("Astrosp/Awesome-OSINT-List",),
    ),
    RuUaSource(
        "TGStat RU",
        "https://tgstat.ru/",
        "telegram-analytics",
        "ru",
        "Russian Telegram analytics/search resource referenced by Telegram/SOCMINT lists.",
        ("ItIsMeCall911/Awesome-Telegram-OSINT", "osintambition/Social-Media-OSINT-Tools-Collection"),
    ),
    RuUaSource(
        "VK",
        "https://vk.com/",
        "social-platform",
        "ru",
        "VKontakte platform/API appears across RU-oriented OSINT resources.",
        ("cipher387/API-s-for-OSINT", "snooppr/snoop"),
    ),
    RuUaSource(
        "Odnoklassniki",
        "https://ok.ru/",
        "social-platform",
        "ru",
        "Odnoklassniki API/platform source in RU-oriented OSINT API lists.",
        ("cipher387/API-s-for-OSINT",),
    ),
    RuUaSource(
        "Yandex",
        "https://yandex.com/",
        "search-platform",
        "ru",
        "Yandex search/dorks/trends resources appear in multiple OSINT lists.",
        ("jivoi/awesome-osint", "cipher387/Dorks-collections-list", "Jieyab89/OSINT-Cheat-sheet"),
    ),
    RuUaSource(
        "Mail.ru",
        "https://mail.ru/",
        "platform",
        "ru",
        "mail.ru appears in account/email-related source lists; use only within lawful scope.",
        ("megadose/holehe",),
    ),
    RuUaSource(
        "Geocam.ru",
        "https://www.geocam.ru/en/",
        "geospatial",
        "ru",
        "Webcam/geospatial resource referenced by hacker search engine lists.",
        ("edoardottt/awesome-hacker-search-engines",),
    ),
    RuUaSource(
        "paste.in.ua",
        "https://paste.in.ua/",
        "pastebin",
        "ua",
        "Ukrainian pastebin resource referenced by awesome-osint.",
        ("jivoi/awesome-osint",),
    ),
)


@dataclass(frozen=True)
class RuUaSourcePackModule:
    name: str = "ru-ua-source-pack"
    supported_targets: tuple[str, ...] = ("ru-ua",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        del config
        selector = target.value.strip().lower() or "all"
        sources = filter_sources(selector, target.region)
        if not sources:
            return (
                Finding(
                    module=self.name,
                    source="source-pack",
                    target=target.value,
                    status="not_found",
                    confidence="high",
                    evidence="No RU/UA source-pack entries matched the selector.",
                ),
            )
        return tuple(source_to_finding(self.name, target.value, source) for source in sources)


def filter_sources(selector: str, region: str) -> tuple[RuUaSource, ...]:
    matched: list[RuUaSource] = []
    for source in RU_UA_SOURCES:
        if region in {"ru", "ua"} and source.region != region:
            continue
        if selector in {"all", "ru-ua", "russia-ukraine"}:
            matched.append(source)
        elif selector in {source.region, source.category.lower()}:
            matched.append(source)
        elif selector == "platforms" and "platform" in source.category.lower():
            matched.append(source)
        elif selector == "maps" and "map" in source.category.lower():
            matched.append(source)
        elif selector in source.name.lower() or selector in source.note.lower():
            matched.append(source)
    return tuple(matched)


def source_to_finding(module: str, target: str, source: RuUaSource) -> Finding:
    return Finding(
        module=module,
        source=source.name,
        target=target,
        status="reference",
        url=source.url,
        confidence="curated",
        evidence=source.note,
        metadata={
            "category": source.category,
            "region": source.region,
            "upstream_refs": ", ".join(source.upstream_refs),
        },
    )
