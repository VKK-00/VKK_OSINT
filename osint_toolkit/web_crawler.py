from __future__ import annotations

import html
import re
from collections import deque
from dataclasses import dataclass
from urllib.parse import urldefrag, urljoin, urlparse

from .http_client import HttpClient, HttpResult
from .web_extract import (
    extract_public_emails,
    extract_public_links,
    extract_public_phones,
    filter_social_links,
)

ROBOTS_DISALLOW_LIMIT = 50
SITEMAP_FETCH_LIMIT = 5
SITEMAP_URL_LIMIT = 100
SITEMAP_LOC_RE = re.compile(r"<loc[^>]*>(.*?)</loc>", re.IGNORECASE | re.DOTALL)


@dataclass(frozen=True)
class CrawledPage:
    requested_url: str
    final_url: str
    depth: int
    status_code: int | None
    title: str = ""
    content_type: str = ""
    error: str = ""
    emails: tuple[str, ...] = ()
    phones: tuple[str, ...] = ()
    internal_links: tuple[str, ...] = ()
    external_links: tuple[str, ...] = ()
    social_links: tuple[str, ...] = ()


@dataclass(frozen=True)
class CrawlResult:
    seed_url: str
    root_host: str
    max_pages: int
    max_depth: int
    pages: tuple[CrawledPage, ...]
    queued_url_count: int
    truncated: bool
    robots_url: str = ""
    robots_status_code: int | None = None
    robots_sitemaps: tuple[str, ...] = ()
    robots_disallow_paths: tuple[str, ...] = ()
    sitemap_sources: tuple[str, ...] = ()
    sitemap_urls: tuple[str, ...] = ()

    @property
    def crawled_urls(self) -> tuple[str, ...]:
        return _dedupe(page.final_url or page.requested_url for page in self.pages)

    @property
    def emails(self) -> tuple[str, ...]:
        return _dedupe(value for page in self.pages for value in page.emails)

    @property
    def phones(self) -> tuple[str, ...]:
        return _dedupe(value for page in self.pages for value in page.phones)

    @property
    def internal_links(self) -> tuple[str, ...]:
        return _dedupe(value for page in self.pages for value in page.internal_links)

    @property
    def external_links(self) -> tuple[str, ...]:
        return _dedupe(value for page in self.pages for value in page.external_links)

    @property
    def social_links(self) -> tuple[str, ...]:
        return _dedupe(value for page in self.pages for value in page.social_links)


def crawl_public_site(
    seed_url: str,
    client: HttpClient,
    *,
    max_pages: int = 5,
    max_depth: int = 1,
    initial_results: tuple[HttpResult, ...] = (),
) -> CrawlResult:
    max_pages = max(1, max_pages)
    max_depth = max(0, max_depth)
    root_host = _host(seed_url)
    pages: list[CrawledPage] = []
    queued: set[str] = set()
    visited: set[str] = set()
    pending: deque[tuple[str, int]] = deque()
    discovery = _discover_site_urls(seed_url, root_host, client)

    if initial_results:
        for result in initial_results:
            _consume_result(
                result,
                depth=0,
                root_host=root_host,
                pages=pages,
                queued=queued,
                visited=visited,
                pending=pending,
                max_depth=max_depth,
            )
    else:
        _queue(seed_url, 0, queued, pending)
    if max_depth > 0:
        for sitemap_url in discovery.sitemap_urls:
            _queue(sitemap_url, 1, queued, pending)

    while pending and len(pages) < max_pages:
        url, depth = pending.popleft()
        result = client.check(url, fetch_title=True)
        _consume_result(
            result,
            depth=depth,
            root_host=root_host,
            pages=pages,
            queued=queued,
            visited=visited,
            pending=pending,
            max_depth=max_depth,
        )

    return CrawlResult(
        seed_url=seed_url,
        root_host=root_host,
        max_pages=max_pages,
        max_depth=max_depth,
        pages=tuple(pages[:max_pages]),
        robots_url=discovery.robots_url,
        robots_status_code=discovery.robots_status_code,
        robots_sitemaps=discovery.robots_sitemaps,
        robots_disallow_paths=discovery.robots_disallow_paths,
        sitemap_sources=discovery.sitemap_sources,
        sitemap_urls=discovery.sitemap_urls,
        queued_url_count=len(queued),
        truncated=bool(pending) or len(pages) > max_pages,
    )


def crawl_metadata(result: CrawlResult) -> dict[str, str]:
    return {
        "seed_url": result.seed_url,
        "root_host": result.root_host,
        "max_pages": str(result.max_pages),
        "max_depth": str(result.max_depth),
        "pages_fetched": str(len(result.pages)),
        "robots_url": result.robots_url,
        "robots_status": str(result.robots_status_code or ""),
        "robots_sitemaps": _join(result.robots_sitemaps),
        "robots_disallow_paths": _join(result.robots_disallow_paths),
        "robots_sitemap_count": str(len(result.robots_sitemaps)),
        "robots_disallow_count": str(len(result.robots_disallow_paths)),
        "sitemap_sources": _join(result.sitemap_sources),
        "sitemap_urls": _join(result.sitemap_urls),
        "sitemap_source_count": str(len(result.sitemap_sources)),
        "sitemap_url_count": str(len(result.sitemap_urls)),
        "queued_url_count": str(result.queued_url_count),
        "truncated": "yes" if result.truncated else "no",
        "crawled_urls": _join(result.crawled_urls),
        "discovered_urls": _join(result.internal_links),
        "external_urls": _join(result.external_links),
        "social_urls": _join(result.social_links),
        "emails": _join(result.emails),
        "phones": _join(result.phones),
        "email_count": str(len(result.emails)),
        "phone_count": str(len(result.phones)),
        "discovered_url_count": str(len(result.internal_links)),
        "external_url_count": str(len(result.external_links)),
        "social_url_count": str(len(result.social_links)),
    }


@dataclass(frozen=True)
class _DiscoveryResult:
    robots_url: str = ""
    robots_status_code: int | None = None
    robots_sitemaps: tuple[str, ...] = ()
    robots_disallow_paths: tuple[str, ...] = ()
    sitemap_sources: tuple[str, ...] = ()
    sitemap_urls: tuple[str, ...] = ()


def _discover_site_urls(seed_url: str, root_host: str, client: HttpClient) -> _DiscoveryResult:
    if not root_host:
        return _DiscoveryResult()
    root_url = _root_url(seed_url, root_host)
    robots_url = f"{root_url}/robots.txt"
    robots_result = client.check(robots_url, fetch_title=True)
    robots_sitemaps, disallow_paths = _parse_robots_txt(robots_result.body_text, root_url)
    sitemap_candidates = _dedupe((*robots_sitemaps, f"{root_url}/sitemap.xml"))
    sitemap_sources, sitemap_urls = _fetch_sitemap_urls(sitemap_candidates, root_host, client)
    return _DiscoveryResult(
        robots_url=robots_url,
        robots_status_code=robots_result.status_code,
        robots_sitemaps=robots_sitemaps,
        robots_disallow_paths=disallow_paths,
        sitemap_sources=sitemap_sources,
        sitemap_urls=sitemap_urls,
    )


def _parse_robots_txt(text: str, root_url: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if not text:
        return (), ()
    sitemaps: list[str] = []
    disallow_paths: list[str] = []
    seen_disallow: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "sitemap":
            sitemap = _normalize_url(value, root_url)
            if sitemap:
                sitemaps.append(sitemap)
        elif key == "disallow" and value:
            normalized = value.strip()
            if len(disallow_paths) < ROBOTS_DISALLOW_LIMIT and normalized not in seen_disallow:
                seen_disallow.add(normalized)
                disallow_paths.append(normalized)
    return _dedupe(sitemaps), tuple(disallow_paths)


def _fetch_sitemap_urls(
    sitemap_candidates: tuple[str, ...],
    root_host: str,
    client: HttpClient,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    pending: deque[str] = deque(sitemap_candidates)
    fetched: list[str] = []
    seen_sources: set[str] = set()
    urls: list[str] = []
    seen_urls: set[str] = set()
    while pending and len(fetched) < SITEMAP_FETCH_LIMIT and len(urls) < SITEMAP_URL_LIMIT:
        sitemap_url = pending.popleft()
        source_key = sitemap_url.lower()
        if source_key in seen_sources:
            continue
        seen_sources.add(source_key)
        result = client.check(
            sitemap_url,
            fetch_title=True,
            headers={"Accept": "application/xml,text/xml,text/plain,text/html"},
        )
        if result.status_code is None or result.status_code >= 400 or not result.body_text:
            continue
        fetched.append(result.final_url or sitemap_url)
        for loc in _parse_sitemap_locations(result.body_text, result.final_url or sitemap_url):
            if not _same_site(_host(loc), root_host):
                continue
            if _looks_like_sitemap_url(loc) and len(fetched) + len(pending) < SITEMAP_FETCH_LIMIT:
                pending.append(loc)
                continue
            key = loc.lower()
            if key not in seen_urls:
                seen_urls.add(key)
                urls.append(loc)
            if len(urls) >= SITEMAP_URL_LIMIT:
                break
    return _dedupe(fetched), tuple(urls)


def _parse_sitemap_locations(text: str, base_url: str) -> tuple[str, ...]:
    values: list[str] = []
    for match in SITEMAP_LOC_RE.finditer(text):
        loc = _normalize_url(html.unescape(re.sub(r"\s+", " ", match.group(1))).strip(), base_url)
        if loc:
            values.append(loc)
    if not values:
        for line in text.splitlines():
            loc = _normalize_url(line.strip(), base_url)
            if loc:
                values.append(loc)
    return _dedupe(values)


def _consume_result(
    result: HttpResult,
    *,
    depth: int,
    root_host: str,
    pages: list[CrawledPage],
    queued: set[str],
    visited: set[str],
    pending: deque[tuple[str, int]],
    max_depth: int,
) -> None:
    page_url = result.final_url or result.url
    page_key = _canonical_url(page_url)
    if page_key in visited:
        return
    visited.add(page_key)

    links = extract_public_links(result.body_text, page_url)
    internal_links, external_links = _split_links_by_scope(links, root_host)
    social_links = filter_social_links(links)
    page = CrawledPage(
        requested_url=result.url,
        final_url=page_url,
        depth=depth,
        status_code=result.status_code,
        title=result.title,
        content_type=result.content_type,
        error=result.error,
        emails=extract_public_emails(result.body_text),
        phones=extract_public_phones(result.body_text),
        internal_links=internal_links,
        external_links=external_links,
        social_links=social_links,
    )
    pages.append(page)

    if depth >= max_depth:
        return
    for link in internal_links:
        if _canonical_url(link) not in visited:
            _queue(link, depth + 1, queued, pending)


def _queue(url: str, depth: int, queued: set[str], pending: deque[tuple[str, int]]) -> None:
    key = _canonical_url(url)
    if not key or key in queued:
        return
    queued.add(key)
    pending.append((url, depth))


def _split_links_by_scope(links: tuple[str, ...], root_host: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    internal: list[str] = []
    external: list[str] = []
    for link in links:
        host = _host(link)
        if _same_site(host, root_host):
            internal.append(link)
        else:
            external.append(link)
    return tuple(internal), tuple(external)


def _same_site(host: str, root_host: str) -> bool:
    if not host or not root_host:
        return False
    return host == root_host or host.endswith(f".{root_host}") or f"www.{host}" == root_host


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower().strip(".")


def _root_url(seed_url: str, root_host: str) -> str:
    parsed = urlparse(seed_url)
    scheme = parsed.scheme if parsed.scheme in {"http", "https"} else "https"
    port = f":{parsed.port}" if parsed.port else ""
    return f"{scheme}://{root_host}{port}"


def _normalize_url(value: str, base_url: str) -> str:
    if not value:
        return ""
    absolute, _fragment = urldefrag(urljoin(base_url, value.strip()))
    parsed = urlparse(absolute)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return absolute


def _looks_like_sitemap_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return "sitemap" in path and path.endswith((".xml", ".xml.gz", ".txt"))


def _canonical_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    host = (parsed.hostname or "").lower()
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme.lower()}://{host}{port}{path}{query}"


def _dedupe(values) -> tuple[str, ...]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        normalized = str(value).strip()
        key = normalized.lower()
        if normalized and key not in seen:
            seen.add(key)
            deduped.append(normalized)
    return tuple(deduped)


def _join(values: tuple[str, ...], *, limit: int = 50) -> str:
    return ", ".join(values[:limit])
