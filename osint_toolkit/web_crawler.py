from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from urllib.parse import urlparse

from .http_client import HttpClient, HttpResult
from .web_extract import (
    extract_public_emails,
    extract_public_links,
    extract_public_phones,
    filter_social_links,
)


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
