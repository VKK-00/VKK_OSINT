from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from ..engine import Finding, RunConfig, ScanTarget
from ..http_client import HttpClient
from ..web_crawler import CrawlResult, crawl_metadata, crawl_public_site
from ..web_extract import extract_public_emails


@dataclass(frozen=True)
class WebMetadataModule:
    name: str = "web-metadata"
    supported_targets: tuple[str, ...] = ("url",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        url = _normalize_url(target.value)
        if not config.live:
            return (
                Finding(
                    module=self.name,
                    source="web",
                    target=target.value,
                    status="planned",
                    url=url,
                    confidence="not_checked",
                    evidence="Dry run only. Pass --live to fetch status, final URL and page title.",
                ),
                Finding(
                    module=self.name,
                    source="page-email-extraction",
                    target=target.value,
                    status="planned",
                    url=url,
                    confidence="not_checked",
                    evidence="Dry run only. Pass --live to extract public email addresses from the page.",
                ),
                Finding(
                    module=self.name,
                    source="web-crawl",
                    target=target.value,
                    status="planned",
                    url=url,
                    confidence="not_checked",
                    evidence="Dry run only. Pass --live to crawl bounded same-site links and extract public contacts.",
                    metadata={
                        "seed_url": url,
                        "max_pages": str(config.crawl_pages),
                        "max_depth": str(config.crawl_depth),
                    },
                ),
            )

        client = HttpClient(
            timeout=config.timeout,
            user_agent=config.user_agent,
            retries=config.http_retries,
            backoff_seconds=config.http_backoff,
        )
        result = client.check(url, fetch_title=True)
        crawl = crawl_public_site(
            result.final_url or url,
            client,
            max_pages=config.crawl_pages,
            max_depth=config.crawl_depth,
            initial_results=(result,),
        )
        status = "candidate" if result.status_code and result.status_code < 400 else "unknown"
        return (
            Finding(
                module=self.name,
                source="web",
                target=target.value,
                status=status,
                url=result.final_url or url,
                title=result.title,
                http_status=result.status_code,
                confidence="medium" if result.status_code and result.status_code < 400 else "low",
                evidence=result.error or f"HTTP {result.status_code}",
                metadata={"content_type": result.content_type, "requested_url": url},
            ),
            _page_email_extraction(self.name, target.value, result),
            _web_crawl(self.name, target.value, crawl),
        )


def _normalize_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme:
        return value
    return f"https://{value}"


def _page_email_extraction(module: str, original: str, result) -> Finding:
    emails = extract_public_emails(result.body_text)
    final_url = result.final_url or result.url
    metadata = {
        "emails": ", ".join(emails),
        "email_count": str(len(emails)),
        "requested_url": result.url,
    }
    domain = _domain_from_url(final_url)
    if domain:
        metadata["domain"] = domain
    if not emails:
        return Finding(
            module=module,
            source="page-email-extraction",
            target=original,
            status="not_found",
            url=final_url,
            http_status=result.status_code,
            confidence="medium",
            evidence="No public email addresses found on fetched page.",
            metadata=metadata,
        )
    return Finding(
        module=module,
        source="page-email-extraction",
        target=original,
        status="candidate",
        url=final_url,
        http_status=result.status_code,
        confidence="medium",
        evidence=f"Found {len(emails)} public email address(es) on fetched page.",
        metadata=metadata,
    )


def _domain_from_url(value: str) -> str:
    parsed = urlparse(value)
    return (parsed.hostname or "").lower()


def _web_crawl(module: str, original: str, crawl: CrawlResult) -> Finding:
    metadata = crawl_metadata(crawl)
    if crawl.root_host:
        metadata["domain"] = crawl.root_host
    successful_pages = sum(1 for page in crawl.pages if page.status_code and page.status_code < 400)
    status = "candidate" if successful_pages else "unknown" if crawl.pages else "error"
    return Finding(
        module=module,
        source="web-crawl",
        target=original,
        status=status,
        url=crawl.crawled_urls[0] if crawl.crawled_urls else crawl.seed_url,
        http_status=crawl.pages[0].status_code if crawl.pages else None,
        confidence="medium" if successful_pages else "low",
        evidence=(
            f"Crawled {len(crawl.pages)} page(s); found {len(crawl.internal_links)} same-site URL(s), "
            f"{len(crawl.external_links)} external URL(s), {len(crawl.social_links)} social URL(s), "
            f"{len(crawl.emails)} email(s) and {len(crawl.phones)} phone(s)."
        ),
        metadata=metadata,
    )
