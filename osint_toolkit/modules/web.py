from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from ..engine import Finding, RunConfig, ScanTarget
from ..http_client import HttpClient
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
            )

        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent)
        result = client.check(url, fetch_title=True)
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
