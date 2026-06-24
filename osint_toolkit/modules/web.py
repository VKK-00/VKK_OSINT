from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from ..engine import Finding, RunConfig, ScanTarget
from ..http_client import HttpClient


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
        )


def _normalize_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme:
        return value
    return f"https://{value}"

