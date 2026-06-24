from __future__ import annotations

import socket
from dataclasses import dataclass
from urllib.parse import urlparse

from ..engine import Finding, RunConfig, ScanTarget
from ..http_client import HttpClient

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
)


@dataclass(frozen=True)
class DomainScanModule:
    name: str = "domain-baseline"
    supported_targets: tuple[str, ...] = ("domain",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        domain = normalize_domain(target.value)
        if not domain:
            return (
                Finding(
                    module=self.name,
                    source="normalizer",
                    target=target.value,
                    status="invalid",
                    confidence="high",
                    evidence="Could not normalize input into a domain name.",
                ),
            )

        if not config.live:
            return (
                Finding(
                    module=self.name,
                    source="dns-resolution",
                    target=target.value,
                    status="planned",
                    confidence="not_checked",
                    evidence="Dry run only. Pass --live to resolve the domain.",
                    metadata={"domain": domain},
                ),
                Finding(
                    module=self.name,
                    source="https-metadata",
                    target=target.value,
                    status="planned",
                    url=f"https://{domain}",
                    confidence="not_checked",
                    evidence="Dry run only. Pass --live to fetch HTTPS metadata.",
                    metadata={"domain": domain},
                ),
                Finding(
                    module=self.name,
                    source="http-metadata",
                    target=target.value,
                    status="planned",
                    url=f"http://{domain}",
                    confidence="not_checked",
                    evidence="Dry run only. Pass --live to fetch HTTP metadata.",
                    metadata={"domain": domain},
                ),
            )

        findings: list[Finding] = []
        findings.append(_resolve_domain(self.name, target.value, domain))
        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent)
        findings.append(_http_metadata(self.name, target.value, domain, "https", client))
        findings.append(_http_metadata(self.name, target.value, domain, "http", client))
        return tuple(findings)


def normalize_domain(value: str) -> str:
    raw = value.strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or ""
    host = host.strip(".").lower()
    if not host or " " in host or "." not in host:
        return ""
    return host


def _resolve_domain(module: str, original: str, domain: str) -> Finding:
    try:
        records = socket.getaddrinfo(domain, None)
    except socket.gaierror as exc:
        return Finding(
            module=module,
            source="dns-resolution",
            target=original,
            status="not_found",
            confidence="medium",
            evidence=str(exc),
            metadata={"domain": domain},
        )

    addresses = sorted({record[4][0] for record in records if record and record[4]})
    return Finding(
        module=module,
        source="dns-resolution",
        target=original,
        status="candidate",
        confidence="medium",
        evidence=f"Resolved {len(addresses)} unique address(es).",
        metadata={"domain": domain, "addresses": ", ".join(addresses[:10])},
    )


def _http_metadata(module: str, original: str, domain: str, scheme: str, client: HttpClient) -> Finding:
    url = f"{scheme}://{domain}"
    result = client.check(url, fetch_title=True)
    status = "candidate" if result.status_code and result.status_code < 400 else "unknown"
    security_headers = {
        header: result.headers[header]
        for header in SECURITY_HEADERS
        if header in result.headers
    }
    return Finding(
        module=module,
        source=f"{scheme}-metadata",
        target=original,
        status=status,
        url=result.final_url or url,
        title=result.title,
        http_status=result.status_code,
        confidence="medium" if result.status_code and result.status_code < 400 else "low",
        evidence=result.error or f"HTTP {result.status_code}",
        metadata={
            "domain": domain,
            "content_type": result.content_type,
            "requested_url": url,
            "security_headers_present": ", ".join(sorted(security_headers)),
        },
    )
