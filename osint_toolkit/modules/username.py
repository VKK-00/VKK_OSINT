from __future__ import annotations

from dataclasses import dataclass

from ..engine import Finding, RunConfig, ScanTarget
from ..http_client import HttpClient
from ..sites import USERNAME_SITES, UsernameSite


@dataclass(frozen=True)
class UsernameScanModule:
    sites: tuple[UsernameSite, ...] = USERNAME_SITES
    name: str = "username-public-profiles"
    supported_targets: tuple[str, ...] = ("username",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        username = normalize_username(target.value)
        if not username:
            return (
                Finding(
                    module=self.name,
                    source="normalizer",
                    target=target.value,
                    status="invalid",
                    confidence="high",
                    evidence="Username is empty after normalization.",
                ),
            )

        sites = _filter_sites(self.sites, target.region)
        if config.limit is not None:
            sites = sites[: config.limit]
        if not config.live:
            return tuple(_planned_or_skipped_finding(self.name, target.value, username, site) for site in sites)

        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent)
        findings: list[Finding] = []
        for site in sites:
            skip_reason = site.validate_username(username)
            if skip_reason:
                findings.append(_skipped_finding(self.name, target.value, username, site, skip_reason))
                continue
            url = site.url_for(username)
            result = client.check(url, fetch_title=True)
            status, confidence = _classify_status(result.status_code)
            findings.append(
                Finding(
                    module=self.name,
                    source=site.name,
                    target=target.value,
                    status=status,
                    url=result.final_url or url,
                    title=result.title,
                    http_status=result.status_code,
                    confidence=confidence,
                    evidence=result.error or f"HTTP {result.status_code}",
                    metadata={
                        "region": site.region,
                        "normalized_username": username,
                        "rule_status": "matched",
                        "source_projects": ", ".join(site.source_projects),
                        "requested_url": url,
                    },
                )
            )
        return tuple(findings)


def _filter_sites(sites: tuple[UsernameSite, ...], region: str) -> tuple[UsernameSite, ...]:
    if region == "all":
        return sites
    if region == "ru":
        return tuple(site for site in sites if site.region in {"global", "ru"})
    if region == "ua":
        # There are no Ukraine-specific username templates in the initial native set.
        return tuple(site for site in sites if site.region == "global")
    return sites


def normalize_username(value: str) -> str:
    return value.strip().lstrip("@").strip()


def _planned_or_skipped_finding(module: str, original: str, username: str, site: UsernameSite) -> Finding:
    skip_reason = site.validate_username(username)
    if skip_reason:
        return _skipped_finding(module, original, username, site, skip_reason)
    return _planned_finding(module, original, username, site)


def _planned_finding(module: str, original: str, username: str, site: UsernameSite) -> Finding:
    return Finding(
        module=module,
        source=site.name,
        target=original,
        status="planned",
        url=site.url_for(username),
        confidence="not_checked",
        evidence="Dry run only. Pass --live to perform public HTTP checks.",
        metadata={
            "region": site.region,
            "normalized_username": username,
            "rule_status": "matched",
            "source_projects": ", ".join(site.source_projects),
        },
    )


def _skipped_finding(module: str, original: str, username: str, site: UsernameSite, reason: str) -> Finding:
    return Finding(
        module=module,
        source=site.name,
        target=original,
        status="skipped",
        confidence="high",
        evidence=reason,
        metadata={
            "region": site.region,
            "normalized_username": username,
            "rule_status": "skipped",
            "source_projects": ", ".join(site.source_projects),
        },
    )


def _classify_status(status_code: int | None) -> tuple[str, str]:
    if status_code is None:
        return "error", "unknown"
    if status_code in {200, 201, 202, 204, 301, 302, 303, 307, 308}:
        return "candidate", "medium"
    if status_code == 404:
        return "not_found", "medium"
    if status_code in {401, 403, 429}:
        return "unknown", "low"
    if 500 <= status_code:
        return "unknown", "low"
    return "unknown", "low"
