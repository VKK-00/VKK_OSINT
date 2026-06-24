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
        sites = _filter_sites(self.sites, target.region)
        if config.limit is not None:
            sites = sites[: config.limit]
        if not config.live:
            return tuple(_planned_finding(self.name, target.value, site) for site in sites)

        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent)
        findings: list[Finding] = []
        for site in sites:
            url = site.url_for(target.value)
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


def _planned_finding(module: str, username: str, site: UsernameSite) -> Finding:
    return Finding(
        module=module,
        source=site.name,
        target=username,
        status="planned",
        url=site.url_for(username),
        confidence="not_checked",
        evidence="Dry run only. Pass --live to perform public HTTP checks.",
        metadata={"region": site.region, "source_projects": ", ".join(site.source_projects)},
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

