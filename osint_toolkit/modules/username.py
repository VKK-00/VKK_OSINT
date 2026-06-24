from __future__ import annotations

from dataclasses import dataclass

from ..engine import Finding, RunConfig, ScanTarget
from ..http_client import HttpClient, HttpResult
from ..sites import USERNAME_SITES, UsernameSite


@dataclass(frozen=True)
class UsernameHttpClassification:
    status: str
    confidence: str
    evidence: str
    content_rule: str = "unmatched"
    content_marker: str = ""


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
            profile_url = site.profile_url_for(username)
            headers = dict(site.request_headers)
            request_body = site.request_body_for(username)
            if site.request_method == "POST" and _looks_like_json(request_body):
                header_names = {header.casefold() for header in headers}
                if "content-type" not in header_names:
                    headers["Content-Type"] = "application/json"
            result = client.check(
                url,
                fetch_title=True,
                headers=headers or None,
                method=site.request_method,
                body=request_body,
            )
            classification = classify_username_http_result(site, username, result)
            metadata = {
                "region": site.region,
                "normalized_username": username,
                "rule_status": "matched",
                "content_rule": classification.content_rule,
                "content_marker": classification.content_marker,
                "source_projects": ", ".join(site.source_projects),
                "requested_url": url,
                "custom_headers": "yes" if headers else "no",
                "request_method": site.request_method,
            }
            if profile_url:
                metadata["profile_url"] = profile_url
            findings.append(
                Finding(
                    module=self.name,
                    source=site.name,
                    target=target.value,
                    status=classification.status,
                    url=result.final_url or url,
                    title=result.title,
                    http_status=result.status_code,
                    confidence=classification.confidence,
                    evidence=classification.evidence,
                    metadata=metadata,
                )
            )
        return tuple(findings)


def _filter_sites(sites: tuple[UsernameSite, ...], region: str) -> tuple[UsernameSite, ...]:
    if region == "all":
        return sites
    if region == "ru":
        return tuple(site for site in sites if site.region in {"global", "ru", "ru-ua"})
    if region == "ua":
        return tuple(site for site in sites if site.region in {"global", "ua", "ru-ua"})
    return sites


def classify_username_http_result(
    site: UsernameSite,
    username: str,
    result: HttpResult,
) -> UsernameHttpClassification:
    content_rule, content_marker = site.match_content(username, result.title, result.body_text)
    if content_rule == "not_found_marker":
        return UsernameHttpClassification(
            status="not_found",
            confidence="high",
            evidence=f"HTTP {result.status_code}; matched {site.name} not-found marker.",
            content_rule=content_rule,
            content_marker=content_marker,
        )
    if content_rule == "profile_marker":
        return UsernameHttpClassification(
            status="candidate",
            confidence="high",
            evidence=f"HTTP {result.status_code}; matched {site.name} profile marker.",
            content_rule=content_rule,
            content_marker=content_marker,
        )
    not_found_url = site.not_found_url_for(username)
    if _url_matches_rule(result.final_url, not_found_url):
        return UsernameHttpClassification(
            status="not_found",
            confidence="high",
            evidence=f"HTTP {result.status_code}; matched {site.name} response-url not-found rule.",
            content_rule="response_url",
            content_marker=not_found_url,
        )

    if result.status_code in site.not_found_status_codes and (
        result.status_code >= 300 or not site.not_found_markers
    ):
        return UsernameHttpClassification(
            status="not_found",
            confidence="high",
            evidence=f"HTTP {result.status_code}; matched {site.name} not-found status rule.",
            content_rule=content_rule or "not_found_status",
            content_marker="",
        )
    if result.status_code in site.candidate_status_codes and (
        result.status_code >= 400 or not site.profile_markers
    ):
        return UsernameHttpClassification(
            status="candidate",
            confidence="medium",
            evidence=f"HTTP {result.status_code}; matched {site.name} candidate status rule.",
            content_rule=content_rule or "candidate_status",
            content_marker="",
        )

    status, confidence = _classify_status(result.status_code)
    return UsernameHttpClassification(
        status=status,
        confidence=confidence,
        evidence=result.error or f"HTTP {result.status_code}",
        content_rule=content_rule or "unmatched",
        content_marker=content_marker,
    )


def normalize_username(value: str) -> str:
    return value.strip().lstrip("@").strip()


def _looks_like_json(value: str) -> bool:
    stripped = value.lstrip()
    return stripped.startswith("{") or stripped.startswith("[")


def _url_matches_rule(actual_url: str, expected_url: str) -> bool:
    if not actual_url or not expected_url:
        return False
    actual = actual_url.strip().rstrip("/").casefold()
    expected = expected_url.strip().rstrip("/").casefold()
    if actual == expected:
        return True
    if expected.endswith("=") and actual.startswith(expected):
        return True
    if "://" not in expected:
        actual_without_scheme = actual.split("://", 1)[-1]
        return actual_without_scheme == expected or (
            expected.endswith("=") and actual_without_scheme.startswith(expected)
        )
    return False


def _planned_or_skipped_finding(module: str, original: str, username: str, site: UsernameSite) -> Finding:
    skip_reason = site.validate_username(username)
    if skip_reason:
        return _skipped_finding(module, original, username, site, skip_reason)
    return _planned_finding(module, original, username, site)


def _planned_finding(module: str, original: str, username: str, site: UsernameSite) -> Finding:
    metadata = {
        "region": site.region,
        "normalized_username": username,
        "rule_status": "matched",
        "source_projects": ", ".join(site.source_projects),
        "request_method": site.request_method,
    }
    profile_url = site.profile_url_for(username)
    if profile_url:
        metadata["profile_url"] = profile_url
    return Finding(
        module=module,
        source=site.name,
        target=original,
        status="planned",
        url=site.url_for(username),
        confidence="not_checked",
        evidence="Dry run only. Pass --live to perform public HTTP checks.",
        metadata=metadata,
    )


def _skipped_finding(module: str, original: str, username: str, site: UsernameSite, reason: str) -> Finding:
    metadata = {
        "region": site.region,
        "normalized_username": username,
        "rule_status": "skipped",
        "source_projects": ", ".join(site.source_projects),
        "request_method": site.request_method,
    }
    profile_url = site.profile_url_for(username)
    if profile_url:
        metadata["profile_url"] = profile_url
    return Finding(
        module=module,
        source=site.name,
        target=original,
        status="skipped",
        confidence="high",
        evidence=reason,
        metadata=metadata,
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
