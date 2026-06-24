from __future__ import annotations

import csv
import io
import json
import re
from typing import Any
from urllib.parse import urlparse

from .engine import Finding, ScanTarget

URL_RE = re.compile(r"https?://[^\s<>\]\)\"']+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"\+[1-9]\d{7,14}\b")
KEY_VALUE_RE = re.compile(r"^\s*(?P<key>[A-Za-z][A-Za-z0-9 _./-]{1,40})\s*[:=]\s*(?P<value>.+?)\s*$")
SOCIAL_LINE_RE = re.compile(r"^\s*(?:\[[+*]\]|\+|FOUND:?)?\s*(?P<label>[A-Za-z0-9_. /-]{2,40})\s*[:|-]\s*(?P<rest>.+)$")
USER_SCANNER_LINE_RE = re.compile(
    r"^\s*(?:\[[^\]]+\]\s*)?"
    r"(?P<site>[A-Za-z0-9_. ()/-]{2,80})"
    r"(?:\s+\[(?P<url>https?://[^\]]+)\])?"
    r"\s+\((?P<value>[^)]+)\):\s*"
    r"(?P<status>Registered|Available|Found|Not Found|Not Registered|Error)"
    r"(?:\s*[-:]\s*(?P<reason>.*))?\s*$",
    re.IGNORECASE,
)
SNOOP_LINE_RE = re.compile(
    r"^\s*(?:\[[+\-]\]\s*)?(?P<site>[^:]{2,120}):\s*(?P<rest>.+?)\s*$",
    re.IGNORECASE,
)
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

PARSER_REPOSITORIES = {
    "sherlock-project/sherlock",
    "soxoj/maigret",
    "thewhiteh4t/nexfil",
    "snooppr/snoop",
    "alpkeskin/mosint",
    "khast3x/h8mail",
    "sundowndev/phoneinfoga",
    "kaifcodec/user-scanner",
}

PHONE_KEYS = {
    "country": "country",
    "carrier": "carrier",
    "location": "location",
    "line type": "line_type",
    "international format": "normalized",
    "e164": "normalized",
    "number": "normalized",
    "phone": "phone",
}

EMAIL_KEYS = {
    "email": "email",
    "domain": "domain",
    "name": "name",
    "full name": "name",
}


def parse_adapter_output(
    repository: str,
    target: ScanTarget,
    stdout: str,
    stderr: str = "",
) -> tuple[Finding, ...]:
    text = _clean_output("\n".join(part for part in (stdout, stderr) if part))
    if not text or repository not in PARSER_REPOSITORIES:
        return ()

    if repository == "kaifcodec/user-scanner":
        return _user_scanner_findings(repository, target, text)
    if repository == "snooppr/snoop":
        return _snoop_findings(repository, target, text)
    if repository == "soxoj/maigret":
        return _maigret_findings(repository, target, text)
    if repository == "alpkeskin/mosint":
        return _mosint_findings(repository, target, text)
    if repository == "khast3x/h8mail":
        return _h8mail_findings(repository, target, text)

    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for line in text.splitlines():
        compact = " ".join(line.split())
        if not compact:
            continue
        findings.extend(_url_findings(repository, target, compact, seen))
        findings.extend(_email_findings(repository, target, compact, seen))
        findings.extend(_phone_findings(repository, target, compact, seen))
        key_value = _key_value_finding(repository, target, compact, seen)
        if key_value:
            findings.append(key_value)
    return tuple(findings)


def _mosint_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    structured = _mosint_json_findings(repository, target, text)
    if structured:
        return structured

    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for line in text.splitlines():
        compact = " ".join(line.split())
        if not compact:
            continue
        findings.extend(_url_findings(repository, target, compact, seen))
        findings.extend(_email_findings(repository, target, compact, seen))
        findings.extend(_phone_findings(repository, target, compact, seen))
        key_value = _key_value_finding(repository, target, compact, seen)
        if key_value:
            findings.append(key_value)
    return tuple(findings)


def _mosint_json_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    payload = _load_json_payload(text)
    if not isinstance(payload, dict):
        return ()

    email = _first_scalar(payload.get("email")) or target.value
    findings: list[Finding] = []
    seen: set[tuple[str, ...]] = set()

    _append_if(findings, _mosint_verification_finding(repository, target, email, payload, seen))
    findings.extend(_mosint_emailrep_findings(repository, target, email, payload.get("emailrep"), seen))
    findings.extend(_mosint_breachdirectory_findings(repository, target, email, payload.get("breachdirectory"), seen))
    findings.extend(_mosint_hibp_findings(repository, target, email, payload.get("haveibeenpwned"), seen))
    findings.extend(_mosint_hunter_findings(repository, target, email, payload.get("hunter"), seen))
    findings.extend(_mosint_url_list_findings(repository, target, email, payload.get("google_search"), "google-search", seen))
    findings.extend(_mosint_url_list_findings(repository, target, email, payload.get("psbdmp"), "paste-dump", seen))
    findings.extend(_mosint_url_list_findings(repository, target, email, payload.get("intelx"), "intelx", seen))
    findings.extend(_mosint_social_findings(repository, target, email, payload, seen))
    findings.extend(_mosint_dns_findings(repository, target, email, payload.get("dns_records"), seen))
    _append_if(findings, _mosint_ipapi_finding(repository, target, email, payload.get("ipapi"), seen))
    return tuple(findings)


def _mosint_verification_finding(
    repository: str,
    target: ScanTarget,
    email: str,
    payload: dict[str, Any],
    seen: set[tuple[str, ...]],
) -> Finding | None:
    if not email and "verified" not in payload:
        return None
    verified = bool(payload.get("verified"))
    metadata = _mosint_metadata(repository, target, email, "verification", "mosint")
    metadata["verified"] = str(verified).lower()
    return _mosint_finding(
        repository=repository,
        target=target,
        status="candidate" if verified else "observed",
        confidence="medium" if verified else "low",
        evidence=f"Mosint verification for {email or target.value}: {str(verified).lower()}",
        metadata=metadata,
        seen=seen,
        key=("mosint", "verification", email.lower(), str(verified).lower()),
    )


def _mosint_emailrep_findings(
    repository: str,
    target: ScanTarget,
    email: str,
    value: object,
    seen: set[tuple[str, ...]],
) -> tuple[Finding, ...]:
    if not isinstance(value, dict):
        return ()

    details = value.get("details") if isinstance(value.get("details"), dict) else {}
    rep_email = _first_scalar(value.get("email")) or email
    reputation = _first_scalar(value.get("reputation"))
    references = _first_scalar(value.get("references"))
    if not rep_email and not reputation and not references:
        return ()

    metadata = _mosint_metadata(repository, target, rep_email, "email-reputation", "emailrep")
    for source_key, metadata_key in (
        ("reputation", "reputation"),
        ("suspicious", "suspicious"),
        ("references", "references"),
    ):
        result = _first_scalar(value.get(source_key))
        if result:
            metadata[metadata_key] = result
    for source_key in (
        "blacklisted",
        "malicious_activity",
        "credentials_leaked",
        "credentials_leaked_recent",
        "data_breach",
        "first_seen",
        "last_seen",
        "domain_reputation",
        "spam",
        "deliverable",
        "valid_mx",
        "primary_mx",
        "spf_strict",
        "dmarc_enforced",
    ):
        result = _first_scalar(details.get(source_key))
        if result:
            metadata[f"extra_{source_key}"] = result

    risk = any(_truthy(details.get(key)) for key in ("credentials_leaked", "data_breach", "blacklisted", "malicious_activity"))
    findings: list[Finding] = []
    _append_if(
        findings,
        _mosint_finding(
            repository=repository,
            target=target,
            status="candidate" if risk else "observed",
            confidence="high" if risk else "medium",
            evidence=_short(f"Mosint EmailRep: reputation={reputation or 'unknown'}, suspicious={_first_scalar(value.get('suspicious')) or 'false'}"),
            metadata=metadata,
            seen=seen,
            key=("mosint", "emailrep", rep_email.lower(), reputation.lower()),
        ),
    )

    profiles = details.get("profiles")
    if isinstance(profiles, list):
        for profile in profiles:
            platform = _first_scalar(profile)
            if not platform:
                continue
            social_metadata = _mosint_metadata(repository, target, rep_email, "social-account", platform)
            _append_if(
                findings,
                _mosint_finding(
                    repository=repository,
                    target=target,
                    status="candidate",
                    confidence="medium",
                    evidence=f"Mosint EmailRep social profile signal: {platform}",
                    metadata=social_metadata,
                    seen=seen,
                    key=("mosint", "emailrep-profile", rep_email.lower(), platform.lower()),
                ),
            )
    return tuple(findings)


def _mosint_breachdirectory_findings(
    repository: str,
    target: ScanTarget,
    email: str,
    value: object,
    seen: set[tuple[str, ...]],
) -> tuple[Finding, ...]:
    if not isinstance(value, dict):
        return ()

    found = _safe_int(_first_scalar(value.get("found")) or "0") or 0
    success = _truthy(value.get("success"))
    findings: list[Finding] = []
    if success or found:
        metadata = _mosint_metadata(repository, target, email, "breach-summary", "breachdirectory")
        metadata["breach_count"] = str(found)
        _append_if(
            findings,
            _mosint_finding(
                repository=repository,
                target=target,
                status="candidate" if found > 0 else "not_found",
                confidence="high" if found > 0 else "medium",
                evidence=f"Mosint BreachDirectory: {found} result(s)",
                metadata=metadata,
                seen=seen,
                key=("mosint", "breachdirectory-summary", email.lower(), str(found)),
            ),
        )

    results = value.get("result")
    if not isinstance(results, list):
        return tuple(findings)

    for index, record in enumerate(results):
        if not isinstance(record, dict):
            continue
        sources = record.get("sources")
        if isinstance(sources, list):
            for source in sources:
                label = _first_scalar(source)
                if not label:
                    continue
                metadata = _mosint_metadata(repository, target, email, "breach-source", "breachdirectory")
                metadata["source_label"] = label
                _append_if(
                    findings,
                    _mosint_finding(
                        repository=repository,
                        target=target,
                        status="observed",
                        confidence="medium",
                        evidence=f"Mosint BreachDirectory source: {label}",
                        metadata=metadata,
                        seen=seen,
                        key=("mosint", "breachdirectory-source", email.lower(), label.lower()),
                    ),
                )
        if _truthy(record.get("has_password")) or record.get("password") or record.get("hash") or record.get("sha1"):
            metadata = _mosint_metadata(repository, target, email, "credential-exposure", "breachdirectory")
            metadata["sensitive_value_redacted"] = "true"
            metadata["credential_signal"] = "password_hash"
            _append_if(
                findings,
                _mosint_finding(
                    repository=repository,
                    target=target,
                    status="candidate",
                    confidence="high",
                    evidence="Mosint BreachDirectory credential exposure observed; sensitive value redacted",
                    metadata=metadata,
                    seen=seen,
                    key=("mosint", "breachdirectory-credential", email.lower(), str(index)),
                ),
            )
    return tuple(findings)


def _mosint_hibp_findings(
    repository: str,
    target: ScanTarget,
    email: str,
    value: object,
    seen: set[tuple[str, ...]],
) -> tuple[Finding, ...]:
    if not isinstance(value, list):
        return ()

    findings: list[Finding] = []
    for record in value:
        if not isinstance(record, dict):
            continue
        name = _first_scalar(record.get("Name"))
        title = _first_scalar(record.get("Title")) or name
        breach_domain = _first_scalar(record.get("Domain"))
        breach_date = _first_scalar(record.get("BreachDate"))
        if not any((name, title, breach_domain, breach_date)):
            continue
        metadata = _mosint_metadata(repository, target, email, "breach", "haveibeenpwned")
        if breach_domain:
            metadata["domain"] = breach_domain.lower()
        if name:
            metadata["breach_name"] = name
        if breach_date:
            metadata["breach_date"] = breach_date
        pwn_count = _first_scalar(record.get("PwnCount"))
        if pwn_count:
            metadata["pwn_count"] = pwn_count
        data_classes = _string_list(record.get("DataClasses"))
        if data_classes:
            metadata["data_classes"] = ", ".join(data_classes)
        for key in ("IsVerified", "IsFabricated", "IsSensitive", "IsRetired", "IsSpamList", "IsMalware"):
            result = _first_scalar(record.get(key))
            if result:
                metadata[f"extra_{_metadata_key(key)}"] = result
        _append_if(
            findings,
            _mosint_finding(
                repository=repository,
                target=target,
                status="candidate",
                confidence="high" if _truthy(record.get("IsVerified")) else "medium",
                evidence=_short(f"Mosint HIBP breach: {title or name or breach_domain} ({breach_date or 'date unknown'})"),
                metadata=metadata,
                seen=seen,
                key=("mosint", "hibp", email.lower(), (name or title or breach_domain).lower()),
            ),
        )
    return tuple(findings)


def _mosint_hunter_findings(
    repository: str,
    target: ScanTarget,
    email: str,
    value: object,
    seen: set[tuple[str, ...]],
) -> tuple[Finding, ...]:
    if not isinstance(value, dict):
        return ()

    data = value.get("data") if isinstance(value.get("data"), dict) else {}
    meta = value.get("meta") if isinstance(value.get("meta"), dict) else {}
    domain = _first_scalar(data.get("domain"))
    organization = _first_scalar(data.get("organization"))
    country = _first_scalar(data.get("country"))
    results = _first_scalar(meta.get("results"))

    findings: list[Finding] = []
    if any((domain, organization, country, results)):
        metadata = _mosint_metadata(repository, target, email, "domain-enrichment", "hunter")
        if domain:
            metadata["domain"] = domain.lower()
        if organization:
            metadata["extra_organization"] = organization
        if country:
            metadata["country"] = country
        if results:
            metadata["count"] = results
        _append_if(
            findings,
            _mosint_finding(
                repository=repository,
                target=target,
                status="observed",
                confidence="medium",
                evidence=_short(f"Mosint Hunter domain enrichment: {domain or email} ({results or 0} result(s))"),
                metadata=metadata,
                seen=seen,
                key=("mosint", "hunter-domain", email.lower(), domain.lower(), results),
            ),
        )

    emails = data.get("emails")
    if isinstance(emails, list):
        for record in emails:
            if not isinstance(record, dict):
                continue
            related = _first_scalar(record.get("value"))
            if not related or not EMAIL_RE.fullmatch(related):
                continue
            metadata = _mosint_metadata(repository, target, related, "related-email", "hunter")
            name = " ".join(part for part in (_first_scalar(record.get("first_name")), _first_scalar(record.get("last_name"))) if part)
            if name:
                metadata["name"] = name
            for source_key in ("type", "confidence", "position", "seniority", "department"):
                result = _first_scalar(record.get(source_key))
                if result:
                    metadata[f"extra_{source_key}"] = result
            verification = record.get("verification")
            if isinstance(verification, dict):
                status = _first_scalar(verification.get("status"))
                if status:
                    metadata["result_status"] = status
            _append_if(
                findings,
                _mosint_finding(
                    repository=repository,
                    target=target,
                    status="candidate",
                    confidence="high",
                    evidence=f"Mosint Hunter related email: {related}",
                    metadata=metadata,
                    seen=seen,
                    key=("mosint", "hunter-email", email.lower(), related.lower()),
                ),
            )

            sources = record.get("sources")
            if isinstance(sources, list):
                for source in sources:
                    if not isinstance(source, dict):
                        continue
                    uri = _first_scalar(source.get("uri"))
                    if uri and uri.startswith(("http://", "https://")):
                        findings.extend(_mosint_url_list_findings(repository, target, email, (uri,), "hunter-source", seen))

    linked_domains = data.get("linked_domains")
    if isinstance(linked_domains, list):
        for linked_domain in linked_domains:
            domain_value = _first_scalar(linked_domain).lower()
            if not domain_value:
                continue
            metadata = _mosint_metadata(repository, target, email, "linked-domain", "hunter")
            metadata["domain"] = domain_value
            _append_if(
                findings,
                _mosint_finding(
                    repository=repository,
                    target=target,
                    status="candidate",
                    confidence="medium",
                    evidence=f"Mosint Hunter linked domain: {domain_value}",
                    metadata=metadata,
                    seen=seen,
                    key=("mosint", "hunter-linked-domain", email.lower(), domain_value),
                ),
            )
    return tuple(findings)


def _mosint_url_list_findings(
    repository: str,
    target: ScanTarget,
    email: str,
    value: object,
    category: str,
    seen: set[tuple[str, ...]],
) -> tuple[Finding, ...]:
    items = value if isinstance(value, (list, tuple)) else ()
    findings: list[Finding] = []
    for item in items:
        raw_value = _first_scalar(item)
        if not raw_value:
            continue
        urls = URL_RE.findall(raw_value)
        if not urls and raw_value.startswith(("http://", "https://")):
            urls = [raw_value]
        for raw_url in urls:
            url = raw_url.rstrip(".,;")
            metadata = _mosint_metadata(repository, target, email, category, category)
            domain = (urlparse(url).hostname or "").lower()
            if domain:
                metadata["domain"] = domain
            _append_if(
                findings,
                _mosint_finding(
                    repository=repository,
                    target=target,
                    status="candidate",
                    confidence="medium",
                    evidence=f"Mosint {category} URL: {url}",
                    metadata=metadata,
                    seen=seen,
                    key=("mosint", category, email.lower(), url.lower()),
                    url=url,
                ),
            )
    return tuple(findings)


def _mosint_social_findings(
    repository: str,
    target: ScanTarget,
    email: str,
    payload: dict[str, Any],
    seen: set[tuple[str, ...]],
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for key, platform in (
        ("instagram_exists", "Instagram"),
        ("spotify_exists", "Spotify"),
        ("twitter_exists", "Twitter"),
    ):
        if not _truthy(payload.get(key)):
            continue
        metadata = _mosint_metadata(repository, target, email, "social-account", platform)
        metadata["result_status"] = "exists"
        _append_if(
            findings,
            _mosint_finding(
                repository=repository,
                target=target,
                status="candidate",
                confidence="medium",
                evidence=f"Mosint social account signal: {platform}",
                metadata=metadata,
                seen=seen,
                key=("mosint", "social", email.lower(), platform.lower()),
            ),
        )
    return tuple(findings)


def _mosint_dns_findings(
    repository: str,
    target: ScanTarget,
    email: str,
    value: object,
    seen: set[tuple[str, ...]],
) -> tuple[Finding, ...]:
    if not isinstance(value, list):
        return ()
    findings: list[Finding] = []
    for record in value:
        if not isinstance(record, dict):
            continue
        record_type = _first_scalar(record.get("Type") or record.get("type"))
        record_value = _first_scalar(record.get("Value") or record.get("value"))
        if not record_type and not record_value:
            continue
        metadata = _mosint_metadata(repository, target, email, "dns-record", "dns")
        if record_type:
            metadata["record_type"] = record_type
        if record_value:
            metadata["record_value"] = record_value
        _append_if(
            findings,
            _mosint_finding(
                repository=repository,
                target=target,
                status="observed",
                confidence="medium",
                evidence=_short(f"Mosint DNS {record_type or 'record'}: {record_value}"),
                metadata=metadata,
                seen=seen,
                key=("mosint", "dns", email.lower(), record_type.lower(), record_value.lower()),
            ),
        )
    return tuple(findings)


def _mosint_ipapi_finding(
    repository: str,
    target: ScanTarget,
    email: str,
    value: object,
    seen: set[tuple[str, ...]],
) -> Finding | None:
    if not isinstance(value, dict):
        return None
    ip = _first_scalar(value.get("ip"))
    country = _first_scalar(value.get("country_name") or value.get("country"))
    city = _first_scalar(value.get("city"))
    org = _first_scalar(value.get("org"))
    asn = _first_scalar(value.get("asn"))
    if not any((ip, country, city, org, asn)):
        return None
    metadata = _mosint_metadata(repository, target, email, "domain-ip-intel", "ipapi")
    if country:
        metadata["country"] = country
    if city:
        metadata["location"] = city
    if ip:
        metadata["extra_ip"] = ip
    if org:
        metadata["extra_org"] = org
    if asn:
        metadata["extra_asn"] = asn
    return _mosint_finding(
        repository=repository,
        target=target,
        status="observed",
        confidence="medium",
        evidence=_short(f"Mosint ipapi: {country or 'unknown country'} {city or ''}".strip()),
        metadata=metadata,
        seen=seen,
        key=("mosint", "ipapi", email.lower(), ip, country, city, asn),
    )


def _mosint_metadata(
    repository: str,
    target: ScanTarget,
    email: str,
    category: str,
    source_label: str,
) -> dict[str, str]:
    metadata = {
        "repository": repository,
        "parser": "mosint",
        "target_kind": target.kind,
        "category": category,
    }
    if source_label:
        metadata["source_label"] = source_label
    if EMAIL_RE.fullmatch(email):
        metadata["email"] = email
        metadata["domain"] = email.rsplit("@", 1)[1].lower()
    return metadata


def _mosint_finding(
    *,
    repository: str,
    target: ScanTarget,
    status: str,
    confidence: str,
    evidence: str,
    metadata: dict[str, str],
    seen: set[tuple[str, ...]],
    key: tuple[str, ...],
    url: str = "",
) -> Finding | None:
    if key in seen:
        return None
    seen.add(key)
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status=status,
        url=url,
        confidence=confidence,
        evidence=_short(evidence),
        metadata=metadata,
    )


def _h8mail_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    structured = _h8mail_json_findings(repository, target, text)
    if structured:
        return structured

    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for line in text.splitlines():
        compact = " ".join(line.split())
        if not compact:
            continue
        findings.extend(_url_findings(repository, target, compact, seen))
        findings.extend(_email_findings(repository, target, compact, seen))
        findings.extend(_phone_findings(repository, target, compact, seen))
        key_value = _key_value_finding(repository, target, compact, seen)
        if key_value:
            findings.append(key_value)
    return tuple(findings)


def _h8mail_json_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    payload = _load_json_payload(text)
    if payload is None:
        return ()

    records = _h8mail_records(payload)
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for record in records:
        target_value = _first_scalar(record.get("target")) or target.value
        pwn_num = _first_scalar(record.get("pwn_num"))
        summary = _h8mail_summary_finding(repository, target, target_value, pwn_num, seen)
        if summary:
            findings.append(summary)

        for group in _h8mail_data_groups(record.get("data")):
            source_label = _h8mail_source_label(group)
            for result_type, value in group:
                finding = _h8mail_entry_finding(
                    repository=repository,
                    target=target,
                    h8mail_target=target_value,
                    result_type=result_type,
                    value=value,
                    source_label=source_label,
                    seen=seen,
                )
                if finding:
                    findings.append(finding)
    return tuple(findings)


def _h8mail_records(payload: object) -> tuple[dict[str, Any], ...]:
    if isinstance(payload, dict) and isinstance(payload.get("targets"), list):
        return tuple(record for record in payload["targets"] if isinstance(record, dict))
    if isinstance(payload, list):
        return tuple(record for record in payload if isinstance(record, dict))
    if isinstance(payload, dict) and "target" in payload:
        return (payload,)
    return ()


def _h8mail_data_groups(value: object) -> tuple[tuple[tuple[str, str], ...], ...]:
    groups: list[tuple[tuple[str, str], ...]] = []
    if not isinstance(value, list):
        return ()

    for raw_group in value:
        raw_items = raw_group if isinstance(raw_group, list) else [raw_group]
        parsed: list[tuple[str, str]] = []
        for item in raw_items:
            entry = _h8mail_entry(item)
            if entry:
                parsed.append(entry)
        if parsed:
            groups.append(tuple(parsed))
    return tuple(groups)


def _h8mail_entry(item: object) -> tuple[str, str] | None:
    if isinstance(item, dict):
        result_type = _first_scalar(item.get("type") or item.get("key") or item.get("name"))
        value = _first_scalar(item.get("data") or item.get("value") or item.get("result"))
        if result_type and value:
            return result_type.strip(), value.strip()
        return None
    if isinstance(item, (list, tuple)) and len(item) >= 2:
        result_type = _first_scalar(item[0])
        value = _first_scalar(item[1])
        if result_type and value:
            return result_type.strip(), value.strip()
        return None
    if isinstance(item, str) and ":" in item:
        result_type, value = item.split(":", 1)
        result_type = result_type.strip()
        value = value.strip()
        if result_type and value:
            return result_type, value
    return None


def _h8mail_summary_finding(
    repository: str,
    target: ScanTarget,
    h8mail_target: str,
    pwn_num: str,
    seen: set[tuple[str, str, str]],
) -> Finding | None:
    if not pwn_num:
        return None
    key = ("h8mail-summary", h8mail_target.lower(), pwn_num)
    if key in seen:
        return None
    seen.add(key)

    count = _safe_int(pwn_num)
    status = "candidate" if count and count > 0 else "not_found"
    confidence = "medium" if status == "candidate" else "low"
    metadata = {
        "repository": repository,
        "parser": "h8mail",
        "target_kind": target.kind,
        "h8mail_target": h8mail_target,
        "breach_count": pwn_num,
        "category": "breach-summary",
    }
    if EMAIL_RE.fullmatch(h8mail_target):
        metadata["email"] = h8mail_target
        metadata["domain"] = h8mail_target.rsplit("@", 1)[1].lower()
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status=status,
        confidence=confidence,
        evidence=f"h8mail {h8mail_target}: {pwn_num} breach-related result(s)",
        metadata=metadata,
    )


def _h8mail_entry_finding(
    *,
    repository: str,
    target: ScanTarget,
    h8mail_target: str,
    result_type: str,
    value: str,
    source_label: str,
    seen: set[tuple[str, str, str]],
) -> Finding | None:
    if value.upper() == "N/A":
        return None

    normalized_type = result_type.upper()
    sensitive = _h8mail_sensitive_type(normalized_type)
    category = _h8mail_category(normalized_type, value, sensitive)
    key = ("h8mail-entry", h8mail_target.lower(), normalized_type, "" if sensitive else value.lower())
    if key in seen:
        return None
    seen.add(key)

    metadata = _h8mail_metadata(
        repository=repository,
        target=target,
        h8mail_target=h8mail_target,
        result_type=result_type,
        value=value,
        source_label=source_label,
        category=category,
        sensitive=sensitive,
    )
    url = value if category == "url" and value.startswith(("http://", "https://")) else ""
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status="candidate" if category not in {"service-info", "breach-source"} else "observed",
        url=url,
        confidence="high" if sensitive or category in {"related-email", "username", "url"} else "medium",
        evidence=_short(_h8mail_evidence(h8mail_target, result_type, value, category, sensitive, source_label)),
        metadata=metadata,
    )


def _h8mail_metadata(
    *,
    repository: str,
    target: ScanTarget,
    h8mail_target: str,
    result_type: str,
    value: str,
    source_label: str,
    category: str,
    sensitive: bool,
) -> dict[str, str]:
    metadata = {
        "repository": repository,
        "parser": "h8mail",
        "target_kind": target.kind,
        "h8mail_target": h8mail_target,
        "result_type": result_type,
        "category": category,
    }
    if source_label:
        metadata["source_label"] = source_label
    if EMAIL_RE.fullmatch(h8mail_target):
        metadata["email"] = h8mail_target
        metadata["domain"] = h8mail_target.rsplit("@", 1)[1].lower()

    if sensitive:
        metadata["sensitive_value_redacted"] = "true"
        metadata["credential_signal"] = _metadata_key(result_type)
        return metadata

    if category == "related-email" and EMAIL_RE.fullmatch(value):
        metadata["email"] = value
        metadata["domain"] = value.rsplit("@", 1)[1].lower()
    elif category == "username":
        metadata["username"] = value
    elif category == "url":
        domain = (urlparse(value).hostname or "").lower()
        if domain:
            metadata["domain"] = domain
    elif category == "name":
        metadata["name"] = value
    elif category == "phone":
        metadata["phone"] = value
    elif category == "breach-source":
        metadata["source_label"] = value
    elif category == "count":
        metadata["count"] = value
    else:
        metadata[f"extra_{_metadata_key(result_type)}"] = value
    return metadata


def _h8mail_source_label(group: tuple[tuple[str, str], ...]) -> str:
    for result_type, value in group:
        normalized_type = result_type.upper()
        if "SOURCE" in normalized_type or normalized_type.endswith("_SRC") or normalized_type.endswith("_EXTSRC"):
            return value.strip()
    return ""


def _h8mail_sensitive_type(normalized_type: str) -> bool:
    tokens = {token for token in re.split(r"[^A-Z0-9]+", normalized_type) if token}
    sensitive_tokens = {"PASSWORD", "PASS", "PWD", "HASH", "HASHSALT", "MD5", "SHA1", "SALT", "TOKEN", "SECRET", "KEY"}
    return bool(tokens & sensitive_tokens)


def _h8mail_category(normalized_type: str, value: str, sensitive: bool) -> str:
    if sensitive:
        return "credential-exposure"
    if value.startswith(("http://", "https://")):
        return "url"
    if "SOURCE" in normalized_type or normalized_type.endswith("_SRC") or normalized_type.endswith("_EXTSRC"):
        return "breach-source"
    if "RELATED" in normalized_type or normalized_type.endswith("_EMAIL") or normalized_type == "EMAIL":
        return "related-email" if EMAIL_RE.fullmatch(value) else "service-info"
    if "USERNAME" in normalized_type:
        return "username"
    if "NAME" in normalized_type:
        return "name"
    if "PHONE" in normalized_type or "MOBILE" in normalized_type:
        return "phone"
    if normalized_type.endswith("_TOTAL") or normalized_type.endswith("_PUB") or normalized_type in {"HIBP3"}:
        return "count" if _safe_int(value) is not None else "service-info"
    return "service-info"


def _h8mail_evidence(
    h8mail_target: str,
    result_type: str,
    value: str,
    category: str,
    sensitive: bool,
    source_label: str,
) -> str:
    source = f" from {source_label}" if source_label and source_label.upper() != "N/A" else ""
    if sensitive:
        return f"h8mail {h8mail_target}: {result_type}{source} observed; sensitive value redacted"
    if category == "related-email":
        return f"h8mail {h8mail_target}: related email {value}{source}"
    if category == "breach-source":
        return f"h8mail {h8mail_target}: breach source {value}"
    return f"h8mail {h8mail_target}: {result_type}={value}{source}"


def _safe_int(value: str) -> int | None:
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def _truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1", "y"}
    return False


def _append_if(findings: list[Finding], finding: Finding | None) -> None:
    if finding:
        findings.append(finding)


def _maigret_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    structured = _maigret_json_findings(repository, target, text)
    if structured:
        return structured

    csv_findings = _maigret_csv_findings(repository, target, text)
    if csv_findings:
        return csv_findings

    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for line in text.splitlines():
        compact = " ".join(line.split())
        if not compact:
            continue
        findings.extend(_url_findings(repository, target, compact, seen))
        findings.extend(_email_findings(repository, target, compact, seen))
        findings.extend(_phone_findings(repository, target, compact, seen))
    return tuple(findings)


def _maigret_json_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        records.extend(_maigret_records(payload))

    if not records:
        payload = _load_json_payload(text)
        if payload is not None:
            records.extend(_maigret_records(payload))

    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for record in records:
        finding = _maigret_record_finding(repository, target, record, seen)
        if finding:
            findings.append(finding)
    return tuple(findings)


def _maigret_records(payload: object) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [record for record in payload if isinstance(record, dict)]
    if not isinstance(payload, dict):
        return []

    if "status" in payload or "sitename" in payload:
        return [payload]

    records: list[dict[str, Any]] = []
    for site_name, record in payload.items():
        if not isinstance(record, dict):
            continue
        copied = dict(record)
        copied.setdefault("sitename", str(site_name))
        records.append(copied)
    return records


def _maigret_csv_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    rows = _maigret_csv_rows(text)
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        site_name = _csv_row_value(row, "name")
        if not site_name:
            continue
        record = {
            "sitename": site_name,
            "url_main": _csv_row_value(row, "url_main"),
            "url_user": _csv_row_value(row, "url_user"),
            "http_status": _csv_row_value(row, "http_status"),
            "status": {
                "username": _csv_row_value(row, "username") or target.value,
                "site_name": site_name,
                "url": _csv_row_value(row, "url_user"),
                "status": _csv_row_value(row, "exists"),
                "ids": {},
                "tags": [],
            },
        }
        finding = _maigret_record_finding(repository, target, record, seen)
        if finding:
            findings.append(finding)
    return tuple(findings)


def _maigret_csv_rows(text: str) -> tuple[dict[str, str], ...]:
    lines = [line for line in text.strip("\ufeff \n\t").splitlines() if line.strip()]
    header_index = -1
    for index, line in enumerate(lines):
        normalized = line.strip("\ufeff ").lower()
        if normalized.startswith(("username,name,url_main,url_user,exists,http_status",)):
            header_index = index
            break
    if header_index == -1:
        return ()

    reader = csv.DictReader(io.StringIO("\n".join(lines[header_index:])))
    rows: list[dict[str, str]] = []
    for row in reader:
        if row and any(value for value in row.values() if value):
            rows.append({(key or "").strip("\ufeff "): (value or "").strip() for key, value in row.items()})
    return tuple(rows)


def _maigret_record_finding(
    repository: str,
    target: ScanTarget,
    record: dict[str, Any],
    seen: set[tuple[str, str, str]],
) -> Finding | None:
    status_obj = record.get("status")
    status_data = status_obj if isinstance(status_obj, dict) else {}
    raw_status = str(status_data.get("status") or status_obj or record.get("exists") or "").strip()
    site_name = str(
        status_data.get("site_name")
        or record.get("sitename")
        or record.get("name")
        or record.get("site_name")
        or ""
    ).strip()
    url = str(status_data.get("url") or record.get("url_user") or record.get("url") or "").strip()
    site_url = str(record.get("url_main") or "").strip()
    identity = str(status_data.get("username") or record.get("username") or target.value).strip()
    http_status = str(record.get("http_status") or "").strip()
    ids = status_data.get("ids") or record.get("ids_data") or record.get("ids") or {}
    tags = status_data.get("tags") or record.get("tags") or []

    if not raw_status and not site_name and not url:
        return None

    status, confidence = _maigret_status(raw_status)
    finding_url = url if status == "candidate" and url.startswith(("http://", "https://")) else ""
    key = ("maigret", site_name.lower(), identity.lower(), raw_status.lower(), url.lower())
    if key in seen:
        return None
    seen.add(key)

    metadata = _maigret_metadata(
        repository=repository,
        target=target,
        site_name=site_name,
        raw_status=raw_status,
        identity=identity,
        url=finding_url,
        checked_url="" if finding_url else url,
        site_url=site_url,
        http_status=http_status,
        ids=ids,
        tags=tags,
    )
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status=status,
        url=finding_url,
        confidence=confidence,
        evidence=_short(_maigret_evidence(site_name, raw_status, tags)),
        metadata=metadata,
    )


def _maigret_status(raw_status: str) -> tuple[str, str]:
    normalized = " ".join(raw_status.lower().split())
    if normalized == "claimed":
        return "candidate", "high"
    if normalized == "available":
        return "not_found", "medium"
    if normalized == "unknown":
        return "error", "low"
    if normalized == "illegal":
        return "skipped", "high"
    return "observed", "medium"


def _maigret_metadata(
    *,
    repository: str,
    target: ScanTarget,
    site_name: str,
    raw_status: str,
    identity: str,
    url: str,
    checked_url: str,
    site_url: str,
    http_status: str,
    ids: object,
    tags: object,
) -> dict[str, str]:
    metadata = {
        "repository": repository,
        "parser": "maigret",
        "target_kind": target.kind,
        "result_status": raw_status,
    }
    if site_name:
        metadata["site_name"] = site_name
    if identity:
        metadata["username"] = identity
    if url:
        domain = (urlparse(url).hostname or "").lower()
        if domain:
            metadata["domain"] = domain
    if checked_url:
        metadata["checked_url"] = checked_url
    if site_url:
        metadata["site_url"] = site_url
    if http_status:
        metadata["http_status"] = http_status

    tag_values = _string_list(tags)
    if tag_values:
        metadata["tags"] = ", ".join(tag_values)
        region = _region_from_tags(tag_values) or (target.region.upper() if target.region in {"ru", "ua"} else "")
        if region:
            metadata["region"] = region

    if isinstance(ids, dict):
        _merge_maigret_ids(metadata, ids)
    return metadata


def _merge_maigret_ids(metadata: dict[str, str], ids: dict[Any, Any]) -> None:
    mapped_keys = {
        "fullname": "name",
        "full_name": "name",
        "name": "name",
        "location": "location",
        "country": "country",
        "email": "email",
        "phone": "phone",
        "username": "username",
    }
    for raw_key, raw_value in ids.items():
        key = _metadata_key(str(raw_key))
        value = _first_scalar(raw_value)
        if not value:
            continue
        mapped = mapped_keys.get(key)
        if mapped and mapped not in metadata:
            metadata[mapped] = value
        elif mapped:
            continue
        else:
            metadata[f"extra_{key}"] = value


def _maigret_evidence(site_name: str, raw_status: str, tags: object) -> str:
    evidence = f"Maigret {site_name or 'site'}: {raw_status or 'observed'}"
    tag_values = _string_list(tags)
    if tag_values:
        evidence += f" ({', '.join(tag_values[:5])})"
    return evidence


def _snoop_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    findings, _ = _snoop_csv_findings(repository, target, text)
    if findings:
        return findings

    parsed: list[Finding] = []
    line_seen: set[tuple[str, str, str]] = set()
    for line in text.splitlines():
        compact = " ".join(line.split())
        if not compact:
            continue
        finding = _snoop_line_finding(repository, target, compact, line_seen)
        if finding:
            parsed.append(finding)
            continue
        parsed.extend(_url_findings(repository, target, compact, line_seen))
        parsed.extend(_email_findings(repository, target, compact, line_seen))
        parsed.extend(_phone_findings(repository, target, compact, line_seen))
    return tuple(parsed)


def _snoop_csv_findings(
    repository: str,
    target: ScanTarget,
    text: str,
) -> tuple[tuple[Finding, ...], set[tuple[str, str, str]]]:
    rows = _snoop_csv_rows(text)
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        site_name = _snoop_row_value(row, "resource", "ресурс")
        if not site_name or site_name.startswith(("«", "-", "БД_", "Дата")):
            continue
        status_text = _snoop_row_value(row, "status", "статус")
        profile_url = _snoop_row_value(row, "url_username", "ссылка_на_профиль")
        site_url = _snoop_row_value(row, "url")
        region = _snoop_row_value(row, "geo", "гео")
        http_status = _snoop_row_value(row, "http_code", "статус_http")

        finding = _snoop_record_finding(
            repository=repository,
            target=target,
            site_name=site_name,
            status_text=status_text,
            profile_url=profile_url,
            site_url=site_url,
            region=region,
            http_status=http_status,
            evidence="",
            seen=seen,
        )
        if finding:
            findings.append(finding)
    return tuple(findings), seen


def _snoop_csv_rows(text: str) -> tuple[dict[str, str], ...]:
    lines = [line for line in text.strip("\ufeff \n\t").splitlines() if line.strip()]
    header_index = -1
    for index, line in enumerate(lines):
        normalized = line.strip("\ufeff ").lower()
        if normalized.startswith(("resource,", "resource;", "ресурс,", "ресурс;")):
            header_index = index
            break
    if header_index == -1:
        return ()

    csv_text = "\n".join(lines[header_index:])
    header = lines[header_index]
    delimiter = ";" if header.count(";") > header.count(",") else ","
    reader = csv.DictReader(io.StringIO(csv_text), delimiter=delimiter)
    rows: list[dict[str, str]] = []
    for row in reader:
        if not row:
            continue
        normalized_row = {
            (key or "").strip("\ufeff "): (value or "").strip()
            for key, value in row.items()
            if key is not None
        }
        if any(normalized_row.values()):
            rows.append(normalized_row)
    return tuple(rows)


def _snoop_row_value(row: dict[str, str], *names: str) -> str:
    wanted = {name.lower() for name in names}
    for key, value in row.items():
        if key.strip("\ufeff ").lower() in wanted:
            return value.strip()
    return ""


def _snoop_line_finding(
    repository: str,
    target: ScanTarget,
    line: str,
    seen: set[tuple[str, str, str]],
) -> Finding | None:
    match = SNOOP_LINE_RE.match(line)
    if not match:
        return None

    site_name = _snoop_site_name(match.group("site"))
    rest = match.group("rest").strip()
    raw_url_match = URL_RE.search(rest)
    profile_url = raw_url_match.group(0).rstrip(".,;") if raw_url_match else ""
    status_text = "найден!" if profile_url else rest
    status, _ = _snoop_status(status_text)
    if status == "observed" and not profile_url:
        return None

    return _snoop_record_finding(
        repository=repository,
        target=target,
        site_name=site_name,
        status_text=status_text,
        profile_url=profile_url,
        site_url="",
        region="",
        http_status="",
        evidence=line,
        seen=seen,
    )


def _snoop_record_finding(
    *,
    repository: str,
    target: ScanTarget,
    site_name: str,
    status_text: str,
    profile_url: str,
    site_url: str,
    region: str,
    http_status: str,
    evidence: str,
    seen: set[tuple[str, str, str]],
) -> Finding | None:
    status, confidence = _snoop_status(status_text)
    if status == "observed" and not profile_url:
        return None

    finding_url = profile_url if status == "candidate" and profile_url.startswith(("http://", "https://")) else ""
    checked_url = "" if finding_url else profile_url
    key = ("snoop", site_name.lower(), status.lower(), (profile_url or site_url).lower())
    if key in seen:
        return None
    seen.add(key)

    metadata = _snoop_metadata(
        repository=repository,
        target=target,
        site_name=site_name,
        status_text=status_text,
        profile_url=finding_url,
        checked_url=checked_url,
        site_url=site_url,
        region=region,
        http_status=http_status,
    )
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status=status,
        url=finding_url,
        confidence=confidence,
        evidence=_short(evidence or _snoop_evidence(site_name, status_text, region, http_status)),
        metadata=metadata,
    )


def _snoop_status(raw_status: str) -> tuple[str, str]:
    normalized = " ".join(raw_status.lower().strip("!. ").split())
    if normalized in {"найден", "found", "exists", "true"} or "найден" in normalized:
        return "candidate", "high"
    if normalized in {"увы", "not found", "not_found", "not-found", "false", "no"} or "увы" in normalized:
        return "not_found", "medium"
    if "invalid" in normalized or "недопуст" in normalized:
        return "skipped", "high"
    if normalized in {"блок", "block", "blocked", "timeout", "сбой", "завис", "err", "error"}:
        return "error", "low"
    if any(marker in normalized for marker in ("блок", "timeout", "ошиб", "error", "err")):
        return "error", "low"
    return "observed", "medium"


def _snoop_metadata(
    *,
    repository: str,
    target: ScanTarget,
    site_name: str,
    status_text: str,
    profile_url: str,
    checked_url: str,
    site_url: str,
    region: str,
    http_status: str,
) -> dict[str, str]:
    metadata = {
        "repository": repository,
        "parser": "snoop",
        "target_kind": target.kind,
        "result_status": status_text,
    }
    if site_name:
        metadata["site_name"] = site_name
    if region:
        metadata["region"] = region.upper()
    if profile_url:
        domain = (urlparse(profile_url).hostname or "").lower()
        if domain:
            metadata["domain"] = domain
    if checked_url:
        metadata["checked_url"] = checked_url
    if site_url:
        metadata["site_url"] = site_url
    if http_status:
        metadata["http_status"] = http_status
    return metadata


def _snoop_site_name(value: str) -> str:
    cleaned = re.sub(r"^[^\wА-Яа-я]+", "", value.strip())
    return " ".join(cleaned.split()).strip(" :-")


def _snoop_evidence(site_name: str, status_text: str, region: str, http_status: str) -> str:
    evidence = f"Snoop {site_name or 'site'}: {status_text or 'observed'}"
    details = [detail for detail in (region.upper(), f"HTTP {http_status}" if http_status else "") if detail]
    if details:
        evidence += f" ({', '.join(details)})"
    return evidence


def _user_scanner_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    structured = _user_scanner_json_findings(repository, target, text)
    if structured:
        return structured

    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for line in text.splitlines():
        compact = " ".join(line.split())
        if not compact:
            continue
        parsed = _user_scanner_line_finding(repository, target, compact, seen)
        if parsed:
            findings.append(parsed)
            continue
        findings.extend(_url_findings(repository, target, compact, seen))
        findings.extend(_email_findings(repository, target, compact, seen))
        findings.extend(_phone_findings(repository, target, compact, seen))
    return tuple(findings)


def _user_scanner_json_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    payload = _load_json_payload(text)
    if payload is None:
        return ()

    records = payload if isinstance(payload, list) else [payload]
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        finding = _user_scanner_record_finding(repository, target, record, seen)
        if finding:
            findings.append(finding)
    return tuple(findings)


def _user_scanner_record_finding(
    repository: str,
    target: ScanTarget,
    record: dict[str, Any],
    seen: set[tuple[str, str, str]],
) -> Finding | None:
    raw_status = str(record.get("status", "")).strip()
    site_name = str(record.get("site_name", "")).strip()
    category = str(record.get("category", "")).strip()
    url = str(record.get("url", "")).strip()
    reason = str(record.get("reason", "")).strip()
    identity = str(record.get("email") or record.get("username") or target.value).strip()

    if not raw_status and not site_name and not url:
        return None

    status, confidence = _user_scanner_status(raw_status)
    finding_url = url if status == "candidate" and url.startswith(("http://", "https://")) else ""
    metadata = _user_scanner_metadata(
        repository=repository,
        target=target,
        site_name=site_name,
        category=category,
        raw_status=raw_status,
        identity=identity,
        reason=reason,
        url=finding_url,
        checked_url="" if finding_url else url,
        extra=record.get("extra"),
    )
    key = ("user-scanner", site_name.lower(), identity.lower(), raw_status.lower(), url.lower())
    if key in seen:
        return None
    seen.add(key)

    evidence = _user_scanner_evidence(site_name, raw_status, reason)
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status=status,
        url=finding_url,
        confidence=confidence,
        evidence=evidence,
        metadata=metadata,
    )


def _user_scanner_line_finding(
    repository: str,
    target: ScanTarget,
    line: str,
    seen: set[tuple[str, str, str]],
) -> Finding | None:
    match = USER_SCANNER_LINE_RE.match(line)
    if not match:
        return None

    site_name = " ".join(match.group("site").split())
    url = (match.group("url") or "").strip()
    identity = (match.group("value") or target.value).strip()
    raw_status = (match.group("status") or "").strip()
    reason = (match.group("reason") or "").strip()
    status, confidence = _user_scanner_status(raw_status)
    key = ("user-scanner", site_name.lower(), identity.lower(), raw_status.lower(), url.lower())
    if key in seen:
        return None
    seen.add(key)

    finding_url = url if status == "candidate" and url.startswith(("http://", "https://")) else ""
    metadata = _user_scanner_metadata(
        repository=repository,
        target=target,
        site_name=site_name,
        category="",
        raw_status=raw_status,
        identity=identity,
        reason=reason,
        url=finding_url,
        checked_url="" if finding_url else url,
        extra=None,
    )
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status=status,
        url=finding_url,
        confidence=confidence,
        evidence=_short(line),
        metadata=metadata,
    )


def _url_findings(
    repository: str,
    target: ScanTarget,
    line: str,
    seen: set[tuple[str, str, str]],
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    label = _line_label(line)
    for raw_url in URL_RE.findall(line):
        url = raw_url.rstrip(".,;")
        key = ("url", url.lower(), label.lower())
        if key in seen:
            continue
        seen.add(key)
        parsed = urlparse(url)
        metadata = {
            "repository": repository,
            "parser": "url",
            "domain": (parsed.hostname or "").lower(),
        }
        if label:
            metadata["source_label"] = label
        findings.append(
            Finding(
                module="external-adapter-parser",
                source=repository,
                target=target.value,
                status="candidate",
                url=url,
                confidence="medium",
                evidence=_short(line),
                metadata=metadata,
            )
        )
    return tuple(findings)


def _email_findings(
    repository: str,
    target: ScanTarget,
    line: str,
    seen: set[tuple[str, str, str]],
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for email in EMAIL_RE.findall(line):
        key = ("email", email.lower(), "")
        if key in seen:
            continue
        seen.add(key)
        domain = email.rsplit("@", 1)[1].lower()
        findings.append(
            Finding(
                module="external-adapter-parser",
                source=repository,
                target=target.value,
                status="candidate",
                confidence="medium",
                evidence=_short(line),
                metadata={"repository": repository, "parser": "email", "domain": domain},
            )
        )
    return tuple(findings)


def _phone_findings(
    repository: str,
    target: ScanTarget,
    line: str,
    seen: set[tuple[str, str, str]],
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for phone in PHONE_RE.findall(line):
        key = ("phone", phone, "")
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                module="external-adapter-parser",
                source=repository,
                target=target.value,
                status="candidate",
                confidence="medium",
                evidence=_short(line),
                metadata={"repository": repository, "parser": "phone", "normalized": phone},
            )
        )
    return tuple(findings)


def _key_value_finding(
    repository: str,
    target: ScanTarget,
    line: str,
    seen: set[tuple[str, str, str]],
) -> Finding | None:
    match = KEY_VALUE_RE.match(_strip_prefix(line))
    if not match:
        return None

    key = " ".join(match.group("key").lower().replace("_", " ").split())
    value = match.group("value").strip()
    if not value or value.lower() in {"none", "not found", "unknown", "n/a"}:
        return None

    metadata_key = PHONE_KEYS.get(key) or EMAIL_KEYS.get(key)
    if not metadata_key:
        return None

    seen_key = ("kv", metadata_key, value.lower())
    if seen_key in seen:
        return None
    seen.add(seen_key)

    metadata = {"repository": repository, "parser": "key-value", metadata_key: value}
    if metadata_key == "domain":
        status = "candidate"
    elif metadata_key in {"normalized", "country", "carrier", "location", "line_type"}:
        status = "candidate"
    else:
        status = "observed"

    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status=status,
        confidence="medium",
        evidence=_short(line),
        metadata=metadata,
    )


def _load_json_payload(text: str) -> object | None:
    stripped = text.strip("\ufeff \n\t")
    if not stripped:
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    start_candidates = [index for index in (stripped.find("["), stripped.find("{")) if index != -1]
    if not start_candidates:
        return None
    start = min(start_candidates)
    end = max(stripped.rfind("]"), stripped.rfind("}"))
    if end <= start:
        return None
    try:
        return json.loads(stripped[start : end + 1])
    except json.JSONDecodeError:
        return None


def _user_scanner_status(raw_status: str) -> tuple[str, str]:
    normalized = " ".join(raw_status.lower().split())
    if normalized in {"registered", "found"}:
        return "candidate", "high"
    if normalized in {"available", "not found", "not registered"}:
        return "not_found", "medium"
    if normalized == "error":
        return "error", "low"
    return "observed", "medium"


def _user_scanner_metadata(
    *,
    repository: str,
    target: ScanTarget,
    site_name: str,
    category: str,
    raw_status: str,
    identity: str,
    reason: str,
    url: str,
    checked_url: str,
    extra: object,
) -> dict[str, str]:
    metadata = {
        "repository": repository,
        "parser": "user-scanner",
        "target_kind": target.kind,
        "result_status": raw_status,
    }
    if site_name:
        metadata["site_name"] = site_name
    if category:
        metadata["category"] = category
    if reason:
        metadata["reason"] = reason
    if checked_url:
        metadata["checked_url"] = checked_url
    if url:
        domain = (urlparse(url).hostname or "").lower()
        if domain:
            metadata["domain"] = domain
    if "@" in identity and EMAIL_RE.fullmatch(identity):
        metadata["email"] = identity
    elif identity:
        metadata["username"] = identity

    if isinstance(extra, dict):
        for key, value in extra.items():
            if isinstance(value, (str, int, float, bool)) and value not in {"", None}:
                metadata[f"extra_{_metadata_key(str(key))}"] = str(value)
    elif isinstance(extra, str) and extra.strip():
        metadata["extra"] = extra.strip()
    return metadata


def _metadata_key(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", value.strip().lower()).strip("_")
    return normalized or "value"


def _csv_row_value(row: dict[str, str], name: str) -> str:
    for key, value in row.items():
        if key.strip("\ufeff ").lower() == name.lower():
            return value.strip()
    return ""


def _string_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _first_scalar(value: object) -> str:
    if isinstance(value, (list, tuple)):
        for item in value:
            scalar = _first_scalar(item)
            if scalar:
                return scalar
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value).strip()
    return ""


def _region_from_tags(tags: list[str]) -> str:
    for tag in tags:
        normalized = tag.lower()
        if normalized in {"ru", "ua"}:
            return normalized.upper()
    return ""


def _user_scanner_evidence(site_name: str, raw_status: str, reason: str) -> str:
    label = site_name or "User Scanner"
    evidence = f"User Scanner {label}: {raw_status or 'observed'}"
    if reason:
        evidence += f" ({reason})"
    return _short(evidence)


def _clean_output(value: str) -> str:
    return ANSI_RE.sub("", value.replace("\r\n", "\n").replace("\r", "\n"))


def _line_label(line: str) -> str:
    match = SOCIAL_LINE_RE.match(_strip_prefix(line))
    if not match:
        return ""
    rest = match.group("rest")
    if not URL_RE.search(rest):
        return ""
    return " ".join(match.group("label").split()).strip(" :-")


def _strip_prefix(line: str) -> str:
    return re.sub(r"^\s*(?:\[[+*!-]\]|\+|-|\*)\s*", "", line).strip()


def _short(value: str, limit: int = 300) -> str:
    compact = " ".join(value.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1] + "..."
