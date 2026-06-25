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
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
HOSTNAME_RE = re.compile(r"\b(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}\b", re.IGNORECASE)
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
DETECTDEE_RESULT_RE = re.compile(
    r"^\s*(?P<identity>[^,\n]+?)\s*,\s*(?P<site>[^,\n]+?)\s*,\s*(?P<url>https?://\S+)\s*$",
    re.IGNORECASE,
)
DETECTDEE_STDOUT_RE = re.compile(
    r"\[\+\]\s*(?P<identity>\S+)\s+(?P<site>[^:]{2,120}?)\s*:\s*(?P<url>https?://\S+)",
    re.IGNORECASE,
)
PWNEDORNOT_STATUS_RE = re.compile(
    r"Checking Breach status for\s+(?P<email>\S+)\s+\[\s*(?P<status>not pwned|pwned)\s*\]",
    re.IGNORECASE,
)
PWNEDORNOT_TOTAL_RE = re.compile(r"Total Breaches\s*:\s*(?P<count>\d+)", re.IGNORECASE)
PWNEDORNOT_API_STATUS_RE = re.compile(r"Status\s+(?P<code>\d{3})\s*:\s*(?P<message>.+)", re.IGNORECASE)
SHERLOCK_LINE_RE = re.compile(
    r"^\s*(?:\[(?P<marker>[+\-])\]\s*)?(?P<site>[^:]{2,120}):\s*(?P<rest>.+?)\s*$",
    re.IGNORECASE,
)
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

PARSER_REPOSITORIES = {
    "sherlock-project/sherlock",
    "soxoj/maigret",
    "thewhiteh4t/nexfil",
    "qeeqbox/social-analyzer",
    "p1ngul1n0/blackbird",
    "snooppr/snoop",
    "alpkeskin/mosint",
    "khast3x/h8mail",
    "thewhiteh4t/pwnedOrNot",
    "sundowndev/phoneinfoga",
    "kaifcodec/user-scanner",
    "projectdiscovery/subfinder",
    "projectdiscovery/httpx",
    "owasp-amass/amass",
    "laramies/theHarvester",
    "blacklanternsecurity/bbot",
    "smicallef/spiderfoot",
    "jasonxtn/argus",
    "Yvesssn/DetectDee",
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

    if repository == "sherlock-project/sherlock":
        return _sherlock_findings(repository, target, text)
    if repository == "thewhiteh4t/nexfil":
        return _nexfil_findings(repository, target, text)
    if repository == "qeeqbox/social-analyzer":
        return _social_analyzer_findings(repository, target, text)
    if repository == "p1ngul1n0/blackbird":
        return _blackbird_findings(repository, target, text)
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
    if repository == "thewhiteh4t/pwnedOrNot":
        return _pwnedornot_findings(repository, target, text)
    if repository == "sundowndev/phoneinfoga":
        return _phoneinfoga_findings(repository, target, text)
    if repository == "projectdiscovery/subfinder":
        return _subfinder_findings(repository, target, text)
    if repository == "projectdiscovery/httpx":
        return _httpx_findings(repository, target, text)
    if repository == "owasp-amass/amass":
        return _amass_findings(repository, target, text)
    if repository == "laramies/theHarvester":
        return _theharvester_findings(repository, target, text)
    if repository == "blacklanternsecurity/bbot":
        return _bbot_findings(repository, target, text)
    if repository == "smicallef/spiderfoot":
        return _spiderfoot_findings(repository, target, text)
    if repository == "jasonxtn/argus":
        return _argus_findings(repository, target, text)
    if repository == "Yvesssn/DetectDee":
        return _detectdee_findings(repository, target, text)

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


def _subfinder_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    root_domain = _target_domain(target)
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for record in _json_records(text):
        raw_subdomain = _first_scalar(
            record.get("host") or record.get("subdomain") or record.get("fqdn") or record.get("domain")
        )
        subdomain = _normalize_hostname(raw_subdomain)
        source_label = _first_scalar(record.get("source"))
        if not source_label:
            source_label = _metadata_list_text(record.get("sources"))
        ip = _metadata_list_text(record.get("ip") or record.get("ips"))
        finding = _subdomain_finding(
            repository=repository,
            parser="subfinder",
            target=target,
            root_domain=root_domain,
            subdomain=subdomain,
            source_label=source_label,
            ip=ip,
            raw_line="",
            seen=seen,
        )
        if finding:
            findings.append(finding)

    for line in text.splitlines():
        compact = " ".join(line.split())
        if not compact or compact.startswith(("{", "[")):
            continue
        for subdomain in _hostnames_from_text(compact):
            finding = _subdomain_finding(
                repository=repository,
                parser="subfinder",
                target=target,
                root_domain=root_domain,
                subdomain=subdomain,
                source_label="",
                ip="",
                raw_line=compact,
                seen=seen,
            )
            if finding:
                findings.append(finding)
    return tuple(findings)


def _amass_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    root_domain = _target_domain(target)
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for record in _json_records(text):
        raw_subdomain = _first_scalar(
            record.get("name") or record.get("host") or record.get("subdomain") or record.get("fqdn") or record.get("domain")
        )
        subdomain = _normalize_hostname(raw_subdomain)
        source_label = _metadata_list_text(record.get("source") or record.get("sources"))
        finding = _subdomain_finding(
            repository=repository,
            parser="amass",
            target=target,
            root_domain=root_domain,
            subdomain=subdomain,
            source_label=source_label,
            ip=_metadata_list_text(record.get("addresses") or record.get("ips") or record.get("ip")),
            raw_line="",
            seen=seen,
        )
        if finding:
            findings.append(finding)

    for line in text.splitlines():
        compact = " ".join(line.split())
        if not compact:
            continue
        for subdomain in _hostnames_from_text(compact):
            finding = _subdomain_finding(
                repository=repository,
                parser="amass",
                target=target,
                root_domain=root_domain,
                subdomain=subdomain,
                source_label="",
                ip="",
                raw_line=compact,
                seen=seen,
            )
            if finding:
                findings.append(finding)
    return tuple(findings)


def _subdomain_finding(
    *,
    repository: str,
    parser: str,
    target: ScanTarget,
    root_domain: str,
    subdomain: str,
    source_label: str,
    ip: str,
    raw_line: str,
    seen: set[tuple[str, str]],
) -> Finding | None:
    normalized = _normalize_hostname(subdomain)
    if not normalized:
        return None
    if root_domain:
        if normalized == root_domain or not normalized.endswith(f".{root_domain}"):
            return None

    key = (parser, normalized)
    if key in seen:
        return None
    seen.add(key)

    metadata = {
        "repository": repository,
        "parser": parser,
        "subdomain": normalized,
    }
    if root_domain:
        metadata["domain"] = root_domain
    if source_label:
        metadata["source_label"] = source_label
    if ip:
        metadata["ip"] = ip

    label = {
        "subfinder": "Subfinder",
        "amass": "Amass",
        "theharvester": "theHarvester",
        "bbot": "BBOT",
        "spiderfoot": "SpiderFoot",
        "argus": "Argus",
    }.get(parser, parser)
    evidence = f"{label} reported subdomain: {normalized}"
    if source_label:
        evidence += f" (source: {source_label})"
    elif raw_line:
        evidence = raw_line
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status="candidate",
        confidence="high",
        evidence=_short(evidence),
        metadata=metadata,
    )


def _httpx_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for record in _json_records(text):
        finding = _httpx_record_finding(repository, target, record, seen)
        if finding:
            findings.append(finding)

    for line in text.splitlines():
        compact = " ".join(line.split())
        if not compact or compact.startswith(("{", "[")):
            continue
        for finding in _httpx_line_findings(repository, target, compact, seen):
            findings.append(finding)
    return tuple(findings)


def _httpx_record_finding(
    repository: str,
    target: ScanTarget,
    record: dict[str, Any],
    seen: set[tuple[str, str]],
) -> Finding | None:
    url = _httpx_record_url(record)
    if not url:
        return None

    http_status = _int_value(
        record.get("status_code")
        or record.get("status-code")
        or record.get("status")
        or record.get("http_status")
        or record.get("response_status_code")
    )
    title = _first_scalar(record.get("title"))
    error = _first_scalar(record.get("error") or record.get("failed_reason"))
    failed = _truthy(record.get("failed")) or _truthy(record.get("probe_failed"))
    status = "error" if failed or error else "candidate"
    confidence = "high" if http_status is not None and status == "candidate" else "medium"
    finding_url = url if status == "candidate" else ""

    key = ("httpx", url.lower())
    if key in seen:
        return None
    seen.add(key)

    parsed = urlparse(url)
    domain = (parsed.hostname or _normalize_hostname(_first_scalar(record.get("host")))).lower()
    metadata = {
        "repository": repository,
        "parser": "httpx",
        "target_kind": target.kind,
    }
    if domain:
        metadata["domain"] = domain
    if not finding_url:
        metadata["checked_url"] = url
    _set_metadata(metadata, "http_status", "" if http_status is None else str(http_status))
    _set_metadata(metadata, "title", title)
    _set_metadata(metadata, "input", _first_scalar(record.get("input")))
    _set_metadata(metadata, "host", _first_scalar(record.get("host")))
    _set_metadata(metadata, "port", _first_scalar(record.get("port")))
    _set_metadata(metadata, "scheme", _first_scalar(record.get("scheme")))
    _set_metadata(metadata, "path", _first_scalar(record.get("path")))
    _set_metadata(metadata, "method", _first_scalar(record.get("method")))
    _set_metadata(metadata, "webserver", _first_scalar(record.get("webserver") or record.get("web_server")))
    _set_metadata(metadata, "tech", _metadata_list_text(record.get("tech") or record.get("technologies")))
    _set_metadata(metadata, "content_type", _first_scalar(record.get("content_type") or record.get("content-type")))
    _set_metadata(metadata, "content_length", _first_scalar(record.get("content_length") or record.get("content-length")))
    _set_metadata(metadata, "response_time", _first_scalar(record.get("response_time") or record.get("response-time")))
    _set_metadata(metadata, "location", _first_scalar(record.get("location")))
    _set_metadata(metadata, "cdn", _first_scalar(record.get("cdn") or record.get("cdn_name")))
    _set_metadata(metadata, "ip", _metadata_list_text(record.get("ip") or record.get("ips")))
    _set_metadata(metadata, "cname", _metadata_list_text(record.get("cname") or record.get("cnames")))
    if failed:
        metadata["failed"] = "true"
    _set_metadata(metadata, "error", error)

    evidence = f"httpx reported {url}"
    if http_status is not None:
        evidence += f" with HTTP {http_status}"
    if title:
        evidence += f" title={title}"
    if error:
        evidence += f" error={error}"
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status=status,
        url=finding_url,
        title=title,
        http_status=http_status,
        confidence=confidence,
        evidence=_short(evidence),
        metadata=metadata,
    )


def _httpx_line_findings(
    repository: str,
    target: ScanTarget,
    line: str,
    seen: set[tuple[str, str]],
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for raw_url in URL_RE.findall(line):
        url = raw_url.rstrip(".,;")
        key = ("httpx", url.lower())
        if key in seen:
            continue
        seen.add(key)
        http_status = _http_status_from_line(line)
        parsed = urlparse(url)
        metadata = {
            "repository": repository,
            "parser": "httpx",
            "target_kind": target.kind,
            "domain": (parsed.hostname or "").lower(),
        }
        if http_status is not None:
            metadata["http_status"] = str(http_status)
        findings.append(
            Finding(
                module="external-adapter-parser",
                source=repository,
                target=target.value,
                status="candidate",
                url=url,
                http_status=http_status,
                confidence="medium",
                evidence=_short(line),
                metadata=metadata,
            )
        )
    return tuple(findings)


def _theharvester_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    payload = _load_json_payload(text)
    structured = _theharvester_json_findings(repository, target, payload)
    if structured:
        return structured

    root_domain = _target_domain(target)
    findings: list[Finding] = []
    seen_subdomains: set[tuple[str, str]] = set()
    seen_emails: set[str] = set()
    seen_urls: set[str] = set()
    for line in text.splitlines():
        compact = " ".join(line.split())
        if not compact:
            continue
        for email in EMAIL_RE.findall(compact):
            finding = _theharvester_email_finding(repository, target, email, "console", seen_emails)
            if finding:
                findings.append(finding)
        for raw_url in URL_RE.findall(compact):
            finding = _theharvester_url_finding(repository, target, raw_url.rstrip(".,;"), "console", seen_urls)
            if finding:
                findings.append(finding)
        for hostname in _hostnames_from_text(compact):
            finding = _subdomain_finding(
                repository=repository,
                parser="theharvester",
                target=target,
                root_domain=root_domain,
                subdomain=hostname,
                source_label="console",
                ip="",
                raw_line=compact,
                seen=seen_subdomains,
            )
            if finding:
                findings.append(finding)
    return tuple(findings)


def _theharvester_json_findings(
    repository: str,
    target: ScanTarget,
    payload: object | None,
) -> tuple[Finding, ...]:
    if not isinstance(payload, dict):
        return ()

    root_domain = _target_domain(target)
    findings: list[Finding] = []
    seen_subdomains: set[tuple[str, str]] = set()
    seen_emails: set[str] = set()
    seen_urls: set[str] = set()
    seen_observed: set[tuple[str, str]] = set()

    for email in _string_list(payload.get("emails")):
        finding = _theharvester_email_finding(repository, target, email, "email", seen_emails)
        if finding:
            findings.append(finding)

    for raw_host in _string_list(payload.get("hosts")) + _string_list(payload.get("vhosts")):
        hostname, ip = _theharvester_host_ip(raw_host)
        finding = _subdomain_finding(
            repository=repository,
            parser="theharvester",
            target=target,
            root_domain=root_domain,
            subdomain=hostname,
            source_label="host",
            ip=ip,
            raw_line="",
            seen=seen_subdomains,
        )
        if finding:
            findings.append(finding)

    for key, category in (
        ("interesting_urls", "interesting-url"),
        ("trello_urls", "trello-url"),
        ("linkedin_links", "linkedin-link"),
    ):
        for url in _string_list(payload.get(key)):
            finding = _theharvester_url_finding(repository, target, url, category, seen_urls)
            if finding:
                findings.append(finding)

    for ip in _string_list(payload.get("ips")):
        finding = _theharvester_observed_finding(repository, target, "ip", ip, "ip", seen_observed)
        if finding:
            findings.append(finding)

    for asn in _string_list(payload.get("asns")):
        finding = _theharvester_observed_finding(repository, target, "asn", asn, "asn", seen_observed)
        if finding:
            findings.append(finding)

    for person in _theharvester_people(payload.get("people")):
        finding = _theharvester_observed_finding(repository, target, "name", person, "person", seen_observed)
        if finding:
            findings.append(finding)

    for person in _string_list(payload.get("twitter_people")):
        finding = _theharvester_observed_finding(repository, target, "username", person, "twitter-person", seen_observed)
        if finding:
            findings.append(finding)
    for person in _string_list(payload.get("linkedin_people")):
        finding = _theharvester_observed_finding(repository, target, "name", person, "linkedin-person", seen_observed)
        if finding:
            findings.append(finding)

    return tuple(findings)


def _theharvester_email_finding(
    repository: str,
    target: ScanTarget,
    email: str,
    category: str,
    seen: set[str],
) -> Finding | None:
    normalized = email.strip().lower()
    if not EMAIL_RE.fullmatch(normalized):
        return None
    if normalized in seen:
        return None
    seen.add(normalized)
    domain = normalized.rsplit("@", 1)[1]
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status="candidate",
        confidence="medium",
        evidence=f"theHarvester reported email: {normalized}",
        metadata={
            "repository": repository,
            "parser": "theharvester",
            "category": category,
            "email": normalized,
            "domain": domain,
        },
    )


def _theharvester_url_finding(
    repository: str,
    target: ScanTarget,
    url: str,
    category: str,
    seen: set[str],
) -> Finding | None:
    value = url.strip()
    if not value.startswith(("http://", "https://")):
        return None
    key = value.lower()
    if key in seen:
        return None
    seen.add(key)
    domain = (urlparse(value).hostname or "").lower()
    metadata = {
        "repository": repository,
        "parser": "theharvester",
        "category": category,
    }
    if domain:
        metadata["domain"] = domain
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status="candidate",
        url=value,
        confidence="medium",
        evidence=f"theHarvester reported URL: {value}",
        metadata=metadata,
    )


def _theharvester_observed_finding(
    repository: str,
    target: ScanTarget,
    metadata_key: str,
    value: str,
    category: str,
    seen: set[tuple[str, str]],
) -> Finding | None:
    normalized = " ".join(value.strip().split())
    if not normalized:
        return None
    seen_key = (metadata_key, normalized.lower())
    if seen_key in seen:
        return None
    seen.add(seen_key)
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status="observed",
        confidence="medium",
        evidence=f"theHarvester reported {category}: {normalized}",
        metadata={
            "repository": repository,
            "parser": "theharvester",
            "category": category,
            metadata_key: normalized,
        },
    )


def _theharvester_host_ip(value: str) -> tuple[str, str]:
    raw = value.strip()
    if raw.count(":") == 1 and "://" not in raw:
        host, ip = raw.rsplit(":", 1)
        return _normalize_hostname(host), ip.strip()
    return _normalize_hostname(raw), ""


def _theharvester_people(value: object) -> tuple[str, ...]:
    people: list[str] = []
    if isinstance(value, dict):
        value = [value]
    if isinstance(value, (list, tuple)):
        for item in value:
            if isinstance(item, dict):
                full_name = _first_scalar(
                    item.get("name")
                    or item.get("full_name")
                    or item.get("fullname")
                    or " ".join(
                        part
                        for part in (
                            _first_scalar(item.get("first_name")),
                            _first_scalar(item.get("last_name")),
                        )
                        if part
                    )
                )
                if full_name:
                    people.append(full_name)
            else:
                scalar = _first_scalar(item)
                if scalar:
                    people.append(scalar)
    return _dedupe_text(people)


def _bbot_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    seen_subdomains: set[tuple[str, str]] = set()
    root_domain = _target_domain(target)

    for record in _bbot_event_records(text):
        event_type = _first_scalar(record.get("type")).upper()
        if not event_type:
            continue
        finding = _bbot_event_finding(
            repository=repository,
            target=target,
            record=record,
            event_type=event_type,
            root_domain=root_domain,
            seen=seen,
            seen_subdomains=seen_subdomains,
        )
        if finding:
            findings.append(finding)

    if findings:
        return tuple(findings)

    for line in text.splitlines():
        compact = " ".join(line.split())
        if not compact:
            continue
        event_match = re.match(r"^\[(?P<type>[A-Z0-9_]+)\]\s+(?P<data>\S+)(?:\s+(?P<module>\S+))?", compact)
        if not event_match:
            continue
        record = {
            "type": event_match.group("type"),
            "data": event_match.group("data"),
            "module": event_match.group("module") or "stdout",
        }
        finding = _bbot_event_finding(
            repository=repository,
            target=target,
            record=record,
            event_type=event_match.group("type").upper(),
            root_domain=root_domain,
            seen=seen,
            seen_subdomains=seen_subdomains,
        )
        if finding:
            findings.append(finding)
    return tuple(findings)


def _bbot_event_records(text: str) -> tuple[dict[str, Any], ...]:
    records: list[dict[str, Any]] = []
    payload = _load_json_payload(text)
    records.extend(_bbot_payload_records(payload))

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith(("{", "[")):
            start = stripped.find("{")
            end = stripped.rfind("}")
            if start == -1 or end <= start:
                continue
            stripped = stripped[start : end + 1]
        try:
            line_payload = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        records.extend(_bbot_payload_records(line_payload))

    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        key = json.dumps(record, sort_keys=True, ensure_ascii=False, default=str)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(record)
    return tuple(deduped)


def _bbot_payload_records(payload: object | None) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        if _first_scalar(payload.get("type")) and "data" in payload:
            return [payload]
        records: list[dict[str, Any]] = []
        for key in ("events", "results", "data"):
            nested = payload.get(key)
            if isinstance(nested, (list, tuple)):
                records.extend(_bbot_payload_records(list(nested)))
        return records
    if isinstance(payload, list):
        records = []
        for item in payload:
            if isinstance(item, dict):
                records.extend(_bbot_payload_records(item))
        return records
    return []


def _bbot_event_finding(
    *,
    repository: str,
    target: ScanTarget,
    record: dict[str, Any],
    event_type: str,
    root_domain: str,
    seen: set[tuple[str, str]],
    seen_subdomains: set[tuple[str, str]],
) -> Finding | None:
    data = record.get("data")
    data_text = _bbot_data_text(data)
    if not data_text:
        return None

    if event_type == "DNS_NAME":
        subdomain = _normalize_hostname(data_text)
        return _subdomain_finding(
            repository=repository,
            parser="bbot",
            target=target,
            root_domain=root_domain,
            subdomain=subdomain,
            source_label=_first_scalar(record.get("module")),
            ip=_metadata_list_text(record.get("resolved_hosts")),
            raw_line="",
            seen=seen_subdomains,
        )

    if event_type == "EMAIL_ADDRESS":
        return _bbot_email_finding(repository, target, data_text, record, seen)

    if event_type in {"URL", "URL_UNVERIFIED"}:
        return _bbot_url_finding(repository, target, data_text, event_type, record, seen)

    metadata = _bbot_base_metadata(repository, record, event_type)
    status = "observed"
    confidence = _bbot_confidence(record)
    url = ""
    title = ""
    http_status = None

    if event_type == "IP_ADDRESS":
        metadata["ip"] = data_text
    elif event_type == "IP_RANGE":
        metadata["ip_range"] = data_text
    elif event_type == "OPEN_TCP_PORT":
        host, port = _bbot_host_port(data_text, record)
        _set_metadata(metadata, "host", host)
        _set_metadata(metadata, "port", port)
        status = "candidate"
    elif event_type == "TECHNOLOGY":
        metadata["technology"] = data_text
    elif event_type == "USERNAME":
        metadata["username"] = data_text.strip().lstrip("@")
    elif event_type in {"FINDING", "VULNERABILITY", "STORAGE_BUCKET"}:
        status = "candidate"
        if event_type == "VULNERABILITY":
            confidence = "high"
        if isinstance(data, dict):
            url = _first_scalar(data.get("url") or data.get("host") or data.get("endpoint"))
            if url and not url.startswith(("http://", "https://")):
                url = ""
            title = _first_scalar(data.get("title") or data.get("description") or data.get("name"))
            _set_metadata(metadata, "severity", _first_scalar(data.get("severity")))
            _set_metadata(metadata, "description", _first_scalar(data.get("description") or data.get("name")))
            _set_metadata(metadata, "host", _first_scalar(data.get("host")))
            _set_metadata(metadata, "technology", _first_scalar(data.get("technology")))
            http_status = _int_value(data.get("status_code") or data.get("http_status"))
        elif data_text.startswith(("http://", "https://")):
            url = data_text
    elif event_type == "HTTP_RESPONSE" and isinstance(data, dict):
        url = _first_scalar(data.get("url") or data.get("request_url"))
        title = _first_scalar(data.get("title"))
        http_status = _int_value(data.get("status_code") or data.get("http_status"))
        status = "candidate"
    else:
        metadata["value"] = data_text

    if url:
        domain = (urlparse(url).hostname or "").lower()
        if domain:
            metadata["domain"] = domain

    key = (event_type, (url or data_text).lower())
    if key in seen:
        return None
    seen.add(key)

    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status=status,
        url=url,
        title=title,
        http_status=http_status,
        confidence=confidence,
        evidence=_short(f"BBOT {event_type}: {title or data_text}"),
        metadata=metadata,
    )


def _bbot_email_finding(
    repository: str,
    target: ScanTarget,
    email: str,
    record: dict[str, Any],
    seen: set[tuple[str, str]],
) -> Finding | None:
    normalized = email.strip().lower()
    if not EMAIL_RE.fullmatch(normalized):
        return None
    key = ("EMAIL_ADDRESS", normalized)
    if key in seen:
        return None
    seen.add(key)
    metadata = _bbot_base_metadata(repository, record, "EMAIL_ADDRESS")
    metadata["email"] = normalized
    metadata["domain"] = normalized.rsplit("@", 1)[1]
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status="candidate",
        confidence=_bbot_confidence(record),
        evidence=f"BBOT EMAIL_ADDRESS: {normalized}",
        metadata=metadata,
    )


def _bbot_url_finding(
    repository: str,
    target: ScanTarget,
    url: str,
    event_type: str,
    record: dict[str, Any],
    seen: set[tuple[str, str]],
) -> Finding | None:
    value = url.strip()
    if not value.startswith(("http://", "https://")):
        return None
    key = (event_type, value.lower())
    if key in seen:
        return None
    seen.add(key)
    metadata = _bbot_base_metadata(repository, record, event_type)
    domain = (urlparse(value).hostname or "").lower()
    if domain:
        metadata["domain"] = domain
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status="candidate",
        url=value,
        confidence=_bbot_confidence(record),
        evidence=f"BBOT {event_type}: {value}",
        metadata=metadata,
    )


def _bbot_base_metadata(repository: str, record: dict[str, Any], event_type: str) -> dict[str, str]:
    metadata = {
        "repository": repository,
        "parser": "bbot",
        "event_type": event_type,
    }
    for key in ("module", "scope_description", "host", "port", "scan", "parent", "parent_uuid", "uuid", "id"):
        _set_metadata(metadata, f"bbot_{key}", _first_scalar(record.get(key)))
    tags = _metadata_list_text(record.get("tags"))
    if tags:
        metadata["bbot_tags"] = tags
    resolved_hosts = _metadata_list_text(record.get("resolved_hosts"))
    if resolved_hosts:
        metadata["resolved_hosts"] = resolved_hosts
    return metadata


def _bbot_data_text(value: object) -> str:
    if isinstance(value, dict):
        for key in ("url", "email", "host", "name", "description", "technology", "bucket", "id", "value"):
            scalar = _first_scalar(value.get(key))
            if scalar:
                return scalar
        return _short(json.dumps(value, sort_keys=True, ensure_ascii=False, default=str), limit=200)
    return _first_scalar(value)


def _bbot_confidence(record: dict[str, Any]) -> str:
    scope = _first_scalar(record.get("scope_description")).lower()
    tags = {item.lower() for item in _string_list(record.get("tags"))}
    if scope == "in-scope" or "in-scope" in tags:
        return "high"
    return "medium"


def _bbot_host_port(data_text: str, record: dict[str, Any]) -> tuple[str, str]:
    host = _first_scalar(record.get("host"))
    port = _first_scalar(record.get("port"))
    if host and port:
        return host, port
    value = data_text.strip()
    if ":" in value:
        host_part, port_part = value.rsplit(":", 1)
        return _normalize_hostname(host_part) or host_part.strip(), port_part.strip()
    return host, port


def _spiderfoot_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    seen_subdomains: set[tuple[str, str]] = set()
    root_domain = _target_domain(target)

    for record in _spiderfoot_event_records(text):
        event_type = _first_scalar(record.get("type") or record.get("event_type")).upper()
        if not event_type:
            continue
        finding = _spiderfoot_event_finding(
            repository=repository,
            target=target,
            record=record,
            event_type=event_type,
            root_domain=root_domain,
            seen=seen,
            seen_subdomains=seen_subdomains,
        )
        if finding:
            findings.append(finding)

    if findings:
        return tuple(findings)

    for line in text.splitlines():
        compact = " ".join(line.split())
        if not compact:
            continue
        event_match = re.match(r"^\[(?P<type>[A-Z0-9_]+)\]\s+(?P<data>.+?)\s*$", compact)
        if not event_match:
            continue
        finding = _spiderfoot_event_finding(
            repository=repository,
            target=target,
            record={"type": event_match.group("type"), "data": event_match.group("data"), "module": "stdout"},
            event_type=event_match.group("type").upper(),
            root_domain=root_domain,
            seen=seen,
            seen_subdomains=seen_subdomains,
        )
        if finding:
            findings.append(finding)
    return tuple(findings)


def _spiderfoot_event_records(text: str) -> tuple[dict[str, Any], ...]:
    records: list[dict[str, Any]] = []
    payload = _load_json_payload(text)
    records.extend(_spiderfoot_payload_records(payload))

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith(("{", "[")):
            start = stripped.find("{")
            end = stripped.rfind("}")
            if start == -1 or end <= start:
                continue
            stripped = stripped[start : end + 1]
        try:
            line_payload = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        records.extend(_spiderfoot_payload_records(line_payload))

    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        key = json.dumps(record, sort_keys=True, ensure_ascii=False, default=str)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(record)
    return tuple(deduped)


def _spiderfoot_payload_records(payload: object | None) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        if _first_scalar(payload.get("type") or payload.get("event_type")) and "data" in payload:
            return [payload]
        records: list[dict[str, Any]] = []
        for key in ("events", "results", "data"):
            nested = payload.get(key)
            if isinstance(nested, (list, tuple)):
                records.extend(_spiderfoot_payload_records(list(nested)))
        return records
    if isinstance(payload, list):
        records = []
        for item in payload:
            if isinstance(item, dict):
                records.extend(_spiderfoot_payload_records(item))
        return records
    return []


def _spiderfoot_event_finding(
    *,
    repository: str,
    target: ScanTarget,
    record: dict[str, Any],
    event_type: str,
    root_domain: str,
    seen: set[tuple[str, str]],
    seen_subdomains: set[tuple[str, str]],
) -> Finding | None:
    data = record.get("data")
    data_text = _spiderfoot_data_text(data)
    if not data_text:
        return None

    if event_type in {"INTERNET_NAME", "INTERNET_NAME_UNRESOLVED", "DNS_NAME", "DOMAIN_NAME"}:
        host = _normalize_hostname(data_text)
        if root_domain and host != root_domain and host.endswith(f".{root_domain}"):
            return _subdomain_finding(
                repository=repository,
                parser="spiderfoot",
                target=target,
                root_domain=root_domain,
                subdomain=host,
                source_label=_spiderfoot_source_label(record),
                ip="",
                raw_line="",
                seen=seen_subdomains,
            )
        return _spiderfoot_observed_finding(repository, target, record, event_type, "domain", host, seen)

    if _spiderfoot_is_url_event(event_type) or data_text.startswith(("http://", "https://")):
        return _spiderfoot_url_finding(repository, target, record, event_type, data_text, seen)

    if "EMAIL" in event_type:
        return _spiderfoot_observed_finding(repository, target, record, event_type, "email", data_text.lower(), seen)

    if event_type in {"IP_ADDRESS", "IPV6_ADDRESS"}:
        return _spiderfoot_observed_finding(repository, target, record, event_type, "ip", data_text, seen)

    if event_type in {"IP_NETBLOCK", "NETBLOCK"}:
        return _spiderfoot_observed_finding(repository, target, record, event_type, "ip_range", data_text, seen)

    if event_type in {"TCP_PORT_OPEN", "UDP_PORT_OPEN", "OPEN_TCP_PORT"}:
        host, port = _spiderfoot_host_port(data_text, record)
        metadata = _spiderfoot_base_metadata(repository, record, event_type, target)
        _set_metadata(metadata, "host", host)
        _set_metadata(metadata, "port", port)
        return _spiderfoot_custom_finding(
            repository=repository,
            target=target,
            record=record,
            event_type=event_type,
            value=data_text,
            metadata=metadata,
            seen=seen,
            status="candidate",
        )

    if event_type in {"USERNAME", "ACCOUNT_EXTERNAL_OWNED"}:
        return _spiderfoot_observed_finding(repository, target, record, event_type, "username", data_text.strip().lstrip("@"), seen)

    if event_type in {"HUMAN_NAME", "PERSON_NAME", "COMPANY_NAME"}:
        return _spiderfoot_observed_finding(repository, target, record, event_type, "name", data_text, seen)

    if "PHONE" in event_type:
        return _spiderfoot_observed_finding(repository, target, record, event_type, "phone", data_text, seen)

    if "TECHNOLOGY" in event_type:
        return _spiderfoot_observed_finding(repository, target, record, event_type, "technology", data_text, seen)

    if event_type in {"BGP_AS_MEMBER", "BGP_AS_OWNER", "ASN"}:
        return _spiderfoot_observed_finding(repository, target, record, event_type, "asn", data_text, seen)

    if event_type.startswith("VULNERABILITY") or event_type in {"FINDING", "LEAKSITE_DOMAIN", "MALICIOUS_IPADDR"}:
        metadata = _spiderfoot_base_metadata(repository, record, event_type, target)
        metadata["value"] = data_text
        return _spiderfoot_custom_finding(
            repository=repository,
            target=target,
            record=record,
            event_type=event_type,
            value=data_text,
            metadata=metadata,
            seen=seen,
            status="candidate",
            confidence="high",
        )

    metadata = _spiderfoot_base_metadata(repository, record, event_type, target)
    metadata["value"] = data_text
    return _spiderfoot_custom_finding(
        repository=repository,
        target=target,
        record=record,
        event_type=event_type,
        value=data_text,
        metadata=metadata,
        seen=seen,
        status="observed",
    )


def _spiderfoot_observed_finding(
    repository: str,
    target: ScanTarget,
    record: dict[str, Any],
    event_type: str,
    metadata_key: str,
    value: str,
    seen: set[tuple[str, str]],
) -> Finding | None:
    normalized = " ".join(str(value).split())
    if not normalized:
        return None
    if metadata_key == "email" and not EMAIL_RE.fullmatch(normalized):
        return None
    if metadata_key == "domain":
        normalized = _normalize_hostname(normalized)
        if not normalized:
            return None
    key = (event_type, normalized.lower())
    if key in seen:
        return None
    seen.add(key)
    metadata = _spiderfoot_base_metadata(repository, record, event_type, target)
    metadata[metadata_key] = normalized
    if metadata_key == "email":
        metadata["domain"] = normalized.rsplit("@", 1)[1].lower()
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status="candidate" if metadata_key in {"email", "domain", "phone"} else "observed",
        confidence=_spiderfoot_confidence(record),
        evidence=_short(f"SpiderFoot {event_type}: {normalized}"),
        metadata=metadata,
    )


def _spiderfoot_url_finding(
    repository: str,
    target: ScanTarget,
    record: dict[str, Any],
    event_type: str,
    url: str,
    seen: set[tuple[str, str]],
) -> Finding | None:
    value = url.strip()
    if not value.startswith(("http://", "https://")):
        return None
    key = (event_type, value.lower())
    if key in seen:
        return None
    seen.add(key)
    metadata = _spiderfoot_base_metadata(repository, record, event_type, target)
    domain = (urlparse(value).hostname or "").lower()
    if domain:
        metadata["domain"] = domain
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status="candidate",
        url=value,
        confidence=_spiderfoot_confidence(record),
        evidence=_short(f"SpiderFoot {event_type}: {value}"),
        metadata=metadata,
    )


def _spiderfoot_custom_finding(
    *,
    repository: str,
    target: ScanTarget,
    record: dict[str, Any],
    event_type: str,
    value: str,
    metadata: dict[str, str],
    seen: set[tuple[str, str]],
    status: str,
    confidence: str = "",
) -> Finding | None:
    normalized = " ".join(value.split())
    if not normalized:
        return None
    key = (event_type, normalized.lower())
    if key in seen:
        return None
    seen.add(key)
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status=status,
        confidence=confidence or _spiderfoot_confidence(record),
        evidence=_short(f"SpiderFoot {event_type}: {normalized}"),
        metadata=metadata,
    )


def _spiderfoot_base_metadata(
    repository: str,
    record: dict[str, Any],
    event_type: str,
    target: ScanTarget | None = None,
) -> dict[str, str]:
    metadata = {
        "repository": repository,
        "parser": "spiderfoot",
        "event_type": event_type,
    }
    if target is not None:
        metadata["target_kind"] = target.kind
        metadata["target_value"] = target.value
    for source_key, metadata_key in (
        ("module", "spiderfoot_module"),
        ("sourceModule", "spiderfoot_module"),
        ("source", "spiderfoot_source"),
        ("sourceEvent", "spiderfoot_source_event"),
        ("confidence", "spiderfoot_confidence"),
        ("visibility", "spiderfoot_visibility"),
        ("risk", "spiderfoot_risk"),
    ):
        value = record.get(source_key)
        if source_key == "sourceEvent" and isinstance(value, dict):
            value = value.get("type") or value.get("data")
        _set_metadata(metadata, metadata_key, _first_scalar(value))
    return metadata


def _spiderfoot_data_text(value: object) -> str:
    if isinstance(value, dict):
        for key in ("url", "email", "host", "name", "title", "description", "value", "data"):
            scalar = _first_scalar(value.get(key))
            if scalar:
                return scalar
        return _short(json.dumps(value, sort_keys=True, ensure_ascii=False, default=str), limit=200)
    return _first_scalar(value)


def _spiderfoot_is_url_event(event_type: str) -> bool:
    return event_type in {
        "URL",
        "WEBLINK",
        "LINKED_URL_INTERNAL",
        "LINKED_URL_EXTERNAL",
        "AFFILIATE_LINK",
        "SOCIAL_MEDIA",
    } or event_type.endswith("_URL")


def _spiderfoot_confidence(record: dict[str, Any]) -> str:
    confidence = _int_value(record.get("confidence"))
    if confidence is not None:
        if confidence >= 80:
            return "high"
        if confidence < 40:
            return "low"
    return "medium"


def _spiderfoot_source_label(record: dict[str, Any]) -> str:
    return _first_scalar(record.get("module") or record.get("sourceModule") or record.get("source"))


def _spiderfoot_host_port(data_text: str, record: dict[str, Any]) -> tuple[str, str]:
    host = _first_scalar(record.get("host"))
    port = _first_scalar(record.get("port"))
    if host and port:
        return host, port
    if ":" in data_text:
        host_part, port_part = data_text.rsplit(":", 1)
        return _normalize_hostname(host_part) or host_part.strip(), port_part.strip()
    return host, port or data_text.strip()


def _argus_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    seen_subdomains: set[tuple[str, str]] = set()
    root_domain = _target_domain(target)

    for record in _json_records(text):
        for finding in _argus_record_findings(repository, target, record, root_domain, seen, seen_subdomains):
            findings.append(finding)

    for line in text.splitlines():
        compact = " ".join(line.split())
        if not compact:
            continue
        for finding in _argus_line_findings(repository, target, compact, root_domain, seen, seen_subdomains):
            findings.append(finding)
    return tuple(findings)


def _argus_record_findings(
    repository: str,
    target: ScanTarget,
    record: dict[str, Any],
    root_domain: str,
    seen: set[tuple[str, str]],
    seen_subdomains: set[tuple[str, str]],
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    module = _first_scalar(record.get("module") or record.get("name") or record.get("category"))
    for key in ("url", "link", "endpoint"):
        finding = _argus_url_finding(repository, target, _first_scalar(record.get(key)), module, seen)
        if finding:
            findings.append(finding)
    for key in ("email", "emails"):
        for email in _string_list(record.get(key)):
            finding = _argus_observed_finding(repository, target, "email", email.lower(), module, seen)
            if finding:
                findings.append(finding)
    for key in ("host", "domain", "subdomain", "fqdn"):
        hostname = _normalize_hostname(_first_scalar(record.get(key)))
        if not hostname:
            continue
        if root_domain and hostname != root_domain and hostname.endswith(f".{root_domain}"):
            finding = _subdomain_finding(
                repository=repository,
                parser="argus",
                target=target,
                root_domain=root_domain,
                subdomain=hostname,
                source_label=module,
                ip=_metadata_list_text(record.get("ip") or record.get("ips")),
                raw_line="",
                seen=seen_subdomains,
            )
        else:
            finding = _argus_observed_finding(repository, target, "domain", hostname, module, seen)
        if finding:
            findings.append(finding)
    for key in ("ip", "address"):
        finding = _argus_observed_finding(repository, target, "ip", _first_scalar(record.get(key)), module, seen)
        if finding:
            findings.append(finding)
    for key in ("port", "open_port"):
        finding = _argus_observed_finding(repository, target, "port", _first_scalar(record.get(key)), module, seen)
        if finding:
            findings.append(finding)
    for key in ("technology", "tech", "cms", "server"):
        finding = _argus_observed_finding(repository, target, "technology", _metadata_list_text(record.get(key)), module, seen)
        if finding:
            findings.append(finding)
    return tuple(findings)


def _argus_line_findings(
    repository: str,
    target: ScanTarget,
    line: str,
    root_domain: str,
    seen: set[tuple[str, str]],
    seen_subdomains: set[tuple[str, str]],
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    module = _argus_module_label(line)

    for raw_url in URL_RE.findall(line):
        finding = _argus_url_finding(repository, target, raw_url.rstrip(".,;"), module, seen)
        if finding:
            findings.append(finding)

    for email in EMAIL_RE.findall(line):
        finding = _argus_observed_finding(repository, target, "email", email.lower(), module, seen)
        if finding:
            findings.append(finding)

    for phone in PHONE_RE.findall(line):
        finding = _argus_observed_finding(repository, target, "phone", phone, module, seen)
        if finding:
            findings.append(finding)

    for ip in IPV4_RE.findall(line):
        finding = _argus_observed_finding(repository, target, "ip", ip, module, seen)
        if finding:
            findings.append(finding)

    for port in _argus_ports(line):
        finding = _argus_observed_finding(repository, target, "port", port, module, seen)
        if finding:
            findings.append(finding)

    technology = _argus_technology(line)
    if technology:
        finding = _argus_observed_finding(repository, target, "technology", technology, module, seen)
        if finding:
            findings.append(finding)

    for hostname in _hostnames_from_text(line):
        finding = _subdomain_finding(
            repository=repository,
            parser="argus",
            target=target,
            root_domain=root_domain,
            subdomain=hostname,
            source_label=module,
            ip="",
            raw_line="",
            seen=seen_subdomains,
        )
        if finding:
            findings.append(finding)
    return tuple(findings)


def _argus_url_finding(
    repository: str,
    target: ScanTarget,
    url: str,
    module: str,
    seen: set[tuple[str, str]],
) -> Finding | None:
    value = url.strip()
    if not value.startswith(("http://", "https://")):
        return None
    key = ("url", value.lower())
    if key in seen:
        return None
    seen.add(key)
    metadata = _argus_metadata(repository, module)
    domain = (urlparse(value).hostname or "").lower()
    if domain:
        metadata["domain"] = domain
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status="candidate",
        url=value,
        confidence="medium",
        evidence=_short(f"Argus reported URL: {value}"),
        metadata=metadata,
    )


def _argus_observed_finding(
    repository: str,
    target: ScanTarget,
    metadata_key: str,
    value: str,
    module: str,
    seen: set[tuple[str, str]],
) -> Finding | None:
    normalized = " ".join(str(value).split()).strip(" ,;")
    if not normalized:
        return None
    if metadata_key == "email" and not EMAIL_RE.fullmatch(normalized):
        return None
    if metadata_key == "domain":
        normalized = _normalize_hostname(normalized)
        if not normalized:
            return None
    if metadata_key == "phone" and not PHONE_RE.fullmatch(normalized):
        return None
    if metadata_key == "port" and not _valid_port(normalized):
        return None
    key = (metadata_key, normalized.lower())
    if key in seen:
        return None
    seen.add(key)
    metadata = _argus_metadata(repository, module)
    metadata[metadata_key] = normalized
    if metadata_key == "email":
        metadata["domain"] = normalized.rsplit("@", 1)[1].lower()
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status="candidate" if metadata_key in {"email", "phone", "domain", "port"} else "observed",
        confidence="medium",
        evidence=_short(f"Argus reported {metadata_key}: {normalized}"),
        metadata=metadata,
    )


def _argus_metadata(repository: str, module: str) -> dict[str, str]:
    metadata = {
        "repository": repository,
        "parser": "argus",
    }
    if module:
        metadata["argus_module"] = module
    return metadata


def _argus_module_label(line: str) -> str:
    stripped = _strip_prefix(line)
    match = KEY_VALUE_RE.match(stripped)
    if match:
        return " ".join(match.group("key").split())
    if ":" in stripped:
        return " ".join(stripped.split(":", 1)[0].split())
    return ""


def _argus_ports(line: str) -> tuple[str, ...]:
    lowered = line.lower()
    if not any(keyword in lowered for keyword in ("port", "open", "tcp", "udp", "service")):
        return ()
    ports: list[str] = []
    for match in re.finditer(r"\b(?P<port>[1-9]\d{0,4})/(?:tcp|udp)\b", line, re.IGNORECASE):
        if _valid_port(match.group("port")):
            ports.append(match.group("port"))
    for match in re.finditer(r"\bport\s*[:=]?\s*(?P<port>[1-9]\d{0,4})\b", line, re.IGNORECASE):
        if _valid_port(match.group("port")):
            ports.append(match.group("port"))
    return _dedupe_text(ports)


def _argus_technology(line: str) -> str:
    lowered = line.lower()
    if not any(keyword in lowered for keyword in ("technology", "tech stack", "cms", "server info", "server:")):
        return ""
    match = KEY_VALUE_RE.match(_strip_prefix(line))
    if not match:
        return ""
    value = match.group("value").strip()
    if value.startswith(("http://", "https://")):
        return ""
    return value


def _valid_port(value: str) -> bool:
    try:
        port = int(value)
    except ValueError:
        return False
    return 0 < port <= 65535


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


def _pwnedornot_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    seen: set[tuple[str, ...]] = set()

    email = _pwnedornot_email(target, text)
    status_label = _pwnedornot_status(text)
    total_breaches = _pwnedornot_total(text)

    summary = _pwnedornot_summary_finding(repository, target, email, status_label, total_breaches, seen)
    if summary:
        findings.append(summary)

    for record in _pwnedornot_breach_records(text):
        finding = _pwnedornot_breach_finding(repository, target, email, record, seen)
        if finding:
            findings.append(finding)

    credential = _pwnedornot_credential_finding(repository, target, email, text, seen)
    if credential:
        findings.append(credential)

    error = _pwnedornot_error_finding(repository, target, email, text, seen)
    if error:
        findings.append(error)

    return tuple(findings)


def _pwnedornot_email(target: ScanTarget, text: str) -> str:
    if EMAIL_RE.fullmatch(target.value):
        return target.value
    match = EMAIL_RE.search(text)
    return match.group(0) if match else target.value


def _pwnedornot_status(text: str) -> str:
    match = PWNEDORNOT_STATUS_RE.search(text)
    if not match:
        return ""
    return "not_pwned" if "not" in match.group("status").lower() else "pwned"


def _pwnedornot_total(text: str) -> int | None:
    match = PWNEDORNOT_TOTAL_RE.search(text)
    if not match:
        return None
    try:
        return int(match.group("count"))
    except ValueError:
        return None


def _pwnedornot_summary_finding(
    repository: str,
    target: ScanTarget,
    email: str,
    status_label: str,
    total_breaches: int | None,
    seen: set[tuple[str, ...]],
) -> Finding | None:
    if not status_label and total_breaches is None:
        return None
    count = total_breaches if total_breaches is not None else (0 if status_label == "not_pwned" else None)
    status = "candidate" if status_label == "pwned" or (count is not None and count > 0) else "not_found"
    confidence = "high" if status == "candidate" else "medium"
    metadata = _pwnedornot_metadata(repository, target, email, "breach-summary")
    if status_label:
        metadata["result_status"] = status_label
    if count is not None:
        metadata["breach_count"] = str(count)
    evidence = f"pwnedOrNot {email}: {count} breach(es)" if count is not None else f"pwnedOrNot {email}: {status_label}"
    return _pwnedornot_finding(
        repository=repository,
        target=target,
        status=status,
        confidence=confidence,
        evidence=evidence,
        metadata=metadata,
        seen=seen,
        key=("pwnedornot", "summary", email.lower(), status_label, str(count)),
    )


def _pwnedornot_breach_records(text: str) -> tuple[dict[str, str], ...]:
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = _strip_prefix(raw_line)
        if not line or ":" not in line:
            continue
        label, value = line.split(":", 1)
        key = _metadata_key(label)
        value = " ".join(value.split())
        if key not in {
            "breach",
            "domain",
            "date",
            "breachedinfo",
            "breached_info",
            "data_types",
            "pwn_count",
            "fabricated",
            "verified",
            "retired",
            "spam",
        }:
            continue
        if key == "breach" and current:
            records.append(current)
            current = {}
        current[key] = value
    if current:
        records.append(current)
    return tuple(records)


def _pwnedornot_breach_finding(
    repository: str,
    target: ScanTarget,
    email: str,
    record: dict[str, str],
    seen: set[tuple[str, ...]],
) -> Finding | None:
    breach_name = record.get("breach", "")
    breach_domain = record.get("domain", "")
    breach_date = record.get("date", "")
    if not any((breach_name, breach_domain, breach_date)):
        return None

    metadata = _pwnedornot_metadata(repository, target, email, "breach")
    if breach_name:
        metadata["breach_name"] = breach_name
    if breach_domain:
        metadata["domain"] = breach_domain.lower()
    if breach_date:
        metadata["breach_date"] = breach_date
    data_classes = record.get("breachedinfo") or record.get("breached_info") or record.get("data_types")
    if data_classes:
        metadata["data_classes"] = data_classes.strip("[]")
    if record.get("pwn_count"):
        metadata["pwn_count"] = record["pwn_count"]
    for source_key, metadata_key in (
        ("fabricated", "extra_is_fabricated"),
        ("verified", "extra_is_verified"),
        ("retired", "extra_is_retired"),
        ("spam", "extra_is_spam_list"),
    ):
        if record.get(source_key):
            metadata[metadata_key] = record[source_key]

    return _pwnedornot_finding(
        repository=repository,
        target=target,
        status="candidate",
        confidence="high" if record.get("verified", "").lower() == "true" else "medium",
        evidence=f"pwnedOrNot HIBP breach: {breach_name or breach_domain} ({breach_date or 'date unknown'})",
        metadata=metadata,
        seen=seen,
        key=("pwnedornot", "breach", email.lower(), breach_name.lower(), breach_domain.lower(), breach_date),
    )


def _pwnedornot_credential_finding(
    repository: str,
    target: ScanTarget,
    email: str,
    text: str,
    seen: set[tuple[str, ...]],
) -> Finding | None:
    if not _pwnedornot_has_dump_signal(text):
        return None
    metadata = _pwnedornot_metadata(repository, target, email, "credential-exposure")
    metadata["sensitive_value_redacted"] = "true"
    metadata["credential_signal"] = "password_or_dump"
    return _pwnedornot_finding(
        repository=repository,
        target=target,
        status="candidate",
        confidence="high",
        evidence="pwnedOrNot dump/password signal observed; sensitive values redacted",
        metadata=metadata,
        seen=seen,
        key=("pwnedornot", "credential", email.lower()),
    )


def _pwnedornot_has_dump_signal(text: str) -> bool:
    for raw_line in text.splitlines():
        line = _strip_prefix(raw_line)
        lowered = line.lower()
        if "dumps found" in lowered and "no dumps found" not in lowered:
            return True
        if re.fullmatch(r"passwords\s*:", line, re.IGNORECASE):
            return True
    return False


def _pwnedornot_error_finding(
    repository: str,
    target: ScanTarget,
    email: str,
    text: str,
    seen: set[tuple[str, ...]],
) -> Finding | None:
    match = PWNEDORNOT_API_STATUS_RE.search(text)
    message = ""
    status_code = ""
    if match:
        status_code = match.group("code")
        message = _short(match.group("message"), 160)
    elif "Error :" in text:
        message = _short(text.split("Error :", 1)[1], 160)
    if not message:
        return None
    metadata = _pwnedornot_metadata(repository, target, email, "api-error")
    if status_code:
        metadata["status_code"] = status_code
    metadata["error_summary"] = message
    return _pwnedornot_finding(
        repository=repository,
        target=target,
        status="error",
        confidence="medium",
        evidence=f"pwnedOrNot API error{f' {status_code}' if status_code else ''}: {message}",
        metadata=metadata,
        seen=seen,
        key=("pwnedornot", "error", email.lower(), status_code, message.lower()),
    )


def _pwnedornot_metadata(repository: str, target: ScanTarget, email: str, category: str) -> dict[str, str]:
    metadata = {
        "repository": repository,
        "parser": "pwnedornot",
        "target_kind": target.kind,
        "category": category,
        "source_label": "haveibeenpwned",
    }
    if EMAIL_RE.fullmatch(email):
        metadata["email"] = email
        metadata["domain"] = email.rsplit("@", 1)[1].lower()
    return metadata


def _pwnedornot_finding(
    *,
    repository: str,
    target: ScanTarget,
    status: str,
    confidence: str,
    evidence: str,
    metadata: dict[str, str],
    seen: set[tuple[str, ...]],
    key: tuple[str, ...],
) -> Finding | None:
    if key in seen:
        return None
    seen.add(key)
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status=status,
        confidence=confidence,
        evidence=_short(evidence),
        metadata=metadata,
    )


PHONEINFOGA_SCALAR_KEYS = {
    "raw local": "raw_local",
    "raw_local": "raw_local",
    "local": "local",
    "local format": "local_format",
    "local_format": "local_format",
    "e164": "normalized",
    "international": "international",
    "international format": "normalized",
    "international_format": "normalized",
    "valid": "valid",
    "found": "found",
    "number": "phone_number",
    "phone": "phone",
    "country": "country",
    "country code": "country_code",
    "country_code": "country_code",
    "country name": "country",
    "country_name": "country",
    "country prefix": "country_prefix",
    "country_prefix": "country_prefix",
    "location": "location",
    "city": "location",
    "carrier": "carrier",
    "line type": "line_type",
    "line_type": "line_type",
    "number range": "number_range",
    "number_range": "number_range",
    "zip code": "zip_code",
    "zip_code": "zip_code",
    "homepage": "homepage",
    "results shown": "result_count",
    "result count": "result_count",
    "result_count": "result_count",
    "total number of results": "total_result_count",
    "total result count": "total_result_count",
    "total_result_count": "total_result_count",
    "requests made": "total_request_count",
    "total request count": "total_request_count",
    "total_request_count": "total_request_count",
}

PHONEINFOGA_GOOGLE_CATEGORIES = {
    "social_media",
    "disposable_providers",
    "reputation",
    "individuals",
    "general",
    "items",
}


def _phoneinfoga_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    structured = _phoneinfoga_json_findings(repository, target, text)
    if structured:
        return structured
    return _phoneinfoga_console_findings(repository, target, text)


def _phoneinfoga_json_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    payload = _load_json_payload(text)
    if payload is None:
        return ()

    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for scanner, result in _phoneinfoga_json_results(payload):
        if isinstance(result, str):
            finding = _phoneinfoga_error_finding(repository, target, scanner or "api", result, seen)
            if finding:
                findings.append(finding)
            continue
        findings.extend(_phoneinfoga_result_findings(repository, target, scanner, result, seen))
    return tuple(findings)


def _phoneinfoga_json_results(payload: object) -> list[tuple[str, object]]:
    if isinstance(payload, list):
        results: list[tuple[str, object]] = []
        for item in payload:
            results.extend(_phoneinfoga_json_results(item))
        return results
    if not isinstance(payload, dict):
        return []

    if payload.get("success") is False and payload.get("error"):
        return [("api", str(payload["error"]))]

    if "result" in payload:
        result = payload["result"]
        scanner = _first_scalar(payload.get("scanner") or payload.get("name"))
        return [(scanner or _phoneinfoga_infer_scanner(result), result)]

    scanner_names = {"local", "numverify", "googlesearch", "googlecse", "ovh"}
    keyed_results = [
        (str(key), value)
        for key, value in payload.items()
        if str(key).lower() in scanner_names and isinstance(value, (dict, list))
    ]
    if keyed_results:
        return keyed_results

    scanner = _first_scalar(payload.get("scanner") or payload.get("name"))
    if scanner and any(key in payload for key in ("data", "response", "result")):
        return [(scanner, payload.get("data") or payload.get("response") or payload.get("result"))]

    inferred = _phoneinfoga_infer_scanner(payload)
    return [(inferred, payload)] if inferred else []


def _phoneinfoga_infer_scanner(result: object) -> str:
    if not isinstance(result, dict):
        return ""
    keys = {_metadata_key(str(key)) for key in result}
    if keys & {"raw_local", "e164", "international"}:
        return "local"
    if keys & {"local_format", "international_format", "line_type", "country_prefix"}:
        return "numverify"
    if keys & {"social_media", "disposable_providers", "reputation", "individuals", "general"}:
        return "googlesearch"
    if keys & {"homepage", "result_count", "total_result_count", "total_request_count", "items"}:
        return "googlecse"
    if keys & {"number_range", "zip_code", "found", "city"}:
        return "ovh"
    return ""


def _phoneinfoga_result_findings(
    repository: str,
    target: ScanTarget,
    scanner: str,
    result: object,
    seen: set[tuple[str, str, str]],
) -> tuple[Finding, ...]:
    if isinstance(result, list):
        findings: list[Finding] = []
        for item in result:
            findings.extend(_phoneinfoga_result_findings(repository, target, scanner, item, seen))
        return tuple(findings)
    if not isinstance(result, dict):
        scalar = _first_scalar(result)
        if not scalar:
            return ()
        finding = _phoneinfoga_scalar_finding(repository, target, scanner or "api", "value", scalar, seen)
        return (finding,) if finding else ()

    normalized_scanner = (scanner or _phoneinfoga_infer_scanner(result) or "api").lower()
    findings: list[Finding] = []
    for key, value in result.items():
        normalized_key = _metadata_key(str(key))
        if isinstance(value, list):
            if normalized_key in PHONEINFOGA_GOOGLE_CATEGORIES:
                findings.extend(
                    _phoneinfoga_records_findings(repository, target, normalized_scanner, normalized_key, value, seen)
                )
            continue
        if isinstance(value, dict):
            if normalized_key in {"result", "data", "response"}:
                findings.extend(
                    _phoneinfoga_result_findings(repository, target, normalized_scanner, value, seen)
                )
            continue

        scalar = _first_scalar(value)
        if not scalar:
            continue
        if scalar.startswith(("http://", "https://")):
            finding = _phoneinfoga_url_finding(
                repository,
                target,
                normalized_scanner,
                _phoneinfoga_display_key(str(key)),
                scalar,
                seen,
                dork="",
                title="",
            )
        else:
            finding = _phoneinfoga_scalar_finding(
                repository,
                target,
                normalized_scanner,
                _phoneinfoga_display_key(str(key)),
                scalar,
                seen,
            )
        if finding:
            findings.append(finding)
    return tuple(findings)


def _phoneinfoga_records_findings(
    repository: str,
    target: ScanTarget,
    scanner: str,
    category: str,
    records: list[object],
    seen: set[tuple[str, str, str]],
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        url = _first_scalar(record.get("url") or record.get("link"))
        if not url:
            continue
        finding = _phoneinfoga_url_finding(
            repository,
            target,
            scanner,
            _phoneinfoga_display_key(category),
            url,
            seen,
            dork=_first_scalar(record.get("dork") or record.get("query")),
            title=_first_scalar(record.get("title")),
            number=_first_scalar(record.get("number")),
        )
        if finding:
            findings.append(finding)
    return tuple(findings)


def _phoneinfoga_console_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    scanner = ""
    category = ""
    in_errors = False

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith("running scan for phone number"):
            continue
        if re.fullmatch(r"\d+\s+scanner\(s\)\s+succeeded", stripped, re.IGNORECASE):
            continue

        if stripped.lower() == "the following scanners returned errors:":
            in_errors = True
            scanner = ""
            category = ""
            continue

        section = re.match(r"^Results for\s+(?P<scanner>.+)$", stripped, re.IGNORECASE)
        if section:
            in_errors = False
            scanner = section.group("scanner").strip().lower()
            category = ""
            continue

        if in_errors:
            error_match = re.match(r"^(?P<scanner>[^:]{2,80}):\s*(?P<error>.+)$", stripped)
            if error_match:
                finding = _phoneinfoga_error_finding(
                    repository,
                    target,
                    error_match.group("scanner").strip().lower(),
                    error_match.group("error").strip(),
                    seen,
                )
                if finding:
                    findings.append(finding)
            continue

        if stripped.endswith(":") and not URL_RE.search(stripped):
            category = _metadata_key(stripped[:-1])
            continue

        match = KEY_VALUE_RE.match(_strip_prefix(stripped))
        if match:
            raw_key = " ".join(match.group("key").split())
            value = match.group("value").strip()
            if raw_key.lower() == "url" and value.startswith(("http://", "https://")):
                finding = _phoneinfoga_url_finding(
                    repository,
                    target,
                    scanner or "cli",
                    _phoneinfoga_display_key(category or raw_key),
                    value,
                    seen,
                    dork="",
                    title="",
                )
            else:
                finding = _phoneinfoga_scalar_finding(
                    repository,
                    target,
                    scanner or "cli",
                    raw_key,
                    value,
                    seen,
                    category=category,
                )
            if finding:
                findings.append(finding)
            continue

        for url in URL_RE.findall(stripped):
            finding = _phoneinfoga_url_finding(
                repository,
                target,
                scanner or "cli",
                _phoneinfoga_display_key(category or "url"),
                url.rstrip(".,;"),
                seen,
                dork="",
                title="",
            )
            if finding:
                findings.append(finding)
    return tuple(findings)


def _phoneinfoga_scalar_finding(
    repository: str,
    target: ScanTarget,
    scanner: str,
    raw_key: str,
    value: str,
    seen: set[tuple[str, str, str]],
    *,
    category: str = "",
) -> Finding | None:
    value = value.strip()
    if not value or value.lower() in {"none", "not found", "unknown", "n/a"}:
        return None

    normalized_key = _metadata_key(raw_key).replace("_", " ")
    metadata_key = PHONEINFOGA_SCALAR_KEYS.get(normalized_key)
    if not metadata_key:
        metadata_key = f"phoneinfoga_{_metadata_key(raw_key)}"

    seen_key = ("phoneinfoga-kv", scanner.lower(), f"{metadata_key}:{value.lower()}")
    if seen_key in seen:
        return None
    seen.add(seen_key)

    metadata = {
        "repository": repository,
        "parser": "phoneinfoga",
        "scanner": scanner,
        "field": _phoneinfoga_display_key(raw_key),
        metadata_key: value,
    }
    if category:
        metadata["category"] = category
    if metadata_key == "phone_number" and value.startswith("+"):
        metadata["normalized"] = value
    elif metadata_key == "country_code" and re.fullmatch(r"[A-Za-z]{2}", value):
        metadata["country"] = value.upper()

    entity_keys = {
        "normalized",
        "country",
        "country_code",
        "carrier",
        "location",
        "line_type",
        "number_range",
        "zip_code",
    }
    status = "candidate" if set(metadata) & entity_keys else "observed"
    confidence = "medium" if status == "candidate" else "low"
    evidence = f"PhoneInfoga {scanner}: {_phoneinfoga_display_key(raw_key)}: {value}"
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status=status,
        confidence=confidence,
        evidence=_short(evidence),
        metadata=metadata,
    )


def _phoneinfoga_url_finding(
    repository: str,
    target: ScanTarget,
    scanner: str,
    category: str,
    url: str,
    seen: set[tuple[str, str, str]],
    *,
    dork: str = "",
    title: str = "",
    number: str = "",
) -> Finding | None:
    url = url.strip().rstrip(".,;")
    if not url.startswith(("http://", "https://")):
        return None
    seen_key = ("phoneinfoga-url", scanner.lower(), url.lower())
    if seen_key in seen:
        return None
    seen.add(seen_key)

    parsed = urlparse(url)
    metadata = {
        "repository": repository,
        "parser": "phoneinfoga",
        "scanner": scanner,
        "category": _metadata_key(category),
        "domain": (parsed.hostname or "").lower(),
    }
    if dork:
        metadata["dork"] = dork
    if title:
        metadata["title"] = title
    if number:
        metadata["phone_number"] = number
        if number.startswith("+"):
            metadata["normalized"] = number

    evidence_bits = [f"PhoneInfoga {scanner}", category]
    if title:
        evidence_bits.append(title)
    if dork:
        evidence_bits.append(dork)
    evidence_bits.append(url)
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status="candidate",
        url=url,
        confidence="medium",
        evidence=_short(": ".join(bit for bit in evidence_bits if bit)),
        metadata=metadata,
    )


def _phoneinfoga_error_finding(
    repository: str,
    target: ScanTarget,
    scanner: str,
    error: str,
    seen: set[tuple[str, str, str]],
) -> Finding | None:
    error = error.strip()
    if not error:
        return None
    seen_key = ("phoneinfoga-error", scanner.lower(), error.lower())
    if seen_key in seen:
        return None
    seen.add(seen_key)
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status="error",
        confidence="low",
        evidence=_short(f"PhoneInfoga {scanner}: {error}"),
        metadata={"repository": repository, "parser": "phoneinfoga", "scanner": scanner, "error": error},
    )


def _phoneinfoga_display_key(value: str) -> str:
    value = value.replace("_", " ").strip()
    return " ".join(value.split()).title()


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


def _sherlock_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    for row in _sherlock_csv_rows(text):
        finding = _sherlock_record_finding(repository, target, row, seen)
        if finding:
            findings.append(finding)

    for line in text.splitlines():
        compact = " ".join(line.split())
        if not compact:
            continue
        if compact.lower().startswith("total websites username detected on"):
            continue
        if _looks_like_sherlock_csv_line(compact):
            continue
        finding = _sherlock_line_finding(repository, target, compact, seen)
        if finding:
            findings.append(finding)
            continue
        findings.extend(_sherlock_txt_url_findings(repository, target, compact, seen))
    return tuple(findings)


def _sherlock_csv_rows(text: str) -> tuple[dict[str, str], ...]:
    lines = [line for line in text.strip("\ufeff \n\t").splitlines() if line.strip()]
    header_index = -1
    for index, line in enumerate(lines):
        normalized = line.strip("\ufeff ").lower()
        if normalized.startswith("username,name,url_main,url_user,exists,http_status,response_time_s"):
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


def _looks_like_sherlock_csv_line(line: str) -> bool:
    lowered = line.strip("\ufeff ").lower()
    if lowered.startswith("username,name,url_main,url_user,exists,http_status,response_time_s"):
        return True
    return line.count(",") >= 6 and "://" in line


def _sherlock_record_finding(
    repository: str,
    target: ScanTarget,
    row: dict[str, str],
    seen: set[tuple[str, str, str]],
) -> Finding | None:
    site_name = _csv_row_value(row, "name")
    identity = _csv_row_value(row, "username") or target.value
    url = _csv_row_value(row, "url_user")
    site_url = _csv_row_value(row, "url_main")
    raw_status = _csv_row_value(row, "exists")
    http_status = _csv_row_value(row, "http_status")
    response_time_s = _csv_row_value(row, "response_time_s")
    if not site_name and not url and not raw_status:
        return None
    return _sherlock_finding(
        repository=repository,
        target=target,
        site_name=site_name,
        identity=identity,
        raw_status=raw_status,
        url=url,
        site_url=site_url,
        http_status=http_status,
        response_time_s=response_time_s,
        evidence="",
        seen=seen,
    )


def _sherlock_line_finding(
    repository: str,
    target: ScanTarget,
    line: str,
    seen: set[tuple[str, str, str]],
) -> Finding | None:
    match = SHERLOCK_LINE_RE.match(_strip_prefix(line))
    if not match:
        return None

    site_name = " ".join(match.group("site").split()).strip()
    rest = match.group("rest").strip()
    marker = (match.group("marker") or "").strip()
    if not site_name or site_name.lower() in {"checking username", "search completed with"}:
        return None

    raw_status = _sherlock_status_from_line(marker, rest)
    url = rest if rest.startswith(("http://", "https://")) else ""
    return _sherlock_finding(
        repository=repository,
        target=target,
        site_name=site_name,
        identity=target.value,
        raw_status=raw_status,
        url=url,
        site_url="",
        http_status="",
        response_time_s="",
        evidence=line,
        seen=seen,
    )


def _sherlock_txt_url_findings(
    repository: str,
    target: ScanTarget,
    line: str,
    seen: set[tuple[str, str, str]],
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for raw_url in URL_RE.findall(line):
        url = raw_url.rstrip(".,;")
        finding = _sherlock_finding(
            repository=repository,
            target=target,
            site_name=(urlparse(url).hostname or "").lower(),
            identity=target.value,
            raw_status="Claimed",
            url=url,
            site_url="",
            http_status="",
            response_time_s="",
            evidence=line,
            seen=seen,
        )
        if finding:
            findings.append(finding)
    return tuple(findings)


def _sherlock_finding(
    *,
    repository: str,
    target: ScanTarget,
    site_name: str,
    identity: str,
    raw_status: str,
    url: str,
    site_url: str,
    http_status: str,
    response_time_s: str,
    evidence: str,
    seen: set[tuple[str, str, str]],
) -> Finding | None:
    normalized_status = _sherlock_normalize_status(raw_status)
    status, confidence = _sherlock_status(normalized_status)
    finding_url = url if status == "candidate" and url.startswith(("http://", "https://")) else ""
    if finding_url:
        url_key = ("sherlock-url", identity.lower(), finding_url.lower())
        if url_key in seen:
            return None
        seen.add(url_key)
    key = ("sherlock", site_name.lower(), identity.lower(), normalized_status.lower(), (url or site_url).lower())
    if key in seen:
        return None
    seen.add(key)

    metadata = _sherlock_metadata(
        repository=repository,
        site_name=site_name,
        raw_status=normalized_status,
        identity=identity,
        url=finding_url,
        checked_url="" if finding_url else url,
        site_url=site_url,
        http_status=http_status,
        response_time_s=response_time_s,
    )
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status=status,
        url=finding_url,
        confidence=confidence,
        evidence=_short(evidence or _sherlock_evidence(site_name, normalized_status, url)),
        metadata=metadata,
    )


def _sherlock_status_from_line(marker: str, value: str) -> str:
    normalized = " ".join(value.lower().strip(" !").split())
    if value.startswith(("http://", "https://")) or marker == "+":
        return "Claimed"
    if "not found" in normalized:
        return "Available"
    if "illegal username" in normalized:
        return "Illegal"
    if "blocked by bot detection" in normalized or "waf" in normalized:
        return "WAF"
    return "Unknown"


def _sherlock_normalize_status(raw_status: str) -> str:
    normalized = " ".join(str(raw_status).strip(" !").split())
    lowered = normalized.lower()
    if lowered in {"claimed", "found", "true"}:
        return "Claimed"
    if lowered in {"available", "not found", "false"}:
        return "Available"
    if lowered in {"illegal", "illegal username format for this site"}:
        return "Illegal"
    if lowered in {"waf", "blocked by bot detection"}:
        return "WAF"
    if lowered in {"unknown", "error"}:
        return "Unknown"
    return normalized or "Unknown"


def _sherlock_status(raw_status: str) -> tuple[str, str]:
    normalized = raw_status.lower()
    if normalized == "claimed":
        return "candidate", "high"
    if normalized == "available":
        return "not_found", "medium"
    if normalized == "illegal":
        return "skipped", "high"
    if normalized == "waf":
        return "error", "low"
    if normalized == "unknown":
        return "error", "low"
    return "observed", "medium"


def _sherlock_metadata(
    *,
    repository: str,
    site_name: str,
    raw_status: str,
    identity: str,
    url: str,
    checked_url: str,
    site_url: str,
    http_status: str,
    response_time_s: str,
) -> dict[str, str]:
    metadata = {
        "repository": repository,
        "parser": "sherlock",
        "raw_status": raw_status,
        "username": identity,
    }
    if site_name:
        metadata["site_name"] = site_name
    if url:
        metadata["url"] = url
        domain = (urlparse(url).hostname or "").lower()
        if domain:
            metadata["domain"] = domain
    if checked_url:
        metadata["checked_url"] = checked_url
    if site_url:
        metadata["site_url"] = site_url
    if http_status:
        metadata["http_status"] = http_status
    if response_time_s:
        metadata["response_time_s"] = response_time_s
    return metadata


def _sherlock_evidence(site_name: str, raw_status: str, url: str) -> str:
    evidence = f"Sherlock {site_name or 'site'}: {raw_status or 'observed'}"
    if url:
        evidence += f" {url}"
    return evidence


def _nexfil_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    report_metadata = _nexfil_report_metadata(text, target.value)
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    summary = _nexfil_summary_finding(repository, target, report_metadata, seen)
    if summary:
        findings.append(summary)

    in_report_urls = False
    for line in text.splitlines():
        compact = " ".join(line.split()).strip()
        if not compact:
            continue
        if compact.lower().startswith("urls"):
            in_report_urls = True
            continue
        if in_report_urls and set(compact) <= {"-"}:
            in_report_urls = False
            continue

        if not compact.startswith(("http://", "https://")):
            continue
        for raw_url in URL_RE.findall(compact):
            finding = _nexfil_url_finding(
                repository=repository,
                target=target,
                url=raw_url.rstrip(".,;"),
                username=report_metadata.get("username", target.value),
                report_metadata=report_metadata,
                seen=seen,
            )
            if finding:
                findings.append(finding)
    return tuple(findings)


def _nexfil_report_metadata(text: str, target_value: str) -> dict[str, str]:
    metadata: dict[str, str] = {"username": target_value}
    key_map = {
        "username": "username",
        "total hits": "total_hits",
        "total profiles found": "total_hits",
        "total timeouts": "total_timeouts",
        "total errors": "total_errors",
        "total exceptions": "total_errors",
    }
    for line in text.splitlines():
        match = KEY_VALUE_RE.match(_strip_prefix(line))
        if not match:
            continue
        key = " ".join(match.group("key").lower().split())
        mapped = key_map.get(key)
        if not mapped:
            continue
        value = match.group("value").strip()
        if mapped == "username" and "," in value:
            metadata["usernames"] = value
        elif value:
            metadata[mapped] = value
    return metadata


def _nexfil_summary_finding(
    repository: str,
    target: ScanTarget,
    report_metadata: dict[str, str],
    seen: set[tuple[str, str, str]],
) -> Finding | None:
    metric_keys = ("total_hits", "total_timeouts", "total_errors")
    if not any(report_metadata.get(key) for key in metric_keys):
        return None
    seen_key = ("nexfil-summary", target.value.lower(), "")
    if seen_key in seen:
        return None
    seen.add(seen_key)
    metadata = {
        "repository": repository,
        "parser": "nexfil",
        **{key: value for key, value in report_metadata.items() if value},
    }
    evidence = "Nexfil report: " + ", ".join(
        f"{key.replace('_', ' ')}={report_metadata[key]}" for key in metric_keys if report_metadata.get(key)
    )
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status="observed",
        confidence="medium",
        evidence=_short(evidence),
        metadata=metadata,
    )


def _nexfil_url_finding(
    *,
    repository: str,
    target: ScanTarget,
    url: str,
    username: str,
    report_metadata: dict[str, str],
    seen: set[tuple[str, str, str]],
) -> Finding | None:
    if not url.startswith(("http://", "https://")):
        return None
    seen_key = ("nexfil-url", username.lower(), url.lower())
    if seen_key in seen:
        return None
    seen.add(seen_key)

    parsed = urlparse(url)
    domain = (parsed.hostname or "").lower()
    metadata = {
        "repository": repository,
        "parser": "nexfil",
        "username": username,
        "domain": domain,
        "site_name": domain,
        "url": url,
    }
    for key in ("total_hits", "total_timeouts", "total_errors"):
        if report_metadata.get(key):
            metadata[key] = report_metadata[key]

    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status="candidate",
        url=url,
        confidence="high",
        evidence=_short(f"Nexfil found profile: {url}"),
        metadata=metadata,
    )


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


def _social_analyzer_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    payload = _load_json_payload(text)
    if isinstance(payload, dict):
        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        for group in ("detected", "unknown", "failed"):
            records = payload.get(group)
            if not isinstance(records, list):
                continue
            for record in records:
                if not isinstance(record, dict):
                    continue
                finding = _social_analyzer_record_finding(repository, target, record, group, seen)
                if finding:
                    findings.append(finding)
        return tuple(findings)

    findings = []
    seen_lines: set[tuple[str, str, str]] = set()
    for line in text.splitlines():
        compact = " ".join(line.split())
        if not compact:
            continue
        findings.extend(_url_findings(repository, target, compact, seen_lines))
    return tuple(findings)


def _social_analyzer_record_finding(
    repository: str,
    target: ScanTarget,
    record: dict[str, Any],
    group: str,
    seen: set[tuple[str, str, str]],
) -> Finding | None:
    profile_url = _first_scalar(record.get("link") or record.get("url") or record.get("profile_url"))
    checked_url = profile_url if profile_url.startswith(("http://", "https://")) else ""
    site_name = _social_analyzer_site_name(record, checked_url)
    raw_status = _first_scalar(record.get("status"))
    rate = _first_scalar(record.get("rate"))
    status, confidence = _social_analyzer_status(group, raw_status, rate)
    finding_url = checked_url if status == "candidate" else ""

    if not site_name and not checked_url and not raw_status:
        return None

    key = (group, site_name.lower(), checked_url.lower() or json.dumps(record, sort_keys=True, default=str))
    if key in seen:
        return None
    seen.add(key)

    metadata = _social_analyzer_metadata(
        repository=repository,
        target=target,
        record=record,
        group=group,
        raw_status=raw_status,
        rate=rate,
        site_name=site_name,
        profile_url=finding_url,
        checked_url="" if finding_url else checked_url,
    )
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status=status,
        url=finding_url,
        confidence=confidence,
        evidence=_short(_social_analyzer_evidence(site_name, group, raw_status, rate)),
        metadata=metadata,
    )


def _social_analyzer_metadata(
    *,
    repository: str,
    target: ScanTarget,
    record: dict[str, Any],
    group: str,
    raw_status: str,
    rate: str,
    site_name: str,
    profile_url: str,
    checked_url: str,
) -> dict[str, str]:
    metadata = {
        "repository": repository,
        "parser": "social-analyzer",
        "target_kind": target.kind,
        "profile_group": group,
    }
    if site_name:
        metadata["site_name"] = site_name
    if raw_status:
        metadata["result_status"] = raw_status
    if rate:
        metadata["rate"] = rate
    if target.kind == "username":
        metadata["social_username"] = target.value.strip().lstrip("@")
    url = profile_url or checked_url
    domain = (urlparse(url).hostname or "").lower()
    if domain:
        metadata["platform_domain"] = domain
    if checked_url:
        metadata["checked_url"] = checked_url
    for source_key, metadata_key in (
        ("title", "title"),
        ("language", "language"),
        ("type", "profile_type"),
        ("country", "country"),
    ):
        value = _first_scalar(record.get(source_key))
        if value:
            metadata[metadata_key] = value
    extracted = _metadata_list_text(record.get("extracted"))
    if extracted:
        metadata["extracted"] = extracted
    metadata_count = _social_analyzer_metadata_count(record.get("metadata"))
    if metadata_count:
        metadata["metadata_count"] = metadata_count
    return metadata


def _social_analyzer_status(group: str, raw_status: str, rate: str) -> tuple[str, str]:
    normalized_status = raw_status.strip().lower()
    if group == "failed":
        return "error", "low"
    if group == "unknown":
        return "not_found", "medium"
    if normalized_status == "good":
        return "candidate", "high"
    if normalized_status == "maybe":
        return "candidate", "medium"
    if normalized_status == "bad":
        return "candidate", "low"
    numeric_rate = _social_analyzer_rate_number(rate)
    if numeric_rate is not None:
        if numeric_rate >= 90:
            return "candidate", "high"
        if numeric_rate >= 50:
            return "candidate", "medium"
        return "candidate", "low"
    if group == "detected":
        return "candidate", "medium"
    return "observed", "medium"


def _social_analyzer_rate_number(rate: str) -> float | None:
    cleaned = rate.strip().strip("%")
    if not cleaned:
        return None
    try:
        return float(cleaned)
    except ValueError:
        return None


def _social_analyzer_site_name(record: dict[str, Any], url: str) -> str:
    for key in ("site", "site_name", "name", "website"):
        value = _first_scalar(record.get(key))
        if value:
            return value
    hostname = (urlparse(url).hostname or "").lower()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname


def _social_analyzer_metadata_count(value: object) -> str:
    if isinstance(value, (list, tuple, dict)):
        return str(len(value))
    return ""


def _social_analyzer_evidence(site_name: str, group: str, raw_status: str, rate: str) -> str:
    label = site_name or "profile"
    details = [detail for detail in (raw_status, rate) if detail]
    suffix = f" ({', '.join(details)})" if details else ""
    return f"Social Analyzer {group}: {label}{suffix}"


def _blackbird_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for record in _blackbird_json_records(text):
        finding = _blackbird_record_finding(repository, target, record, seen)
        if finding:
            findings.append(finding)

    for line in text.splitlines():
        compact = " ".join(line.split())
        if not compact:
            continue
        finding = _blackbird_stdout_finding(repository, target, compact, seen)
        if finding:
            findings.append(finding)

    if findings:
        return tuple(findings)

    fallback: list[Finding] = []
    fallback_seen: set[tuple[str, str, str]] = set()
    for line in text.splitlines():
        compact = " ".join(line.split())
        if compact:
            fallback.extend(_url_findings(repository, target, compact, fallback_seen))
    return tuple(fallback)


def _blackbird_json_records(text: str) -> tuple[dict[str, Any], ...]:
    records: list[dict[str, Any]] = []
    starts = [0]
    starts.extend(match.start() for match in re.finditer(r"(?m)^\s*[\[{]", text))
    for start in _dedupe_numbers(starts):
        payload = _load_json_payload(text[start:])
        records.extend(_blackbird_records(payload))

    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        key = json.dumps(record, sort_keys=True, ensure_ascii=False, default=str)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(record)
    return tuple(deduped)


def _blackbird_records(payload: object | None) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        if any(key in payload for key in ("url", "name", "status", "metadata")):
            return [payload]
        records: list[dict[str, Any]] = []
        for key in ("results", "data", "accounts"):
            nested = payload.get(key)
            if isinstance(nested, (list, tuple)):
                records.extend(_blackbird_records(list(nested)))
        return records
    if isinstance(payload, list):
        records = []
        for item in payload:
            if isinstance(item, dict):
                records.extend(_blackbird_records(item))
        return records
    return []


def _blackbird_record_finding(
    repository: str,
    target: ScanTarget,
    record: dict[str, Any],
    seen: set[tuple[str, str, str]],
) -> Finding | None:
    site_name = _first_scalar(record.get("name") or record.get("site") or record.get("site_name"))
    url = _first_scalar(record.get("url") or record.get("profile_url") or record.get("uri"))
    raw_status = _first_scalar(record.get("status")) or ("FOUND" if url else "")
    status, confidence = _blackbird_status(raw_status)
    if not site_name and not url and not raw_status:
        return None

    is_profile_url = url.startswith(("http://", "https://"))
    finding_url = url if is_profile_url and status == "candidate" else ""
    checked_url = url if is_profile_url and status != "candidate" else ""
    key = ("blackbird", site_name.lower(), (finding_url or checked_url).lower())
    if key in seen:
        return None
    seen.add(key)

    metadata = _blackbird_metadata(
        repository=repository,
        target=target,
        record=record,
        site_name=site_name,
        raw_status=raw_status,
        profile_url=finding_url,
        checked_url=checked_url,
    )
    return Finding(
        module="external-adapter-parser",
        source=repository,
        target=target.value,
        status=status,
        url=finding_url,
        confidence=confidence,
        evidence=_short(_blackbird_evidence(site_name, raw_status, finding_url or checked_url)),
        metadata=metadata,
    )


def _blackbird_stdout_finding(
    repository: str,
    target: ScanTarget,
    line: str,
    seen: set[tuple[str, str, str]],
) -> Finding | None:
    match = re.search(
        r"(?:✔|✓|FOUND:?|\[\+\]).*?\[(?P<site>[^\]]{2,100})\]\s+(?P<url>https?://\S+)",
        line,
        re.IGNORECASE,
    )
    if not match:
        return None
    record = {
        "name": match.group("site").strip(),
        "url": match.group("url").rstrip(".,;"),
        "status": "FOUND",
    }
    return _blackbird_record_finding(repository, target, record, seen)


def _blackbird_metadata(
    *,
    repository: str,
    target: ScanTarget,
    record: dict[str, Any],
    site_name: str,
    raw_status: str,
    profile_url: str,
    checked_url: str,
) -> dict[str, str]:
    metadata = {
        "repository": repository,
        "parser": "blackbird",
        "target_kind": target.kind,
    }
    if site_name:
        metadata["site_name"] = site_name
    if raw_status:
        metadata["result_status"] = raw_status
    category = _first_scalar(record.get("category") or record.get("cat"))
    if category:
        metadata["category"] = category
    url = profile_url or checked_url
    domain = (urlparse(url).hostname or "").lower()
    if domain:
        metadata["platform_domain"] = domain
    if checked_url:
        metadata["checked_url"] = checked_url
    if target.kind == "username":
        metadata["social_username"] = target.value.strip().lstrip("@")
    elif target.kind == "email":
        metadata["email"] = target.value.strip()
    _merge_blackbird_metadata_items(metadata, record.get("metadata"))
    return metadata


def _merge_blackbird_metadata_items(metadata: dict[str, str], items: object) -> None:
    metadata_text = _metadata_list_text(items)
    if metadata_text:
        metadata["blackbird_metadata"] = metadata_text
    for item in _blackbird_metadata_items(items):
        label = _first_scalar(item.get("name") or item.get("key") or item.get("label"))
        value = _metadata_list_text(item.get("value"))
        if not label or not value:
            continue
        normalized = _metadata_key(label)
        mapped_key = {
            "name": "name",
            "full_name": "name",
            "display_name": "name",
            "username": "username",
            "location": "location",
            "country": "country",
            "email": "email",
            "phone": "phone",
            "profile_image": "profile_image_url",
            "profile_image_url": "profile_image_url",
            "avatar": "profile_image_url",
            "image": "profile_image_url",
        }.get(normalized)
        if mapped_key and mapped_key not in metadata:
            metadata[mapped_key] = value


def _blackbird_metadata_items(items: object) -> tuple[dict[Any, Any], ...]:
    if isinstance(items, dict):
        return (items,)
    if isinstance(items, (list, tuple)):
        return tuple(item for item in items if isinstance(item, dict))
    return ()


def _blackbird_status(raw_status: str) -> tuple[str, str]:
    normalized = " ".join(raw_status.lower().replace("_", "-").split())
    if normalized in {"found", "exists", "claimed", "candidate"}:
        return "candidate", "high"
    if normalized in {"not-found", "not found", "available", "missing"}:
        return "not_found", "medium"
    if normalized in {"error", "failed", "timeout"}:
        return "error", "low"
    if normalized in {"none", ""}:
        return "observed", "low"
    return "observed", "medium"


def _blackbird_evidence(site_name: str, raw_status: str, url: str) -> str:
    label = site_name or "site"
    suffix = f" {url}" if url else ""
    return f"Blackbird {label}: {raw_status or 'observed'}{suffix}"


def _detectdee_findings(repository: str, target: ScanTarget, text: str) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for line in text.splitlines():
        compact = " ".join(line.split())
        if not compact:
            continue
        match = DETECTDEE_RESULT_RE.match(compact) or DETECTDEE_STDOUT_RE.search(compact)
        if not match:
            continue
        identity = _detectdee_clean_identity(match.group("identity"))
        site_name = " ".join(match.group("site").split())
        url = _detectdee_clean_url(match.group("url"))
        if not identity or not site_name or not url:
            continue
        key = (identity.lower(), site_name.lower(), url.lower())
        if key in seen:
            continue
        seen.add(key)
        metadata = {
            "repository": repository,
            "parser": "detectdee",
            "site_name": site_name,
            "identity": identity,
            "profile_url": url,
            "target_kind": target.kind,
        }
        if target.kind in {"username", "email", "phone"}:
            metadata[target.kind] = identity
        findings.append(
            Finding(
                module="external-adapter-parser",
                source=repository,
                target=target.value,
                status="candidate",
                url=url,
                confidence="medium",
                evidence=f"DetectDee found {identity} on {site_name}: {url}",
                metadata=metadata,
            )
        )
    return tuple(findings)


def _detectdee_clean_identity(value: str) -> str:
    return " ".join(value.strip().strip(",").split())


def _detectdee_clean_url(value: str) -> str:
    return value.strip().rstrip(".,;)")


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


def _json_records(text: str) -> tuple[dict[str, Any], ...]:
    records: list[dict[str, Any]] = []
    payload = _load_json_payload(text)
    records.extend(_payload_records(payload))

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(("{", "[")):
            candidate = stripped
        else:
            start = stripped.find("{")
            end = stripped.rfind("}")
            if start == -1 or end <= start:
                continue
            candidate = stripped[start : end + 1]
        try:
            line_payload = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        records.extend(_payload_records(line_payload))

    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        key = json.dumps(record, sort_keys=True, ensure_ascii=False, default=str)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(record)
    return tuple(deduped)


def _payload_records(payload: object | None) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        if any(key in payload for key in ("url", "host", "name", "subdomain", "fqdn", "domain", "status_code")):
            return [payload]
        records: list[dict[str, Any]] = []
        for key in ("results", "data", "hosts", "subdomains"):
            nested = payload.get(key)
            if isinstance(nested, (list, tuple)):
                records.extend(_payload_records(list(nested)))
        return records
    if isinstance(payload, list):
        records = []
        for item in payload:
            if isinstance(item, dict):
                records.extend(_payload_records(item))
        return records
    return []


def _target_domain(target: ScanTarget) -> str:
    if target.kind == "domain":
        return _normalize_hostname(target.value)
    if target.kind == "url":
        return _normalize_hostname(target.value)
    return ""


def _normalize_hostname(value: str) -> str:
    raw = (value or "").strip().strip("[](){}<>\"'")
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.hostname or ""
    else:
        if "/" in raw:
            parsed = urlparse(f"//{raw}")
            raw = parsed.hostname or raw.split("/", 1)[0]
        if ":" in raw and raw.count(":") == 1:
            raw = raw.rsplit(":", 1)[0]
    raw = raw.strip().strip(".").lower()
    if raw.startswith("*."):
        raw = raw[2:]
    if not HOSTNAME_RE.fullmatch(raw):
        return ""
    return raw


def _hostnames_from_text(text: str) -> tuple[str, ...]:
    seen: set[str] = set()
    hosts: list[str] = []
    for match in HOSTNAME_RE.findall(text):
        host = _normalize_hostname(match)
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)
    return tuple(hosts)


def _httpx_record_url(record: dict[str, Any]) -> str:
    raw_url = _first_scalar(record.get("url") or record.get("final_url") or record.get("input"))
    if raw_url.startswith(("http://", "https://")):
        return raw_url

    host = _normalize_hostname(raw_url) or _normalize_hostname(_first_scalar(record.get("host")))
    if not host:
        return ""
    scheme = _first_scalar(record.get("scheme")).lower()
    if scheme not in {"http", "https"}:
        scheme = "https"
    return f"{scheme}://{host}"


def _http_status_from_line(line: str) -> int | None:
    bracketed = re.search(r"\[(?P<status>[1-5]\d\d)\]", line)
    if bracketed:
        return int(bracketed.group("status"))
    bare = re.search(r"\b(?P<status>[1-5]\d\d)\b", line)
    if bare:
        return int(bare.group("status"))
    return None


def _set_metadata(metadata: dict[str, str], key: str, value: str) -> None:
    compact = " ".join(str(value).split())
    if compact:
        metadata[key] = compact


def _metadata_list_text(value: object) -> str:
    values: list[str] = []

    def add(item: object) -> None:
        if isinstance(item, dict):
            for nested_key in ("ip", "address", "host", "name", "source", "value"):
                if nested_key in item:
                    add(item[nested_key])
            return
        if isinstance(item, (list, tuple, set)):
            for nested in item:
                add(nested)
            return
        scalar = _first_scalar(item)
        if scalar:
            values.append(scalar)

    add(value)
    return ", ".join(_dedupe_text(values))


def _int_value(value: object) -> int | None:
    scalar = _first_scalar(value)
    if not scalar:
        return None
    match = re.search(r"\d+", scalar)
    if not match:
        return None
    try:
        return int(match.group(0))
    except ValueError:
        return None


def _truthy(value: object) -> bool:
    scalar = _first_scalar(value).lower()
    return scalar in {"1", "true", "yes", "y", "failed", "failure", "error"}


def _dedupe_text(values: list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        compact = " ".join(value.split())
        key = compact.lower()
        if compact and key not in seen:
            seen.add(key)
            deduped.append(compact)
    return tuple(deduped)


def _dedupe_numbers(values: list[int]) -> tuple[int, ...]:
    seen: set[int] = set()
    deduped: list[int] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return tuple(deduped)


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
