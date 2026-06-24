from __future__ import annotations

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
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

PARSER_REPOSITORIES = {
    "sherlock-project/sherlock",
    "soxoj/maigret",
    "thewhiteh4t/nexfil",
    "snooppr/snoop",
    "alpkeskin/mosint",
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
