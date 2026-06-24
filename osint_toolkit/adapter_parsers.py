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
    sensitive_tokens = {"PASSWORD", "PASS", "PWD", "HASH", "HASHSALT", "MD5", "SALT", "TOKEN", "SECRET", "KEY"}
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
