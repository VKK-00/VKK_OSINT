from __future__ import annotations

import re
from urllib.parse import urlparse

from .engine import Finding, ScanTarget

URL_RE = re.compile(r"https?://[^\s<>\]\)\"']+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"\+[1-9]\d{7,14}\b")
KEY_VALUE_RE = re.compile(r"^\s*(?P<key>[A-Za-z][A-Za-z0-9 _./-]{1,40})\s*[:=]\s*(?P<value>.+?)\s*$")
SOCIAL_LINE_RE = re.compile(r"^\s*(?:\[[+*]\]|\+|FOUND:?)?\s*(?P<label>[A-Za-z0-9_. /-]{2,40})\s*[:|-]\s*(?P<rest>.+)$")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

PARSER_REPOSITORIES = {
    "sherlock-project/sherlock",
    "soxoj/maigret",
    "thewhiteh4t/nexfil",
    "snooppr/snoop",
    "alpkeskin/mosint",
    "sundowndev/phoneinfoga",
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
