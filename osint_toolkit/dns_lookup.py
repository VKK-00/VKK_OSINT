from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class DnsLookupResult:
    domain: str
    record_type: str
    status: str
    records: tuple[str, ...] = ()
    error: str = ""
    raw_excerpt: str = ""

    def evidence(self) -> str:
        if self.records:
            return f"Resolved {len(self.records)} {self.record_type} record(s)."
        if self.error:
            return self.error
        return f"No {self.record_type} records found."


def lookup_dns_records(domain: str, record_type: str, *, timeout: float = 10.0) -> DnsLookupResult:
    normalized_type = record_type.strip().upper()
    if normalized_type not in {"MX", "TXT"}:
        raise ValueError(f"Unsupported DNS record type: {record_type}")

    command = ("nslookup", f"-type={normalized_type}", domain)
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return DnsLookupResult(
            domain=domain,
            record_type=normalized_type,
            status="missing",
            error="nslookup executable is not available on PATH.",
        )
    except subprocess.TimeoutExpired:
        return DnsLookupResult(
            domain=domain,
            record_type=normalized_type,
            status="timeout",
            error=f"nslookup timed out after {timeout} seconds.",
        )

    output = "\n".join(part for part in (result.stdout, result.stderr) if part)
    records = parse_nslookup_records(output, normalized_type)
    if records:
        return DnsLookupResult(
            domain=domain,
            record_type=normalized_type,
            status="candidate",
            records=records,
            raw_excerpt=_excerpt(output),
        )

    status = "not_found" if result.returncode == 0 else "error"
    error = _dns_error(output) or f"nslookup returned exit code {result.returncode}."
    return DnsLookupResult(
        domain=domain,
        record_type=normalized_type,
        status=status,
        error=error,
        raw_excerpt=_excerpt(output),
    )


def parse_nslookup_records(output: str, record_type: str) -> tuple[str, ...]:
    normalized_type = record_type.strip().upper()
    if normalized_type == "MX":
        return _parse_mx_records(output)
    if normalized_type == "TXT":
        return _parse_txt_records(output)
    raise ValueError(f"Unsupported DNS record type: {record_type}")


def _parse_mx_records(output: str) -> tuple[str, ...]:
    records: list[str] = []
    for line in _content_lines(output):
        lowered = line.lower()
        if "mail exchanger" not in lowered:
            continue
        host_match = re.search(r"mail exchanger\s*=\s*(?:(?P<priority>\d+)\s+)?(?P<host>\S+)", line, flags=re.IGNORECASE)
        if not host_match:
            continue
        preference_match = re.search(r"(?:mx preference|preference)\s*=\s*(?P<preference>\d+)", line, flags=re.IGNORECASE)
        host = host_match.group("host").rstrip(".")
        priority = preference_match.group("preference") if preference_match else host_match.group("priority")
        if priority:
            records.append(f"{priority} {host}")
        else:
            records.append(host)
    return _dedupe(records)


def _parse_txt_records(output: str) -> tuple[str, ...]:
    records: list[str] = []
    pending_text_block = False
    for line in _content_lines(output):
        lowered = line.lower()
        if "text =" in lowered:
            pending_text_block = True
            value = line.split("=", 1)[1].strip()
            records.extend(_quoted_or_plain_text(value))
            continue
        if pending_text_block and line.startswith('"'):
            records.extend(_quoted_or_plain_text(line))
            continue
        pending_text_block = False
    return _dedupe(records)


def _quoted_or_plain_text(value: str) -> tuple[str, ...]:
    quoted = tuple(match.group(1).strip() for match in re.finditer(r'"([^"]*)"', value) if match.group(1).strip())
    if quoted:
        return quoted
    stripped = value.strip().strip('"')
    return (stripped,) if stripped else ()


def _content_lines(output: str) -> tuple[str, ...]:
    ignored_prefixes = ("server:", "address:", "name:", "aliases:")
    lines: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if any(lowered.startswith(prefix) for prefix in ignored_prefixes):
            continue
        lines.append(line)
    return tuple(lines)


def _dns_error(output: str) -> str:
    for line in _content_lines(output):
        lowered = line.lower()
        if any(marker in lowered for marker in ("can't find", "non-existent", "no answer", "nxdomain")):
            return line
    return ""


def _dedupe(values: list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        normalized = " ".join(value.split())
        key = normalized.lower()
        if normalized and key not in seen:
            seen.add(key)
            deduped.append(normalized)
    return tuple(deduped)


def _excerpt(value: str, limit: int = 800) -> str:
    compact = " ".join(value.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1] + "…"
