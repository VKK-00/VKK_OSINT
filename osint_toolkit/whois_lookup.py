from __future__ import annotations

import socket
from dataclasses import dataclass

WHOIS_RESPONSE_LIMIT = 131_072

WHOIS_SERVERS = {
    "app": "whois.nic.google",
    "ai": "whois.nic.ai",
    "biz": "whois.biz",
    "co": "whois.nic.co",
    "com": "whois.verisign-grs.com",
    "dev": "whois.nic.google",
    "info": "whois.afilias.net",
    "io": "whois.nic.io",
    "kz": "whois.nic.kz",
    "me": "whois.nic.me",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "ru": "whois.tcinet.ru",
    "su": "whois.tcinet.ru",
    "ua": "whois.ua",
}

NO_MATCH_MARKERS = (
    "no match for",
    "not found",
    "no data found",
    "no entries found",
    "object does not exist",
    "domain not found",
)


@dataclass(frozen=True)
class WhoisDomainRecord:
    domain: str
    server: str
    referral_server: str = ""
    registrar: str = ""
    statuses: tuple[str, ...] = ()
    nameservers: tuple[str, ...] = ()
    created_at: str = ""
    updated_at: str = ""
    expires_at: str = ""
    raw_line_count: int = 0
    found: bool = False
    error: str = ""


def lookup_whois_domain(domain: str, *, timeout: float = 10.0) -> WhoisDomainRecord:
    normalized_domain = domain.strip().lower().strip(".")
    server = whois_server_for_domain(normalized_domain)
    if not server:
        return WhoisDomainRecord(
            domain=normalized_domain,
            server="",
            error="No WHOIS server mapping for this top-level domain.",
        )

    try:
        raw_text = _query_whois(server, normalized_domain, timeout=timeout)
    except OSError as exc:
        return WhoisDomainRecord(domain=normalized_domain, server=server, error=str(exc))

    record = parse_whois_domain_record(raw_text, normalized_domain, server=server)
    referral = record.referral_server
    if referral and referral.lower() != server.lower():
        try:
            referral_text = _query_whois(referral, normalized_domain, timeout=timeout)
        except OSError:
            return record
        referral_record = parse_whois_domain_record(
            referral_text,
            normalized_domain,
            server=server,
            referral_server=referral,
        )
        if referral_record.found:
            return referral_record
    return record


def whois_server_for_domain(domain: str) -> str:
    if "." not in domain:
        return ""
    tld = domain.rsplit(".", 1)[-1].lower()
    return WHOIS_SERVERS.get(tld, f"whois.nic.{tld}")


def parse_whois_domain_record(
    text: str,
    domain: str,
    *,
    server: str,
    referral_server: str = "",
) -> WhoisDomainRecord:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    fields: dict[str, list[str]] = {}
    for line in lines:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        normalized_key = " ".join(key.strip().lower().replace("_", " ").split())
        normalized_value = value.strip()
        if normalized_key and normalized_value:
            fields.setdefault(normalized_key, []).append(normalized_value)

    parsed_referral = referral_server or _first_field(
        fields,
        "whois server",
        "registrar whois server",
        "referralserver",
    )
    if parsed_referral.lower().startswith("whois://"):
        parsed_referral = parsed_referral[8:]

    nameservers = _normalize_nameservers(
        _field_values(fields, "name server", "nameserver", "nserver")
    )
    statuses = _dedupe_strings(_field_values(fields, "domain status", "status", "state"))
    found = bool(fields) and not _looks_not_found(text)

    return WhoisDomainRecord(
        domain=domain,
        server=server,
        referral_server=parsed_referral,
        registrar=_first_field(fields, "registrar", "registrar name", "sponsoring registrar"),
        statuses=statuses,
        nameservers=nameservers,
        created_at=_first_field(fields, "creation date", "created", "created on", "registered on"),
        updated_at=_first_field(fields, "updated date", "last updated", "last modified"),
        expires_at=_first_field(
            fields,
            "registry expiry date",
            "registrar registration expiration date",
            "expiration date",
            "paid-till",
        ),
        raw_line_count=len(lines),
        found=found,
    )


def _query_whois(server: str, query: str, *, timeout: float) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as connection:
        connection.settimeout(timeout)
        connection.sendall(f"{query}\r\n".encode("utf-8"))
        chunks: list[bytes] = []
        total = 0
        while total < WHOIS_RESPONSE_LIMIT:
            chunk = connection.recv(min(4096, WHOIS_RESPONSE_LIMIT - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    return b"".join(chunks).decode("utf-8", errors="ignore")


def _first_field(fields: dict[str, list[str]], *keys: str) -> str:
    for key in keys:
        values = fields.get(key, ())
        for value in values:
            normalized = value.strip()
            if normalized:
                return normalized
    return ""


def _field_values(fields: dict[str, list[str]], *keys: str) -> tuple[str, ...]:
    values: list[str] = []
    for key in keys:
        values.extend(fields.get(key, ()))
    return tuple(values)


def _normalize_nameservers(values: tuple[str, ...]) -> tuple[str, ...]:
    nameservers: list[str] = []
    for value in values:
        first_part = value.split()[0].strip().lower().strip(".")
        if first_part:
            nameservers.append(first_part)
    return _dedupe_strings(tuple(nameservers))


def _dedupe_strings(values: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        normalized = str(value).strip()
        key = normalized.lower()
        if normalized and key not in seen:
            seen.add(key)
            deduped.append(normalized)
    return tuple(deduped)


def _looks_not_found(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in NO_MATCH_MARKERS)
