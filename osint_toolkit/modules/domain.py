from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from urllib.parse import quote, urlparse

from ..engine import Finding, RunConfig, ScanTarget
from ..http_client import HttpClient, HttpResult

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
)
CT_SUBDOMAIN_LIMIT = 50
RDAP_NAMESERVER_LIMIT = 20


@dataclass(frozen=True)
class DomainScanModule:
    name: str = "domain-baseline"
    supported_targets: tuple[str, ...] = ("domain",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        domain = normalize_domain(target.value)
        if not domain:
            return (
                Finding(
                    module=self.name,
                    source="normalizer",
                    target=target.value,
                    status="invalid",
                    confidence="high",
                    evidence="Could not normalize input into a domain name.",
                ),
            )

        if not config.live:
            return (
                Finding(
                    module=self.name,
                    source="dns-resolution",
                    target=target.value,
                    status="planned",
                    confidence="not_checked",
                    evidence="Dry run only. Pass --live to resolve the domain.",
                    metadata={"domain": domain},
                ),
                Finding(
                    module=self.name,
                    source="https-metadata",
                    target=target.value,
                    status="planned",
                    url=f"https://{domain}",
                    confidence="not_checked",
                    evidence="Dry run only. Pass --live to fetch HTTPS metadata.",
                    metadata={"domain": domain},
                ),
                Finding(
                    module=self.name,
                    source="http-metadata",
                    target=target.value,
                    status="planned",
                    url=f"http://{domain}",
                    confidence="not_checked",
                    evidence="Dry run only. Pass --live to fetch HTTP metadata.",
                    metadata={"domain": domain},
                ),
                Finding(
                    module=self.name,
                    source="certificate-transparency",
                    target=target.value,
                    status="planned",
                    url=_crtsh_url(domain),
                    confidence="not_checked",
                    evidence="Dry run only. Pass --live to query certificate transparency records.",
                    metadata={"domain": domain, "provider": "crt.sh"},
                ),
                Finding(
                    module=self.name,
                    source="rdap-domain",
                    target=target.value,
                    status="planned",
                    url=_rdap_url(domain),
                    confidence="not_checked",
                    evidence="Dry run only. Pass --live to query RDAP domain registration data.",
                    metadata={"domain": domain, "provider": "rdap.org"},
                ),
            )

        findings: list[Finding] = []
        findings.append(_resolve_domain(self.name, target.value, domain))
        client = HttpClient(
            timeout=config.timeout,
            user_agent=config.user_agent,
            retries=config.http_retries,
            backoff_seconds=config.http_backoff,
        )
        findings.append(_http_metadata(self.name, target.value, domain, "https", client))
        findings.append(_http_metadata(self.name, target.value, domain, "http", client))
        findings.append(_certificate_transparency(self.name, target.value, domain, client))
        findings.append(_rdap_domain(self.name, target.value, domain, client))
        return tuple(findings)


def normalize_domain(value: str) -> str:
    raw = value.strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or ""
    host = host.strip(".").lower()
    if not host or " " in host or "." not in host:
        return ""
    return host


def _resolve_domain(module: str, original: str, domain: str) -> Finding:
    try:
        records = socket.getaddrinfo(domain, None)
    except socket.gaierror as exc:
        return Finding(
            module=module,
            source="dns-resolution",
            target=original,
            status="not_found",
            confidence="medium",
            evidence=str(exc),
            metadata={"domain": domain},
        )

    addresses = sorted({record[4][0] for record in records if record and record[4]})
    return Finding(
        module=module,
        source="dns-resolution",
        target=original,
        status="candidate",
        confidence="medium",
        evidence=f"Resolved {len(addresses)} unique address(es).",
        metadata={"domain": domain, "addresses": ", ".join(addresses[:10])},
    )


def _http_metadata(module: str, original: str, domain: str, scheme: str, client: HttpClient) -> Finding:
    url = f"{scheme}://{domain}"
    result = client.check(url, fetch_title=True)
    status = "candidate" if result.status_code and result.status_code < 400 else "unknown"
    security_headers = {
        header: result.headers[header]
        for header in SECURITY_HEADERS
        if header in result.headers
    }
    return Finding(
        module=module,
        source=f"{scheme}-metadata",
        target=original,
        status=status,
        url=result.final_url or url,
        title=result.title,
        http_status=result.status_code,
        confidence="medium" if result.status_code and result.status_code < 400 else "low",
        evidence=result.error or f"HTTP {result.status_code}",
        metadata={
            "domain": domain,
            "content_type": result.content_type,
            "requested_url": url,
            "security_headers_present": ", ".join(sorted(security_headers)),
        },
    )


def _certificate_transparency(module: str, original: str, domain: str, client: HttpClient) -> Finding:
    url = _crtsh_url(domain)
    result = client.check(url, fetch_title=True, headers={"Accept": "application/json"})
    metadata = {
        "domain": domain,
        "provider": "crt.sh",
        "requested_url": url,
        "http_attempts": str(result.attempts),
    }
    if result.status_code is None or result.status_code >= 400:
        return Finding(
            module=module,
            source="certificate-transparency",
            target=original,
            status="error",
            url=result.final_url or url,
            http_status=result.status_code,
            confidence="low",
            evidence=result.error or f"HTTP {result.status_code}",
            metadata=metadata,
        )
    if not result.body_text:
        return Finding(
            module=module,
            source="certificate-transparency",
            target=original,
            status="error",
            url=result.final_url or url,
            http_status=result.status_code,
            confidence="low",
            evidence="crt.sh returned no JSON body.",
            metadata=metadata,
        )

    try:
        subdomains = parse_crtsh_subdomains(result.body_text, domain)
    except ValueError as exc:
        return Finding(
            module=module,
            source="certificate-transparency",
            target=original,
            status="error",
            url=result.final_url or url,
            http_status=result.status_code,
            confidence="low",
            evidence=str(exc),
            metadata=metadata,
        )

    limited = subdomains[:CT_SUBDOMAIN_LIMIT]
    metadata.update(
        {
            "subdomain_count": str(len(subdomains)),
            "subdomains": ", ".join(limited),
            "truncated": "yes" if len(subdomains) > len(limited) else "no",
        }
    )
    if not subdomains:
        return Finding(
            module=module,
            source="certificate-transparency",
            target=original,
            status="not_found",
            url=result.final_url or url,
            http_status=result.status_code,
            confidence="medium",
            evidence="No subdomains found in crt.sh certificate transparency response.",
            metadata=metadata,
        )
    return Finding(
        module=module,
        source="certificate-transparency",
        target=original,
        status="candidate",
        url=result.final_url or url,
        http_status=result.status_code,
        confidence="medium",
        evidence=f"Found {len(subdomains)} unique subdomain(s) in certificate transparency records.",
        metadata=metadata,
    )


def parse_crtsh_subdomains(body_text: str, domain: str) -> tuple[str, ...]:
    try:
        payload = json.loads(body_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Could not parse crt.sh JSON response: {exc}") from exc
    if isinstance(payload, dict):
        rows = (payload,)
    elif isinstance(payload, list):
        rows = tuple(row for row in payload if isinstance(row, dict))
    else:
        raise ValueError("crt.sh JSON response is not an object or list of objects.")

    normalized_domain = domain.lower().strip(".")
    names: set[str] = set()
    for row in rows:
        for key in ("name_value", "common_name"):
            value = row.get(key, "")
            if not isinstance(value, str):
                continue
            for raw_name in value.splitlines():
                name = _normalize_ct_name(raw_name)
                if _is_subdomain_of(name, normalized_domain):
                    names.add(name)
    return tuple(sorted(names))


def _crtsh_url(domain: str) -> str:
    return f"https://crt.sh/?q={quote(f'%.{domain}', safe='')}&output=json"


@dataclass(frozen=True)
class RdapDomainRecord:
    domain: str
    registrar: str = ""
    handle: str = ""
    statuses: tuple[str, ...] = ()
    nameservers: tuple[str, ...] = ()
    created_at: str = ""
    updated_at: str = ""
    expires_at: str = ""


def _rdap_domain(module: str, original: str, domain: str, client: HttpClient) -> Finding:
    url = _rdap_url(domain)
    result = client.check(url, fetch_title=True, headers={"Accept": "application/rdap+json, application/json"})
    metadata = {
        "domain": domain,
        "provider": "rdap.org",
        "requested_url": url,
        "http_attempts": str(result.attempts),
    }
    if result.status_code == 404:
        return Finding(
            module=module,
            source="rdap-domain",
            target=original,
            status="not_found",
            url=result.final_url or url,
            http_status=result.status_code,
            confidence="medium",
            evidence="RDAP returned 404 for this domain.",
            metadata=metadata,
        )
    if result.status_code is None or result.status_code >= 400:
        return Finding(
            module=module,
            source="rdap-domain",
            target=original,
            status="error",
            url=result.final_url or url,
            http_status=result.status_code,
            confidence="low",
            evidence=result.error or f"HTTP {result.status_code}",
            metadata=metadata,
        )
    if not result.body_text:
        return Finding(
            module=module,
            source="rdap-domain",
            target=original,
            status="error",
            url=result.final_url or url,
            http_status=result.status_code,
            confidence="low",
            evidence="RDAP returned no JSON body.",
            metadata=metadata,
        )

    try:
        record = parse_rdap_domain_record(result.body_text, domain)
    except ValueError as exc:
        return Finding(
            module=module,
            source="rdap-domain",
            target=original,
            status="error",
            url=result.final_url or url,
            http_status=result.status_code,
            confidence="low",
            evidence=str(exc),
            metadata=metadata,
        )

    nameservers = record.nameservers[:RDAP_NAMESERVER_LIMIT]
    metadata.update(
        {
            "rdap_domain": record.domain,
            "registrar": record.registrar,
            "domain_handle": record.handle,
            "domain_statuses": ", ".join(record.statuses),
            "nameservers": ", ".join(nameservers),
            "nameserver_count": str(len(record.nameservers)),
            "nameservers_truncated": "yes" if len(record.nameservers) > len(nameservers) else "no",
            "created_at": record.created_at,
            "updated_at": record.updated_at,
            "expires_at": record.expires_at,
        }
    )
    return Finding(
        module=module,
        source="rdap-domain",
        target=original,
        status="candidate",
        url=result.final_url or url,
        http_status=result.status_code,
        confidence="medium",
        evidence="RDAP domain registration record found.",
        metadata=metadata,
    )


def parse_rdap_domain_record(body_text: str, domain: str) -> RdapDomainRecord:
    try:
        payload = json.loads(body_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Could not parse RDAP JSON response: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("RDAP JSON response is not an object.")

    nameservers = _rdap_nameservers(payload.get("nameservers", ()))
    events = _rdap_events(payload.get("events", ()))
    return RdapDomainRecord(
        domain=str(payload.get("ldhName") or payload.get("unicodeName") or domain).strip().lower(),
        registrar=_rdap_registrar(payload.get("entities", ())),
        handle=str(payload.get("handle", "")).strip(),
        statuses=_dedupe_strings(payload.get("status", ())),
        nameservers=nameservers,
        created_at=events.get("registration", ""),
        updated_at=events.get("last changed", "") or events.get("last update of rdap database", ""),
        expires_at=events.get("expiration", ""),
    )


def _rdap_url(domain: str) -> str:
    return f"https://rdap.org/domain/{quote(domain, safe='')}"


def _rdap_nameservers(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    names: list[str] = []
    for row in value:
        if not isinstance(row, dict):
            continue
        name = str(row.get("ldhName") or row.get("unicodeName") or "").strip().lower().strip(".")
        if name:
            names.append(name)
    return _dedupe_strings(names)


def _rdap_events(value: object) -> dict[str, str]:
    if not isinstance(value, list):
        return {}
    events: dict[str, str] = {}
    for row in value:
        if not isinstance(row, dict):
            continue
        action = str(row.get("eventAction", "")).strip().lower()
        date = str(row.get("eventDate", "")).strip()
        if action and date and action not in events:
            events[action] = date
    return events


def _rdap_registrar(value: object) -> str:
    if not isinstance(value, list):
        return ""
    for row in value:
        if not isinstance(row, dict):
            continue
        role_values = row.get("roles", ())
        roles = (
            {str(role).strip().lower() for role in role_values if str(role).strip()}
            if isinstance(role_values, (list, tuple, set))
            else set()
        )
        if "registrar" not in roles:
            continue
        name = _rdap_entity_name(row)
        if name:
            return name
    for row in value:
        if isinstance(row, dict):
            name = _rdap_entity_name(row)
            if name:
                return name
    return ""


def _rdap_entity_name(entity: dict[str, object]) -> str:
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) >= 2 and isinstance(vcard[1], list):
        for field in vcard[1]:
            if not isinstance(field, list) or len(field) < 4:
                continue
            name = str(field[0]).strip().lower()
            value = field[3]
            if name in {"fn", "org"}:
                if isinstance(value, list):
                    flattened = " ".join(str(part).strip() for part in value if str(part).strip())
                    if flattened:
                        return flattened
                text = str(value).strip()
                if text:
                    return text

    public_ids = entity.get("publicIds")
    if isinstance(public_ids, list):
        for row in public_ids:
            if isinstance(row, dict) and str(row.get("type", "")).strip().lower() == "iana registrar id":
                identifier = str(row.get("identifier", "")).strip()
                if identifier:
                    return f"IANA Registrar ID {identifier}"
    return ""


def _dedupe_strings(values: object) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        return ()
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        normalized = str(value).strip()
        key = normalized.lower()
        if normalized and key not in seen:
            seen.add(key)
            deduped.append(normalized)
    return tuple(deduped)


def _normalize_ct_name(value: str) -> str:
    name = value.strip().lower().strip(".")
    if name.startswith("*."):
        name = name[2:]
    if not name or " " in name or "@" in name:
        return ""
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
    if any(char not in allowed for char in name):
        return ""
    return name


def _is_subdomain_of(name: str, domain: str) -> bool:
    return bool(name and name != domain and name.endswith(f".{domain}"))
