from __future__ import annotations

from dataclasses import dataclass

from .dns_lookup import DnsLookupResult


@dataclass(frozen=True)
class EmailAuthPolicy:
    source: str
    status: str
    confidence: str
    evidence: str
    metadata: dict[str, str]


def classify_spf_policy(domain: str, txt_result: DnsLookupResult) -> EmailAuthPolicy:
    if txt_result.status != "candidate":
        return EmailAuthPolicy(
            source="spf-policy",
            status=txt_result.status,
            confidence="low",
            evidence=f"Cannot classify SPF because TXT lookup status is {txt_result.status}.",
            metadata={
                "domain": domain,
                "lookup_domain": txt_result.domain,
                "lookup_status": txt_result.status,
                "records": " | ".join(txt_result.records),
            },
        )

    spf_records = _records_with_prefix(txt_result.records, "v=spf1")
    if not spf_records:
        return EmailAuthPolicy(
            source="spf-policy",
            status="not_found",
            confidence="medium",
            evidence="No SPF record found in domain TXT records.",
            metadata={"domain": domain, "lookup_domain": txt_result.domain, "record_count": "0"},
        )
    if len(spf_records) > 1:
        return EmailAuthPolicy(
            source="spf-policy",
            status="warning",
            confidence="medium",
            evidence=f"Multiple SPF records found: {len(spf_records)}.",
            metadata={
                "domain": domain,
                "lookup_domain": txt_result.domain,
                "record_count": str(len(spf_records)),
                "records": " | ".join(spf_records),
            },
        )

    record = spf_records[0]
    all_mechanism, policy = _spf_all_policy(record)
    includes = _count_terms(record, "include:")
    redirects = _count_terms(record, "redirect=")
    return EmailAuthPolicy(
        source="spf-policy",
        status="candidate",
        confidence="high",
        evidence=f"SPF record found with {policy or 'no explicit all mechanism'} policy.",
        metadata={
            "domain": domain,
            "lookup_domain": txt_result.domain,
            "record_count": "1",
            "record": record,
            "all_mechanism": all_mechanism,
            "policy": policy,
            "include_count": str(includes),
            "redirect_count": str(redirects),
        },
    )


def classify_dmarc_policy(domain: str, dmarc_result: DnsLookupResult) -> EmailAuthPolicy:
    if dmarc_result.status == "not_found":
        return EmailAuthPolicy(
            source="dmarc-policy",
            status="not_found",
            confidence="medium",
            evidence="No DMARC record found at _dmarc domain.",
            metadata={
                "domain": domain,
                "lookup_domain": dmarc_result.domain,
                "lookup_status": dmarc_result.status,
                "records": " | ".join(dmarc_result.records),
            },
        )
    if dmarc_result.status != "candidate":
        return EmailAuthPolicy(
            source="dmarc-policy",
            status=dmarc_result.status,
            confidence="low" if dmarc_result.status in {"missing", "timeout", "error"} else "medium",
            evidence=f"Cannot classify DMARC because TXT lookup status is {dmarc_result.status}.",
            metadata={
                "domain": domain,
                "lookup_domain": dmarc_result.domain,
                "lookup_status": dmarc_result.status,
                "records": " | ".join(dmarc_result.records),
            },
        )

    dmarc_records = _records_with_prefix(dmarc_result.records, "v=DMARC1")
    if not dmarc_records:
        return EmailAuthPolicy(
            source="dmarc-policy",
            status="not_found",
            confidence="medium",
            evidence="No DMARC record found at _dmarc domain.",
            metadata={"domain": domain, "lookup_domain": dmarc_result.domain, "record_count": "0"},
        )
    if len(dmarc_records) > 1:
        return EmailAuthPolicy(
            source="dmarc-policy",
            status="warning",
            confidence="medium",
            evidence=f"Multiple DMARC records found: {len(dmarc_records)}.",
            metadata={
                "domain": domain,
                "lookup_domain": dmarc_result.domain,
                "record_count": str(len(dmarc_records)),
                "records": " | ".join(dmarc_records),
            },
        )

    record = dmarc_records[0]
    tags = _dmarc_tags(record)
    policy = tags.get("p", "")
    if not policy:
        return EmailAuthPolicy(
            source="dmarc-policy",
            status="warning",
            confidence="medium",
            evidence="DMARC record found without required p= policy.",
            metadata={
                "domain": domain,
                "lookup_domain": dmarc_result.domain,
                "record_count": "1",
                "record": record,
            },
        )

    return EmailAuthPolicy(
        source="dmarc-policy",
        status="candidate",
        confidence="high",
        evidence=f"DMARC policy found: p={policy}.",
        metadata={
            "domain": domain,
            "lookup_domain": dmarc_result.domain,
            "record_count": "1",
            "record": record,
            "policy": policy,
            "subdomain_policy": tags.get("sp", ""),
            "alignment_dkim": tags.get("adkim", ""),
            "alignment_spf": tags.get("aspf", ""),
            "percent": tags.get("pct", ""),
            "rua": tags.get("rua", ""),
            "ruf": tags.get("ruf", ""),
        },
    )


def _records_with_prefix(records: tuple[str, ...], prefix: str) -> tuple[str, ...]:
    lowered_prefix = prefix.casefold()
    return tuple(record for record in records if record.strip().casefold().startswith(lowered_prefix))


def _spf_all_policy(record: str) -> tuple[str, str]:
    for term in record.split():
        normalized = term.strip()
        if normalized in {"-all", "~all", "?all", "+all", "all"}:
            return normalized, {
                "-all": "hardfail",
                "~all": "softfail",
                "?all": "neutral",
                "+all": "pass_all",
                "all": "pass_all",
            }[normalized]
    return "", ""


def _count_terms(record: str, prefix: str) -> int:
    lowered_prefix = prefix.casefold()
    return sum(1 for term in record.split() if term.casefold().startswith(lowered_prefix))


def _dmarc_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for raw_part in record.split(";"):
        part = raw_part.strip()
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        tags[key.strip().lower()] = value.strip()
    return tags
