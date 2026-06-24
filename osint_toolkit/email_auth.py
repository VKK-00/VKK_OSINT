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


def classify_mta_sts_policy(domain: str, mta_sts_result: DnsLookupResult) -> EmailAuthPolicy:
    return _classify_single_txt_policy(
        domain,
        mta_sts_result,
        source="mta-sts-policy",
        label="MTA-STS",
        prefix="v=STSv1",
        metadata_keys=("id",),
        extra_metadata={"policy_url": f"https://mta-sts.{domain}/.well-known/mta-sts.txt"},
    )


def classify_tls_rpt_policy(domain: str, tls_rpt_result: DnsLookupResult) -> EmailAuthPolicy:
    return _classify_single_txt_policy(
        domain,
        tls_rpt_result,
        source="tls-rpt-policy",
        label="TLS-RPT",
        prefix="v=TLSRPTv1",
        metadata_keys=("rua",),
    )


def classify_bimi_policy(domain: str, bimi_result: DnsLookupResult) -> EmailAuthPolicy:
    return _classify_single_txt_policy(
        domain,
        bimi_result,
        source="bimi-policy",
        label="BIMI",
        prefix="v=BIMI1",
        metadata_keys=("l", "a"),
        extra_metadata={"selector": "default"},
    )


def classify_txt_service_signals(domain: str, txt_result: DnsLookupResult) -> EmailAuthPolicy:
    if txt_result.status != "candidate":
        return EmailAuthPolicy(
            source="txt-service-signals",
            status=txt_result.status,
            confidence="low",
            evidence=f"Cannot classify domain TXT service signals because lookup status is {txt_result.status}.",
            metadata={
                "domain": domain,
                "lookup_domain": txt_result.domain,
                "lookup_status": txt_result.status,
            },
        )

    signals = _dedupe(tuple(_txt_service_signal(record) for record in txt_result.records))
    if not signals:
        return EmailAuthPolicy(
            source="txt-service-signals",
            status="not_found",
            confidence="medium",
            evidence="No recognized ownership/service TXT signals found.",
            metadata={"domain": domain, "lookup_domain": txt_result.domain, "signal_count": "0"},
        )

    return EmailAuthPolicy(
        source="txt-service-signals",
        status="candidate",
        confidence="medium",
        evidence=f"Detected TXT ownership/service signals: {', '.join(signals)}.",
        metadata={
            "domain": domain,
            "lookup_domain": txt_result.domain,
            "signal_count": str(len(signals)),
            "signal_types": ", ".join(signals),
        },
    )


def _classify_single_txt_policy(
    domain: str,
    result: DnsLookupResult,
    *,
    source: str,
    label: str,
    prefix: str,
    metadata_keys: tuple[str, ...],
    extra_metadata: dict[str, str] | None = None,
) -> EmailAuthPolicy:
    if result.status == "not_found":
        return EmailAuthPolicy(
            source=source,
            status="not_found",
            confidence="medium",
            evidence=f"No {label} TXT record found.",
            metadata={
                "domain": domain,
                "lookup_domain": result.domain,
                "lookup_status": result.status,
                "record_count": "0",
            },
        )
    if result.status != "candidate":
        return EmailAuthPolicy(
            source=source,
            status=result.status,
            confidence="low" if result.status in {"missing", "timeout", "error"} else "medium",
            evidence=f"Cannot classify {label} because TXT lookup status is {result.status}.",
            metadata={
                "domain": domain,
                "lookup_domain": result.domain,
                "lookup_status": result.status,
                "records": " | ".join(result.records),
            },
        )

    records = _records_with_prefix(result.records, prefix)
    if not records:
        return EmailAuthPolicy(
            source=source,
            status="not_found",
            confidence="medium",
            evidence=f"No {label} TXT record found.",
            metadata={"domain": domain, "lookup_domain": result.domain, "record_count": "0"},
        )
    if len(records) > 1:
        return EmailAuthPolicy(
            source=source,
            status="warning",
            confidence="medium",
            evidence=f"Multiple {label} TXT records found: {len(records)}.",
            metadata={
                "domain": domain,
                "lookup_domain": result.domain,
                "record_count": str(len(records)),
                "records": " | ".join(records),
            },
        )

    record = records[0]
    tags = _dns_tags(record)
    metadata = {
        "domain": domain,
        "lookup_domain": result.domain,
        "record_count": "1",
        "record": record,
    }
    for key in metadata_keys:
        metadata[key] = tags.get(key, "")
    if extra_metadata:
        metadata.update(extra_metadata)
    return EmailAuthPolicy(
        source=source,
        status="candidate",
        confidence="high",
        evidence=f"{label} TXT record found.",
        metadata=metadata,
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
    return _dns_tags(record)


def _dns_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for raw_part in record.split(";"):
        part = raw_part.strip()
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        tags[key.strip().lower()] = value.strip()
    return tags


def _txt_service_signal(record: str) -> str:
    normalized = record.strip().casefold()
    markers = (
        ("google-site-verification=", "google_site_verification"),
        ("ms=", "microsoft_365_verification"),
        ("v=msv1", "microsoft_365_verification"),
        ("apple-domain-verification=", "apple_domain_verification"),
        ("facebook-domain-verification=", "facebook_domain_verification"),
        ("globalsign-domain-verification=", "globalsign_domain_verification"),
        ("adobe-idp-site-verification=", "adobe_idp_verification"),
        ("atlassian-domain-verification=", "atlassian_domain_verification"),
        ("dropbox-domain-verification=", "dropbox_domain_verification"),
        ("protonmail-verification=", "protonmail_verification"),
        ("zoho-verification=", "zoho_verification"),
        ("amazonses:", "amazon_ses_verification"),
        ("yandex-verification:", "yandex_verification"),
        ("yandex-verification=", "yandex_verification"),
        ("mailru-verification:", "mailru_verification"),
        ("mailru-verification=", "mailru_verification"),
    )
    for marker, label in markers:
        if normalized.startswith(marker):
            return label
    return ""


def _dedupe(values: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        normalized = value.strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            deduped.append(normalized)
    return tuple(deduped)
