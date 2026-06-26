from __future__ import annotations

import re
import socket
from dataclasses import dataclass

from ..dns_lookup import DnsLookupResult, lookup_dns_records
from ..email_auth import (
    EmailAuthPolicy,
    classify_bimi_policy,
    classify_dmarc_policy,
    classify_mta_sts_policy,
    classify_spf_policy,
    classify_tls_rpt_policy,
    classify_txt_service_signals,
)
from ..engine import Finding, RunConfig, ScanTarget

EMAIL_RE = re.compile(
    r"^(?P<local>[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+)@(?P<domain>[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+)$",
    re.IGNORECASE,
)
ROLE_LOCAL_PARTS = {
    "abuse",
    "admin",
    "billing",
    "contact",
    "hello",
    "help",
    "hostmaster",
    "info",
    "jobs",
    "marketing",
    "media",
    "news",
    "no-reply",
    "noreply",
    "office",
    "postmaster",
    "press",
    "privacy",
    "sales",
    "security",
    "support",
    "team",
    "webmaster",
}


@dataclass(frozen=True)
class LocalPartProfile:
    status: str
    confidence: str
    category: str
    evidence: str
    metadata: dict[str, str]


@dataclass(frozen=True)
class EmailScanModule:
    name: str = "email-baseline"
    supported_targets: tuple[str, ...] = ("email",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        value = target.value.strip()
        match = EMAIL_RE.match(value)
        if not match:
            return (
                Finding(
                    module=self.name,
                    source="syntax",
                    target=value,
                    status="invalid",
                    confidence="high",
                    evidence="Input is not a syntactically valid email address.",
                ),
            )

        domain = match.group("domain").lower()
        local_part = match.group("local")
        findings = [
            Finding(
                module=self.name,
                source="syntax",
                target=value,
                status="valid",
                confidence="high",
                evidence="Email syntax is valid.",
                metadata={"domain": domain, "local_length": str(len(local_part))},
            )
        ]
        findings.append(_local_part_profile_finding(self.name, value, local_part, domain))

        if not config.live:
            findings.append(
                Finding(
                    module=self.name,
                    source="domain-resolution",
                    target=value,
                    status="planned",
                    confidence="not_checked",
                    evidence="Dry run only. Pass --live to resolve the email domain.",
                    metadata={"domain": domain},
                )
            )
            findings.append(_planned_dns_record_finding(self.name, value, domain, "MX"))
            findings.append(_planned_dns_record_finding(self.name, value, domain, "NS"))
            findings.append(_planned_dns_record_finding(self.name, value, domain, "TXT"))
            findings.append(_planned_email_auth_finding(self.name, value, domain, "txt-service-signals"))
            findings.append(_planned_email_auth_finding(self.name, value, domain, "spf-policy"))
            findings.append(_planned_email_auth_finding(self.name, value, domain, "dmarc-policy"))
            findings.append(_planned_email_auth_finding(self.name, value, domain, "mta-sts-policy"))
            findings.append(_planned_email_auth_finding(self.name, value, domain, "tls-rpt-policy"))
            findings.append(_planned_email_auth_finding(self.name, value, domain, "bimi-policy"))
            return tuple(findings)

        try:
            records = socket.getaddrinfo(domain, None)
        except socket.gaierror as exc:
            findings.append(
                Finding(
                    module=self.name,
                    source="domain-resolution",
                    target=value,
                    status="not_found",
                    confidence="medium",
                    evidence=str(exc),
                    metadata={"domain": domain},
                )
            )
        else:
            families = sorted({str(record[0].name) for record in records if hasattr(record[0], "name")})
            findings.append(
                Finding(
                    module=self.name,
                    source="domain-resolution",
                    target=value,
                    status="candidate",
                    confidence="medium",
                    evidence=f"Domain resolved with {len(records)} address records.",
                    metadata={"domain": domain, "address_families": ", ".join(families)},
                )
            )

        mx_result = lookup_dns_records(domain, "MX", timeout=config.timeout)
        ns_result = lookup_dns_records(domain, "NS", timeout=config.timeout)
        txt_result = lookup_dns_records(domain, "TXT", timeout=config.timeout)
        findings.append(_dns_record_finding(self.name, value, mx_result))
        findings.append(_dns_record_finding(self.name, value, ns_result))
        findings.append(_dns_record_finding(self.name, value, txt_result))
        findings.append(_email_auth_finding(self.name, value, classify_txt_service_signals(domain, txt_result)))
        findings.append(_email_auth_finding(self.name, value, classify_spf_policy(domain, txt_result)))

        dmarc_result = lookup_dns_records(f"_dmarc.{domain}", "TXT", timeout=config.timeout)
        findings.append(_email_auth_finding(self.name, value, classify_dmarc_policy(domain, dmarc_result)))

        mta_sts_result = lookup_dns_records(f"_mta-sts.{domain}", "TXT", timeout=config.timeout)
        tls_rpt_result = lookup_dns_records(f"_smtp._tls.{domain}", "TXT", timeout=config.timeout)
        bimi_result = lookup_dns_records(f"default._bimi.{domain}", "TXT", timeout=config.timeout)
        findings.append(_email_auth_finding(self.name, value, classify_mta_sts_policy(domain, mta_sts_result)))
        findings.append(_email_auth_finding(self.name, value, classify_tls_rpt_policy(domain, tls_rpt_result)))
        findings.append(_email_auth_finding(self.name, value, classify_bimi_policy(domain, bimi_result)))
        return tuple(findings)


def _local_part_profile_finding(module: str, email: str, local_part: str, domain: str) -> Finding:
    profile = profile_email_local_part(local_part)
    metadata = {"domain": domain, **profile.metadata}
    return Finding(
        module=module,
        source="local-part-profile",
        target=email,
        status=profile.status,
        confidence=profile.confidence,
        evidence=profile.evidence,
        metadata=metadata,
    )


def profile_email_local_part(local_part: str) -> LocalPartProfile:
    normalized = local_part.strip().lower()
    base, tag = _split_plus_tag(normalized)
    metadata = {
        "local_part": normalized,
        "base_local_part": base,
        "local_part_category": "",
        "category": "",
    }
    if tag:
        metadata["plus_tag"] = tag

    if base in ROLE_LOCAL_PARTS:
        metadata["local_part_category"] = "role"
        metadata["category"] = "role"
        return LocalPartProfile(
            status="skipped",
            confidence="high",
            category="role",
            evidence="Local part appears to be a shared or role mailbox, not a person handle.",
            metadata=metadata,
        )

    username = _username_from_local_part(base)
    if not username:
        metadata["local_part_category"] = "opaque"
        metadata["category"] = "opaque"
        return LocalPartProfile(
            status="skipped",
            confidence="medium",
            category="opaque",
            evidence="Local part is not a stable username candidate.",
            metadata=metadata,
        )

    metadata["username"] = username
    person_name = _person_name_from_local_part(base)
    if person_name:
        metadata["local_part_category"] = "person_like"
        metadata["category"] = "person_like"
        metadata["name"] = person_name
        evidence = "Local part looks like a person-name handle; verify before treating it as an identity clue."
    else:
        metadata["local_part_category"] = "handle_like"
        metadata["category"] = "handle_like"
        evidence = "Local part looks like a username handle; verify before treating it as an identity clue."
    if tag:
        evidence += " Plus-addressing tag was separated from the base handle."
    return LocalPartProfile(
        status="candidate",
        confidence="medium",
        category=metadata["local_part_category"],
        evidence=evidence,
        metadata=metadata,
    )


def _split_plus_tag(local_part: str) -> tuple[str, str]:
    if "+" not in local_part:
        return local_part, ""
    base, tag = local_part.split("+", 1)
    return base.strip("._-"), tag.strip("._-")


def _username_from_local_part(local_part: str) -> str:
    username = local_part.strip("._-")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,31}", username):
        return ""
    return username


def _person_name_from_local_part(local_part: str) -> str:
    parts = [part for part in re.split(r"[._-]+", local_part.strip("._-")) if part]
    if len(parts) != 2:
        return ""
    if not all(re.fullmatch(r"[a-z]{2,32}", part) for part in parts):
        return ""
    return " ".join(parts)


def _planned_dns_record_finding(module: str, email: str, domain: str, record_type: str) -> Finding:
    return Finding(
        module=module,
        source=f"{record_type.lower()}-records",
        target=email,
        status="planned",
        confidence="not_checked",
        evidence=f"Dry run only. Pass --live to query {record_type} records for the email domain.",
        metadata={"domain": domain, "record_type": record_type},
    )


def _dns_record_finding(module: str, email: str, result: DnsLookupResult) -> Finding:
    confidence = {
        "candidate": "medium",
        "not_found": "medium",
        "missing": "low",
        "timeout": "low",
        "error": "low",
    }.get(result.status, "unknown")
    return Finding(
        module=module,
        source=f"{result.record_type.lower()}-records",
        target=email,
        status=result.status,
        confidence=confidence,
        evidence=result.evidence(),
        metadata={
            "domain": result.domain,
            "record_type": result.record_type,
            "records": " | ".join(result.records),
            "raw_excerpt": result.raw_excerpt,
        },
    )


def _planned_email_auth_finding(module: str, email: str, domain: str, source: str) -> Finding:
    label = {
        "spf-policy": "SPF",
        "dmarc-policy": "DMARC",
        "mta-sts-policy": "MTA-STS",
        "tls-rpt-policy": "TLS-RPT",
        "bimi-policy": "BIMI",
        "txt-service-signals": "TXT service signals",
    }.get(source, source)
    action = f"classify {label}" if source == "txt-service-signals" else f"classify {label} policy"
    return Finding(
        module=module,
        source=source,
        target=email,
        status="planned",
        confidence="not_checked",
        evidence=f"Dry run only. Pass --live to {action} for the email domain.",
        metadata={"domain": domain},
    )


def _email_auth_finding(module: str, email: str, policy: EmailAuthPolicy) -> Finding:
    return Finding(
        module=module,
        source=policy.source,
        target=email,
        status=policy.status,
        confidence=policy.confidence,
        evidence=policy.evidence,
        metadata=policy.metadata,
    )
