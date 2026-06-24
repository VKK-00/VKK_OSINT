from __future__ import annotations

import re
import socket
from dataclasses import dataclass

from ..dns_lookup import DnsLookupResult, lookup_dns_records
from ..email_auth import EmailAuthPolicy, classify_dmarc_policy, classify_spf_policy
from ..engine import Finding, RunConfig, ScanTarget

EMAIL_RE = re.compile(
    r"^(?P<local>[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+)@(?P<domain>[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+)$",
    re.IGNORECASE,
)


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
        findings = [
            Finding(
                module=self.name,
                source="syntax",
                target=value,
                status="valid",
                confidence="high",
                evidence="Email syntax is valid.",
                metadata={"domain": domain, "local_length": str(len(match.group('local')))},
            )
        ]

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
            findings.append(_planned_dns_record_finding(self.name, value, domain, "TXT"))
            findings.append(_planned_email_auth_finding(self.name, value, domain, "spf-policy"))
            findings.append(_planned_email_auth_finding(self.name, value, domain, "dmarc-policy"))
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
        txt_result = lookup_dns_records(domain, "TXT", timeout=config.timeout)
        findings.append(_dns_record_finding(self.name, value, mx_result))
        findings.append(_dns_record_finding(self.name, value, txt_result))
        findings.append(_email_auth_finding(self.name, value, classify_spf_policy(domain, txt_result)))

        dmarc_result = lookup_dns_records(f"_dmarc.{domain}", "TXT", timeout=config.timeout)
        findings.append(_email_auth_finding(self.name, value, classify_dmarc_policy(domain, dmarc_result)))
        return tuple(findings)


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
    label = "SPF" if source == "spf-policy" else "DMARC"
    return Finding(
        module=module,
        source=source,
        target=email,
        status="planned",
        confidence="not_checked",
        evidence=f"Dry run only. Pass --live to classify {label} policy for the email domain.",
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
