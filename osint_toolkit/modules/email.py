from __future__ import annotations

import re
import socket
from dataclasses import dataclass

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
        return tuple(findings)

