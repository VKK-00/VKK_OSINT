from __future__ import annotations

import re
from dataclasses import dataclass

from ..engine import Finding, RunConfig, ScanTarget


COUNTRY_PREFIXES: tuple[tuple[str, str, str], ...] = (
    ("+380", "Ukraine", "ua"),
    ("+7", "Russia/Kazakhstan", "ru"),
    ("+1", "North America", "global"),
    ("+44", "United Kingdom", "global"),
    ("+49", "Germany", "global"),
    ("+33", "France", "global"),
    ("+39", "Italy", "global"),
    ("+34", "Spain", "global"),
    ("+48", "Poland", "global"),
)


@dataclass(frozen=True)
class PhoneScanModule:
    name: str = "phone-baseline"
    supported_targets: tuple[str, ...] = ("phone",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        del config
        normalized = normalize_phone(target.value)
        if not normalized:
            return (
                Finding(
                    module=self.name,
                    source="normalizer",
                    target=target.value,
                    status="invalid",
                    confidence="high",
                    evidence="Could not normalize input into an E.164-like phone number.",
                ),
            )

        valid = is_e164_like(normalized)
        findings = [
            Finding(
                module=self.name,
                source="normalizer",
                target=target.value,
                status="valid" if valid else "invalid",
                confidence="high" if valid else "medium",
                evidence="Normalized to E.164-like format." if valid else "Normalized value is outside E.164 length/prefix rules.",
                metadata={"normalized": normalized},
            )
        ]

        country_name, region = detect_country(normalized)
        findings.append(
            Finding(
                module=self.name,
                source="country-prefix",
                target=target.value,
                status="candidate" if country_name else "unknown",
                confidence="medium" if country_name else "low",
                evidence=f"Prefix maps to {country_name}." if country_name else "No built-in country prefix match.",
                metadata={"normalized": normalized, "country": country_name, "region": region},
            )
        )
        return tuple(findings)


def normalize_phone(value: str) -> str:
    compact = re.sub(r"[^\d+]", "", value.strip())
    if compact.startswith("00"):
        compact = "+" + compact[2:]
    if compact.count("+") > 1:
        return ""
    if "+" in compact and not compact.startswith("+"):
        return ""
    if not compact.startswith("+"):
        return ""
    digits = compact[1:]
    if not digits.isdigit():
        return ""
    return "+" + digits


def is_e164_like(value: str) -> bool:
    return bool(re.match(r"^\+[1-9]\d{7,14}$", value))


def detect_country(value: str) -> tuple[str, str]:
    for prefix, country, region in COUNTRY_PREFIXES:
        if value.startswith(prefix):
            return country, region
    return "", ""

