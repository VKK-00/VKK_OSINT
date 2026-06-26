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
class NumberingPlanHint:
    country: str
    country_code: str
    region: str
    national_destination_code: str
    line_type: str
    carrier: str = ""
    location: str = ""
    note: str = ""


# Static numbering-plan hints only. Mobile portability can make the current
# operator differ from the original allocation carrier.
UKRAINE_MOBILE_ALLOCATIONS: dict[str, str] = {
    "50": "Vodafone Ukraine",
    "66": "Vodafone Ukraine",
    "75": "Vodafone Ukraine",
    "95": "Vodafone Ukraine",
    "99": "Vodafone Ukraine",
    "63": "lifecell",
    "73": "lifecell",
    "93": "lifecell",
    "67": "Kyivstar",
    "68": "Kyivstar",
    "77": "Kyivstar",
    "96": "Kyivstar",
    "97": "Kyivstar",
    "98": "Kyivstar",
    "91": "3mob",
    "92": "PEOPLEnet",
    "94": "Intertelecom",
}

UKRAINE_FIXED_LOCATIONS: dict[str, str] = {
    "31": "Zakarpattia region",
    "32": "Lviv region",
    "33": "Volyn region",
    "34": "Ivano-Frankivsk region",
    "35": "Ternopil region",
    "36": "Rivne region",
    "37": "Chernivtsi region",
    "38": "Khmelnytskyi region",
    "41": "Zhytomyr region",
    "43": "Vinnytsia region",
    "44": "Kyiv",
    "45": "Kyiv region",
    "46": "Chernihiv region",
    "47": "Cherkasy region",
    "48": "Odesa region",
    "51": "Mykolaiv region",
    "52": "Kirovohrad region",
    "53": "Poltava region",
    "54": "Sumy region",
    "55": "Kherson region",
    "56": "Dnipropetrovsk region",
    "57": "Kharkiv region",
    "61": "Zaporizhzhia region",
    "62": "Donetsk region",
    "64": "Luhansk region",
    "65": "Crimea",
    "69": "Sevastopol",
}

RUSSIA_FIXED_LOCATIONS: dict[str, str] = {
    "301": "Buryatia",
    "302": "Zabaykalsky Krai",
    "341": "Udmurtia",
    "342": "Perm Krai",
    "343": "Sverdlovsk region",
    "345": "Tyumen region",
    "351": "Chelyabinsk region",
    "381": "Omsk region",
    "383": "Novosibirsk region",
    "401": "Kaliningrad region",
    "411": "Sakha Republic",
    "421": "Khabarovsk Krai",
    "423": "Primorsky Krai",
    "495": "Moscow",
    "496": "Moscow region",
    "498": "Moscow region",
    "499": "Moscow",
    "812": "Saint Petersburg",
    "831": "Nizhny Novgorod region",
    "843": "Tatarstan",
    "846": "Samara region",
    "861": "Krasnodar Krai",
    "863": "Rostov region",
}


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
        numbering_hint = detect_numbering_plan(normalized)
        if numbering_hint:
            findings.append(
                Finding(
                    module=self.name,
                    source="numbering-plan",
                    target=target.value,
                    status="candidate",
                    confidence="medium",
                    evidence=_numbering_plan_evidence(numbering_hint),
                    metadata=_numbering_plan_metadata(normalized, numbering_hint),
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


def detect_numbering_plan(value: str) -> NumberingPlanHint | None:
    if value.startswith("+380"):
        return _ukraine_numbering_plan(value[4:])
    if value.startswith("+7"):
        return _zone7_numbering_plan(value[2:])
    return None


def _ukraine_numbering_plan(national_number: str) -> NumberingPlanHint | None:
    if len(national_number) != 9 or not national_number.isdigit():
        return None
    ndc = national_number[:2]
    if ndc in UKRAINE_MOBILE_ALLOCATIONS:
        return NumberingPlanHint(
            country="Ukraine",
            country_code="UA",
            region="ua",
            national_destination_code=ndc,
            line_type="mobile",
            carrier=UKRAINE_MOBILE_ALLOCATIONS[ndc],
            note="Carrier is an original numbering allocation hint; mobile number portability may change the actual operator.",
        )
    if ndc in UKRAINE_FIXED_LOCATIONS:
        return NumberingPlanHint(
            country="Ukraine",
            country_code="UA",
            region="ua",
            national_destination_code=ndc,
            line_type="fixed",
            location=UKRAINE_FIXED_LOCATIONS[ndc],
            note="Location is inferred from the Ukrainian national destination code.",
        )
    return None


def _zone7_numbering_plan(national_number: str) -> NumberingPlanHint | None:
    if len(national_number) != 10 or not national_number.isdigit():
        return None
    ndc = national_number[:3]
    ndc_int = int(ndc)
    if 700 <= ndc_int <= 799:
        return NumberingPlanHint(
            country="Kazakhstan",
            country_code="KZ",
            region="kz",
            national_destination_code=ndc,
            line_type="fixed_or_mobile",
            note="Country code +7 is shared; this NDC range is assigned to Kazakhstan in the numbering zone.",
        )
    if ndc in RUSSIA_FIXED_LOCATIONS:
        return NumberingPlanHint(
            country="Russia",
            country_code="RU",
            region="ru",
            national_destination_code=ndc,
            line_type="fixed",
            location=RUSSIA_FIXED_LOCATIONS[ndc],
            note="Location is inferred from the Russian geographic national destination code.",
        )
    if ndc == "954":
        return NumberingPlanHint(
            country="Russia",
            country_code="RU",
            region="ru",
            national_destination_code=ndc,
            line_type="satellite",
            note="NDC is listed for satellite operators in the Russian numbering plan.",
        )
    if ndc == "970":
        return NumberingPlanHint(
            country="Russia",
            country_code="RU",
            region="ru",
            national_destination_code=ndc,
            line_type="telematic_service",
            note="NDC is listed for telematic services in the Russian numbering plan.",
        )
    if ndc == "971":
        return NumberingPlanHint(
            country="Russia",
            country_code="RU",
            region="ru",
            national_destination_code=ndc,
            line_type="data_service",
            note="NDC is listed for data communication services in the Russian numbering plan.",
        )
    if 900 <= ndc_int <= 969 or 972 <= ndc_int <= 999:
        return NumberingPlanHint(
            country="Russia",
            country_code="RU",
            region="ru",
            national_destination_code=ndc,
            line_type="mobile",
            note="Mobile range hint from the Russian numbering plan; mobile number portability may change the actual operator.",
        )
    return None


def _numbering_plan_metadata(normalized: str, hint: NumberingPlanHint) -> dict[str, str]:
    metadata = {
        "normalized": normalized,
        "country": hint.country,
        "country_code": hint.country_code,
        "region": hint.region,
        "national_destination_code": hint.national_destination_code,
        "line_type": hint.line_type,
        "numbering_plan_note": hint.note,
    }
    if hint.carrier:
        metadata["carrier"] = hint.carrier
    if hint.location:
        metadata["location"] = hint.location
    return metadata


def _numbering_plan_evidence(hint: NumberingPlanHint) -> str:
    details = [f"NDC {hint.national_destination_code}", f"{hint.country}", f"{hint.line_type}"]
    if hint.carrier:
        details.append(hint.carrier)
    if hint.location:
        details.append(hint.location)
    return "Numbering plan hint: " + "; ".join(details) + ". " + hint.note
