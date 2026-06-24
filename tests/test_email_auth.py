import unittest

from osint_toolkit.dns_lookup import DnsLookupResult
from osint_toolkit.email_auth import (
    classify_bimi_policy,
    classify_dmarc_policy,
    classify_mta_sts_policy,
    classify_spf_policy,
    classify_tls_rpt_policy,
    classify_txt_service_signals,
)


class EmailAuthTests(unittest.TestCase):
    def test_classify_spf_policy_extracts_all_mechanism(self):
        policy = classify_spf_policy(
            "example.com",
            DnsLookupResult(
                domain="example.com",
                record_type="TXT",
                status="candidate",
                records=("v=spf1 include:_spf.example.com -all",),
            ),
        )

        self.assertEqual(policy.status, "candidate")
        self.assertEqual(policy.confidence, "high")
        self.assertEqual(policy.metadata["policy"], "hardfail")
        self.assertEqual(policy.metadata["include_count"], "1")

    def test_classify_spf_policy_warns_on_multiple_records(self):
        policy = classify_spf_policy(
            "example.com",
            DnsLookupResult(
                domain="example.com",
                record_type="TXT",
                status="candidate",
                records=("v=spf1 -all", "v=spf1 ~all"),
            ),
        )

        self.assertEqual(policy.status, "warning")
        self.assertIn("Multiple SPF", policy.evidence)

    def test_classify_dmarc_policy_extracts_policy_tags(self):
        policy = classify_dmarc_policy(
            "example.com",
            DnsLookupResult(
                domain="_dmarc.example.com",
                record_type="TXT",
                status="candidate",
                records=("v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=r; pct=50; rua=mailto:d@example.com",),
            ),
        )

        self.assertEqual(policy.status, "candidate")
        self.assertEqual(policy.confidence, "high")
        self.assertEqual(policy.metadata["policy"], "reject")
        self.assertEqual(policy.metadata["subdomain_policy"], "quarantine")
        self.assertEqual(policy.metadata["percent"], "50")

    def test_classify_dmarc_policy_reports_missing_record(self):
        policy = classify_dmarc_policy(
            "example.com",
            DnsLookupResult(domain="_dmarc.example.com", record_type="TXT", status="not_found"),
        )

        self.assertEqual(policy.status, "not_found")
        self.assertEqual(policy.confidence, "medium")

    def test_classify_additional_email_txt_policies(self):
        mta_sts = classify_mta_sts_policy(
            "example.com",
            DnsLookupResult(
                domain="_mta-sts.example.com",
                record_type="TXT",
                status="candidate",
                records=("v=STSv1; id=20260624",),
            ),
        )
        tls_rpt = classify_tls_rpt_policy(
            "example.com",
            DnsLookupResult(
                domain="_smtp._tls.example.com",
                record_type="TXT",
                status="candidate",
                records=("v=TLSRPTv1; rua=mailto:tls@example.com",),
            ),
        )
        bimi = classify_bimi_policy(
            "example.com",
            DnsLookupResult(
                domain="default._bimi.example.com",
                record_type="TXT",
                status="candidate",
                records=("v=BIMI1; l=https://example.com/bimi.svg; a=https://example.com/vmc.pem",),
            ),
        )

        self.assertEqual(mta_sts.status, "candidate")
        self.assertEqual(mta_sts.metadata["id"], "20260624")
        self.assertIn("mta-sts.example.com", mta_sts.metadata["policy_url"])
        self.assertEqual(tls_rpt.metadata["rua"], "mailto:tls@example.com")
        self.assertEqual(bimi.metadata["selector"], "default")
        self.assertEqual(bimi.metadata["l"], "https://example.com/bimi.svg")

    def test_classify_txt_service_signals_summarizes_public_markers(self):
        policy = classify_txt_service_signals(
            "example.com",
            DnsLookupResult(
                domain="example.com",
                record_type="TXT",
                status="candidate",
                records=(
                    "google-site-verification=abc",
                    "MS=ms123",
                    "yandex-verification: yx123",
                ),
            ),
        )

        self.assertEqual(policy.status, "candidate")
        self.assertEqual(policy.metadata["signal_count"], "3")
        self.assertIn("google_site_verification", policy.metadata["signal_types"])
        self.assertIn("microsoft_365_verification", policy.metadata["signal_types"])
        self.assertIn("yandex_verification", policy.metadata["signal_types"])


if __name__ == "__main__":
    unittest.main()
