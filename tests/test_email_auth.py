import unittest

from osint_toolkit.dns_lookup import DnsLookupResult
from osint_toolkit.email_auth import classify_dmarc_policy, classify_spf_policy


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


if __name__ == "__main__":
    unittest.main()
