import subprocess
import unittest
from unittest.mock import patch

from osint_toolkit.dns_lookup import lookup_dns_records, parse_nslookup_records


class DnsLookupTests(unittest.TestCase):
    def test_parse_windows_mx_records(self):
        output = """
        Server:  resolver.local
        Address:  192.0.2.53

        example.com MX preference = 10, mail exchanger = mail.example.com
        example.com MX preference = 20, mail exchanger = backup.example.com.
        """

        self.assertEqual(
            parse_nslookup_records(output, "MX"),
            ("10 mail.example.com", "20 backup.example.com"),
        )

    def test_parse_unix_mx_records(self):
        output = """
        example.com     mail exchanger = 5 mail.example.com.
        example.com     mail exchanger = 10 backup.example.com.
        """

        self.assertEqual(
            parse_nslookup_records(output, "MX"),
            ("5 mail.example.com", "10 backup.example.com"),
        )

    def test_parse_txt_records(self):
        output = '''
        example.com text =
            "v=spf1 include:_spf.example.com -all"
        example.com text = "google-site-verification=abc"
        '''

        self.assertEqual(
            parse_nslookup_records(output, "TXT"),
            ("v=spf1 include:_spf.example.com -all", "google-site-verification=abc"),
        )

    def test_parse_txt_records_joins_split_chunks(self):
        output = '''
        example.com text =
            "v=spf1 include:_spf.example.com "
            "include:_spf2.example.com -all"
        _dmarc.example.com text = "v=DMARC1; p=reject; "
            "rua=mailto:dmarc@example.com"
        '''

        self.assertEqual(
            parse_nslookup_records(output, "TXT"),
            (
                "v=spf1 include:_spf.example.com include:_spf2.example.com -all",
                "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
            ),
        )

    def test_lookup_dns_records_uses_nslookup_output(self):
        completed = subprocess.CompletedProcess(
            args=["nslookup", "-type=MX", "example.com"],
            returncode=0,
            stdout="example.com MX preference = 10, mail exchanger = mail.example.com\n",
            stderr="",
        )

        with patch("osint_toolkit.dns_lookup.subprocess.run", return_value=completed):
            result = lookup_dns_records("example.com", "MX")

        self.assertEqual(result.status, "candidate")
        self.assertEqual(result.records, ("10 mail.example.com",))

    def test_lookup_dns_records_reports_missing_nslookup(self):
        with patch("osint_toolkit.dns_lookup.subprocess.run", side_effect=FileNotFoundError):
            result = lookup_dns_records("example.com", "MX")

        self.assertEqual(result.status, "missing")
        self.assertIn("nslookup", result.error)


if __name__ == "__main__":
    unittest.main()
