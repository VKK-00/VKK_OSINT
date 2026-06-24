import subprocess
import unittest
from unittest.mock import patch

from osint_toolkit.adapter_parsers import parse_adapter_output
from osint_toolkit.adapter_runner import run_adapter_findings
from osint_toolkit.entities import entities_from_findings
from osint_toolkit.engine import ScanTarget


class AdapterParserTests(unittest.TestCase):
    def test_parse_username_adapter_urls(self):
        findings = parse_adapter_output(
            "sherlock-project/sherlock",
            ScanTarget(kind="username", value="example_user"),
            """
            [+] GitHub: https://github.com/example_user
            [+] Reddit: https://www.reddit.com/user/example_user
            [-] Instagram: Not Found
            """,
        )

        urls = {finding.url for finding in findings}
        self.assertIn("https://github.com/example_user", urls)
        self.assertIn("https://www.reddit.com/user/example_user", urls)
        self.assertTrue(all(finding.module == "external-adapter-parser" for finding in findings))
        self.assertTrue(any(finding.metadata["source_label"] == "GitHub" for finding in findings))

    def test_parse_mosint_style_key_values(self):
        findings = parse_adapter_output(
            "alpkeskin/mosint",
            ScanTarget(kind="email", value="person@example.com"),
            """
            Email: person@example.com
            Domain: example.com
            Name: Example Person
            """,
        )

        metadata = [finding.metadata for finding in findings]
        self.assertTrue(any(item.get("domain") == "example.com" for item in metadata))
        self.assertTrue(any(item.get("name") == "Example Person" for item in metadata))
        self.assertTrue(any(item.get("parser") == "email" for item in metadata))

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("email", "person@example.com"), entities)
        self.assertIn(("domain", "example.com"), entities)
        self.assertIn(("name", "example person"), entities)

    def test_parse_phoneinfoga_style_key_values(self):
        findings = parse_adapter_output(
            "sundowndev/phoneinfoga",
            ScanTarget(kind="phone", value="+380441234567"),
            """
            International format: +380441234567
            Country: Ukraine
            Carrier: Example Mobile
            """,
        )

        metadata = [finding.metadata for finding in findings]
        self.assertTrue(any(item.get("normalized") == "+380441234567" for item in metadata))
        self.assertTrue(any(item.get("country") == "Ukraine" for item in metadata))
        self.assertTrue(any(item.get("carrier") == "Example Mobile" for item in metadata))

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("normalized-value", "+380441234567"), entities)
        self.assertIn(("country", "ukraine"), entities)
        self.assertIn(("carrier", "example mobile"), entities)

    def test_run_adapter_findings_adds_parsed_results_after_execution(self):
        completed = subprocess.CompletedProcess(
            args=["sherlock", "example_user"],
            returncode=0,
            stdout="[+] GitHub: https://github.com/example_user\n",
            stderr="",
        )

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="sherlock"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            return_value=completed,
        ):
            findings = run_adapter_findings(
                "sherlock-project/sherlock",
                ScanTarget(kind="username", value="example_user"),
                execute=True,
            )

        self.assertEqual(findings[0].module, "external-adapter")
        self.assertEqual(findings[0].status, "completed")
        self.assertTrue(any(finding.url == "https://github.com/example_user" for finding in findings[1:]))


if __name__ == "__main__":
    unittest.main()
