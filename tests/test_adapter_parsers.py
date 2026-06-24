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

    def test_parse_user_scanner_json_results(self):
        findings = parse_adapter_output(
            "kaifcodec/user-scanner",
            ScanTarget(kind="username", value="kaifcodec"),
            """
            [
              {
                "status": "Found",
                "reason": "",
                "username": "kaifcodec",
                "site_name": "Github",
                "category": "Dev",
                "url": "https://github.com/kaifcodec",
                "extra": {"name": "Kaif", "followers": "243"}
              },
              {
                "status": "Not Found",
                "reason": "",
                "username": "kaifcodec",
                "site_name": "Example",
                "category": "Social",
                "url": "https://example.com/kaifcodec",
                "extra": {}
              }
            ]
            """,
        )

        self.assertEqual(len(findings), 2)
        github = next(finding for finding in findings if finding.metadata["site_name"] == "Github")
        self.assertEqual(github.status, "candidate")
        self.assertEqual(github.confidence, "high")
        self.assertEqual(github.url, "https://github.com/kaifcodec")
        self.assertEqual(github.metadata["parser"], "user-scanner")
        self.assertEqual(github.metadata["username"], "kaifcodec")
        self.assertEqual(github.metadata["extra_name"], "Kaif")
        missing = next(finding for finding in findings if finding.metadata["site_name"] == "Example")
        self.assertEqual(missing.status, "not_found")
        self.assertEqual(missing.url, "")
        self.assertEqual(missing.metadata["checked_url"], "https://example.com/kaifcodec")

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("username", "kaifcodec"), entities)
        self.assertIn(("domain", "github.com"), entities)
        self.assertNotIn(("domain", "example.com"), entities)

    def test_parse_user_scanner_email_json_result(self):
        findings = parse_adapter_output(
            "kaifcodec/user-scanner",
            ScanTarget(kind="email", value="target@gmail.com"),
            """
            {
              "email": "target@gmail.com",
              "category": "Social",
              "site_name": "Instagram",
              "status": "Registered",
              "url": "https://instagram.com",
              "extra": "",
              "reason": ""
            }
            """,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "candidate")
        self.assertEqual(findings[0].metadata["email"], "target@gmail.com")
        self.assertEqual(findings[0].metadata["category"], "Social")

    def test_parse_user_scanner_verbose_lines(self):
        findings = parse_adapter_output(
            "kaifcodec/user-scanner",
            ScanTarget(kind="email", value="johndoe@gmail.com"),
            """
            [ok] Huggingface [https://huggingface.co] (johndoe@gmail.com): Registered
            [x] Envato [https://account.envato.com] (johndoe@gmail.com): Available
            """,
        )

        statuses = {finding.metadata["site_name"]: finding.status for finding in findings}
        self.assertEqual(statuses["Huggingface"], "candidate")
        self.assertEqual(statuses["Envato"], "not_found")
        envato = next(finding for finding in findings if finding.metadata["site_name"] == "Envato")
        self.assertEqual(envato.url, "")
        self.assertEqual(envato.metadata["checked_url"], "https://account.envato.com")

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

    def test_run_user_scanner_adapter_adds_parsed_json_results_after_execution(self):
        completed = subprocess.CompletedProcess(
            args=["user-scanner", "-u", "kaifcodec", "-f", "json"],
            returncode=0,
            stdout='[{"status":"Found","username":"kaifcodec","site_name":"Github","category":"Dev","url":"https://github.com/kaifcodec","extra":{},"reason":""}]',
            stderr="",
        )

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="user-scanner"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            return_value=completed,
        ):
            findings = run_adapter_findings(
                "kaifcodec/user-scanner",
                ScanTarget(kind="username", value="kaifcodec"),
                execute=True,
            )

        self.assertEqual(findings[0].status, "completed")
        self.assertTrue(any(finding.metadata.get("site_name") == "Github" for finding in findings[1:]))


if __name__ == "__main__":
    unittest.main()
