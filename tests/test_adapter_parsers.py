import subprocess
import unittest
from pathlib import Path
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

    def test_parse_maigret_ndjson_report(self):
        findings = parse_adapter_output(
            "soxoj/maigret",
            ScanTarget(kind="username", value="bellingcat", region="ua"),
            """
            {"sitename":"GitHub","url_user":"https://github.com/bellingcat","http_status":200,"status":{"username":"bellingcat","site_name":"GitHub","url":"https://github.com/bellingcat","status":"Claimed","ids":{"fullname":"Bellingcat","location":"Netherlands"},"tags":["coding","global"]}}
            {"sitename":"Example","url_user":"https://example.com/bellingcat","http_status":404,"status":{"username":"bellingcat","site_name":"Example","url":"https://example.com/bellingcat","status":"Available","ids":{},"tags":["ua"]}}
            """,
        )

        self.assertEqual(len(findings), 2)
        github = next(finding for finding in findings if finding.metadata["site_name"] == "GitHub")
        self.assertEqual(github.status, "candidate")
        self.assertEqual(github.confidence, "high")
        self.assertEqual(github.url, "https://github.com/bellingcat")
        self.assertEqual(github.metadata["parser"], "maigret")
        self.assertEqual(github.metadata["name"], "Bellingcat")
        self.assertEqual(github.metadata["location"], "Netherlands")

        missing = next(finding for finding in findings if finding.metadata["site_name"] == "Example")
        self.assertEqual(missing.status, "not_found")
        self.assertEqual(missing.url, "")
        self.assertEqual(missing.metadata["checked_url"], "https://example.com/bellingcat")
        self.assertEqual(missing.metadata["region"], "UA")

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("domain", "github.com"), entities)
        self.assertIn(("name", "bellingcat"), entities)
        self.assertIn(("location", "netherlands"), entities)
        self.assertIn(("region", "ua"), entities)
        self.assertNotIn(("domain", "example.com"), entities)

    def test_parse_maigret_simple_json_report(self):
        findings = parse_adapter_output(
            "soxoj/maigret",
            ScanTarget(kind="username", value="bellingcat"),
            """
            {
              "Telegram": {
                "url_user": "https://t.me/bellingcat",
                "http_status": 200,
                "status": {
                  "username": "bellingcat",
                  "site_name": "Telegram",
                  "url": "https://t.me/bellingcat",
                  "status": "Claimed",
                  "ids": {"country": "Ukraine"},
                  "tags": ["ua", "messaging"]
                }
              }
            }
            """,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].metadata["site_name"], "Telegram")
        self.assertEqual(findings[0].metadata["country"], "Ukraine")
        self.assertEqual(findings[0].metadata["region"], "UA")

    def test_parse_maigret_csv_report(self):
        findings = parse_adapter_output(
            "soxoj/maigret",
            ScanTarget(kind="username", value="bellingcat"),
            """
            username,name,url_main,url_user,exists,http_status
            bellingcat,GitHub,https://github.com,https://github.com/bellingcat,Claimed,200
            bellingcat,Example,https://example.com,https://example.com/bellingcat,Available,404
            bellingcat,Broken,https://broken.example,https://broken.example/bellingcat,Unknown,0
            """,
        )

        statuses = {finding.metadata["site_name"]: finding.status for finding in findings}
        self.assertEqual(statuses["GitHub"], "candidate")
        self.assertEqual(statuses["Example"], "not_found")
        self.assertEqual(statuses["Broken"], "error")
        github = next(finding for finding in findings if finding.metadata["site_name"] == "GitHub")
        self.assertEqual(github.url, "https://github.com/bellingcat")
        example = next(finding for finding in findings if finding.metadata["site_name"] == "Example")
        self.assertEqual(example.url, "")
        self.assertEqual(example.metadata["checked_url"], "https://example.com/bellingcat")

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

    def test_parse_h8mail_json_report_redacts_sensitive_values(self):
        findings = parse_adapter_output(
            "khast3x/h8mail",
            ScanTarget(kind="email", value="target@example.com"),
            """
            {
              "targets": [
                {
                  "target": "target@example.com",
                  "pwn_num": 3,
                  "data": [
                    ["HIBP3:Adobe", "HIBP3:LinkedIn"],
                    ["HUNTER_RELATED:admin@example.com"],
                    ["SNUS_USERNAME:targetuser", "SNUS_PASSWORD:secret-value", "SNUS_SOURCE:combo-db"],
                    ["HIBP3_PASTE:https://pastebin.com/abc123"]
                  ]
                }
              ]
            }
            """,
        )

        self.assertTrue(any(finding.metadata.get("parser") == "h8mail" for finding in findings))
        summary = next(finding for finding in findings if finding.metadata.get("category") == "breach-summary")
        self.assertEqual(summary.status, "candidate")
        self.assertEqual(summary.metadata["breach_count"], "3")

        related = next(finding for finding in findings if finding.metadata.get("category") == "related-email")
        self.assertEqual(related.metadata["email"], "admin@example.com")
        self.assertEqual(related.metadata["domain"], "example.com")

        username = next(finding for finding in findings if finding.metadata.get("username") == "targetuser")
        self.assertEqual(username.metadata["category"], "username")

        secret = next(finding for finding in findings if finding.metadata.get("category") == "credential-exposure")
        self.assertEqual(secret.metadata["sensitive_value_redacted"], "true")
        self.assertNotIn("secret-value", secret.evidence)
        self.assertFalse(any(value == "secret-value" for value in secret.metadata.values()))

        paste = next(finding for finding in findings if finding.url == "https://pastebin.com/abc123")
        self.assertEqual(paste.metadata["domain"], "pastebin.com")

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("email", "admin@example.com"), entities)
        self.assertIn(("username", "targetuser"), entities)
        self.assertIn(("domain", "pastebin.com"), entities)

    def test_parse_snoop_csv_report(self):
        findings = parse_adapter_output(
            "snooppr/snoop",
            ScanTarget(kind="username", value="example_user", region="ua"),
            """
            Resource,Geo,Url,Url_username,Status,Http_code,Deceleration/s,Response/s,Time/s,Session/kB
            GitHub,US,https://github.com,https://github.com/example_user,найден!,200,0.1,0.2,0.3,12
            Example UA,UA,https://example.ua,https://example.ua/example_user,Увы!,404,0.1,0.2,0.4,4
            Broken RU,RU,https://broken.ru,https://broken.ru/example_user,блок,сбой,0.1,0.2,0.5,Bad
            «-----------------------------------,----,-----------------------------------,--------------------------------------------------------,-------------,-----------------,-------------------------------------,-----------------,----------------------------,--------------»
            Nick=example_user
            """,
        )

        self.assertEqual(len(findings), 3)
        github = next(finding for finding in findings if finding.metadata["site_name"] == "GitHub")
        self.assertEqual(github.status, "candidate")
        self.assertEqual(github.confidence, "high")
        self.assertEqual(github.url, "https://github.com/example_user")
        self.assertEqual(github.metadata["parser"], "snoop")
        self.assertEqual(github.metadata["region"], "US")
        self.assertEqual(github.metadata["domain"], "github.com")

        missing = next(finding for finding in findings if finding.metadata["site_name"] == "Example UA")
        self.assertEqual(missing.status, "not_found")
        self.assertEqual(missing.url, "")
        self.assertEqual(missing.metadata["checked_url"], "https://example.ua/example_user")

        blocked = next(finding for finding in findings if finding.metadata["site_name"] == "Broken RU")
        self.assertEqual(blocked.status, "error")
        self.assertEqual(blocked.confidence, "low")
        self.assertEqual(blocked.url, "")

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("domain", "github.com"), entities)
        self.assertIn(("region", "ua"), entities)
        self.assertIn(("region", "ru"), entities)
        self.assertNotIn(("domain", "example.ua"), entities)
        self.assertNotIn(("domain", "broken.ru"), entities)

    def test_parse_snoop_stdout_lines(self):
        findings = parse_adapter_output(
            "snooppr/snoop",
            ScanTarget(kind="username", value="example_user"),
            """
            [+] GitHub: https://github.com/example_user
            [-] VK: Увы!
            """,
        )

        statuses = {finding.metadata["site_name"]: finding.status for finding in findings}
        self.assertEqual(statuses["GitHub"], "candidate")
        self.assertEqual(statuses["VK"], "not_found")
        github = next(finding for finding in findings if finding.metadata["site_name"] == "GitHub")
        self.assertEqual(github.url, "https://github.com/example_user")

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

    def test_run_maigret_adapter_reads_generated_json_report_after_execution(self):
        def fake_run(args, **kwargs):
            output_dir = Path(args[args.index("--folderoutput") + 1])
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "report_bellingcat_ndjson.json").write_text(
                '{"sitename":"GitHub","url_user":"https://github.com/bellingcat","http_status":200,'
                '"status":{"username":"bellingcat","site_name":"GitHub","url":"https://github.com/bellingcat",'
                '"status":"Claimed","ids":{"fullname":"Bellingcat"},"tags":["global"]}}\n',
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="JSON report saved\n", stderr="")

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="maigret"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            side_effect=fake_run,
        ):
            findings = run_adapter_findings(
                "soxoj/maigret",
                ScanTarget(kind="username", value="bellingcat"),
                execute=True,
            )

        self.assertEqual(findings[0].status, "completed")
        self.assertEqual(findings[0].metadata["generated_output_files"], "1")
        self.assertIn("--folderoutput", findings[0].metadata["command"])
        self.assertTrue(any(finding.metadata.get("parser") == "maigret" for finding in findings[1:]))
        self.assertTrue(any(finding.url == "https://github.com/bellingcat" for finding in findings[1:]))

    def test_run_h8mail_adapter_reads_generated_json_report_after_execution(self):
        def fake_run(args, **kwargs):
            self.assertIn("--hide", args)
            output_file = Path(args[args.index("-j") + 1])
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(
                '{"targets":[{"target":"target@example.com","pwn_num":1,'
                '"data":[["HUNTER_RELATED:admin@example.com"],["SNUS_PASSWORD:secret-value","SNUS_SOURCE:combo-db"]]}]}',
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="JSON report saved\n", stderr="")

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="h8mail"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            side_effect=fake_run,
        ):
            findings = run_adapter_findings(
                "khast3x/h8mail",
                ScanTarget(kind="email", value="target@example.com"),
                execute=True,
            )

        self.assertEqual(findings[0].status, "completed")
        self.assertEqual(findings[0].metadata["generated_output_files"], "1")
        self.assertIn("-j", findings[0].metadata["command"])
        self.assertTrue(any(finding.metadata.get("parser") == "h8mail" for finding in findings[1:]))
        self.assertTrue(any(finding.metadata.get("email") == "admin@example.com" for finding in findings[1:]))
        self.assertFalse(any("secret-value" in finding.evidence for finding in findings))

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

    def test_run_snoop_adapter_adds_parsed_results_after_execution(self):
        completed = subprocess.CompletedProcess(
            args=["snoop", "--no-func", "--found-print", "--include", "UA", "example_user"],
            returncode=0,
            stdout="[+] Example UA: https://example.ua/example_user\n",
            stderr="",
        )

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="snoop"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            return_value=completed,
        ):
            findings = run_adapter_findings(
                "snooppr/snoop",
                ScanTarget(kind="username", value="example_user", region="ua"),
                execute=True,
            )

        self.assertEqual(findings[0].status, "completed")
        self.assertTrue(any(finding.metadata.get("parser") == "snoop" for finding in findings[1:]))
        self.assertTrue(any(finding.url == "https://example.ua/example_user" for finding in findings[1:]))


if __name__ == "__main__":
    unittest.main()
