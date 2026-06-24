import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "osint_toolkit", *args],
            cwd=Path(__file__).resolve().parents[1],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_stats_command(self):
        result = self.run_cli("stats")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Total:        100", result.stdout)
        self.assertIn("People:       55", result.stdout)

    def test_catalog_markdown_command(self):
        result = self.run_cli("catalog", "--kind", "ru-ua", "--level", "direct_ru_ua", "--format", "markdown")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("snooppr/snoop", result.stdout)
        self.assertIn("| Rank | Repository |", result.stdout)

    def test_scan_username_dry_run_command(self):
        result = self.run_cli("scan", "username", "example_user", "--limit", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("GitHub", result.stdout)
        self.assertIn("planned", result.stdout)

    def test_scan_email_dry_run_command(self):
        result = self.run_cli("scan", "email", "person@example.com")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("email-baseline", result.stdout)
        self.assertIn("domain-resolution", result.stdout)

    def test_scan_phone_dry_run_command(self):
        result = self.run_cli("scan", "phone", "+380441234567")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("phone-baseline", result.stdout)
        self.assertIn("Ukraine", result.stdout)

    def test_scan_domain_dry_run_command(self):
        result = self.run_cli("scan", "domain", "example.com")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("domain-baseline", result.stdout)
        self.assertIn("dns-resolution", result.stdout)

    def test_scan_telegram_dry_run_command(self):
        result = self.run_cli("scan", "telegram", "@durov")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("telegram-baseline", result.stdout)
        self.assertIn("https://t.me/durov", result.stdout)

    def test_scan_ru_ua_source_pack_command(self):
        result = self.run_cli("scan", "ru-ua", "all", "--region", "ua", "--format", "markdown")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("DeepStateMap", result.stdout)
        self.assertIn("paste.in.ua", result.stdout)
        self.assertNotIn("| VK |", result.stdout)

    def test_adapters_command(self):
        result = self.run_cli("adapters", "--status", "partial_native")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sherlock-project/sherlock", result.stdout)

    def test_run_adapter_dry_run_command(self):
        result = self.run_cli("run-adapter", "sherlock-project/sherlock", "username", "example_user")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("planned", result.stdout)
        self.assertIn("sherlock example_user", result.stdout)

    def test_run_adapter_restricted_command(self):
        result = self.run_cli("run-adapter", "megadose/holehe", "email", "person@example.com")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("restricted", result.stdout)

    def test_doctor_command(self):
        result = self.run_cli("doctor", "--status", "restricted")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("megadose/holehe", result.stdout)
        self.assertIn("restricted", result.stdout)

    def test_investigate_command_writes_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "case.md"
            result = self.run_cli(
                "investigate",
                "--title",
                "example case",
                "--username",
                "example_user",
                "--domain",
                "example.com",
                "--include-adapters",
                "--out",
                str(output),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.exists())
            content = output.read_text(encoding="utf-8")
            self.assertIn("# example case", content)
            self.assertIn("Entity Summary", content)
            self.assertIn("Native Findings", content)
            self.assertIn("Adapter Dry Runs", content)

    def test_investigate_json_includes_entities(self):
        result = self.run_cli(
            "investigate",
            "--email",
            "person@example.com",
            "--telegram",
            "@durov",
            "--format",
            "json",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        entities = {(entity["kind"], entity["value"].lower()) for entity in payload["entities"]}
        self.assertIn(("email", "person@example.com"), entities)
        self.assertIn(("domain", "example.com"), entities)
        self.assertIn(("telegram", "@durov"), entities)
        self.assertIn(("url", "https://t.me/durov"), entities)

    def test_investigate_can_save_and_show_case(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "cases.sqlite"
            report_path = Path(tmpdir) / "case.md"
            save_result = self.run_cli(
                "investigate",
                "--title",
                "saved case",
                "--email",
                "person@example.com",
                "--telegram",
                "@durov",
                "--case-db",
                str(db_path),
                "--case-id",
                "case-1",
                "--out",
                str(report_path),
            )
            self.assertEqual(save_result.returncode, 0, save_result.stderr)
            self.assertTrue(db_path.exists())
            self.assertIn("Saved case case-1", save_result.stdout)

            list_result = self.run_cli("cases", "--case-db", str(db_path))
            self.assertEqual(list_result.returncode, 0, list_result.stderr)
            self.assertIn("case-1", list_result.stdout)
            self.assertIn("saved case", list_result.stdout)

            show_result = self.run_cli("case-show", "--case-db", str(db_path), "case-1", "--format", "json")
            self.assertEqual(show_result.returncode, 0, show_result.stderr)
            payload = json.loads(show_result.stdout)
            self.assertEqual(payload["case"]["title"], "saved case")
            entities = {(entity["kind"], entity["value"].lower()) for entity in payload["entities"]}
            self.assertIn(("email", "person@example.com"), entities)
            self.assertIn(("domain", "example.com"), entities)

    def test_brief_command_writes_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "brief.md"
            result = self.run_cli(
                "brief",
                "--task",
                "telegram",
                "--region",
                "ua",
                "--target-value",
                "public channel",
                "--out",
                str(output),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.exists())
            content = output.read_text(encoding="utf-8")
            self.assertIn("OSINT brief", content)
            self.assertIn("Seed value: `public channel`", content)


if __name__ == "__main__":
    unittest.main()
