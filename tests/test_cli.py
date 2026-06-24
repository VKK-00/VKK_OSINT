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
