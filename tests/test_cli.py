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

    def test_adapter_setup_command(self):
        result = self.run_cli("adapter-setup", "sherlock-project/sherlock", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)

        self.assertEqual(payload[0]["repository"], "sherlock-project/sherlock")
        self.assertEqual(payload[0]["install_kind"], "pipx")
        self.assertEqual(payload[0]["install_command"], "pipx install sherlock-project")
        self.assertIn("sherlockproject.xyz", payload[0]["docs_url"])

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

    def test_investigate_execute_adapters_requires_include_adapters(self):
        result = self.run_cli(
            "investigate",
            "--username",
            "example_user",
            "--execute-adapters",
            "--format",
            "json",
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("--execute-adapters requires --include-adapters", result.stderr)

    def test_investigate_adapter_allowlist_requires_include_adapters(self):
        result = self.run_cli(
            "investigate",
            "--username",
            "example_user",
            "--adapter",
            "soxoj/maigret",
            "--format",
            "json",
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("--adapter requires --include-adapters", result.stderr)

    def test_investigate_adapter_allowlist_filters_adapter_findings(self):
        result = self.run_cli(
            "investigate",
            "--username",
            "example_user",
            "--include-adapters",
            "--adapter",
            "soxoj/maigret",
            "--format",
            "json",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual([finding["source"] for finding in payload["adapter_findings"]], ["soxoj/maigret"])
        self.assertEqual(payload["adapter_findings"][0]["status"], "planned")

    def test_investigate_allow_restricted_adapters_requires_execute_adapters(self):
        result = self.run_cli(
            "investigate",
            "--username",
            "example_user",
            "--include-adapters",
            "--allow-restricted-adapters",
            "--format",
            "json",
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("--allow-restricted-adapters requires --execute-adapters", result.stderr)

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
            edges = {
                (edge["source_kind"], edge["relation"], edge["target_kind"], edge["target_value"].lower())
                for edge in payload["edges"]
            }
            self.assertIn(("email", "email_domain", "domain", "example.com"), edges)

            graph_result = self.run_cli("case-graph", "--case-db", str(db_path), "case-1", "--format", "json")
            self.assertEqual(graph_result.returncode, 0, graph_result.stderr)
            graph_payload = json.loads(graph_result.stdout)
            self.assertEqual(graph_payload["case_id"], "case-1")
            self.assertGreaterEqual(graph_payload["node_count"], 4)
            self.assertEqual(graph_payload["relation_counts"]["email_domain"], 1)

            focus_result = self.run_cli(
                "case-graph",
                "--case-db",
                str(db_path),
                "case-1",
                "--entity-kind",
                "email",
                "--entity-value",
                "person@example.com",
                "--format",
                "json",
            )
            self.assertEqual(focus_result.returncode, 0, focus_result.stderr)
            focus_payload = json.loads(focus_result.stdout)
            self.assertEqual(focus_payload["focus"]["kind"], "email")
            neighbors = {
                (neighbor["kind"], neighbor["value"].lower(), neighbor["relation"])
                for neighbor in focus_payload["neighbors"]
            }
            self.assertIn(("domain", "example.com", "email_domain"), neighbors)

    def test_case_index_can_find_shared_entities(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "cases.sqlite"
            first = self.run_cli(
                "investigate",
                "--title",
                "first case",
                "--email",
                "person@example.com",
                "--case-db",
                str(db_path),
                "--case-id",
                "case-1",
                "--out",
                str(Path(tmpdir) / "first.md"),
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            second = self.run_cli(
                "investigate",
                "--title",
                "second case",
                "--domain",
                "example.com",
                "--case-db",
                str(db_path),
                "--case-id",
                "case-2",
                "--out",
                str(Path(tmpdir) / "second.md"),
            )
            self.assertEqual(second.returncode, 0, second.stderr)

            index_result = self.run_cli(
                "case-index",
                "--case-db",
                str(db_path),
                "--kind",
                "domain",
                "--min-cases",
                "2",
                "--format",
                "json",
            )
            self.assertEqual(index_result.returncode, 0, index_result.stderr)
            index_payload = json.loads(index_result.stdout)
            records = {(record["kind"], record["value"].lower()): record for record in index_payload}
            self.assertIn(("domain", "example.com"), records)
            self.assertEqual(records[("domain", "example.com")]["case_count"], 2)

            search_result = self.run_cli(
                "case-index",
                "--case-db",
                str(db_path),
                "--kind",
                "domain",
                "--value",
                "example.com",
                "--format",
                "json",
            )
            self.assertEqual(search_result.returncode, 0, search_result.stderr)
            hits = json.loads(search_result.stdout)
            self.assertEqual({hit["case_id"] for hit in hits}, {"case-1", "case-2"})

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
