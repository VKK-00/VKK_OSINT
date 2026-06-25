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

    def test_scan_accepts_http_backoff_options(self):
        result = self.run_cli(
            "scan",
            "username",
            "example_user",
            "--limit",
            "1",
            "--http-retries",
            "2",
            "--http-backoff",
            "0.2",
            "--request-delay",
            "0.1",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("GitHub", result.stdout)

    def test_scan_accepts_crawl_options(self):
        result = self.run_cli(
            "scan",
            "url",
            "example.com",
            "--crawl-pages",
            "2",
            "--crawl-depth",
            "0",
            "--format",
            "json",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        crawl = {finding["source"]: finding for finding in payload}["web-crawl"]

        self.assertEqual(crawl["metadata"]["max_pages"], "2")
        self.assertEqual(crawl["metadata"]["max_depth"], "0")

    def test_scan_username_reports_site_rule_skip(self):
        result = self.run_cli("scan", "username", "example_user", "--limit", "1", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)

        self.assertEqual(payload[0]["source"], "GitHub")
        self.assertEqual(payload[0]["status"], "skipped")
        self.assertEqual(payload[0]["metadata"]["rule_status"], "skipped")

    def test_scan_username_normalizes_at_prefix(self):
        result = self.run_cli("scan", "username", "@durov", "--limit", "1", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)

        self.assertEqual(payload[0]["url"], "https://github.com/durov")
        self.assertEqual(payload[0]["metadata"]["normalized_username"], "durov")

    def test_scan_person_dry_run_command(self):
        result = self.run_cli("scan", "person", "Ivan Petrenko", "--limit", "3", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        usernames = [finding["metadata"]["username"] for finding in payload]

        self.assertEqual(payload[0]["module"], "person-name-expansion")
        self.assertIn("ivanpetrenko", usernames)

    def test_scan_person_accepts_operator_alias(self):
        result = self.run_cli(
            "scan",
            "person",
            "Volodymyr Zelenskyy",
            "--person-alias",
            "ze-team",
            "--limit",
            "16",
            "--format",
            "json",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        by_username = {finding["metadata"]["username"]: finding["metadata"]["strategy"] for finding in payload}

        self.assertEqual(by_username["ze-team"], "operator_alias")
        self.assertEqual(by_username["zeteamzelenskyy"], "operator_alias_last_joined")

    def test_scan_person_accepts_alias_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            alias_path = Path(tmpdir) / "aliases.txt"
            alias_path.write_text("# known handles\nze-team, sluha\n", encoding="utf-8")
            result = self.run_cli(
                "scan",
                "person",
                "Volodymyr Zelenskyy",
                "--person-alias-file",
                str(alias_path),
                "--limit",
                "20",
                "--format",
                "json",
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        usernames = {finding["metadata"]["username"] for finding in payload}

        self.assertIn("ze-team", usernames)
        self.assertIn("sluha", usernames)

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
        self.assertIn("page-email-extraction", result.stdout)
        self.assertIn("web-crawl", result.stdout)
        self.assertIn("certificate-transparency", result.stdout)
        self.assertIn("rdap-domain", result.stdout)
        self.assertIn("whois-domain", result.stdout)

    def test_scan_telegram_dry_run_command(self):
        result = self.run_cli("scan", "telegram", "@durov")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("telegram-baseline", result.stdout)
        self.assertIn("https://t.me/durov", result.stdout)

    def test_scan_instagram_dry_run_command(self):
        result = self.run_cli("scan", "instagram", "@exampleuser", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)

        self.assertEqual(payload[0]["module"], "instagram-public-profile")
        self.assertEqual(payload[0]["source"], "instagram-profile-url")
        self.assertEqual(payload[0]["url"], "https://www.instagram.com/exampleuser/")
        self.assertEqual(payload[0]["metadata"]["instagram_username"], "@exampleuser")

    def test_scan_social_dry_run_command(self):
        result = self.run_cli("scan", "social", "vk:exampleuser", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)

        self.assertEqual(payload[0]["module"], "social-public-profile")
        self.assertEqual(payload[0]["source"], "vk-profile-url")
        self.assertEqual(payload[0]["url"], "https://vk.com/exampleuser")
        self.assertEqual(payload[0]["metadata"]["social_profile"], "vk:exampleuser")

    def test_scan_social_yandex_dry_run_command(self):
        result = self.run_cli("scan", "social", "yandex:q/exampleuser", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)

        self.assertEqual(payload[0]["module"], "social-public-profile")
        self.assertEqual(payload[0]["source"], "yandex-profile-url")
        self.assertEqual(payload[0]["url"], "https://yandex.ru/q/profile/exampleuser/")
        self.assertEqual(payload[0]["metadata"]["social_profile"], "yandex:q/exampleuser")

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

    def test_adapter_profiles_command(self):
        result = self.run_cli("adapter-profiles", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        profiles = {profile["name"]: profile for profile in payload}
        self.assertIn("username-full", profiles)
        self.assertIn("email-safe", profiles)
        self.assertIn("sherlock-project/sherlock", profiles["username-full"]["repositories"])

    def test_profiles_list_command(self):
        result = self.run_cli("profiles", "list", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        profiles = {profile["name"]: profile for profile in payload}

        self.assertIn("phone-full", profiles)
        self.assertIn("image-full", profiles)
        self.assertIn("phone", profiles["phone-full"]["target_kinds"])

    def test_profiles_show_accepts_custom_profile_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_path = Path(tmpdir) / "profiles.json"
            profile_path.write_text(
                json.dumps(
                    {
                        "profiles": [
                            {
                                "name": "case-image-local",
                                "target_kinds": ["image"],
                                "local_tools": ["powershell-file-baseline"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = self.run_cli(
                "profiles",
                "show",
                "case-image-local",
                "--profile-file",
                str(profile_path),
                "--format",
                "json",
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)

        self.assertEqual(payload["name"], "case-image-local")
        self.assertEqual(payload["local_tools"], ["powershell-file-baseline"])

    def test_profiles_export_writes_reusable_profile_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            export_path = Path(tmpdir) / "profiles" / "email-full.json"
            export_result = self.run_cli(
                "profiles",
                "export",
                "email-full",
                "--out",
                str(export_path),
            )
            self.assertEqual(export_result.returncode, 0, export_result.stderr)
            self.assertTrue(export_path.exists())

            exported = json.loads(export_path.read_text(encoding="utf-8"))
            self.assertEqual(exported["profiles"][0]["name"], "email-full")
            search_result = self.run_cli(
                "search",
                "email",
                "person@example.com",
                "--profile",
                "email-full",
                "--profile-file",
                str(export_path),
                "--plan-only",
                "--format",
                "json",
            )

        self.assertEqual(search_result.returncode, 0, search_result.stderr)
        payload = json.loads(search_result.stdout)
        self.assertEqual(payload["profile"]["name"], "email-full")

    def test_run_adapter_dry_run_command(self):
        result = self.run_cli("run-adapter", "sherlock-project/sherlock", "username", "example_user")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("planned", result.stdout)
        self.assertIn("sherlock example_user", result.stdout)

    def test_run_adapter_user_scanner_target_specific_commands(self):
        email = self.run_cli("run-adapter", "kaifcodec/user-scanner", "email", "person@example.com", "--format", "json")
        username = self.run_cli("run-adapter", "kaifcodec/user-scanner", "username", "example_user", "--format", "json")

        self.assertEqual(email.returncode, 0, email.stderr)
        self.assertEqual(json.loads(email.stdout)[0]["metadata"]["command"], "user-scanner -e person@example.com -f json")
        self.assertEqual(username.returncode, 0, username.stderr)
        self.assertEqual(json.loads(username.stdout)[0]["metadata"]["command"], "user-scanner -u example_user -f json")

    def test_run_adapter_maigret_region_command(self):
        result = self.run_cli(
            "run-adapter",
            "soxoj/maigret",
            "username",
            "example_user",
            "--region",
            "ua",
            "--format",
            "json",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout)[0]["metadata"]["command"],
            "maigret example_user --json ndjson --tags ua",
        )

    def test_run_adapter_snoop_region_command(self):
        result = self.run_cli(
            "run-adapter",
            "snooppr/snoop",
            "username",
            "example_user",
            "--region",
            "ua",
            "--format",
            "json",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout)[0]["metadata"]["command"],
            "snoop --no-func --found-print --include UA example_user",
        )

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
            "--instagram",
            "@exampleuser",
            "--social",
            "vk:exampleuser",
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
        self.assertIn(("instagram", "@exampleuser"), entities)
        self.assertIn(("url", "https://www.instagram.com/exampleuser/"), entities)
        self.assertIn(("social-profile", "vk:exampleuser"), entities)
        self.assertIn(("url", "https://vk.com/exampleuser"), entities)

    def test_investigate_person_expands_username_candidates(self):
        result = self.run_cli(
            "investigate",
            "--person",
            "Ivan Petrenko",
            "--format",
            "json",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        entities = {(entity["kind"], entity["value"].lower()) for entity in payload["entities"]}
        self.assertIn(("person", "ivan petrenko"), entities)
        self.assertIn(("username", "ivanpetrenko"), entities)
        self.assertIn(("url", "https://github.com/ivanpetrenko"), entities)

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

    def test_investigate_adapter_profile_requires_include_adapters(self):
        result = self.run_cli(
            "investigate",
            "--username",
            "example_user",
            "--adapter-profile",
            "username-full",
            "--format",
            "json",
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("--adapter-profile requires --include-adapters", result.stderr)

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

    def test_investigate_adapter_profile_filters_adapter_findings(self):
        result = self.run_cli(
            "investigate",
            "--username",
            "example_user",
            "--include-adapters",
            "--adapter-profile",
            "username-ru-ua",
            "--adapter-limit",
            "2",
            "--format",
            "json",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(
            [finding["source"] for finding in payload["adapter_findings"]],
            ["snooppr/snoop", "soxoj/maigret"],
        )

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
                "--scope-note",
                "internal validation scope",
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
            self.assertEqual(payload["metadata"]["workflow"], "investigate")
            self.assertFalse(payload["metadata"]["include_adapters"])
            self.assertEqual(payload["metadata"]["expanded_adapter_repositories"], [])
            self.assertEqual(payload["metadata"]["scope_note"], "internal validation scope")
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

    def test_case_update_delete_and_filtered_list_commands(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "cases.sqlite"
            report_path = Path(tmpdir) / "email.md"
            save_result = self.run_cli(
                "search",
                "email",
                "person@example.com",
                "--profile",
                "email-full",
                "--execute-adapters",
                "--adapter-limit",
                "0",
                "--case-db",
                str(db_path),
                "--case-id",
                "email-1",
                "--scope-note",
                "server scope",
                "--out",
                str(report_path),
            )
            self.assertEqual(save_result.returncode, 0, save_result.stderr)

            list_result = self.run_cli(
                "cases",
                "--case-db",
                str(db_path),
                "--workflow",
                "search",
                "--profile",
                "email-full",
                "--scope-query",
                "server",
                "--format",
                "json",
            )
            self.assertEqual(list_result.returncode, 0, list_result.stderr)
            list_payload = json.loads(list_result.stdout)
            self.assertEqual([record["case_id"] for record in list_payload], ["email-1"])

            update_result = self.run_cli(
                "case-update",
                "--case-db",
                str(db_path),
                "email-1",
                "--title",
                "updated email case",
                "--scope-note",
                "updated scope",
                "--format",
                "json",
            )
            self.assertEqual(update_result.returncode, 0, update_result.stderr)
            update_payload = json.loads(update_result.stdout)
            self.assertEqual(update_payload["case"]["title"], "updated email case")
            self.assertEqual(update_payload["metadata"]["scope_note"], "updated scope")

            delete_without_confirmation = self.run_cli(
                "case-delete",
                "--case-db",
                str(db_path),
                "email-1",
            )
            self.assertEqual(delete_without_confirmation.returncode, 2)
            self.assertIn("case-delete requires --yes", delete_without_confirmation.stderr)

            delete_result = self.run_cli(
                "case-delete",
                "--case-db",
                str(db_path),
                "email-1",
                "--yes",
                "--format",
                "json",
            )
            self.assertEqual(delete_result.returncode, 0, delete_result.stderr)
            self.assertEqual(json.loads(delete_result.stdout), {"case_id": "email-1", "deleted": True})

            show_result = self.run_cli("case-show", "--case-db", str(db_path), "email-1")
            self.assertEqual(show_result.returncode, 2)
            self.assertIn("case not found", show_result.stderr)

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
                "--url",
                "https://example.com/profile",
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

            path_result = self.run_cli(
                "case-path",
                "--case-db",
                str(db_path),
                "--from-kind",
                "email",
                "--from-value",
                "person@example.com",
                "--to-kind",
                "url",
                "--to-value",
                "https://example.com/profile",
                "--format",
                "json",
            )
            self.assertEqual(path_result.returncode, 0, path_result.stderr)
            path_payload = json.loads(path_result.stdout)
            self.assertTrue(path_payload["found"])
            self.assertEqual(path_payload["hop_count"], 2)
            self.assertEqual([step["case_id"] for step in path_payload["steps"]], ["case-1", "case-2"])

            network_result = self.run_cli(
                "case-network",
                "--case-db",
                str(db_path),
                "--kind",
                "domain",
                "--format",
                "json",
            )
            self.assertEqual(network_result.returncode, 0, network_result.stderr)
            network_payload = json.loads(network_result.stdout)
            self.assertGreaterEqual(network_payload["visible_node_count"], 3)
            network_nodes = {
                (node["kind"], node["value"].lower()): node
                for node in network_payload["nodes"]
            }
            self.assertEqual(network_nodes[("domain", "example.com")]["case_count"], 2)
            self.assertIn("email_domain", network_payload["relation_counts"])

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

    def test_toolbox_command_writes_html_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "toolbox.html"
            result = self.run_cli("toolbox", "--out", str(output))

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.exists())
            content = output.read_text(encoding="utf-8")
            self.assertIn("OSINT Toolkit Control Window", content)
            self.assertIn("Фото / изображение", content)
            self.assertIn("username-full", content)

    def test_search_phone_plan_json(self):
        result = self.run_cli(
            "search",
            "phone",
            "+380441234567",
            "--profile",
            "phone-full",
            "--plan-only",
            "--format",
            "json",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        sources = {step["source"]: step for step in payload["steps"]}

        self.assertEqual(payload["target"]["kind"], "phone")
        self.assertEqual(payload["profile"]["name"], "phone-full")
        self.assertIn("sundowndev/phoneinfoga", sources)
        self.assertEqual(sources["megadose/ignorant"]["status"], "excluded")

    def test_search_auto_email_plan_json(self):
        result = self.run_cli(
            "search",
            "auto",
            "person@example.com",
            "--profile",
            "auto",
            "--plan-only",
            "--format",
            "json",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)

        self.assertEqual(payload["target"]["kind"], "email")
        self.assertEqual(payload["profile"]["name"], "email-full")

    def test_search_accepts_custom_profile_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_path = Path(tmpdir) / "profiles.json"
            profile_path.write_text(
                json.dumps(
                    {
                        "profiles": [
                            {
                                "name": "case-email-safe",
                                "target_kinds": ["email"],
                                "native_kinds": ["email"],
                                "adapter_profiles": ["email-safe"],
                                "adapter_repositories": ["p1ngul1n0/blackbird"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = self.run_cli(
                "search",
                "email",
                "person@example.com",
                "--profile",
                "case-email-safe",
                "--profile-file",
                str(profile_path),
                "--plan-only",
                "--format",
                "json",
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        sources = {step["source"] for step in payload["steps"]}

        self.assertEqual(payload["profile"]["name"], "case-email-safe")
        self.assertIn("scan email", sources)
        self.assertIn("p1ngul1n0/blackbird", sources)

    def test_search_image_plan_markdown(self):
        result = self.run_cli(
            "search",
            "image",
            r"C:\x\photo.jpg",
            "--profile",
            "image-full",
            "--plan-only",
            "--format",
            "markdown",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("# Search Plan: image", result.stdout)
        self.assertIn("tesseract-ocr", result.stdout)
        self.assertIn("face recognition", result.stdout)

    def test_search_include_restricted_marks_restricted(self):
        result = self.run_cli(
            "search",
            "phone",
            "+380441234567",
            "--profile",
            "phone-full",
            "--include-restricted",
            "--plan-only",
            "--format",
            "json",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        sources = {step["source"]: step for step in payload["steps"]}

        self.assertEqual(sources["megadose/ignorant"]["status"], "restricted")

    def test_search_execute_adapters_writes_json_report_without_ready_adapters(self):
        result = self.run_cli(
            "search",
            "email",
            "person@example.com",
            "--profile",
            "email-full",
            "--execute-adapters",
            "--adapter-limit",
            "0",
            "--format",
            "json",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)

        self.assertEqual(payload["search_plan"]["target"]["kind"], "email")
        self.assertEqual(payload["executed_adapters"], [])
        self.assertEqual(payload["investigation"]["targets"][0]["value"], "person@example.com")
        targets = {(target["kind"], target["value"]) for target in payload["investigation"]["targets"]}
        self.assertIn(("domain", "example.com"), targets)
        self.assertEqual(payload["derived_targets"], [{"kind": "domain", "value": "example.com", "region": "all"}])

    def test_search_execute_adapters_derives_domain_from_url(self):
        result = self.run_cli(
            "search",
            "url",
            "https://example.com/path",
            "--profile",
            "web-full",
            "--execute-adapters",
            "--adapter-limit",
            "0",
            "--format",
            "json",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)

        targets = {(target["kind"], target["value"]) for target in payload["investigation"]["targets"]}
        self.assertIn(("url", "https://example.com/path"), targets)
        self.assertIn(("domain", "example.com"), targets)
        self.assertEqual(payload["derived_targets"], [{"kind": "domain", "value": "example.com", "region": "all"}])

    def test_search_execute_adapters_respects_custom_profile_native_kinds(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_path = Path(tmpdir) / "profiles.json"
            profile_path.write_text(
                json.dumps(
                    {
                        "profiles": [
                            {
                                "name": "case-email-adapter-only",
                                "target_kinds": ["email"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = self.run_cli(
                "search",
                "email",
                "person@example.com",
                "--profile",
                "case-email-adapter-only",
                "--profile-file",
                str(profile_path),
                "--execute-adapters",
                "--adapter-limit",
                "0",
                "--format",
                "json",
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["search_plan"]["profile"]["native_kinds"], [])
        self.assertEqual(payload["investigation"]["findings"], [])
        self.assertEqual(payload["executed_adapters"], [])
        self.assertEqual(payload["derived_targets"], [])

    def test_search_execute_adapters_can_save_report_and_case(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "search.md"
            db_path = Path(tmpdir) / "cases.sqlite"
            result = self.run_cli(
                "search",
                "phone",
                "+380441234567",
                "--profile",
                "phone-full",
                "--execute-adapters",
                "--adapter-limit",
                "0",
                "--out",
                str(report_path),
                "--case-db",
                str(db_path),
                "--case-id",
                "phone-search-1",
                "--scope-note",
                "phone validation scope",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(report_path.exists())
            self.assertTrue(db_path.exists())
            self.assertIn("Wrote", result.stdout)
            self.assertIn("Saved case phone-search-1", result.stdout)

            content = report_path.read_text(encoding="utf-8")
            self.assertIn("# Search Execution Report: phone", content)
            self.assertIn("## Fan-out Plan", content)
            self.assertIn("## Investigation Report", content)
            show_result = self.run_cli(
                "case-show",
                "--case-db",
                str(db_path),
                "phone-search-1",
                "--format",
                "json",
            )
            self.assertEqual(show_result.returncode, 0, show_result.stderr)
            payload = json.loads(show_result.stdout)
            self.assertEqual(payload["metadata"]["workflow"], "search")
            self.assertEqual(payload["metadata"]["requested_profile"], "phone-full")
            self.assertEqual(payload["metadata"]["search_profile"]["name"], "phone-full")
            self.assertEqual(payload["metadata"]["executed_adapters"], [])
            self.assertEqual(payload["metadata"]["scope_note"], "phone validation scope")

    def test_search_execute_adapters_runs_image_local_tools_and_saves_case(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = Path(tmpdir) / "photo.jpg"
            image_path.write_bytes(b"not really an image")
            report_path = Path(tmpdir) / "image.md"
            db_path = Path(tmpdir) / "cases.sqlite"
            result = self.run_cli(
                "search",
                "image",
                str(image_path),
                "--profile",
                "image-full",
                "--execute-adapters",
                "--adapter-limit",
                "0",
                "--out",
                str(report_path),
                "--case-db",
                str(db_path),
                "--case-id",
                "image-search-1",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(report_path.exists())
            self.assertTrue(db_path.exists())
            self.assertIn("Saved case image-search-1", result.stdout)
            content = report_path.read_text(encoding="utf-8")
            self.assertIn("# Search Execution Report: image", content)
            self.assertIn("Executed Local Tools", content)
            self.assertIn("Face recognition: disabled", content)

    def test_search_execute_adapters_rejects_plan_only_conflict(self):
        result = self.run_cli(
            "search",
            "phone",
            "+380441234567",
            "--profile",
            "phone-full",
            "--plan-only",
            "--execute-adapters",
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("mutually exclusive", result.stderr)

    def test_search_case_id_requires_case_db(self):
        result = self.run_cli(
            "search",
            "phone",
            "+380441234567",
            "--profile",
            "phone-full",
            "--execute-adapters",
            "--adapter-limit",
            "0",
            "--case-id",
            "phone-search-1",
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("--case-id requires --case-db", result.stderr)

    def test_tools_doctor_profile_reports_search_profile_readiness(self):
        result = self.run_cli("tools", "doctor", "--profile", "image-full", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        names = {row["name"] for row in payload}

        self.assertIn("powershell-file-baseline", names)
        self.assertIn("tesseract-ocr", names)

    def test_tools_doctor_accepts_custom_profile_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_path = Path(tmpdir) / "profiles.json"
            profile_path.write_text(
                json.dumps(
                    {
                        "profiles": [
                            {
                                "name": "case-image-local",
                                "target_kinds": ["image"],
                                "local_tools": ["powershell-file-baseline", "tesseract-ocr"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = self.run_cli(
                "tools",
                "doctor",
                "--profile",
                "case-image-local",
                "--profile-file",
                str(profile_path),
                "--format",
                "json",
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        names = {row["name"] for row in json.loads(result.stdout)}

        self.assertEqual(names, {"powershell-file-baseline", "tesseract-ocr"})

    def test_tools_install_plan_profile_shows_actions(self):
        result = self.run_cli("tools", "install-plan", "--profile", "image-full", "--format", "markdown")
        self.assertEqual(result.returncode, 0, result.stderr)

        self.assertIn("Install / action", result.stdout)
        self.assertIn("ExifTool", result.stdout)

    def test_tools_install_plan_skips_excluded_restricted_adapters(self):
        doctor = self.run_cli("tools", "doctor", "--profile", "phone-full", "--format", "json")
        self.assertEqual(doctor.returncode, 0, doctor.stderr)
        rows = {row["name"]: row for row in json.loads(doctor.stdout)}
        self.assertEqual(rows["megadose/ignorant"]["readiness"], "excluded")

        result = self.run_cli("tools", "install-plan", "--profile", "phone-full", "--format", "markdown")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("megadose/ignorant", result.stdout)

    def test_tools_env_profile_shows_names_only(self):
        result = self.run_cli("tools", "env", "--profile", "email-full", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        serialized = json.dumps(payload)

        self.assertIn("BLACKBIRD_DIR", serialized)
        self.assertNotIn("secret-value", serialized)


if __name__ == "__main__":
    unittest.main()
