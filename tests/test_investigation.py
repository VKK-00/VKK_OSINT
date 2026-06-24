import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from osint_toolkit.engine import ScanTarget
from osint_toolkit.investigation import render_investigation_markdown, run_investigation


class InvestigationTests(unittest.TestCase):
    def test_adapter_allowlist_limits_dry_run_repositories(self):
        result = run_investigation(
            (ScanTarget(kind="username", value="example_user"),),
            include_adapters=True,
            adapter_limit=10,
            adapter_repositories=("soxoj/maigret", "sherlock-project/sherlock", "soxoj/maigret"),
        )

        repositories = [finding.source for finding in result.adapter_findings]
        self.assertEqual(repositories, ["soxoj/maigret", "sherlock-project/sherlock"])
        self.assertTrue(all(finding.status == "planned" for finding in result.adapter_findings))

    def test_unsupported_dry_run_adapter_stays_in_dry_run_section(self):
        result = run_investigation(
            (ScanTarget(kind="domain", value="example.com"),),
            include_adapters=True,
            adapter_repositories=("laramies/theHarvester",),
        )

        self.assertEqual(result.adapter_findings[0].status, "unsupported")
        report = render_investigation_markdown(result)
        self.assertIn("## Adapter Dry Runs", report)
        self.assertNotIn("## Adapter Findings", report)

    def test_execute_adapters_adds_parsed_entities_and_edges(self):
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
            result = run_investigation(
                (ScanTarget(kind="username", value="example_user"),),
                include_adapters=True,
                execute_adapters=True,
                adapter_limit=1,
            )

        self.assertTrue(any(finding.status == "completed" for finding in result.adapter_findings))
        self.assertTrue(any(finding.module == "external-adapter-parser" for finding in result.adapter_findings))

        entities = {(entity.kind, entity.value.lower()) for entity in result.entities}
        self.assertIn(("url", "https://github.com/example_user"), entities)
        self.assertIn(("domain", "github.com"), entities)

        edges = {
            (edge.source_kind, edge.source_value.lower(), edge.relation, edge.target_kind, edge.target_value.lower())
            for edge in result.edges
        }
        self.assertIn(("username", "example_user", "produced_url", "url", "https://github.com/example_user"), edges)

        report = render_investigation_markdown(result)
        self.assertIn("## Adapter Findings", report)
        self.assertIn("external-adapter-parser", report)

    def test_execute_user_scanner_adapter_adds_parsed_entities_and_edges(self):
        completed = subprocess.CompletedProcess(
            args=["user-scanner", "-u", "kaifcodec", "-f", "json"],
            returncode=0,
            stdout='[{"status":"Found","username":"kaifcodec","site_name":"Custom","category":"Social","url":"https://profiles.example.net/kaifcodec","extra":{"name":"Kaif"},"reason":""}]',
            stderr="",
        )

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="user-scanner"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            return_value=completed,
        ):
            result = run_investigation(
                (ScanTarget(kind="username", value="kaifcodec"),),
                include_adapters=True,
                execute_adapters=True,
                adapter_repositories=("kaifcodec/user-scanner",),
            )

        parsed = [finding for finding in result.adapter_findings if finding.module == "external-adapter-parser"]
        self.assertEqual(parsed[0].metadata["parser"], "user-scanner")
        self.assertEqual(parsed[0].metadata["site_name"], "Custom")

        entities = {(entity.kind, entity.value.lower()) for entity in result.entities}
        self.assertIn(("url", "https://profiles.example.net/kaifcodec"), entities)
        self.assertIn(("domain", "profiles.example.net"), entities)

        edges = {
            (edge.source_kind, edge.source_value.lower(), edge.relation, edge.target_kind, edge.target_value.lower())
            for edge in result.edges
        }
        self.assertIn(("username", "kaifcodec", "produced_url", "url", "https://profiles.example.net/kaifcodec"), edges)

    def test_execute_snoop_adapter_adds_parsed_entities_and_edges(self):
        completed = subprocess.CompletedProcess(
            args=["snoop", "--no-func", "--found-print", "--include", "UA", "example_user"],
            returncode=0,
            stdout=(
                "Resource,Geo,Url,Url_username,Status,Http_code,Deceleration/s,Response/s,Time/s,Session/kB\n"
                "Example UA,UA,https://example.ua,https://example.ua/example_user,найден!,200,0.1,0.2,0.3,12\n"
            ),
            stderr="",
        )

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="snoop"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            return_value=completed,
        ):
            result = run_investigation(
                (ScanTarget(kind="username", value="example_user", region="ua"),),
                include_adapters=True,
                execute_adapters=True,
                adapter_repositories=("snooppr/snoop",),
            )

        parsed = [finding for finding in result.adapter_findings if finding.module == "external-adapter-parser"]
        self.assertEqual(parsed[0].metadata["parser"], "snoop")
        self.assertEqual(parsed[0].metadata["site_name"], "Example UA")
        self.assertEqual(parsed[0].metadata["region"], "UA")

        entities = {(entity.kind, entity.value.lower()) for entity in result.entities}
        self.assertIn(("url", "https://example.ua/example_user"), entities)
        self.assertIn(("domain", "example.ua"), entities)
        self.assertIn(("region", "ua"), entities)

        edges = {
            (edge.source_kind, edge.source_value.lower(), edge.relation, edge.target_kind, edge.target_value.lower())
            for edge in result.edges
        }
        self.assertIn(("username", "example_user", "produced_url", "url", "https://example.ua/example_user"), edges)
        self.assertIn(("username", "example_user", "region_hint", "region", "ua"), edges)

    def test_execute_maigret_adapter_reads_report_into_entities_and_edges(self):
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
            result = run_investigation(
                (ScanTarget(kind="username", value="bellingcat"),),
                include_adapters=True,
                execute_adapters=True,
                adapter_repositories=("soxoj/maigret",),
            )

        parsed = [finding for finding in result.adapter_findings if finding.module == "external-adapter-parser"]
        self.assertEqual(parsed[0].metadata["parser"], "maigret")
        self.assertEqual(parsed[0].metadata["site_name"], "GitHub")
        self.assertEqual(parsed[0].metadata["name"], "Bellingcat")

        entities = {(entity.kind, entity.value.lower()) for entity in result.entities}
        self.assertIn(("url", "https://github.com/bellingcat"), entities)
        self.assertIn(("domain", "github.com"), entities)
        self.assertIn(("name", "bellingcat"), entities)

        edges = {
            (edge.source_kind, edge.source_value.lower(), edge.relation, edge.target_kind, edge.target_value.lower())
            for edge in result.edges
        }
        self.assertIn(("username", "bellingcat", "produced_url", "url", "https://github.com/bellingcat"), edges)
        self.assertIn(("username", "bellingcat", "name_hint", "name", "bellingcat"), edges)

    def test_execute_h8mail_adapter_reads_report_into_entities_and_edges(self):
        def fake_run(args, **kwargs):
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
            result = run_investigation(
                (ScanTarget(kind="email", value="target@example.com"),),
                include_adapters=True,
                execute_adapters=True,
                adapter_repositories=("khast3x/h8mail",),
            )

        parsed = [finding for finding in result.adapter_findings if finding.module == "external-adapter-parser"]
        self.assertTrue(any(finding.metadata.get("parser") == "h8mail" for finding in parsed))
        self.assertFalse(any("secret-value" in finding.evidence for finding in parsed))

        entities = {(entity.kind, entity.value.lower()) for entity in result.entities}
        self.assertIn(("email", "admin@example.com"), entities)
        self.assertIn(("domain", "example.com"), entities)

        edges = {
            (edge.source_kind, edge.source_value.lower(), edge.relation, edge.target_kind, edge.target_value.lower())
            for edge in result.edges
        }
        self.assertIn(("email", "target@example.com", "related_email", "email", "admin@example.com"), edges)
        self.assertNotIn(("email", "target@example.com", "related_email", "email", "target@example.com"), edges)

    def test_execute_mosint_adapter_reads_report_into_entities_and_edges(self):
        def fake_run(args, **kwargs):
            output_file = Path(args[args.index("--output") + 1])
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(
                '{"email":"target@example.com","verified":true,'
                '"hunter":{"data":{"domain":"example.com","emails":[{"value":"admin@example.com"}]},"meta":{"results":1}},'
                '"breachdirectory":{"success":true,"found":1,"result":[{"has_password":true,"password":"secret-value","sources":["combo-db"]}]}}',
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="JSON report saved\n", stderr="")

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="mosint"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            side_effect=fake_run,
        ):
            result = run_investigation(
                (ScanTarget(kind="email", value="target@example.com"),),
                include_adapters=True,
                execute_adapters=True,
                adapter_repositories=("alpkeskin/mosint",),
            )

        parsed = [finding for finding in result.adapter_findings if finding.module == "external-adapter-parser"]
        self.assertTrue(any(finding.metadata.get("parser") == "mosint" for finding in parsed))
        self.assertFalse(any("secret-value" in finding.evidence for finding in parsed))

        entities = {(entity.kind, entity.value.lower()) for entity in result.entities}
        self.assertIn(("email", "admin@example.com"), entities)
        self.assertIn(("domain", "example.com"), entities)

        edges = {
            (edge.source_kind, edge.source_value.lower(), edge.relation, edge.target_kind, edge.target_value.lower())
            for edge in result.edges
        }
        self.assertIn(("email", "target@example.com", "related_email", "email", "admin@example.com"), edges)

    def test_execute_domain_recon_adapter_adds_subdomain_entities_and_edges(self):
        completed = subprocess.CompletedProcess(
            args=["subfinder", "-d", "example.com", "-oJ", "-silent"],
            returncode=0,
            stdout='{"host":"api.example.com","input":"example.com","source":"crtsh"}\n',
            stderr="",
        )

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="subfinder"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            return_value=completed,
        ):
            result = run_investigation(
                (ScanTarget(kind="domain", value="example.com"),),
                include_adapters=True,
                execute_adapters=True,
                adapter_repositories=("projectdiscovery/subfinder",),
            )

        parsed = [finding for finding in result.adapter_findings if finding.module == "external-adapter-parser"]
        self.assertEqual(parsed[0].metadata["parser"], "subfinder")
        self.assertEqual(parsed[0].metadata["subdomain"], "api.example.com")

        entities = {(entity.kind, entity.value.lower()) for entity in result.entities}
        self.assertIn(("subdomain", "api.example.com"), entities)

        edges = {
            (edge.source_kind, edge.source_value.lower(), edge.relation, edge.target_kind, edge.target_value.lower())
            for edge in result.edges
        }
        self.assertIn(("domain", "example.com", "discovered_subdomain", "subdomain", "api.example.com"), edges)

    def test_person_target_expands_to_username_scan_edges(self):
        result = run_investigation((ScanTarget(kind="person", value="Ivan Petrenko"),))

        entities = {(entity.kind, entity.value.lower()) for entity in result.entities}
        self.assertIn(("person", "ivan petrenko"), entities)
        self.assertIn(("normalized-name", "ivan petrenko"), entities)
        self.assertIn(("username", "ivanpetrenko"), entities)
        self.assertIn(("username", "vanyapetrenko"), entities)
        self.assertIn(("url", "https://github.com/ivanpetrenko"), entities)

        edges = {
            (edge.source_kind, edge.source_value.lower(), edge.relation, edge.target_kind, edge.target_value.lower())
            for edge in result.edges
        }
        self.assertIn(("person", "ivan petrenko", "generated_username_candidate", "username", "ivanpetrenko"), edges)
        self.assertIn(("person", "ivan petrenko", "generated_username_candidate", "username", "vanyapetrenko"), edges)
        self.assertIn(("username", "ivanpetrenko", "produced_url", "url", "https://github.com/ivanpetrenko"), edges)

    def test_person_target_uses_operator_aliases(self):
        result = run_investigation(
            (ScanTarget(kind="person", value="Volodymyr Zelenskyy"),),
            person_aliases=("ze-team",),
        )

        entities = {(entity.kind, entity.value.lower()) for entity in result.entities}
        self.assertIn(("username", "ze-team"), entities)

        edges = {
            (edge.source_kind, edge.source_value.lower(), edge.relation, edge.target_kind, edge.target_value.lower())
            for edge in result.edges
        }
        self.assertIn(("person", "volodymyr zelenskyy", "generated_username_candidate", "username", "ze-team"), edges)

    def test_person_target_adapter_allowlist_runs_only_on_derived_usernames(self):
        result = run_investigation(
            (ScanTarget(kind="person", value="Ivan Petrenko"),),
            include_adapters=True,
            adapter_limit=1,
            adapter_repositories=("snooppr/snoop",),
        )

        self.assertTrue(result.adapter_findings)
        self.assertTrue(all(finding.status == "planned" for finding in result.adapter_findings))
        self.assertNotIn("Ivan Petrenko", {finding.target for finding in result.adapter_findings})
        self.assertIn("ivanpetrenko", {finding.target for finding in result.adapter_findings})


if __name__ == "__main__":
    unittest.main()
