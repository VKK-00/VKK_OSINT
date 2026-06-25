import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osint_toolkit.engine import Finding, ScanTarget
from osint_toolkit.investigation import InvestigationResult, render_investigation_markdown, run_investigation


class InvestigationTests(unittest.TestCase):
    def test_native_kinds_can_disable_native_scans(self):
        result = run_investigation(
            (ScanTarget(kind="email", value="person@example.com"),),
            native_kinds=(),
        )

        self.assertEqual(result.findings, ())
        entities = {(entity.kind, entity.value.lower()) for entity in result.entities}
        self.assertIn(("email", "person@example.com"), entities)

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
        result = InvestigationResult(
            title="unsupported adapter",
            targets=(ScanTarget(kind="domain", value="example.com"),),
            findings=(),
            adapter_findings=(
                Finding(
                    module="external-adapter",
                    source="example/adapter",
                    target="example.com",
                    status="unsupported",
                    confidence="not_checked",
                    evidence="No executable command template is configured.",
                ),
            ),
            entities=(),
            edges=(),
            generated_at="2026-06-24T00:00:00+00:00",
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

    def test_execute_social_analyzer_adapter_adds_entities_and_edges(self):
        completed = subprocess.CompletedProcess(
            args=["node", "app.js", "--username", "example_user", "--output", "json"],
            returncode=0,
            stdout=(
                '{"detected":[{"link":"https://github.com/example_user","status":"good","rate":"%100.00",'
                '"country":"us"}]}'
            ),
            stderr="",
        )

        with patch.dict(os.environ, {"SOCIAL_ANALYZER_APP_JS": "C:\\tools\\social-analyzer\\app.js"}), patch(
            "osint_toolkit.adapter_runner.shutil.which",
            return_value="node",
        ), patch("osint_toolkit.adapter_runner.subprocess.run", return_value=completed):
            result = run_investigation(
                (ScanTarget(kind="username", value="example_user", region="ru"),),
                include_adapters=True,
                execute_adapters=True,
                adapter_repositories=("qeeqbox/social-analyzer",),
            )

        parsed = [finding for finding in result.adapter_findings if finding.module == "external-adapter-parser"]
        self.assertEqual(parsed[0].metadata["parser"], "social-analyzer")
        self.assertEqual(parsed[0].metadata["site_name"], "github.com")

        entities = {(entity.kind, entity.value.lower()) for entity in result.entities}
        self.assertIn(("url", "https://github.com/example_user"), entities)
        self.assertIn(("domain", "github.com"), entities)
        self.assertIn(("username", "example_user"), entities)
        self.assertIn(("country", "us"), entities)

        edges = {
            (edge.source_kind, edge.source_value.lower(), edge.relation, edge.target_kind, edge.target_value.lower())
            for edge in result.edges
        }
        self.assertIn(("username", "example_user", "produced_url", "url", "https://github.com/example_user"), edges)
        self.assertIn(("username", "example_user", "country_hint", "country", "us"), edges)

    def test_execute_blackbird_adapter_adds_entities_and_edges(self):
        with tempfile.TemporaryDirectory() as directory:
            blackbird_dir = Path(directory)
            results_dir = blackbird_dir / "results"

            def fake_run(args, **kwargs):
                self.assertEqual(Path(kwargs["cwd"]), blackbird_dir)
                fresh_dir = results_dir / "example_user_06_25_2026_blackbird"
                fresh_dir.mkdir(parents=True)
                (fresh_dir / "example_user_06_25_2026_blackbird.json").write_text(
                    """
                    [
                      {
                        "name": "GitHub",
                        "url": "https://github.com/example_user",
                        "category": "coding",
                        "status": "FOUND",
                        "metadata": [
                          {"name": "Name", "value": "Example User"},
                          {"name": "Location", "value": "Kyiv"}
                        ]
                      }
                    ]
                    """,
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="Saved results\n", stderr="")

            with patch.dict(os.environ, {"BLACKBIRD_DIR": str(blackbird_dir)}), patch(
                "osint_toolkit.adapter_runner.shutil.which",
                return_value="python",
            ), patch("osint_toolkit.adapter_runner.subprocess.run", side_effect=fake_run):
                result = run_investigation(
                    (ScanTarget(kind="username", value="example_user"),),
                    include_adapters=True,
                    execute_adapters=True,
                    adapter_repositories=("p1ngul1n0/blackbird",),
                )

        parsed = [finding for finding in result.adapter_findings if finding.module == "external-adapter-parser"]
        self.assertEqual(parsed[0].metadata["parser"], "blackbird")
        self.assertEqual(parsed[0].metadata["site_name"], "GitHub")

        entities = {(entity.kind, entity.value.lower()) for entity in result.entities}
        self.assertIn(("url", "https://github.com/example_user"), entities)
        self.assertIn(("domain", "github.com"), entities)
        self.assertIn(("username", "example_user"), entities)
        self.assertIn(("name", "example user"), entities)
        self.assertIn(("location", "kyiv"), entities)

        edges = {
            (edge.source_kind, edge.source_value.lower(), edge.relation, edge.target_kind, edge.target_value.lower())
            for edge in result.edges
        }
        self.assertIn(("username", "example_user", "produced_url", "url", "https://github.com/example_user"), edges)

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

        def fake_run(args, **kwargs):
            if tuple(args) == ("subfinder", "-h"):
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="subfinder\n  -d\n  -silent\n", stderr="")
            return completed

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="subfinder"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            side_effect=fake_run,
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

    def test_execute_theharvester_adapter_adds_entities_and_edges(self):
        def fake_run(args, **kwargs):
            if tuple(args) == ("theHarvester", "-h"):
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="theHarvester\n  -d\n  -b\n", stderr="")
            output_file = Path(args[args.index("-f") + 1])
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(
                '{"emails":["admin@example.com"],"hosts":["api.example.com"],"interesting_urls":["https://www.example.com/login"]}',
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="JSON File saved\n", stderr="")

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="theHarvester"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            side_effect=fake_run,
        ):
            result = run_investigation(
                (ScanTarget(kind="domain", value="example.com"),),
                include_adapters=True,
                execute_adapters=True,
                adapter_repositories=("laramies/theHarvester",),
            )

        parsed = [finding for finding in result.adapter_findings if finding.module == "external-adapter-parser"]
        self.assertTrue(any(finding.metadata.get("parser") == "theharvester" for finding in parsed))

        entities = {(entity.kind, entity.value.lower()) for entity in result.entities}
        self.assertIn(("email", "admin@example.com"), entities)
        self.assertIn(("subdomain", "api.example.com"), entities)
        self.assertIn(("url", "https://www.example.com/login"), entities)

        edges = {
            (edge.source_kind, edge.source_value.lower(), edge.relation, edge.target_kind, edge.target_value.lower())
            for edge in result.edges
        }
        self.assertIn(("domain", "example.com", "related_email", "email", "admin@example.com"), edges)
        self.assertIn(("domain", "example.com", "discovered_subdomain", "subdomain", "api.example.com"), edges)
        self.assertIn(("domain", "example.com", "produced_url", "url", "https://www.example.com/login"), edges)

    def test_execute_bbot_adapter_adds_entities_and_edges(self):
        def fake_run(args, **kwargs):
            if tuple(args) == ("bbot", "-h"):
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="bbot usage\n  -t TARGET\n  -p PRESET\n", stderr="")
            output_dir = Path(args[args.index("--output") + 1])
            scan_dir = output_dir / "osint-toolkit"
            scan_dir.mkdir(parents=True, exist_ok=True)
            (scan_dir / "output.json").write_text(
                '{"type":"DNS_NAME","data":"api.example.com","module":"certspotter","scope_description":"in-scope","resolved_hosts":["93.184.216.34"]}\n'
                '{"type":"EMAIL_ADDRESS","data":"admin@example.com","module":"emailformat","scope_description":"in-scope"}\n'
                '{"type":"URL","data":"https://www.example.com/login","module":"httpx","scope_description":"in-scope"}\n'
                '{"type":"OPEN_TCP_PORT","data":"api.example.com:443","host":"api.example.com","port":443,"module":"portscan"}\n'
                '{"type":"TECHNOLOGY","data":"nginx","module":"wappalyzer"}\n',
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="Scan complete\n", stderr="")

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="bbot"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            side_effect=fake_run,
        ):
            result = run_investigation(
                (ScanTarget(kind="domain", value="example.com"),),
                include_adapters=True,
                execute_adapters=True,
                adapter_repositories=("blacklanternsecurity/bbot",),
            )

        parsed = [finding for finding in result.adapter_findings if finding.module == "external-adapter-parser"]
        self.assertTrue(any(finding.metadata.get("parser") == "bbot" for finding in parsed))

        entities = {(entity.kind, entity.value.lower()) for entity in result.entities}
        self.assertIn(("email", "admin@example.com"), entities)
        self.assertIn(("subdomain", "api.example.com"), entities)
        self.assertIn(("url", "https://www.example.com/login"), entities)
        self.assertIn(("ip", "93.184.216.34"), entities)
        self.assertIn(("port", "443"), entities)
        self.assertIn(("technology", "nginx"), entities)

        edges = {
            (edge.source_kind, edge.source_value.lower(), edge.relation, edge.target_kind, edge.target_value.lower())
            for edge in result.edges
        }
        self.assertIn(("domain", "example.com", "related_email", "email", "admin@example.com"), edges)
        self.assertIn(("domain", "example.com", "discovered_subdomain", "subdomain", "api.example.com"), edges)
        self.assertIn(("domain", "example.com", "produced_url", "url", "https://www.example.com/login"), edges)
        self.assertIn(("domain", "example.com", "resolved_ip", "ip", "93.184.216.34"), edges)
        self.assertIn(("domain", "example.com", "open_port", "port", "443"), edges)
        self.assertIn(("domain", "example.com", "uses_technology", "technology", "nginx"), edges)

    def test_execute_spiderfoot_adapter_adds_entities_and_edges(self):
        completed = subprocess.CompletedProcess(
            args=["python", "sf.py", "-s", "example.com", "-u", "passive", "-o", "json", "-q"],
            returncode=0,
            stdout=(
                '[{"type":"INTERNET_NAME","data":"api.example.com","module":"sfp_dnsresolve","confidence":100},'
                '{"type":"EMAILADDR","data":"admin@example.com","module":"sfp_email","confidence":80},'
                '{"type":"WEBLINK","data":"https://www.example.com/login","module":"sfp_spider","confidence":80},'
                '{"type":"IP_ADDRESS","data":"93.184.216.34","module":"sfp_dnsresolve","confidence":80},'
                '{"type":"TCP_PORT_OPEN","data":"api.example.com:443","module":"sfp_portscan","confidence":80},'
                '{"type":"PHONE_NUMBER","data":"+380441234567","module":"sfp_phone","confidence":80}]'
            ),
            stderr="",
        )

        with patch.dict(os.environ, {"SPIDERFOOT_SF_PATH": "C:\\tools\\spiderfoot\\sf.py"}), patch(
            "osint_toolkit.adapter_runner.shutil.which",
            return_value="C:\\Python\\python.exe",
        ), patch("osint_toolkit.adapter_runner.subprocess.run", return_value=completed):
            result = run_investigation(
                (ScanTarget(kind="domain", value="example.com"),),
                include_adapters=True,
                execute_adapters=True,
                adapter_repositories=("smicallef/spiderfoot",),
            )

        parsed = [finding for finding in result.adapter_findings if finding.module == "external-adapter-parser"]
        self.assertTrue(any(finding.metadata.get("parser") == "spiderfoot" for finding in parsed))

        entities = {(entity.kind, entity.value.lower()) for entity in result.entities}
        self.assertIn(("email", "admin@example.com"), entities)
        self.assertIn(("subdomain", "api.example.com"), entities)
        self.assertIn(("url", "https://www.example.com/login"), entities)
        self.assertIn(("ip", "93.184.216.34"), entities)
        self.assertIn(("port", "443"), entities)
        self.assertIn(("phone", "+380441234567"), entities)

        edges = {
            (edge.source_kind, edge.source_value.lower(), edge.relation, edge.target_kind, edge.target_value.lower())
            for edge in result.edges
        }
        self.assertIn(("domain", "example.com", "related_email", "email", "admin@example.com"), edges)
        self.assertIn(("domain", "example.com", "related_phone", "phone", "+380441234567"), edges)
        self.assertIn(("domain", "example.com", "discovered_subdomain", "subdomain", "api.example.com"), edges)
        self.assertIn(("domain", "example.com", "produced_url", "url", "https://www.example.com/login"), edges)
        self.assertIn(("domain", "example.com", "resolved_ip", "ip", "93.184.216.34"), edges)
        self.assertIn(("domain", "example.com", "open_port", "port", "443"), edges)

    def test_execute_argus_adapter_adds_entities_and_edges(self):
        def fake_run(args, **kwargs):
            self.assertEqual(args, ["argus"])
            self.assertEqual(kwargs["input"], "set target example.com\nrunall infra\nviewout\nexit\n")
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout=(
                    "Associated Hosts: api.example.com\n"
                    "Email Harvesting: admin@example.com\n"
                    "Archive History: https://www.example.com/login\n"
                    "IP Info: 93.184.216.34\n"
                    "Open Ports Scan: 443/tcp open\n"
                    "Technology Stack: nginx\n"
                    "Contact: +380441234567\n"
                ),
                stderr="",
            )

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="argus"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            side_effect=fake_run,
        ):
            result = run_investigation(
                (ScanTarget(kind="domain", value="example.com"),),
                include_adapters=True,
                execute_adapters=True,
                adapter_repositories=("jasonxtn/argus",),
            )

        parsed = [finding for finding in result.adapter_findings if finding.module == "external-adapter-parser"]
        self.assertTrue(any(finding.metadata.get("parser") == "argus" for finding in parsed))

        entities = {(entity.kind, entity.value.lower()) for entity in result.entities}
        self.assertIn(("email", "admin@example.com"), entities)
        self.assertIn(("subdomain", "api.example.com"), entities)
        self.assertIn(("url", "https://www.example.com/login"), entities)
        self.assertIn(("ip", "93.184.216.34"), entities)
        self.assertIn(("port", "443"), entities)
        self.assertIn(("technology", "nginx"), entities)
        self.assertIn(("phone", "+380441234567"), entities)

        edges = {
            (edge.source_kind, edge.source_value.lower(), edge.relation, edge.target_kind, edge.target_value.lower())
            for edge in result.edges
        }
        self.assertIn(("domain", "example.com", "related_email", "email", "admin@example.com"), edges)
        self.assertIn(("domain", "example.com", "related_phone", "phone", "+380441234567"), edges)
        self.assertIn(("domain", "example.com", "discovered_subdomain", "subdomain", "api.example.com"), edges)
        self.assertIn(("domain", "example.com", "produced_url", "url", "https://www.example.com/login"), edges)
        self.assertIn(("domain", "example.com", "resolved_ip", "ip", "93.184.216.34"), edges)
        self.assertIn(("domain", "example.com", "open_port", "port", "443"), edges)
        self.assertIn(("domain", "example.com", "uses_technology", "technology", "nginx"), edges)

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
