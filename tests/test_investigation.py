import subprocess
import unittest
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

    def test_person_target_expands_to_username_scan_edges(self):
        result = run_investigation((ScanTarget(kind="person", value="Ivan Petrenko"),))

        entities = {(entity.kind, entity.value.lower()) for entity in result.entities}
        self.assertIn(("person", "ivan petrenko"), entities)
        self.assertIn(("normalized-name", "ivan petrenko"), entities)
        self.assertIn(("username", "ivanpetrenko"), entities)
        self.assertIn(("url", "https://github.com/ivanpetrenko"), entities)

        edges = {
            (edge.source_kind, edge.source_value.lower(), edge.relation, edge.target_kind, edge.target_value.lower())
            for edge in result.edges
        }
        self.assertIn(("person", "ivan petrenko", "generated_username_candidate", "username", "ivanpetrenko"), edges)
        self.assertIn(("username", "ivanpetrenko", "produced_url", "url", "https://github.com/ivanpetrenko"), edges)

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
