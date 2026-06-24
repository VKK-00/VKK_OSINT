import subprocess
import unittest
from unittest.mock import patch

from osint_toolkit.engine import ScanTarget
from osint_toolkit.investigation import render_investigation_markdown, run_investigation


class InvestigationTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
