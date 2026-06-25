import unittest

from osint_toolkit.engine import Finding
from osint_toolkit.output import finding_source_summary, format_finding_source_summary


class OutputTests(unittest.TestCase):
    def test_source_summary_includes_deduped_adapter_execution_provenance(self):
        findings = (
            Finding(
                module="external-adapter",
                source="sherlock-project/sherlock",
                target="example_user",
                status="completed",
                confidence="unknown",
                metadata={
                    "command": "sherlock example_user",
                    "execution_route": "native",
                    "returncode": "0",
                    "started_at": "2026-06-26T01:00:00+03:00",
                    "duration_ms": "42",
                    "generated_output_files": "2",
                    "parser_version": "adapter-parsers-v1",
                },
            ),
            Finding(
                module="external-adapter-parser",
                source="sherlock-project/sherlock",
                target="example_user",
                status="candidate",
                confidence="high",
                url="https://github.com/example_user",
                metadata={
                    "parser": "sherlock",
                    "adapter_repository": "sherlock-project/sherlock",
                    "adapter_command": "sherlock example_user",
                    "adapter_execution_route": "native",
                    "adapter_returncode": "0",
                    "adapter_started_at": "2026-06-26T01:00:00+03:00",
                    "adapter_duration_ms": "42",
                    "adapter_generated_output_files": "2",
                    "parser_version": "adapter-parsers-v1",
                },
            ),
        )

        row = finding_source_summary(findings)[0]
        self.assertEqual(row["execution_count"], 1)
        self.assertEqual(row["execution_routes"], ("native",))
        self.assertEqual(row["returncodes"], {"0": 1})
        self.assertEqual(row["duration_ms_total"], 42)
        self.assertEqual(row["generated_output_files"], 2)
        self.assertEqual(row["parser_versions"], ("adapter-parsers-v1",))

        markdown = format_finding_source_summary(findings, output_format="markdown")
        self.assertIn("| Source | Findings | Statuses | Confidence | Signals | Runs | Routes | Exit |", markdown)
        self.assertIn("| sherlock-project/sherlock | 2 |", markdown)
        self.assertIn("| 1 | native | 0:1 | 42 | adapter-parsers-v1 |", markdown)


if __name__ == "__main__":
    unittest.main()
