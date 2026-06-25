import subprocess
import unittest
from unittest.mock import patch

from osint_toolkit.tools import (
    ToolReadiness,
    build_tool_install_results,
    format_tool_install_results,
)


class ToolInstallTests(unittest.TestCase):
    def test_install_results_are_dry_run_by_default(self):
        rows = (
            ToolReadiness(
                kind="adapter",
                name="example/pipx",
                readiness="missing",
                install_command="pipx install example",
            ),
            ToolReadiness(
                kind="adapter",
                name="example/config",
                readiness="config_missing",
                required_env=("EXAMPLE_DIR",),
                missing_env=("EXAMPLE_DIR",),
            ),
            ToolReadiness(
                kind="adapter",
                name="example/runtime",
                readiness="runtime_error",
                readiness_note="fcntl is unavailable",
            ),
            ToolReadiness(
                kind="adapter",
                name="example/excluded",
                readiness="excluded",
                install_command="pipx install excluded",
            ),
        )

        results = build_tool_install_results(rows)
        by_name = {result.name: result for result in results}

        self.assertEqual(set(by_name), {"example/pipx", "example/config", "example/runtime"})
        self.assertEqual(by_name["example/pipx"].status, "planned")
        self.assertEqual(by_name["example/pipx"].action, "install")
        self.assertEqual(by_name["example/config"].status, "manual")
        self.assertEqual(by_name["example/config"].action, "configure-env")
        self.assertEqual(by_name["example/runtime"].status, "skipped")

    def test_install_execute_runs_only_allowlisted_missing_commands(self):
        rows = (
            ToolReadiness(
                kind="adapter",
                name="example/pipx",
                readiness="missing",
                install_command="pipx install example",
            ),
            ToolReadiness(
                kind="adapter",
                name="example/manual",
                readiness="missing",
                install_command="curl https://example.test/install.ps1",
            ),
        )
        completed = subprocess.CompletedProcess(args=("pipx", "install", "example"), returncode=0, stdout="ok", stderr="")

        with patch("osint_toolkit.tools.subprocess.run", return_value=completed) as run:
            results = build_tool_install_results(rows, execute=True, timeout=10)

        by_name = {result.name: result for result in results}
        self.assertEqual(by_name["example/pipx"].status, "installed")
        self.assertEqual(by_name["example/manual"].status, "manual")
        run.assert_called_once_with(
            ("pipx", "install", "example"),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_install_formatter_outputs_json(self):
        results = build_tool_install_results(
            (
                ToolReadiness(
                    kind="local-tool",
                    name="exiftool",
                    readiness="missing",
                    install_command="winget install OliverBetz.ExifTool",
                ),
            )
        )

        payload = format_tool_install_results(results, output_format="json")

        self.assertIn('"name": "exiftool"', payload)
        self.assertIn('"status": "planned"', payload)


if __name__ == "__main__":
    unittest.main()
