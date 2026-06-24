import unittest
from unittest.mock import patch

from osint_toolkit.adapter_setup import build_adapter_setup
from osint_toolkit.adapters import find_adapter
from osint_toolkit.doctor import inspect_adapters
from osint_toolkit.engine import ScanTarget


class AdapterSetupTests(unittest.TestCase):
    def test_sherlock_setup_has_install_command_and_docs(self):
        adapter = find_adapter("sherlock-project/sherlock")

        with patch("osint_toolkit.adapter_setup.shutil.which", return_value=""):
            setup = build_adapter_setup(adapter)

        self.assertEqual(setup.repository, "sherlock-project/sherlock")
        self.assertEqual(setup.readiness, "missing")
        self.assertEqual(setup.install_kind, "pipx")
        self.assertEqual(setup.install_command, "pipx install sherlock-project")
        self.assertIn("sherlockproject.xyz", setup.docs_url)

    def test_setup_reports_ready_when_executable_exists(self):
        adapter = find_adapter("soxoj/maigret")

        with patch("osint_toolkit.adapter_setup.shutil.which", return_value="C:\\tools\\maigret.exe"):
            setup = build_adapter_setup(adapter)

        self.assertEqual(setup.readiness, "ready")
        self.assertEqual(setup.executable_path, "C:\\tools\\maigret.exe")

    def test_h8mail_setup_has_executable_command(self):
        adapter = find_adapter("khast3x/h8mail")

        with patch("osint_toolkit.adapter_setup.shutil.which", return_value=""):
            setup = build_adapter_setup(adapter)

        self.assertEqual(setup.readiness, "missing")
        self.assertEqual(setup.install_command, "python -m pip install h8mail")
        self.assertEqual(
            adapter.render_command(ScanTarget(kind="email", value="person@example.com")),
            ("h8mail", "-t", "person@example.com"),
        )

    def test_user_scanner_setup_uses_target_specific_command_templates(self):
        adapter = find_adapter("kaifcodec/user-scanner")

        with patch("osint_toolkit.adapter_setup.shutil.which", return_value=""):
            setup = build_adapter_setup(adapter)

        self.assertEqual(setup.readiness, "missing")
        self.assertEqual(setup.executable, "user-scanner")
        self.assertEqual(setup.install_command, "python -m pip install user-scanner")
        self.assertEqual(
            adapter.render_command(ScanTarget(kind="email", value="person@example.com")),
            ("user-scanner", "-e", "person@example.com"),
        )
        self.assertEqual(
            adapter.render_command(ScanTarget(kind="username", value="example_user")),
            ("user-scanner", "-u", "example_user"),
        )

    def test_setup_reports_not_configured_for_dataset_adapter(self):
        setup = build_adapter_setup(find_adapter("WebBreacher/WhatsMyName"))

        self.assertEqual(setup.readiness, "not_configured")
        self.assertEqual(setup.install_kind, "dataset")

    def test_doctor_missing_finding_includes_install_hint(self):
        with patch("osint_toolkit.adapter_setup.shutil.which", return_value=""):
            findings = inspect_adapters("partial_native")

        sherlock = next(finding for finding in findings if finding.source == "sherlock-project/sherlock")
        self.assertEqual(sherlock.status, "missing")
        self.assertIn("pipx install sherlock-project", sherlock.evidence)
        self.assertEqual(sherlock.metadata["install_kind"], "pipx")


if __name__ == "__main__":
    unittest.main()
