import os
import subprocess
import unittest
from unittest.mock import patch

from osint_toolkit.adapter_runner import run_adapter_findings
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
        self.assertEqual(
            adapter.render_output_dir_args("C:\\tmp\\sherlock"),
            ("--no-color", "--print-all", "--csv", "--txt", "--folderoutput", "C:\\tmp\\sherlock"),
        )
        self.assertEqual(adapter.generated_output_patterns, ("*.csv", "*.txt"))

    def test_setup_reports_ready_when_executable_exists(self):
        adapter = find_adapter("soxoj/maigret")

        with patch("osint_toolkit.adapter_setup.shutil.which", return_value="C:\\tools\\maigret.exe"):
            setup = build_adapter_setup(adapter)

        self.assertEqual(setup.readiness, "ready")
        self.assertEqual(setup.executable_path, "C:\\tools\\maigret.exe")
        self.assertEqual(adapter.render_command(ScanTarget(kind="username", value="example_user")), ("maigret", "example_user", "--json", "ndjson"))
        self.assertEqual(
            adapter.render_command(ScanTarget(kind="username", value="example_user", region="ua")),
            ("maigret", "example_user", "--json", "ndjson", "--tags", "ua"),
        )
        self.assertEqual(adapter.render_output_dir_args("C:\\tmp\\maigret"), ("--folderoutput", "C:\\tmp\\maigret"))
        self.assertEqual(adapter.generated_output_patterns, ("*.json",))

    def test_h8mail_setup_has_executable_command(self):
        adapter = find_adapter("khast3x/h8mail")

        with patch("osint_toolkit.adapter_setup.shutil.which", return_value=""):
            setup = build_adapter_setup(adapter)

        self.assertEqual(setup.readiness, "missing")
        self.assertEqual(setup.install_kind, "pipx")
        self.assertEqual(setup.install_command, "pipx install h8mail")
        self.assertEqual(
            adapter.render_command(ScanTarget(kind="email", value="person@example.com")),
            ("h8mail", "-t", "person@example.com", "--hide"),
        )
        self.assertEqual(adapter.render_output_file_args("C:\\tmp\\h8mail.json"), ("-j", "C:\\tmp\\h8mail.json"))
        self.assertEqual(adapter.generated_output_patterns, ("*.json",))

    def test_pwnedornot_setup_uses_safe_email_flags(self):
        adapter = find_adapter("thewhiteh4t/pwnedOrNot")

        with patch("osint_toolkit.adapter_setup.shutil.which", return_value=""):
            setup = build_adapter_setup(adapter)

        self.assertEqual(setup.readiness, "missing")
        self.assertEqual(setup.install_kind, "manual")
        self.assertEqual(
            adapter.render_command(ScanTarget(kind="email", value="person@example.com")),
            ("pwnedornot", "-e", "person@example.com", "-n"),
        )
        self.assertIn("PWNED_API_KEY", adapter.optional_env)

    def test_mosint_setup_uses_json_output_command(self):
        adapter = find_adapter("alpkeskin/mosint")

        with patch("osint_toolkit.adapter_setup.shutil.which", return_value=""):
            setup = build_adapter_setup(adapter)

        self.assertEqual(setup.readiness, "missing")
        self.assertEqual(setup.install_command, "go install github.com/alpkeskin/mosint/v3/cmd/mosint@latest")
        self.assertEqual(
            adapter.render_command(ScanTarget(kind="email", value="person@example.com")),
            ("mosint", "--silent", "person@example.com"),
        )
        self.assertEqual(adapter.render_output_file_args("C:\\tmp\\mosint.json"), ("--output", "C:\\tmp\\mosint.json"))
        self.assertEqual(adapter.generated_output_patterns, ("*.json",))

    def test_user_scanner_setup_uses_target_specific_command_templates(self):
        adapter = find_adapter("kaifcodec/user-scanner")

        with patch("osint_toolkit.adapter_setup.shutil.which", return_value=""):
            setup = build_adapter_setup(adapter)

        self.assertEqual(setup.readiness, "missing")
        self.assertEqual(setup.executable, "user-scanner")
        self.assertEqual(setup.install_kind, "pipx")
        self.assertEqual(setup.install_command, "pipx install user-scanner")
        self.assertEqual(
            adapter.render_command(ScanTarget(kind="email", value="person@example.com")),
            ("user-scanner", "-e", "person@example.com", "-f", "json"),
        )
        self.assertEqual(
            adapter.render_command(ScanTarget(kind="username", value="example_user")),
            ("user-scanner", "-u", "example_user", "-f", "json"),
        )

    def test_socialscan_setup_uses_generated_json_output(self):
        adapter = find_adapter("iojw/socialscan")

        with patch("osint_toolkit.adapter_setup.shutil.which", return_value=""):
            setup = build_adapter_setup(adapter)

        self.assertEqual(setup.readiness, "missing")
        self.assertEqual(setup.install_kind, "pipx")
        self.assertEqual(setup.install_command, "pipx install socialscan")
        self.assertEqual(
            adapter.render_command(ScanTarget(kind="username", value="example_user")),
            ("socialscan", "example_user"),
        )
        self.assertEqual(
            adapter.render_command(ScanTarget(kind="email", value="person@example.com")),
            ("socialscan", "person@example.com"),
        )
        self.assertEqual(adapter.render_output_file_args("C:\\tmp\\socialscan.json"), ("--json", "C:\\tmp\\socialscan.json"))
        self.assertEqual(adapter.generated_output_patterns, ("*.json",))

    def test_social_analyzer_setup_uses_upstream_app_path_and_region_filter(self):
        adapter = find_adapter("qeeqbox/social-analyzer")

        with patch.dict(os.environ, {}, clear=True), patch("osint_toolkit.adapter_setup.shutil.which", return_value="C:\\node\\node.exe"):
            setup = build_adapter_setup(adapter)

        self.assertEqual(setup.readiness, "config_missing")
        self.assertEqual(setup.missing_env, ("SOCIAL_ANALYZER_APP_JS",))
        self.assertEqual(setup.install_kind, "manual")
        self.assertIn("social-analyzer", setup.docs_url)

        with patch.dict(os.environ, {"SOCIAL_ANALYZER_APP_JS": "C:\\tools\\social-analyzer\\app.js"}):
            self.assertEqual(
                adapter.render_command(ScanTarget(kind="username", value="example_user", region="ua")),
                (
                    "node",
                    "C:\\tools\\social-analyzer\\app.js",
                    "--username",
                    "example_user",
                    "--output",
                    "json",
                    "--mode",
                    "fast",
                    "--method",
                    "all",
                    "--filter",
                    "good,maybe",
                    "--profiles",
                    "detected",
                    "--countries",
                    "ua",
                ),
            )

    def test_blackbird_setup_uses_checkout_workdir_and_target_specific_commands(self):
        adapter = find_adapter("p1ngul1n0/blackbird")

        with patch.dict(os.environ, {}, clear=True), patch("osint_toolkit.adapter_setup.shutil.which", return_value="C:\\Python\\python.exe"):
            setup = build_adapter_setup(adapter)

        self.assertEqual(setup.readiness, "config_missing")
        self.assertEqual(setup.missing_env, ("BLACKBIRD_DIR",))
        self.assertEqual(setup.install_kind, "manual")
        self.assertIn("blackbird", setup.docs_url)
        self.assertEqual(adapter.working_dir_env, "BLACKBIRD_DIR")
        self.assertEqual(adapter.generated_output_base_env, "BLACKBIRD_DIR")
        self.assertEqual(adapter.generated_output_subdir, "results")
        self.assertEqual(adapter.generated_output_patterns, ("*.json",))
        self.assertEqual(
            adapter.render_command(ScanTarget(kind="username", value="example_user")),
            ("python", "blackbird.py", "--username", "example_user", "--json", "--no-update", "--timeout", "30"),
        )
        self.assertEqual(
            adapter.render_command(ScanTarget(kind="email", value="person@example.com")),
            ("python", "blackbird.py", "--email", "person@example.com", "--json", "--no-update", "--timeout", "30"),
        )
        with patch.dict(os.environ, {"BLACKBIRD_PYTHON": "C:\\tools\\blackbird\\.venv\\Scripts\\python.exe"}):
            self.assertEqual(adapter.executable_names(), ("C:\\tools\\blackbird\\.venv\\Scripts\\python.exe",))
            self.assertEqual(
                adapter.render_command(ScanTarget(kind="username", value="example_user")),
                (
                    "C:\\tools\\blackbird\\.venv\\Scripts\\python.exe",
                    "blackbird.py",
                    "--username",
                    "example_user",
                    "--json",
                    "--no-update",
                    "--timeout",
                    "30",
                ),
            )

    def test_nexfil_setup_uses_isolated_workdir_reports(self):
        adapter = find_adapter("thewhiteh4t/nexfil")

        with patch("osint_toolkit.adapter_setup.shutil.which", return_value=""):
            setup = build_adapter_setup(adapter)

        self.assertEqual(setup.readiness, "missing")
        self.assertEqual(setup.install_kind, "pipx")
        self.assertEqual(setup.install_command, "pipx install nexfil")
        self.assertEqual(
            adapter.render_command(ScanTarget(kind="username", value="example_user")),
            ("nexfil", "-u", "example_user"),
        )
        self.assertEqual(adapter.generated_output_patterns, ("*.txt",))
        self.assertTrue(adapter.generated_output_workdir)

    def test_snoop_setup_uses_region_aware_command_template(self):
        adapter = find_adapter("snooppr/snoop")

        with patch("osint_toolkit.adapter_setup.shutil.which", return_value=""):
            setup = build_adapter_setup(adapter)

        self.assertEqual(setup.readiness, "missing")
        self.assertEqual(setup.executable, "snoop")
        self.assertEqual(
            adapter.render_command(ScanTarget(kind="username", value="example_user")),
            ("snoop", "--no-func", "--found-print", "example_user"),
        )
        self.assertEqual(
            adapter.render_command(ScanTarget(kind="username", value="example_user", region="ru")),
            ("snoop", "--no-func", "--found-print", "--include", "RU", "example_user"),
        )

    def test_domain_recon_adapters_render_upstream_commands(self):
        subfinder = find_adapter("projectdiscovery/subfinder")
        httpx = find_adapter("projectdiscovery/httpx")
        amass = find_adapter("owasp-amass/amass")
        theharvester = find_adapter("laramies/theHarvester")
        bbot = find_adapter("blacklanternsecurity/bbot")
        spiderfoot = find_adapter("smicallef/spiderfoot")
        argus = find_adapter("jasonxtn/argus")

        self.assertEqual(
            subfinder.render_command(ScanTarget(kind="domain", value="example.com")),
            ("subfinder", "-d", "example.com", "-oJ", "-silent"),
        )
        self.assertEqual(
            httpx.render_command(ScanTarget(kind="domain", value="example.com"))[:6],
            ("httpx", "-u", "example.com", "-json", "-silent", "-status-code"),
        )
        self.assertIn("-tech-detect", httpx.render_command(ScanTarget(kind="url", value="https://example.com")))
        self.assertEqual(
            amass.render_command(ScanTarget(kind="domain", value="example.com")),
            ("amass", "enum", "-passive", "-nocolor", "-d", "example.com"),
        )
        self.assertEqual(
            theharvester.render_command(ScanTarget(kind="domain", value="example.com")),
            ("theHarvester", "-d", "example.com", "-b", "all"),
        )
        self.assertEqual(theharvester.render_output_file_args("C:\\tmp\\harvester.json"), ("-f", "C:\\tmp\\harvester.json"))
        self.assertEqual(theharvester.generated_output_patterns, ("*.json",))
        self.assertEqual(
            bbot.render_command(ScanTarget(kind="domain", value="example.com")),
            ("bbot", "-t", "example.com", "-p", "subdomain-enum", "-rf", "passive"),
        )
        self.assertEqual(
            bbot.render_command(ScanTarget(kind="username", value="@example_user")),
            ("bbot", "-t", "USER:example_user", "-p", "subdomain-enum", "-rf", "passive"),
        )
        self.assertEqual(bbot.render_output_dir_args("C:\\tmp\\bbot"), ("--output", "C:\\tmp\\bbot", "--name", "osint-toolkit"))
        self.assertEqual(bbot.generated_output_patterns, ("*.json",))

        with patch.dict(os.environ, {"SPIDERFOOT_SF_PATH": "C:\\tools\\spiderfoot\\sf.py"}):
            self.assertEqual(
                spiderfoot.render_command(ScanTarget(kind="domain", value="example.com")),
                ("python", "C:\\tools\\spiderfoot\\sf.py", "-s", "example.com", "-u", "passive", "-o", "json", "-q"),
            )
            self.assertEqual(
                spiderfoot.render_command(ScanTarget(kind="email", value="person@example.com")),
                ("python", "C:\\tools\\spiderfoot\\sf.py", "-s", "person@example.com", "-u", "passive", "-o", "json", "-q"),
            )
            self.assertEqual(
                spiderfoot.render_command(ScanTarget(kind="phone", value="+380441234567")),
                ("python", "C:\\tools\\spiderfoot\\sf.py", "-s", "+380441234567", "-u", "passive", "-o", "json", "-q"),
            )
            self.assertEqual(
                spiderfoot.render_command(ScanTarget(kind="username", value="example_user")),
                ("python", "C:\\tools\\spiderfoot\\sf.py", "-s", "example_user", "-u", "passive", "-o", "json", "-q"),
            )
        with patch.dict(
            os.environ,
            {
                "SPIDERFOOT_SF_PATH": "C:\\tools\\spiderfoot\\sf.py",
                "SPIDERFOOT_PYTHON": "C:\\tools\\spiderfoot\\.venv\\Scripts\\python.exe",
            },
        ):
            self.assertEqual(spiderfoot.executable_names(), ("C:\\tools\\spiderfoot\\.venv\\Scripts\\python.exe",))
            self.assertEqual(
                spiderfoot.render_command(ScanTarget(kind="domain", value="example.com")),
                (
                    "C:\\tools\\spiderfoot\\.venv\\Scripts\\python.exe",
                    "C:\\tools\\spiderfoot\\sf.py",
                    "-s",
                    "example.com",
                    "-u",
                    "passive",
                    "-o",
                    "json",
                    "-q",
                ),
            )

        self.assertEqual(argus.render_command(ScanTarget(kind="domain", value="example.com")), ("argus",))
        self.assertEqual(
            argus.render_command_input(ScanTarget(kind="domain", value="example.com")),
            "set target example.com\nrunall infra\nviewout\nexit\n",
        )

        with patch("osint_toolkit.adapter_setup.shutil.which", return_value=""):
            setup = build_adapter_setup(subfinder)

        self.assertEqual(setup.install_kind, "go")
        self.assertIn("projectdiscovery/subfinder", setup.install_command)

        with patch("osint_toolkit.adapter_setup.shutil.which", return_value=""):
            harvester_setup = build_adapter_setup(theharvester)

        self.assertEqual(harvester_setup.readiness, "missing")
        self.assertEqual(harvester_setup.install_kind, "manual")
        self.assertIn("Python 3.12+", harvester_setup.install_note)

        with patch("osint_toolkit.adapter_setup.shutil.which", return_value=""):
            bbot_setup = build_adapter_setup(bbot)

        self.assertEqual(bbot_setup.readiness, "missing")
        self.assertEqual(bbot_setup.install_kind, "pipx")
        self.assertEqual(bbot_setup.install_command, "pipx install bbot")

        with patch.dict(os.environ, {}, clear=True), patch("osint_toolkit.adapter_setup.shutil.which", return_value="C:\\Python\\python.exe"):
            spiderfoot_missing_config = build_adapter_setup(spiderfoot)

        self.assertEqual(spiderfoot_missing_config.readiness, "config_missing")
        self.assertEqual(spiderfoot_missing_config.missing_env, ("SPIDERFOOT_SF_PATH",))

        with patch.dict(os.environ, {"SPIDERFOOT_SF_PATH": "C:\\tools\\spiderfoot\\sf.py"}), patch(
            "osint_toolkit.adapter_setup.shutil.which",
            return_value="C:\\Python\\python.exe",
        ):
            spiderfoot_ready = build_adapter_setup(spiderfoot)

        self.assertEqual(spiderfoot_ready.readiness, "ready")
        self.assertEqual(spiderfoot_ready.install_kind, "manual")

        with patch("osint_toolkit.adapter_setup.shutil.which", return_value=""):
            argus_setup = build_adapter_setup(argus)

        self.assertEqual(argus_setup.readiness, "missing")
        self.assertEqual(argus_setup.install_kind, "pipx")
        self.assertEqual(argus_setup.install_command, "pipx install argus-recon")

    def test_url_archive_adapters_render_upstream_commands(self):
        yark = find_adapter("Owez/yark")
        target = ScanTarget(kind="url", value="https://www.youtube.com/channel/ExampleChannel")

        self.assertEqual(
            yark.render_command(target),
            ("yark", "new", "youtube.com-channel-examplechannel", "https://www.youtube.com/channel/ExampleChannel"),
        )
        self.assertEqual(yark.generated_output_patterns, ("*/yark.json",))
        self.assertTrue(yark.generated_output_workdir)

    def test_httpx_setup_rejects_wrong_executable_on_path(self):
        adapter = find_adapter("projectdiscovery/httpx")
        wrong_help = subprocess.CompletedProcess(
            args=("httpx", "-h"),
            returncode=0,
            stdout="Usage: httpx [OPTIONS] URL\n",
            stderr="",
        )

        with patch("osint_toolkit.adapter_setup.shutil.which", return_value="C:\\Python\\Scripts\\httpx.exe"), patch(
            "osint_toolkit.adapter_probe.subprocess.run",
            return_value=wrong_help,
        ):
            setup = build_adapter_setup(adapter)

        self.assertEqual(setup.readiness, "wrong_executable")
        self.assertIn("projectdiscovery/httpx", setup.readiness_note)
        self.assertIn("-tech-detect", setup.readiness_note)

    def test_httpx_setup_accepts_projectdiscovery_help_flags(self):
        adapter = find_adapter("projectdiscovery/httpx")
        projectdiscovery_help = subprocess.CompletedProcess(
            args=("httpx", "-h"),
            returncode=0,
            stdout="Usage: httpx\n  -status-code\n  -tech-detect\n",
            stderr="",
        )

        with patch("osint_toolkit.adapter_setup.shutil.which", return_value="C:\\tools\\httpx.exe"), patch(
            "osint_toolkit.adapter_probe.subprocess.run",
            return_value=projectdiscovery_help,
        ):
            setup = build_adapter_setup(adapter)

        self.assertEqual(setup.readiness, "ready")

    def test_httpx_execute_rejects_wrong_executable_before_running_target_command(self):
        wrong_help = subprocess.CompletedProcess(
            args=("httpx", "-h"),
            returncode=0,
            stdout="Usage: httpx [OPTIONS] URL\n",
            stderr="",
        )

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="C:\\Python\\Scripts\\httpx.exe"), patch(
            "osint_toolkit.adapter_probe.subprocess.run",
            return_value=wrong_help,
        ):
            findings = run_adapter_findings(
                "projectdiscovery/httpx",
                ScanTarget(kind="domain", value="example.com"),
                execute=True,
            )

        self.assertEqual(findings[0].status, "wrong_executable")
        self.assertIn("projectdiscovery/httpx", findings[0].evidence)

    def test_declarative_probe_rejects_wrong_subfinder_executable(self):
        adapter = find_adapter("projectdiscovery/subfinder")
        wrong_help = subprocess.CompletedProcess(
            args=("subfinder", "-h"),
            returncode=0,
            stdout="Usage: subfinder [OPTIONS]\n",
            stderr="",
        )

        with patch("osint_toolkit.adapter_setup.shutil.which", return_value="C:\\tools\\subfinder.exe"), patch(
            "osint_toolkit.adapter_probe.subprocess.run",
            return_value=wrong_help,
        ):
            setup = build_adapter_setup(adapter)

        self.assertEqual(setup.readiness, "wrong_executable")
        self.assertIn("projectdiscovery/subfinder", setup.readiness_note)
        self.assertIn("-d", setup.readiness_note)

    def test_declarative_probe_accepts_subfinder_help_markers(self):
        adapter = find_adapter("projectdiscovery/subfinder")
        subfinder_help = subprocess.CompletedProcess(
            args=("subfinder", "-h"),
            returncode=0,
            stdout="subfinder usage\n  -d string\n  -silent\n",
            stderr="",
        )

        with patch("osint_toolkit.adapter_setup.shutil.which", return_value="C:\\tools\\subfinder.exe"), patch(
            "osint_toolkit.adapter_probe.subprocess.run",
            return_value=subfinder_help,
        ):
            setup = build_adapter_setup(adapter)

        self.assertEqual(setup.readiness, "ready")

    def test_declarative_probe_uses_adapter_timeout(self):
        adapter = find_adapter("blacklanternsecurity/bbot")
        bbot_help = subprocess.CompletedProcess(
            args=("bbot", "-h"),
            returncode=0,
            stdout="usage: bbot\n  -t TARGET\n  -p PRESET\n",
            stderr="",
        )

        with patch("osint_toolkit.adapter_setup.shutil.which", return_value="C:\\tools\\bbot.exe"), patch(
            "osint_toolkit.adapter_probe.subprocess.run",
            return_value=bbot_help,
        ) as run_probe:
            setup = build_adapter_setup(adapter)

        self.assertEqual(setup.readiness, "ready")
        self.assertEqual(run_probe.call_args.kwargs["timeout"], 15.0)

    def test_detectdee_setup_uses_target_specific_commands_and_data_file(self):
        adapter = find_adapter("Yvesssn/DetectDee")
        help_output = subprocess.CompletedProcess(
            args=("DetectDee", "detect", "-h"),
            returncode=0,
            stdout="DetectDee detect [flags]\n  -n, --name strings\n  -e, --email strings\n  -p, --phone strings\n  -o, --output string\n",
            stderr="",
        )

        with patch.dict(os.environ, {}, clear=True), patch(
            "osint_toolkit.adapter_setup.shutil.which",
            return_value="C:\\tools\\DetectDee.exe",
        ), patch("osint_toolkit.adapter_probe.subprocess.run", return_value=help_output):
            setup = build_adapter_setup(adapter)

        self.assertEqual(setup.readiness, "config_missing")
        self.assertEqual(setup.missing_env, ("DETECTDEE_DATA",))
        self.assertEqual(setup.install_kind, "binary")
        self.assertEqual(adapter.generated_output_file_args, ("-o", "{output_file}"))

        with patch.dict(os.environ, {"DETECTDEE_DATA": "C:\\tools\\DetectDee\\data.json"}), patch(
            "osint_toolkit.adapter_setup.shutil.which",
            return_value="C:\\tools\\DetectDee.exe",
        ), patch("osint_toolkit.adapter_probe.subprocess.run", return_value=help_output):
            ready = build_adapter_setup(adapter)
            self.assertEqual(ready.readiness, "ready")
            self.assertEqual(
                adapter.render_command(ScanTarget(kind="username", value="example_user")),
                (
                    "DetectDee",
                    "detect",
                    "-n",
                    "example_user",
                    "-f",
                    "C:\\tools\\DetectDee\\data.json",
                    "-r",
                    "1",
                    "--timeout",
                    "10",
                ),
            )
            self.assertEqual(
                adapter.render_command(ScanTarget(kind="email", value="person@example.com"))[:4],
                ("DetectDee", "detect", "-e", "person@example.com"),
            )
            self.assertEqual(
                adapter.render_command(ScanTarget(kind="phone", value="+380441234567"))[:4],
                ("DetectDee", "detect", "-p", "+380441234567"),
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
