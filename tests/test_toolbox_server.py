import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from osint_toolkit.case_store import CaseStore
from osint_toolkit.engine import ScanTarget
from osint_toolkit.investigation import run_investigation
from osint_toolkit.toolbox_server import ToolboxJobRunner, create_toolbox_server


class ToolboxServerTests(unittest.TestCase):
    def test_cli_toolbox_serve_process_runs_search_job_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]

            repo_root = Path(__file__).resolve().parents[1]
            env = os.environ.copy()
            env["PYTHONPATH"] = (
                str(repo_root)
                if not env.get("PYTHONPATH")
                else os.pathsep.join((str(repo_root), env["PYTHONPATH"]))
            )
            env["PYTHONUNBUFFERED"] = "1"
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "osint_toolkit",
                    "toolbox",
                    "--serve",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--out",
                    "toolbox.html",
                ],
                cwd=tmpdir,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            base_url = f"http://127.0.0.1:{port}"
            try:
                html = self._wait_for_toolbox_root(base_url, process)
                token_match = re.search(r'auth:\s*"([^"]+)"', html)
                self.assertIsNotNone(token_match)
                token = token_match.group(1)

                submitted = self._request_json(
                    f"{base_url}/api/search",
                    method="POST",
                    auth=token,
                    payload={
                        "target_kind": "phone",
                        "target_value": "+380441234567",
                        "profile": "phone-full",
                        "execute_adapters": True,
                        "adapter_limit": 0,
                        "out": "reports/phone.md",
                        "case_db": "cases.sqlite",
                        "case_id": "cli-smoke-phone",
                        "scope_note": "cli toolbox smoke",
                        "format": "markdown",
                    },
                )
                job_id = submitted["job"]["id"]
                job = self._wait_for_job(base_url, job_id, auth=token)
                self.assertEqual(job["status"], "completed", job)
                self.assertEqual(job["returncode"], 0)
                self.assertTrue(job["report_available"])

                report = self._request_text(f"{base_url}/api/jobs/{job_id}/report", auth=token)
                self.assertIn("## Phone Sources", report)
                self.assertIn("| Source | Findings | Statuses | Confidence | Signals |", report)

                cases = self._request_json(f"{base_url}/api/cases?case_db=cases.sqlite", auth=token)
                self.assertIn("cli-smoke-phone", {record["case_id"] for record in cases["cases"]})
                case = self._request_json(
                    f"{base_url}/api/cases/cli-smoke-phone?case_db=cases.sqlite",
                    auth=token,
                )
                self.assertEqual(case["metadata"]["scope_note"], "cli toolbox smoke")
                self.assertTrue(Path(tmpdir, "toolbox.html").exists())
                self.assertTrue(Path(tmpdir, "reports", "phone.md").exists())
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)
                if process.stdout:
                    process.stdout.close()
                if process.stderr:
                    process.stderr.close()

    def test_runner_rejects_outputs_outside_working_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = ToolboxJobRunner(cwd=tmpdir, auth="test-auth")

            with self.assertRaises(ValueError):
                runner.submit_search(
                    {
                        "target_kind": "email",
                        "target_value": "person@example.com",
                        "profile": "email-full",
                        "execute_adapters": True,
                        "out": "../outside.md",
                    }
                )

    def test_http_search_job_writes_report_and_case(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = ToolboxJobRunner(cwd=tmpdir, auth="test-auth")
            server = create_toolbox_server(host="127.0.0.1", port=0, runner=runner)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://{server.server_address[0]}:{server.server_address[1]}"
            try:
                payload = {
                    "target_kind": "email",
                    "target_value": "person@example.com",
                    "profile": "email-full",
                    "execute_adapters": True,
                    "adapter_limit": 0,
                    "out": "reports/email.md",
                    "case_db": "cases.sqlite",
                    "case_id": "email-1",
                    "scope_note": "server scope",
                    "format": "markdown",
                }
                data = self._request_json(
                    f"{base_url}/api/search",
                    method="POST",
                    auth="test-auth",
                    payload=payload,
                )
                job_id = data["job"]["id"]
                job = self._wait_for_job(base_url, job_id)

                self.assertEqual(job["status"], "completed", job)
                self.assertEqual(job["returncode"], 0)
                self.assertIn("--scope-note", job["command_preview"])
                self.assertTrue(Path(tmpdir, "reports", "email.md").exists())
                self.assertTrue(Path(tmpdir, "cases.sqlite").exists())
                self.assertIn("Search Execution Report: email", Path(tmpdir, "reports", "email.md").read_text(encoding="utf-8"))

                report = self._request_text(
                    f"{base_url}/api/jobs/{job_id}/report",
                    auth="test-auth",
                )
                self.assertIn("Search Execution Report: email", report)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_http_case_endpoints_read_saved_case_data(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = ToolboxJobRunner(cwd=tmpdir, auth="test-auth")
            server = create_toolbox_server(host="127.0.0.1", port=0, runner=runner)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://{server.server_address[0]}:{server.server_address[1]}"
            try:
                payload = {
                    "target_kind": "email",
                    "target_value": "person@example.com",
                    "profile": "email-full",
                    "execute_adapters": True,
                    "adapter_limit": 0,
                    "case_db": "cases.sqlite",
                    "case_id": "email-1",
                    "scope_note": "server scope",
                    "format": "json",
                }
                data = self._request_json(
                    f"{base_url}/api/search",
                    method="POST",
                    auth="test-auth",
                    payload=payload,
                )
                self._wait_for_job(base_url, data["job"]["id"])
                second_payload = {
                    "target_kind": "url",
                    "target_value": "https://example.com/profile",
                    "profile": "web-full",
                    "execute_adapters": True,
                    "adapter_limit": 0,
                    "case_db": "cases.sqlite",
                    "case_id": "url-1",
                    "format": "json",
                }
                second = self._request_json(
                    f"{base_url}/api/search",
                    method="POST",
                    auth="test-auth",
                    payload=second_payload,
                )
                self._wait_for_job(base_url, second["job"]["id"])

                cases = self._request_json(
                    f"{base_url}/api/cases?case_db=cases.sqlite",
                    auth="test-auth",
                )
                self.assertIn("email-1", {record["case_id"] for record in cases["cases"]})

                case = self._request_json(
                    f"{base_url}/api/cases/email-1?case_db=cases.sqlite",
                    auth="test-auth",
                )
                self.assertEqual(case["metadata"]["workflow"], "search")
                self.assertEqual(case["metadata"]["requested_profile"], "email-full")
                self.assertEqual(case["metadata"]["scope_note"], "server scope")

                graph = self._request_json(
                    f"{base_url}/api/cases/email-1/graph?case_db=cases.sqlite",
                    auth="test-auth",
                )
                self.assertEqual(graph["case_id"], "email-1")
                self.assertGreaterEqual(graph["node_count"], 2)

                index = self._request_json(
                    f"{base_url}/api/case-index?case_db=cases.sqlite&kind=domain&min_cases=1",
                    auth="test-auth",
                )
                values = {record["value"] for record in index["entities"]}
                self.assertIn("example.com", values)

                path = self._request_json(
                    (
                        f"{base_url}/api/case-path?case_db=cases.sqlite"
                        "&from_kind=email&from_value=person%40example.com"
                        "&to_kind=url&to_value=https%3A%2F%2Fexample.com%2Fprofile"
                    ),
                    auth="test-auth",
                )
                self.assertTrue(path["found"])
                self.assertEqual(path["hop_count"], 2)
                self.assertEqual([step["case_id"] for step in path["steps"]], ["email-1", "url-1"])

                network = self._request_json(
                    f"{base_url}/api/case-network?case_db=cases.sqlite&kind=domain",
                    auth="test-auth",
                )
                self.assertGreaterEqual(network["visible_node_count"], 3)
                network_nodes = {
                    (node["kind"], node["value"].lower()): node
                    for node in network["nodes"]
                }
                self.assertEqual(network_nodes[("domain", "example.com")]["case_count"], 2)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_http_case_management_endpoints_filter_update_and_delete(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "cases.sqlite"
            result = run_investigation(
                (ScanTarget(kind="email", value="person@example.com"),),
                title="server case",
            )
            CaseStore(db_path).save(
                result,
                case_id="case-1",
                metadata={
                    "workflow": "search",
                    "requested_profile": "email-full",
                    "scope_note": "server scope",
                },
            )

            runner = ToolboxJobRunner(cwd=tmpdir, auth="test-auth")
            server = create_toolbox_server(host="127.0.0.1", port=0, runner=runner)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://{server.server_address[0]}:{server.server_address[1]}"
            try:
                cases = self._request_json(
                    (
                        f"{base_url}/api/cases?case_db=cases.sqlite"
                        "&workflow=search&profile=email-full&scope_query=server"
                    ),
                    auth="test-auth",
                )
                self.assertEqual([record["case_id"] for record in cases["cases"]], ["case-1"])

                updated = self._request_json(
                    f"{base_url}/api/cases/case-1/update",
                    method="POST",
                    auth="test-auth",
                    payload={
                        "case_db": "cases.sqlite",
                        "title": "updated server case",
                        "scope_note": "updated scope",
                    },
                )
                self.assertEqual(updated["case"]["title"], "updated server case")
                self.assertEqual(updated["metadata"]["scope_note"], "updated scope")

                with self.assertRaises(urllib.error.HTTPError) as raised:
                    self._request_json(
                        f"{base_url}/api/cases/case-1/delete",
                        method="POST",
                        auth="test-auth",
                        payload={"case_db": "cases.sqlite", "confirm": "wrong"},
                    )
                self.assertEqual(raised.exception.code, 400)

                deleted = self._request_json(
                    f"{base_url}/api/cases/case-1/delete",
                    method="POST",
                    auth="test-auth",
                    payload={"case_db": "cases.sqlite", "confirm": "case-1"},
                )
                self.assertEqual(deleted, {"case_id": "case-1", "deleted": True})

                empty = self._request_json(
                    f"{base_url}/api/cases?case_db=cases.sqlite",
                    auth="test-auth",
                )
                self.assertEqual(empty["cases"], [])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_http_profiles_endpoint_and_search_accept_custom_profile_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_dir = Path(tmpdir) / "profiles"
            profile_dir.mkdir()
            profile_path = profile_dir / "case_profiles.json"
            profile_path.write_text(
                json.dumps(
                    {
                        "profiles": [
                            {
                                "name": "case-email-safe",
                                "target_kinds": ["email"],
                                "native_kinds": ["email"],
                                "adapter_profiles": ["email-safe"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            runner = ToolboxJobRunner(cwd=tmpdir, auth="test-auth")
            server = create_toolbox_server(host="127.0.0.1", port=0, runner=runner)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://{server.server_address[0]}:{server.server_address[1]}"
            try:
                profiles = self._request_json(
                    f"{base_url}/api/profiles?profile_file=profiles/case_profiles.json",
                    auth="test-auth",
                )
                profile_names = {profile["name"] for profile in profiles["profiles"]}
                self.assertEqual(profiles["custom_count"], 1)
                self.assertIn("case-email-safe", profile_names)

                data = self._request_json(
                    f"{base_url}/api/search",
                    method="POST",
                    auth="test-auth",
                    payload={
                        "target_kind": "email",
                        "target_value": "person@example.com",
                        "profile": "case-email-safe",
                        "profile_file": "profiles/case_profiles.json",
                        "execute_adapters": False,
                        "format": "json",
                    },
                )
                job = self._wait_for_job(base_url, data["job"]["id"])

                self.assertEqual(job["status"], "completed", job)
                self.assertIn("--profile-file", job["command_preview"])
                self.assertIn("case-email-safe", job["stdout"])

                with self.assertRaises(urllib.error.HTTPError) as raised:
                    self._request_json(
                        f"{base_url}/api/profiles?profile_file=../outside.json",
                        auth="test-auth",
                    )
                self.assertEqual(raised.exception.code, 400)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_http_profile_editor_can_save_update_and_delete_profile(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = ToolboxJobRunner(cwd=tmpdir, auth="test-auth")
            server = create_toolbox_server(host="127.0.0.1", port=0, runner=runner)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://{server.server_address[0]}:{server.server_address[1]}"
            try:
                profile_payload = {
                    "profile_file": "profiles/case_profiles.json",
                    "profile": {
                        "name": "case-email-safe",
                        "title": "Case email safe",
                        "target_kinds": ["email"],
                        "native_kinds": ["email"],
                        "derived_target_kinds": ["domain"],
                        "adapter_profiles": ["email-safe"],
                    },
                }
                saved = self._request_json(
                    f"{base_url}/api/profiles/save",
                    method="POST",
                    auth="test-auth",
                    payload=profile_payload,
                )
                self.assertTrue(Path(tmpdir, "profiles", "case_profiles.json").exists())
                self.assertTrue(saved["saved"])
                self.assertEqual(saved["custom_count"], 1)
                self.assertEqual(saved["profile"]["name"], "case-email-safe")
                self.assertEqual(saved["profile"]["derived_target_kinds"], ["domain"])

                profile_payload["profile"]["description"] = "Updated profile"
                updated = self._request_json(
                    f"{base_url}/api/profiles/save",
                    method="POST",
                    auth="test-auth",
                    payload=profile_payload,
                )
                custom_profiles = [
                    profile for profile in updated["profiles"]
                    if profile["name"] == "case-email-safe"
                ]
                self.assertEqual(len(custom_profiles), 1)
                self.assertEqual(custom_profiles[0]["description"], "Updated profile")

                data = self._request_json(
                    f"{base_url}/api/search",
                    method="POST",
                    auth="test-auth",
                    payload={
                        "target_kind": "email",
                        "target_value": "person@example.com",
                        "profile": "case-email-safe",
                        "profile_file": "profiles/case_profiles.json",
                        "execute_adapters": False,
                        "format": "json",
                    },
                )
                job = self._wait_for_job(base_url, data["job"]["id"])
                self.assertEqual(job["status"], "completed", job)
                self.assertIn("case-email-safe", job["stdout"])

                deleted = self._request_json(
                    f"{base_url}/api/profiles/delete",
                    method="POST",
                    auth="test-auth",
                    payload={
                        "profile_file": "profiles/case_profiles.json",
                        "profile": "case-email-safe",
                    },
                )
                self.assertTrue(deleted["deleted"])
                self.assertEqual(deleted["custom_count"], 0)

                with self.assertRaises(urllib.error.HTTPError) as raised:
                    self._request_json(
                        f"{base_url}/api/profiles/save",
                        method="POST",
                        auth="test-auth",
                        payload={
                            "profile_file": "../outside.json",
                            "profile": profile_payload["profile"],
                        },
                    )
                self.assertEqual(raised.exception.code, 400)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_http_tools_endpoint_reports_profile_readiness(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_dir = Path(tmpdir) / "profiles"
            profile_dir.mkdir()
            profile_path = profile_dir / "case_profiles.json"
            profile_path.write_text(
                json.dumps(
                    {
                        "profiles": [
                            {
                                "name": "case-email-safe",
                                "target_kinds": ["email"],
                                "adapter_profiles": ["email-safe"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            runner = ToolboxJobRunner(cwd=tmpdir, auth="test-auth")
            server = create_toolbox_server(host="127.0.0.1", port=0, runner=runner)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://{server.server_address[0]}:{server.server_address[1]}"
            try:
                doctor = self._request_json(
                    (
                        f"{base_url}/api/tools?profile=case-email-safe"
                        "&profile_file=profiles/case_profiles.json"
                        "&view=doctor&format=markdown"
                    ),
                    auth="test-auth",
                )
                names = {row["name"] for row in doctor["rows"]}
                self.assertEqual(doctor["profile"]["name"], "case-email-safe")
                self.assertEqual(doctor["view"], "doctor")
                self.assertIn("alpkeskin/mosint", names)
                self.assertIn("| Kind | Name | Readiness |", doctor["content"])

                env = self._request_json(
                    (
                        f"{base_url}/api/tools?profile=case-email-safe"
                        "&profile_file=profiles/case_profiles.json"
                        "&view=env&format=markdown"
                    ),
                    auth="test-auth",
                )
                self.assertIn("HIBP_API_KEY", env["content"])

                install = self._request_json(
                    f"{base_url}/api/tools?profile=image-full&view=install-plan&format=markdown",
                    auth="test-auth",
                )
                self.assertIn("Install / action", install["content"])

                with self.assertRaises(urllib.error.HTTPError) as raised:
                    self._request_json(
                        f"{base_url}/api/tools?profile=case-email-safe&profile_file=../outside.json",
                        auth="test-auth",
                    )
                self.assertEqual(raised.exception.code, 400)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_http_tools_install_endpoint_runs_profile_aware_dry_run_and_execute(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_dir = Path(tmpdir) / "profiles"
            profile_dir.mkdir()
            (profile_dir / "case_profiles.json").write_text(
                json.dumps(
                    {
                        "profiles": [
                            {
                                "name": "empty-email-safe",
                                "target_kinds": ["email"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            runner = ToolboxJobRunner(cwd=tmpdir, auth="test-auth")
            server = create_toolbox_server(host="127.0.0.1", port=0, runner=runner)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://{server.server_address[0]}:{server.server_address[1]}"
            try:
                dry_run = self._request_json(
                    f"{base_url}/api/tools/install",
                    method="POST",
                    auth="test-auth",
                    payload={
                        "profile": "empty-email-safe",
                        "profile_file": "profiles/case_profiles.json",
                        "execute": False,
                        "format": "markdown",
                    },
                )
                self.assertFalse(dry_run["execute"])
                self.assertEqual(dry_run["profile"]["name"], "empty-email-safe")
                self.assertEqual(dry_run["results"], [])
                self.assertIn("| Kind | Name | Readiness | Action | Status |", dry_run["content"])

                executed = self._request_json(
                    f"{base_url}/api/tools/install",
                    method="POST",
                    auth="test-auth",
                    payload={
                        "profile": "empty-email-safe",
                        "profile_file": "profiles/case_profiles.json",
                        "execute": True,
                        "format": "markdown",
                    },
                )
                self.assertTrue(executed["execute"])
                self.assertEqual(executed["results"], [])

                with self.assertRaises(urllib.error.HTTPError) as raised:
                    self._request_json(
                        f"{base_url}/api/tools/install",
                        method="POST",
                        auth="test-auth",
                        payload={
                            "profile": "empty-email-safe",
                            "profile_file": "../outside.json",
                            "execute": False,
                        },
                    )
                self.assertEqual(raised.exception.code, 400)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_http_case_endpoints_reject_db_outside_working_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = ToolboxJobRunner(cwd=tmpdir, auth="test-auth")
            server = create_toolbox_server(host="127.0.0.1", port=0, runner=runner)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://{server.server_address[0]}:{server.server_address[1]}"
            try:
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    self._request_text(
                        f"{base_url}/api/cases?case_db=../outside.sqlite",
                        auth="test-auth",
                    )
                self.assertEqual(raised.exception.code, 400)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_http_api_requires_token(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = ToolboxJobRunner(cwd=tmpdir, auth="test-auth")
            server = create_toolbox_server(host="127.0.0.1", port=0, runner=runner)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://{server.server_address[0]}:{server.server_address[1]}"
            try:
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    self._request_text(f"{base_url}/api/jobs")
                self.assertEqual(raised.exception.code, 400)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_root_html_does_not_expose_cors_but_api_does(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = ToolboxJobRunner(cwd=tmpdir, auth="test-auth")
            server = create_toolbox_server(host="127.0.0.1", port=0, runner=runner)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://{server.server_address[0]}:{server.server_address[1]}"
            try:
                with urllib.request.urlopen(f"{base_url}/", timeout=20) as response:
                    html = response.read().decode("utf-8")
                    self.assertIn("Unified Search Runner", html)
                    self.assertIsNone(response.headers.get("Access-Control-Allow-Origin"))

                request = urllib.request.Request(
                    f"{base_url}/api/jobs",
                    headers={"X-OSINT-Token": "test-auth"},
                )
                with urllib.request.urlopen(request, timeout=20) as response:
                    self.assertEqual(response.headers.get("Access-Control-Allow-Origin"), "*")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def _wait_for_toolbox_root(self, base_url: str, process: subprocess.Popen[str]) -> str:
        last_error = ""
        for _ in range(120):
            if process.poll() is not None:
                stdout, stderr = process.communicate(timeout=5)
                self.fail(f"toolbox server exited early: stdout={stdout!r} stderr={stderr!r}")
            try:
                html = self._request_text(f"{base_url}/")
                if "Unified Search Runner" in html:
                    return html
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                last_error = str(exc)
            time.sleep(0.25)
        self.fail(f"Toolbox root did not become ready: {last_error}")

    def _wait_for_job(self, base_url: str, job_id: str, *, auth: str = "test-auth") -> dict[str, object]:
        last_job: dict[str, object] | None = None
        for _ in range(180):
            job = self._request_json(f"{base_url}/api/jobs/{job_id}", auth=auth)
            last_job = job
            if job["status"] in {"completed", "failed"}:
                return job
            time.sleep(0.2)
        self.fail(f"Job did not finish: {job_id}; last status: {last_job}")

    def _request_json(
        self,
        url: str,
        *,
        method: str = "GET",
        auth: str = "",
        payload: dict[str, object] | None = None,
    ) -> dict[str, object]:
        return json.loads(self._request_text(url, method=method, auth=auth, payload=payload))

    def _request_text(
        self,
        url: str,
        *,
        method: str = "GET",
        auth: str = "",
        payload: dict[str, object] | None = None,
    ) -> str:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {}
        if auth:
            headers["X-OSINT-Token"] = auth
        if payload is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.read().decode("utf-8")


if __name__ == "__main__":
    unittest.main()
