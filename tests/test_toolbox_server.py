import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from osint_toolkit.toolbox_server import ToolboxJobRunner, create_toolbox_server


class ToolboxServerTests(unittest.TestCase):
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

    def _wait_for_job(self, base_url: str, job_id: str) -> dict[str, object]:
        for _ in range(60):
            job = self._request_json(f"{base_url}/api/jobs/{job_id}", auth="test-auth")
            if job["status"] in {"completed", "failed"}:
                return job
            time.sleep(0.2)
        self.fail(f"Job did not finish: {job_id}")

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
