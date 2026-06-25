from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from .case_store import CaseStore
from .graph import analyze_case_graph, analyze_cross_case_network, analyze_cross_case_path
from .search import TARGET_KINDS, list_search_profiles
from .toolbox import render_toolbox_html, write_toolbox


VALID_TARGET_KINDS = ("auto", *TARGET_KINDS)
VALID_PROFILES = ("auto", *(profile.name for profile in list_search_profiles()))
VALID_REGIONS = ("all", "ru", "ua")
VALID_FORMATS = ("markdown", "json")


@dataclass
class ToolboxJob:
    id: str
    command: list[str]
    command_preview: str
    cwd: Path
    status: str = "queued"
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    report_path: Path | None = None
    case_db: Path | None = None
    case_id: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "status": self.status,
            "command": self.command,
            "command_preview": self.command_preview,
            "cwd": str(self.cwd),
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "error": self.error,
            "report_path": str(self.report_path) if self.report_path else "",
            "report_available": bool(self.report_path and self.report_path.exists()),
            "case_db": str(self.case_db) if self.case_db else "",
            "case_id": self.case_id,
        }


class ToolboxJobRunner:
    def __init__(self, *, cwd: str | Path, auth: str | None = None) -> None:
        self.cwd = Path(cwd).resolve()
        self.cwd.mkdir(parents=True, exist_ok=True)
        self.auth = auth or secrets.token_urlsafe(24)
        self._jobs: dict[str, ToolboxJob] = {}
        self._lock = threading.Lock()
        self._package_root = Path(__file__).resolve().parents[1]

    def submit_search(self, payload: dict[str, Any]) -> ToolboxJob:
        job_id = secrets.token_hex(8)
        command, report_path, case_db, case_id = self._build_search_command(payload, job_id=job_id)
        job = ToolboxJob(
            id=job_id,
            command=command,
            command_preview=subprocess.list2cmdline(command),
            cwd=self.cwd,
            report_path=report_path,
            case_db=case_db,
            case_id=case_id,
        )
        with self._lock:
            self._jobs[job.id] = job
        thread = threading.Thread(target=self._run_job, args=(job,), daemon=True)
        thread.start()
        return job

    def list_jobs(self) -> tuple[ToolboxJob, ...]:
        with self._lock:
            return tuple(sorted(self._jobs.values(), key=lambda item: item.created_at))

    def get_job(self, job_id: str) -> ToolboxJob:
        with self._lock:
            try:
                return self._jobs[job_id]
            except KeyError as exc:
                raise ValueError(f"Unknown job id: {job_id}") from exc

    def read_report(self, job_id: str) -> str:
        job = self.get_job(job_id)
        if not job.report_path:
            raise ValueError("Job has no report path.")
        if not job.report_path.exists():
            raise ValueError("Report is not available yet.")
        return job.report_path.read_text(encoding="utf-8", errors="replace")

    def list_cases(self, case_db: str, *, limit: int) -> dict[str, object]:
        records = CaseStore(self._case_db_path(case_db)).list_cases(limit=limit)
        return {"cases": [record.to_dict() for record in records]}

    def load_case(self, case_db: str, case_id: str) -> dict[str, object]:
        normalized_case_id = case_id.strip()
        if not normalized_case_id:
            raise ValueError("case_id is required.")
        return CaseStore(self._case_db_path(case_db)).load_case(normalized_case_id)

    def case_graph(
        self,
        case_db: str,
        case_id: str,
        *,
        focus_kind: str = "",
        focus_value: str = "",
        limit: int = 20,
    ) -> dict[str, object]:
        payload = self.load_case(case_db, case_id)
        return analyze_case_graph(
            payload,
            focus_kind=focus_kind,
            focus_value=focus_value,
            limit=limit,
        ).to_dict()

    def case_index(
        self,
        case_db: str,
        *,
        kind: str = "",
        value: str = "",
        min_cases: int = 1,
        limit: int = 50,
    ) -> dict[str, object]:
        store = CaseStore(self._case_db_path(case_db))
        if value:
            if not kind:
                raise ValueError("kind is required when value is provided.")
            hits = store.find_cases_by_entity(kind=kind, value=value)
            return {"hits": [hit.to_dict() for hit in hits]}
        records = store.list_entity_index(kind=kind, min_cases=min_cases, limit=limit)
        return {"entities": [record.to_dict() for record in records]}

    def case_path(
        self,
        case_db: str,
        *,
        source_kind: str,
        source_value: str,
        target_kind: str,
        target_value: str,
        case_limit: int = 100,
        max_depth: int = 6,
    ) -> dict[str, object]:
        store = CaseStore(self._case_db_path(case_db))
        return analyze_cross_case_path(
            store.load_cases(limit=case_limit),
            source_kind=source_kind,
            source_value=source_value,
            target_kind=target_kind,
            target_value=target_value,
            max_depth=max_depth,
        ).to_dict()

    def case_network(
        self,
        case_db: str,
        *,
        kind: str = "",
        relation: str = "",
        case_limit: int = 100,
        node_limit: int = 60,
        edge_limit: int = 120,
        min_degree: int = 1,
    ) -> dict[str, object]:
        store = CaseStore(self._case_db_path(case_db))
        return analyze_cross_case_network(
            store.load_cases(limit=case_limit),
            kind_filter=kind,
            relation_filter=relation,
            min_degree=min_degree,
            node_limit=node_limit,
            edge_limit=edge_limit,
        ).to_dict()

    def _run_job(self, job: ToolboxJob) -> None:
        self._set_job(job.id, status="running", started_at=time.time())
        env = os.environ.copy()
        existing_pythonpath = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = (
            str(self._package_root)
            if not existing_pythonpath
            else os.pathsep.join((str(self._package_root), existing_pythonpath))
        )
        try:
            result = subprocess.run(
                job.command,
                cwd=job.cwd,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
        except OSError as exc:
            self._set_job(
                job.id,
                status="failed",
                finished_at=time.time(),
                error=str(exc),
                returncode=None,
            )
            return
        status = "completed" if result.returncode == 0 else "failed"
        self._set_job(
            job.id,
            status=status,
            finished_at=time.time(),
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    def _set_job(self, job_id: str, **updates: object) -> None:
        with self._lock:
            job = self._jobs[job_id]
            for key, value in updates.items():
                setattr(job, key, value)

    def _build_search_command(
        self,
        payload: dict[str, Any],
        *,
        job_id: str,
    ) -> tuple[list[str], Path | None, Path | None, str]:
        target_kind = _choice(payload, "target_kind", VALID_TARGET_KINDS, default="auto")
        target_value = str(payload.get("target_value", "")).strip()
        if not target_value:
            raise ValueError("target_value is required.")
        profile = _choice(payload, "profile", VALID_PROFILES, default="auto")
        region = _choice(payload, "region", VALID_REGIONS, default="all")
        output_format = _choice(payload, "format", VALID_FORMATS, default="markdown")
        execute_adapters = bool(payload.get("execute_adapters", False))
        include_restricted = bool(payload.get("include_restricted", False))
        adapter_limit = _int_value(payload, "adapter_limit", default=20, minimum=0, maximum=500)
        derived_limit = _int_value(payload, "derived_limit", default=20, minimum=0, maximum=500)
        scope_note = str(payload.get("scope_note", "")).strip()
        timeout = _float_value(payload, "timeout", default=10.0, minimum=0.1, maximum=3600.0)
        adapter_timeout = _float_value(
            payload,
            "adapter_timeout",
            default=60.0,
            minimum=0.1,
            maximum=7200.0,
        )

        command = [
            sys.executable,
            "-m",
            "osint_toolkit",
            "search",
            target_kind,
            target_value,
            "--profile",
            profile,
            "--region",
            region,
            "--format",
            output_format,
            "--timeout",
            str(timeout),
            "--adapter-timeout",
            str(adapter_timeout),
            "--adapter-limit",
            str(adapter_limit),
            "--derived-limit",
            str(derived_limit),
        ]
        if include_restricted:
            command.append("--include-restricted")

        report_path: Path | None = None
        case_db: Path | None = None
        case_id = str(payload.get("case_id", "")).strip() or job_id
        if execute_adapters:
            command.append("--execute-adapters")
            suffix = "json" if output_format == "json" else "md"
            default_report = f"reports/toolbox-{job_id}.{suffix}"
            report_path = self._output_path(str(payload.get("out", "")).strip(), default_report)
            case_db = self._output_path(str(payload.get("case_db", "")).strip(), "cases.sqlite")
            command.extend(["--out", str(report_path), "--case-db", str(case_db), "--case-id", case_id])
            if scope_note:
                command.extend(["--scope-note", scope_note])
        else:
            command.append("--plan-only")
        return command, report_path, case_db, case_id

    def _output_path(self, value: str, default: str) -> Path:
        path = Path(value or default)
        if not path.is_absolute():
            path = self.cwd / path
        resolved = path.resolve()
        if not resolved.is_relative_to(self.cwd):
            raise ValueError(f"Backend output path must stay inside {self.cwd}: {value or default}")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        return resolved

    def _case_db_path(self, value: str) -> Path:
        normalized = str(value or "cases.sqlite").strip() or "cases.sqlite"
        path = Path(normalized)
        if not path.is_absolute():
            path = self.cwd / path
        resolved = path.resolve()
        if not resolved.is_relative_to(self.cwd):
            raise ValueError(f"Case DB path must stay inside {self.cwd}: {normalized}")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        return resolved


def create_toolbox_server(
    *,
    host: str,
    port: int,
    runner: ToolboxJobRunner,
) -> ThreadingHTTPServer:
    class Handler(ToolboxRequestHandler):
        pass

    server = ThreadingHTTPServer((host, port), Handler)
    server.runner = runner  # type: ignore[attr-defined]
    return server


def run_toolbox_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    out: str = "osint_toolbox.html",
    open_browser: bool = False,
) -> int:
    runner = ToolboxJobRunner(cwd=Path.cwd())
    server = create_toolbox_server(host=host, port=port, runner=runner)
    actual_host, actual_port = server.server_address
    backend_url = f"http://{actual_host}:{actual_port}"
    path = write_toolbox(out, backend_url=backend_url, backend_auth=runner.auth).resolve()
    print(f"Toolbox backend: {backend_url}")
    print(f"Wrote toolbox {path}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        webbrowser.open(backend_url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


class ToolboxRequestHandler(BaseHTTPRequestHandler):
    server_version = "OSINTToolbox/0.1"

    def do_OPTIONS(self) -> None:
        self._send_empty(204)

    def do_GET(self) -> None:
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path
            query = parse_qs(parsed_url.query)
            if path == "/":
                runner = self._runner()
                host, port = self.server.server_address[:2]
                html = render_toolbox_html(
                    backend_url=f"http://{host}:{port}",
                    backend_auth=runner.auth,
                )
                self._send_text(200, html, content_type="text/html; charset=utf-8", cors=False)
                return
            if path == "/api/health":
                self._require_token()
                self._send_json(200, {"status": "ok"})
                return
            if path == "/api/jobs":
                self._require_token()
                jobs = [job.to_dict() for job in self._runner().list_jobs()]
                self._send_json(200, {"jobs": jobs})
                return
            if path == "/api/cases":
                self._require_token()
                self._send_json(
                    200,
                    self._runner().list_cases(
                        _query_string(query, "case_db", default="cases.sqlite"),
                        limit=_query_int(query, "limit", default=20, minimum=1, maximum=500),
                    ),
                )
                return
            if path == "/api/case-index":
                self._require_token()
                self._send_json(
                    200,
                    self._runner().case_index(
                        _query_string(query, "case_db", default="cases.sqlite"),
                        kind=_query_string(query, "kind", default=""),
                        value=_query_string(query, "value", default=""),
                        min_cases=_query_int(query, "min_cases", default=1, minimum=1, maximum=500),
                        limit=_query_int(query, "limit", default=50, minimum=1, maximum=500),
                    ),
                )
                return
            if path == "/api/case-path":
                self._require_token()
                self._send_json(
                    200,
                    self._runner().case_path(
                        _query_string(query, "case_db", default="cases.sqlite"),
                        source_kind=_query_string(query, "from_kind", default=""),
                        source_value=_query_string(query, "from_value", default=""),
                        target_kind=_query_string(query, "to_kind", default=""),
                        target_value=_query_string(query, "to_value", default=""),
                        case_limit=_query_int(query, "case_limit", default=100, minimum=1, maximum=1000),
                        max_depth=_query_int(query, "max_depth", default=6, minimum=1, maximum=20),
                    ),
                )
                return
            if path == "/api/case-network":
                self._require_token()
                self._send_json(
                    200,
                    self._runner().case_network(
                        _query_string(query, "case_db", default="cases.sqlite"),
                        kind=_query_string(query, "kind", default=""),
                        relation=_query_string(query, "relation", default=""),
                        case_limit=_query_int(query, "case_limit", default=100, minimum=1, maximum=1000),
                        node_limit=_query_int(query, "node_limit", default=60, minimum=1, maximum=500),
                        edge_limit=_query_int(query, "edge_limit", default=120, minimum=1, maximum=1000),
                        min_degree=_query_int(query, "min_degree", default=1, minimum=0, maximum=1000),
                    ),
                )
                return
            case_id, case_route = self._case_route(path)
            if case_id and case_route == "show":
                self._require_token()
                self._send_json(
                    200,
                    self._runner().load_case(
                        _query_string(query, "case_db", default="cases.sqlite"),
                        case_id,
                    ),
                )
                return
            if case_id and case_route == "graph":
                self._require_token()
                self._send_json(
                    200,
                    self._runner().case_graph(
                        _query_string(query, "case_db", default="cases.sqlite"),
                        case_id,
                        focus_kind=_query_string(query, "entity_kind", default=""),
                        focus_value=_query_string(query, "entity_value", default=""),
                        limit=_query_int(query, "limit", default=20, minimum=1, maximum=500),
                    ),
                )
                return
            job_id, report = self._job_route(path)
            if job_id and report:
                self._require_token()
                self._send_text(200, self._runner().read_report(job_id), content_type="text/plain; charset=utf-8")
                return
            if job_id:
                self._require_token()
                self._send_json(200, self._runner().get_job(job_id).to_dict())
                return
            self._send_json(404, {"error": "not_found"})
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})

    def do_POST(self) -> None:
        try:
            self._require_token()
            path = urlparse(self.path).path
            if path != "/api/search":
                self._send_json(404, {"error": "not_found"})
                return
            payload = self._read_json()
            job = self._runner().submit_search(payload)
            self._send_json(202, {"job": job.to_dict()})
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})

    def log_message(self, format: str, *args: object) -> None:
        return

    def _runner(self) -> ToolboxJobRunner:
        return self.server.runner  # type: ignore[attr-defined,no-any-return]

    def _require_token(self) -> None:
        expected = self._runner().auth
        provided = self.headers.get("X-OSINT-Token", "")
        if not expected or provided != expected:
            raise ValueError("Invalid or missing backend token.")

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError("JSON payload must be an object.")
        return value

    def _job_route(self, path: str) -> tuple[str, bool]:
        parts = [part for part in path.split("/") if part]
        if len(parts) == 3 and parts[:2] == ["api", "jobs"]:
            return parts[2], False
        if len(parts) == 4 and parts[:2] == ["api", "jobs"] and parts[3] == "report":
            return parts[2], True
        return "", False

    def _case_route(self, path: str) -> tuple[str, str]:
        parts = [part for part in path.split("/") if part]
        if len(parts) == 3 and parts[:2] == ["api", "cases"]:
            return unquote(parts[2]), "show"
        if len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[3] == "graph":
            return unquote(parts[2]), "graph"
        return "", ""

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self._common_headers("application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status: int, body: str, *, content_type: str, cors: bool = True) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self._common_headers(content_type, cors=cors)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_empty(self, status: int) -> None:
        self.send_response(status)
        self._common_headers("text/plain; charset=utf-8", cors=True)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _common_headers(self, content_type: str, *, cors: bool = True) -> None:
        self.send_header("Content-Type", content_type)
        if cors:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-OSINT-Token")


def _choice(
    payload: dict[str, Any],
    key: str,
    choices: tuple[str, ...],
    *,
    default: str,
) -> str:
    value = str(payload.get(key, default) or default).strip()
    if value not in choices:
        raise ValueError(f"{key} must be one of: {', '.join(choices)}")
    return value


def _query_string(query: dict[str, list[str]], key: str, *, default: str) -> str:
    values = query.get(key)
    if not values:
        return default
    return str(values[0]).strip()


def _query_int(
    query: dict[str, list[str]],
    key: str,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    raw = _query_string(query, key, default=str(default))
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be an integer.") from exc
    if value < minimum or value > maximum:
        raise ValueError(f"{key} must be between {minimum} and {maximum}.")
    return value


def _int_value(
    payload: dict[str, Any],
    key: str,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    raw = payload.get(key, default)
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be an integer.") from exc
    if value < minimum or value > maximum:
        raise ValueError(f"{key} must be between {minimum} and {maximum}.")
    return value


def _float_value(
    payload: dict[str, Any],
    key: str,
    *,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    raw = payload.get(key, default)
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be a number.") from exc
    if value < minimum or value > maximum:
        raise ValueError(f"{key} must be between {minimum} and {maximum}.")
    return value
