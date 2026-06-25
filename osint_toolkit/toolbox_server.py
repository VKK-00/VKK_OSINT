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

from .case_store import CaseStore, CaseStoreError
from .environment import refresh_runtime_environment
from .graph import analyze_case_graph, analyze_cross_case_network, analyze_cross_case_path
from .output import findings_from_case_payload, finding_source_summary, format_case_source_summary
from .search import (
    TARGET_KINDS,
    SearchProfile,
    find_search_profile,
    list_search_profiles,
    load_search_profiles,
    parse_search_profiles,
)
from .toolbox import render_toolbox_html, write_toolbox
from .tools import (
    build_tool_install_results,
    build_profile_tool_readiness,
    format_env_plan,
    format_install_plan,
    format_tool_install_results,
    format_tool_readiness,
)


VALID_TARGET_KINDS = ("auto", *TARGET_KINDS)
VALID_REGIONS = ("all", "ru", "ua")
VALID_FORMATS = ("markdown", "json")
VALID_TOOL_VIEWS = ("doctor", "install-plan", "env")


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

    def list_profiles(self, profile_file: str = "") -> dict[str, object]:
        custom_profiles, profile_file_path = self._custom_profiles(profile_file)
        profiles = list_search_profiles(custom_profiles)
        return {
            "profile_file": str(profile_file_path) if profile_file_path else "",
            "custom_count": len(custom_profiles),
            "profiles": [profile.to_dict() for profile in profiles],
        }

    def save_profile(self, payload: dict[str, Any]) -> dict[str, object]:
        profile_file = str(payload.get("profile_file", "")).strip()
        if not profile_file:
            raise ValueError("profile_file is required.")
        profile_payload = payload.get("profile")
        if not isinstance(profile_payload, dict):
            raise ValueError("profile must be a JSON object.")

        profile_file_path = self._profile_file_path(profile_file, allow_create=True)
        existing_profiles = (
            load_search_profiles(profile_file_path)
            if profile_file_path.exists()
            else ()
        )
        parsed_profile = parse_search_profiles({"profiles": [profile_payload]})
        if not parsed_profile:
            raise ValueError("profile must define a custom search profile, not a built-in no-op export.")
        profile = parsed_profile[0]

        replacement = profile.to_dict()
        next_profiles: list[dict[str, object]] = [
            existing.to_dict()
            for existing in existing_profiles
            if existing.name.lower() != profile.name.lower()
        ]
        next_profiles.append(replacement)
        validated_profiles = parse_search_profiles({"profiles": next_profiles})
        _write_profile_file(profile_file_path, validated_profiles)
        return {
            "saved": True,
            "profile_file": str(profile_file_path),
            "profile": profile.to_dict(),
            "custom_count": len(validated_profiles),
            "profiles": [item.to_dict() for item in list_search_profiles(validated_profiles)],
        }

    def delete_profile(self, payload: dict[str, Any]) -> dict[str, object]:
        profile_file = str(payload.get("profile_file", "")).strip()
        profile_name = str(payload.get("profile", "")).strip()
        if not profile_file:
            raise ValueError("profile_file is required.")
        if not profile_name:
            raise ValueError("profile is required.")

        profile_file_path = self._profile_file_path(profile_file, allow_create=False)
        custom_profiles = load_search_profiles(profile_file_path)
        remaining_profiles = tuple(
            profile for profile in custom_profiles if profile.name.lower() != profile_name.lower()
        )
        if len(remaining_profiles) == len(custom_profiles):
            raise ValueError(f"custom profile not found: {profile_name}")
        _write_profile_file(profile_file_path, remaining_profiles)
        return {
            "deleted": True,
            "profile_file": str(profile_file_path),
            "profile": profile_name,
            "custom_count": len(remaining_profiles),
            "profiles": [item.to_dict() for item in list_search_profiles(remaining_profiles)],
        }

    def profile_tools(
        self,
        *,
        profile: str,
        profile_file: str = "",
        view: str = "doctor",
        output_format: str = "markdown",
    ) -> dict[str, object]:
        refresh_runtime_environment()
        if view not in VALID_TOOL_VIEWS:
            raise ValueError(f"view must be one of: {', '.join(VALID_TOOL_VIEWS)}")
        if output_format not in VALID_FORMATS:
            raise ValueError(f"format must be one of: {', '.join(VALID_FORMATS)}")
        custom_profiles, profile_file_path = self._custom_profiles(profile_file)
        selected_profile = find_search_profile(profile, custom_profiles=custom_profiles)
        rows = build_profile_tool_readiness(selected_profile.name, custom_profiles=custom_profiles)
        if view == "install-plan":
            content = format_install_plan(rows, output_format=output_format)
        elif view == "env":
            content = format_env_plan(rows, output_format=output_format)
        else:
            content = format_tool_readiness(rows, output_format=output_format)
        return {
            "profile_file": str(profile_file_path) if profile_file_path else "",
            "profile": selected_profile.to_dict(),
            "view": view,
            "format": output_format,
            "rows": [row.to_dict() for row in rows],
            "content": content,
        }

    def profile_tools_install(self, payload: dict[str, Any]) -> dict[str, object]:
        refresh_runtime_environment()
        profile = str(payload.get("profile", "all-safe") or "all-safe").strip() or "all-safe"
        profile_file = str(payload.get("profile_file", "") or "").strip()
        output_format = _choice(payload, "format", VALID_FORMATS, default="markdown")
        execute = bool(payload.get("execute", False))
        timeout = _float_value(payload, "timeout", default=300.0, minimum=0.1, maximum=7200.0)
        custom_profiles, profile_file_path = self._custom_profiles(profile_file)
        selected_profile = find_search_profile(profile, custom_profiles=custom_profiles)
        rows = build_profile_tool_readiness(selected_profile.name, custom_profiles=custom_profiles)
        results = build_tool_install_results(rows, execute=execute, timeout=timeout)
        return {
            "profile_file": str(profile_file_path) if profile_file_path else "",
            "profile": selected_profile.to_dict(),
            "execute": execute,
            "format": output_format,
            "results": [result.to_dict() for result in results],
            "content": format_tool_install_results(results, output_format=output_format),
        }

    def list_cases(
        self,
        case_db: str,
        *,
        limit: int,
        workflow: str = "",
        profile: str = "",
        scope_query: str = "",
    ) -> dict[str, object]:
        records = CaseStore(self._case_db_path(case_db)).list_cases(
            limit=limit,
            workflow=workflow,
            profile=profile,
            scope_query=scope_query,
        )
        return {"cases": [record.to_dict() for record in records]}

    def load_case(self, case_db: str, case_id: str) -> dict[str, object]:
        normalized_case_id = case_id.strip()
        if not normalized_case_id:
            raise ValueError("case_id is required.")
        return CaseStore(self._case_db_path(case_db)).load_case(normalized_case_id)

    def update_case(self, case_db: str, case_id: str, payload: dict[str, Any]) -> dict[str, object]:
        normalized_case_id = case_id.strip()
        if not normalized_case_id:
            raise ValueError("case_id is required.")
        metadata_updates: dict[str, object] = {}
        if "scope_note" in payload:
            metadata_updates["scope_note"] = str(payload.get("scope_note", ""))
        title = payload.get("title")
        return CaseStore(self._case_db_path(case_db)).update_case(
            normalized_case_id,
            title=None if title is None else str(title),
            metadata_updates=metadata_updates,
        )

    def delete_case(self, case_db: str, case_id: str, payload: dict[str, Any]) -> dict[str, object]:
        normalized_case_id = case_id.strip()
        if not normalized_case_id:
            raise ValueError("case_id is required.")
        confirmation = str(payload.get("confirm", "")).strip()
        if confirmation != normalized_case_id:
            raise ValueError("delete confirmation must exactly match case_id.")
        deleted_case_id = CaseStore(self._case_db_path(case_db)).delete_case(normalized_case_id)
        return {"case_id": deleted_case_id, "deleted": True}

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

    def case_sources(
        self,
        case_db: str,
        case_id: str,
        *,
        output_format: str = "markdown",
    ) -> dict[str, object]:
        if output_format not in VALID_FORMATS:
            raise ValueError(f"format must be one of: {', '.join(VALID_FORMATS)}")
        payload = self.load_case(case_db, case_id)
        findings = findings_from_case_payload(payload)
        return {
            "case": payload.get("case", {}),
            "format": output_format,
            "source_summary": list(finding_source_summary(findings)),
            "content": format_case_source_summary(payload, output_format=output_format),
        }

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
        profile = str(payload.get("profile", "auto") or "auto").strip() or "auto"
        custom_profiles, profile_file_path = self._custom_profiles(str(payload.get("profile_file", "")))
        if profile != "auto":
            find_search_profile(profile, custom_profiles=custom_profiles)
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
        if profile_file_path:
            command.extend(["--profile-file", str(profile_file_path)])
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

    def _custom_profiles(self, value: str) -> tuple[tuple[SearchProfile, ...], Path | None]:
        normalized = value.strip()
        if not normalized:
            return (), None
        profile_file_path = self._profile_file_path(normalized, allow_create=False)
        return load_search_profiles(profile_file_path), profile_file_path

    def _profile_file_path(self, value: str, *, allow_create: bool) -> Path:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Profile file is required.")
        if Path(normalized).suffix.lower() != ".json":
            raise ValueError("Profile file must use a .json extension.")
        path = Path(normalized)
        if not path.is_absolute():
            path = self.cwd / path
        resolved = path.resolve()
        if not resolved.is_relative_to(self.cwd):
            raise ValueError(f"Profile file path must stay inside {self.cwd}: {value}")
        if not resolved.exists():
            if not allow_create:
                raise ValueError(f"Profile file not found: {value}")
            resolved.parent.mkdir(parents=True, exist_ok=True)
        if resolved.exists() and not resolved.is_file():
            raise ValueError(f"Profile file is not a file: {value}")
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


def _write_profile_file(path: Path, profiles: tuple[SearchProfile, ...]) -> None:
    payload = {"profiles": [profile.to_dict() for profile in profiles]}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


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
            if path == "/api/profiles":
                self._require_token()
                self._send_json(
                    200,
                    self._runner().list_profiles(
                        _query_string(query, "profile_file", default=""),
                    ),
                )
                return
            if path == "/api/tools":
                self._require_token()
                self._send_json(
                    200,
                    self._runner().profile_tools(
                        profile=_query_string(query, "profile", default="all-safe"),
                        profile_file=_query_string(query, "profile_file", default=""),
                        view=_query_string(query, "view", default="doctor"),
                        output_format=_query_string(query, "format", default="markdown"),
                    ),
                )
                return
            if path == "/api/cases":
                self._require_token()
                self._send_json(
                    200,
                    self._runner().list_cases(
                        _query_string(query, "case_db", default="cases.sqlite"),
                        limit=_query_int(query, "limit", default=20, minimum=1, maximum=500),
                        workflow=_query_string(query, "workflow", default=""),
                        profile=_query_string(query, "profile", default=""),
                        scope_query=_query_string(query, "scope_query", default=""),
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
            if case_id and case_route == "sources":
                self._require_token()
                self._send_json(
                    200,
                    self._runner().case_sources(
                        _query_string(query, "case_db", default="cases.sqlite"),
                        case_id,
                        output_format=_query_string(query, "format", default="markdown"),
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
        except (CaseStoreError, ValueError) as exc:
            self._send_json(400, {"error": str(exc)})

    def do_POST(self) -> None:
        try:
            self._require_token()
            path = urlparse(self.path).path
            if path == "/api/search":
                payload = self._read_json()
                job = self._runner().submit_search(payload)
                self._send_json(202, {"job": job.to_dict()})
                return
            if path == "/api/profiles/save":
                self._send_json(200, self._runner().save_profile(self._read_json()))
                return
            if path == "/api/profiles/delete":
                self._send_json(200, self._runner().delete_profile(self._read_json()))
                return
            if path == "/api/tools/install":
                self._send_json(200, self._runner().profile_tools_install(self._read_json()))
                return
            case_id, case_route = self._case_route(path)
            if case_id and case_route in {"update", "delete"}:
                payload = self._read_json()
                case_db = str(payload.get("case_db", "cases.sqlite"))
                if case_route == "update":
                    self._send_json(200, self._runner().update_case(case_db, case_id, payload))
                    return
                self._send_json(200, self._runner().delete_case(case_db, case_id, payload))
                return
            self._send_json(404, {"error": "not_found"})
        except (CaseStoreError, ValueError) as exc:
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
        if len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[3] == "sources":
            return unquote(parts[2]), "sources"
        if len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[3] == "update":
            return unquote(parts[2]), "update"
        if len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[3] == "delete":
            return unquote(parts[2]), "delete"
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
