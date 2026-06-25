from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from pathlib import Path

from .adapter_runner import run_adapter_findings
from .adapter_setup import build_adapter_setups
from .adapters import expand_adapter_repositories, filter_adapters, find_adapter, list_adapter_profiles
from .case_store import CaseStore, CaseStoreError
from .catalog import Catalog, CatalogError
from .doctor import inspect_adapters
from .engine import RunConfig, ScanTarget
from .environment import refresh_runtime_environment
from .graph import analyze_case_graph, analyze_cross_case_network, analyze_cross_case_path
from .image_runner import render_image_search_execution, run_image_search
from .investigation import (
    render_investigation_json,
    render_investigation_markdown,
    run_investigation,
    write_investigation,
)
from .output import (
    finding_source_summary,
    format_adapters,
    format_adapter_profiles,
    format_adapter_setups,
    format_case_entity_hits,
    format_case_entity_index,
    format_case_graph_analysis,
    format_cross_case_network_analysis,
    format_cross_case_path_analysis,
    format_case_delete_result,
    format_case_detail,
    format_case_source_summary,
    format_cases,
    format_findings,
    format_finding_source_summary,
    format_project_detail,
    format_projects,
    format_search_profile_detail,
    format_search_profiles,
    format_search_plan,
    format_stats,
)
from .runtime import build_default_engine
from .search import (
    TARGET_KINDS,
    SearchPlan,
    build_search_plan,
    derived_search_targets,
    find_search_profile,
    list_search_profiles,
    load_search_profiles,
    native_kinds_for_plan,
    ready_adapter_repositories,
)
from .toolbox import write_toolbox
from .tools import (
    build_profile_tool_readiness,
    build_tool_install_results,
    format_env_plan,
    format_install_plan,
    format_tool_install_results,
    format_tool_readiness,
)
from .workflows import TASK_PROFILES, recommend_projects, render_brief, render_recommendation, write_brief


def main(argv: list[str] | None = None) -> int:
    refresh_runtime_environment()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (CaseStoreError, CatalogError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osint-toolkit",
        description="Unified OSINT engine based on the curated GitHub OSINT snapshot.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    stats = subparsers.add_parser("stats", help="Show catalog statistics.")
    _add_data_dir(stats)
    stats.set_defaults(handler=handle_stats)

    catalog = subparsers.add_parser("catalog", help="Search and filter catalog entries.")
    _add_data_dir(catalog)
    catalog.add_argument("--kind", choices=("all", "people", "ru-ua", "relevant"), default="all")
    catalog.add_argument("--level", help="Filter by relation level, for example direct_tool or direct_ru_ua.")
    catalog.add_argument("--query", help="Search terms. All terms must be present in normalized project text.")
    catalog.add_argument("--min-stars", type=int, help="Minimum GitHub star count.")
    catalog.add_argument("--direct-only", action="store_true", help="Keep only direct people or direct RU/UA entries.")
    catalog.add_argument("--limit", type=int, default=20)
    catalog.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    catalog.set_defaults(handler=handle_catalog)

    show = subparsers.add_parser("show", help="Show one repository card.")
    _add_data_dir(show)
    show.add_argument("repository", help="Repository full name, for example sherlock-project/sherlock.")
    show.add_argument("--format", choices=("table", "markdown", "json"), default="table")
    show.set_defaults(handler=handle_show)

    scan = subparsers.add_parser("scan", help="Run native unified OSINT scan modules.")
    scan.add_argument("target_kind", choices=("person", "username", "email", "phone", "domain", "url", "telegram", "instagram", "social", "ru-ua"))
    scan.add_argument("target_value")
    scan.add_argument("--region", choices=("all", "ru", "ua"), default="all")
    scan.add_argument("--live", action="store_true", help="Perform network checks. Default is dry-run planning.")
    scan.add_argument("--timeout", type=float, default=10.0)
    scan.add_argument("--http-retries", type=int, default=1, help="Retry 429/temporary 5xx HTTP responses this many times.")
    scan.add_argument("--http-backoff", type=float, default=1.0, help="Base backoff seconds for HTTP retries.")
    scan.add_argument("--request-delay", type=float, default=0.0, help="Delay seconds between live username HTTP checks.")
    scan.add_argument("--crawl-pages", type=int, default=5, help="Maximum same-site pages for live URL/domain crawler.")
    scan.add_argument("--crawl-depth", type=int, default=1, help="Maximum link depth for live URL/domain crawler.")
    scan.add_argument("--person-alias", action="append", default=[], help="Known person alias/handle to include in person username expansion. Can be repeated.")
    scan.add_argument("--person-alias-file", action="append", default=[], help="UTF-8 file with one alias per line or comma-separated aliases.")
    scan.add_argument("--limit", type=int)
    scan.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    scan.set_defaults(handler=handle_scan)

    adapters = subparsers.add_parser("adapters", help="Show upstream integration/parity adapter plan.")
    adapters.add_argument("--status", choices=("partial_native", "planned", "restricted"))
    adapters.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    adapters.set_defaults(handler=handle_adapters)

    adapter_profiles = subparsers.add_parser("adapter-profiles", help="Show reusable adapter groups for investigations.")
    adapter_profiles.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    adapter_profiles.set_defaults(handler=handle_adapter_profiles)

    profiles = subparsers.add_parser("profiles", help="List, show or export unified search profiles.")
    profiles_subparsers = profiles.add_subparsers(dest="profiles_command", required=True)

    profiles_list = profiles_subparsers.add_parser("list", help="List built-in and optional custom search profiles.")
    profiles_list.add_argument("--profile-file", help="JSON file with custom search profiles.")
    profiles_list.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    profiles_list.set_defaults(handler=handle_profiles_list)

    profiles_show = profiles_subparsers.add_parser("show", help="Show one built-in or custom search profile.")
    profiles_show.add_argument("profile")
    profiles_show.add_argument("--profile-file", help="JSON file with custom search profiles.")
    profiles_show.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    profiles_show.set_defaults(handler=handle_profiles_show)

    profiles_export = profiles_subparsers.add_parser("export", help="Export one search profile as reusable JSON.")
    profiles_export.add_argument("profile")
    profiles_export.add_argument("--profile-file", help="JSON file with custom search profiles.")
    profiles_export.add_argument("--out", required=True, help="Output JSON path.")
    profiles_export.set_defaults(handler=handle_profiles_export)

    doctor = subparsers.add_parser("doctor", help="Check local readiness of configured upstream adapters.")
    doctor.add_argument("--status", choices=("partial_native", "planned", "restricted"))
    doctor.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    doctor.set_defaults(handler=handle_doctor)

    tools = subparsers.add_parser("tools", help="Profile-level readiness, install and environment helpers.")
    tools_subparsers = tools.add_subparsers(dest="tools_command", required=True)

    tools_doctor = tools_subparsers.add_parser("doctor", help="Check readiness for all tools in a search profile.")
    tools_doctor.add_argument("--profile", required=True)
    tools_doctor.add_argument("--profile-file", help="JSON file with custom search profiles.")
    tools_doctor.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    tools_doctor.set_defaults(handler=handle_tools_doctor)

    tools_install = tools_subparsers.add_parser("install-plan", help="Show install/config actions for a search profile.")
    tools_install.add_argument("--profile", required=True)
    tools_install.add_argument("--profile-file", help="JSON file with custom search profiles.")
    tools_install.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    tools_install.set_defaults(handler=handle_tools_install_plan)

    tools_install_run = tools_subparsers.add_parser("install", help="Install missing allowlisted tools for a search profile.")
    tools_install_run.add_argument("profile")
    tools_install_run.add_argument("--profile-file", help="JSON file with custom search profiles.")
    tools_install_run.add_argument("--execute", action="store_true", help="Actually run allowlisted install commands. Default is dry-run.")
    tools_install_run.add_argument("--timeout", type=float, default=300.0)
    tools_install_run.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    tools_install_run.set_defaults(handler=handle_tools_install)

    tools_env = tools_subparsers.add_parser("env", help="Show required and optional env variable names for a search profile.")
    tools_env.add_argument("--profile", required=True)
    tools_env.add_argument("--profile-file", help="JSON file with custom search profiles.")
    tools_env.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    tools_env.set_defaults(handler=handle_tools_env)

    adapter_setup = subparsers.add_parser("adapter-setup", help="Show install/config plan for upstream adapters.")
    adapter_setup.add_argument("repository", nargs="?", help="Adapter repository, for example sherlock-project/sherlock.")
    adapter_setup.add_argument("--status", choices=("partial_native", "planned", "restricted"))
    adapter_setup.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    adapter_setup.set_defaults(handler=handle_adapter_setup)

    run = subparsers.add_parser("run-adapter", help="Dry-run or execute one configured upstream adapter.")
    run.add_argument("repository", help="Adapter repository, for example sherlock-project/sherlock.")
    run.add_argument("target_kind", choices=("username", "email", "phone", "domain", "url", "telegram", "instagram", "ru-ua"))
    run.add_argument("target_value")
    run.add_argument("--region", choices=("all", "ru", "ua"), default="all")
    run.add_argument("--execute", action="store_true", help="Actually run the external command. Default is dry-run.")
    run.add_argument("--allow-restricted", action="store_true", help="Allow restricted adapters after scope review.")
    run.add_argument("--timeout", type=float, default=60.0)
    run.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    run.set_defaults(handler=handle_run_adapter)

    recommend = subparsers.add_parser("recommend", help="Recommend a safe workflow and relevant catalog entries.")
    _add_data_dir(recommend)
    recommend.add_argument("task", choices=sorted(TASK_PROFILES))
    recommend.add_argument("--region", choices=("all", "ru", "ua"), default="all")
    recommend.add_argument("--limit", type=int, default=10)
    recommend.set_defaults(handler=handle_recommend)

    brief = subparsers.add_parser("brief", help="Write a Markdown investigation brief.")
    _add_data_dir(brief)
    brief.add_argument("--task", choices=sorted(TASK_PROFILES), required=True)
    brief.add_argument("--region", choices=("all", "ru", "ua"), default="all")
    brief.add_argument("--target-value", default="", help="Seed value to record in the brief. No lookup is performed.")
    brief.add_argument("--limit", type=int, default=10)
    brief.add_argument("--out", required=True, help="Output Markdown path.")
    brief.set_defaults(handler=handle_brief)

    toolbox = subparsers.add_parser("toolbox", help="Generate a local one-window OSINT toolbox.")
    toolbox.add_argument("--out", default="osint_toolbox.html", help="Output HTML path.")
    toolbox.add_argument("--open", action="store_true", help="Open the generated HTML file in the default browser.")
    toolbox.add_argument("--serve", action="store_true", help="Run a local backend so the toolbox can execute unified search jobs.")
    toolbox.add_argument("--host", default="127.0.0.1", help="Toolbox backend host for --serve.")
    toolbox.add_argument("--port", type=int, default=8765, help="Toolbox backend port for --serve.")
    toolbox.set_defaults(handler=handle_toolbox)

    search = subparsers.add_parser("search", help="Build a unified fan-out search plan for one OSINT seed.")
    search.add_argument("target_kind", choices=("auto", *TARGET_KINDS))
    search.add_argument("target_value")
    search.add_argument("--profile", default="auto")
    search.add_argument("--profile-file", help="JSON file with custom search profiles.")
    search.add_argument("--plan-only", action="store_true", help="Only show the fan-out plan. No tools are executed.")
    search.add_argument("--execute-adapters", action="store_true", help="Execute ready non-restricted external adapters from the search plan.")
    search.add_argument("--install-missing", action="store_true", help="Show or install missing allowlisted tools for the resolved search profile.")
    search.add_argument("--execute-install", action="store_true", help="Actually run allowlisted install commands with --install-missing. Default is dry-run.")
    search.add_argument("--include-restricted", action="store_true", help="Include restricted tools in the plan with explicit markings.")
    search.add_argument("--region", choices=("all", "ru", "ua"), default="all")
    search.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    search.add_argument("--out", help="Write execution report to this path.")
    search.add_argument("--case-db", help="SQLite database path for saving execution results.")
    search.add_argument("--case-id", help="Optional stable case id when --case-db is used.")
    search.add_argument("--scope-note", default="", help="Scope/context note saved in case metadata when --case-db is used.")
    search.add_argument("--timeout", type=float, default=10.0)
    search.add_argument("--adapter-timeout", type=float, default=60.0)
    search.add_argument("--install-timeout", type=float, default=300.0)
    search.add_argument("--adapter-limit", type=int, default=20)
    search.add_argument("--derived-limit", type=int, default=20, help="Maximum image-derived seeds to route into normal search.")
    search.set_defaults(handler=handle_search)

    investigate = subparsers.add_parser("investigate", help="Run a multi-target OSINT case through native modules.")
    investigate.add_argument("--title", default="OSINT investigation")
    investigate.add_argument("--person", action="append", default=[], help="Person name to expand into username candidates.")
    investigate.add_argument("--username", action="append", default=[])
    investigate.add_argument("--email", action="append", default=[])
    investigate.add_argument("--phone", action="append", default=[])
    investigate.add_argument("--domain", action="append", default=[])
    investigate.add_argument("--url", action="append", default=[])
    investigate.add_argument("--telegram", action="append", default=[])
    investigate.add_argument("--instagram", action="append", default=[])
    investigate.add_argument("--social", action="append", default=[])
    investigate.add_argument("--ru-ua", action="append", default=[])
    investigate.add_argument("--region", choices=("all", "ru", "ua"), default="all")
    investigate.add_argument("--live", action="store_true", help="Perform live checks for native modules.")
    investigate.add_argument("--include-adapters", action="store_true", help="Add adapter dry-run commands.")
    investigate.add_argument("--adapter-profile", action="append", default=[], help="Use a reusable adapter profile. Can be repeated.")
    investigate.add_argument("--adapter", action="append", default=[], help="Restrict investigation adapters to this repository. Can be repeated.")
    investigate.add_argument("--execute-adapters", action="store_true", help="Execute configured upstream adapters. Requires --include-adapters.")
    investigate.add_argument("--allow-restricted-adapters", action="store_true", help="Allow restricted adapters during --execute-adapters after scope review.")
    investigate.add_argument("--adapter-timeout", type=float, default=60.0)
    investigate.add_argument("--adapter-limit", type=int, default=20)
    investigate.add_argument("--timeout", type=float, default=10.0)
    investigate.add_argument("--http-retries", type=int, default=1, help="Retry 429/temporary 5xx HTTP responses this many times.")
    investigate.add_argument("--http-backoff", type=float, default=1.0, help="Base backoff seconds for HTTP retries.")
    investigate.add_argument("--request-delay", type=float, default=0.0, help="Delay seconds between live username HTTP checks.")
    investigate.add_argument("--crawl-pages", type=int, default=5, help="Maximum same-site pages for live URL/domain crawler.")
    investigate.add_argument("--crawl-depth", type=int, default=1, help="Maximum link depth for live URL/domain crawler.")
    investigate.add_argument("--person-alias", action="append", default=[], help="Known person alias/handle to include in person username expansion. Can be repeated.")
    investigate.add_argument("--person-alias-file", action="append", default=[], help="UTF-8 file with one alias per line or comma-separated aliases.")
    investigate.add_argument("--format", choices=("markdown", "json"), default="markdown")
    investigate.add_argument("--out", help="Write investigation report to this path.")
    investigate.add_argument("--case-db", help="SQLite database path for saving the case.")
    investigate.add_argument("--case-id", help="Optional stable case id when --case-db is used.")
    investigate.add_argument("--scope-note", default="", help="Scope/context note saved in case metadata when --case-db is used.")
    investigate.set_defaults(handler=handle_investigate)

    cases = subparsers.add_parser("cases", help="List saved investigation cases.")
    cases.add_argument("--case-db", required=True, help="SQLite database path.")
    cases.add_argument("--limit", type=int, default=20)
    cases.add_argument("--workflow", default="", help="Filter by saved workflow metadata, for example search.")
    cases.add_argument("--profile", default="", help="Filter by requested/search profile metadata.")
    cases.add_argument("--scope-query", default="", help="Case-insensitive substring filter over scope_note metadata.")
    cases.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    cases.set_defaults(handler=handle_cases)

    case_show = subparsers.add_parser("case-show", help="Show one saved investigation case.")
    case_show.add_argument("--case-db", required=True, help="SQLite database path.")
    case_show.add_argument("case_id")
    case_show.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="json")
    case_show.set_defaults(handler=handle_case_show)

    case_sources = subparsers.add_parser("case-sources", help="Summarize finding sources for one saved case.")
    case_sources.add_argument("--case-db", required=True, help="SQLite database path.")
    case_sources.add_argument("case_id")
    case_sources.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    case_sources.set_defaults(handler=handle_case_sources)

    case_update = subparsers.add_parser("case-update", help="Update safe metadata for one saved case.")
    case_update.add_argument("--case-db", required=True, help="SQLite database path.")
    case_update.add_argument("case_id")
    case_update.add_argument("--title", help="Replace the case title.")
    case_update.add_argument("--scope-note", help="Replace or add scope_note metadata.")
    case_update.add_argument("--format", choices=("table", "markdown", "json"), default="markdown")
    case_update.set_defaults(handler=handle_case_update)

    case_delete = subparsers.add_parser("case-delete", help="Delete one saved case from SQLite.")
    case_delete.add_argument("--case-db", required=True, help="SQLite database path.")
    case_delete.add_argument("case_id")
    case_delete.add_argument("--yes", action="store_true", help="Required confirmation for deletion.")
    case_delete.add_argument("--format", choices=("table", "json"), default="table")
    case_delete.set_defaults(handler=handle_case_delete)

    case_graph = subparsers.add_parser("case-graph", help="Analyze graph edges for one saved investigation case.")
    case_graph.add_argument("--case-db", required=True, help="SQLite database path.")
    case_graph.add_argument("case_id")
    case_graph.add_argument("--entity-kind", default="", help="Optional focus entity kind, for example email.")
    case_graph.add_argument("--entity-value", default="", help="Optional focus entity value, for example person@example.com.")
    case_graph.add_argument("--limit", type=int, default=10)
    case_graph.add_argument("--format", choices=("table", "markdown", "json"), default="table")
    case_graph.set_defaults(handler=handle_case_graph)

    case_index = subparsers.add_parser("case-index", help="Index and search entities across saved cases.")
    case_index.add_argument("--case-db", required=True, help="SQLite database path.")
    case_index.add_argument("--kind", default="", help="Optional entity kind filter, for example email or domain.")
    case_index.add_argument("--value", default="", help="Exact entity value to find saved cases.")
    case_index.add_argument("--min-cases", type=int, default=1)
    case_index.add_argument("--limit", type=int, default=50)
    case_index.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    case_index.set_defaults(handler=handle_case_index)

    case_path = subparsers.add_parser("case-path", help="Find a weighted path across saved case graphs.")
    case_path.add_argument("--case-db", required=True, help="SQLite database path.")
    case_path.add_argument("--from-kind", required=True, help="Source entity kind, for example email.")
    case_path.add_argument("--from-value", required=True, help="Source entity value, for example person@example.com.")
    case_path.add_argument("--to-kind", required=True, help="Target entity kind, for example url.")
    case_path.add_argument("--to-value", required=True, help="Target entity value.")
    case_path.add_argument("--case-limit", type=int, default=100)
    case_path.add_argument("--max-depth", type=int, default=6)
    case_path.add_argument("--format", choices=("table", "markdown", "json"), default="table")
    case_path.set_defaults(handler=handle_case_path)

    case_network = subparsers.add_parser("case-network", help="Show a bounded cross-case entity graph.")
    case_network.add_argument("--case-db", required=True, help="SQLite database path.")
    case_network.add_argument("--kind", default="", help="Optional entity kind neighborhood filter.")
    case_network.add_argument("--relation", default="", help="Optional relation filter.")
    case_network.add_argument("--case-limit", type=int, default=100)
    case_network.add_argument("--node-limit", type=int, default=60)
    case_network.add_argument("--edge-limit", type=int, default=120)
    case_network.add_argument("--min-degree", type=int, default=1)
    case_network.add_argument("--format", choices=("table", "markdown", "json"), default="table")
    case_network.set_defaults(handler=handle_case_network)

    return parser


def handle_stats(args: argparse.Namespace) -> int:
    catalog = _load(args)
    print(format_stats(catalog.stats()))
    return 0


def handle_catalog(args: argparse.Namespace) -> int:
    catalog = _load(args)
    projects = catalog.filter(
        kind=args.kind,
        level=args.level,
        query=args.query,
        min_stars=args.min_stars,
        direct_only=args.direct_only,
        limit=args.limit,
    )
    print(format_projects(projects, output_format=args.format, kind=args.kind))
    return 0


def handle_show(args: argparse.Namespace) -> int:
    catalog = _load(args)
    print(format_project_detail(catalog.get(args.repository), output_format=args.format))
    return 0


def handle_scan(args: argparse.Namespace) -> int:
    engine = build_default_engine()
    target = ScanTarget(kind=args.target_kind, value=args.target_value, region=args.region)
    config = RunConfig(
        live=args.live,
        timeout=args.timeout,
        limit=args.limit,
        http_retries=args.http_retries,
        http_backoff=args.http_backoff,
        request_delay=args.request_delay,
        crawl_pages=args.crawl_pages,
        crawl_depth=args.crawl_depth,
        person_aliases=_person_aliases_from_args(args),
    )
    findings = engine.scan(target, config)
    print(format_findings(findings, output_format=args.format))
    return 0


def handle_adapters(args: argparse.Namespace) -> int:
    print(format_adapters(filter_adapters(args.status), output_format=args.format))
    return 0


def handle_adapter_profiles(args: argparse.Namespace) -> int:
    print(format_adapter_profiles(list_adapter_profiles(), output_format=args.format))
    return 0


def handle_profiles_list(args: argparse.Namespace) -> int:
    custom_profiles = load_search_profiles(args.profile_file)
    print(format_search_profiles(list_search_profiles(custom_profiles), output_format=args.format))
    return 0


def handle_profiles_show(args: argparse.Namespace) -> int:
    custom_profiles = load_search_profiles(args.profile_file)
    profile = find_search_profile(args.profile, custom_profiles=custom_profiles)
    print(format_search_profile_detail(profile, output_format=args.format))
    return 0


def handle_profiles_export(args: argparse.Namespace) -> int:
    custom_profiles = load_search_profiles(args.profile_file)
    profile = find_search_profile(args.profile, custom_profiles=custom_profiles)
    path = Path(args.out)
    if path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"profiles": [profile.to_dict()]}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {path}")
    return 0


def handle_doctor(args: argparse.Namespace) -> int:
    print(format_findings(inspect_adapters(args.status), output_format=args.format))
    return 0


def handle_tools_doctor(args: argparse.Namespace) -> int:
    custom_profiles = load_search_profiles(args.profile_file)
    rows = build_profile_tool_readiness(args.profile, custom_profiles=custom_profiles)
    print(format_tool_readiness(rows, output_format=args.format))
    return 0


def handle_tools_install_plan(args: argparse.Namespace) -> int:
    custom_profiles = load_search_profiles(args.profile_file)
    rows = build_profile_tool_readiness(args.profile, custom_profiles=custom_profiles)
    print(format_install_plan(rows, output_format=args.format))
    return 0


def handle_tools_install(args: argparse.Namespace) -> int:
    custom_profiles = load_search_profiles(args.profile_file)
    rows = build_profile_tool_readiness(args.profile, custom_profiles=custom_profiles)
    results = build_tool_install_results(rows, execute=args.execute, timeout=args.timeout)
    print(format_tool_install_results(results, output_format=args.format))
    if args.execute and any(result.status == "failed" for result in results):
        return 1
    return 0


def handle_tools_env(args: argparse.Namespace) -> int:
    custom_profiles = load_search_profiles(args.profile_file)
    rows = build_profile_tool_readiness(args.profile, custom_profiles=custom_profiles)
    print(format_env_plan(rows, output_format=args.format))
    return 0


def handle_adapter_setup(args: argparse.Namespace) -> int:
    if args.repository:
        adapters = (find_adapter(args.repository),)
    else:
        adapters = filter_adapters(args.status)
    print(format_adapter_setups(build_adapter_setups(adapters), output_format=args.format))
    return 0


def handle_run_adapter(args: argparse.Namespace) -> int:
    target = ScanTarget(kind=args.target_kind, value=args.target_value, region=args.region)
    findings = run_adapter_findings(
        args.repository,
        target,
        execute=args.execute,
        allow_restricted=args.allow_restricted,
        timeout=args.timeout,
    )
    print(format_findings(findings, output_format=args.format))
    return 0


def handle_recommend(args: argparse.Namespace) -> int:
    catalog = _load(args)
    profile, projects = recommend_projects(catalog, args.task, region=args.region, limit=args.limit)
    print(render_recommendation(profile, projects, region=args.region))
    return 0


def handle_brief(args: argparse.Namespace) -> int:
    catalog = _load(args)
    profile, projects = recommend_projects(catalog, args.task, region=args.region, limit=args.limit)
    content = render_brief(profile, projects, target_value=args.target_value, region=args.region)
    path = write_brief(args.out, content)
    print(f"Wrote {path}")
    return 0


def handle_toolbox(args: argparse.Namespace) -> int:
    if args.serve:
        from .toolbox_server import run_toolbox_server

        return run_toolbox_server(
            host=args.host,
            port=args.port,
            out=args.out,
            open_browser=args.open,
        )
    path = write_toolbox(args.out).resolve()
    print(f"Wrote toolbox {path}")
    if args.open:
        webbrowser.open(path.as_uri())
    return 0


def handle_search(args: argparse.Namespace) -> int:
    custom_profiles = load_search_profiles(args.profile_file)
    plan = build_search_plan(
        args.target_kind,
        args.target_value,
        profile_name=args.profile,
        region=args.region,
        include_restricted=args.include_restricted,
        custom_profiles=custom_profiles,
    )
    selected_modes = sum(bool(value) for value in (args.plan_only, args.execute_adapters, args.install_missing))
    if selected_modes > 1:
        raise ValueError("--plan-only, --execute-adapters and --install-missing are mutually exclusive.")
    if args.execute_install and not args.install_missing:
        raise ValueError("--execute-install requires --install-missing.")
    if args.install_missing:
        rows = build_profile_tool_readiness(plan.profile.name, custom_profiles=custom_profiles)
        results = build_tool_install_results(rows, execute=args.execute_install, timeout=args.install_timeout)
        print(format_tool_install_results(results, output_format=args.format))
        if args.execute_install and any(result.status == "failed" for result in results):
            return 1
        return 0
    if not args.execute_adapters:
        print(format_search_plan(plan, output_format=args.format))
        return 0
    if args.case_id and not args.case_db:
        raise ValueError("--case-id requires --case-db.")
    if plan.target.kind == "image":
        execution = run_image_search(
            plan,
            timeout=args.timeout,
            adapter_timeout=args.adapter_timeout,
            adapter_limit=args.adapter_limit,
            derived_limit=args.derived_limit,
        )
        content = render_image_search_execution(plan, execution, output_format=args.format)
        saved_message = ""
        if args.case_db:
            case_id = CaseStore(args.case_db).save(
                execution.investigation,
                case_id=args.case_id,
                metadata=_search_case_metadata(
                    plan,
                    args,
                    executed_adapters=execution.executed_adapters,
                    executed_local_tools=execution.executed_local_tools,
                    derived_targets=execution.derived_targets,
                ),
            )
            saved_message = f"Saved case {case_id} to {args.case_db}"
        if args.out:
            path = write_investigation(args.out, content)
            print(f"Wrote {path}")
        else:
            print(content)
        if saved_message:
            if args.out:
                print(saved_message)
            else:
                print(saved_message, file=sys.stderr)
        return 0
    executable_adapters = ready_adapter_repositories(plan, limit=args.adapter_limit)
    derived_targets = derived_search_targets(plan)
    result = run_investigation(
        (plan.target, *derived_targets),
        title=f"Unified search: {plan.target.kind}:{plan.target.value}",
        live=False,
        timeout=args.timeout,
        include_adapters=bool(executable_adapters),
        execute_adapters=bool(executable_adapters),
        allow_restricted_adapters=False,
        adapter_timeout=args.adapter_timeout,
        adapter_limit=args.adapter_limit,
        adapter_repositories=executable_adapters,
        native_kinds=native_kinds_for_plan(plan),
    )
    content = _render_search_execution(
        plan,
        result,
        executable_adapters,
        derived_targets=derived_targets,
        output_format=args.format,
    )
    saved_message = ""
    if args.case_db:
        case_id = CaseStore(args.case_db).save(
            result,
            case_id=args.case_id,
            metadata=_search_case_metadata(
                plan,
                args,
                executed_adapters=executable_adapters,
                derived_targets=derived_targets,
            ),
        )
        saved_message = f"Saved case {case_id} to {args.case_db}"
    if args.out:
        path = write_investigation(args.out, content)
        print(f"Wrote {path}")
    else:
        print(content)
    if saved_message:
        if args.out:
            print(saved_message)
        else:
            print(saved_message, file=sys.stderr)
    return 0


def _render_search_execution(
    plan: SearchPlan,
    result,
    executable_adapters: tuple[str, ...],
    *,
    derived_targets: tuple[ScanTarget, ...] = (),
    output_format: str,
) -> str:
    if output_format == "json":
        return json.dumps(
            {
                "search_plan": plan.to_dict(),
                "derived_targets": [
                    {"kind": target.kind, "value": target.value, "region": target.region}
                    for target in derived_targets
                ],
                "executed_adapters": list(executable_adapters),
                "source_summary": list(finding_source_summary(result.all_findings())),
                "investigation": result.to_dict(),
            },
            ensure_ascii=False,
            indent=2,
        )
    plan_markdown = format_search_plan(plan, output_format="markdown")
    investigation_markdown = render_investigation_markdown(result)
    adapter_lines = "\n".join(f"- `{repository}`" for repository in executable_adapters) or "- none"
    derived_lines = "\n".join(f"- `{target.kind}:{target.value}`" for target in derived_targets) or "- none"
    source_summary = format_finding_source_summary(
        result.all_findings(),
        title=_source_summary_title(plan.target.kind),
    )
    return "\n".join(
        [
            f"# Search Execution Report: {plan.target.kind}",
            "",
            f"- Target: `{plan.target.value}`",
            f"- Profile: `{plan.profile.name}`",
            "- Restricted execution: disabled",
            "",
            "## Derived Targets",
            "",
            derived_lines,
            "",
            "## Executed Adapters",
            "",
            adapter_lines,
            "",
            source_summary,
            "",
            "## Fan-out Plan",
            "",
            plan_markdown,
            "",
            "## Investigation Report",
            "",
            investigation_markdown.strip(),
            "",
        ]
    )


def _source_summary_title(target_kind: str) -> str:
    if target_kind == "phone":
        return "Phone Sources"
    if target_kind == "email":
        return "Email Sources"
    if target_kind == "image":
        return "Image Sources"
    if target_kind in {"domain", "url"}:
        return "Web Sources"
    return "Source Summary"


def _search_case_metadata(
    plan: SearchPlan,
    args: argparse.Namespace,
    *,
    executed_adapters: tuple[str, ...],
    executed_local_tools: tuple[str, ...] = (),
    derived_targets: tuple[ScanTarget, ...] = (),
) -> dict[str, object]:
    return {
        "workflow": "search",
        "target_kind": plan.target.kind,
        "target_region": plan.target.region,
        "requested_profile": args.profile,
        "profile_file": args.profile_file or "",
        "scope_note": args.scope_note,
        "search_profile": plan.profile.to_dict(),
        "include_restricted": bool(args.include_restricted),
        "execute_adapters": bool(args.execute_adapters),
        "executed_adapters": list(executed_adapters),
        "executed_local_tools": list(executed_local_tools),
        "derived_targets": [
            {"kind": target.kind, "value": target.value, "region": target.region}
            for target in derived_targets
        ],
        "timeout": args.timeout,
        "adapter_timeout": args.adapter_timeout,
        "adapter_limit": args.adapter_limit,
    }


def handle_investigate(args: argparse.Namespace) -> int:
    targets = _targets_from_args(args)
    if not targets:
        raise ValueError("At least one investigation seed is required.")
    if args.case_id and not args.case_db:
        raise ValueError("--case-id requires --case-db.")
    if args.adapter_profile and not args.include_adapters:
        raise ValueError("--adapter-profile requires --include-adapters.")
    if args.adapter and not args.include_adapters:
        raise ValueError("--adapter requires --include-adapters.")
    if args.execute_adapters and not args.include_adapters:
        raise ValueError("--execute-adapters requires --include-adapters.")
    if args.allow_restricted_adapters and not args.execute_adapters:
        raise ValueError("--allow-restricted-adapters requires --execute-adapters.")
    adapter_repositories = expand_adapter_repositories(
        tuple(args.adapter_profile),
        tuple(args.adapter),
    )
    result = run_investigation(
        targets,
        title=args.title,
        live=args.live,
        timeout=args.timeout,
        include_adapters=args.include_adapters,
        execute_adapters=args.execute_adapters,
        allow_restricted_adapters=args.allow_restricted_adapters,
        adapter_timeout=args.adapter_timeout,
        adapter_limit=args.adapter_limit,
        http_retries=args.http_retries,
        http_backoff=args.http_backoff,
        request_delay=args.request_delay,
        crawl_pages=args.crawl_pages,
        crawl_depth=args.crawl_depth,
        person_aliases=_person_aliases_from_args(args),
        adapter_repositories=adapter_repositories,
    )
    content = (
        render_investigation_json(result)
        if args.format == "json"
        else render_investigation_markdown(result)
    )
    saved_message = ""
    if args.case_db:
        case_id = CaseStore(args.case_db).save(
            result,
            case_id=args.case_id,
            metadata=_investigation_case_metadata(args, adapter_repositories),
        )
        saved_message = f"Saved case {case_id} to {args.case_db}"
    if args.out:
        path = write_investigation(args.out, content)
        print(f"Wrote {path}")
    else:
        print(content)
    if saved_message:
        if args.out:
            print(saved_message)
        else:
            print(saved_message, file=sys.stderr)
    return 0


def _investigation_case_metadata(
    args: argparse.Namespace,
    adapter_repositories: tuple[str, ...],
) -> dict[str, object]:
    return {
        "workflow": "investigate",
        "live": bool(args.live),
        "include_adapters": bool(args.include_adapters),
        "execute_adapters": bool(args.execute_adapters),
        "allow_restricted_adapters": bool(args.allow_restricted_adapters),
        "scope_note": args.scope_note,
        "adapter_profiles": list(args.adapter_profile),
        "adapter_repositories": list(args.adapter),
        "expanded_adapter_repositories": list(adapter_repositories),
        "adapter_timeout": args.adapter_timeout,
        "adapter_limit": args.adapter_limit,
        "timeout": args.timeout,
    }


def handle_cases(args: argparse.Namespace) -> int:
    records = CaseStore(args.case_db).list_cases(
        limit=args.limit,
        workflow=args.workflow,
        profile=args.profile,
        scope_query=args.scope_query,
    )
    print(format_cases(records, output_format=args.format))
    return 0


def handle_case_show(args: argparse.Namespace) -> int:
    payload = CaseStore(args.case_db).load_case(args.case_id)
    print(format_case_detail(payload, output_format=args.format))
    return 0


def handle_case_sources(args: argparse.Namespace) -> int:
    payload = CaseStore(args.case_db).load_case(args.case_id)
    print(format_case_source_summary(payload, output_format=args.format))
    return 0


def handle_case_update(args: argparse.Namespace) -> int:
    metadata_updates: dict[str, object] = {}
    if args.scope_note is not None:
        metadata_updates["scope_note"] = args.scope_note
    payload = CaseStore(args.case_db).update_case(
        args.case_id,
        title=args.title,
        metadata_updates=metadata_updates,
    )
    print(format_case_detail(payload, output_format=args.format))
    return 0


def handle_case_delete(args: argparse.Namespace) -> int:
    if not args.yes:
        raise ValueError("case-delete requires --yes.")
    case_id = CaseStore(args.case_db).delete_case(args.case_id)
    print(format_case_delete_result(case_id, output_format=args.format))
    return 0


def handle_case_graph(args: argparse.Namespace) -> int:
    payload = CaseStore(args.case_db).load_case(args.case_id)
    analysis = analyze_case_graph(
        payload,
        focus_kind=args.entity_kind,
        focus_value=args.entity_value,
        limit=args.limit,
    )
    print(format_case_graph_analysis(analysis, output_format=args.format))
    return 0


def handle_case_index(args: argparse.Namespace) -> int:
    store = CaseStore(args.case_db)
    if args.value:
        if not args.kind:
            raise ValueError("--value requires --kind.")
        hits = store.find_cases_by_entity(kind=args.kind, value=args.value)
        print(format_case_entity_hits(hits, output_format=args.format))
        return 0
    records = store.list_entity_index(kind=args.kind, min_cases=args.min_cases, limit=args.limit)
    print(format_case_entity_index(records, output_format=args.format))
    return 0


def handle_case_path(args: argparse.Namespace) -> int:
    store = CaseStore(args.case_db)
    analysis = analyze_cross_case_path(
        store.load_cases(limit=args.case_limit),
        source_kind=args.from_kind,
        source_value=args.from_value,
        target_kind=args.to_kind,
        target_value=args.to_value,
        max_depth=args.max_depth,
    )
    print(format_cross_case_path_analysis(analysis, output_format=args.format))
    return 0


def handle_case_network(args: argparse.Namespace) -> int:
    store = CaseStore(args.case_db)
    analysis = analyze_cross_case_network(
        store.load_cases(limit=args.case_limit),
        kind_filter=args.kind,
        relation_filter=args.relation,
        min_degree=args.min_degree,
        node_limit=args.node_limit,
        edge_limit=args.edge_limit,
    )
    print(format_cross_case_network_analysis(analysis, output_format=args.format))
    return 0


def _add_data_dir(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--data-dir", help="Directory with the OSINT snapshot CSV files.")


def _load(args: argparse.Namespace) -> Catalog:
    return Catalog.load(args.data_dir)


def _person_aliases_from_args(args: argparse.Namespace) -> tuple[str, ...]:
    aliases: list[str] = []
    aliases.extend(getattr(args, "person_alias", ()))
    for path in getattr(args, "person_alias_file", ()):
        aliases.extend(_read_person_alias_file(path))

    seen: set[str] = set()
    deduped: list[str] = []
    for alias in aliases:
        normalized = alias.strip()
        key = normalized.casefold()
        if normalized and key not in seen:
            seen.add(key)
            deduped.append(normalized)
    return tuple(deduped)


def _read_person_alias_file(path: str) -> tuple[str, ...]:
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ValueError(f"Could not read person alias file {path}: {exc}") from exc

    aliases: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        aliases.extend(part.strip() for part in stripped.split(",") if part.strip())
    return tuple(aliases)


def _targets_from_args(args: argparse.Namespace) -> tuple[ScanTarget, ...]:
    targets: list[ScanTarget] = []
    for kind in ("person", "username", "email", "phone", "domain", "url", "telegram", "instagram", "social"):
        for value in getattr(args, kind):
            targets.append(ScanTarget(kind=kind, value=value, region=args.region))
    for value in getattr(args, "ru_ua"):
        targets.append(ScanTarget(kind="ru-ua", value=value, region=args.region))
    return tuple(targets)


if __name__ == "__main__":
    raise SystemExit(main())
