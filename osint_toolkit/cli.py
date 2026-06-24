from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .adapter_runner import run_adapter_findings
from .adapter_setup import build_adapter_setups
from .adapters import expand_adapter_repositories, filter_adapters, find_adapter, list_adapter_profiles
from .case_store import CaseStore, CaseStoreError
from .catalog import Catalog, CatalogError
from .doctor import inspect_adapters
from .engine import RunConfig, ScanTarget
from .graph import analyze_case_graph
from .investigation import (
    render_investigation_json,
    render_investigation_markdown,
    run_investigation,
    write_investigation,
)
from .output import (
    format_adapters,
    format_adapter_profiles,
    format_adapter_setups,
    format_case_entity_hits,
    format_case_entity_index,
    format_case_graph_analysis,
    format_case_detail,
    format_cases,
    format_findings,
    format_project_detail,
    format_projects,
    format_stats,
)
from .runtime import build_default_engine
from .workflows import TASK_PROFILES, recommend_projects, render_brief, render_recommendation, write_brief


def main(argv: list[str] | None = None) -> int:
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
    scan.add_argument("target_kind", choices=("person", "username", "email", "phone", "domain", "url", "telegram", "ru-ua"))
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

    doctor = subparsers.add_parser("doctor", help="Check local readiness of configured upstream adapters.")
    doctor.add_argument("--status", choices=("partial_native", "planned", "restricted"))
    doctor.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    doctor.set_defaults(handler=handle_doctor)

    adapter_setup = subparsers.add_parser("adapter-setup", help="Show install/config plan for upstream adapters.")
    adapter_setup.add_argument("repository", nargs="?", help="Adapter repository, for example sherlock-project/sherlock.")
    adapter_setup.add_argument("--status", choices=("partial_native", "planned", "restricted"))
    adapter_setup.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    adapter_setup.set_defaults(handler=handle_adapter_setup)

    run = subparsers.add_parser("run-adapter", help="Dry-run or execute one configured upstream adapter.")
    run.add_argument("repository", help="Adapter repository, for example sherlock-project/sherlock.")
    run.add_argument("target_kind", choices=("username", "email", "phone", "domain", "url", "telegram", "ru-ua"))
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

    investigate = subparsers.add_parser("investigate", help="Run a multi-target OSINT case through native modules.")
    investigate.add_argument("--title", default="OSINT investigation")
    investigate.add_argument("--person", action="append", default=[], help="Person name to expand into username candidates.")
    investigate.add_argument("--username", action="append", default=[])
    investigate.add_argument("--email", action="append", default=[])
    investigate.add_argument("--phone", action="append", default=[])
    investigate.add_argument("--domain", action="append", default=[])
    investigate.add_argument("--url", action="append", default=[])
    investigate.add_argument("--telegram", action="append", default=[])
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
    investigate.set_defaults(handler=handle_investigate)

    cases = subparsers.add_parser("cases", help="List saved investigation cases.")
    cases.add_argument("--case-db", required=True, help="SQLite database path.")
    cases.add_argument("--limit", type=int, default=20)
    cases.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    cases.set_defaults(handler=handle_cases)

    case_show = subparsers.add_parser("case-show", help="Show one saved investigation case.")
    case_show.add_argument("--case-db", required=True, help="SQLite database path.")
    case_show.add_argument("case_id")
    case_show.add_argument("--format", choices=("table", "markdown", "json"), default="json")
    case_show.set_defaults(handler=handle_case_show)

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


def handle_doctor(args: argparse.Namespace) -> int:
    print(format_findings(inspect_adapters(args.status), output_format=args.format))
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
        adapter_repositories=expand_adapter_repositories(
            tuple(args.adapter_profile),
            tuple(args.adapter),
        ),
    )
    content = (
        render_investigation_json(result)
        if args.format == "json"
        else render_investigation_markdown(result)
    )
    saved_message = ""
    if args.case_db:
        case_id = CaseStore(args.case_db).save(result, case_id=args.case_id)
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


def handle_cases(args: argparse.Namespace) -> int:
    records = CaseStore(args.case_db).list_cases(limit=args.limit)
    print(format_cases(records, output_format=args.format))
    return 0


def handle_case_show(args: argparse.Namespace) -> int:
    payload = CaseStore(args.case_db).load_case(args.case_id)
    print(format_case_detail(payload, output_format=args.format))
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
    for kind in ("person", "username", "email", "phone", "domain", "url", "telegram"):
        for value in getattr(args, kind):
            targets.append(ScanTarget(kind=kind, value=value, region=args.region))
    for value in getattr(args, "ru_ua"):
        targets.append(ScanTarget(kind="ru-ua", value=value, region=args.region))
    return tuple(targets)


if __name__ == "__main__":
    raise SystemExit(main())
