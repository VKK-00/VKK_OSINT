from __future__ import annotations

import argparse
import sys

from .adapter_runner import run_adapter
from .adapters import filter_adapters
from .catalog import Catalog, CatalogError
from .doctor import inspect_adapters
from .engine import RunConfig, ScanTarget
from .investigation import (
    render_investigation_json,
    render_investigation_markdown,
    run_investigation,
    write_investigation,
)
from .output import format_adapters, format_findings, format_project_detail, format_projects, format_stats
from .runtime import build_default_engine
from .workflows import TASK_PROFILES, recommend_projects, render_brief, render_recommendation, write_brief


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (CatalogError, ValueError) as exc:
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
    scan.add_argument("target_kind", choices=("username", "email", "phone", "domain", "url", "telegram", "ru-ua"))
    scan.add_argument("target_value")
    scan.add_argument("--region", choices=("all", "ru", "ua"), default="all")
    scan.add_argument("--live", action="store_true", help="Perform network checks. Default is dry-run planning.")
    scan.add_argument("--timeout", type=float, default=10.0)
    scan.add_argument("--limit", type=int)
    scan.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    scan.set_defaults(handler=handle_scan)

    adapters = subparsers.add_parser("adapters", help="Show upstream integration/parity adapter plan.")
    adapters.add_argument("--status", choices=("partial_native", "planned", "restricted"))
    adapters.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    adapters.set_defaults(handler=handle_adapters)

    doctor = subparsers.add_parser("doctor", help="Check local readiness of configured upstream adapters.")
    doctor.add_argument("--status", choices=("partial_native", "planned", "restricted"))
    doctor.add_argument("--format", choices=("table", "markdown", "csv", "json"), default="table")
    doctor.set_defaults(handler=handle_doctor)

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
    investigate.add_argument("--adapter-limit", type=int, default=20)
    investigate.add_argument("--timeout", type=float, default=10.0)
    investigate.add_argument("--format", choices=("markdown", "json"), default="markdown")
    investigate.add_argument("--out", help="Write investigation report to this path.")
    investigate.set_defaults(handler=handle_investigate)

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
    config = RunConfig(live=args.live, timeout=args.timeout, limit=args.limit)
    findings = engine.scan(target, config)
    print(format_findings(findings, output_format=args.format))
    return 0


def handle_adapters(args: argparse.Namespace) -> int:
    print(format_adapters(filter_adapters(args.status), output_format=args.format))
    return 0


def handle_doctor(args: argparse.Namespace) -> int:
    print(format_findings(inspect_adapters(args.status), output_format=args.format))
    return 0


def handle_run_adapter(args: argparse.Namespace) -> int:
    target = ScanTarget(kind=args.target_kind, value=args.target_value, region=args.region)
    finding = run_adapter(
        args.repository,
        target,
        execute=args.execute,
        allow_restricted=args.allow_restricted,
        timeout=args.timeout,
    )
    print(format_findings((finding,), output_format=args.format))
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
    result = run_investigation(
        targets,
        title=args.title,
        live=args.live,
        timeout=args.timeout,
        include_adapters=args.include_adapters,
        adapter_limit=args.adapter_limit,
    )
    content = (
        render_investigation_json(result)
        if args.format == "json"
        else render_investigation_markdown(result)
    )
    if args.out:
        path = write_investigation(args.out, content)
        print(f"Wrote {path}")
    else:
        print(content)
    return 0


def _add_data_dir(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--data-dir", help="Directory with the OSINT snapshot CSV files.")


def _load(args: argparse.Namespace) -> Catalog:
    return Catalog.load(args.data_dir)


def _targets_from_args(args: argparse.Namespace) -> tuple[ScanTarget, ...]:
    targets: list[ScanTarget] = []
    for kind in ("username", "email", "phone", "domain", "url", "telegram"):
        for value in getattr(args, kind):
            targets.append(ScanTarget(kind=kind, value=value, region=args.region))
    for value in getattr(args, "ru_ua"):
        targets.append(ScanTarget(kind="ru-ua", value=value, region=args.region))
    return tuple(targets)


if __name__ == "__main__":
    raise SystemExit(main())
