from __future__ import annotations

import argparse
import sys

from .adapters import filter_adapters
from .catalog import Catalog, CatalogError
from .engine import Engine, RunConfig, ScanTarget
from .modules import UsernameScanModule, WebMetadataModule
from .output import format_adapters, format_findings, format_project_detail, format_projects, format_stats
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
    scan.add_argument("target_kind", choices=("username", "url"))
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
    engine = Engine([UsernameScanModule(), WebMetadataModule()])
    target = ScanTarget(kind=args.target_kind, value=args.target_value, region=args.region)
    config = RunConfig(live=args.live, timeout=args.timeout, limit=args.limit)
    findings = engine.scan(target, config)
    print(format_findings(findings, output_format=args.format))
    return 0


def handle_adapters(args: argparse.Namespace) -> int:
    print(format_adapters(filter_adapters(args.status), output_format=args.format))
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


def _add_data_dir(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--data-dir", help="Directory with the OSINT snapshot CSV files.")


def _load(args: argparse.Namespace) -> Catalog:
    return Catalog.load(args.data_dir)


if __name__ == "__main__":
    raise SystemExit(main())
