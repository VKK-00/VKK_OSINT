from __future__ import annotations

import csv
import io
import json
from typing import Iterable

from .adapter_setup import AdapterSetup
from .adapters import AdapterProfile, AdapterSpec
from .case_store import CaseEntityHit, CaseEntityRecord, CaseRecord
from .engine import Finding
from .graph import GraphAnalysis
from .models import OsintProject
from .search import SearchPlan, SearchProfile


def format_projects(projects: Iterable[OsintProject], *, output_format: str, kind: str = "all") -> str:
    project_list = tuple(projects)
    if output_format == "json":
        return json.dumps([project.to_dict() for project in project_list], ensure_ascii=False, indent=2)
    if output_format == "csv":
        return _projects_csv(project_list, kind=kind)
    if output_format == "markdown":
        return _projects_markdown(project_list, kind=kind)
    if output_format == "table":
        return _projects_table(project_list, kind=kind)
    raise ValueError(f"Unsupported output format: {output_format}")


def format_project_detail(project: OsintProject, *, output_format: str = "table") -> str:
    if output_format == "json":
        return json.dumps(project.to_dict(), ensure_ascii=False, indent=2)
    if output_format == "markdown":
        lines = [
            f"# {project.full_name}",
            "",
            f"- Rank: {project.rank}",
            f"- Stars: {project.stars}",
            f"- Forks: {project.forks}",
            f"- Language: {project.language or 'unknown'}",
            f"- License: {project.license or 'unknown'}",
            f"- URL: {project.html_url}",
            f"- Description: {project.description}",
            f"- People: {project.people_level or '-'} / {project.people_focus or '-'}",
            f"- RU/UA: {project.ru_ua_level or '-'} / {project.ru_ua_focus or '-'}",
            f"- Topics: {', '.join(project.topics)}",
        ]
        return "\n".join(lines)
    lines = [
        f"Repository: {project.full_name}",
        f"Rank:       {project.rank}",
        f"Stars:      {project.stars}",
        f"Forks:      {project.forks}",
        f"Language:   {project.language or 'unknown'}",
        f"License:    {project.license or 'unknown'}",
        f"URL:        {project.html_url}",
        f"People:     {project.people_level or '-'} | {project.people_focus or '-'}",
        f"RU/UA:      {project.ru_ua_level or '-'} | {project.ru_ua_focus or '-'}",
        f"Summary:    {project.description}",
    ]
    if project.people_note:
        lines.append(f"People note: {project.people_note}")
    if project.ru_ua_note:
        lines.append(f"RU/UA note:  {project.ru_ua_note}")
    return "\n".join(lines)


def format_findings(findings: Iterable[Finding], *, output_format: str = "table") -> str:
    finding_list = tuple(findings)
    if output_format == "json":
        return json.dumps([finding.to_dict() for finding in finding_list], ensure_ascii=False, indent=2)
    if output_format == "csv":
        return _findings_csv(finding_list)
    if output_format == "markdown":
        lines = [
            "| Module | Source | Status | Confidence | HTTP | URL | Evidence |",
            "|---|---|---|---|---:|---|---|",
        ]
        for finding in finding_list:
            http_status = finding.http_status if finding.http_status is not None else ""
            lines.append(
                f"| {finding.module} | {finding.source} | {finding.status} | {finding.confidence} | "
                f"{http_status} | {_escape_md(finding.url)} | {_escape_md(finding.evidence)} |"
            )
        return "\n".join(lines)
    if output_format == "table":
        headers = ("Module", "Source", "Status", "HTTP", "Confidence", "Evidence", "URL")
        rows = [
            (
                finding.module,
                finding.source,
                finding.status,
                "" if finding.http_status is None else str(finding.http_status),
                finding.confidence,
                _short(finding.evidence, 48),
                _short(finding.url, 72),
            )
            for finding in finding_list
        ]
        return _format_table(headers, rows)
    raise ValueError(f"Unsupported output format: {output_format}")


def format_adapters(adapters: Iterable[AdapterSpec], *, output_format: str = "table") -> str:
    adapter_list = tuple(adapters)
    if output_format == "json":
        return json.dumps([adapter.to_dict() for adapter in adapter_list], ensure_ascii=False, indent=2)
    if output_format == "markdown":
        lines = [
            "| Repository | Capability | Integration | Status | License | Note |",
            "|---|---|---|---|---|---|",
        ]
        for adapter in adapter_list:
            lines.append(
                f"| {adapter.repository} | {_escape_md(adapter.capability)} | {adapter.integration} | "
                f"{adapter.status} | {adapter.license} | {_escape_md(adapter.note)} |"
            )
        return "\n".join(lines)
    if output_format == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(
            buffer,
            fieldnames=(
                "repository",
                "capability",
                "integration",
                "status",
                "license",
                "command_hint",
                "target_kinds",
                "command_template",
                "command_templates",
                "command_input_template",
                "install_kind",
                "install_command",
                "install_note",
                "docs_url",
                "required_env",
                "optional_env",
                "generated_output_dir_args",
                "generated_output_file_args",
                "generated_output_patterns",
                "generated_output_workdir",
                "note",
            ),
            lineterminator="\n",
        )
        writer.writeheader()
        for adapter in adapter_list:
            writer.writerow(adapter.to_dict())
        return buffer.getvalue().strip()
    if output_format == "table":
        headers = ("Repository", "Integration", "Status", "Capability")
        rows = [
            (
                adapter.repository,
                adapter.integration,
                adapter.status,
                _short(adapter.capability, 46),
            )
            for adapter in adapter_list
        ]
        return _format_table(headers, rows)
    raise ValueError(f"Unsupported output format: {output_format}")


def format_adapter_profiles(profiles: Iterable[AdapterProfile], *, output_format: str = "table") -> str:
    profile_list = tuple(profiles)
    if output_format == "json":
        return json.dumps([profile.to_dict() for profile in profile_list], ensure_ascii=False, indent=2)
    if output_format == "markdown":
        lines = [
            "| Profile | Targets | Repositories | Description |",
            "|---|---|---|---|",
        ]
        for profile in profile_list:
            lines.append(
                f"| {profile.name} | {_escape_md(', '.join(profile.target_kinds))} | "
                f"{_escape_md(', '.join(profile.repositories))} | {_escape_md(profile.description)} |"
            )
        return "\n".join(lines)
    if output_format == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(
            buffer,
            fieldnames=("name", "title", "description", "target_kinds", "repositories", "note"),
            lineterminator="\n",
        )
        writer.writeheader()
        for profile in profile_list:
            writer.writerow(profile.to_dict())
        return buffer.getvalue().strip()
    if output_format == "table":
        headers = ("Profile", "Targets", "Repositories", "Description")
        rows = [
            (
                profile.name,
                ", ".join(profile.target_kinds),
                _short(", ".join(profile.repositories), 64),
                _short(profile.description, 58),
            )
            for profile in profile_list
        ]
        return _format_table(headers, rows)
    raise ValueError(f"Unsupported output format: {output_format}")


def format_search_profiles(profiles: Iterable[SearchProfile], *, output_format: str = "table") -> str:
    profile_list = tuple(profiles)
    if output_format == "json":
        return json.dumps([profile.to_dict() for profile in profile_list], ensure_ascii=False, indent=2)
    if output_format == "markdown":
        lines = [
            "| Profile | Targets | Native | Adapter profiles | Local tools | Description |",
            "|---|---|---|---|---|---|",
        ]
        for profile in profile_list:
            lines.append(
                f"| {profile.name} | {_escape_md(', '.join(profile.target_kinds))} | "
                f"{_escape_md(', '.join(profile.native_kinds) or '-')} | "
                f"{_escape_md(', '.join(profile.adapter_profiles) or '-')} | "
                f"{_escape_md(', '.join(profile.local_tools) or '-')} | "
                f"{_escape_md(profile.description)} |"
            )
        return "\n".join(lines)
    if output_format == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(
            buffer,
            fieldnames=(
                "name",
                "title",
                "description",
                "target_kinds",
                "native_kinds",
                "adapter_profiles",
                "adapter_repositories",
                "local_tools",
                "excluded_repositories",
                "include_restricted",
                "note",
            ),
            lineterminator="\n",
        )
        writer.writeheader()
        for profile in profile_list:
            writer.writerow(_search_profile_csv_row(profile))
        return buffer.getvalue().strip()
    if output_format == "table":
        headers = ("Profile", "Targets", "Native", "Adapter profiles", "Local tools", "Description")
        rows = [
            (
                profile.name,
                _short(", ".join(profile.target_kinds), 30),
                _short(", ".join(profile.native_kinds) or "-", 30),
                _short(", ".join(profile.adapter_profiles) or "-", 42),
                _short(", ".join(profile.local_tools) or "-", 42),
                _short(profile.description, 56),
            )
            for profile in profile_list
        ]
        return _format_table(headers, rows)
    raise ValueError(f"Unsupported output format: {output_format}")


def format_search_profile_detail(profile: SearchProfile, *, output_format: str = "table") -> str:
    if output_format == "json":
        return json.dumps(profile.to_dict(), ensure_ascii=False, indent=2)
    if output_format == "markdown":
        lines = [
            f"# {profile.name}",
            "",
            f"- Title: {_escape_md(profile.title)}",
            f"- Description: {_escape_md(profile.description or '-')}",
            f"- Target kinds: {_escape_md(', '.join(profile.target_kinds))}",
            f"- Native kinds: {_escape_md(', '.join(profile.native_kinds) or '-')}",
            f"- Adapter profiles: {_escape_md(', '.join(profile.adapter_profiles) or '-')}",
            f"- Adapter repositories: {_escape_md(', '.join(profile.adapter_repositories) or '-')}",
            f"- Local tools: {_escape_md(', '.join(profile.local_tools) or '-')}",
            f"- Excluded repositories: {_escape_md(', '.join(profile.excluded_repositories) or '-')}",
            f"- Include restricted: {str(profile.include_restricted).lower()}",
            f"- Note: {_escape_md(profile.note or '-')}",
        ]
        return "\n".join(lines)
    if output_format == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(
            buffer,
            fieldnames=tuple(_search_profile_csv_row(profile).keys()),
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerow(_search_profile_csv_row(profile))
        return buffer.getvalue().strip()
    if output_format == "table":
        row = _search_profile_csv_row(profile)
        return _format_table(("Field", "Value"), [(key, _short(str(value), 100)) for key, value in row.items()])
    raise ValueError(f"Unsupported output format: {output_format}")


def format_adapter_setups(setups: Iterable[AdapterSetup], *, output_format: str = "table") -> str:
    setup_list = tuple(setups)
    if output_format == "json":
        return json.dumps([setup.to_dict() for setup in setup_list], ensure_ascii=False, indent=2)
    if output_format == "markdown":
        lines = [
            "| Repository | Readiness | Install | Required env | Docs |",
            "|---|---|---|---|---|",
        ]
        for setup in setup_list:
            install = setup.install_command or setup.install_note or setup.install_kind or "-"
            required_env = ", ".join(setup.required_env) or "-"
            docs = f"[docs]({setup.docs_url})" if setup.docs_url else "-"
            lines.append(
                f"| {setup.repository} | {setup.readiness} | {_escape_md(install)} | "
                f"{_escape_md(required_env)} | {docs} |"
            )
        return "\n".join(lines)
    if output_format == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(
            buffer,
            fieldnames=(
                "repository",
                "adapter_status",
                "readiness",
                "executable",
                "executable_path",
                "install_kind",
                "install_command",
                "install_note",
                "docs_url",
                "required_env",
                "missing_env",
                "optional_env",
                "command_hint",
            ),
            lineterminator="\n",
        )
        writer.writeheader()
        for setup in setup_list:
            row = setup.to_dict()
            row["required_env"] = ", ".join(setup.required_env)
            row["missing_env"] = ", ".join(setup.missing_env)
            row["optional_env"] = ", ".join(setup.optional_env)
            writer.writerow(row)
        return buffer.getvalue().strip()
    if output_format == "table":
        headers = ("Repository", "Readiness", "Install", "Required env")
        rows = [
            (
                setup.repository,
                setup.readiness,
                _short(setup.install_command or setup.install_note or setup.install_kind or "-", 54),
                _short(", ".join(setup.required_env) or "-", 28),
            )
            for setup in setup_list
        ]
        return _format_table(headers, rows)
    raise ValueError(f"Unsupported output format: {output_format}")


def format_search_plan(plan: SearchPlan, *, output_format: str = "table") -> str:
    if output_format == "json":
        return json.dumps(plan.to_dict(), ensure_ascii=False, indent=2)
    if output_format == "csv":
        return _search_plan_csv(plan)
    if output_format == "markdown":
        lines = [
            f"# Search Plan: {plan.target.kind}",
            "",
            f"- Target: `{_escape_md(plan.target.value)}`",
            f"- Region: `{plan.target.region}`",
            f"- Profile: `{plan.profile.name}` - {_escape_md(plan.profile.title)}",
            "",
            "## Warnings",
            "",
        ]
        if plan.warnings:
            lines.extend(f"- {_escape_md(warning)}" for warning in plan.warnings)
        else:
            lines.append("- none")
        lines.extend(
            [
                "",
                "## Steps",
                "",
                "| Stage | Source | Target | Status | Readiness | Command / install hint | Reason |",
                "|---|---|---|---|---|---|---|",
            ]
        )
        for step in plan.steps:
            target = f"{step.target_kind}:{step.target_value}"
            command = step.command or step.install_note or "-"
            lines.append(
                f"| {step.stage} | {_escape_md(step.source)} | {_escape_md(target)} | "
                f"{step.status} | {step.readiness or '-'} | {_escape_md(command)} | {_escape_md(step.reason)} |"
            )
        return "\n".join(lines)
    if output_format == "table":
        header = [
            f"Target:  {plan.target.kind}:{plan.target.value}",
            f"Profile: {plan.profile.name} ({plan.profile.title})",
        ]
        if plan.warnings:
            header.append("Warnings:")
            header.extend(f"- {warning}" for warning in plan.warnings)
        rows = [
            (
                step.stage,
                _short(step.source, 38),
                _short(f"{step.target_kind}:{step.target_value}", 34),
                step.status,
                step.readiness or "-",
                _short(step.command or step.install_note or "-", 72),
            )
            for step in plan.steps
        ]
        return "\n".join([*header, "", _format_table(("Stage", "Source", "Target", "Status", "Ready", "Command / install"), rows)])
    raise ValueError(f"Unsupported output format: {output_format}")


def format_cases(cases: Iterable[CaseRecord], *, output_format: str = "table") -> str:
    case_list = tuple(cases)
    if output_format == "json":
        return json.dumps([case.to_dict() for case in case_list], ensure_ascii=False, indent=2)
    if output_format == "markdown":
        lines = [
            "| Case ID | Title | Saved | Targets | Entities | Edges | Findings |",
            "|---|---|---|---:|---:|---:|---:|",
        ]
        for case in case_list:
            lines.append(
                f"| {case.case_id} | {_escape_md(case.title)} | {case.saved_at} | "
                f"{case.target_count} | {case.entity_count} | {case.edge_count} | {case.finding_count} |"
            )
        return "\n".join(lines)
    if output_format == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(
            buffer,
            fieldnames=(
                "case_id",
                "title",
                "generated_at",
                "saved_at",
                "target_count",
                "entity_count",
                "finding_count",
                "edge_count",
            ),
            lineterminator="\n",
        )
        writer.writeheader()
        for case in case_list:
            writer.writerow(case.to_dict())
        return buffer.getvalue().strip()
    if output_format == "table":
        headers = ("Case ID", "Title", "Saved", "Targets", "Entities", "Edges", "Findings")
        rows = [
            (
                case.case_id,
                _short(case.title, 34),
                case.saved_at,
                str(case.target_count),
                str(case.entity_count),
                str(case.edge_count),
                str(case.finding_count),
            )
            for case in case_list
        ]
        return _format_table(headers, rows)
    raise ValueError(f"Unsupported output format: {output_format}")


def format_case_detail(payload: dict[str, object], *, output_format: str = "json") -> str:
    if output_format == "json":
        return json.dumps(payload, ensure_ascii=False, indent=2)

    case = payload["case"]
    targets = payload["targets"]
    entities = payload["entities"]
    edges = payload["edges"]
    findings = payload["findings"]
    metadata = payload.get("metadata", {})
    valid_payload = (
        isinstance(case, dict)
        and isinstance(targets, list)
        and isinstance(entities, list)
        and isinstance(edges, list)
        and isinstance(findings, list)
        and isinstance(metadata, dict)
    )
    if not valid_payload:
        raise ValueError("Invalid case payload.")

    if output_format == "markdown":
        lines = [
            f"# {case['title']}",
            "",
            f"- Case ID: `{case['case_id']}`",
            f"- Generated: {case['generated_at']}",
            f"- Saved: {case['saved_at']}",
            "",
            "## Case Metadata",
            "",
        ]
        if metadata:
            for key, value in metadata.items():
                rendered_value = json.dumps(value, ensure_ascii=False, sort_keys=True)
                lines.append(f"- `{_escape_md(str(key))}`: `{_escape_md(rendered_value)}`")
        else:
            lines.append("- none")
        lines.extend(
            [
                "",
                "## Targets",
                "",
                "| Kind | Value | Region |",
                "|---|---|---|",
            ]
        )
        for target in targets:
            lines.append(f"| {target['kind']} | {_escape_md(str(target['value']))} | {target['region']} |")
        lines.extend(
            [
                "",
                "## Entities",
                "",
                "| Kind | Value | Confidence | Source |",
                "|---|---|---|---|",
            ]
        )
        for entity in entities:
            lines.append(
                f"| {entity['kind']} | {_escape_md(str(entity['value']))} | "
                f"{entity['confidence']} | {_escape_md(str(entity['source']))} |"
            )
        lines.extend(
            [
                "",
                "## Graph Edges",
                "",
                "| Source | Relation | Target | Confidence |",
                "|---|---|---|---|",
            ]
        )
        for edge in edges:
            source = f"{edge['source_kind']}:{edge['source_value']}"
            target = f"{edge['target_kind']}:{edge['target_value']}"
            lines.append(
                f"| {_escape_md(source)} | {edge['relation']} | "
                f"{_escape_md(target)} | {edge['confidence']} |"
            )
        lines.extend(
            [
                "",
                "## Findings",
                "",
                "| Collection | Module | Source | Status | Confidence | Target |",
                "|---|---|---|---|---|---|",
            ]
        )
        for finding in findings:
            lines.append(
                f"| {finding['collection']} | {finding['module']} | {_escape_md(str(finding['source']))} | "
                f"{finding['status']} | {finding['confidence']} | {_escape_md(str(finding['target']))} |"
            )
        return "\n".join(lines)

    if output_format == "table":
        lines = [
            f"Case ID:     {case['case_id']}",
            f"Title:       {case['title']}",
            f"Generated:   {case['generated_at']}",
            f"Saved:       {case['saved_at']}",
            f"Targets:     {len(targets)}",
            f"Entities:    {len(entities)}",
            f"Edges:       {len(edges)}",
            f"Findings:    {len(findings)}",
            f"Metadata:    {len(metadata)}",
        ]
        return "\n".join(lines)

    raise ValueError(f"Unsupported output format: {output_format}")


def format_case_graph_analysis(analysis: GraphAnalysis, *, output_format: str = "table") -> str:
    if output_format == "json":
        return json.dumps(analysis.to_dict(), ensure_ascii=False, indent=2)

    if output_format == "markdown":
        lines = [
            f"# Case Graph: {_escape_md(analysis.case_id)}",
            "",
            f"- Nodes: {analysis.node_count}",
            f"- Edges: {analysis.edge_count}",
            "",
            "## Relation Counts",
            "",
        ]
        lines.extend(_markdown_count_table("Relation", analysis.relation_counts))
        lines.extend(["", "## Entity Kind Counts", ""])
        lines.extend(_markdown_count_table("Kind", analysis.kind_counts))
        lines.extend(["", "## Top Connected Nodes", ""])
        lines.extend(_markdown_top_nodes(analysis))
        if analysis.focus:
            lines.extend(["", f"## Neighbors for `{_escape_md(analysis.focus.label())}`", ""])
            lines.extend(_markdown_neighbors(analysis))
        return "\n".join(lines)

    if output_format == "table":
        sections = [
            f"Case ID: {analysis.case_id}",
            f"Nodes:   {analysis.node_count}",
            f"Edges:   {analysis.edge_count}",
            "",
            "Relation counts:",
            _format_table(("Relation", "Count"), [(key, str(count)) for key, count in analysis.relation_counts])
            if analysis.relation_counts
            else "(none)",
            "",
            "Entity kind counts:",
            _format_table(("Kind", "Count"), [(key, str(count)) for key, count in analysis.kind_counts])
            if analysis.kind_counts
            else "(none)",
            "",
            "Top connected nodes:",
            _format_table(
                ("Entity", "Degree"),
                [(f"{node.kind}:{node.value}", str(node.degree)) for node in analysis.top_nodes],
            )
            if analysis.top_nodes
            else "(none)",
        ]
        if analysis.focus:
            sections.extend(
                [
                    "",
                    f"Neighbors for {analysis.focus.label()}:",
                    _format_table(
                        ("Direction", "Relation", "Neighbor", "Confidence", "Source"),
                        [
                            (
                                neighbor.direction,
                                neighbor.relation,
                                f"{neighbor.kind}:{neighbor.value}",
                                neighbor.confidence,
                                neighbor.source,
                            )
                            for neighbor in analysis.neighbors
                        ],
                    )
                    if analysis.neighbors
                    else "(none)",
                ]
            )
        return "\n".join(sections)

    raise ValueError(f"Unsupported output format: {output_format}")


def format_case_entity_index(records: Iterable[CaseEntityRecord], *, output_format: str = "table") -> str:
    record_list = tuple(records)
    if output_format == "json":
        return json.dumps([record.to_dict() for record in record_list], ensure_ascii=False, indent=2)
    if output_format == "csv":
        return _case_entity_index_csv(record_list)
    if output_format == "markdown":
        lines = [
            "| Kind | Value | Cases | Case IDs |",
            "|---|---|---:|---|",
        ]
        for record in record_list:
            lines.append(
                f"| {record.kind} | {_escape_md(record.value)} | "
                f"{record.case_count} | {_escape_md(', '.join(record.cases))} |"
            )
        return "\n".join(lines)
    if output_format == "table":
        return _format_table(
            ("Kind", "Value", "Cases", "Case IDs"),
            [
                (
                    record.kind,
                    _short(record.value, 48),
                    str(record.case_count),
                    _short(", ".join(record.cases), 70),
                )
                for record in record_list
            ],
        )
    raise ValueError(f"Unsupported output format: {output_format}")


def format_case_entity_hits(hits: Iterable[CaseEntityHit], *, output_format: str = "table") -> str:
    hit_list = tuple(hits)
    if output_format == "json":
        return json.dumps([hit.to_dict() for hit in hit_list], ensure_ascii=False, indent=2)
    if output_format == "csv":
        return _case_entity_hits_csv(hit_list)
    if output_format == "markdown":
        lines = [
            "| Case ID | Title | Saved | Entity | Confidence | Source |",
            "|---|---|---|---|---|---|",
        ]
        for hit in hit_list:
            entity = f"{hit.kind}:{hit.value}"
            lines.append(
                f"| {hit.case_id} | {_escape_md(hit.title)} | {hit.saved_at} | "
                f"{_escape_md(entity)} | {hit.confidence} | {_escape_md(hit.source)} |"
            )
        return "\n".join(lines)
    if output_format == "table":
        return _format_table(
            ("Case ID", "Title", "Saved", "Entity", "Confidence", "Source"),
            [
                (
                    hit.case_id,
                    _short(hit.title, 34),
                    hit.saved_at,
                    _short(f"{hit.kind}:{hit.value}", 48),
                    hit.confidence,
                    _short(hit.source, 34),
                )
                for hit in hit_list
            ],
        )
    raise ValueError(f"Unsupported output format: {output_format}")


def format_stats(stats: dict[str, object]) -> str:
    lines = [
        "OSINT Toolkit catalog stats",
        f"Data dir:     {stats['data_dir']}",
        f"Total:        {stats['total']}",
        f"People:       {stats['people']}",
        f"RU/UA:        {stats['ru_ua']}",
        f"Relevant:     {stats['relevant']}",
        f"Intersection: {stats['intersection']}",
        "",
        "People levels:",
    ]
    lines.extend(f"- {key}: {value}" for key, value in sorted(stats["people_levels"].items()))
    lines.append("")
    lines.append("RU/UA levels:")
    lines.extend(f"- {key}: {value}" for key, value in sorted(stats["ru_ua_levels"].items()))
    lines.append("")
    lines.append("Top languages:")
    languages = sorted(stats["languages"].items(), key=lambda item: (-item[1], item[0]))[:10]
    lines.extend(f"- {key}: {value}" for key, value in languages)
    return "\n".join(lines)


def _projects_table(projects: tuple[OsintProject, ...], *, kind: str) -> str:
    headers = ("Rank", "Repository", "Stars", "Level", "Focus")
    rows = []
    for project in projects:
        level = _level(project, kind)
        focus = _focus(project, kind)
        rows.append(
            (
                str(project.rank),
                project.full_name,
                str(project.stars),
                level or "-",
                _short(focus or project.description, 58),
            )
        )
    return _format_table(headers, rows)


def _projects_markdown(projects: tuple[OsintProject, ...], *, kind: str) -> str:
    lines = [
        "| Rank | Repository | Stars | Level | Focus |",
        "|---:|---|---:|---|---|",
    ]
    for project in projects:
        level = _level(project, kind)
        focus = _escape_md(_focus(project, kind) or project.description)
        lines.append(
            f"| {project.rank} | [{project.full_name}]({project.html_url}) | "
            f"{project.stars} | {level or '-'} | {focus} |"
        )
    return "\n".join(lines)


def _projects_csv(projects: tuple[OsintProject, ...], *, kind: str) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=("rank", "full_name", "stars", "level", "focus", "language", "html_url", "description"),
        lineterminator="\n",
    )
    writer.writeheader()
    for project in projects:
        writer.writerow(
            {
                "rank": project.rank,
                "full_name": project.full_name,
                "stars": project.stars,
                "level": _level(project, kind),
                "focus": _focus(project, kind),
                "language": project.language,
                "html_url": project.html_url,
                "description": project.description,
            }
        )
    return buffer.getvalue().strip()


def _findings_csv(findings: tuple[Finding, ...]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=("module", "source", "target", "status", "url", "title", "http_status", "confidence", "evidence"),
        lineterminator="\n",
    )
    writer.writeheader()
    for finding in findings:
        writer.writerow(
            {
                "module": finding.module,
                "source": finding.source,
                "target": finding.target,
                "status": finding.status,
                "url": finding.url,
                "title": finding.title,
                "http_status": finding.http_status if finding.http_status is not None else "",
                "confidence": finding.confidence,
                "evidence": finding.evidence,
            }
        )
    return buffer.getvalue().strip()


def _case_entity_index_csv(records: tuple[CaseEntityRecord, ...]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=("kind", "value", "case_count", "cases"),
        lineterminator="\n",
    )
    writer.writeheader()
    for record in records:
        writer.writerow(
            {
                "kind": record.kind,
                "value": record.value,
                "case_count": record.case_count,
                "cases": ";".join(record.cases),
            }
        )
    return buffer.getvalue().strip()


def _case_entity_hits_csv(hits: tuple[CaseEntityHit, ...]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=("case_id", "title", "saved_at", "kind", "value", "source", "confidence", "note"),
        lineterminator="\n",
    )
    writer.writeheader()
    for hit in hits:
        writer.writerow(hit.to_dict())
    return buffer.getvalue().strip()


def _search_plan_csv(plan: SearchPlan) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=(
            "stage",
            "source",
            "title",
            "target_kind",
            "target_value",
            "status",
            "readiness",
            "command",
            "reason",
            "install_note",
            "docs_url",
        ),
        lineterminator="\n",
    )
    writer.writeheader()
    for step in plan.steps:
        writer.writerow(
            {
                "stage": step.stage,
                "source": step.source,
                "title": step.title,
                "target_kind": step.target_kind,
                "target_value": step.target_value,
                "status": step.status,
                "readiness": step.readiness,
                "command": step.command,
                "reason": step.reason,
                "install_note": step.install_note,
                "docs_url": step.docs_url,
            }
        )
    return buffer.getvalue().strip()


def _search_profile_csv_row(profile: SearchProfile) -> dict[str, str]:
    return {
        "name": profile.name,
        "title": profile.title,
        "description": profile.description,
        "target_kinds": ", ".join(profile.target_kinds),
        "native_kinds": ", ".join(profile.native_kinds),
        "adapter_profiles": ", ".join(profile.adapter_profiles),
        "adapter_repositories": ", ".join(profile.adapter_repositories),
        "local_tools": ", ".join(profile.local_tools),
        "excluded_repositories": ", ".join(profile.excluded_repositories),
        "include_restricted": str(profile.include_restricted).lower(),
        "note": profile.note,
    }


def _markdown_count_table(label: str, counts: tuple[tuple[str, int], ...]) -> list[str]:
    lines = [f"| {label} | Count |", "|---|---:|"]
    if not counts:
        lines.append("| - | 0 |")
        return lines
    for key, count in counts:
        lines.append(f"| {_escape_md(key)} | {count} |")
    return lines


def _markdown_top_nodes(analysis: GraphAnalysis) -> list[str]:
    lines = ["| Entity | Degree |", "|---|---:|"]
    if not analysis.top_nodes:
        lines.append("| - | 0 |")
        return lines
    for node in analysis.top_nodes:
        lines.append(f"| {_escape_md(f'{node.kind}:{node.value}')} | {node.degree} |")
    return lines


def _markdown_neighbors(analysis: GraphAnalysis) -> list[str]:
    lines = ["| Direction | Relation | Neighbor | Confidence | Source |", "|---|---|---|---|---|"]
    if not analysis.neighbors:
        lines.append("| - | - | - | - | - |")
        return lines
    for neighbor in analysis.neighbors:
        lines.append(
            f"| {neighbor.direction} | {neighbor.relation} | "
            f"{_escape_md(f'{neighbor.kind}:{neighbor.value}')} | "
            f"{neighbor.confidence} | {_escape_md(neighbor.source)} |"
        )
    return lines


def _format_table(headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        widths = [max(width, len(cell)) for width, cell in zip(widths, row)]
    line = "  ".join(header.ljust(width) for header, width in zip(headers, widths))
    sep = "  ".join("-" * width for width in widths)
    body = ["  ".join(cell.ljust(width) for cell, width in zip(row, widths)) for row in rows]
    return "\n".join([line, sep, *body])


def _level(project: OsintProject, kind: str) -> str:
    if kind == "people":
        return project.people_level
    if kind == "ru-ua":
        return project.ru_ua_level
    return project.people_level or project.ru_ua_level


def _focus(project: OsintProject, kind: str) -> str:
    if kind == "people":
        return project.people_focus
    if kind == "ru-ua":
        return project.ru_ua_focus
    if project.people_focus and project.ru_ua_focus:
        return f"{project.people_focus}; {project.ru_ua_focus}"
    return project.people_focus or project.ru_ua_focus


def _short(value: str, limit: int) -> str:
    compact = " ".join(value.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1] + "…"


def _escape_md(value: str) -> str:
    return " ".join(value.split()).replace("|", "\\|")
