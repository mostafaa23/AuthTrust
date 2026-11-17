"""wily iam <authorization-details.json>

Analyzes the output of `aws iam get-account-authorization-details` and
discovers privilege-escalation paths.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from wily.report.json_report import export_json
from wily.scanners.iam_privesc import (
    build_privesc_graph,
    find_privesc_paths,
    load_authorization_details,
)

console = Console(stderr=True)


def run(
    authorization_details_file: str = typer.Argument(
        ..., help="Path to the JSON output of: aws iam get-account-authorization-details"
    ),
    output: str = typer.Option("wily-iam-report.json", "-o", "--output", help="Path to write the report to."),
) -> None:
    """Builds a permission graph and discovers privilege escalation paths
    (self-mutation, trust-policy abuse, resource hijack, and pass_role
    across 8 services)."""
    console.print(f"[cyan][*][/cyan] Analyzing [bold]{authorization_details_file}[/bold]...")

    principals = load_authorization_details(Path(authorization_details_file))
    console.print(f"[cyan][*][/cyan] Loaded {len(principals)} principal(s) (users + roles).")

    graph = build_privesc_graph(principals)
    console.print(f"[cyan][*][/cyan] The permission graph has {graph.number_of_edges()} suspicious edge(s).")

    findings = find_privesc_paths(graph, principals)
    _print_findings(findings)

    path = export_json(findings, Path(output))
    console.print(f"[green][+][/green] Report: {path.resolve()}")


def _print_findings(findings: list) -> None:
    if not findings:
        console.print("[green][-][/green] No clear privilege-escalation paths.")
        return
    table = Table(title=f"Findings ({len(findings)})")
    table.add_column("Principal", style="red")
    table.add_column("Category")
    table.add_column("Severity")
    for f in findings:
        table.add_row(f.evidence.get("principal", "?"), f.category, f.severity)
    console.print(table)
