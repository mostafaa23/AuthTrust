"""wily authz <url>

Runs AuthzBypassScanner (missing-authorizer + method-inconsistency) and
CorsMisconfigScanner against a real resource.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.table import Table

from wily.core.scope_manager import ScopeManager
from wily.report.json_report import export_json
from wily.scanners.authz_bypass import (
    AuthzBypassScanner,
    AuthzBypassTarget,
    CorsMisconfigScanner,
    CorsMisconfigTarget,
)
from wily.scanners.base import ScannerConfirmationError

console = Console(stderr=True)


def run(
    url: str = typer.Argument(..., help="The target resource (e.g. https://api.example.com/orders/123)."),
    skip_cors: bool = typer.Option(False, "--skip-cors", help="Skip the CORS misconfiguration check."),
    allow_local: bool = typer.Option(False, "--allow-local", help="Allow scanning 127.0.0.1/localhost (local testing only)."),
    confirm_destructive: bool = typer.Option(
        True, "--confirm-destructive/--no-destructive",
        help=(
            "Probe write methods (POST/PUT/DELETE/PATCH). ON by default "
            "(offensive). These requests can create, modify, or delete real "
            "data on the target - pass --no-destructive to restrict to safe "
            "read methods only."
        ),
    ),
    output: str = typer.Option("wily-authz-report.json", "-o", "--output", help="Path to write the report to."),
) -> None:
    """Checks for missing-authorizer, method-inconsistency, and CORS misconfiguration."""
    console.print(f"[cyan][*][/cyan] Scanning [bold]{url}[/bold] (Auth Bypass)...")

    findings: list = []
    target = AuthzBypassTarget(url=url, include_destructive_methods=confirm_destructive)
    root_host = urlparse(url).hostname
    scope = ScopeManager(root_host, allow_local_targets=allow_local)

    try:
        scanner = AuthzBypassScanner(scope_manager=scope, confirm_destructive=confirm_destructive)
        findings += scanner.run(target)
    except ScannerConfirmationError as e:
        console.print(f"[yellow][!][/yellow] {e}")

    if not skip_cors:
        cors_target = CorsMisconfigTarget(url=url)
        findings += CorsMisconfigScanner(scope_manager=scope).run(cors_target)

    _print_findings(findings)
    path = export_json(findings, Path(output))
    console.print(f"[green][+][/green] Report: {path.resolve()}")


def _print_findings(findings: list) -> None:
    if not findings:
        console.print("[green][-][/green] No findings.")
        return
    table = Table(title=f"Findings ({len(findings)})")
    table.add_column("Category", style="red")
    table.add_column("Severity")
    table.add_column("Confidence")
    for f in findings:
        table.add_row(f.category, f.severity, f"{f.confidence:.2f}")
    console.print(table)
