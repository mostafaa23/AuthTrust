"""wily ssrf <url> --param url

Runs SsrfImdsScanner (4 levels: direct, IP-bypass, IMDSv2, blind OOB)
against an endpoint that has a parameter which accepts a URL from the
user.
"""

from __future__ import annotations

from contextlib import nullcontext
from pathlib import Path
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.table import Table

from wily.core.oob_canary import OOBCanaryServer
from wily.core.scope_manager import ScopeManager
from wily.report.json_report import export_json
from wily.scanners.base import ScannerConfirmationError
from wily.scanners.ssrf_imds import SsrfImdsScanner, SsrfImdsTarget

console = Console(stderr=True)


def run(
    url: str = typer.Argument(..., help="The target endpoint."),
    param: str = typer.Option("url", "--param", "-p", help="Name of the parameter that takes the URL."),
    method: str = typer.Option("GET", "--method", "-m", help="HTTP method."),
    metadata_ip: str = typer.Option(
        "169.254.169.254", "--metadata-ip",
        help="The target IMDS address (set to a local IP:port only for local testing).",
    ),
    blind: bool = typer.Option(
        False, "--blind",
        help="Enable Blind SSRF testing via a local OOB canary (level 4).",
    ),
    allow_custom_method: bool = typer.Option(
        False, "--allow-custom-method",
        help="Enable only if the endpoint actually lets you choose the method via a query param (rare).",
    ),
    allow_custom_headers: bool = typer.Option(
        False, "--allow-custom-headers",
        help="Enable only if the endpoint actually lets you set headers via a query param (rare).",
    ),
    allow_local: bool = typer.Option(False, "--allow-local", help="Allow scanning 127.0.0.1/localhost (local testing only)."),
    confirm_owned_infra: bool = typer.Option(
        True, "--confirm-owned-infra/--no-owned-infra",
        help=(
            "Run this check. ON by default (offensive). It makes the target "
            "fetch internal metadata endpoints on your behalf - pass "
            "--no-owned-infra to skip it."
        ),
    ),
    output: str = typer.Option("wily-ssrf-report.json", "-o", "--output", help="Path to write the report to."),
) -> None:
    """Checks for SSRF against IMDS: level 1 (direct), level 2 (IP bypass),
    level 3 (IMDSv2, if --allow-custom-method/--allow-custom-headers are
    enabled), and level 4 (blind, if --blind is enabled)."""
    console.print(f"[cyan][*][/cyan] Scanning [bold]{url}[/bold] (SSRF/IMDS)...")

    canary_ctx = OOBCanaryServer() if blind else nullcontext()
    with canary_ctx as canary:
        if canary:
            console.print(f"[cyan][*][/cyan] OOB canary running locally: {canary.base_url}")

        target = SsrfImdsTarget(
            url=url,
            param_name=param,
            method=method,
            metadata_ip=metadata_ip,
            supports_custom_method=allow_custom_method,
            supports_custom_headers=allow_custom_headers,
            canary_server=canary,
        )

        root_host = urlparse(url).hostname
        scope = ScopeManager(root_host, allow_local_targets=allow_local)
        try:
            scanner = SsrfImdsScanner(scope_manager=scope, confirm_owned_infra=confirm_owned_infra)
            findings = scanner.run(target)
        except ScannerConfirmationError as e:
            console.print(f"[yellow][!][/yellow] {e}")
            findings = []

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
