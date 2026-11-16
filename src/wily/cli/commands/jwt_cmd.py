"""wily jwt <url> --token <TOKEN>

Runs JwtTamperScanner against a real JWT-protected endpoint.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.table import Table

from wily.core.scope_manager import ScopeManager
from wily.report.json_report import export_json
from wily.scanners.jwt_tamper import JwtTamperScanner, JwtTarget

console = Console(stderr=True)


def run(
    url: str = typer.Argument(..., help="The JWT-protected endpoint (e.g. https://api.example.com/profile)."),
    token: str = typer.Option(..., "--token", "-t", help="A valid JWT (from an ordinary login)."),
    method: str = typer.Option("GET", "--method", "-m", help="HTTP method used for the endpoint."),
    auth_header: str = typer.Option("Authorization", "--auth-header", help="Name of the header carrying the token."),
    known_public_key: str = typer.Option(
        None, "--public-key-file",
        help="Path to a PEM public-key file (enables the RS256->HS256 confusion test).",
    ),
    allow_local: bool = typer.Option(False, "--allow-local", help="Allow scanning 127.0.0.1/localhost (local testing only)."),
    output: str = typer.Option("wily-jwt-report.json", "-o", "--output", help="Path to write the report to."),
) -> None:
    """Checks a JWT-protected endpoint: alg:none, signature-stripped, jwk-injection,
    rs256->hs256 confusion, kid-null-key, expiry claims."""
    public_key_pem = None
    if known_public_key:
        public_key_pem = Path(known_public_key).read_text(encoding="utf-8")

    target = JwtTarget(
        url=url,
        sample_token=token,
        method=method,
        auth_header_name=auth_header,
        known_public_key_pem=public_key_pem,
    )

    console.print(f"[cyan][*][/cyan] Scanning [bold]{url}[/bold] (JWT Tampering)...")
    root_host = urlparse(url).hostname
    scope = ScopeManager(root_host, allow_local_targets=allow_local)
    findings = JwtTamperScanner(scope_manager=scope).run(target)

    _print_findings(findings)
    path = export_json(findings, Path(output))
    console.print(f"[green][+][/green] Report: {path.resolve()}")


def _print_findings(findings: list) -> None:
    if not findings:
        console.print("[green][-][/green] No findings (the endpoint resisted the techniques tested).")
        return

    table = Table(title=f"Findings ({len(findings)})")
    table.add_column("Category", style="red")
    table.add_column("Severity")
    table.add_column("Confidence")
    for f in findings:
        table.add_row(f.category, f.severity, f"{f.confidence:.2f}")
    console.print(table)
