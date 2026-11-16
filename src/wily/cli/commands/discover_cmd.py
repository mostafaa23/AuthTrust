"""wily discover <domain>

Runs ApiDiscoveryPipeline on its own and prints/saves the discovered
endpoints - useful for seeing what Wily found before deciding which
check to run against it.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.table import Table

from wily.core.scope_manager import ScopeManager
from wily.recon.api_discovery import ApiDiscoveryPipeline, DiscoveryConfig

console = Console(stderr=True)


def run(
    target: str = typer.Argument(..., help="The target base URL (e.g. https://api.example.com)."),
    allow_local: bool = typer.Option(
        False, "--allow-local",
        help="Allow scanning 127.0.0.1/localhost (local testing only).",
    ),
    output: str = typer.Option(None, "-o", "--output", help="Path to write a JSON file of the results (optional)."),
) -> None:
    """Discovers real endpoints via an OpenAPI spec, JS scraping, and wordlist fuzzing."""
    if target.startswith("http"):
        target_url = target
    else:
        scheme = "http" if allow_local else "https"
        target_url = f"{scheme}://{target}"

    root_domain = urlparse(target_url).hostname or target
    scope = ScopeManager(root_domain, allow_local_targets=allow_local)

    console.print(f"[cyan][*][/cyan] Discovering endpoints on [bold]{target_url}[/bold]...")

    config = DiscoveryConfig(target=target_url, scope=scope, allow_local_targets=allow_local)
    report = asyncio.run(ApiDiscoveryPipeline(config).run())

    payload = report.to_json()
    endpoints = payload.get("endpoints", [])

    if not endpoints:
        console.print("[yellow][-][/yellow] No endpoints discovered.")
        return

    table = Table(title=f"Discovered endpoints ({len(endpoints)})")
    table.add_column("URL", style="cyan")
    for ep in endpoints:
        table.add_row(ep if isinstance(ep, str) else str(ep))
    console.print(table)

    if output:
        Path(output).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"[green][+][/green] Results saved to: {Path(output).resolve()}")
