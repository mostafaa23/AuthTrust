"""wily triage <report.json>

Records an analyst's --valid / --fp decision against a finding from a prior
scan report, keyed by the finding's stable hash (risk/ml/dedup.py's
finding_hash_key) rather than its row position - so the decision survives a
re-scan where the object id in the asset URL changes but the underlying
finding shape doesn't. Decisions accumulate in a local, append-only JSONL
feedback log (--store); this is the labeled data source a future heuristic
scorer revision or trained classifier would need. This command itself does
not train anything.

    wily triage wily-report.json --list
    wily triage wily-report.json --valid 2 --fp 5 --note "confirmed in demo"
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from wily.risk.ml.dedup import finding_hash_key
from wily.risk.ml.feedback import FALSE_POSITIVE, VALID, FeedbackStore

console = Console(stderr=True)

_DEFAULT_STORE = "wily-feedback.jsonl"


def _load_findings(report_path: Path) -> list[dict]:
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        console.print(f"[red][-][/red] Could not read {report_path}: {exc}")
        raise typer.Exit(code=1)
    findings = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(findings, list):
        console.print(f"[red][-][/red] {report_path}: no 'findings' list in report")
        raise typer.Exit(code=1)
    return findings


def _resolve_row(findings: list[dict], idx: int, report_path: Path) -> dict:
    if idx < 1 or idx > len(findings):
        console.print(f"[red][-][/red] Row {idx} out of range (1..{len(findings)}) for {report_path}")
        raise typer.Exit(code=1)
    return findings[idx - 1]


def run(
    report: str = typer.Argument(..., help="Path to a wily JSON report (-o/--output from `wily scan`)."),
    valid: list[int] = typer.Option(
        None, "--valid", help="1-based row number (see --list) of a confirmed real finding. Repeatable.",
    ),
    fp: list[int] = typer.Option(
        None, "--fp", help="1-based row number of a confirmed false positive. Repeatable.",
    ),
    note: str = typer.Option("", "--note", help="Optional free-text note attached to every decision recorded in this run."),
    store: str = typer.Option(_DEFAULT_STORE, "--store", help="Path to the local feedback log (JSONL, append-only)."),
    list_findings: bool = typer.Option(False, "--list", help="Print each finding's row number, hash key and prior verdict, then exit."),
) -> None:
    """Record --valid/--fp decisions against findings from a prior scan report."""
    report_path = Path(report)
    if not report_path.exists():
        console.print(f"[red][-][/red] Report not found: {report_path}")
        raise typer.Exit(code=1)

    findings = _load_findings(report_path)
    feedback = FeedbackStore(store)

    if list_findings:
        table = Table(title=f"Findings in {report_path.name} ({len(findings)})")
        table.add_column("#", justify="right")
        table.add_column("Category", style="red")
        table.add_column("Asset", overflow="fold")
        table.add_column("Prior verdict")
        decisions = feedback.decisions_by_hash()
        for i, f in enumerate(findings, start=1):
            try:
                key = finding_hash_key(f)
            except Exception:
                key = None
            prior = decisions.get(key) if key else None
            table.add_row(str(i), f.get("category", ""), str(f.get("asset", "")), prior.verdict if prior else "-")
        console.print(table)
        return

    if not valid and not fp:
        console.print(
            "[yellow][!][/yellow] Nothing to record. Pass --valid/--fp N (see --list "
            "for row numbers), e.g.: wily triage report.json --valid 2 --fp 5"
        )
        return

    recorded = 0
    for idx in valid or []:
        f = _resolve_row(findings, idx, report_path)
        feedback.record(f, VALID, note=note)
        recorded += 1
        console.print(f"[green][+][/green] #{idx} {f.get('category')} -> valid")
    for idx in fp or []:
        f = _resolve_row(findings, idx, report_path)
        feedback.record(f, FALSE_POSITIVE, note=note)
        recorded += 1
        console.print(f"[green][+][/green] #{idx} {f.get('category')} -> false_positive")

    console.print(f"\n[cyan][*][/cyan] {recorded} decision(s) appended to {Path(store).resolve()}")
