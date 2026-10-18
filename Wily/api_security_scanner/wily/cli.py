#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wily :: wily/cli.py
====================
The actual front door: ``python -m wily`` or ``python -m wily.cli``.

Runs straight through, no prompts
----------------------------------
``wily <domain>`` runs every fully-automatable stage back to back and exits -
Stage 0/1/2/3 discovery (api_discovery.py), then Stage 5 BOLA/Cross-Tenant
testing (bola_tester.py) if two or more ``--identity`` accounts were given.
Nothing here ever blocks on a terminal prompt.

Stage 4 (traffic_monitor.py) is the one exception, and it stays strictly
opt-in via ``--traffic``: it opens a real Chromium window and needs an
authorised human at the keyboard by design (see traffic_monitor.py's own
docstring) - that cannot be made "automatic" without lying about what it
does, so it is simply not part of the default run.

    1. Target domain (required positional argument).
    2. Already have an API spec/docs from the bug-bounty program?
         --api PATH_OR_URL  -> loaded directly (Stage 0); Stages 1-3 skipped.
         (omitted)          -> the fallback chain runs on its own:
             Stage 1  doc-path probing      (/swagger.json, /openapi.yaml, ...)
             Stage 2  JS scraping + regex   (only if Stage 1 found nothing)
             Stage 3  wordlist fuzzing      (only if the harvest is still thin;
                      --deep-fuzz swaps in the large SecLists-derived list)
    3. --traffic [--identity-name NAME]  -> also run Stage 4, once, tagged
       with NAME so captured endpoints carry known ownership.
    4. --identity NAME=Header:Value (repeatable, 2+) -> after discovery,
       automatically BOLA/Cross-Tenant-test every bola_candidate endpoint
       found (by any stage) across all the given identities.

Every endpoint from every discovery stage lands in one DiscoveryReport
(api_discovery.DiscoveryReport), deduped by canonical URL and tagged with
every source that found it. BOLA findings are reported alongside it under
the top-level ``bola_testing`` key of the JSON output.

Only point this at a target you are authorised to test.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional

from .api_discovery import ApiDiscoveryPipeline, DiscoveryConfig, DiscoveryReport, EXTENDED_FUZZ_ROUTES
from .bola_tester import BolaTester, Identity
from .traffic_monitor import TrafficConfig, TrafficMonitor

logger = logging.getLogger("wily.cli")

__version__ = "0.1.0"
_TAGLINE = "Cloud-native, black-box API security scanner"

# Block-letter "WILY" banner, in the spirit of nuclei's startup banner.
# Printed to STDERR only (never stdout) so `wily target -o report.json` or
# `wily target | jq .` stays clean - exactly how nuclei keeps its banner
# and [INF]/[WRN] log lines off the results stream.
_BANNER = """\033[96m
 ██╗    ██╗██╗██╗  ██╗   ██╗
 ██║    ██║██║██║  ╚██╗ ██╔╝
 ██║ █╗ ██║██║██║   ╚████╔╝ 
 ██║███╗██║██║██║    ╚██╔╝  
 ╚███╔███╔╝██║███████╗██║   
  ╚══╝╚══╝ ╚═╝╚══════╝╚═╝   \033[0m
  
\033[97m[\033[96m*\033[97m] Wily - Cloud-Native API Security Scanner
\033[97m[\033[96m*\033[97m] Version 1.0.0\033[0m
"""


def _print_banner() -> None:
    if not sys.stderr.isatty():
        # Non-interactive output (piped/redirected): skip the art, keep one
        # plain identifying line so logs/CI output still say what ran.
        print(f"wily v{__version__} - {_TAGLINE}", file=sys.stderr)
        return
    print(_BANNER, file=sys.stderr)
    print(f"        v{__version__}  -  {_TAGLINE}", file=sys.stderr)
    print("        Only scan targets you are authorised to test.\n", file=sys.stderr)


def _normalise_target(raw: str) -> str:
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


# ---------------------------------------------------------------------------
# --identity NAME=Header:Value parsing
# ---------------------------------------------------------------------------


def _parse_identity_args(raw_args: List[str]) -> List[Identity]:
    """Turn repeated ``--identity NAME=Header: Value`` flags into Identity
    objects, merging repeats of the same NAME into one identity with
    several headers (e.g. Authorization + a required tenant header).

    Examples
    --------
        --identity "alice=Authorization: Bearer eyJ..."
        --identity "alice=Authorization: Bearer eyJ..." --identity "alice=X-Tenant: 42"
        --identity "bob=Cookie: session=abc123"
    """
    by_name: Dict[str, Dict[str, str]] = {}
    order: List[str] = []
    for raw in raw_args:
        if "=" not in raw:
            raise argparse.ArgumentTypeError(
                f"--identity {raw!r}: expected NAME=Header: Value"
            )
        name, _, header_part = raw.partition("=")
        name = name.strip()
        if ":" not in header_part:
            raise argparse.ArgumentTypeError(
                f"--identity {raw!r}: expected a 'Header: Value' pair after '='"
            )
        header_name, _, header_value = header_part.partition(":")
        if not name:
            raise argparse.ArgumentTypeError(f"--identity {raw!r}: identity name is empty")
        if name not in by_name:
            by_name[name] = {}
            order.append(name)
        by_name[name][header_name.strip()] = header_value.strip()
    return [Identity(name=n, headers=by_name[n]) for n in order]


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------


async def run_all(
    cfg: DiscoveryConfig,
    *,
    run_traffic: bool,
    identity_name: Optional[str],
    identities: List[Identity],
    allow_destructive: bool,
    min_confidence: str,
) -> Dict[str, object]:
    """Discovery, then (optionally) traffic capture, then (optionally) BOLA
    testing - one call, no prompts in between."""
    report = await ApiDiscoveryPipeline(cfg).run()
    print(f"\n[Wily] Discovery: {len(report.endpoints)} endpoint(s) found.", file=sys.stderr)

    if run_traffic:
        print(
            "[Wily] Stage 4: opening a browser. Log in with the authorised "
            "test account and use the app, then press ENTER in this terminal.",
            file=sys.stderr,
        )
        monitor = TrafficMonitor(TrafficConfig(target_url=cfg.target, identity_name=identity_name))
        await monitor.run()
        monitor.merge_into(report)
        print(f"[Wily] After traffic capture: {len(report.endpoints)} endpoint(s) total.", file=sys.stderr)

    payload = report.to_json()

    if len(identities) >= 2:
        candidate_count = len(BolaTester(identities).candidates(report))
        print(
            f"[Wily] Stage 5: BOLA/Cross-Tenant testing {candidate_count} "
            f"candidate(s) across {len(identities)} identities "
            f"({', '.join(i.name for i in identities)})...",
            file=sys.stderr,
        )
        tester = BolaTester(identities, allow_destructive=allow_destructive, min_confidence=min_confidence)
        findings = await tester.run(report)
        print(f"[Wily] BOLA testing: {len(findings)} finding(s) at/above {min_confidence}.", file=sys.stderr)
        payload["bola_testing"] = {
            "identities": [i.name for i in identities],
            "min_confidence": min_confidence,
            "allow_destructive": allow_destructive,
            "findings": [f.to_dict() for f in findings],
            "errors": tester.errors,
        }
    elif identities:
        print(
            "[Wily] Only one --identity given; BOLA testing needs at least two "
            "to compare against each other, so Stage 5 was skipped.",
            file=sys.stderr,
        )

    return payload


def main(argv: Optional[list] = None) -> int:
    logging.basicConfig(
        level=logging.INFO, format="[%(levelname)s] %(message)s", stream=sys.stderr
    )

    parser = argparse.ArgumentParser(
        prog="wily",
        description="Wily - black-box API security scanner. Runs straight through, no prompts. "
        "Only scan targets you are authorised to test.",
    )
    parser.add_argument("target", help="Target domain or URL.")
    parser.add_argument(
        "--api", "--spec", dest="spec", metavar="PATH_OR_URL",
        help="Already have an OpenAPI/Swagger spec or docs link? Use it directly and skip discovery.",
    )
    parser.add_argument(
        "--deep-fuzz", action="store_true",
        help=f"Stage 3 also tries the extended SecLists-derived wordlist ({len(EXTENDED_FUZZ_ROUTES)} paths)",
    )
    parser.add_argument(
        "--traffic", action="store_true",
        help="Also run Stage 4 (opens a real browser; needs a human at an authorised test account)",
    )
    parser.add_argument(
        "--identity-name", metavar="NAME",
        help="Tag Stage 4's capture as belonging to this identity (should match an --identity NAME)",
    )
    parser.add_argument(
        "--identity", metavar="NAME=Header:Value", action="append", default=[],
        help="A test account for Stage 5 BOLA testing, e.g. "
        '\'alice=Authorization: Bearer eyJ...\'. Repeat (same NAME to add more '
        "headers to one identity) - give at least two different NAMEs to enable Stage 5.",
    )
    parser.add_argument(
        "--allow-destructive", action="store_true",
        help="Let Stage 5 replay state-changing (POST/PUT/PATCH/DELETE) candidates too (off by default)",
    )
    parser.add_argument(
        "--min-confidence", choices=["LOW", "MEDIUM", "HIGH"], default="LOW",
        help="Lowest Stage 5 finding confidence to report (default: LOW)",
    )
    parser.add_argument("-o", "--output", metavar="FILE", help="Write the JSON report to FILE")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner")
    parser.add_argument("--version", action="version", version=f"wily v{__version__}")
    args = parser.parse_args(argv)

    if not args.no_banner:
        _print_banner()

    try:
        identities = _parse_identity_args(args.identity)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))
        return 2  # unreachable; parser.error() exits, this satisfies type-checkers

    cfg = DiscoveryConfig(
        target=_normalise_target(args.target),
        spec=args.spec,
        deep_fuzz=args.deep_fuzz,
    )

    if args.verbose:
        logging.getLogger("wily").setLevel(logging.DEBUG)

    try:
        payload = asyncio.run(
            run_all(
                cfg,
                run_traffic=args.traffic,
                identity_name=args.identity_name,
                identities=identities,
                allow_destructive=args.allow_destructive,
                min_confidence=args.min_confidence,
            )
        )
    except KeyboardInterrupt:
        return 130

    text = json.dumps(payload, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        print(f"\n[Wily] Report saved to: {args.output}", file=sys.stderr)
    else:
        print("\n" + text)

    return 0 if payload.get("endpoints") else 1


if __name__ == "__main__":
    raise SystemExit(main())
