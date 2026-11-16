"""The unified orchestrator: wily scan <domain>

Runs the following bundle automatically against every endpoint it
discovers (with no extra input required):
  - Auth Bypass (missing-authorizer, method-inconsistency, CORS)
  - SSRF levels 1+2 (direct + IP bypass) against parameters classified
    url-likely

And enables the following modules once their required input is supplied:
  - JWT Tampering          -> --token
  - BOLA                   -> --identity name=HeaderValue (at least twice)
  - IAM Privesc             -> --iam-file (fully independent of the domain)
  - SSRF level 4 (Blind)   -> --blind

Safety gates:
  - By default, AuthzBypassScanner only tests non-destructive methods
    (GET/HEAD/OPTIONS). Pass --confirm-destructive to also test
    POST/PUT/DELETE/PATCH, acknowledging that those requests can mutate
    or delete real data on the target.
  - SsrfImdsScanner requires the tester to own the target infrastructure
    (requires_owned_infra). Pass --confirm-owned-infra to acknowledge
    that and enable it.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table

from wily.core.oob_canary import OOBCanaryServer
from wily.core.rate_limiter import AdaptiveRateLimiter
from wily.core.scope_manager import ScopeManager
from wily.recon.api_discovery import ApiDiscoveryPipeline, DiscoveryConfig
from wily.recon.parameter_discovery import (
    ParameterDiscoveryConfig,
    discover_parameters,
    select_ssrf_candidates,
)
from wily.report.json_report import export_json
from wily.scanners.authz_bypass import (
    AuthzBypassScanner,
    AuthzBypassTarget,
    CorsMisconfigScanner,
    CorsMisconfigTarget,
)
from wily.scanners.base import Finding, ScannerConfirmationError
from wily.scanners.bola import BolaTester, Identity
from wily.scanners.http_engine import HttpEngine
from wily.scanners.iam_privesc import (
    build_privesc_graph,
    find_privesc_paths,
    load_authorization_details,
)
from wily.scanners.jwt_tamper import JwtTamperScanner, JwtTarget
from wily.scanners.ssrf_imds import SsrfImdsScanner, SsrfImdsTarget

console = Console(stderr=True)


async def run_full_scan(
    domain: str,
    token: str | None,
    identities_raw: list[str],
    iam_file: str | None,
    allow_local: bool,
    blind: bool,
    output: str,
    confirm_destructive: bool = True,
    confirm_owned_infra: bool = True,
) -> None:
    all_findings: list = []

    if iam_file:
        console.print(f"[cyan][*][/cyan] IAM: analyzing {iam_file} ...")
        principals = load_authorization_details(Path(iam_file))
        graph = build_privesc_graph(principals)
        iam_findings = find_privesc_paths(graph, principals)
        all_findings += iam_findings
        console.print(f"[cyan][*][/cyan] IAM: {len(iam_findings)} finding(s).")

    if not domain:
        _finish(all_findings, output)
        return

    if domain.startswith("http"):
        target_url = domain
    else:
        scheme = "http" if allow_local else "https"
        target_url = f"{scheme}://{domain}"

    root_domain = urlparse(target_url).hostname or domain

    # One ScopeManager, one rate limiter, one HttpEngine for the entire
    # scan: every scanner below shares them, so the AdaptiveRateLimiter's
    # per-host backoff state (e.g. after a 429) carries across scanners
    # and endpoints instead of resetting on every single call.
    scope = ScopeManager(root_domain, allow_local_targets=allow_local)
    rate_limiter = AdaptiveRateLimiter()
    http_engine = HttpEngine(scope_manager=scope, rate_limiter=rate_limiter)

    console.print(f"[cyan][*][/cyan] Discovering endpoints on [bold]{target_url}[/bold] ...")
    # Offensive-by-default discovery: run every stage (docs + JS + fuzz)
    # regardless of early hits (aggressive) and sweep the full SecLists-
    # derived wordlist (deep_fuzz), so protected targets that return few
    # obvious endpoints still get a thorough pass instead of "0 endpoints".
    disc_config = DiscoveryConfig(
        target=target_url,
        scope=scope,
        allow_local_targets=allow_local,
        aggressive=True,
        deep_fuzz=True,
    )
    report = await ApiDiscoveryPipeline(disc_config).run()
    payload = report.to_json()
    endpoints = payload.get("endpoints", [])
    console.print(f"[cyan][*][/cyan] {len(endpoints)} endpoint(s) discovered.")

    if not endpoints:
        console.print("[yellow][-][/yellow] No endpoints found, stopping here.")
        _finish(all_findings, output)
        return

    canary = OOBCanaryServer() if blind else None
    if canary:
        console.print(f"[cyan][*][/cyan] OOB canary running locally: {canary.base_url}")

    try:
        for ep_url in endpoints:
            console.print(f"[cyan]  ->[/cyan] {ep_url}")

            try:
                authz_scanner = AuthzBypassScanner(
                    scope_manager=scope,
                    http_engine=http_engine,
                    confirm_destructive=confirm_destructive,
                )
                all_findings += authz_scanner.run(
                    AuthzBypassTarget(
                        url=ep_url,
                        include_destructive_methods=confirm_destructive,
                    )
                )
                all_findings += CorsMisconfigScanner(
                    scope_manager=scope, http_engine=http_engine
                ).run(CorsMisconfigTarget(url=ep_url))
            except ScannerConfirmationError as e:
                console.print(f"[yellow]    [!][/yellow] Auth Bypass skipped: {e}")
            except Exception as e:
                console.print(f"[yellow]    [!][/yellow] Auth Bypass failed: {e}")

            try:
                # Use the full Arjun-derived wordlist (no artificial 300-param
                # cap) so uncommon URL/webhook/redirect parameter names that
                # back real SSRF are not missed.
                pconfig = ParameterDiscoveryConfig(url=ep_url, max_params=2000)
                # discover_parameters is a synchronous, potentially slow
                # call (up to max_params sequential HTTP requests). It is
                # offloaded to a worker thread so it never blocks this
                # coroutine's event loop while it runs.
                discovery_result = await asyncio.to_thread(
                    discover_parameters, pconfig, scope, http_engine
                )
                ssrf_params = select_ssrf_candidates(discovery_result)
                if discovery_result.probe_errors:
                    console.print(
                        f"[yellow]    [!][/yellow] Parameter discovery: "
                        f"{discovery_result.probe_errors}/{discovery_result.probes_sent} probes failed"
                    )
                for param_name in ssrf_params:
                    console.print(f"[cyan]    [*][/cyan] SSRF candidate: {param_name}")
                    ssrf_target = SsrfImdsTarget(
                        url=ep_url, param_name=param_name, canary_server=canary
                    )
                    ssrf_scanner = SsrfImdsScanner(
                        scope_manager=scope,
                        http_engine=http_engine,
                        confirm_owned_infra=confirm_owned_infra,
                    )
                    all_findings += ssrf_scanner.run(ssrf_target)
            except ScannerConfirmationError as e:
                console.print(f"[yellow]    [!][/yellow] SSRF skipped: {e}")
            except Exception as e:
                console.print(f"[yellow]    [!][/yellow] Parameter discovery failed: {e}")

            if token:
                try:
                    jwt_target = JwtTarget(url=ep_url, sample_token=token)
                    all_findings += JwtTamperScanner(
                        scope_manager=scope, http_engine=http_engine
                    ).run(jwt_target)
                except Exception as e:
                    console.print(f"[yellow]    [!][/yellow] JWT check failed: {e}")
    finally:
        if canary:
            canary.stop()

    identities = _parse_identities(identities_raw)
    if len(identities) >= 2:
        console.print(f"[cyan][*][/cyan] BOLA: testing with {len(identities)} identities ...")
        tester = BolaTester(identities=identities, min_confidence="LOW", scope_manager=scope)
        bola_findings = await tester.run(report)
        all_findings += [_bola_to_finding(bf) for bf in bola_findings]
        console.print(f"[cyan][*][/cyan] BOLA: {len(bola_findings)} finding(s).")
    elif identities_raw:
        console.print(
            "[yellow][!][/yellow] BOLA requires at least two --identity values "
            "(one identity alone can't be compared) - skipped."
        )

    _finish(all_findings, output)


_BOLA_CONFIDENCE_TO_FLOAT = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.4}
_BOLA_CONFIDENCE_TO_SEVERITY = {"HIGH": "critical", "MEDIUM": "high", "LOW": "medium"}


def _bola_to_finding(bf) -> Finding:
    """BolaFinding has a different schema from the shared Finding type
    (confidence is a string like HIGH/MEDIUM/LOW, no separate severity) -
    converted here so the unified report stays consistent with every
    other module."""
    return Finding(
        asset=bf.endpoint,
        category="bola-cross-tenant-access",
        severity=_BOLA_CONFIDENCE_TO_SEVERITY.get(bf.confidence, "medium"),
        confidence=_BOLA_CONFIDENCE_TO_FLOAT.get(bf.confidence, 0.5),
        evidence={
            "owner_identity": bf.owner_identity,
            "tester_identity": bf.tester_identity,
            "json_similarity": bf.json_similarity,
            "grounding": bf.grounding,
            "notes": bf.notes,
        },
        discovery_source="scanner",
        remediation=(
            "Actually verify resource ownership before returning data "
            "(match the identity extracted from the session against the "
            "resource's owner), not just that the JWT/session is valid."
        ),
    )


def _parse_identities(raw: list[str]) -> list[Identity]:
    """Each --identity is name=HeaderValue (e.g. tenant_a='Bearer xyz')."""
    identities = []
    for item in raw:
        if "=" not in item:
            continue
        name, _, header_value = item.partition("=")
        identities.append(Identity(name=name, headers={"Authorization": header_value}))
    return identities


def _finish(findings: list, output: str) -> None:
    console.print(f"\n[green][+][/green] Total findings: {len(findings)}\n")
    if findings:
        table = Table(title="All findings")
        table.add_column("Category", style="red")
        table.add_column("Asset", overflow="fold")
        table.add_column("Severity")
        for f in findings:
            table.add_row(f.category, str(f.asset), f.severity)
        console.print(table)

    path = export_json(findings, Path(output))
    console.print(f"\n[green][+][/green] Unified report: {path.resolve()}")
