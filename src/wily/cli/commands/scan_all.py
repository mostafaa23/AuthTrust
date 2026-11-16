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
from wily.core.scope_manager import ScopeError, ScopeManager, load_scope_config
from wily.recon.api_discovery import (
    ApiDiscoveryPipeline,
    DiscoveryConfig,
    DiscoveryReport,
)
from wily.recon.parameter_discovery import (
    ParameterDiscoveryConfig,
    discover_parameters,
    select_ssrf_candidates,
)
from wily.recon.traffic_import import ImportedTraffic, import_traffic
from wily.report.json_report import export_json
from wily.risk.rules_engine import apply_deterministic_rules
from wily.risk.scoring import compute_risk_score
from wily.risk.triggers import TriggerContext, derive_followups
from wily.scanners.authz_bypass import (
    AuthzBypassScanner,
    AuthzBypassTarget,
    CorsMisconfigScanner,
    CorsMisconfigTarget,
)
from wily.scanners.base import Finding, ScannerConfirmationError, run_scanner
from wily.scanners.bola import BolaTester, Identity
from wily.scanners.http_engine import HttpEngine
from wily.scanners.iam_privesc import (
    build_privesc_graph,
    filter_principals_in_scope,
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
    show_leak: bool = False,
    burp_xml: str | None = None,
    import_har: str | None = None,
    scope_buckets: list[str] | None = None,
    scope_accounts: list[str] | None = None,
    scope_config: str | None = None,
) -> None:
    all_findings: list = []

    # --- Resolve the extended scope (buckets + AWS accounts) from CLI/config.
    buckets: tuple[str, ...] = tuple(scope_buckets or ())
    accounts: tuple[str, ...] = tuple(scope_accounts or ())
    excluded: tuple[str, ...] = ()
    if scope_config:
        try:
            cfg = load_scope_config(scope_config)
            buckets += cfg["buckets"]
            accounts += cfg["accounts"]
            excluded += cfg["exclude"]
        except (ScopeError, OSError) as e:
            console.print(f"[yellow][!][/yellow] Scope config ignored: {e}")
    if buckets:
        console.print(f"[cyan][*][/cyan] S3 bucket scope: {', '.join(buckets)}")
    if accounts:
        console.print(f"[cyan][*][/cyan] AWS account scope: {', '.join(accounts)}")

    # --- Hybrid input: parse any imported traffic (offline - no replay).
    imported: ImportedTraffic | None = None
    if burp_xml or import_har:
        imported = import_traffic(burp_xml=burp_xml, har=import_har)
        console.print(
            f"[cyan][*][/cyan] Imported traffic: {len(imported.endpoints)} endpoint(s), "
            f"{len(imported.tokens)} token(s), {len(imported.s3_links)} S3 link(s)."
        )
        for err in imported.errors:
            console.print(f"[yellow][!][/yellow] Traffic import: {err}")
        # Seed the JWT --token path from an observed bearer token when the user
        # did not supply one explicitly.
        if not token and imported.jwt_tokens:
            token = imported.jwt_tokens[0]
            console.print("[cyan][*][/cyan] JWT: seeded --token from imported bearer token.")

    if iam_file:
        console.print(f"[cyan][*][/cyan] IAM: analyzing {iam_file} ...")
        try:
            principals = load_authorization_details(Path(iam_file))
            if accounts:
                before = len(principals)
                principals = filter_principals_in_scope(principals, accounts)
                if len(principals) < before:
                    console.print(
                        f"[cyan][*][/cyan] IAM: {before - len(principals)} principal(s) "
                        "dropped as out-of-account-scope."
                    )
            graph = build_privesc_graph(principals)
            iam_findings = find_privesc_paths(graph, principals)
            all_findings += iam_findings
            console.print(f"[cyan][*][/cyan] IAM: {len(iam_findings)} finding(s).")
        except Exception as e:
            # A malformed/partial authorization-details file (missing keys,
            # bad JSON) must not abort the whole scan - skip IAM and continue
            # with the rest of the modules.
            console.print(f"[yellow][!][/yellow] IAM analysis skipped: {e}")

    # When no domain was supplied but imported traffic carried endpoints, adopt
    # the first imported endpoint's host as the scan target so those endpoints
    # can be scanned. Active discovery is skipped in that case (the tester chose
    # import mode, not "go probe this live target").
    user_supplied_domain = bool(domain)
    if not domain and imported and imported.endpoints:
        first_host = urlparse(imported.endpoints[0]).hostname
        if first_host:
            domain = first_host
            console.print(
                f"[cyan][*][/cyan] No domain given; scoping to imported host [bold]{first_host}[/bold]."
            )

    if not domain:
        _finish(all_findings, output, show_leak)
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
    scope = ScopeManager(
        root_domain,
        allow_local_targets=allow_local,
        excluded_hosts=excluded,
        s3_buckets=buckets,
        aws_accounts=accounts,
    )
    rate_limiter = AdaptiveRateLimiter()
    http_engine = HttpEngine(scope_manager=scope, rate_limiter=rate_limiter)

    # A DiscoveryReport always exists so BOLA (which consumes the report
    # object) has one to work with, even in pure import mode.
    report = DiscoveryReport(target=target_url)
    endpoints: list[str] = []
    if user_supplied_domain:
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
        endpoints = list(payload.get("endpoints", []))
        console.print(f"[cyan][*][/cyan] {len(endpoints)} endpoint(s) discovered.")

    # Merge in imported endpoints that fall inside the authorized scope. They
    # are added to the same per-endpoint queue the scanners loop over below
    # (and into the report so BOLA sees them too); out-of-scope ones are
    # dropped (and reported) rather than scanned.
    if imported and imported.endpoints:
        seen = set(endpoints)
        kept = dropped = 0
        for ep in imported.endpoints:
            if not scope.is_in_scope(ep):
                dropped += 1
                continue
            report.add_endpoint(ep, source="traffic_import")
            if ep not in seen:
                endpoints.append(ep)
                seen.add(ep)
                kept += 1
        console.print(
            f"[cyan][*][/cyan] Imported endpoints added to queue: {kept}"
            + (f" ({dropped} out-of-scope, skipped)" if dropped else "")
        )

    if not endpoints:
        console.print("[yellow][-][/yellow] No endpoints found, stopping here.")
        _finish(all_findings, output, show_leak)
        return

    canary = OOBCanaryServer() if blind else None
    if canary:
        console.print(f"[cyan][*][/cyan] OOB canary running locally: {canary.base_url}")

    # Track which (scanner, asset) pairs the broad detection pass already ran,
    # so the finding-driven follow-up step below never re-runs the same test.
    scanned: set[tuple[str, str]] = set()

    try:
        for ep_url in endpoints:
            console.print(f"[cyan]  ->[/cyan] {ep_url}")

            try:
                authz_scanner = AuthzBypassScanner(
                    scope_manager=scope,
                    http_engine=http_engine,
                    confirm_destructive=confirm_destructive,
                )
                all_findings += await run_scanner(
                    authz_scanner,
                    AuthzBypassTarget(
                        url=ep_url,
                        include_destructive_methods=confirm_destructive,
                    ),
                )
                all_findings += await run_scanner(
                    CorsMisconfigScanner(scope_manager=scope, http_engine=http_engine),
                    CorsMisconfigTarget(url=ep_url),
                )
                scanned.add(("authz_bypass", ep_url))
                scanned.add(("cors_misconfig", ep_url))
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
                    all_findings += await run_scanner(ssrf_scanner, ssrf_target)
                    scanned.add(("ssrf_imds", ep_url))
            except ScannerConfirmationError as e:
                console.print(f"[yellow]    [!][/yellow] SSRF skipped: {e}")
            except Exception as e:
                console.print(f"[yellow]    [!][/yellow] Parameter discovery failed: {e}")

            if token:
                try:
                    jwt_target = JwtTarget(url=ep_url, sample_token=token)
                    all_findings += await run_scanner(
                        JwtTamperScanner(scope_manager=scope, http_engine=http_engine),
                        jwt_target,
                    )
                    scanned.add(("jwt_tamper", ep_url))
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

    # --- Finding-driven follow-ups: run (or recommend) only the deeper tests
    # the detection pass actually justified - see risk/triggers.py. The broad
    # pass above already covered its own (scanner, asset) pairs, so follow-ups
    # that duplicate it are skipped; the value grows as later phases add
    # scanners (S3, API-keys) whose findings trigger new deep tests. ---
    context = TriggerContext(
        has_token=bool(token),
        has_identities=len(identities) >= 2,
        has_canary=False,  # the OOB canary is already stopped here; blind escalation is advised, not auto-run
        has_iam_file=bool(iam_file),
    )
    followups = derive_followups(all_findings, context)
    pending = [fu for fu in followups if (fu.scanner, fu.asset) not in scanned]
    if pending:
        console.print(f"\n[cyan][*][/cyan] Finding-driven follow-ups: {len(pending)}")
        for fu in pending:
            if fu.scanner == "jwt_tamper" and token:
                try:
                    all_findings += await run_scanner(
                        JwtTamperScanner(scope_manager=scope, http_engine=http_engine),
                        JwtTarget(url=fu.asset, sample_token=token),
                    )
                    scanned.add((fu.scanner, fu.asset))
                    console.print(f"[cyan]    [>][/cyan] ran {fu.scanner} on {fu.asset} — {fu.reason}")
                except Exception as e:
                    console.print(f"[yellow]    [!][/yellow] follow-up {fu.scanner} failed: {e}")
            else:
                # No standalone target available to auto-run this one here;
                # surface it as a justified next step for the analyst.
                console.print(f"[cyan]    [>][/cyan] recommend {fu.scanner} on {fu.asset} — {fu.reason}")

    _finish(all_findings, output, show_leak)


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


def _finish(findings: list, output: str, show_leak: bool = False) -> None:
    # Correlation/dedup pass before anything is displayed or written, so the
    # console summary and the report agree and neither shows the same issue
    # twice.
    findings = apply_deterministic_rules(findings)

    # Rank by risk (severity x confidence) so the most important findings are
    # at the top of both the table and the JSON report.
    findings.sort(
        key=lambda f: compute_risk_score(f.severity, f.confidence), reverse=True
    )

    console.print(f"\n[green][+][/green] Total findings: {len(findings)}\n")
    if findings:
        table = Table(title="All findings (highest risk first)")
        table.add_column("Risk", justify="right")
        table.add_column("Category", style="red")
        table.add_column("Asset", overflow="fold")
        table.add_column("Severity")
        for f in findings:
            risk = compute_risk_score(f.severity, f.confidence)
            table.add_row(f"{risk:.1f}", f.category, str(f.asset), f.severity)
        console.print(table)

    path = export_json(findings, Path(output), redact=not show_leak)
    if show_leak:
        console.print(
            "[yellow][!][/yellow] --show-leak: evidence written UNREDACTED "
            "(captured secrets are visible in the report)."
        )
    console.print(f"\n[green][+][/green] Unified report: {path.resolve()}")
