"""The unified orchestrator: ``wily scan <domain>``.

Runs Auth Bypass and SSRF levels 1+2 automatically against every endpoint
it discovers. JWT Tampering, BOLA, IAM Privesc, and blind SSRF (level 4)
each enable themselves once their required input is supplied (--token,
--identity, --iam-file, --blind respectively).

Safety gates: destructive-method auth-bypass testing needs
--confirm-destructive; SSRF/IMDS needs --confirm-owned-infra, since it
must only target infrastructure the tester owns.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table

from wily.core.oob_canary import OOBCanaryServer
from wily.core.rate_limiter import AdaptiveRateLimiter
from wily.core.scope_manager import (
    ScopeError,
    ScopeManager,
    extract_bucket_name,
    load_scope_config,
)
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
from wily.recon.cloud_enum import (
    azure_account_name,
    generate_candidates,
    keyword_from_domain,
    load_mutations,
)
from wily.recon.live_filter import filter_live_assets
from wily.recon.traffic_import import ImportedTraffic, import_traffic
from wily.report.html_report import export_html
from wily.report.json_report import export_json
from wily.report.sarif_report import export_sarif
from wily.scanners.s3_bucket import S3BucketScanner, S3BucketTarget, s3_host_for
from wily.scanners.secret_scan import (
    SecretScanScanner,
    SecretScanTarget,
    SecretSource,
)
from wily.scanners.takeover import TakeoverScanner, TakeoverTarget
from wily.risk.ml.dedup import cluster_by_endpoint_hash, deduplicate
from wily.risk.ml.feedback import FeedbackStore
from wily.risk.ml.ranker import rank_findings
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
from wily.scanners.cloud_storage import CloudStorageScanner, CloudStorageTarget
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
    report_formats: list[str] | None = None,
    confirm_destructive: bool = True,
    confirm_owned_infra: bool = True,
    confirm_s3_writes: bool = False,
    probe_live: bool = False,
    cloud_enum: bool = False,
    cloud_keywords: list[str] | None = None,
    cloud_enum_wordlist: str | None = None,
    cloud_enum_max: int = 300,
    show_leak: bool = False,
    burp_xml: str | None = None,
    import_har: str | None = None,
    scope_buckets: list[str] | None = None,
    scope_accounts: list[str] | None = None,
    scope_config: str | None = None,
    feedback_store: str | None = None,
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
        _finish(all_findings, output, show_leak, report_formats, feedback_store)
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

    # --- Live-asset filtering (Phase 4, HTTPX-style). Before any expensive
    # scanner runs, collapse exact + near-identical endpoints (same route with a
    # different object id) and, optionally, drop endpoints that don't answer a
    # cheap liveness probe. Dedup is always free; the probe is opt-in
    # (--probe-live) and goes through the shared, scope-enforcing HttpEngine. ---
    if endpoints:
        before = len(endpoints)
        lf = filter_live_assets(
            endpoints,
            scope=scope,
            http_engine=http_engine if probe_live else None,
            probe=probe_live,
        )
        endpoints = lf.kept
        if lf.dropped:
            summary = []
            if lf.collapsed:
                summary.append(f"{lf.collapsed} duplicate")
            if lf.out_of_scope:
                summary.append(f"{len(lf.out_of_scope)} out-of-scope")
            if lf.dead:
                summary.append(f"{len(lf.dead)} dead")
            console.print(
                f"[cyan][*][/cyan] Live-asset filter: {before} -> {len(endpoints)} "
                f"target(s) ({', '.join(summary)} dropped)."
            )

    # Track which (scanner, asset) pairs ran, so the finding-driven follow-up
    # step never re-runs the same test. Defined before the cloud scanners below
    # so they can register into it too.
    scanned: set[tuple[str, str]] = set()

    # --- Cloud scanners (S3 misconfig, secrets, takeover). These are not tied
    # to the per-endpoint API loop: S3 runs off bucket references, secrets off
    # discovered JS + imported traffic, takeover off discovered hosts. They run
    # even when no API endpoints were found (e.g. a pure bucket-scope scan). ---
    s3_scan_targets: dict[str, tuple] = {}  # asset -> (engine, target) for follow-ups
    await _run_cloud_scanners(
        all_findings=all_findings,
        scanned=scanned,
        s3_scan_targets=s3_scan_targets,
        endpoints=endpoints,
        imported=imported,
        buckets=buckets,
        root_domain=root_domain,
        scope=scope,
        http_engine=http_engine,
        rate_limiter=rate_limiter,
        allow_local=allow_local,
        confirm_s3_writes=confirm_s3_writes,
    )

    # --- Cloud resource enumeration (cloud_enum-style). Opt-in: generate
    # candidate names from the target keyword(s) and probe AWS S3 / Azure Blob /
    # GCP for existing/open storage, auto-handing AWS hits to the deep s3_bucket
    # scanner. Keyword-driven, so it runs even with no HTTP endpoints. ---
    if cloud_enum:
        await _run_cloud_enum(
            all_findings=all_findings,
            scanned=scanned,
            s3_scan_targets=s3_scan_targets,
            root_domain=root_domain,
            keywords=cloud_keywords or [],
            wordlist_path=cloud_enum_wordlist,
            max_candidates=cloud_enum_max,
            rate_limiter=rate_limiter,
            allow_local=allow_local,
        )

    if not endpoints:
        if not all_findings:
            console.print("[yellow][-][/yellow] No endpoints found, stopping here.")
        _finish(all_findings, output, show_leak, report_formats, feedback_store)
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
        confirm_s3_writes=confirm_s3_writes,
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
            elif fu.scanner == "s3_permcheck" and fu.asset in s3_scan_targets:
                # Deeper S3 step: re-run the bucket with confirm_writes=True so
                # the (read-only, ACL-derived) write/delete permission check is
                # evaluated now that a public finding justified it.
                try:
                    engine, s3_target = s3_scan_targets[fu.asset]
                    all_findings += await run_scanner(
                        S3BucketScanner(
                            scope_manager=scope,
                            http_engine=engine,
                            confirm_writes=True,
                        ),
                        s3_target,
                    )
                    scanned.add((fu.scanner, fu.asset))
                    console.print(f"[cyan]    [>][/cyan] ran s3 permission-check on {fu.asset} — {fu.reason}")
                except Exception as e:
                    console.print(f"[yellow]    [!][/yellow] follow-up {fu.scanner} failed: {e}")
            else:
                # No standalone target available to auto-run this one here;
                # surface it as a justified next step for the analyst.
                console.print(f"[cyan]    [>][/cyan] recommend {fu.scanner} on {fu.asset} — {fu.reason}")

    _finish(all_findings, output, show_leak, report_formats, feedback_store)


_BARE_BUCKET_RE = re.compile(r"[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]")


def _concrete_bucket(ref: str) -> str | None:
    """Resolve a bucket reference (name / s3:// URI / S3 URL) to a concrete
    bucket name, or None for a glob pattern or non-bucket string (a glob like
    'target-*' is a scope filter, not something that can be probed)."""
    name = extract_bucket_name(ref)
    if name:
        return name
    r = (ref or "").strip().lower()
    if "*" in r or "?" in r:
        return None
    return r if _BARE_BUCKET_RE.fullmatch(r) else None


def _s3_object_key(ref: str) -> str | None:
    """Best-effort object key from an s3:// URI or an S3 URL path."""
    if not isinstance(ref, str):
        return None
    v = ref.strip()
    if v.lower().startswith("s3://"):
        rest = v[5:].split("?", 1)[0]
        parts = rest.split("/", 1)
        return parts[1] if len(parts) == 2 and parts[1] else None
    if "amazonaws.com" in v.lower():
        parsed = urlparse(v if "://" in v else "//" + v)
        host = (parsed.hostname or "").lower()
        path = parsed.path.lstrip("/")
        if not path:
            return None
        first_label = host.split(".", 1)[0]
        # Virtual-hosted host is "<bucket>.s3...": the whole path is the key.
        # Path-style host is "s3...": the first path segment is the bucket, the
        # remainder is the key.
        if first_label and first_label != "s3" and not first_label.startswith("s3-"):
            return path or None
        parts = path.split("/", 1)
        return parts[1] if len(parts) == 2 and parts[1] else None
    return None


def _build_s3_engine(
    bucket: str, region: str | None, allow_local: bool, rate_limiter
) -> "HttpEngine | None":
    """An HttpEngine scoped to the bucket's S3 host. S3 endpoints are public,
    so the engine's own scope guard permits them while still refusing any
    non-S3 host; returns None if the host is not a usable scope target."""
    host = s3_host_for(bucket, region)
    try:
        s3_scope = ScopeManager(host, allow_local_targets=allow_local)
    except ScopeError:
        return None
    return HttpEngine(scope_manager=s3_scope, rate_limiter=rate_limiter)


def _cname_resolver(host: str) -> str | None:
    """Best-effort CNAME lookup via the stdlib (no extra dependency). The alias
    list from ``gethostbyname_ex`` carries the CNAME chain; the last alias is
    the closest-to-target canonical name. Returns None on any failure."""
    import socket

    try:
        _name, aliases, _ips = socket.gethostbyname_ex(host)
    except Exception:
        return None
    return aliases[-1] if aliases else None


async def _run_cloud_scanners(
    *,
    all_findings: list,
    scanned: set,
    s3_scan_targets: dict,
    endpoints: list[str],
    imported: "ImportedTraffic | None",
    buckets: tuple[str, ...],
    root_domain: str,
    scope: ScopeManager,
    http_engine: HttpEngine,
    rate_limiter,
    allow_local: bool,
    confirm_s3_writes: bool,
) -> None:
    """Run the Phase 3 cloud scanners and fold their findings into the run.

    Each scanner is isolated in its own try/except so a failure in one (or a
    single bad target) never aborts the scan.
    """
    # ---- S3 bucket misconfiguration ------------------------------------
    # Candidate references: explicit bucket scope + imported s3 links + any S3
    # URLs discovered among endpoints. Deduplicated by concrete bucket name.
    s3_refs: list[str] = list(buckets)
    if imported and imported.s3_links:
        s3_refs += imported.s3_links
    s3_refs += [ep for ep in endpoints if extract_bucket_name(ep)]

    seen_buckets: set[str] = set()
    for ref in s3_refs:
        bucket = _concrete_bucket(ref)
        if not bucket or bucket in seen_buckets:
            continue
        seen_buckets.add(bucket)
        # Respect bucket scope when configured.
        if scope.has_bucket_scope and not scope.is_bucket_in_scope(ref):
            console.print(f"[yellow]    [!][/yellow] S3 bucket out of scope, skipped: {bucket}")
            continue
        engine = _build_s3_engine(bucket, None, allow_local, rate_limiter)
        if engine is None:
            continue
        target = S3BucketTarget(bucket=bucket, sample_object_key=_s3_object_key(ref))
        try:
            found = await run_scanner(
                S3BucketScanner(
                    scope_manager=scope, http_engine=engine, confirm_writes=False
                ),
                target,
            )
            all_findings += found
            scanned.add(("s3_bucket", f"s3://{bucket}"))
            # Stash for a possible write-permission follow-up (keyed by the
            # finding asset, which is "s3://<bucket>").
            s3_scan_targets[f"s3://{bucket}"] = (engine, target)
            if found:
                console.print(f"[cyan]    [*][/cyan] S3 {bucket}: {len(found)} finding(s).")
        except Exception as e:
            console.print(f"[yellow]    [!][/yellow] S3 scan failed for {bucket}: {e}")

    # ---- Secrets / API-key exposure ------------------------------------
    secret_sources: list[SecretSource] = []
    # Observed auth tokens from an imported capture are themselves exposed
    # credentials; wrap each so the detector sees an Authorization context.
    for tok in (imported.tokens if imported else []):
        secret_sources.append(
            SecretSource(
                label="imported-traffic-token",
                content=f"Authorization: Bearer {tok}",
                location="imported-traffic",
            )
        )
    # Discovered JS bundles are the prime place hardcoded keys leak; fetch the
    # in-scope ones and scan their bodies.
    js_urls = [
        ep for ep in endpoints
        if urlparse(ep).path.lower().endswith(".js") and scope.is_in_scope(ep)
    ]
    if secret_sources or js_urls:
        try:
            found = await run_scanner(
                SecretScanScanner(scope_manager=scope, http_engine=http_engine),
                SecretScanTarget(sources=secret_sources, fetch_urls=js_urls),
            )
            all_findings += found
            scanned.add(("secret_scan", root_domain))
            if found:
                console.print(
                    f"[cyan]    [*][/cyan] Secret scan: {len(found)} exposed secret(s) "
                    f"across {len(secret_sources)} source(s) + {len(js_urls)} JS file(s)."
                )
        except Exception as e:
            console.print(f"[yellow]    [!][/yellow] Secret scan failed: {e}")

    # ---- Subdomain / resource takeover ---------------------------------
    hosts: list[str] = []
    seen_hosts: set[str] = set()
    for candidate in [root_domain] + [urlparse(ep).hostname or "" for ep in endpoints]:
        h = (candidate or "").strip().lower()
        if not h or h in seen_hosts or not scope.is_in_scope(h):
            continue
        seen_hosts.add(h)
        hosts.append(h)
    for host in hosts:
        try:
            found = await run_scanner(
                TakeoverScanner(
                    scope_manager=scope,
                    http_engine=http_engine,
                    resolver=_cname_resolver,
                ),
                TakeoverTarget(host=host),
            )
            all_findings += found
            scanned.add(("takeover", host))
            if found:
                console.print(f"[cyan]    [*][/cyan] Takeover indicator on {host}: {len(found)}.")
        except Exception as e:
            console.print(f"[yellow]    [!][/yellow] Takeover scan failed for {host}: {e}")


def _provider_engine_factory(allow_local: bool, rate_limiter):
    """Return ``factory(host) -> HttpEngine`` that builds (and caches) one
    scope-to-that-host engine per provider host. Each engine's own ScopeManager
    permits only its single public cloud host; a host that is not a valid scope
    target yields None (the scanner then skips that provider)."""
    cache: dict[str, "HttpEngine | None"] = {}

    def factory(host: str):
        if host in cache:
            return cache[host]
        try:
            eng = HttpEngine(
                scope_manager=ScopeManager(host, allow_local_targets=allow_local),
                rate_limiter=rate_limiter,
            )
        except ScopeError:
            eng = None
        cache[host] = eng
        return eng

    return factory


async def _run_cloud_enum(
    *,
    all_findings: list,
    scanned: set,
    s3_scan_targets: dict,
    root_domain: str,
    keywords: list[str],
    wordlist_path: str | None,
    max_candidates: int,
    rate_limiter,
    allow_local: bool,
) -> None:
    """Generate candidate names from keyword(s) and probe AWS/Azure/GCP storage.

    AWS hits are handed to the deep ``s3_bucket`` scanner (the "auto -> S3
    scanner" flow); Azure and GCP hits are reported directly. All probes are
    read-only GETs through per-host, scope-enforcing engines.
    """
    kws = [k for k in keywords if k.strip()]
    derived = keyword_from_domain(root_domain)
    if derived and derived not in kws:
        kws.append(derived)
    if not kws:
        console.print("[yellow][!][/yellow] Cloud enum: no usable keyword, skipped.")
        return

    mutations = None
    if wordlist_path:
        try:
            mutations = load_mutations(wordlist_path)
        except OSError as e:
            console.print(f"[yellow][!][/yellow] Cloud enum wordlist ignored: {e}")

    candidates = generate_candidates(kws, mutations, max_candidates=max_candidates)
    console.print(
        f"[cyan][*][/cyan] Cloud enum: {len(candidates)} candidate name(s) from "
        f"keyword(s) {', '.join(kws)} (AWS/Azure/GCP)."
    )

    factory = _provider_engine_factory(allow_local, rate_limiter)
    enum_scanner = CloudStorageScanner(engine_factory=factory)
    aws_hits: set[str] = set()

    for name in candidates:
        target = CloudStorageTarget(name=name, azure_account=azure_account_name(name))
        try:
            found = await run_scanner(enum_scanner, target)
        except Exception as e:
            console.print(f"[yellow]    [!][/yellow] Cloud enum failed for {name}: {e}")
            continue
        if not found:
            continue
        all_findings += found
        scanned.add(("cloud_storage_enum", name))
        for f in found:
            if f.evidence.get("provider") == "aws":
                aws_hits.add(f.evidence.get("bucket") or name)
            console.print(
                f"[cyan]    [*][/cyan] {f.category}: {f.asset}"
            )

    # Auto hand-off: run the deep S3 scanner on every existing AWS bucket found.
    for bucket in sorted(aws_hits):
        asset = f"s3://{bucket}"
        if ("s3_bucket", asset) in scanned:
            continue
        engine = _build_s3_engine(bucket, None, allow_local, rate_limiter)
        if engine is None:
            continue
        s3_target = S3BucketTarget(bucket=bucket)
        try:
            deep = await run_scanner(
                S3BucketScanner(http_engine=engine, confirm_writes=False), s3_target
            )
            all_findings += deep
            scanned.add(("s3_bucket", asset))
            s3_scan_targets[asset] = (engine, s3_target)
            if deep:
                console.print(
                    f"[cyan]    [>][/cyan] s3_bucket deep scan on {bucket}: {len(deep)} finding(s)."
                )
        except Exception as e:
            console.print(f"[yellow]    [!][/yellow] s3_bucket deep scan failed for {bucket}: {e}")


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


_VALID_FORMATS = ("json", "html", "sarif")

# Each writer takes (findings, path, redact=..., preserve_order=...) and the
# extension its output path should carry.
_FORMAT_WRITERS = {
    "json": (export_json, ".json"),
    "html": (export_html, ".html"),
    "sarif": (export_sarif, ".sarif"),
}


def parse_report_formats(raw: list[str] | None) -> list[str]:
    """Normalize --format values (repeatable and/or comma-separated) into an
    ordered, de-duplicated list of known formats. Unknown tokens are dropped
    with a warning; JSON is always included so the default report never
    vanishes."""
    formats: list[str] = []
    for item in raw or []:
        for token in str(item).split(","):
            name = token.strip().lower()
            if not name:
                continue
            if name not in _VALID_FORMATS:
                console.print(f"[yellow][!][/yellow] Unknown --format '{name}', ignored.")
                continue
            if name not in formats:
                formats.append(name)
    if "json" not in formats:
        formats.insert(0, "json")
    return formats


def _report_path(output: Path, fmt: str) -> Path:
    """Where format ``fmt`` is written relative to the user's -o path.

    The requested path keeps its exact name for the format that matches its
    suffix (so JSON stays at ``wily-report.json``); other formats are written
    as siblings with the format's own extension.
    """
    writer, ext = _FORMAT_WRITERS[fmt]
    if output.suffix.lower() == ext:
        return output
    # Strip a known report extension before appending the new one, so
    # "wily-report.json" + html -> "wily-report.html", not ".json.html".
    stem = output
    if output.suffix.lower() in (".json", ".html", ".sarif"):
        stem = output.with_suffix("")
    return stem.with_name(stem.name + ext)


def _write_reports(
    findings: list, output: str, show_leak: bool, report_formats: list[str] | None
) -> None:
    formats = parse_report_formats(report_formats)
    base = Path(output)
    for fmt in formats:
        writer, _ext = _FORMAT_WRITERS[fmt]
        path = _report_path(base, fmt)
        writer(findings, path, redact=not show_leak, preserve_order=True)
        console.print(f"[green][+][/green] {fmt.upper()} report: {path.resolve()}")


def _finish(
    findings: list,
    output: str,
    show_leak: bool = False,
    report_formats: list[str] | None = None,
    feedback_store: str | None = None,
) -> None:
    # Correlation/dedup pass before anything is displayed or written, so the
    # console summary and the report agree and neither shows the same issue
    # twice. In order:
    #   1. exact-duplicate collapse (deterministic rules),
    #   2. near-duplicate clustering on the SAME asset (risk/ml/dedup.deduplicate),
    #   3. endpoint-hash clustering across DIFFERENT assets that normalize to
    #      the same shape (risk/ml/dedup.cluster_by_endpoint_hash),
    #   4. annotate with any prior analyst --valid/--fp decision, if a
    #      feedback store was given (risk/ml/feedback - opt-in, informational
    #      only: it never drops or reorders a finding), then
    #   5. ranking/prioritisation (risk/ml/ranker) - the single source of the
    #      order the table and the JSON report both use.
    findings = apply_deterministic_rules(findings)
    findings = deduplicate(findings)
    findings = cluster_by_endpoint_hash(findings)
    if feedback_store:
        findings = FeedbackStore(feedback_store).apply(findings)
    findings = rank_findings(findings)

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

    if show_leak:
        console.print(
            "[yellow][!][/yellow] --show-leak: evidence written UNREDACTED "
            "(captured secrets are visible in the report)."
        )
    _write_reports(findings, output, show_leak, report_formats)
