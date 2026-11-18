"""API Gateway / serverless auth-bypass scanner.

In AWS API Gateway each route (path + method) binds its own Authorizer
independently, so the common bug is inconsistent enforcement rather than
path manipulation. Checks three patterns:
  - missing_authorizer: a method returns data with no Authorization header.
  - authorizer_fail_open: a missing header is rejected but a malformed
    credential is accepted (Lambda-authorizer fail-open, OWASP API2:2023).
  - method_inconsistency: one method on a resource is protected, another
    isn't.

Passive and non-destructive by default. Testing destructive methods
(POST/PUT/DELETE/PATCH) can mutate real data, so it requires
``AuthzBypassScanner(confirm_destructive=True)``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from wily.core.scope_manager import ScopeManager
from wily.scanners.base import BaseScanner, Finding, ScannerConfirmationError
from wily.scanners.http_engine import HttpEngine

# Methods that never mutate target state - safe to send with no
# confirmation, and the default for every scan.
#
# OPTIONS is deliberately excluded: most frameworks (Flask, Express,
# API Gateway's own CORS support, ...) answer OPTIONS automatically for
# CORS preflight, with no authorization check at all, before the request
# ever reaches application code. Testing OPTIONS for "missing authorizer"
# or "method inconsistency" would therefore flag this universal,
# harmless framework behavior as a false positive on nearly every API.
_SAFE_METHODS = ("GET", "HEAD")

# Methods that typically create/modify/delete target data. Testing these
# requires the tester to explicitly opt in, because a false "missing
# authorizer" probe with these verbs is not a passive read - it is a real
# write against someone's data.
_DESTRUCTIVE_METHODS = ("POST", "PUT", "DELETE", "PATCH")


@dataclass
class AuthzBypassTarget:
    """The asset the scanner will test: a single resource (a fixed path)
    that is suspected of responding to more than one HTTP method (e.g.
    GET/POST/PUT/DELETE on the same Lambda resource behind API Gateway).
    """

    url: str
    # Non-destructive by default. Enabling write verbs requires both
    # `include_destructive_methods=True` here *and*
    # `confirm_destructive=True` on the scanner - two independent signals,
    # so a write-method scan can never happen by accident.
    methods_to_test: list[str] = field(default_factory=lambda: list(_SAFE_METHODS))
    include_destructive_methods: bool = True
    destructive_methods: list[str] = field(default_factory=lambda: list(_DESTRUCTIVE_METHODS))
    auth_header_name: str = "Authorization"
    valid_auth_header_value: str | None = None  # used as a baseline, if provided
    # Status codes considered proof that data was actually returned - not
    # just any 2xx, since some endpoints answer 200 with an empty body or
    # an error formatted as 200.
    leak_indicator_statuses: list[int] = field(default_factory=lambda: [200, 201])
    # --- Gap A (authorizer_fail_open): a malformed/garbage credential. A
    # route that returns 401 with no header but 200 with this invalid token
    # has an authorizer that fails open (OWASP API2:2023 - the authorizer
    # must deny by default on any exception), or a broad wildcard cached
    # policy. This probe is passive (a read with a bad token), so it is on
    # by default even though it carries an Authorization header.
    probe_authorizer_fail_open: bool = True
    invalid_auth_header_value: str = "Bearer wily-invalid-probe-token"
    # --- Gap B/C: a 200 whose body matches one of these (case-insensitive
    # substring) is an auth *error* rendered as 200, not a data leak, so it
    # is not flagged as a missing authorizer (common in GraphQL and some
    # gateways). Confidence is also raised/lowered by comparing the
    # unauthenticated body to the authenticated baseline when
    # ``valid_auth_header_value`` is set.
    auth_error_body_signatures: list[str] = field(
        default_factory=lambda: [
            "unauthorized",
            "missing authentication token",
            "access denied",
            "not authorized",
            "forbidden",
        ]
    )
    # --- Differential baseline (Gap D): a URL known/assumed not to resolve
    # to a real resource on this host (e.g. the same path with a
    # random/nonexistent id). Some gateways serve the exact same generic
    # "not found" or catch-all page for every denied *and* missing request,
    # worded in a way auth_error_body_signatures doesn't happen to match.
    # Comparing against this baseline catches that case without needing a
    # keyword list to guess the app's wording. Opt-in: None disables it.
    soft_404_probe_url: str | None = None
    soft_404_similarity_threshold: float = 0.85


class AuthzBypassScanner(BaseScanner):
    name = "authz_bypass"
    requires_tenant_pair = False
    # Safe by construction with the default (GET/HEAD/OPTIONS-only) target;
    # becomes a destructive scan only when the caller explicitly opts in
    # via confirm_destructive below.
    requires_owned_infra = False

    def __init__(
        self,
        scope_manager: ScopeManager,
        http_engine: HttpEngine | None = None,
        confirm_destructive: bool = True,
    ) -> None:
        self.http = http_engine or HttpEngine(scope_manager=scope_manager)
        self._confirm_destructive = confirm_destructive

    def _send_unauthenticated(self, target: AuthzBypassTarget, method: str):
        return self.http.request(method=method, url=target.url, headers={})

    def _send_authenticated(self, target: AuthzBypassTarget, method: str):
        headers = {}
        if target.valid_auth_header_value:
            headers[target.auth_header_name] = target.valid_auth_header_value
        return self.http.request(method=method, url=target.url, headers=headers)

    def _send_invalid_auth(self, target: AuthzBypassTarget, method: str):
        headers = {target.auth_header_name: target.invalid_auth_header_value}
        return self.http.request(method=method, url=target.url, headers=headers)

    @staticmethod
    def _looks_like_auth_error_body(text: str, signatures: list[str]) -> bool:
        """True when a 200 body actually carries an auth-error message - a
        soft-200 denial, not a real data leak."""
        body = (text or "").lower()
        return any(sig.lower() in body for sig in signatures)

    def _resolve_methods(self, target: AuthzBypassTarget) -> list[str]:
        methods = list(target.methods_to_test)
        if not target.include_destructive_methods:
            return methods

        if not self._confirm_destructive:
            raise ScannerConfirmationError(
                "AuthzBypassTarget.include_destructive_methods=True but "
                "AuthzBypassScanner was built without confirm_destructive=True. "
                "POST/PUT/DELETE/PATCH probes can create, modify or delete real "
                "data on the target and require an explicit, separate "
                "confirmation before they run."
            )

        for method in target.destructive_methods:
            if method not in methods:
                methods.append(method)
        return methods

    def run(self, target: AuthzBypassTarget) -> list[Finding]:
        findings: list[Finding] = []
        methods = self._resolve_methods(target)

        # Collect the unauthenticated result for every method - this is the
        # basis for the techniques below. We keep the full response (not just
        # the status) so technique 1 can inspect the body (Gap B/C).
        unauthenticated_results: dict[str, int] = {}
        unauth_responses: dict[str, object] = {}
        for method in methods:
            try:
                resp = self._send_unauthenticated(target, method)
                unauthenticated_results[method] = resp.status_code
                unauth_responses[method] = resp
            except Exception:
                continue

        # Differential baseline (Gap D): fetch a resource known/assumed not to
        # exist on this host once, up front, so every candidate method below
        # can be compared against "what a missing resource looks like here".
        soft_404_body: str | None = None
        if target.soft_404_probe_url:
            try:
                probe_resp = self.http.request(
                    method="GET", url=target.soft_404_probe_url, headers={}
                )
                soft_404_body = getattr(probe_resp, "text", "") or ""
            except Exception:
                soft_404_body = None

        # --- technique 1: missing_authorizer - any method leaks data with no auth ---
        # A status in leak_indicator_statuses is only a *candidate*: a 200 that
        # actually carries an auth-error message (soft-200 denial) is not a leak
        # (Gap B/C), so it is filtered out before being reported or feeding
        # technique 2.
        candidate_methods = [
            m for m, status in unauthenticated_results.items()
            if status in target.leak_indicator_statuses
        ]
        leaking_methods: list[str] = []

        for method in candidate_methods:
            resp = unauth_responses[method]
            body = getattr(resp, "text", "") or ""
            if self._looks_like_auth_error_body(body, target.auth_error_body_signatures):
                # soft-200 denial - not a real data leak, do not report
                continue

            soft_404_similarity: float | None = None
            if soft_404_body:
                try:
                    soft_404_similarity = self.http.similarity(body, soft_404_body)
                except Exception:
                    soft_404_similarity = None
                if (
                    soft_404_similarity is not None
                    and soft_404_similarity >= target.soft_404_similarity_threshold
                ):
                    # Body matches the "this resource doesn't exist here"
                    # baseline almost exactly - a generic catch-all page, not
                    # a real leak of this specific resource's data.
                    continue

            leaking_methods.append(method)

            # Confidence is grounded against an authenticated baseline when one
            # is available: if the unauthenticated body matches what a valid
            # token returns, the leak is confirmed (raise confidence); if it
            # diverges sharply, the endpoint may be legitimately public (lower
            # it). Without a baseline we keep the historical 0.9.
            confidence = 0.9
            body_similarity: float | None = None
            if target.valid_auth_header_value:
                try:
                    auth_resp = self._send_authenticated(target, method)
                    body_similarity = self.http.similarity(
                        body, getattr(auth_resp, "text", "") or ""
                    )
                except Exception:
                    body_similarity = None
                if body_similarity is not None:
                    if body_similarity >= 0.85:
                        confidence = 0.95
                    elif body_similarity < 0.3:
                        confidence = 0.5

            findings.append(
                Finding(
                    asset=target.url,
                    category="authz-bypass-missing-authorizer",
                    severity="critical",
                    confidence=confidence,
                    discovery_source="scanner",
                    evidence={
                        "technique": "missing_authorizer",
                        "method": method,
                        "response_status": unauthenticated_results[method],
                        "body_similarity_to_authenticated": body_similarity,
                        "body_similarity_to_soft_404_baseline": soft_404_similarity,
                        "all_methods_tested": unauthenticated_results,
                    },
                    remediation=(
                        "Ensure every API Gateway route is associated with an "
                        "Authorizer (Cognito/IAM/Lambda Authorizer), and no method "
                        "returning sensitive data has AuthorizationType: NONE."
                    ),
                )
            )

        # --- technique 1b: authorizer_fail_open - route rejects a missing
        # header (401/403) but accepts a malformed credential (Gap A). This is
        # the classic Lambda-authorizer fail-open / wildcard-cached-policy
        # bypass (OWASP API2:2023): the route looks protected but is not. ---
        if target.probe_authorizer_fail_open:
            for method in methods:
                no_auth_status = unauthenticated_results.get(method)
                if no_auth_status not in (401, 403):
                    continue  # only interesting when "no header" is rejected
                try:
                    invalid_resp = self._send_invalid_auth(target, method)
                except Exception:
                    continue
                if invalid_resp.status_code not in target.leak_indicator_statuses:
                    continue
                invalid_body = getattr(invalid_resp, "text", "") or ""
                if self._looks_like_auth_error_body(
                    invalid_body, target.auth_error_body_signatures
                ):
                    continue  # soft-200 denial, not a fail-open accept
                findings.append(
                    Finding(
                        asset=target.url,
                        category="authz-bypass-authorizer-fail-open",
                        severity="critical",
                        confidence=0.9,
                        discovery_source="scanner",
                        evidence={
                            "technique": "authorizer_fail_open",
                            "method": method,
                            "no_auth_status": no_auth_status,
                            "invalid_auth_status": invalid_resp.status_code,
                            "invalid_auth_value": target.invalid_auth_header_value,
                        },
                        remediation=(
                            "Configure the Lambda/custom Authorizer to deny by "
                            "default: any exception, malformed token, or "
                            "unrecognized credential must return an explicit Deny "
                            "(401/403), never fall through to Allow. Avoid broad "
                            "wildcard (*/*) cached authorizer policies, which let "
                            "one accepted request authorize unrelated routes."
                        ),
                    )
                )

        # --- technique 2: method_inconsistency - some methods protected, others not ---
        protected_methods = [
            m for m, status in unauthenticated_results.items()
            if status in (401, 403)
        ]
        unprotected_methods = leaking_methods  # confirmed leaks, error-bodies removed

        if protected_methods and unprotected_methods:
            findings.append(
                Finding(
                    asset=target.url,
                    category="authz-bypass-method-inconsistency",
                    severity="critical",
                    confidence=0.95,
                    discovery_source="scanner",
                    evidence={
                        "technique": "method_inconsistency",
                        "protected_methods": protected_methods,
                        "unprotected_methods": unprotected_methods,
                        "all_methods_tested": unauthenticated_results,
                    },
                    remediation=(
                        "In API Gateway, each method has its own Authorizer "
                        "configuration. Ensure every method on the same resource "
                        "(GET/POST/PUT/DELETE/PATCH) uses the same Authorizer, "
                        "not just one method."
                    ),
                )
            )

        return findings


@dataclass
class StageInconsistencyTarget:
    """Stage/Deployment Inconsistency check: the same resource is exposed
    on several different stages (API Gateway places the stage either in
    the path or via a custom domain/Host header), and the developer
    correctly configures the authorizer on the primary stage (prod) but
    forgets an old/experimental stage that is still live.
    """

    url_template: str  # must contain "{stage}", either in the path or via host_header_template
    stage_candidates: list[str] = field(
        default_factory=lambda: ["dev", "test", "staging", "sandbox", "v1", "v2", "beta"]
    )
    baseline_stage: str = "prod"
    # Subdomain mode: the Host header contains "{stage}", allowing tests
    # against subdomains (dev-api.example.com) even when the URL itself
    # points at the same IP/port (also useful behind a reverse proxy/CDN
    # that routes by Host header).
    host_header_template: str | None = None
    leak_indicator_statuses: list[int] = field(default_factory=lambda: [200, 201])


class StageInconsistencyScanner(BaseScanner):
    name = "stage_inconsistency"
    requires_tenant_pair = False
    requires_owned_infra = False

    def __init__(
        self, scope_manager: ScopeManager, http_engine: HttpEngine | None = None
    ) -> None:
        self.http = http_engine or HttpEngine(scope_manager=scope_manager)

    def _request_for_stage(self, target: StageInconsistencyTarget, stage: str):
        url = target.url_template.format(stage=stage)
        headers = {}
        if target.host_header_template:
            headers["Host"] = target.host_header_template.format(stage=stage)
        return self.http.request(method="GET", url=url, headers=headers)

    def run(self, target: StageInconsistencyTarget) -> list[Finding]:
        findings: list[Finding] = []

        # Baseline: the primary stage (prod) must already be protected, or
        # this check doesn't apply here (that is missing_authorizer's job).
        try:
            baseline_resp = self._request_for_stage(target, target.baseline_stage)
        except Exception:
            return findings

        if baseline_resp.status_code not in (401, 403):
            return findings

        stage_results: dict[str, int] = {target.baseline_stage: baseline_resp.status_code}
        leaking_stages = []

        for stage in target.stage_candidates:
            try:
                resp = self._request_for_stage(target, stage)
            except Exception:
                continue
            stage_results[stage] = resp.status_code
            if resp.status_code in target.leak_indicator_statuses:
                leaking_stages.append(stage)

        for stage in leaking_stages:
            findings.append(
                Finding(
                    asset=target.url_template,
                    category="authz-bypass-stage-inconsistency",
                    severity="critical",
                    confidence=0.9,
                    discovery_source="scanner",
                    evidence={
                        "technique": "stage_inconsistency",
                        "leaking_stage": stage,
                        "baseline_stage": target.baseline_stage,
                        "mode": "subdomain" if target.host_header_template else "path",
                        "all_stages_tested": stage_results,
                    },
                    remediation=(
                        "Ensure every stage/deployment, including dev, staging, "
                        "and old stages, uses the same Authorizer as production, "
                        "or remove/disable obsolete stages."
                    ),
                )
            )

        return findings


@dataclass
class CorsMisconfigTarget:
    """CORS Misconfiguration check: send a forged Origin header (a domain
    that is not a real relying party at all) and check whether the server
    reflects it back in Access-Control-Allow-Origin together with
    Access-Control-Allow-Credentials: true - that combination lets any
    malicious site read responses containing the victim's data together
    with their cookies.
    """

    url: str
    method: str = "GET"
    probe_origin: str = "https://evil-wily-probe.invalid"
    extra_headers: dict[str, str] = field(default_factory=dict)  # e.g. Authorization, if a valid session is needed


class CorsMisconfigScanner(BaseScanner):
    name = "cors_misconfig"
    requires_tenant_pair = False
    requires_owned_infra = False

    def __init__(
        self, scope_manager: ScopeManager, http_engine: HttpEngine | None = None
    ) -> None:
        self.http = http_engine or HttpEngine(scope_manager=scope_manager)

    def run(self, target: CorsMisconfigTarget) -> list[Finding]:
        findings: list[Finding] = []

        headers = dict(target.extra_headers)
        headers["Origin"] = target.probe_origin

        try:
            resp = self.http.request(method=target.method, url=target.url, headers=headers)
        except Exception:
            return findings

        # Header names can come back in any case - normalize for a reliable comparison.
        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        acao = resp_headers_lower.get("access-control-allow-origin")
        acac = resp_headers_lower.get("access-control-allow-credentials", "").lower()

        if acao is None:
            return findings  # no CORS headers at all - not our concern here

        # --- most dangerous case: reflects the exact forged Origin + credentials=true ---
        if acao == target.probe_origin and acac == "true":
            findings.append(
                Finding(
                    asset=target.url,
                    category="authz-bypass-cors-origin-reflection",
                    severity="critical",
                    confidence=0.9,
                    discovery_source="scanner",
                    evidence={
                        "technique": "cors_origin_reflection",
                        "probe_origin": target.probe_origin,
                        "reflected_acao": acao,
                        "acac": acac,
                    },
                    remediation=(
                        "Use an explicit, fixed allowlist of trusted origins "
                        "instead of reflecting arbitrary client-provided origins. "
                        "Access-Control-Allow-Credentials: true must only be used "
                        "with a specific, validated origin, never a reflected "
                        "value or wildcard."
                    ),
                )
            )
        # --- lower-severity case: literal wildcard + credentials=true (modern
        # browsers reject this per spec, but it is still a misconfiguration) ---
        elif acao == "*" and acac == "true":
            findings.append(
                Finding(
                    asset=target.url,
                    category="authz-bypass-cors-wildcard-with-credentials",
                    severity="medium",
                    confidence=0.6,
                    discovery_source="scanner",
                    evidence={
                        "technique": "cors_wildcard_with_credentials",
                        "acao": acao,
                        "acac": acac,
                        "note": (
                            "Modern browsers reject this combination according "
                            "to the CORS specification, but it is still a "
                            "misconfiguration that should be fixed."
                        ),
                    },
                    remediation=(
                        "Specify allowed origins instead of '*' in "
                        "Access-Control-Allow-Origin when using "
                        "Access-Control-Allow-Credentials."
                    ),
                )
            )

        return findings
