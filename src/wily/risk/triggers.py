"""Finding-driven trigger layer.

The orchestrator runs a broad but cheap *detection* pass (auth-bypass, CORS,
parameter discovery). This module turns the findings/indicators from that pass
into the set of *deeper* tests that are actually justified - so an aggressive
or expensive check only runs when an earlier result points at it, instead of
every module running against every asset.

``derive_followups`` is a pure function (findings + context in, follow-up
tasks out) with no I/O, so the decision logic is unit-testable on its own and
the orchestrator just executes whatever it returns. New scanners (e.g. the S3
and API-key modules in later phases) plug in by adding a rule here.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FollowUp:
    """A deeper test that an earlier finding justified running.

    ``scanner`` is a scanner name (matches a scanner's ``name`` attribute).
    ``asset`` is what to run it against. ``reason`` records the indicator that
    triggered it, so the report can explain *why* the deeper test ran.
    """

    scanner: str
    asset: str
    reason: str


@dataclass
class TriggerContext:
    """What the current scan has available, so a rule only fires a follow-up
    that can actually run (e.g. don't trigger JWT tampering with no token)."""

    has_token: bool = False
    has_identities: bool = False
    has_canary: bool = False
    has_iam_file: bool = False
    # Opt-in: when set, a public-S3 finding escalates to the (read-only,
    # ACL-derived) write/delete permission check. Off by default so concluding
    # "publicly writable" never happens without the tester asking for it.
    confirm_s3_writes: bool = False


# Evidence substrings that indicate leaked cloud credentials were observed.
_CREDENTIAL_MARKERS = ("AccessKeyId", "SecretAccessKey", "aws_session_token")


def _mentions_credentials(evidence: dict) -> bool:
    for value in evidence.values():
        if isinstance(value, str) and any(m in value for m in _CREDENTIAL_MARKERS):
            return True
        if isinstance(value, (list, tuple)) and any(
            isinstance(v, str) and any(m in v for m in _CREDENTIAL_MARKERS) for v in value
        ):
            return True
    return False


def derive_followups(findings: list, context: TriggerContext) -> list[FollowUp]:
    """Map detection findings to the deeper tests they justify.

    Rules (each fires only when the context can run it):
      - Broken authorization on an endpoint -> if identities are available,
        that endpoint is a prime cross-tenant (BOLA) target; if a token is
        available, deep JWT-tamper it.
      - A confirmed cloud-SSRF -> escalate to an OOB/blind confirmation when a
        canary is running.
      - Leaked cloud credentials (in any finding's evidence, e.g. SSRF->IMDS)
        -> if an IAM authorization-details file was provided, analyze the
        privilege escalation reachable with them.

    Duplicate (scanner, asset) follow-ups are collapsed, preserving first-seen
    order.
    """
    out: list[FollowUp] = []
    seen: set[tuple[str, str]] = set()

    def _add(scanner: str, asset: str, reason: str) -> None:
        key = (scanner, asset)
        if key in seen:
            return
        seen.add(key)
        out.append(FollowUp(scanner=scanner, asset=asset, reason=reason))

    for f in findings:
        category = getattr(f, "category", "") or ""
        asset = getattr(f, "asset", "") or ""
        evidence = getattr(f, "evidence", None) or {}

        if category.startswith("authz-bypass-"):
            if context.has_identities:
                _add("bola", asset, f"broken authorization ({category}) -> check cross-tenant access")
            if context.has_token:
                _add("jwt_tamper", asset, f"broken authorization ({category}) -> deep JWT tampering")

        if category.startswith("cloud-ssrf") and context.has_canary:
            _add("ssrf_blind", asset, f"{category} -> confirm server-side request via OOB canary")

        # A public S3 bucket (listing/object/ACL) -> the canonical "S3 public ->
        # try read/permissions" deeper step: a read-only, ACL-derived check of
        # whether unauthenticated writes/deletes would be accepted. Opt-in.
        if category.startswith("s3-bucket-public") and context.confirm_s3_writes:
            _add("s3_permcheck", asset, f"{category} -> check write/delete permissions (ACL-derived, read-only)")

        # Leaked cloud credentials -> IAM privilege-escalation analysis. Fires on
        # SSRF/IMDS credential leaks (markers in evidence) and on an AWS key found
        # by the secret scanner (whose evidence is masked, so it is matched by
        # category, not by a credential marker).
        is_aws_secret = category.startswith(
            ("secret-exposure-aws", "secret-exposure-private-key")
        )
        if context.has_iam_file and (
            "imds" in category or is_aws_secret or _mentions_credentials(evidence)
        ):
            _add("iam_privesc", asset, "leaked cloud credentials -> analyze IAM privilege escalation")

    return out
