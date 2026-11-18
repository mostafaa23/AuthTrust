"""S3 bucket misconfiguration scanner.

Given a bucket reference (bare name, ``s3://bucket/key``, or
``*.s3*.amazonaws.com`` URL), checks for public bucket listing, public
object read, and ACL/policy exposure granting ``AllUsers``/
``AuthenticatedUsers`` access.

Safety: every request is a GET - never a PUT/DELETE, so it can never
mutate a third-party bucket. Write/delete exposure is only *inferred* from
a readable ACL/policy granting a wildcard principal write access, and
reporting that inference is gated behind ``confirm_writes``
(``--confirm-s3-writes``), default off.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from wily.core.scope_manager import ScopeManager, extract_bucket_name
from wily.scanners.base import BaseScanner, Finding
from wily.scanners.http_engine import HttpEngine

# AWS canonical group URIs that mean "anyone" / "any AWS account".
_ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
_AUTH_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

# How much of an ACL/policy/listing body is kept as evidence.
_EVIDENCE_SNIPPET_LEN = 400

_LIST_RESULT_RE = re.compile(r"<ListBucketResult", re.IGNORECASE)
_NO_SUCH_BUCKET_RE = re.compile(r"<Code>\s*NoSuchBucket\s*</Code>", re.IGNORECASE)


def s3_host_for(bucket: str, region: str | None = None) -> str:
    """The S3 host used to reach ``bucket``.

    Virtual-hosted style is preferred, but a bucket name containing a dot
    breaks TLS virtual-hosting (the wildcard cert does not cover
    ``my.bucket.s3.amazonaws.com``), so those fall back to path-style on the
    plain ``s3[.region].amazonaws.com`` host.
    """
    regional = f"s3.{region}.amazonaws.com" if region else "s3.amazonaws.com"
    if "." in bucket:
        return regional
    return f"{bucket}.{regional}"


def s3_base_url(bucket: str, region: str | None = None) -> str:
    """Base URL for the bucket (path-style includes the bucket segment)."""
    host = s3_host_for(bucket, region)
    if host.startswith(bucket + "."):  # virtual-hosted
        return f"https://{host}"
    return f"https://{host}/{bucket}"


@dataclass
class S3BucketTarget:
    """``bucket`` may be a name, an ``s3://`` URI or an S3 URL - it is
    normalised to the bucket name. ``sample_object_key`` enables the public
    object-read check when a concrete key is known (e.g. from a discovered
    link)."""

    bucket: str
    region: str | None = None
    sample_object_key: str | None = None

    @property
    def name(self) -> str:
        return extract_bucket_name(self.bucket) or self.bucket.strip().lower()


class S3BucketScanner(BaseScanner):
    name = "s3_bucket"
    requires_tenant_pair = False
    # Read-only checks are safe against arbitrary buckets; the write/delete
    # inference is additionally gated by confirm_writes below.
    requires_owned_infra = False

    def __init__(
        self,
        scope_manager: ScopeManager | None = None,
        http_engine: HttpEngine | None = None,
        confirm_writes: bool = False,
    ) -> None:
        self.scope = scope_manager
        self.http = http_engine
        self._confirm_writes = confirm_writes

    def _get(self, url: str):
        if self.http is None:
            return None
        try:
            return self.http.request(method="GET", url=url, headers={})
        except Exception:
            return None

    @staticmethod
    def _snippet(body: str) -> str:
        return (body or "")[:_EVIDENCE_SNIPPET_LEN]

    def run(self, target: S3BucketTarget) -> list[Finding]:
        bucket = target.name
        findings: list[Finding] = []

        # Respect bucket scope when one is configured: don't probe a bucket the
        # tester did not authorise. With no bucket scope configured, read checks
        # run (report-everything mode - see ScopeManager.has_bucket_scope).
        if (
            self.scope is not None
            and self.scope.has_bucket_scope
            and not self.scope.is_bucket_in_scope(target.bucket)
        ):
            return findings

        base = s3_base_url(bucket, target.region)

        # --- Check 1: anonymous bucket listing -----------------------------
        list_resp = self._get(base if base.endswith("/") else base + "/")
        if list_resp is not None and list_resp.status_code == 200 and _LIST_RESULT_RE.search(
            list_resp.text or ""
        ):
            findings.append(
                Finding(
                    asset=f"s3://{bucket}",
                    category="s3-bucket-public-listing",
                    severity="high",
                    confidence=0.9,
                    discovery_source="scanner",
                    evidence={
                        "bucket": bucket,
                        "check": "anonymous_list",
                        "status": list_resp.status_code,
                        "response_snippet": self._snippet(list_resp.text),
                    },
                    remediation=(
                        "Enable S3 Block Public Access at the account and bucket "
                        "level, and remove any bucket policy / ACL grant to "
                        "AllUsers. Anonymous listing exposes every object key."
                    ),
                )
            )

        # --- Check 2: public object read -----------------------------------
        if target.sample_object_key:
            obj_url = f"{base.rstrip('/')}/{target.sample_object_key.lstrip('/')}"
            obj_resp = self._get(obj_url)
            if obj_resp is not None and obj_resp.status_code == 200:
                findings.append(
                    Finding(
                        asset=f"s3://{bucket}/{target.sample_object_key.lstrip('/')}",
                        category="s3-bucket-public-object",
                        severity="high",
                        confidence=0.85,
                        discovery_source="scanner",
                        evidence={
                            "bucket": bucket,
                            "object_key": target.sample_object_key,
                            "check": "anonymous_object_read",
                            "status": obj_resp.status_code,
                        },
                        remediation=(
                            "Make the object private (remove the public-read ACL "
                            "/ policy) unless it is intended to be world-readable; "
                            "serve genuinely public assets via CloudFront with an "
                            "origin access identity instead of a public bucket."
                        ),
                    )
                )

        # --- Check 3: ACL / policy exposure + write inference --------------
        acl_resp = self._get(f"{base.rstrip('/')}/?acl")
        acl_body = (acl_resp.text or "") if acl_resp is not None else ""
        acl_public = acl_resp is not None and acl_resp.status_code == 200 and (
            _ALL_USERS_URI in acl_body or _AUTH_USERS_URI in acl_body
        )
        if acl_public:
            findings.append(
                Finding(
                    asset=f"s3://{bucket}",
                    category="s3-bucket-public-acl",
                    severity="medium",
                    confidence=0.8,
                    discovery_source="scanner",
                    evidence={
                        "bucket": bucket,
                        "check": "anonymous_acl_read",
                        "status": acl_resp.status_code,
                        "grants_all_users": _ALL_USERS_URI in acl_body,
                        "grants_authenticated_users": _AUTH_USERS_URI in acl_body,
                        "response_snippet": self._snippet(acl_body),
                    },
                    remediation=(
                        "The bucket ACL is world-readable and grants a global "
                        "group. Remove AllUsers/AuthenticatedUsers grants and "
                        "disable ACLs (set Object Ownership to 'Bucket owner "
                        "enforced')."
                    ),
                )
            )

        # Write/delete capability: inferred from the public ACL grants only -
        # no mutating request is ever sent. Reporting it is opt-in.
        if self._confirm_writes and acl_resp is not None and acl_resp.status_code == 200:
            writable = self._acl_grants_write(acl_body)
            if writable:
                findings.append(
                    Finding(
                        asset=f"s3://{bucket}",
                        category="s3-bucket-public-writable",
                        severity="critical",
                        confidence=0.75,
                        discovery_source="scanner",
                        evidence={
                            "bucket": bucket,
                            "check": "write_permission_inferred_from_acl",
                            "grants_all_users": _ALL_USERS_URI in acl_body,
                            "inferred_write_grant": writable,
                            "note": (
                                "Writability inferred from a WRITE/WRITE_ACP grant "
                                "to a global group in the bucket ACL. NO PUT or "
                                "DELETE was sent - this is a read-derived "
                                "permission check only."
                            ),
                            "response_snippet": self._snippet(acl_body),
                        },
                        remediation=(
                            "A global group has WRITE access: anyone can upload, "
                            "overwrite or delete objects (defacement / malware "
                            "hosting / data destruction). Remove the WRITE / "
                            "WRITE_ACP grant immediately and enable Block Public "
                            "Access."
                        ),
                    )
                )

        return findings

    @staticmethod
    def _acl_grants_write(acl_body: str) -> list[str]:
        """Return the write-type permissions granted to a global group, read
        straight from the ACL XML. Never sends a request."""
        if not acl_body:
            return []
        granted: list[str] = []
        # Each <Grant> pairs a <Grantee> (may be a global group URI) with a
        # <Permission>. A simple, dependency-free scan: for every global-group
        # URI occurrence, look at the permissions near it.
        if _ALL_USERS_URI not in acl_body and _AUTH_USERS_URI not in acl_body:
            return []
        for perm in ("WRITE_ACP", "WRITE", "FULL_CONTROL"):
            # The permission text appears in the same <Grant> block as the
            # global-group grantee. We treat any WRITE*/FULL_CONTROL alongside a
            # global group as a write grant (conservative - may include a grant
            # to a non-global grantee in a pathological ACL, hence confidence
            # stays < 0.8).
            if re.search(rf"<Permission>\s*{perm}\s*</Permission>", acl_body, re.IGNORECASE):
                granted.append(perm)
        return granted
