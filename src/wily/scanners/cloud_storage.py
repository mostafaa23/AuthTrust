"""Multi-cloud storage enumeration scanner (AWS S3 / Azure Blob / GCP).

Given a single candidate name (produced by ``recon/cloud_enum.py``), this probes
each cloud provider's storage endpoint to decide whether a resource with that
name exists and whether it is publicly open. The detection signals mirror
initstring/cloud_enum:

  * **AWS S3**   ``https://{name}.s3.amazonaws.com/`` - 200 = open, 403 =
                 protected (exists), 404 = none. Existence is reported here; the
                 deep ACL/listing/write analysis is left to the dedicated
                 ``s3_bucket`` scanner, which the orchestrator runs on the hits.
  * **Azure**    ``https://{account}.blob.core.windows.net/`` - the account must
                 resolve (the shared HttpEngine's DNS-safety step enforces that,
                 so a non-existent account is simply unreachable). Open blob
                 *containers* are then found via
                 ``/{container}/?restype=container&comp=list`` (200 = open).
  * **GCP**      ``https://storage.googleapis.com/{name}`` - 200 = open, 403 =
                 protected (exists), 404 = none.

Read-only and safe
------------------
Every probe is a ``GET``. Nothing is created, written, or claimed. The scanner
reports what exists and what is world-readable so it can go in the unified
report; acting on a finding is the analyst's decision.

Testability
-----------
HTTP access to three different provider hosts is obtained through an injected
``engine_factory(host) -> HttpEngine`` (each host needs its own scope). Tests
pass a factory that returns a scripted fake engine, so no network is touched.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from wily.scanners.base import BaseScanner, Finding

# Default Azure blob container names to try on a resolving account. Small and
# high-signal; the orchestrator can pass a larger list.
DEFAULT_AZURE_CONTAINERS: tuple[str, ...] = (
    "backup", "backups", "data", "files", "public", "assets", "static",
    "media", "images", "uploads", "documents", "logs", "web", "$web", "temp",
)

_LIST_RESULT_MARKERS = ("<ListBucketResult", "<EnumerationResults")

# Azure account-existence reason markers (from the response, case-insensitive).
_AZURE_PROTECTED_MARKERS = ("server failed to authenticate the request",)
_AZURE_DISABLED_MARKERS = ("the specified account is disabled",)


EngineFactory = Callable[[str], "object"]


@dataclass
class CloudStorageTarget:
    name: str
    providers: tuple[str, ...] = ("aws", "azure", "gcp")
    azure_containers: tuple[str, ...] = DEFAULT_AZURE_CONTAINERS
    # An Azure-safe reduction of ``name`` (set by the orchestrator); when None
    # the scanner computes it itself.
    azure_account: str | None = None


class CloudStorageScanner(BaseScanner):
    name = "cloud_storage_enum"
    requires_tenant_pair = False
    requires_owned_infra = False

    def __init__(
        self,
        engine_factory: EngineFactory | None = None,
        http_engine=None,
    ) -> None:
        # Either an engine_factory(host) (orchestrator) or a single http_engine
        # used for every host (tests). One of them must be provided to do I/O.
        self._factory = engine_factory
        self._http = http_engine

    def _engine_for(self, host: str):
        if self._http is not None:
            return self._http
        if self._factory is not None:
            return self._factory(host)
        return None

    @staticmethod
    def _get(engine, url: str):
        if engine is None:
            return None
        try:
            return engine.request(method="GET", url=url, headers={})
        except Exception:
            return None

    # -- AWS ---------------------------------------------------------------

    def _check_aws(self, name: str) -> list[Finding]:
        from wily.scanners.s3_bucket import s3_base_url, s3_host_for

        host = s3_host_for(name)
        base = s3_base_url(name)
        resp = self._get(self._engine_for(host), base if base.endswith("/") else base + "/")
        if resp is None:
            return []
        status = resp.status_code
        if status not in (200, 403):
            return []  # 404 / other -> does not exist
        access = "open" if status == 200 else "protected"
        severity = "high" if access == "open" else "low"
        return [
            Finding(
                asset=f"s3://{name}",
                category=f"cloud-storage-s3-{access}",
                severity=severity,
                confidence=0.9 if access == "open" else 0.7,
                discovery_source="scanner",
                evidence={
                    "provider": "aws",
                    "bucket": name,
                    "endpoint": base,
                    "status": status,
                    "access": access,
                    "discovered_via": "cloud_enum_mutation",
                    "note": (
                        "Bucket exists; the s3_bucket scanner performs the deep "
                        "ACL/listing/write analysis."
                    ),
                },
                remediation=(
                    "Confirm this bucket belongs to you; if public, enable S3 "
                    "Block Public Access and remove AllUsers grants."
                ),
            )
        ]

    # -- GCP ---------------------------------------------------------------

    def _check_gcp(self, name: str) -> list[Finding]:
        host = "storage.googleapis.com"
        resp = self._get(self._engine_for(host), f"https://{host}/{name}")
        if resp is None:
            return []
        status = resp.status_code
        if status not in (200, 403):
            return []
        access = "open" if status == 200 else "protected"
        severity = "high" if access == "open" else "low"
        return [
            Finding(
                asset=f"gs://{name}",
                category=f"cloud-storage-gcp-bucket-{access}",
                severity=severity,
                confidence=0.9 if access == "open" else 0.7,
                discovery_source="scanner",
                evidence={
                    "provider": "gcp",
                    "bucket": name,
                    "endpoint": f"https://{host}/{name}",
                    "status": status,
                    "access": access,
                    "discovered_via": "cloud_enum_mutation",
                },
                remediation=(
                    "If this GCS bucket is yours and not meant to be public, "
                    "remove the allUsers/allAuthenticatedUsers IAM bindings and "
                    "enable uniform bucket-level access with public access "
                    "prevention."
                ),
            )
        ]

    # -- Azure -------------------------------------------------------------

    def _check_azure(self, target: CloudStorageTarget) -> list[Finding]:
        from wily.recon.cloud_enum import azure_account_name

        account = target.azure_account or azure_account_name(target.name)
        if not account:
            return []
        host = f"{account}.blob.core.windows.net"
        engine = self._engine_for(host)
        # Account existence: the HttpEngine's DNS-safety step means a
        # non-existent account raises (returns None here) instead of connecting.
        acct_resp = self._get(engine, f"https://{host}/")
        if acct_resp is None:
            return []

        reason = (
            f"{getattr(acct_resp, 'text', '') or ''} "
            f"{' '.join(str(v) for v in getattr(acct_resp, 'headers', {}).values())}"
        ).lower()
        status = acct_resp.status_code

        # 404 with nothing else -> treat as non-existent.
        if status == 404 and not any(
            m in reason for m in _AZURE_PROTECTED_MARKERS + _AZURE_DISABLED_MARKERS
        ):
            return []
        if any(m in reason for m in _AZURE_DISABLED_MARKERS):
            return []  # disabled account - not actionable

        findings: list[Finding] = [
            Finding(
                asset=f"azure://{account}",
                category="cloud-storage-azure-account",
                severity="low",
                confidence=0.7,
                discovery_source="scanner",
                evidence={
                    "provider": "azure",
                    "account": account,
                    "endpoint": f"https://{host}/",
                    "status": status,
                    "access": "protected",
                    "discovered_via": "cloud_enum_mutation",
                    "note": "Storage account exists (DNS-resolving); probing containers.",
                },
                remediation=(
                    "Confirm this storage account is yours; review container "
                    "public-access settings and disable anonymous blob access "
                    "at the account level unless required."
                ),
            )
        ]

        # Open container brute: only a 200 with a listing body is public.
        for container in target.azure_containers:
            curl = f"https://{host}/{container}/?restype=container&comp=list"
            cresp = self._get(engine, curl)
            if cresp is None or cresp.status_code != 200:
                continue
            body = getattr(cresp, "text", "") or ""
            if not any(marker in body for marker in _LIST_RESULT_MARKERS):
                continue
            findings.append(
                Finding(
                    asset=f"azure://{account}/{container}",
                    category="cloud-storage-azure-blob-open",
                    severity="high",
                    confidence=0.9,
                    discovery_source="scanner",
                    evidence={
                        "provider": "azure",
                        "account": account,
                        "container": container,
                        "endpoint": curl,
                        "status": cresp.status_code,
                        "access": "open",
                        "discovered_via": "cloud_enum_mutation",
                    },
                    remediation=(
                        "This blob container allows anonymous public listing. "
                        "Set the container's public access level to Private and "
                        "enable 'Allow Blob public access = Disabled' on the "
                        "storage account."
                    ),
                )
            )
        return findings

    # -- entrypoint --------------------------------------------------------

    def run(self, target: CloudStorageTarget) -> list[Finding]:
        findings: list[Finding] = []
        if "aws" in target.providers:
            findings += self._check_aws(target.name)
        if "gcp" in target.providers:
            findings += self._check_gcp(target.name)
        if "azure" in target.providers:
            findings += self._check_azure(target)
        return findings
