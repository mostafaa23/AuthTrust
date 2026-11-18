"""Phase 3: turn discovery results into testable assets, route each asset
to the appropriate scanner module, and record a discovery_source
(discovery_source) for every finding.

discovery_source ∈ {recon, javascript, openapi, proxy, wordlist, scanner}
"""

from dataclasses import dataclass
from enum import Enum


class AssetType(str, Enum):
    CLOUD_STORAGE = "cloud_storage"
    API_ENDPOINT = "api_endpoint"
    TLS_SERVICE = "tls_service"
    JS_FILE = "js_file"
    VERSIONED_SERVICE = "versioned_service"
    # TODO: add module-specific types for finer-grained routing if needed:
    # BOLA_CANDIDATE, SSRF_CANDIDATE, IAM_PRINCIPAL, JWT_ISSUER ...


@dataclass
class DiscoveredAsset:
    value: str
    asset_type: AssetType
    discovery_source: str  # recon | javascript | openapi | proxy | wordlist | scanner


# Which scanners each asset type should be routed to for its initial
# (always-on, relatively cheap) detection pass. Deeper/aggressive tests are
# not listed here - they are triggered from findings by risk.triggers, so a
# scan stays finding-driven instead of running every module on every asset.
#
# Scanner names match each scanner class's ``name`` attribute. Names for
# scanners not built yet (e.g. "s3_bucket") are included so the routing table
# is the single place that declares intent; the orchestrator simply skips a
# routed scanner it doesn't have wired yet.
_ROUTES: dict[AssetType, list[str]] = {
    AssetType.API_ENDPOINT: ["authz_bypass", "cors_misconfig"],
    AssetType.VERSIONED_SERVICE: ["authz_bypass", "cors_misconfig"],
    AssetType.CLOUD_STORAGE: ["s3_bucket"],
    AssetType.JS_FILE: [],  # mined for endpoints during discovery, not scanned directly
    AssetType.TLS_SERVICE: ["tls_config"],
}


def route_asset(asset: DiscoveredAsset) -> list[str]:
    """Return the scanner names for this asset's initial detection pass.

    Keyed on ``asset_type`` so routing is data-driven in one place instead of
    hardcoded in the orchestrator. An unknown asset type routes to nothing
    (empty list) rather than raising, so a new, unclassified asset can never
    abort a scan.
    """
    return list(_ROUTES.get(asset.asset_type, []))
