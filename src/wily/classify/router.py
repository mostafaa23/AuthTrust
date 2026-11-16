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


def route_asset(asset: DiscoveredAsset) -> list[str]:
    """Return the names of the scanners appropriate for this asset.

    TODO: the actual routing logic, keyed on asset_type.
    """
    raise NotImplementedError
