"""Phase 2: data-driven asset routing (classify/router.py)."""

from wily.classify.router import AssetType, DiscoveredAsset, route_asset


def _asset(asset_type):
    return DiscoveredAsset(value="x", asset_type=asset_type, discovery_source="recon")


def test_api_endpoint_routes_to_auth_and_cors():
    scanners = route_asset(_asset(AssetType.API_ENDPOINT))
    assert "authz_bypass" in scanners
    assert "cors_misconfig" in scanners


def test_cloud_storage_routes_to_s3():
    assert route_asset(_asset(AssetType.CLOUD_STORAGE)) == ["s3_bucket"]


def test_js_file_routes_to_nothing():
    assert route_asset(_asset(AssetType.JS_FILE)) == []


def test_tls_service_routes_to_tls_config():
    assert route_asset(_asset(AssetType.TLS_SERVICE)) == ["tls_config"]


def test_route_returns_a_fresh_list():
    # callers must be able to mutate the result without corrupting the table
    a = route_asset(_asset(AssetType.API_ENDPOINT))
    a.append("mutated")
    b = route_asset(_asset(AssetType.API_ENDPOINT))
    assert "mutated" not in b
