"""Tests for the endpoint-hash clustering added to risk/ml/dedup.py:
  - normalize_endpoint_path collapses object-id-shaped segments to {id} but
    leaves version prefixes (v1, v2, ...) alone.
  - finding_hash_key is stable across different concrete object ids on the
    same endpoint shape, and works on both a Finding dataclass and a plain
    dict (as reloaded from a JSON report).
  - cluster_by_endpoint_hash collapses findings sharing that hash across
    DIFFERENT concrete assets, keeping the higher-confidence copy and
    recording how many endpoints were merged, while never merging genuinely
    distinct findings.
"""

from wily.risk.ml.dedup import (
    cluster_by_endpoint_hash,
    finding_hash_key,
    normalize_endpoint_path,
)
from wily.scanners.base import Finding


def _finding(asset, category, confidence, evidence=None):
    return Finding(
        asset=asset,
        category=category,
        severity="high",
        confidence=confidence,
        evidence=dict(evidence or {}),
        discovery_source="scanner",
    )


# --- normalize_endpoint_path -------------------------------------------------


def test_normalize_collapses_numeric_id_segment():
    assert normalize_endpoint_path("https://x/invoices/1") == "/invoices/{id}"
    assert normalize_endpoint_path("https://x/invoices/100") == "/invoices/{id}"


def test_normalize_collapses_uuid_segment():
    url = "https://x/users/550e8400-e29b-41d4-a716-446655440000/profile"
    assert normalize_endpoint_path(url) == "/users/{id}/profile"


def test_normalize_leaves_version_prefix_alone():
    # v1/v2 must NOT become {id} - that would wrongly merge two API versions.
    assert normalize_endpoint_path("https://x/v1/orders/42") == "/v1/orders/{id}"
    assert normalize_endpoint_path("https://x/v2/orders/42") == "/v2/orders/{id}"


def test_normalize_non_url_asset_returned_unchanged():
    assert normalize_endpoint_path("s3://my-bucket") == "s3://my-bucket"
    assert normalize_endpoint_path("") == ""
    assert normalize_endpoint_path(None) == ""


# --- finding_hash_key ---------------------------------------------------------


def test_hash_key_stable_across_object_ids():
    a = _finding("https://x/invoices/1", "authz-bypass-missing-authorizer", 0.8)
    b = _finding("https://x/invoices/2", "authz-bypass-missing-authorizer", 0.8)
    assert finding_hash_key(a) == finding_hash_key(b)


def test_hash_key_differs_across_categories():
    a = _finding("https://x/invoices/1", "authz-bypass-missing-authorizer", 0.8)
    b = _finding("https://x/invoices/1", "cloud-ssrf", 0.8)
    assert finding_hash_key(a) != finding_hash_key(b)


def test_hash_key_differs_across_api_versions():
    a = _finding("https://x/v1/orders/1", "authz-bypass-missing-authorizer", 0.8)
    b = _finding("https://x/v2/orders/1", "authz-bypass-missing-authorizer", 0.8)
    assert finding_hash_key(a) != finding_hash_key(b)


def test_hash_key_works_on_plain_dict_like_a_reloaded_report():
    finding = _finding("https://x/invoices/1", "authz-bypass-missing-authorizer", 0.8)
    as_dict = finding.to_dict()
    assert finding_hash_key(finding) == finding_hash_key(as_dict)


# --- cluster_by_endpoint_hash --------------------------------------------------


def test_cluster_merges_same_shape_different_object_ids_keeping_higher_confidence():
    findings = [
        _finding(f"https://x/invoices/{i}", "authz-bypass-missing-authorizer", 0.5)
        for i in range(1, 100)
    ]
    findings.append(
        _finding("https://x/invoices/100", "authz-bypass-missing-authorizer", 0.95)
    )
    out = cluster_by_endpoint_hash(findings)
    assert len(out) == 1
    assert out[0].confidence == 0.95
    assert out[0].evidence["merged_endpoint_count"] == 100
    assert len(out[0].evidence["sample_merged_assets"]) <= 5


def test_cluster_keeps_distinct_categories_separate():
    a = _finding("https://x/invoices/1", "authz-bypass-missing-authorizer", 0.8)
    b = _finding("https://x/invoices/1", "cloud-ssrf", 0.8)
    out = cluster_by_endpoint_hash([a, b])
    assert len(out) == 2


def test_cluster_does_not_merge_across_api_versions():
    a = _finding("https://x/v1/orders/1", "authz-bypass-missing-authorizer", 0.8)
    b = _finding("https://x/v2/orders/1", "authz-bypass-missing-authorizer", 0.8)
    out = cluster_by_endpoint_hash([a, b])
    assert len(out) == 2


def test_cluster_singleton_has_no_merge_evidence():
    a = _finding("https://x/invoices/1", "authz-bypass-missing-authorizer", 0.8)
    out = cluster_by_endpoint_hash([a])
    assert "merged_endpoint_count" not in out[0].evidence
