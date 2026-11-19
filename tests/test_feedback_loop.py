"""Tests for risk/ml/feedback.py (the analyst feedback loop):
  - record() appends a decision keyed by finding_hash_key, not by asset.
  - decisions_by_hash() returns the LATEST decision per hash_key (append-
    only log, later record wins).
  - apply() annotates matching findings without dropping/reordering any.
  - a decision recorded against one object id matches the same finding
    shape on a different object id (the whole point of using the hash key).
"""

from wily.risk.ml.dedup import finding_hash_key
from wily.risk.ml.feedback import FALSE_POSITIVE, VALID, FeedbackStore
from wily.scanners.base import Finding


def _finding(asset, category, confidence=0.8, evidence=None):
    return Finding(
        asset=asset,
        category=category,
        severity="high",
        confidence=confidence,
        evidence=dict(evidence or {}),
        discovery_source="scanner",
    )


def test_record_and_read_back(tmp_path):
    store = FeedbackStore(tmp_path / "feedback.jsonl")
    f = _finding("https://x/invoices/1", "authz-bypass-missing-authorizer")
    store.record(f, VALID, note="confirmed in demo")

    decisions = store.all_decisions()
    assert len(decisions) == 1
    assert decisions[0].verdict == VALID
    assert decisions[0].hash_key == finding_hash_key(f)
    assert decisions[0].note == "confirmed in demo"


def test_invalid_verdict_rejected(tmp_path):
    store = FeedbackStore(tmp_path / "feedback.jsonl")
    f = _finding("https://x/a", "cat")
    try:
        store.record(f, "maybe")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_later_decision_overrides_earlier_for_same_hash(tmp_path):
    store = FeedbackStore(tmp_path / "feedback.jsonl")
    f = _finding("https://x/invoices/1", "authz-bypass-missing-authorizer")
    store.record(f, FALSE_POSITIVE)
    store.record(f, VALID)  # analyst changed their mind

    by_hash = store.decisions_by_hash()
    assert len(by_hash) == 1
    assert by_hash[finding_hash_key(f)].verdict == VALID
    # The log itself is append-only - both entries are still there.
    assert len(store.all_decisions()) == 2


def test_decision_survives_a_different_object_id(tmp_path):
    """The whole point of keying on finding_hash_key: a decision recorded
    against /invoices/1 in one scan still matches /invoices/2 in the next."""
    store = FeedbackStore(tmp_path / "feedback.jsonl")
    first_scan = _finding("https://x/invoices/1", "authz-bypass-missing-authorizer")
    store.record(first_scan, FALSE_POSITIVE)

    next_scan = [_finding("https://x/invoices/2", "authz-bypass-missing-authorizer")]
    annotated = store.apply(next_scan)
    assert annotated[0].evidence["feedback_verdict"] == FALSE_POSITIVE


def test_apply_never_drops_or_reorders_findings(tmp_path):
    store = FeedbackStore(tmp_path / "feedback.jsonl")
    a = _finding("https://x/a", "cat1")
    b = _finding("https://x/b", "cat2")
    store.record(a, VALID)

    out = store.apply([a, b])
    assert out == [a, b]
    assert a.evidence["feedback_verdict"] == VALID
    assert "feedback_verdict" not in b.evidence


def test_apply_with_empty_store_is_a_noop(tmp_path):
    store = FeedbackStore(tmp_path / "feedback.jsonl")  # never written to
    a = _finding("https://x/a", "cat1")
    out = store.apply([a])
    assert out == [a]
    assert "feedback_verdict" not in a.evidence


def test_malformed_line_is_skipped_not_fatal(tmp_path):
    path = tmp_path / "feedback.jsonl"
    store = FeedbackStore(path)
    f = _finding("https://x/a", "cat1")
    store.record(f, VALID)
    with path.open("a", encoding="utf-8") as fh:
        fh.write("not json at all\n")
        fh.write('{"hash_key": "deadbeef"}\n')  # missing "verdict" - skipped too

    decisions = store.all_decisions()
    assert len(decisions) == 1
    assert decisions[0].verdict == VALID
