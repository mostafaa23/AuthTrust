"""Tests for risk/ml/sensitivity.py's heuristic response-sensitivity scorer:
  - a concrete secret/credential shape in the text -> positive adjustment.
  - a response that reads like a public catalog/listing shape -> negative
    adjustment.
  - no signal either way -> (0.0, None), never a guess.
"""

from wily.risk.ml.sensitivity import score_response


def test_empty_or_non_string_is_a_noop():
    assert score_response(None) == (0.0, None)
    assert score_response("") == (0.0, None)


def test_plain_text_with_no_signal_is_a_noop():
    assert score_response("hello world, nothing interesting here") == (0.0, None)


def test_aws_key_shaped_value_boosts():
    boost, reason = score_response("leaked: AKIAABCDEFGHIJKLMNOP in the response")
    assert boost > 0
    assert "aws" in reason.lower()


def test_jwt_shaped_value_boosts():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K"
    boost, reason = score_response(f'{{"token": "{jwt}"}}')
    assert boost > 0
    assert "jwt" in reason.lower()


def test_email_and_card_together_boosts():
    text = "contact victim@example.com, card 4111 1111 1111 1111 on file"
    boost, reason = score_response(text)
    assert boost > 0


def test_account_shaped_json_field_boosts():
    text = '{"user_id": 42, "ssn": "123-45-6789", "name": "Jane"}'
    boost, reason = score_response(text)
    assert boost > 0
    assert "account" in reason.lower() or "credential" in reason.lower()


def test_public_catalog_shaped_json_penalizes():
    text = (
        '{"sku": "ABC-123", "price": 19.99, "in_stock": true, '
        '"category": "shoes", "title": "Running shoes", "description": "..."}'
    )
    boost, reason = score_response(text)
    assert boost < 0
    assert "catalog" in reason.lower()


def test_non_json_non_matching_text_is_a_noop():
    assert score_response("<html><body>not json</body></html>") == (0.0, None)
