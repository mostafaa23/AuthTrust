"""Phase 1 (part 1): ScopeManager's two new scope dimensions - S3 buckets and
AWS accounts/ARNs - plus proof that adding them does not change the existing
domain behaviour.
"""

import json

import pytest

from wily.core.scope_manager import (
    ScopeManager,
    account_in_scope,
    bucket_in_scope,
    extract_account_id,
    extract_bucket_name,
    load_scope_config,
)

# --- S3 bucket extraction --------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("s3://company-assets/path/to/key", "company-assets"),
        ("s3://company-assets", "company-assets"),
        ("https://target-logs.s3.amazonaws.com/a/b", "target-logs"),
        ("https://target-logs.s3.us-east-1.amazonaws.com/a", "target-logs"),
        ("https://target-logs.s3-us-west-2.amazonaws.com/a", "target-logs"),
        ("https://my.dotted.bucket.s3.amazonaws.com/x", "my.dotted.bucket"),
        ("https://s3.amazonaws.com/path-style-bucket/key", "path-style-bucket"),
        ("https://s3.eu-west-1.amazonaws.com/path-style-bucket", "path-style-bucket"),
        ("bucket.s3.amazonaws.com/key", "bucket"),  # no scheme, still an S3 host
        ("https://example.com/not-s3", None),       # not S3 at all
        ("just-a-name", None),                       # bare name is not a URL
    ],
)
def test_extract_bucket_name(value, expected):
    assert extract_bucket_name(value) == expected


def test_bucket_in_scope_glob_and_literal():
    patterns = ("target-*", "company-assets")
    assert bucket_in_scope("s3://target-logs/x", patterns) is True
    assert bucket_in_scope("https://company-assets.s3.amazonaws.com/x", patterns) is True
    assert bucket_in_scope("target-reports", patterns) is True        # bare name
    assert bucket_in_scope("s3://someone-elses-bucket/x", patterns) is False
    assert bucket_in_scope("company-assets", patterns) is True


def test_bucket_scope_empty_matches_nothing():
    assert bucket_in_scope("s3://anything/x", ()) is False


def test_scope_manager_bucket_methods():
    scope = ScopeManager("target.com", s3_buckets=("target-*",))
    assert scope.has_bucket_scope is True
    assert scope.is_bucket_in_scope("s3://target-backups/db.sql") is True
    assert scope.is_bucket_in_scope("https://other.s3.amazonaws.com/x") is False

    no_buckets = ScopeManager("target.com")
    assert no_buckets.has_bucket_scope is False
    assert no_buckets.is_bucket_in_scope("s3://target-backups/db.sql") is False


# --- AWS account / ARN extraction & scope ----------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("123456789012", "123456789012"),
        ("arn:aws:iam::123456789012:user/alice", "123456789012"),
        ("arn:aws:s3:::my-bucket", None),            # no account field on S3 ARNs
        ("arn:aws:iam::999988887777:role/app", "999988887777"),
        ("nonsense", None),
    ],
)
def test_extract_account_id(value, expected):
    assert extract_account_id(value) == expected


def test_account_in_scope_by_id():
    accounts = ("123456789012",)
    assert account_in_scope("arn:aws:iam::123456789012:user/alice", accounts) is True
    assert account_in_scope("123456789012", accounts) is True
    assert account_in_scope("arn:aws:iam::555555555555:role/x", accounts) is False


def test_account_in_scope_by_arn_prefix():
    accounts = ("arn:aws:iam::123456789012:*",)
    assert account_in_scope("arn:aws:iam::123456789012:user/alice", accounts) is True
    assert account_in_scope("arn:aws:iam::123456789012:role/admin", accounts) is True
    # Same account id embedded in the pattern still matches a bare id value.
    assert account_in_scope("123456789012", accounts) is True
    assert account_in_scope("arn:aws:iam::000000000000:user/eve", accounts) is False


def test_account_scope_empty_imposes_no_restriction():
    # No account scope -> everything passes (common case: own account export).
    assert account_in_scope("arn:aws:iam::123456789012:user/alice", ()) is True
    scope = ScopeManager("target.com")
    assert scope.has_account_scope is False
    assert scope.is_account_in_scope("arn:aws:iam::999999999999:root") is True


def test_scope_manager_account_methods():
    scope = ScopeManager("target.com", aws_accounts=("123456789012",))
    assert scope.has_account_scope is True
    assert scope.is_account_in_scope("arn:aws:iam::123456789012:user/x") is True
    assert scope.is_account_in_scope("arn:aws:iam::111111111111:user/x") is False


# --- Backwards compatibility: domain behaviour is unchanged ----------------


def test_existing_domain_behaviour_unchanged():
    scope = ScopeManager("example.com", s3_buckets=("target-*",), aws_accounts=("1" * 12,))
    # Everything test_scope_enforcement.py asserts must still hold.
    assert scope.is_in_scope("https://example.com") is True
    assert scope.is_in_scope("https://api.example.com") is True
    assert scope.is_in_scope("https://example.com.attacker.net") is False
    assert scope.is_in_scope("https://attacker-example.com") is False


# --- Config file -----------------------------------------------------------


def test_load_scope_config_json(tmp_path):
    cfg = tmp_path / "scope.json"
    cfg.write_text(
        json.dumps(
            {
                "buckets": ["target-*", "company-assets"],
                "accounts": ["123456789012"],
                "exclude": ["admin.example.com"],
            }
        ),
        encoding="utf-8",
    )
    loaded = load_scope_config(cfg)
    assert loaded["buckets"] == ("target-*", "company-assets")
    assert loaded["accounts"] == ("123456789012",)
    assert loaded["exclude"] == ("admin.example.com",)


def test_load_scope_config_accepts_aliases(tmp_path):
    cfg = tmp_path / "scope.json"
    cfg.write_text(
        json.dumps({"s3_buckets": ["b1"], "aws_accounts": ["123456789012"]}),
        encoding="utf-8",
    )
    loaded = load_scope_config(cfg)
    assert loaded["buckets"] == ("b1",)
    assert loaded["accounts"] == ("123456789012",)
    assert loaded["exclude"] == ()
