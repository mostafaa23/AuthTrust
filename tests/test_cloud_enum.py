"""Phase: cloud resource name generation (recon/cloud_enum.py).

Pure/offline - no network. Mirrors cloud_enum's build_names expansion and the
per-provider name validity rules.
"""

from wily.recon.cloud_enum import (
    azure_account_name,
    build_names,
    clean_text,
    generate_candidates,
    keyword_from_domain,
    valid_s3_name,
)


def test_clean_text_lowercases_and_strips():
    assert clean_text("Example_Corp!") == "examplecorp"
    assert clean_text("My-App.Site") == "my-app.site"


def test_build_names_emits_bare_keyword_and_six_forms():
    out = build_names(["acme"], ["dev"])
    assert "acme" in out
    # six combined forms with ., - and no separator, both orders
    for expected in ("acmedev", "acme.dev", "acme-dev", "devacme", "dev.acme", "dev-acme"):
        assert expected in out
    # 1 bare + 6 combined = 7, de-duplicated and order-preserved
    assert out[0] == "acme"
    assert len(out) == 7


def test_build_names_dedupes_and_caps_length():
    # a mutation that would push a name past 63 chars is dropped
    long_mut = "x" * 60
    out = build_names(["acme"], [long_mut])
    assert all(len(n) <= 63 for n in out)
    # "acme" itself still present
    assert "acme" in out


def test_generate_candidates_respects_max():
    out = generate_candidates(["acme"], ["dev", "prod", "test"], max_candidates=4)
    assert len(out) == 4
    assert out[0] == "acme"  # keyword-first ordering preserved


def test_valid_s3_name():
    assert valid_s3_name("my-bucket")
    assert valid_s3_name("a.b.c")
    assert not valid_s3_name("ab")  # too short
    assert not valid_s3_name("UPPER")  # uppercase not allowed
    assert not valid_s3_name("x" * 64)  # too long


def test_azure_account_name_strips_separators_and_validates():
    assert azure_account_name("acme-dev") == "acmedev"
    assert azure_account_name("acme.backups") == "acmebackups"
    # Result must be 3-24 alphanumerics.
    assert azure_account_name("ab") is None
    assert azure_account_name("x" * 25) is None


def test_keyword_from_domain():
    assert keyword_from_domain("api.example.com") == "example"
    assert keyword_from_domain("example.com") == "example"
    assert keyword_from_domain("shop.example.co.uk") == "example"
    assert keyword_from_domain("https://assets.acme-corp.com/path") == "acme-corp"
