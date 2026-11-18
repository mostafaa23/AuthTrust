"""Mutation-based cloud resource name generation.

Builds candidate bucket/storage names from one or more keywords (typically
the target's own name) combined with mutation words, instead of requiring
a pre-written wordlist file. For each keyword, emits the bare keyword plus
six combined forms per mutation word (``.``/``-``/no separator, both
orders). Pure/offline; the cloud-storage scanner that consumes the
generated names enforces scope and safety.
"""

from __future__ import annotations

import re
from pathlib import Path

__all__ = [
    "DEFAULT_MUTATIONS",
    "clean_text",
    "build_names",
    "generate_candidates",
    "load_mutations",
    "valid_s3_name",
    "valid_gcp_name",
    "azure_account_name",
]

# A small, high-signal default mutation set. Kept intentionally short so the
# default run stays bounded (1 + 6N names per keyword); point --cloud-enum-
# wordlist at a larger list (e.g. cloud_enum's fuzz.txt) for a deeper sweep.
DEFAULT_MUTATIONS: tuple[str, ...] = (
    "dev", "development", "prod", "production", "stage", "staging", "test",
    "qa", "sandbox", "demo", "backup", "backups", "bak", "archive", "old",
    "data", "db", "database", "dump", "logs", "log", "assets", "static",
    "media", "images", "img", "uploads", "files", "public", "private",
    "internal", "external", "www", "web", "app", "api", "cdn", "admin",
    "config", "secret", "secrets", "keys", "temp", "tmp", "cache", "store",
    "storage", "bucket", "s3", "content", "documents", "docs", "download",
    "downloads", "resources", "users", "user", "client", "clients",
)

# Separators cloud_enum combines a keyword and a mutation with (plus "" = none).
_SEPARATORS = (".", "-", "")

# cloud_enum's clean_text: lowercase, then drop anything outside [a-z0-9.-].
_CLEAN_RE = re.compile(r"[^a-z0-9.\-]")

# S3 / GCP bucket naming: 3-63 chars, lowercase alphanumerics, dots, hyphens.
_S3_NAME_RE = re.compile(r"[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]")
# Azure storage account: 3-24 lowercase alphanumerics only (no dots/hyphens).
_AZURE_NAME_RE = re.compile(r"[a-z0-9]{3,24}")


def clean_text(text: str) -> str:
    """Lowercase ``text`` and strip every character outside ``[a-z0-9.-]``."""
    return _CLEAN_RE.sub("", (text or "").lower())


def valid_s3_name(name: str) -> bool:
    """True for a syntactically valid S3/GCP bucket name (3-63 chars)."""
    return bool(3 <= len(name) <= 63 and _S3_NAME_RE.fullmatch(name))


# GCP bucket names follow the same shape here (underscores are legal in GCP but
# are never produced by this generator, so the S3 validator is sufficient).
valid_gcp_name = valid_s3_name


def azure_account_name(name: str) -> str | None:
    """Reduce a candidate to a valid Azure storage-account name, or None.

    Azure accounts are lowercase alphanumerics only, 3-24 chars - so the dots
    and hyphens in a generated name are removed, and the result is accepted
    only if what remains is 3-24 alphanumerics.
    """
    stripped = re.sub(r"[^a-z0-9]", "", (name or "").lower())
    return stripped if _AZURE_NAME_RE.fullmatch(stripped) else None


def build_names(keywords: list[str], mutations: list[str]) -> list[str]:
    """Generate candidate names from keywords x mutations (cloud_enum-style).

    For each cleaned keyword: the bare keyword, then for each cleaned mutation
    the six forms ``{kw}{mut}``, ``{kw}.{mut}``, ``{kw}-{mut}`` and the three
    reversed forms. Order is preserved and exact duplicates are collapsed. Only
    names of length <= 63 are kept (the bucket-name ceiling).
    """
    out: list[str] = []
    seen: set[str] = set()

    def _add(candidate: str) -> None:
        if candidate and len(candidate) <= 63 and candidate not in seen:
            seen.add(candidate)
            out.append(candidate)

    cleaned_mutations = [m for m in (clean_text(m) for m in mutations) if m]
    for raw_kw in keywords:
        base = clean_text(raw_kw)
        if not base:
            continue
        _add(base)
        for mut in cleaned_mutations:
            for sep in _SEPARATORS:
                _add(f"{base}{sep}{mut}")
                _add(f"{mut}{sep}{base}")
    return out


def generate_candidates(
    keywords: list[str],
    mutations: list[str] | None = None,
    *,
    max_candidates: int | None = None,
) -> list[str]:
    """Top-level helper: build candidate names and optionally cap the count.

    ``mutations`` defaults to :data:`DEFAULT_MUTATIONS`. ``max_candidates``
    bounds the output so an enormous wordlist cannot blow up the number of live
    probes - the first ``max_candidates`` (keyword-first order) are kept.
    """
    muts = list(mutations) if mutations is not None else list(DEFAULT_MUTATIONS)
    names = build_names(list(keywords), muts)
    if max_candidates is not None and max_candidates >= 0:
        names = names[:max_candidates]
    return names


def load_mutations(path: str | Path) -> list[str]:
    """Load a mutations wordlist (one entry per line), cloud_enum's fuzz.txt
    format. Blank lines are dropped; no comment/weight syntax is assumed."""
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    return [line.strip() for line in text.splitlines() if line.strip()]


def keyword_from_domain(domain: str) -> str:
    """Derive a default enumeration keyword from a domain: its registrable
    label (e.g. ``example`` from ``api.example.co.uk``). A pragmatic heuristic -
    the second-level label - not a full public-suffix lookup."""
    host = (domain or "").strip().lower().strip(".")
    # Drop a scheme/path if a URL slipped through.
    host = re.sub(r"^[a-z]+://", "", host).split("/", 1)[0].split(":", 1)[0]
    labels = [l for l in host.split(".") if l]
    if not labels:
        return ""
    if len(labels) == 1:
        return clean_text(labels[0])
    # Handle common two-part TLDs (co.uk, com.au, ...) by taking the label
    # before them when present.
    two_part = {"co", "com", "org", "net", "gov", "edu", "ac"}
    if len(labels) >= 3 and labels[-2] in two_part and len(labels[-1]) == 2:
        return clean_text(labels[-3])
    return clean_text(labels[-2])
