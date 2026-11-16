"""Remove duplicate findings and correlate findings about the same asset.

v1: deterministic rules (same asset + same category + evidence
similarity). Later: a model that can be measured against test data (not
a replacement for rules_engine).
"""


def deduplicate(findings: list) -> list:
    raise NotImplementedError
