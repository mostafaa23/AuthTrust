"""JSON export for programmatic consumption: asset, category, severity,
confidence, (redacted) evidence, discovery source, scan time and
remediation steps.
"""

from __future__ import annotations

import json
from pathlib import Path

from wily.evidence.sanitize import sanitize_evidence_dict
from wily.risk.scoring import compute_risk_score


def export_json(
    findings: list,
    output_path: Path,
    redact: bool = True,
    preserve_order: bool = False,
) -> Path:
    """Write the unified report.

    Secrets in evidence (AWS keys, bearer tokens, cookies, ...) are redacted
    by default. Pass ``redact=False`` (wired to the CLI's ``--show-leak``)
    only for a controlled demo where showing the captured leak is the point;
    never for a report that leaves a trusted machine.

    Each finding's ``risk_score`` (severity x confidence) is computed here when
    not already set. By default the report is sorted by that risk_score,
    highest first. Pass ``preserve_order=True`` when the caller has already
    ordered the findings (e.g. via ``risk/ml/ranker.rank_findings``, whose
    priority ordering can differ from raw risk_score) so that ranked order is
    the one the report reflects.
    """
    output_path = Path(output_path)
    serializable = []
    for f in findings:
        if getattr(f, "risk_score", None) is None:
            f.risk_score = compute_risk_score(f.severity, f.confidence)
        d = f.to_dict()
        if redact:
            d["evidence"] = sanitize_evidence_dict(d["evidence"])
        serializable.append(d)

    if not preserve_order:
        serializable.sort(key=lambda d: d.get("risk_score") or 0.0, reverse=True)

    output_path.write_text(
        json.dumps(
            {"findings": serializable, "count": len(serializable)},
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return output_path
