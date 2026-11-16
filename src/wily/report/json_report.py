"""JSON export for programmatic consumption: asset, category, severity,
confidence, (redacted) evidence, discovery source, scan time and
remediation steps.
"""

from __future__ import annotations

import json
from pathlib import Path

from wily.evidence.sanitize import sanitize_evidence_dict
from wily.risk.scoring import compute_risk_score


def export_json(findings: list, output_path: Path, redact: bool = True) -> Path:
    """Write the unified report.

    Secrets in evidence (AWS keys, bearer tokens, cookies, ...) are redacted
    by default. Pass ``redact=False`` (wired to the CLI's ``--show-leak``)
    only for a controlled demo where showing the captured leak is the point;
    never for a report that leaves a trusted machine.

    Findings are sorted by risk_score (severity x confidence), highest first,
    so the most important results are at the top of the report.
    """
    output_path = Path(output_path)
    serializable = []
    for f in findings:
        f.risk_score = compute_risk_score(f.severity, f.confidence)
        d = f.to_dict()
        if redact:
            d["evidence"] = sanitize_evidence_dict(d["evidence"])
        serializable.append(d)

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
