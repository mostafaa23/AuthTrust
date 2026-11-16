"""JSON export for programmatic consumption: asset, category, severity,
confidence, (redacted) evidence, discovery source, scan time and
remediation steps.
"""

from __future__ import annotations

import json
from pathlib import Path

from wily.evidence.sanitize import sanitize_evidence_dict
from wily.risk.scoring import compute_risk_score


def export_json(findings: list, output_path: Path) -> Path:
    output_path = Path(output_path)
    serializable = []
    for f in findings:
        f.risk_score = compute_risk_score(f.severity, f.confidence)
        d = f.to_dict()
    #   d["evidence"] = sanitize_evidence_dict(d["evidence"]) # (لإظهار التسريب)
        serializable.append(d)

    output_path.write_text(
        json.dumps(
            {"findings": serializable, "count": len(serializable)},
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return output_path
