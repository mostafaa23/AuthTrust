"""SARIF 2.1.0 export for integration with code-scanning tooling
(GitHub/GitLab code scanning, and other SARIF consumers).

Each Wily ``Finding`` becomes one SARIF ``result``:
  - ``ruleId``   <- the finding's category (deduplicated into ``tool.driver.rules``)
  - ``level``    <- mapped from severity (error/warning/note)
  - ``message``  <- a short human description
  - ``locations``<- the asset as an artifact URI (http(s), s3:// or a bare host)

Evidence is redacted by default (the same ``sanitize_evidence_dict`` policy
the JSON/HTML writers use); pass ``redact=False`` (wired to ``--show-leak``)
only for a controlled demo.
"""

from __future__ import annotations

import json
from pathlib import Path

from wily import __version__
from wily.evidence.sanitize import sanitize_evidence_dict
from wily.risk.scoring import compute_risk_score

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemas/sarif-schema-2.1.0.json"
)

# SARIF only defines none/note/warning/error. Map Wily severities onto that set.
_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# GitHub reads security-severity (a 0-10 string) to bucket alerts.
_SEVERITY_TO_SECURITY_SCORE = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
}


def _level_for(severity: str) -> str:
    return _SEVERITY_TO_LEVEL.get((severity or "").lower(), "warning")


def _artifact_uri(asset: str) -> str:
    """A URI SARIF consumers accept. http(s) and s3:// pass through; a bare
    host/path gets no scheme invented for it beyond a safe ``wily:`` prefix so
    the value is never silently dropped."""
    a = (asset or "").strip()
    if not a:
        return "wily:unknown"
    lowered = a.lower()
    if lowered.startswith(("http://", "https://", "s3://")):
        return a
    return f"wily://{a}"


def _message_for(f) -> str:
    sev = (f.severity or "unknown").lower()
    return f"{f.category} ({sev}, confidence {float(f.confidence):.2f}) on {f.asset}"


def export_sarif(
    findings: list,
    output_path: Path,
    redact: bool = True,
    preserve_order: bool = False,
) -> Path:
    """Write a valid SARIF 2.1.0 log to ``output_path``.

    Findings are emitted in the given order when ``preserve_order`` is True
    (the ranked order from the pipeline); otherwise sorted by risk_score,
    highest first. Evidence is redacted by default.
    """
    output_path = Path(output_path)

    ordered = list(findings)
    if not preserve_order:
        ordered.sort(
            key=lambda f: (getattr(f, "risk_score", None)
                           or compute_risk_score(f.severity, f.confidence)),
            reverse=True,
        )

    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    results: list[dict] = []

    for f in ordered:
        category = f.category or "finding"
        if category not in rule_index:
            rule_index[category] = len(rules)
            rules.append(
                {
                    "id": category,
                    "name": category,
                    "shortDescription": {"text": category},
                    "defaultConfiguration": {"level": _level_for(f.severity)},
                    "properties": {
                        "security-severity": _SEVERITY_TO_SECURITY_SCORE.get(
                            (f.severity or "").lower(), "5.5"
                        ),
                        "tags": ["security", "wily"],
                    },
                }
            )

        evidence = dict(f.evidence or {})
        if redact:
            evidence = sanitize_evidence_dict(evidence)
        risk = getattr(f, "risk_score", None)
        if risk is None:
            risk = compute_risk_score(f.severity, f.confidence)

        results.append(
            {
                "ruleId": category,
                "ruleIndex": rule_index[category],
                "level": _level_for(f.severity),
                "message": {"text": _message_for(f)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _artifact_uri(f.asset)}
                        }
                    }
                ],
                "properties": {
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "risk_score": round(float(risk), 2),
                    "discovery_source": f.discovery_source,
                    "remediation": f.remediation,
                    "evidence": evidence,
                },
            }
        )

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Wily",
                        "informationUri": "https://github.com/wily/wily",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    output_path.write_text(
        json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return output_path
