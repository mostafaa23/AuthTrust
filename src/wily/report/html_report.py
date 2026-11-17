"""Self-contained HTML report for human review (Jinja2 template in
report/templates/base.html.j2).

A single static .html file (no external CSS/JS, no network) that a tester
can open in any browser. Findings are shown highest-risk first (the order
the pipeline already produced - accepted verbatim, like
``json_report``'s ``preserve_order``) and the table is sortable/filterable
by severity, category and asset client-side.

Evidence is redacted by default (the same ``sanitize_evidence_dict``
policy the JSON writer uses); pass ``redact=False`` (wired to the CLI's
``--show-leak``) only for a controlled demo.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from wily.evidence.sanitize import sanitize_evidence_dict
from wily.risk.scoring import compute_risk_score

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_TEMPLATE_NAME = "base.html.j2"

# Highest first - mirrors the console summary ordering.
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "htm", "xml", "j2"]),
    )


def _evidence_lines(evidence: dict) -> list[tuple[str, str]]:
    """Flatten an evidence dict into (key, value) string pairs for display.

    Autoescaping in the template handles HTML-safety; here we only turn
    non-string values into a readable string.
    """
    lines: list[tuple[str, str]] = []
    for key, value in (evidence or {}).items():
        if isinstance(value, (dict, list)):
            import json as _json

            text = _json.dumps(value, ensure_ascii=False, sort_keys=True)
        else:
            text = str(value)
        lines.append((str(key), text))
    return lines


def _rows(findings: list, redact: bool) -> list[dict]:
    rows: list[dict] = []
    for f in findings:
        risk = getattr(f, "risk_score", None)
        if risk is None:
            risk = compute_risk_score(f.severity, f.confidence)
        evidence = dict(f.evidence or {})
        if redact:
            evidence = sanitize_evidence_dict(evidence)
        rows.append(
            {
                "asset": str(f.asset),
                "category": f.category,
                "severity": f.severity,
                "severity_rank": _SEVERITY_ORDER.get(f.severity, 99),
                "confidence": f.confidence,
                "risk_score": round(float(risk), 2),
                "discovery_source": f.discovery_source,
                "remediation": f.remediation,
                "scanned_at": getattr(f, "scanned_at", None),
                "evidence": _evidence_lines(evidence),
            }
        )
    return rows


def export_html(
    findings: list,
    output_path: Path,
    redact: bool = True,
    preserve_order: bool = False,
) -> Path:
    """Render ``findings`` to a self-contained HTML report at ``output_path``.

    Findings are accepted in the given order (the ranked order from the
    pipeline) when ``preserve_order`` is True; otherwise they are sorted by
    severity then risk_score, highest first. Evidence is redacted by default.
    """
    output_path = Path(output_path)
    rows = _rows(findings, redact)

    if not preserve_order:
        rows.sort(key=lambda r: (r["severity_rank"], -r["risk_score"]))

    severity_counts: dict[str, int] = {}
    for r in rows:
        severity_counts[r["severity"]] = severity_counts.get(r["severity"], 0) + 1
    # Ordered highest-severity first for a stable summary display.
    ordered_counts = [
        (sev, severity_counts[sev])
        for sev in sorted(severity_counts, key=lambda s: _SEVERITY_ORDER.get(s, 99))
    ]

    env = _environment()
    template = env.get_template(_TEMPLATE_NAME)
    html = template.render(
        findings=rows,
        count=len(rows),
        severity_counts=ordered_counts,
        redacted=redact,
        generated_at=_dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
    output_path.write_text(html, encoding="utf-8")
    return output_path
