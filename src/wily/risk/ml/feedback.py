"""Analyst feedback loop.

Records a human's --valid / --false-positive decision against a finding's
stable identity (``risk/ml/dedup.finding_hash_key``) rather than its row
position in one report, so the decision survives a re-scan where the
concrete object id in the asset URL changes but the underlying finding
shape doesn't.

This module only stores and replays decisions - it does not train anything.
It exists to start accumulating the labeled data a future heuristic scorer
revision or trained classifier would need (see ``risk/ml/sensitivity.py``'s
docstring); until there's enough of it, ``apply()`` just annotates matching
findings with the prior verdict for an analyst/report to see, it never
drops or reorders anything itself.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from wily.risk.ml.dedup import finding_hash_key, get_field

VALID = "valid"
FALSE_POSITIVE = "false_positive"
_VERDICTS = frozenset({VALID, FALSE_POSITIVE})

_DECISION_FIELDS = ("hash_key", "verdict", "category", "asset", "note", "recorded_at")


@dataclass
class FeedbackDecision:
    hash_key: str
    verdict: str  # VALID | FALSE_POSITIVE
    category: str = ""
    asset: str = ""
    note: str = ""
    recorded_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {name: getattr(self, name) for name in _DECISION_FIELDS}


class FeedbackStore:
    """An append-only JSONL log of analyst decisions, keyed by
    ``finding_hash_key``.

    Append-only so a later correction is a new line, not a silently lost
    edit; ``decisions_by_hash`` collapses the log to "latest decision per
    hash_key" for callers that just want the current verdict.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def record(self, finding, verdict: str, note: str = "") -> FeedbackDecision:
        """Append one decision for ``finding`` (a ``Finding`` dataclass or a
        dict reloaded from a JSON report - see ``get_field``)."""
        if verdict not in _VERDICTS:
            raise ValueError(f"verdict must be one of {sorted(_VERDICTS)}, got {verdict!r}")
        decision = FeedbackDecision(
            hash_key=finding_hash_key(finding),
            verdict=verdict,
            category=get_field(finding, "category", "") or "",
            asset=get_field(finding, "asset", "") or "",
            note=note,
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(decision.to_dict(), ensure_ascii=False) + "\n")
        return decision

    def all_decisions(self) -> list[FeedbackDecision]:
        """Every decision ever recorded, oldest first. A malformed line is
        skipped rather than aborting the read - a corrupt one entry must
        never hide every other analyst's recorded decision."""
        if not self.path.exists():
            return []
        out: list[FeedbackDecision] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except (ValueError, TypeError):
                continue
            if not isinstance(data, dict) or "hash_key" not in data or "verdict" not in data:
                continue
            out.append(FeedbackDecision(**{name: data.get(name, "") for name in _DECISION_FIELDS}))
        return out

    def decisions_by_hash(self) -> dict[str, FeedbackDecision]:
        """The latest decision per hash_key - a later record() for the same
        finding shape overrides an earlier one (the analyst changed their
        mind), since the log itself is append-only."""
        latest: dict[str, FeedbackDecision] = {}
        for decision in self.all_decisions():
            latest[decision.hash_key] = decision
        return latest

    def apply(self, findings: list) -> list:
        """Annotate each finding whose hash_key has a prior decision with
        ``evidence['feedback_verdict']`` / ``['feedback_recorded_at']``.

        Purely additive: never drops or reorders a finding. A finding
        without a resolvable hash is left untouched rather than erroring.
        """
        decisions = self.decisions_by_hash()
        if not decisions:
            return findings
        for finding in findings:
            try:
                key = finding_hash_key(finding)
            except Exception:
                continue
            decision = decisions.get(key)
            if decision is None:
                continue
            evidence = get_field(finding, "evidence", None)
            if isinstance(evidence, dict):
                evidence["feedback_verdict"] = decision.verdict
                evidence["feedback_recorded_at"] = decision.recorded_at
        return findings
