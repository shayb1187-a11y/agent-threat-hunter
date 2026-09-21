"""Analyst verdicts: what a human decided, and how often the system agreed.

The gap this closes
-------------------
An analyst dismissing a finding taught this system nothing. Every run started from the
same priors, so a false positive an analyst closed on Monday arrived identically on
Tuesday, and there was no way to answer the only question that matters about a triage
layer in production: **is it actually right?** Benchmark numbers come from labelled
fixtures, which measure the system against scenarios its authors invented. Analyst
verdicts measure it against reality.

Storage is a durable, append-only log
--------------------------------------
Verdicts are facts about what a person concluded at a point in time, so they are never
edited or deleted. A later verdict on the same finding supersedes an earlier one for
scoring purposes, and both stay on disk -- an analyst changing their mind is itself
information, and a store that silently overwrote history could not distinguish "we were
right the first time" from "we were never wrong".

JSON Lines, because the operations that matter are *append one record* and *read all
records*, and a text format keeps the log inspectable with a text editor when something
has gone wrong. There is no database here for the same reason there is no ORM: the
deterministic core of this project should stay legible.

What this deliberately does not do
-----------------------------------
**It does not feed back into detection automatically.** Nothing here changes a rule, a
threshold, or a benign signal. A system that silently re-tuned itself on analyst clicks
would drift in ways nobody could audit, and an attacker who could get one finding
dismissed would train the system to dismiss the next one. Feedback is *measurement*
first; any change it motivates is a change a human makes deliberately, with the
disagreement report in front of them.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from ath.logging_setup import get_logger
from ath.triage.benign import Disposition, TriageAssessment

logger = get_logger(__name__)

FEEDBACK_FILENAME = "analyst_feedback.jsonl"


class Verdict(str, Enum):
    """What an analyst concluded about a finding."""

    TRUE_POSITIVE = "true_positive"
    """Real, and the detection was right to raise it."""

    FALSE_POSITIVE = "false_positive"
    """Legitimate activity. The alert cost triage time and returned nothing."""

    BENIGN_TRUE_POSITIVE = "benign_true_positive"
    """The behaviour genuinely happened and the rule was right to describe it, but it
    was authorised. A penetration test, an administrator's own tooling, a sanctioned
    scan. Distinguished from ``false_positive`` because the remedy is different: the
    rule is working and needs an exception, not a fix."""

    UNDETERMINED = "undetermined"
    """Investigated and could not be resolved. Kept as a category rather than forced
    into one of the others -- a system that cannot record "we do not know" quietly
    converts uncertainty into whichever answer is cheaper."""

    @property
    def is_actionable_threat(self) -> bool:
        """Whether this verdict means something genuinely needed a response."""
        return self is Verdict.TRUE_POSITIVE


@dataclass(frozen=True)
class AnalystVerdict:
    """One recorded human decision about one finding.

    Attributes:
        finding_id: The finding judged.
        rule_id: Its rule, denormalised so the log is readable on its own.
        verdict: What the analyst concluded.
        analyst: Who decided. Recorded because disagreement between analysts is a
            different problem from disagreement between analyst and system.
        note: Free-text rationale.
        system_disposition: What triage said at the time, so agreement can be scored
            later without re-running the pipeline against telemetry that may have
            since been rotated away.
        recorded_at: When the verdict was recorded (UTC).
    """

    finding_id: str
    rule_id: str
    verdict: Verdict
    analyst: str = "unknown"
    note: str = ""
    system_disposition: Disposition | None = None
    recorded_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def system_agreed(self) -> bool | None:
        """Whether triage reached the same conclusion. ``None`` when it had no opinion.

        ``needs_review`` is not counted as agreement or disagreement in either
        direction. It is the system declining to call it, which is a legitimate answer
        and must not be scored as a win when the analyst happens to agree -- otherwise
        the safest way to look accurate would be to have no opinion about anything.
        """
        if self.system_disposition is None:
            return None
        if self.system_disposition is Disposition.NEEDS_REVIEW:
            return None
        if self.verdict is Verdict.UNDETERMINED:
            return None
        analyst_says_benign = self.verdict in (
            Verdict.FALSE_POSITIVE, Verdict.BENIGN_TRUE_POSITIVE
        )
        system_says_benign = self.system_disposition is Disposition.LIKELY_BENIGN
        return analyst_says_benign == system_says_benign

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "verdict": self.verdict.value,
            "analyst": self.analyst,
            "note": self.note,
            "system_disposition": (
                self.system_disposition.value if self.system_disposition else None
            ),
            "recorded_at": self.recorded_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> AnalystVerdict:
        disposition = payload.get("system_disposition")
        return cls(
            finding_id=payload["finding_id"],
            rule_id=payload.get("rule_id", ""),
            verdict=Verdict(payload["verdict"]),
            analyst=payload.get("analyst", "unknown"),
            note=payload.get("note", ""),
            system_disposition=Disposition(disposition) if disposition else None,
            recorded_at=datetime.fromisoformat(payload["recorded_at"]),
        )


class FeedbackStore:
    """An append-only JSON Lines log of analyst verdicts.

    Args:
        path: The log file. Created on first write; a missing file reads as empty,
            because "no feedback yet" is the normal state of a new deployment and
            should not be an error.
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    def record(self, verdict: AnalystVerdict) -> None:
        """Append one verdict. Never rewrites or removes an earlier record."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(verdict.to_dict()) + "\n")
        logger.info(
            "recorded %s for %s by %s", verdict.verdict.value,
            verdict.finding_id, verdict.analyst,
        )

    def all_verdicts(self) -> list[AnalystVerdict]:
        """Every verdict ever recorded, in the order recorded.

        A malformed line is skipped with a warning rather than raising: a corrupt entry
        should cost one record, not the whole history.
        """
        if not self.path.exists():
            return []
        verdicts: list[AnalystVerdict] = []
        for number, line in enumerate(
            self.path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            try:
                verdicts.append(AnalystVerdict.from_dict(json.loads(line)))
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                logger.warning("skipping malformed feedback at line %d: %s", number, exc)
        return verdicts

    def current(self) -> dict[str, AnalystVerdict]:
        """The latest verdict per finding.

        History is preserved on disk; this is the view used for scoring, because an
        analyst who revised their conclusion should be scored against the conclusion
        they actually hold.
        """
        latest: dict[str, AnalystVerdict] = {}
        for verdict in self.all_verdicts():
            existing = latest.get(verdict.finding_id)
            if existing is None or verdict.recorded_at >= existing.recorded_at:
                latest[verdict.finding_id] = verdict
        return latest


@dataclass
class FeedbackMetrics:
    """How well triage dispositions match what analysts actually concluded."""

    total: int = 0
    scored: int = 0
    agreed: int = 0
    disagreed: int = 0
    system_had_no_opinion: int = 0
    dangerous_disagreements: tuple[str, ...] = ()
    """Findings the system called benign that an analyst confirmed as real threats.

    Tracked separately from ordinary disagreement because the two are not comparable.
    Every other mistake costs an analyst some time; this one tells them to ignore a
    live intrusion, and one instance is worth more attention than any aggregate rate."""

    by_verdict: dict[str, int] = field(default_factory=dict)
    by_rule: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def agreement_rate(self) -> float:
        """Agreement over the verdicts the system actually took a position on."""
        return 0.0 if not self.scored else self.agreed / self.scored

    @property
    def opinion_rate(self) -> float:
        """Fraction of judged findings the system was willing to call either way.

        Reported next to the agreement rate on purpose. A layer that abstains from
        everything scores a perfect agreement rate while being useless, and these two
        numbers are only meaningful read together.
        """
        return 0.0 if not self.total else self.scored / self.total

    @property
    def noisiest_rules(self) -> list[tuple[str, int]]:
        """Rules with the most analyst-confirmed false positives, worst first.

        The output that should actually drive detection engineering: this is measured
        false-positive cost from production, not an estimate from a fixture.
        """
        counts = [
            (rule, tallies.get(Verdict.FALSE_POSITIVE.value, 0))
            for rule, tallies in self.by_rule.items()
        ]
        return sorted(
            [entry for entry in counts if entry[1]], key=lambda e: -e[1]
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "scored": self.scored,
            "agreed": self.agreed,
            "disagreed": self.disagreed,
            "system_had_no_opinion": self.system_had_no_opinion,
            "agreement_rate": round(self.agreement_rate, 4),
            "opinion_rate": round(self.opinion_rate, 4),
            "dangerous_disagreements": list(self.dangerous_disagreements),
            "by_verdict": dict(self.by_verdict),
            "noisiest_rules": self.noisiest_rules,
        }


def score_feedback(verdicts: Iterable[AnalystVerdict]) -> FeedbackMetrics:
    """Measure triage against recorded analyst verdicts."""
    metrics = FeedbackMetrics()
    dangerous: list[str] = []

    for verdict in verdicts:
        metrics.total += 1
        metrics.by_verdict[verdict.verdict.value] = (
            metrics.by_verdict.get(verdict.verdict.value, 0) + 1
        )
        rule_tallies = metrics.by_rule.setdefault(verdict.rule_id, {})
        rule_tallies[verdict.verdict.value] = (
            rule_tallies.get(verdict.verdict.value, 0) + 1
        )

        agreed = verdict.system_agreed
        if agreed is None:
            metrics.system_had_no_opinion += 1
            continue
        metrics.scored += 1
        if agreed:
            metrics.agreed += 1
        else:
            metrics.disagreed += 1
            if (
                verdict.system_disposition is Disposition.LIKELY_BENIGN
                and verdict.verdict.is_actionable_threat
            ):
                dangerous.append(verdict.finding_id)

    metrics.dangerous_disagreements = tuple(dangerous)
    return metrics


def verdict_from_assessment(
    assessment: TriageAssessment, verdict: Verdict, analyst: str, note: str = ""
) -> AnalystVerdict:
    """Build a verdict that carries what the system thought at the time."""
    return AnalystVerdict(
        finding_id=assessment.finding_id,
        rule_id=assessment.rule_id,
        verdict=verdict,
        analyst=analyst,
        note=note,
        system_disposition=assessment.disposition,
    )
