"""Measure detector quality against synthetic ground truth.

**Ground truth is read here and nowhere else.** Detection code that peeks at labels is
grading its own homework; a test in ``tests/test_hunting.py`` parses the hunting package
AST to enforce that. Evaluation lives in its own package precisely so that boundary is
visible in the directory listing.

Defining what counts as a match -- the part that actually needs thought
----------------------------------------------------------------------
The naive approach is row-level: every telemetry row is a sample, flagged or not,
malicious or not, and you compute precision/recall over rows. For these rules that
produces nonsense, and it is worth being able to say why.

ATH-005 emits **one** finding covering fourteen failed logons plus the success. If you
score it row-wise it looks like fifteen detections. ATH-006 flags exactly one of those
same fifteen rows -- the successful logon -- so row-wise it appears to have "missed"
fourteen events it was never designed to see, and its recall collapses to 0.07. The
metric would be measuring the wrong thing and would push you to "fix" a rule that is
working correctly.

So this module uses two different units, deliberately, and labels them:

**Precision is finding-level.** A finding is a true positive if *any* of its evidence
events belongs to the labelled intrusion, and a false positive otherwise. This matches
how precision is actually experienced in a SOC: an analyst opens an alert, and it is
either worth their time or it is not. Fourteen failed logons in one alert cost one
triage, not fourteen.

    precision = TP findings / (TP findings + FP findings)

**Recall is opportunity-level.** Each rule declares the ground-truth *stages* it is
designed to cover (:data:`RULE_COVERAGE`). A stage is detected if some true-positive
finding from that rule cites at least one of the stage's events. Missed stages are
false negatives.

    recall = detected stages / declared stages

This asks the only recall question that means anything: *of the things this rule was
built to catch, how many did it catch?* Note the honest limitation -- a rule can score
1.00 recall while the portfolio as a whole misses entire attack stages, so
:func:`evaluate` also reports **portfolio coverage** across all ten labelled stages
separately. Per-rule recall and portfolio coverage answer different questions and the
report shows both.

A note on not cheating
----------------------
``RULE_COVERAGE`` lives in this module rather than on the detectors, and it is a
declaration of *design intent* written before looking at results. Tuning it after the
fact to make numbers look better would be overfitting to the synthetic labels, which is
worse than a mediocre score.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ath.hunting.engine import HuntResult
from ath.hunting.finding import Finding
from ath.logging_setup import get_logger
from ath.telemetry.loader import load_ground_truth

logger = get_logger(__name__)

INTRUSION = "intrusion"
BENIGN_LOOKALIKE = "benign_lookalike"


# Which labelled attack stages each rule is *designed* to cover. Declared design
# intent, not a post-hoc fit to the results.
RULE_COVERAGE: dict[str, frozenset[str]] = {
    "ATH-001": frozenset({"2-execution"}),
    "ATH-002": frozenset({"2-execution"}),
    "ATH-003": frozenset({"3-payload-download", "4-command-and-control", "10-exfiltration"}),
    "ATH-004": frozenset({"6-credential-access"}),
    "ATH-005": frozenset({"7-brute-force"}),
    "ATH-006": frozenset({"7-brute-force"}),
    "ATH-007": frozenset({"8-lateral-movement"}),
    "ATH-008": frozenset({"9-collection"}),
    # Added by the detection-engineering loop (Milestone 6). Both were proposed as
    # candidates against the gap this dict itself documented, evaluated, tightened once
    # to remove a measured false positive, and promoted -- see
    # src/ath/engineering/candidates.py and docs/detection-engineering.md.
    "ATH-009": frozenset({"1-initial-access"}),
    "ATH-010": frozenset({"5-discovery"}),
}

# Historical note: as of Milestone 3, NO rule targeted these two stages -- see the
# detection-engineering loop (Milestone 6) that closed this gap with ATH-009/ATH-010.
# Kept as an empty, explicit set rather than deleted, so the evaluation report's
# "untargeted stages" section continues to render (and correctly renders nothing) and
# the history of what this project used to be missing stays visible in the code.
UNCOVERED_STAGES: frozenset[str] = frozenset()


@dataclass(frozen=True)
class RuleEvaluation:
    """Measured quality for a single detection rule.

    Attributes:
        rule_id: The rule measured.
        true_positives: Findings citing at least one labelled intrusion event.
        false_positives: Findings citing no labelled intrusion event.
        false_negatives: Declared coverage stages that produced no true-positive finding.
        detected_stages: Stages this rule successfully covered.
        missed_stages: Stages this rule declared but did not detect.
        fp_benign_lookalike: False positives explained by the labelled benign scenario.
        fp_unexplained: False positives matching no label at all -- these are the ones
            that need investigation, since we cannot account for them.
        flagged_event_ids: Every telemetry event this rule's findings cited.
    """

    rule_id: str
    true_positives: int
    false_positives: int
    false_negatives: int
    detected_stages: tuple[str, ...] = ()
    missed_stages: tuple[str, ...] = ()
    fp_benign_lookalike: int = 0
    fp_unexplained: int = 0
    flagged_event_ids: tuple[str, ...] = ()

    @property
    def findings_total(self) -> int:
        return self.true_positives + self.false_positives

    @property
    def precision(self) -> float:
        """TP / (TP + FP), finding-level. Returns 1.0 when the rule emitted nothing.

        A rule that produces no findings has raised no bad alerts, so it is vacuously
        precise. The recall figure is what exposes a silent rule -- read them together.
        """
        denominator = self.true_positives + self.false_positives
        return 1.0 if denominator == 0 else self.true_positives / denominator

    @property
    def recall(self) -> float:
        """Detected stages / declared stages. Returns 1.0 when nothing was declared."""
        denominator = len(self.detected_stages) + len(self.missed_stages)
        return 1.0 if denominator == 0 else len(self.detected_stages) / denominator

    @property
    def f1(self) -> float:
        """Harmonic mean of precision and recall."""
        p, r = self.precision, self.recall
        return 0.0 if (p + r) == 0 else 2 * p * r / (p + r)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "detected_stages": list(self.detected_stages),
            "missed_stages": list(self.missed_stages),
            "fp_benign_lookalike": self.fp_benign_lookalike,
            "fp_unexplained": self.fp_unexplained,
        }


@dataclass
class EvaluationReport:
    """Evaluation across every rule, plus portfolio-level coverage.

    Attributes:
        rules: Per-rule results, ordered by rule id.
        covered_stages: Attack stages detected by *any* rule.
        uncovered_stages: Labelled stages no rule detected.
        untargeted_stages: Stages no rule even declares coverage for.
        total_events: Total telemetry events evaluated.
    """

    rules: list[RuleEvaluation] = field(default_factory=list)
    covered_stages: tuple[str, ...] = ()
    uncovered_stages: tuple[str, ...] = ()
    untargeted_stages: tuple[str, ...] = ()
    total_events: int = 0

    @property
    def total_true_positives(self) -> int:
        return sum(r.true_positives for r in self.rules)

    @property
    def total_false_positives(self) -> int:
        return sum(r.false_positives for r in self.rules)

    @property
    def overall_precision(self) -> float:
        denominator = self.total_true_positives + self.total_false_positives
        return 1.0 if denominator == 0 else self.total_true_positives / denominator

    @property
    def stage_coverage(self) -> float:
        """Fraction of all labelled attack stages detected by any rule."""
        total = len(self.covered_stages) + len(self.uncovered_stages)
        return 1.0 if total == 0 else len(self.covered_stages) / total

    def to_dict(self) -> dict[str, Any]:
        return {
            "rules": [r.to_dict() for r in self.rules],
            "overall_precision": round(self.overall_precision, 4),
            "stage_coverage": round(self.stage_coverage, 4),
            "covered_stages": list(self.covered_stages),
            "uncovered_stages": list(self.uncovered_stages),
            "untargeted_stages": list(self.untargeted_stages),
            "total_true_positives": self.total_true_positives,
            "total_false_positives": self.total_false_positives,
            "total_events": self.total_events,
        }


def _classify(finding: Finding, attack_ids: set[str]) -> bool:
    """True if the finding cites at least one labelled intrusion event."""
    return bool(set(finding.event_ids) & attack_ids)


def score_rule(
    rule_id: str,
    findings: list[Finding],
    declared_stages: frozenset[str],
    *,
    attack_ids: set[str],
    benign_ids: set[str],
    stages: dict[str, set[str]],
) -> RuleEvaluation:
    """Score one rule's findings against ground truth.

    This is the single place the finding-level-precision / opportunity-level-recall
    semantics are implemented (see the module docstring for why row-level scoring would
    be misleading). :func:`evaluate` calls this once per registered rule; the
    detection-engineering harness (:mod:`ath.engineering.harness`) calls it identically
    for a **candidate** rule that is not registered anywhere -- so a proposed rule is
    scored with exactly the same rules as an accepted one, and "the metrics improved"
    or "the metrics did not improve" means the same thing in both places.

    Args:
        rule_id: Identifier for the rule being scored (registered or candidate).
        findings: This rule's findings.
        declared_stages: Ground-truth stage names this rule is designed to cover.
        attack_ids: All event ids belonging to the labelled intrusion.
        benign_ids: All event ids belonging to the labelled benign look-alike.
        stages: Mapping of stage name -> its event ids.

    Returns:
        A populated :class:`RuleEvaluation`.
    """
    true_positives = [f for f in findings if _classify(f, attack_ids)]
    false_positives = [f for f in findings if not _classify(f, attack_ids)]

    tp_events = {eid for f in true_positives for eid in f.event_ids}
    detected = {s for s in declared_stages if stages.get(s, set()) & tp_events}
    missed = declared_stages - detected

    fp_benign = sum(1 for f in false_positives if set(f.event_ids) & benign_ids)

    return RuleEvaluation(
        rule_id=rule_id,
        true_positives=len(true_positives),
        false_positives=len(false_positives),
        false_negatives=len(missed),
        detected_stages=tuple(sorted(detected)),
        missed_stages=tuple(sorted(missed)),
        fp_benign_lookalike=fp_benign,
        fp_unexplained=len(false_positives) - fp_benign,
        flagged_event_ids=tuple(sorted({eid for f in findings for eid in f.event_ids})),
    )


def load_scoring_context(data_dir: Path) -> tuple[set[str], set[str], dict[str, set[str]]]:
    """Load the (attack_ids, benign_ids, stages) tuple :func:`score_rule` needs.

    Exposed separately so a caller scoring several candidate rules in one session
    (as the engineering harness does) loads ground truth once rather than per rule.
    """
    ground_truth = load_ground_truth(data_dir)
    scenarios = ground_truth["scenarios"]
    attack_ids = set(scenarios[INTRUSION]["event_ids"])
    benign_ids = set(scenarios.get(BENIGN_LOOKALIKE, {}).get("event_ids", []))
    stages = {
        name: set(stage["event_ids"])
        for name, stage in scenarios[INTRUSION]["stages"].items()
    }
    return attack_ids, benign_ids, stages


def evaluate(
    hunt_result: HuntResult,
    data_dir: Path,
    *,
    total_events: int = 0,
) -> EvaluationReport:
    """Score a hunt against ground truth.

    Args:
        hunt_result: Output of :func:`ath.hunting.run_hunt`.
        data_dir: Directory containing ``ground_truth.json``.
        total_events: Optional total event count, for context in the report.

    Returns:
        A populated :class:`EvaluationReport`.
    """
    attack_ids, benign_ids, stages = load_scoring_context(data_dir)

    report = EvaluationReport(total_events=total_events)
    all_detected_stages: set[str] = set()

    for rule_id in sorted(RULE_COVERAGE):
        evaluation = score_rule(
            rule_id, hunt_result.by_rule(rule_id), RULE_COVERAGE[rule_id],
            attack_ids=attack_ids, benign_ids=benign_ids, stages=stages,
        )
        all_detected_stages |= set(evaluation.detected_stages)
        report.rules.append(evaluation)

    report.covered_stages = tuple(sorted(all_detected_stages))
    report.uncovered_stages = tuple(sorted(set(stages) - all_detected_stages))
    report.untargeted_stages = tuple(sorted(UNCOVERED_STAGES & set(stages)))

    logger.info(
        "Evaluation: precision=%.2f over %d findings; stage coverage %d/%d",
        report.overall_precision,
        report.total_true_positives + report.total_false_positives,
        len(report.covered_stages),
        len(stages),
    )
    return report
