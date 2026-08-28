"""The detection-engineering harness: propose, evaluate, iterate, decide.

This module -- like ``ath.evaluation`` -- is explicitly permitted to read ground truth,
because scoring a candidate rule's quality is exactly what evaluation means. The
boundary that matters is upstream of here: :mod:`ath.engineering.candidates` (the
proposal logic itself) never touches ground truth, which is verified by a dedicated
test the same way it is for every rule in :mod:`ath.hunting`.

The workflow this module runs is literally the one Milestone 8 asked for::

    generated rule -> test -> inspect failures -> improve rule -> retest

For each gap (Initial Access, Discovery), ``v1`` is scored, its false positives are
attributed to specific telemetry rows so the failure is inspectable rather than just a
number, ``v2`` is scored, and the two are compared. Nothing here decides in advance
that ``v2`` will win -- the numbers are computed the same way for both, using
:func:`ath.evaluation.score_rule`, the identical function the permanent rule set is
scored with.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ath.engineering.candidates import ALL_CANDIDATES, Candidate
from ath.evaluation.evaluator import RuleEvaluation, load_scoring_context, score_rule
from ath.hunting.finding import Finding
from ath.logging_setup import get_logger
from ath.telemetry.loader import Telemetry

logger = get_logger(__name__)


@dataclass(frozen=True)
class CandidateResult:
    """One candidate's findings, its measured evaluation, and its false positives.

    Attributes:
        candidate: The candidate that was run.
        findings: What it found on this telemetry.
        evaluation: Its score, from the exact same function that scores permanent rules.
        false_positive_examples: Up to a few false-positive findings, rendered so a
            reader can see *why* they were wrong without re-running anything.
    """

    candidate: Candidate
    findings: tuple[Finding, ...]
    evaluation: RuleEvaluation
    false_positive_examples: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate.candidate_id,
            "version": self.candidate.version,
            "title": self.candidate.title,
            "rationale": self.candidate.rationale,
            "finding_count": len(self.findings),
            "evaluation": self.evaluation.to_dict(),
            "false_positive_examples": list(self.false_positive_examples),
        }


@dataclass(frozen=True)
class IterationReport:
    """The full propose -> measure -> iterate story for one coverage gap.

    Attributes:
        target_stage: The ground-truth stage this iteration targets.
        v1: The first, naive candidate's result.
        v2: The tightened candidate's result.
        verdict: A short, deterministic sentence describing what changed and why,
            derived entirely from the two RuleEvaluation objects -- not written by a
            model and not asserted independent of the numbers.
        promoted: Whether v2 was subsequently promoted to a permanent rule. Recorded
            here as a fact about this project's history, not decided by this module.
        promoted_as: The permanent rule id, when promoted.
    """

    target_stage: str
    v1: CandidateResult
    v2: CandidateResult
    verdict: str
    promoted: bool = False
    promoted_as: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_stage": self.target_stage,
            "v1": self.v1.to_dict(),
            "v2": self.v2.to_dict(),
            "verdict": self.verdict,
            "promoted": self.promoted,
            "promoted_as": self.promoted_as,
        }


# Rules a candidate was, in this project's actual history, promoted to. Recorded as
# plain data rather than inferred, because "was this accepted" is a fact about what a
# human (or in this repository's case, the development process) decided to do with the
# result -- the harness measures quality, it does not grant itself write access to the
# registered rule set.
_PROMOTIONS: dict[str, str] = {
    "CAND-INITACCESS-v2": "ATH-009",
    "CAND-DISCOVERY-v2": "ATH-010",
}


def _explain_false_positive(finding: Finding, attack_ids: set[str], benign_ids: set[str]) -> str:
    """One-line explanation of why a specific finding was wrong, for inspection."""
    cited = set(finding.event_ids)
    if cited & benign_ids:
        origin = "matches the labelled benign look-alike scenario"
    else:
        origin = "does not overlap the labelled intrusion at all"
    return f"{finding.rule_id} on {finding.device}/{finding.user} ({origin}): {finding.reason}"


def run_candidate(
    candidate: Candidate,
    telemetry: Telemetry,
    *,
    attack_ids: set[str],
    benign_ids: set[str],
    stages: dict[str, set],
) -> CandidateResult:
    """Run and score a single candidate."""
    findings = candidate.detect(telemetry)
    evaluation = score_rule(
        candidate.candidate_id, findings, frozenset({candidate.target_stage}),
        attack_ids=attack_ids, benign_ids=benign_ids, stages=stages,
    )
    false_positives = [f for f in findings if not (set(f.event_ids) & attack_ids)]
    examples = tuple(
        _explain_false_positive(f, attack_ids, benign_ids) for f in false_positives[:5]
    )
    return CandidateResult(
        candidate=candidate, findings=tuple(findings),
        evaluation=evaluation, false_positive_examples=examples,
    )


def _verdict(target_stage: str, v1: CandidateResult, v2: CandidateResult) -> str:
    """Compose a factual, numbers-derived summary of what changed between versions."""
    fp_delta = v1.evaluation.false_positives - v2.evaluation.false_positives
    stage_v1 = target_stage in v1.evaluation.detected_stages
    stage_v2 = target_stage in v2.evaluation.detected_stages

    parts = [
        f"v1 produced {v1.evaluation.true_positives} true positive(s) and "
        f"{v1.evaluation.false_positives} false positive(s) "
        f"(precision {v1.evaluation.precision:.2f})."
    ]
    if fp_delta > 0:
        parts.append(
            f"v2 removes {fp_delta} of those false positive(s) "
            f"(precision {v1.evaluation.precision:.2f} -> {v2.evaluation.precision:.2f}) "
            f"while {'still' if stage_v2 else 'no longer'} covering {target_stage}."
        )
    elif fp_delta < 0:
        parts.append(
            f"v2 actually introduces {-fp_delta} additional false positive(s) -- the "
            "tightening condition did not help and should not be promoted as written."
        )
    else:
        parts.append(
            "v2 makes no change to the false-positive count on this dataset; the "
            "tightening condition may still be justified on grounds v1 alone does not "
            "capture (see the candidate's own rationale)."
        )
    if stage_v1 and not stage_v2:
        parts.append(
            f"WARNING: v2 lost coverage of {target_stage} that v1 had -- this is a "
            "regression, not an improvement, regardless of precision."
        )
    return " ".join(parts)


def propose_and_iterate(telemetry: Telemetry, data_dir: Path) -> list[IterationReport]:
    """Run every candidate pair through the full propose -> measure -> iterate loop.

    Args:
        telemetry: The telemetry to run candidates against.
        data_dir: Directory containing ``ground_truth.json``, used only for scoring.

    Returns:
        One :class:`IterationReport` per coverage gap, in a stable order.
    """
    attack_ids, benign_ids, stages = load_scoring_context(data_dir)

    by_stage: dict[str, list[type[Candidate]]] = {}
    for cls in ALL_CANDIDATES:
        by_stage.setdefault(cls.target_stage, []).append(cls)

    reports: list[IterationReport] = []
    for target_stage in sorted(by_stage):
        classes = sorted(by_stage[target_stage], key=lambda c: c.version)
        if len(classes) != 2:
            logger.warning(
                "Expected exactly 2 candidate versions for %s, found %d; skipping",
                target_stage, len(classes),
            )
            continue
        v1_cls, v2_cls = classes
        v1_result = run_candidate(
            v1_cls(), telemetry, attack_ids=attack_ids, benign_ids=benign_ids, stages=stages
        )
        v2_result = run_candidate(
            v2_cls(), telemetry, attack_ids=attack_ids, benign_ids=benign_ids, stages=stages
        )
        promoted_as = _PROMOTIONS.get(v2_cls.candidate_id, "")
        reports.append(IterationReport(
            target_stage=target_stage,
            v1=v1_result, v2=v2_result,
            verdict=_verdict(target_stage, v1_result, v2_result),
            promoted=bool(promoted_as), promoted_as=promoted_as,
        ))

    return reports
