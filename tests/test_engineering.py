"""Tests for the detection-engineering loop.

Two things matter most here: (1) the v1/v2 comparison must show a *real, measured*
improvement on this project's actual telemetry, not an assumed one -- these tests pin
the exact numbers the harness produces, the same way ``test_evaluation.py`` pins the
permanent rules' numbers; (2) candidate *generation* logic must never read ground
truth, enforced with the same AST-based check used everywhere else in this project.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from ath.engineering import (
    DiscoveryCommandSequenceV1,
    DiscoveryCommandSequenceV2,
    OfficeMacroDocumentOpenedV1,
    OfficeMacroDocumentOpenedV2,
    propose_and_iterate,
)
from ath.engineering.harness import run_candidate
from ath.evaluation import load_scoring_context
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import load_telemetry

SRC = Path(__file__).resolve().parents[1] / "src" / "ath"


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory):
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("engineering_data")
    write_telemetry(tables, gt, out)
    return out


@pytest.fixture(scope="module")
def telemetry(data_dir):
    return load_telemetry(data_dir)


@pytest.fixture(scope="module")
def scoring_context(data_dir):
    return load_scoring_context(data_dir)


@pytest.fixture(scope="module")
def reports(telemetry, data_dir):
    return propose_and_iterate(telemetry, data_dir)


# ======================================================================================
# Ground-truth isolation for candidate *generation*
# ======================================================================================


def _code_references_ground_truth(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = {
        n.body[0].value
        for n in ast.walk(tree)
        if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and n.body and isinstance(n.body[0], ast.Expr)
        and isinstance(n.body[0].value, ast.Constant)
        and isinstance(n.body[0].value.value, str)
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and "ground_truth" in node.id.lower():
            return True
        if isinstance(node, ast.Attribute) and "ground_truth" in node.attr.lower():
            return True
        if isinstance(node, ast.alias) and "ground_truth" in node.name.lower():
            return True
        if (
            isinstance(node, ast.Constant) and isinstance(node.value, str)
            and node not in docstrings and "ground_truth" in node.value.lower()
        ):
            return True
    return False


def test_candidates_module_never_reads_ground_truth() -> None:
    """Proposal logic must be as label-blind as any registered detection rule."""
    assert not _code_references_ground_truth(SRC / "engineering" / "candidates.py")


def test_harness_module_reuses_evaluations_ground_truth_access() -> None:
    """The harness does not read ground truth directly -- it delegates to
    ``ath.evaluation.load_scoring_context``/``score_rule``, the same functions that
    score the permanent rule set. That is the point: a candidate and a registered rule
    are scored through one shared code path, not two independently-written ones."""
    source = (SRC / "engineering" / "harness.py").read_text(encoding="utf-8")
    assert "load_scoring_context" in source
    assert "score_rule" in source


def test_promoted_rules_never_read_ground_truth() -> None:
    """ATH-009/010 must meet the same bar as every other registered detection."""
    assert not _code_references_ground_truth(
        SRC / "hunting" / "rules" / "initial_access_rules.py"
    )
    assert not _code_references_ground_truth(SRC / "hunting" / "rules" / "discovery_rules.py")


# ======================================================================================
# v1 is measurably worse than v2 -- pinned to the real numbers on this dataset
# ======================================================================================


def test_initial_access_v1_has_poor_precision(telemetry, scoring_context) -> None:
    attack_ids, benign_ids, stages = scoring_context
    result = run_candidate(
        OfficeMacroDocumentOpenedV1(), telemetry,
        attack_ids=attack_ids, benign_ids=benign_ids, stages=stages,
    )
    assert result.evaluation.true_positives == 1
    assert result.evaluation.false_positives >= 20, (
        "v1 should be measurably noisy -- if this drops, the benign dataset's "
        "Notes.docx template may have changed"
    )
    assert result.evaluation.precision < 0.1


def test_initial_access_v2_has_perfect_precision(telemetry, scoring_context) -> None:
    attack_ids, benign_ids, stages = scoring_context
    result = run_candidate(
        OfficeMacroDocumentOpenedV2(), telemetry,
        attack_ids=attack_ids, benign_ids=benign_ids, stages=stages,
    )
    assert result.evaluation.true_positives == 1
    assert result.evaluation.false_positives == 0
    assert result.evaluation.precision == 1.0
    assert "1-initial-access" in result.evaluation.detected_stages


def test_discovery_v1_has_poor_precision(telemetry, scoring_context) -> None:
    attack_ids, benign_ids, stages = scoring_context
    result = run_candidate(
        DiscoveryCommandSequenceV1(), telemetry,
        attack_ids=attack_ids, benign_ids=benign_ids, stages=stages,
    )
    assert result.evaluation.false_positives >= 20
    assert result.evaluation.precision < 0.2


def test_discovery_v2_has_perfect_precision(telemetry, scoring_context) -> None:
    attack_ids, benign_ids, stages = scoring_context
    result = run_candidate(
        DiscoveryCommandSequenceV2(), telemetry,
        attack_ids=attack_ids, benign_ids=benign_ids, stages=stages,
    )
    assert result.evaluation.false_positives == 0
    assert result.evaluation.precision == 1.0
    assert "5-discovery" in result.evaluation.detected_stages


def test_v1_false_positives_are_individually_inspectable(telemetry, scoring_context) -> None:
    """The whole point of the harness: a rejected candidate's failures must be
    attributable to specific, nameable telemetry, not just a bare FP count."""
    attack_ids, benign_ids, stages = scoring_context
    result = run_candidate(
        OfficeMacroDocumentOpenedV1(), telemetry,
        attack_ids=attack_ids, benign_ids=benign_ids, stages=stages,
    )
    assert result.false_positive_examples
    assert any("Notes.docx" in ex or "WINWORD" in ex for ex in result.false_positive_examples)


# ======================================================================================
# propose_and_iterate: the full workflow
# ======================================================================================


def test_propose_and_iterate_covers_both_gaps(reports) -> None:
    stages = {r.target_stage for r in reports}
    assert stages == {"1-initial-access", "5-discovery"}


def test_both_iterations_recommend_promotion(reports) -> None:
    for report in reports:
        assert report.promoted, f"{report.target_stage} was not promoted"
        assert report.promoted_as.startswith("ATH-0")


def test_verdict_describes_a_real_precision_improvement(reports) -> None:
    for report in reports:
        assert "false positive" in report.verdict.lower()
        # v2 must not be worse than v1 for either promoted candidate.
        assert report.v2.evaluation.false_positives <= report.v1.evaluation.false_positives
        assert report.v2.evaluation.precision >= report.v1.evaluation.precision


def test_neither_iteration_loses_stage_coverage(reports) -> None:
    """A verdict that trades away recall for precision would be flagged internally --
    confirm neither promoted candidate actually did that."""
    for report in reports:
        assert report.target_stage in report.v1.evaluation.detected_stages
        assert report.target_stage in report.v2.evaluation.detected_stages


def test_verdict_warns_if_a_candidate_regresses_coverage() -> None:
    """Construct a synthetic case where v2 loses the stage v1 had, and confirm the
    verdict text actually says so -- this is the safety rail against a bad promotion."""
    from ath.engineering.harness import CandidateResult, _verdict
    from ath.evaluation.evaluator import RuleEvaluation

    v1 = CandidateResult(
        candidate=OfficeMacroDocumentOpenedV1(), findings=(),
        evaluation=RuleEvaluation(
            rule_id="x", true_positives=1, false_positives=5, false_negatives=0,
            detected_stages=("1-initial-access",),
        ),
        false_positive_examples=(),
    )
    v2 = CandidateResult(
        candidate=OfficeMacroDocumentOpenedV2(), findings=(),
        evaluation=RuleEvaluation(
            rule_id="x", true_positives=0, false_positives=0, false_negatives=1,
            missed_stages=("1-initial-access",),
        ),
        false_positive_examples=(),
    )
    verdict = _verdict("1-initial-access", v1, v2)
    assert "WARNING" in verdict and "regression" in verdict.lower()


def test_candidate_result_and_iteration_report_serialise_to_json(reports) -> None:
    import json

    for report in reports:
        payload = json.loads(json.dumps(report.to_dict()))
        assert payload["target_stage"] == report.target_stage
        assert payload["v1"]["evaluation"]["true_positives"] >= 0
