"""Tests for the detector evaluation layer."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from ath.evaluation import RULE_COVERAGE, RuleEvaluation, evaluate
from ath.hunting import registered_rule_ids, run_hunt
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import load_ground_truth, load_telemetry

SRC = Path(__file__).resolve().parents[1] / "src" / "ath"


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory) -> Path:
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("eval_data")
    write_telemetry(tables, gt, out)
    return out


@pytest.fixture(scope="module")
def telemetry(data_dir):
    return load_telemetry(data_dir)


@pytest.fixture(scope="module")
def report(telemetry, data_dir):
    return evaluate(run_hunt(telemetry), data_dir, total_events=telemetry.event_count)


# ======================================================================================
# Metric arithmetic
# ======================================================================================


def test_precision_and_recall_arithmetic() -> None:
    ev = RuleEvaluation(
        rule_id="ATH-TEST", true_positives=3, false_positives=1, false_negatives=1,
        detected_stages=("a", "b", "c"), missed_stages=("d",),
    )
    assert ev.precision == pytest.approx(0.75)
    assert ev.recall == pytest.approx(0.75)
    assert ev.f1 == pytest.approx(0.75)
    assert ev.findings_total == 4


def test_no_divide_by_zero_when_rule_is_silent() -> None:
    """A rule producing nothing must not blow up the report."""
    ev = RuleEvaluation(rule_id="ATH-TEST", true_positives=0, false_positives=0,
                        false_negatives=0)
    assert ev.precision == 1.0  # raised no bad alerts
    assert ev.recall == 1.0     # declared no opportunities
    assert ev.f1 == pytest.approx(1.0)


def test_silent_rule_with_declared_stages_scores_zero_recall() -> None:
    """Precision stays vacuously 1.0, but recall correctly exposes the miss."""
    ev = RuleEvaluation(rule_id="ATH-TEST", true_positives=0, false_positives=0,
                        false_negatives=2, missed_stages=("a", "b"))
    assert ev.precision == 1.0
    assert ev.recall == 0.0
    assert ev.f1 == 0.0


def test_all_false_positives_scores_zero_precision() -> None:
    ev = RuleEvaluation(rule_id="ATH-TEST", true_positives=0, false_positives=5,
                        false_negatives=0)
    assert ev.precision == 0.0
    assert ev.f1 == 0.0


# ======================================================================================
# Coverage declarations
# ======================================================================================


def test_every_registered_rule_declares_coverage() -> None:
    assert set(RULE_COVERAGE) == set(registered_rule_ids())


def test_declared_stages_exist_in_ground_truth(data_dir) -> None:
    """A typo in RULE_COVERAGE would silently make recall unmeasurable."""
    gt = load_ground_truth(data_dir)
    real_stages = set(gt["scenarios"]["intrusion"]["stages"])
    for rule_id, stages in RULE_COVERAGE.items():
        assert stages <= real_stages, f"{rule_id} declares unknown stages"


# ======================================================================================
# Measured results on the shipped dataset
# ======================================================================================


def test_report_covers_every_rule(report) -> None:
    assert [r.rule_id for r in report.rules] == sorted(registered_rule_ids())


def test_measured_metrics_match_expectations(report) -> None:
    """Pins the actual numbers so a detector regression is visible immediately."""
    by_rule = {r.rule_id: r for r in report.rules}

    # Perfect rules: one true positive, no noise. Includes ATH-009/010, promoted by the
    # Milestone 6 detection-engineering loop specifically because they achieved this.
    for rule_id in (
        "ATH-001", "ATH-004", "ATH-005", "ATH-006", "ATH-007", "ATH-008",
        "ATH-009", "ATH-010",
    ):
        ev = by_rule[rule_id]
        assert (ev.true_positives, ev.false_positives) == (1, 0), rule_id
        assert ev.precision == 1.0 and ev.recall == 1.0

    # The two rules the benign look-alike trips.
    assert (by_rule["ATH-002"].true_positives, by_rule["ATH-002"].false_positives) == (1, 1)
    assert by_rule["ATH-002"].precision == pytest.approx(0.5)
    assert (by_rule["ATH-003"].true_positives, by_rule["ATH-003"].false_positives) == (2, 1)
    assert by_rule["ATH-003"].precision == pytest.approx(2 / 3)


def test_all_false_positives_are_explained(report) -> None:
    """Every FP should trace to the labelled benign scenario.

    An unexplained false positive means we are flagging something we cannot account
    for, which is the signal to go and look at the data.
    """
    for ev in report.rules:
        assert ev.fp_unexplained == 0, f"{ev.rule_id} has unexplained false positives"
        assert ev.fp_benign_lookalike == ev.false_positives


def test_overall_precision_is_not_perfect(report) -> None:
    """A perfect score on synthetic data would mean the dataset is too easy."""
    assert 0.7 < report.overall_precision < 1.0


def test_stage_coverage_reports_the_real_gaps(report) -> None:
    """As of Milestone 6, ATH-009/ATH-010 closed the two gaps that existed since
    Milestone 3 -- stage coverage is now complete on this dataset."""
    assert report.uncovered_stages == ()
    assert report.stage_coverage == pytest.approx(1.0)
    assert report.untargeted_stages == ()


def test_no_rule_misses_a_stage_it_declared(report) -> None:
    for ev in report.rules:
        assert ev.missed_stages == (), f"{ev.rule_id} missed {ev.missed_stages}"


def test_report_serialises_to_json(report) -> None:
    import json

    payload = json.loads(json.dumps(report.to_dict()))
    assert len(payload["rules"]) == 10
    assert 0 <= payload["overall_precision"] <= 1


# ======================================================================================
# Ground-truth isolation
# ======================================================================================


def _code_references_ground_truth(path: Path) -> bool:
    """True if the module refers to ground truth in code (docstrings excluded)."""
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


@pytest.mark.parametrize("package", ["hunting", "mitre", "correlation", "engineering"])
def test_only_evaluation_reads_ground_truth(package: str) -> None:
    """Detection, interpretation, correlation, and candidate proposal must all be
    label-blind.

    Correlation is included deliberately: a correlator that peeked at labels would
    produce beautiful chains that prove nothing. ``engineering`` is included for the
    same reason candidate rule generation must never see the answer key -- a candidate
    is a *proposal*, and only the harness's scoring step (which legitimately delegates
    to ``ath.evaluation``, see test_engineering.py) may look at ground truth.
    """
    for path in (SRC / package).rglob("*.py"):
        assert not _code_references_ground_truth(path), (
            f"{package}/{path.name} reads ground truth"
        )


def test_evaluation_package_does_read_ground_truth() -> None:
    """The converse: confirm the boundary is where we think it is."""
    assert _code_references_ground_truth(SRC / "evaluation" / "evaluator.py")
