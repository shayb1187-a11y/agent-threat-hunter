"""Detector evaluation against ground truth.

This package -- together with `ath.engineering.harness`, which explicitly reuses
`score_rule` from here -- is the only code permitted to read `ground_truth.json`.
Detection code and candidate-rule *generation* logic that can see labels are not a
detection; only the scoring step that measures them afterwards may look.
"""

from ath.evaluation.evaluator import (
    RULE_COVERAGE,
    UNCOVERED_STAGES,
    EvaluationReport,
    RuleEvaluation,
    evaluate,
    load_scoring_context,
    score_rule,
)

__all__ = [
    "RULE_COVERAGE", "UNCOVERED_STAGES", "EvaluationReport", "RuleEvaluation", "evaluate",
    "load_scoring_context", "score_rule",
]
