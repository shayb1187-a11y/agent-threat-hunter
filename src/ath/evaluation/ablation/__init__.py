"""The agentic ablation harness.

Three arms over one frozen set of cases: the deterministic baseline, a single generalist
LLM investigator, and the specialist crew with a model planning and synthesising. The
package is split so that the three things that can independently go wrong stay
independently readable:

:mod:`~ath.evaluation.ablation.manifest`
    Pins the inputs. Identical inputs is an invariant, not an intention.
:mod:`~ath.evaluation.ablation.arms`
    Defines the arms, their shared budgets, and refuses to mislabel one.
:mod:`~ath.evaluation.ablation.scoring`
    Measures what can be checked without a human, and defines no threshold.
"""

from ath.evaluation.ablation.arms import (
    ABLATION_MODEL,
    ARM_A,
    ARM_B,
    ARM_C,
    ARM_BUILDERS,
    STEP_BUDGET,
    TOOL_CALL_CAP,
    ArmConfig,
    ArmUnavailable,
    CaseResult,
    ManifestMismatch,
    UnequalFooting,
    arm_a,
    arm_b,
    arm_c,
    attach_request_observer,
    begin_token_accounting,
    budgets_of,
    build_client,
    case_footing,
    detach_request_observer,
    identical,
    request_records,
    run_arm,
    tokens_spent,
)
from ath.evaluation.ablation.manifest import (
    CaseManifest,
    build_manifest,
    leading_rule_of,
    load_manifest,
    manifest_hash,
    table_digest,
    telemetry_hash,
    telemetry_rows,
)
from ath.evaluation.ablation.scoring import (
    ByConstructionViolation,
    CaseRubric,
    CaseScores,
    RubricItem,
    UnknownRubric,
    aggregate,
    capture_label_scores,
    context_size,
    cross_domain_claims,
    cross_domain_evidence_recovery,
    domain_of_telemetry,
    domain_tables,
    duplicate_tool_calls,
    footing_differences,
    planner_activation,
    score_case,
    scores_from_dict,
    state_payload,
    techniques_in,
    techniques_looked_up,
    unique_cross_domain_contribution,
)

__all__ = [
    "ABLATION_MODEL", "ARM_A", "ARM_B", "ARM_C", "ARM_BUILDERS", "STEP_BUDGET", "TOOL_CALL_CAP",
    "ArmConfig", "ArmUnavailable",
    "ByConstructionViolation", "CaseManifest", "CaseResult", "CaseRubric", "CaseScores",
    "ManifestMismatch", "RubricItem", "UnequalFooting", "UnknownRubric",
    "aggregate", "arm_a", "arm_b", "arm_c", "attach_request_observer",
    "begin_token_accounting", "budgets_of", "build_client", "build_manifest",
    "capture_label_scores", "case_footing", "context_size", "cross_domain_claims",
    "cross_domain_evidence_recovery", "detach_request_observer", "domain_of_telemetry",
    "domain_tables", "duplicate_tool_calls", "footing_differences",
    "identical", "leading_rule_of", "load_manifest",
    "manifest_hash", "planner_activation", "request_records", "run_arm", "score_case",
    "scores_from_dict", "state_payload", "table_digest",
    "techniques_in", "techniques_looked_up", "tokens_spent",
    "telemetry_hash", "telemetry_rows", "unique_cross_domain_contribution",
]
