"""The agentic ablation harness.

Three arms over one frozen set of cases: the deterministic baseline, a single generalist
LLM investigator, and the specialist crew with a model planning and synthesising. The
package is split so that the three things that can independently go wrong stay
independently readable:

:mod:`~ath.evaluation.ablation.manifest`
    Pins the inputs. Identical inputs is an invariant, not an intention.
:mod:`~ath.evaluation.ablation.arms`
    Defines the arms and refuses to mislabel one. Carries arm B's design note.
:mod:`~ath.evaluation.ablation.scoring`
    Measures what can be checked without a human, and defines no threshold.
"""

from ath.evaluation.ablation.arms import (
    ARM_A,
    ARM_B,
    ARM_C,
    ARM_BUILDERS,
    ArmConfig,
    ArmUnavailable,
    CaseResult,
    ManifestMismatch,
    arm_a,
    arm_b,
    arm_c,
    identical,
    run_arm,
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
    CaseScores,
    aggregate,
    capture_label_scores,
    label_scores_from_outcome,
    score_case,
    scores_from_dict,
    techniques_in,
)

__all__ = [
    "ARM_A", "ARM_B", "ARM_C", "ARM_BUILDERS", "ArmConfig", "ArmUnavailable",
    "ByConstructionViolation", "CaseManifest", "CaseResult", "CaseScores",
    "ManifestMismatch", "aggregate", "arm_a", "arm_b", "arm_c", "build_manifest",
    "capture_label_scores",
    "identical", "label_scores_from_outcome", "leading_rule_of", "load_manifest",
    "manifest_hash", "run_arm", "score_case", "scores_from_dict", "table_digest",
    "techniques_in",
    "telemetry_hash", "telemetry_rows",
]
