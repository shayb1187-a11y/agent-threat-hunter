"""The detection-engineering loop: propose a rule, evaluate it, iterate, decide.

Two-module split mirrors the boundary the rest of this project enforces everywhere:

    candidates.py  -- proposal logic. NEVER reads ground truth. Same discipline as
                      ath.hunting: a dedicated AST test enforces this.
    harness.py     -- scoring. Explicitly permitted to read ground truth, exactly like
                      ath.evaluation (which it reuses `score_rule` from directly, so a
                      candidate and a registered rule are scored identically).

Nothing in this package can register a candidate into the permanent rule set. Promotion
-- turning a v2 candidate into ATH-009/ATH-010 -- is a manual code change to
`ath.hunting.rules`, the same as any other new rule; `harness.py` only records, as data,
which candidates this project's history did promote.
"""

from ath.engineering.candidates import (
    ALL_CANDIDATES,
    Candidate,
    DiscoveryCommandSequenceV1,
    DiscoveryCommandSequenceV2,
    OfficeMacroDocumentOpenedV1,
    OfficeMacroDocumentOpenedV2,
)
from ath.engineering.harness import CandidateResult, IterationReport, propose_and_iterate

__all__ = [
    "ALL_CANDIDATES", "Candidate",
    "OfficeMacroDocumentOpenedV1", "OfficeMacroDocumentOpenedV2",
    "DiscoveryCommandSequenceV1", "DiscoveryCommandSequenceV2",
    "CandidateResult", "IterationReport", "propose_and_iterate",
]
