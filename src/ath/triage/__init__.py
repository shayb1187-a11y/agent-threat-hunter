"""Post-detection triage: whether a finding looks like legitimate activity.

Every layer before this one searches for reasons to be suspicious. This one searches
for reasons not to be -- and never suppresses anything, only annotates. See
:mod:`ath.triage.benign` for why the benign case has to be argued explicitly rather
than expressed as a low severity, and why benign evidence can be out-voted by a single
incriminating indicator but can never out-weigh one.
"""

from ath.triage.feedback import (
    FEEDBACK_FILENAME,
    AnalystVerdict,
    FeedbackMetrics,
    FeedbackStore,
    Verdict,
    score_feedback,
    verdict_from_assessment,
)
from ath.triage.benign import (
    BENIGN_SIGNALS,
    BENIGN_THRESHOLD,
    DISQUALIFIERS,
    VETOES,
    Disposition,
    Signal,
    TriageAssessment,
    assess_finding,
    assess_findings,
    set_aside_ids,
    triage_summary,
)

__all__ = [
    "AnalystVerdict",
    "BENIGN_SIGNALS",
    "BENIGN_THRESHOLD",
    "DISQUALIFIERS",
    "VETOES",
    "Disposition",
    "Signal",
    "TriageAssessment",
    "assess_finding",
    "assess_findings",
    "set_aside_ids",
    "triage_summary",
    "FEEDBACK_FILENAME",
    "FeedbackMetrics",
    "FeedbackStore",
    "Verdict",
    "score_feedback",
    "verdict_from_assessment",
]
