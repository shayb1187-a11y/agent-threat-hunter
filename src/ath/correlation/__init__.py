"""Deterministic attack-chain correlation.

Groups related findings into investigation cases using evidence relationships --
shared events, process lineage, host-to-host authentication -- rather than time
proximity alone. No language model is involved.
"""

from ath.correlation.chain import FindingLink, InvestigationCase, TimelineEntry
from ath.correlation.correlator import (
    CorrelationConfig,
    CorrelationStats,
    correlate,
    correlate_with_stats,
    score_pair,
)

__all__ = [
    "FindingLink", "InvestigationCase", "TimelineEntry",
    "CorrelationConfig", "CorrelationStats", "correlate", "correlate_with_stats",
    "score_pair",
]
