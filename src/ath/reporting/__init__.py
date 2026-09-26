"""Investigation report generation.

Turns a completed (or partially completed) InvestigationState into a self-contained,
evidence-cited document. Nothing here calls a language model -- report assembly is
reorganisation and templated derivation over data the deterministic pipeline and the
agent layer already produced.

Public surface:

    build_report(state, telemetry) -> Report      -- assembly (ath.reporting.builder)
    render_markdown(report) -> str                -- rendering (ath.reporting.markdown)
    render_html(report) -> str                    -- one self-contained page (ath.reporting.html)
    render_index(entries) -> str                  -- a run's index page (ath.reporting.html)
    Report, EvidenceAppendixEntry, RecommendedAction  -- the data model
    Verdict, InvestigationTree, InvestigationStep, ModelExplanation
                                                  -- verdict, tree and model reasoning
    render_claim, audit_calibration                -- calibrated language (language.py)

Two guarantees enforced elsewhere in the codebase and relied on here:

* Every claim in a report was already verified against real telemetry
  (ath.agent.claims.ClaimVerifier) before the investigation state reached this package.
* Every recommended action names the specific claim or coverage gap that produced it
  (RecommendedAction.based_on) -- there is no generic, untraceable advice.
"""

from ath.reporting.builder import build_report
from ath.reporting.html import IndexEntry, render_html, render_index
from ath.reporting.language import (
    CLAIM_PREFIXES,
    OVERCLAIMING_TERMS,
    UNDERCLAIMING_TERMS,
    audit_calibration,
    find_overclaiming,
    find_underclaiming,
    render_claim,
)
from ath.reporting.markdown import render_markdown
from ath.reporting.models import (
    VERDICT_LABELS,
    EvidenceAppendixEntry,
    InvestigationStep,
    InvestigationTree,
    ModelExplanation,
    RecommendedAction,
    Report,
    Verdict,
)

__all__ = [
    "build_report",
    "render_markdown",
    "render_html",
    "render_index",
    "IndexEntry",
    "Report",
    "Verdict",
    "VERDICT_LABELS",
    "InvestigationTree",
    "InvestigationStep",
    "ModelExplanation",
    "EvidenceAppendixEntry",
    "RecommendedAction",
    "render_claim",
    "audit_calibration",
    "find_overclaiming",
    "find_underclaiming",
    "CLAIM_PREFIXES",
    "OVERCLAIMING_TERMS",
    "UNDERCLAIMING_TERMS",
]
