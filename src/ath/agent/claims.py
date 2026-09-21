"""Claims: the unit of anything the investigation layer asserts.

Why this module exists
----------------------
The moment a language model enters a security pipeline, the failure mode changes. A
deterministic rule that is wrong is *consistently* wrong and you can measure it. A model
that is wrong is wrong *fluently* -- it produces a confident, well-structured, plausible
sentence citing an event id that does not exist. That is far more dangerous in a SOC
than an obviously broken rule, because it survives review.

So nothing in the agent layer emits prose. It emits :class:`Claim` objects, and every
claim must declare **what kind of statement it is**:

``FACT``
    Directly readable from telemetry or produced by a deterministic detector. Must cite
    evidence, and must come from a deterministic source -- **a model is never permitted
    to author a FACT**. If the LLM believes something is a fact, the pipeline's job is
    to go and check it with a tool, and the *tool* authors the claim.

``INFERENCE``
    A reasonable conclusion drawn from evidence. Must cite the evidence it rests on. A
    model may author these. "The PowerShell process that contacted 185.220.101.47 is the
    same process the macro spawned" is an inference from two facts.

``HYPOTHESIS``
    A possible explanation that has *not* been verified. May cite no evidence at all --
    that is precisely what makes it a hypothesis. It must never be phrased as settled,
    and downstream consumers render it differently. "The archive may have been
    exfiltrated over the observed C2 channel" is a hypothesis; we never saw the bytes
    leave.

The distinction is not cosmetic. An analyst acts differently on each: a FACT goes in the
incident record, an INFERENCE guides the next pivot, a HYPOTHESIS becomes a question to
answer. Collapsing them into undifferentiated prose -- which is what an unconstrained
chatbot does -- destroys exactly the information the analyst needs.

The verifier
------------
:class:`ClaimVerifier` enforces these rules mechanically against real telemetry. It is
the anti-hallucination control, and it is Python, not a prompt instruction. A claim
citing ``evt-999999`` is rejected regardless of how confident or well-written it is.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ath.telemetry.loader import Telemetry


class ClaimType(str, Enum):
    """The epistemic status of a claim -- how much weight it can bear."""

    FACT = "FACT"
    INFERENCE = "INFERENCE"
    HYPOTHESIS = "HYPOTHESIS"

    @property
    def requires_evidence(self) -> bool:
        """Hypotheses are the only claims allowed to stand without evidence."""
        return self is not ClaimType.HYPOTHESIS

    @property
    def rank(self) -> int:
        return {"FACT": 2, "INFERENCE": 1, "HYPOTHESIS": 0}[self.value]


# Sources trusted to author a FACT. Anything else -- notably any model-backed source --
# may only produce INFERENCE or HYPOTHESIS.
DETERMINISTIC_SOURCES: frozenset[str] = frozenset(
    {"tool", "detector", "correlator", "mitre", "telemetry"}
)


@dataclass(frozen=True)
class Claim:
    """A single assertion made during an investigation.

    Attributes:
        claim_type: FACT, INFERENCE or HYPOTHESIS.
        statement: The assertion, in analyst language.
        evidence_ids: Telemetry event ids supporting it.
        source: Who produced it -- a tool name, a detector, or ``"llm"``.
        agent: Which specialist agent surfaced it.
        confidence: Optional 0-1 score. Only meaningful for INFERENCE/HYPOTHESIS;
            a verified FACT does not need a probability attached to it.
    """

    claim_type: ClaimType
    statement: str
    evidence_ids: tuple[str, ...] = ()
    source: str = "tool"
    agent: str = ""
    confidence: float | None = None

    def __post_init__(self) -> None:
        if self.claim_type.requires_evidence and not self.evidence_ids:
            raise ValueError(
                f"A {self.claim_type.value} must cite evidence: {self.statement!r}. "
                "If no evidence exists, it is a HYPOTHESIS."
            )
        if self.claim_type is ClaimType.FACT and self.source not in DETERMINISTIC_SOURCES:
            raise ValueError(
                f"Source {self.source!r} may not author a FACT: {self.statement!r}. "
                "Facts come from telemetry and deterministic logic; a model's belief "
                "about the data is an INFERENCE until a tool confirms it."
            )
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.claim_type.value,
            "statement": self.statement,
            "evidence_ids": list(self.evidence_ids),
            "source": self.source,
            "agent": self.agent,
            "confidence": self.confidence,
        }

    def __str__(self) -> str:
        evidence = f" [{', '.join(self.evidence_ids)}]" if self.evidence_ids else ""
        return f"{self.claim_type.value}: {self.statement}{evidence}"


@dataclass(frozen=True)
class RejectedClaim:
    """A claim the verifier refused, with the reason."""

    claim: Claim
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"claim": self.claim.to_dict(), "reason": self.reason}


@dataclass
class VerificationResult:
    """Outcome of verifying a batch of claims."""

    accepted: list[Claim] = field(default_factory=list)
    rejected: list[RejectedClaim] = field(default_factory=list)

    @property
    def rejection_rate(self) -> float:
        total = len(self.accepted) + len(self.rejected)
        return 0.0 if total == 0 else len(self.rejected) / total

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": [c.to_dict() for c in self.accepted],
            "rejected": [r.to_dict() for r in self.rejected],
            "rejection_rate": round(self.rejection_rate, 4),
        }


class ClaimVerifier:
    """Validates claims against the telemetry that actually exists.

    This is the control that makes a model-assisted pipeline auditable. It does not ask
    the model to be careful; it checks the model's output against the dataset and drops
    whatever fails. Rejections are *kept* rather than silently discarded, so a
    hallucination rate is a measurable property of the system rather than a vibe.
    """

    def __init__(self, telemetry: Telemetry) -> None:
        self._known_ids: set[str] = set(
            telemetry.processes["event_id"].tolist()
            + telemetry.network["event_id"].tolist()
            + telemetry.logons["event_id"].tolist()
            + telemetry.controls["event_id"].tolist()
        )

    @property
    def known_event_count(self) -> int:
        return len(self._known_ids)

    def check(self, claim: Claim, retrieved: frozenset[str] | None = None) -> str | None:
        """Return a rejection reason, or ``None`` if the claim is acceptable.

        With ``retrieved`` -- the ids this investigation actually *showed* the model, see
        :func:`ath.agent.state.shown_ids` -- a claim citing an id that exists in the
        telemetry but was never handed to the model is rejected too, with its own reason,
        so "fabricated" and "real but never retrieved" stay separate numbers. Without it
        the check is the existence oracle it always was: the frozen scoring code and the
        D1 v3 investigator call it that way, and their rows must not move.
        """
        unknown = [e for e in claim.evidence_ids if e not in self._known_ids]
        if unknown:
            return (
                f"cites {len(unknown)} event id(s) that do not exist in telemetry: "
                f"{', '.join(sorted(unknown)[:5])}"
            )
        if retrieved is not None:
            unseen = [e for e in claim.evidence_ids if e not in retrieved]
            if unseen:
                return (
                    f"cites {len(unseen)} event id(s) that exist but were not retrieved in "
                    f"this investigation: {', '.join(sorted(unseen)[:5])}"
                )
        if claim.claim_type.requires_evidence and not claim.evidence_ids:
            return f"a {claim.claim_type.value} must cite evidence"
        if claim.claim_type is ClaimType.FACT and claim.source not in DETERMINISTIC_SOURCES:
            return f"source {claim.source!r} is not permitted to author a FACT"
        return None

    def verify(
        self, claims: list[Claim], retrieved: frozenset[str] | None = None,
    ) -> VerificationResult:
        """Partition ``claims`` into accepted and rejected (see :meth:`check`)."""
        result = VerificationResult()
        for claim in claims:
            reason = self.check(claim, retrieved)
            if reason is None:
                result.accepted.append(claim)
            else:
                result.rejected.append(RejectedClaim(claim=claim, reason=reason))
        return result
