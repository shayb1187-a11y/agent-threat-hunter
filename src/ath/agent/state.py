"""The investigation state -- the single object every node reads and writes.

Making state explicit and typed is what turns "an agent loop" into something you can
test. Each node is a pure-ish function ``(state) -> state`` with no hidden memory, so a
test can construct a state, run one node, and assert on the result. Conversation-history
agents cannot be tested this way, which is why so many agent projects have no meaningful
tests.

The state also *is* the audit trail: which agents ran, why they ran, what tools they
called, what they claimed, and what was rejected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from ath.agent.claims import Claim, ClaimType, RejectedClaim
from ath.agent.tools import ToolCall
from ath.correlation.chain import InvestigationCase
from ath.environment.model import EnvironmentModel


class InvestigationStatus(str, Enum):
    """Where an investigation currently stands."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETE = "complete"
    """Every applicable specialist ran and produced its conclusions."""
    EXHAUSTED = "exhausted"
    """No further useful step exists -- the evidence available has been used up."""
    STEP_LIMIT = "step_limit"
    """The step budget was reached. A guard against runaway loops, not a success."""


@dataclass(frozen=True)
class AgentResult:
    """What one specialist agent produced in one step.

    Attributes:
        agent: Specialist name.
        ran_because: Why the orchestrator selected it -- recorded so the investigation
            path can be explained afterwards rather than reconstructed by guesswork.
        claims: Structured assertions, each carrying its own epistemic status.
        tool_calls: Tools invoked during this step.
        follow_up: Suggested next domains, used as input to the planner.
        notes: Anything the agent could not determine, kept because gaps matter.
    """

    agent: str
    ran_because: str
    claims: tuple[Claim, ...] = ()
    tool_calls: tuple[ToolCall, ...] = ()
    follow_up: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "ran_because": self.ran_because,
            "claims": [c.to_dict() for c in self.claims],
            "tool_calls": [t.to_dict() for t in self.tool_calls],
            "follow_up": list(self.follow_up),
            "notes": list(self.notes),
        }


@dataclass
class InvestigationState:
    """Everything known about one investigation in progress.

    Attributes:
        case: The correlated case under investigation.
        status: Current status.
        step: How many specialist steps have run.
        max_steps: Step budget. A hard stop, independent of any model's judgement.
        agents_run: Specialists already executed, in order.
        results: Their results.
        claims: Verified claims accumulated so far.
        rejected_claims: Claims the verifier refused, retained for auditing.
        plan_log: Each planning decision and its justification.
    """

    case: InvestigationCase
    environment: EnvironmentModel | None = None
    """The environment this case came from, when one has been derived.

    Lets a specialist decline because the telemetry it needs is *absent* rather than
    run and report nothing -- the same distinction the visibility model draws between
    "nothing happened" and "we cannot see". Optional: without it specialists proceed,
    because a missing visibility assessment is not evidence that telemetry is missing.
    """
    status: InvestigationStatus = InvestigationStatus.PENDING
    step: int = 0
    max_steps: int = 8
    agents_run: list[str] = field(default_factory=list)
    results: list[AgentResult] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    rejected_claims: list[RejectedClaim] = field(default_factory=list)
    plan_log: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    llm_requested: bool = False
    """Whether this run was configured to use a model at all."""
    llm_errors: list[str] = field(default_factory=list)
    """Model calls that failed. Populated even though the run still completes.

    A model outage degrades the investigation to deterministic mode by design -- but
    "deterministic because that is what was asked for" and "deterministic because the
    API key is wrong" are different facts about a run, and a system that reports its
    limitations honestly must not collapse them. Left empty, a reader is entitled to
    assume the model contributed whatever it was asked to."""

    # -- queries used by the planner and by the agents' should_run gates -------------

    def has_run(self, agent: str) -> bool:
        return agent in self.agents_run

    def claims_of(self, claim_type: ClaimType) -> list[Claim]:
        return [c for c in self.claims if c.claim_type is claim_type]

    def claims_by(self, agent: str) -> list[Claim]:
        return [c for c in self.claims if c.agent == agent]

    @property
    def facts(self) -> list[Claim]:
        return self.claims_of(ClaimType.FACT)

    @property
    def inferences(self) -> list[Claim]:
        return self.claims_of(ClaimType.INFERENCE)

    @property
    def hypotheses(self) -> list[Claim]:
        return self.claims_of(ClaimType.HYPOTHESIS)

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        """Every event id cited by any verified claim."""
        return tuple(sorted({e for c in self.claims for e in c.evidence_ids}))

    @property
    def tool_calls(self) -> list[ToolCall]:
        return [t for r in self.results for t in r.tool_calls]

    @property
    def follow_ups(self) -> set[str]:
        """Domains suggested by agents that have not yet run."""
        return {f for r in self.results for f in r.follow_up if not self.has_run(f)}

    @property
    def is_finished(self) -> bool:
        return self.status in (
            InvestigationStatus.COMPLETE,
            InvestigationStatus.EXHAUSTED,
            InvestigationStatus.STEP_LIMIT,
        )

    @property
    def llm_degraded(self) -> bool:
        """True when a model was asked for and could not be used.

        Distinguishes an intentionally deterministic run (``--no-llm``, no key) from
        one that silently lost the model it was configured to use.
        """
        return self.llm_requested and bool(self.llm_errors)

    @property
    def llm_status(self) -> str:
        """One line describing what the model actually contributed."""
        if not self.llm_requested:
            return "deterministic mode (no model requested)"
        if self.llm_errors:
            return (
                f"DEGRADED -- model requested but {len(self.llm_errors)} call(s) "
                f"failed ({self.llm_errors[0]}); ran deterministically"
            )
        return "model available and used for planning/synthesis"

    def record(self, result: AgentResult, accepted: list[Claim],
               rejected: list[RejectedClaim]) -> None:
        """Append a completed step to the state."""
        self.agents_run.append(result.agent)
        self.results.append(result)
        self.claims.extend(accepted)
        self.rejected_claims.extend(rejected)
        self.step += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case.case_id,
            "status": self.status.value,
            "steps": self.step,
            "agents_run": list(self.agents_run),
            "started_at": self.started_at.isoformat(),
            "counts": {
                "facts": len(self.facts),
                "inferences": len(self.inferences),
                "hypotheses": len(self.hypotheses),
                "rejected": len(self.rejected_claims),
                "tool_calls": len(self.tool_calls),
            },
            "llm": {
                "requested": self.llm_requested,
                "degraded": self.llm_degraded,
                "status": self.llm_status,
                "errors": list(self.llm_errors),
            },
            "claims": [c.to_dict() for c in self.claims],
            "rejected_claims": [r.to_dict() for r in self.rejected_claims],
            "plan_log": list(self.plan_log),
            "results": [r.to_dict() for r in self.results],
            "evidence_ids": list(self.evidence_ids),
        }
