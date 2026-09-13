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


PLANNER_DECISIONS: tuple[str, ...] = (
    "only-eligible",
    "planner-not-consulted",
    "model-chosen",
    "model-unparseable",
    "model-error",
    "model-declined",
    "model-invalid-name",
)
"""Every way the next specialist can come to be chosen, counted per run.

The distinction this exists to keep is between *the model steered this investigation*
and *the deterministic order did, on a run labelled as a model arm*. Both produce a plan
log entry and a specialist; only one of them is what an ablation's model arm claims to
measure. Reading the counts:

``only-eligible``
    One candidate. The planner was not asked, because the decision was not a decision.
``planner-not-consulted``
    More than one candidate, and the planner is off or no model is available. The
    deterministic arm's normal state.
``model-chosen``
    The model named an eligible candidate and the run followed it.
``model-unparseable``
    The model answered, completely, with something that is not JSON. Not an outage --
    see :attr:`InvestigationState.llm_unparseable_responses`.
``model-error``
    The call failed, or its reply was truncated or carried no text. This one degrades
    the run.
``model-declined``
    The model answered ``"none"``: no candidate is appropriate. An answer, not a fault.
``model-invalid-name``
    The model named something that was not on the menu. Discarded.
"""

MODEL_FALLBACK_DECISIONS: frozenset = frozenset({
    "model-unparseable", "model-error", "model-declined", "model-invalid-name",
})
"""The decisions in which the model was asked and the deterministic order answered."""


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
    llm_unparseable_responses: int = 0
    """Complete model replies that were not parseable JSON.

    Deliberately *not* an entry in :attr:`llm_errors`: a model that answers in prose is
    a working model being unhelpful, and counting it as an outage would inflate the
    degraded signal until a reader learns to ignore it. But it is not nothing either --
    a model arm whose every answer was discarded ran deterministically in all but name,
    and before this counter existed the only trace of that was a line in ``plan_log``
    that no aggregate read."""
    llm_unparseable_by_kind: dict[str, int] = field(default_factory=dict)
    """The same count split by call kind (``planner`` / ``synthesis``)."""
    planner_decisions: dict[str, int] = field(default_factory=dict)
    """How each planning step was actually decided. See :data:`PLANNER_DECISIONS`."""
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
        """One line describing what the model actually contributed.

        A run that asked for a model says what the model *did*, not merely that one was
        available: "model available and used for planning/synthesis" was equally true of
        a run in which every planner answer was discarded, and that reading is the one
        this milestone exists to close.
        """
        if not self.llm_requested:
            return "deterministic mode (no model requested)"
        if self.llm_errors:
            head = (
                f"DEGRADED -- model requested but {len(self.llm_errors)} call(s) "
                f"failed ({self.llm_errors[0]}); ran deterministically"
            )
        else:
            head = "model available and used for planning/synthesis"
        return head + self._planner_clause() + self._unparseable_clause()

    def _planner_clause(self) -> str:
        multi = self.multi_candidate_steps
        if not multi:
            return (
                "; no step had more than one eligible candidate, so the planner was "
                "never asked"
            )
        return (
            f"; the planner chose {self.planner_chosen} of {multi} step(s) that had "
            "more than one candidate"
        )

    def _unparseable_clause(self) -> str:
        if not self.llm_unparseable_responses:
            return ""
        return (
            f"; {self.llm_unparseable_responses} complete reply(ies) were not parseable "
            "and were discarded"
        )

    def note_planner_decision(self, decision: str) -> None:
        """Count one planning step by how it was decided."""
        if decision not in PLANNER_DECISIONS:
            raise ValueError(
                f"unknown planner decision {decision!r}; known: {PLANNER_DECISIONS}"
            )
        self.planner_decisions[decision] = self.planner_decisions.get(decision, 0) + 1

    def note_unparseable(self, kind: str) -> None:
        """Count one complete-but-unparseable model reply, by call kind."""
        self.llm_unparseable_responses += 1
        self.llm_unparseable_by_kind[kind] = (
            self.llm_unparseable_by_kind.get(kind, 0) + 1
        )

    @property
    def planner_chosen(self) -> int:
        """Steps whose specialist the model picked."""
        return self.planner_decisions.get("model-chosen", 0)

    @property
    def planner_fallbacks(self) -> dict[str, int]:
        """Steps where the model was asked and the deterministic order answered."""
        return {
            reason: count for reason, count in sorted(self.planner_decisions.items())
            if reason in MODEL_FALLBACK_DECISIONS
        }

    @property
    def multi_candidate_steps(self) -> int:
        """Steps that were a real choice: more than one eligible specialist.

        The denominator of the only question that detects a model arm which quietly
        planned deterministically. A case with none of these says nothing either way,
        which is why it is reported rather than scored.
        """
        return sum(
            count for reason, count in self.planner_decisions.items()
            if reason != "only-eligible"
        )

    @property
    def planner_summary(self) -> dict[str, Any]:
        """The planning breakdown, as it appears in the serialised state."""
        return {
            "multi_candidate_steps": self.multi_candidate_steps,
            "chosen_by_model": self.planner_chosen,
            "fallbacks": self.planner_fallbacks,
            "decisions": dict(sorted(self.planner_decisions.items())),
        }

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
                "unparseable_responses": self.llm_unparseable_responses,
                "unparseable_by_kind": dict(sorted(self.llm_unparseable_by_kind.items())),
                "planner": self.planner_summary,
            },
            "claims": [c.to_dict() for c in self.claims],
            "rejected_claims": [r.to_dict() for r in self.rejected_claims],
            "plan_log": list(self.plan_log),
            "results": [r.to_dict() for r in self.results],
            "evidence_ids": list(self.evidence_ids),
        }
