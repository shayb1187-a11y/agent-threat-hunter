"""The investigation orchestrator.

Shape
-----
An explicit graph of pure nodes over :class:`~ath.agent.state.InvestigationState`::

    plan ──► act ──► verify ──► (loop back to plan, or) ──► conclude

* **plan**    decide which specialist runs next, and record why
* **act**     run it, producing claims and tool calls
* **verify**  check every claim against real telemetry; drop what fails
* **conclude** set a terminal status

Each node is ``(state, ...) -> state`` with no hidden memory, which is what makes the
loop testable: a test constructs a state, runs one node, asserts. This is also why the
nodes are framework-free -- see :mod:`ath.agent.graph` for a LangGraph adapter that
wires these exact functions into a ``StateGraph``. The framework is a runtime choice,
not the design.

Autonomy, constrained
---------------------
"Autonomous" here means the *path* is decided at runtime from evidence, not that the
system is unsupervised. Two hard constraints:

1. **The model chooses from a menu; it never invents an action.** The planner asks for
   one name from a list of specialists whose ``should_run`` gate already passed. A
   response naming anything else is discarded and the deterministic planner takes over.
   The model cannot call a tool the toolbox does not expose, and the toolbox is
   read-only.
2. **Stopping conditions are deterministic.** The loop ends when no specialist is
   eligible, or when the step budget is spent. The model is never asked "are you done?"
   -- a model that wants to keep going will always say no.

Deterministic mode
------------------
With no API key the planner falls back to a priority order and the investigation runs
end to end anyway. The LLM adds planning judgement and synthesis; it is not required for
the system to produce evidence-backed conclusions.
"""

from __future__ import annotations

from dataclasses import dataclass

from ath.agent.claims import Claim, ClaimType, ClaimVerifier
from ath.agent.llm import LLMClient, NullLLM
from ath.agent.specialists import Specialist, default_specialists
from ath.agent.state import AgentResult, InvestigationState, InvestigationStatus
from ath.agent.tools import ToolBox
from ath.correlation.chain import InvestigationCase
from ath.environment.model import EnvironmentModel
from ath.logging_setup import get_logger

logger = get_logger(__name__)

# Fallback priority when no model is available, or when the model's answer is rejected.
# Endpoint first because lineage usually reframes everything else; ATT&CK last because
# interpretation is most useful once the evidence is in.
DEFAULT_PRIORITY: tuple[str, ...] = ("endpoint", "identity", "network", "attack")

PLANNER_SYSTEM = (
    "You are the planning component of a security investigation system. You choose "
    "which specialist investigates next. You do not analyse evidence and you do not "
    "make security claims. Respond with JSON only: "
    '{"next_agent": "<name>", "reason": "<one sentence>"}. '
    "The next_agent value MUST be one of the candidate names provided. If none is "
    'appropriate, respond {"next_agent": "none", "reason": "..."}.'
)

SYNTHESIS_SYSTEM = (
    "You are the synthesis component of a security investigation system. You are given "
    "verified claims that were derived from telemetry. Your job is to identify "
    "relationships BETWEEN them that are not already stated.\n"
    "Rules you must follow:\n"
    "1. Respond with JSON only: {\"claims\": [{\"type\": \"INFERENCE\"|\"HYPOTHESIS\", "
    "\"statement\": \"...\", \"evidence_ids\": [\"evt-000123\"], \"confidence\": 0.0-1.0}]}\n"
    "2. You may ONLY cite event ids that appear in the claims given to you. Any other "
    "id will be rejected and discarded.\n"
    "3. You may NOT produce claims of type FACT. Facts come from telemetry, not from you.\n"
    "4. Use HYPOTHESIS for anything not directly supported by the cited evidence.\n"
    "5. Do not restate claims you were given. Add only new relationships.\n"
    "6. If you have nothing to add, respond {\"claims\": []}."
)


@dataclass
class InvestigationConfig:
    """Orchestrator settings.

    Attributes:
        max_steps: Hard cap on specialist steps. A runaway loop guard that no model
            decision can override.
        use_llm_planner: Let the model choose the next specialist from eligible ones.
        use_llm_synthesis: Let the model propose additional INFERENCE/HYPOTHESIS claims.
        max_synthesis_claims: Cap on accepted model claims, so synthesis cannot drown
            the deterministic evidence.
    """

    max_steps: int = 8
    use_llm_planner: bool = True
    use_llm_synthesis: bool = True
    max_synthesis_claims: int = 6


class InvestigationOrchestrator:
    """Runs an evidence-first investigation over one correlated case."""

    def __init__(
        self,
        tools: ToolBox,
        verifier: ClaimVerifier,
        llm: LLMClient | None = None,
        specialists: list[Specialist] | None = None,
        config: InvestigationConfig | None = None,
        environment: EnvironmentModel | None = None,
    ) -> None:
        self.tools = tools
        self.verifier = verifier
        self.llm = llm or NullLLM()
        self.specialists = specialists or default_specialists(tools)
        self.config = config or InvestigationConfig()
        self.environment = environment
        self._by_name = {s.name: s for s in self.specialists}

    # -- node: plan -----------------------------------------------------------------

    def eligible(self, state: InvestigationState) -> list[tuple[Specialist, str]]:
        """Specialists whose gate currently passes, with each one's reason."""
        eligible: list[tuple[Specialist, str]] = []
        for specialist in self.specialists:
            should, reason = specialist.should_run(state)
            if should:
                eligible.append((specialist, reason))
        return eligible

    def plan(self, state: InvestigationState) -> tuple[Specialist | None, str]:
        """Choose the next specialist.

        Returns:
            ``(specialist, reason)``; ``(None, reason)`` when nothing should run.
        """
        candidates = self.eligible(state)
        if not candidates:
            return None, "no specialist has further useful work on the available evidence"

        if len(candidates) == 1:
            specialist, reason = candidates[0]
            return specialist, f"only eligible specialist; {reason}"

        if self.config.use_llm_planner and self.llm.available:
            chosen = self._llm_plan(state, candidates)
            if chosen is not None:
                return chosen

        # Deterministic fallback: fixed priority order.
        by_name = {s.name: (s, r) for s, r in candidates}
        for name in DEFAULT_PRIORITY:
            if name in by_name:
                specialist, reason = by_name[name]
                return specialist, f"deterministic priority order; {reason}"
        specialist, reason = candidates[0]
        return specialist, reason

    def _llm_plan(
        self, state: InvestigationState, candidates: list[tuple[Specialist, str]]
    ) -> tuple[Specialist, str] | None:
        """Ask the model to choose among eligible specialists.

        The model receives a *summary* -- case shape, what has run, what each candidate
        would do. It never receives telemetry. Its answer is validated against the
        candidate list; anything else is discarded.
        """
        names = [s.name for s, _ in candidates]
        summary = "\n".join([
            f"Case: {state.case.case_id}",
            f"Hosts: {', '.join(state.case.devices)}",
            f"Accounts: {', '.join(state.case.users)}",
            f"Detection rules fired: {', '.join(state.case.rule_ids)}",
            f"ATT&CK tactics observed: {', '.join(state.case.tactics) or 'none'}",
            f"Specialists already run: {', '.join(state.agents_run) or 'none'}",
            f"Verified facts so far: {len(state.facts)}; "
            f"inferences: {len(state.inferences)}; hypotheses: {len(state.hypotheses)}",
            "",
            "Candidates:",
            *[f"  {s.name}: {s.domain} (eligible because {r})" for s, r in candidates],
        ])
        response = self.llm.complete(PLANNER_SYSTEM, summary, max_tokens=256)
        if not response.ok:
            # Recorded on the state, not merely logged at debug: a run that lost its
            # model must say so, or "ran deterministically" reads as a choice.
            state.llm_errors.append(response.error or "unknown error")
            state.plan_log.append(
                f"planner: model call failed ({response.error}); "
                "using deterministic priority order"
            )
            logger.warning("Planner LLM unusable (%s); using deterministic order",
                           response.error)
            return None
        if not response.parsed:
            state.plan_log.append(
                "planner: model response was not parseable JSON; "
                "using deterministic priority order"
            )
            logger.info("Planner response unparseable; using deterministic order")
            return None

        choice = str(response.parsed.get("next_agent", "")).strip().lower()
        if choice not in names:
            # Not an error worth failing on -- just an answer we will not act on.
            logger.info(
                "Planner proposed %r which is not an eligible candidate %s; "
                "falling back to deterministic order", choice, names,
            )
            return None

        specialist = self._by_name[choice]
        reason = str(response.parsed.get("reason", "")).strip() or "selected by planner"
        return specialist, f"planner: {reason}"

    # -- node: act ------------------------------------------------------------------

    def act(self, state: InvestigationState, specialist: Specialist, reason: str) -> AgentResult:
        """Run one specialist. Failures are contained, not propagated."""
        try:
            result = specialist.investigate(state)
        except Exception as exc:  # noqa: BLE001 -- one specialist must not end the run
            logger.exception("Specialist %s failed", specialist.name)
            return AgentResult(
                agent=specialist.name,
                ran_because=reason,
                notes=(f"Specialist failed: {type(exc).__name__}: {exc}",),
            )
        return AgentResult(
            agent=result.agent, ran_because=reason, claims=result.claims,
            tool_calls=result.tool_calls, follow_up=result.follow_up, notes=result.notes,
        )

    # -- node: verify ---------------------------------------------------------------

    def verify(self, state: InvestigationState, result: AgentResult) -> InvestigationState:
        """Verify a step's claims and fold the result into the state."""
        verification = self.verifier.verify(list(result.claims))
        if verification.rejected:
            logger.warning(
                "%s: rejected %d/%d claims", result.agent,
                len(verification.rejected), len(result.claims),
            )
        state.record(result, verification.accepted, verification.rejected)
        return state

    # -- node: synthesise ------------------------------------------------------------

    def synthesise(self, state: InvestigationState) -> InvestigationState:
        """Ask the model for additional relationships between verified claims.

        This is the one place a model contributes content, and it is tightly boxed: it
        sees only already-verified claims, may not author FACTs, may only cite event ids
        that appear in what it was given, and everything is re-verified afterwards.
        """
        if not (self.config.use_llm_synthesis and self.llm.available) or not state.claims:
            return state

        allowed = set(state.evidence_ids)
        rendered = "\n".join(
            f"- [{c.claim_type.value}] {c.statement} (evidence: {', '.join(c.evidence_ids)})"
            for c in state.claims
        )
        response = self.llm.complete(
            SYNTHESIS_SYSTEM,
            f"Case {state.case.case_id}. Verified claims:\n{rendered}",
            max_tokens=1500,
        )
        if not response.ok:
            state.llm_errors.append(response.error or "unknown error")
            state.plan_log.append(f"synthesis skipped: model call failed ({response.error})")
            return state
        if not response.parsed:
            state.plan_log.append("synthesis skipped: unparseable response")
            return state

        proposed: list[Claim] = []
        for raw in response.parsed.get("claims", [])[: self.config.max_synthesis_claims]:
            try:
                claim_type = ClaimType(str(raw.get("type", "HYPOTHESIS")).upper())
            except ValueError:
                continue
            if claim_type is ClaimType.FACT:
                # Structurally impossible anyway; skipping avoids a noisy rejection.
                state.plan_log.append("synthesis: discarded a proposed FACT from the model")
                continue
            try:
                proposed.append(Claim(
                    claim_type=claim_type,
                    statement=str(raw.get("statement", "")).strip(),
                    evidence_ids=tuple(str(e) for e in raw.get("evidence_ids", [])),
                    source="llm", agent="synthesis",
                    confidence=_clamp(raw.get("confidence")),
                ))
            except ValueError as exc:
                state.plan_log.append(f"synthesis: discarded malformed claim ({exc})")

        # Belt and braces: reject citations outside what the model was shown, then run
        # the full verifier over whatever survives.
        scoped = [c for c in proposed if set(c.evidence_ids) <= allowed]
        out_of_scope = len(proposed) - len(scoped)
        if out_of_scope:
            state.plan_log.append(
                f"synthesis: discarded {out_of_scope} claim(s) citing evidence "
                "outside the provided context"
            )

        verification = self.verifier.verify(scoped)
        state.claims.extend(verification.accepted)
        state.rejected_claims.extend(verification.rejected)
        state.plan_log.append(
            f"synthesis: accepted {len(verification.accepted)}, "
            f"rejected {len(verification.rejected)}"
        )
        return state

    # -- the loop --------------------------------------------------------------------

    def investigate(self, case: InvestigationCase) -> InvestigationState:
        """Run a full investigation over ``case``."""
        state = InvestigationState(
            case=case, max_steps=self.config.max_steps, environment=self.environment
        )
        state.llm_requested = self.llm.available and (
            self.config.use_llm_planner or self.config.use_llm_synthesis
        )
        state.status = InvestigationStatus.IN_PROGRESS
        logger.info(
            "Investigating %s (%d findings, %d hosts) with llm=%s",
            case.case_id, len(case.findings), len(case.devices), self.llm.name,
        )

        while state.step < state.max_steps:
            specialist, reason = self.plan(state)
            if specialist is None:
                state.plan_log.append(f"step {state.step + 1}: stop -- {reason}")
                state.status = (
                    InvestigationStatus.COMPLETE if state.agents_run
                    else InvestigationStatus.EXHAUSTED
                )
                break

            state.plan_log.append(f"step {state.step + 1}: {specialist.name} -- {reason}")
            result = self.act(state, specialist, reason)
            self.verify(state, result)
        else:
            # Budget exhausted without a natural stop -- reported honestly, not as success.
            state.plan_log.append(
                f"stopped at the {state.max_steps}-step budget with eligible work remaining"
            )
            state.status = InvestigationStatus.STEP_LIMIT

        self.synthesise(state)
        if state.llm_degraded:
            logger.warning("%s: %s", case.case_id, state.llm_status)
        logger.info(
            "%s finished: %s after %d step(s); %d facts, %d inferences, "
            "%d hypotheses, %d rejected",
            case.case_id, state.status.value, state.step, len(state.facts),
            len(state.inferences), len(state.hypotheses), len(state.rejected_claims),
        )
        return state


def _clamp(value: object) -> float | None:
    """Coerce a model-supplied confidence into [0, 1], or drop it."""
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return max(0.0, min(1.0, number))
