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

import time
from dataclasses import dataclass
from typing import Sequence

from ath.agent.claims import Claim, ClaimType, ClaimVerifier
from ath.agent.contract import check_prompt_contract
from ath.agent.llm import LLMClient, LLMResponse, NullLLM
from ath.agent.specialists import Specialist
from ath.agent.state import AgentResult, InvestigationState, InvestigationStatus
from ath.agent.tools import ToolBox
from ath.capabilities.crew import resolve_specialists
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

PLANNER_MAX_TOKENS = 8192
"""Output budget for one planning call.

Thinking tokens count against this cap, and a response that reaches it comes back with
``stop_reason == "max_tokens"`` and possibly no text block at all -- which parses to
``None`` and, before M19 Phase 0.5, fell through to the deterministic order while the
row still described itself as a model arm. The planner's answer is two short JSON
fields, so this is not a target: it is a bound on what one call can cost, set far above
anything the answer needs so that hitting it means something has gone wrong rather than
that the budget was tight.
"""

SYNTHESIS_MAX_TOKENS = 8192
"""Output budget for one synthesis call. Same reasoning, same number."""

PLANNER_USER_TEMPLATE = """Case: {case_id}
Hosts: {hosts}
Accounts: {accounts}
Detection rules fired: {rule_ids}
ATT&CK tactics observed: {tactics}
Specialists already run: {agents_run}
Verified facts so far: {facts}; inferences: {inferences}; hypotheses: {hypotheses}

Candidates:
{candidates}"""
"""The planner's user message, as a template so it can be hashed and frozen.

Extracted for the M19 Phase 1 environment freeze: a prompt that differs between two
arms is a difference between the arms, and the only way to prove it did not is to
record the hash of what was sent before either ran. The rendered text is byte-identical
to what M19-2 and M19-3 sent -- the extraction moved the string, not the prompt.
"""

SYNTHESIS_USER_TEMPLATE = """Case {case_id}. Verified claims:
{claims}"""
"""The synthesis user message, as a template. Hashed and frozen for the same reason."""

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


# -- the synthesis prompt's evidence, and the one bound that can be put on it ----------

ELISION = "+{dropped} more of {total} not shown"
"""How a bounded evidence list says what it left out.

A count, not an ellipsis. The model is being asked to reason about relationships between
claims, and "this host made 589,476 connections, of which here are 66 ids" is a
different premise from "this host made these 66 connections". The second is a lie the
prompt would be telling on the system's behalf.
"""


def render_synthesis_claims(claims: Sequence[Claim], budget: int | None = None) -> str:
    """The claim block of the synthesis user message.

    With ``budget`` unset this is byte-for-byte what the orchestrator has always
    rendered -- the whole point of the flag is that an unset flag changes nothing, and
    ``tests/test_llm_request_size.py`` asserts the two are identical on the
    reconstructed cases.

    With ``budget`` set, each claim contributes at most that many bytes of evidence ids,
    chosen in two passes:

    1. **Ids another claim also cites** come first. Those are the ids that tie two
       facets, or two specialists, to the same event, and they are the only ids in a
       long list whose loss can cost a *relationship* -- which is the only thing
       synthesis is asked to find. An id cited once, in a list of half a million, cannot
       be part of a cross-claim link the model could state.
    2. **Then the rest, in the order the tool returned them**, until the budget is spent.

    Both passes are inside the budget, so a pathological case where two huge claims cite
    the same half-million ids is bounded exactly like one huge claim: the preference is
    a preference, not an exemption. What is never dropped is the *count* -- a truncated
    list ends with :data:`ELISION`, so the model is told how much it is not being shown.

    The bound is per claim rather than per prompt because the claims are what the
    prompt is made of: with ``n`` claims the evidence can contribute at most
    ``n * budget`` bytes, and ``n`` is already bounded by the step budget.
    """
    if budget is not None and budget <= 0:
        raise ValueError(f"tool_output_budget must be positive or None, got {budget}")
    shared = _shared_evidence(claims) if budget is not None else frozenset()
    lines = []
    for claim in claims:
        evidence = (
            ", ".join(claim.evidence_ids) if budget is None
            else _bounded_evidence(claim.evidence_ids, budget, shared)
        )
        lines.append(
            f"- [{claim.claim_type.value}] {claim.statement} (evidence: {evidence})"
        )
    return "\n".join(lines)


def _shared_evidence(claims: Sequence[Claim]) -> frozenset[str]:
    """Ids more than one claim cites -- the cross-claim links worth protecting."""
    seen: set[str] = set()
    shared: set[str] = set()
    for claim in claims:
        for event_id in set(claim.evidence_ids):
            (shared if event_id in seen else seen).add(event_id)
    return frozenset(shared)


def _bounded_evidence(ids: Sequence[str], budget: int, shared: frozenset[str]) -> str:
    """At most ``budget`` bytes of ids, preferring shared ones, then what is left out.

    At least one id is always rendered: a budget too small for a single id is a
    misconfiguration, and answering it with a claim citing nothing would turn a size
    problem into an evidence problem.
    """
    ordered = [e for e in ids if e in shared] + [e for e in ids if e not in shared]
    kept: list[str] = []
    used = 0
    for event_id in ordered:
        cost = len(event_id.encode("utf-8")) + (2 if kept else 0)
        if kept and used + cost > budget:
            break
        kept.append(event_id)
        used += cost
    dropped = len(ids) - len(kept)
    if not dropped:
        return ", ".join(ids)
    # Rendered in the tool's own order, so a reader diffing a bounded prompt against an
    # unbounded one sees a prefix with holes rather than a reshuffle.
    keep = set(kept)
    shown = [e for e in ids if e in keep]
    return ", ".join(shown) + ", " + ELISION.format(dropped=dropped, total=len(ids))


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
        tool_output_budget: Bytes of evidence ids one claim may contribute to the
            synthesis prompt, or ``None`` -- the default -- for no bound at all.

            **Off by default, deliberately.** M19's arm B and arm C ran with no bound
            and their results are frozen; a default that changed the prompt would change
            what a rerun of that experiment means. Setting it is a decision a run has to
            make and record (see ``reports/m19b/http413/``).

            What it bounds is the one thing here that has ever grown without limit: a
            claim's ``evidence_ids``, which are not a summary of a tool result but the
            result itself -- one id per row the tool matched. On the COMISET corpus one
            ``host_network_activity`` call returns 589,476 of them, and the synthesis
            request that carries them reaches 33 MB, which the API rejects with a 413
            (measured; ``reports/m19b/http413/measurements.json``). See
            :func:`render_synthesis_claims` for what a bounded claim looks like: ids
            kept, the count preserved, nothing silently vanished.
    """

    max_steps: int = 8
    use_llm_planner: bool = True
    use_llm_synthesis: bool = True
    max_synthesis_claims: int = 6
    tool_output_budget: int | None = None
    time_budget_seconds: float | None = None
    """Wall-clock budget for one investigation, enforced at every step *and* passed to
    the client as the remaining per-request timeout. ``None`` (the default) is what every
    frozen arm ran under. Not ``max_seconds``: seconds elapse, they are not counted."""
    token_budget: int | None = None
    """Total tokens (as the provider reports them) one investigation may spend. Not
    ``max_tokens``: that name already means the per-response generation cap."""
    reject_unretrieved: bool = False
    """Hand the verifier the ids the model was actually shown, so a synthesis claim
    citing an id that exists but was never retrieved is a *rejection* with its own
    reason rather than a claim silently dropped. Off by default: it changes
    ``rejected_claims`` on new rows and the frozen arms did not run with it."""
    prompt_contract: bool = False
    """Check every rendered prompt with :func:`ath.agent.contract.check_prompt_contract`
    before it is sent; a violation is recorded in ``llm_errors`` and the call is not
    made. Off by default; the frozen prompts pass it (tests/test_prompt_contract.py)."""


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
        self.config = config or InvestigationConfig()
        self.environment = environment
        # Precedence: explicit specialists > environment-assembled crew > fixed
        # default roster. See ath.capabilities.crew.resolve_specialists -- shared
        # with the LangGraph runtime so the two cannot silently plan differently.
        self.specialists = resolve_specialists(specialists, environment, tools)
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
            state.note_planner_decision("only-eligible")
            specialist, reason = candidates[0]
            return specialist, f"only eligible specialist; {reason}"

        # From here the step is a real choice, and the state records who made it. A
        # model arm with no ``model-chosen`` step on a case that offered a menu planned
        # exactly as the deterministic arm did, whatever the row is labelled.
        if self.config.use_llm_planner and self.llm.available:
            chosen, decision = self._llm_plan(state, candidates)
            state.note_planner_decision(decision)
            if chosen is not None:
                return chosen
        else:
            state.note_planner_decision("planner-not-consulted")

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
    ) -> tuple[tuple[Specialist, str] | None, str]:
        """Ask the model to choose among eligible specialists.

        The model receives a *summary* -- case shape, what has run, what each candidate
        would do. It never receives telemetry. Its answer is validated against the
        candidate list; anything else is discarded.

        Returns:
            ``(choice, decision)``. ``choice`` is ``None`` whenever the deterministic
            order must answer instead; ``decision`` is one of the names in
            :data:`ath.agent.state.PLANNER_DECISIONS`, saying *why* -- which is the
            part an aggregate can read. The four ways to end up back on the deterministic path are not the
            same event, and a row that records only "fell back" cannot tell a model
            outage from a model that declined.
        """
        names = [s.name for s, _ in candidates]
        summary = PLANNER_USER_TEMPLATE.format(
            case_id=state.case.case_id,
            hosts=", ".join(state.case.devices),
            accounts=", ".join(state.case.users),
            rule_ids=", ".join(state.case.rule_ids),
            tactics=", ".join(state.case.tactics) or "none",
            agents_run=", ".join(state.agents_run) or "none",
            facts=len(state.facts),
            inferences=len(state.inferences),
            hypotheses=len(state.hypotheses),
            candidates="\n".join(
                f"  {s.name}: {s.domain} (eligible because {r})" for s, r in candidates
            ),
        )
        response = self._complete(
            PLANNER_SYSTEM, summary, max_tokens=PLANNER_MAX_TOKENS
        )
        if not response.ok:
            # Recorded on the state, not merely logged at debug: a run that lost its
            # model must say so, or "ran deterministically" reads as a choice. A reply
            # truncated at the cap, or carrying no text block, arrives here too -- the
            # client turns both into an error precisely so that they degrade the row
            # instead of quietly becoming deterministic planning.
            state.llm_errors.append(response.error or "unknown error")
            state.plan_log.append(
                f"planner: model call failed ({response.error}); "
                "using deterministic priority order"
            )
            logger.warning("Planner LLM unusable (%s); using deterministic order",
                           response.error)
            return None, "model-error"
        if not response.parsed:
            state.note_unparseable("planner")
            state.plan_log.append(
                "planner: model response was not parseable JSON; "
                "using deterministic priority order"
            )
            logger.info("Planner response unparseable; using deterministic order")
            return None, "model-unparseable"

        choice = str(response.parsed.get("next_agent", "")).strip().lower()
        if choice not in names:
            # Not an error worth failing on -- just an answer we will not act on. The
            # two shapes are kept apart: "none" is the answer the system prompt asks
            # for when nothing fits, and any other name is an answer off the menu.
            logger.info(
                "Planner proposed %r which is not an eligible candidate %s; "
                "falling back to deterministic order", choice, names,
            )
            state.plan_log.append(
                f"planner: proposed {choice!r}, which is not one of the eligible "
                f"candidates {names}; using deterministic priority order"
                if choice != "none" else
                "planner: the model judged that no candidate is appropriate; using "
                "deterministic priority order"
            )
            return None, "model-declined" if choice == "none" else "model-invalid-name"

        specialist = self._by_name[choice]
        reason = str(response.parsed.get("reason", "")).strip() or "selected by planner"
        return (specialist, f"planner: {reason}"), "model-chosen"

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
        rendered = render_synthesis_claims(
            state.claims, budget=self.config.tool_output_budget,
        )
        response = self._complete(
            SYNTHESIS_SYSTEM,
            SYNTHESIS_USER_TEMPLATE.format(
                case_id=state.case.case_id, claims=rendered,
            ),
            max_tokens=SYNTHESIS_MAX_TOKENS,
        )
        if not response.ok:
            state.llm_errors.append(response.error or "unknown error")
            state.plan_log.append(f"synthesis skipped: model call failed ({response.error})")
            return state
        if not response.parsed:
            state.note_unparseable("synthesis")
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

        if self.config.reject_unretrieved:
            # The verifier rejects, with its own reason, anything citing an id the model
            # was not shown; nothing is dropped in silence.
            verification = self.verifier.verify(proposed, retrieved=frozenset(allowed))
        else:
            # Belt and braces: reject citations outside what the model was shown, then
            # run the full verifier over whatever survives.
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

    # -- budgets --------------------------------------------------------------------

    _budget_started: float = 0.0
    _budget_tokens_at_start: int = 0

    def _budget_exhausted(self) -> str | None:
        _remaining, reason = _budget_remaining(
            self._budget_started, self._budget_tokens_at_start,
            getattr(self.llm, "tokens_used", None),
            self.config.time_budget_seconds, self.config.token_budget,
        )
        return reason

    def _complete(self, system: str, prompt: str, *, max_tokens: int) -> LLMResponse:
        """One model call, with what is left of the time budget as its timeout, and --
        under ``prompt_contract`` -- refused before it is sent if the prompt carries raw
        schema fields."""
        if self.config.prompt_contract:
            violations = check_prompt_contract(prompt)
            if violations:
                error = f"prompt contract violation: names raw field(s) {', '.join(violations[:6])}"
                logger.error("%s; the call was not sent", error)
                return LLMResponse(error=error, model=self.llm.name)
        if self.config.time_budget_seconds is None:
            return self.llm.complete(system, prompt, max_tokens=max_tokens)
        remaining, _reason = _budget_remaining(
            self._budget_started, self._budget_tokens_at_start, None,
            self.config.time_budget_seconds, None,
        )
        return self.llm.complete(
            system, prompt, max_tokens=max_tokens, timeout_seconds=max(1.0, remaining or 0.0),
        )

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
        self._budget_started = time.perf_counter()
        self._budget_tokens_at_start = getattr(self.llm, "tokens_used", None) or 0
        budget_hit: str | None = None

        while state.step < state.max_steps:
            budget_hit = self._budget_exhausted()
            if budget_hit:
                state.llm_errors.append(budget_hit)
                state.plan_log.append(f"step {state.step + 1}: stop -- {budget_hit}")
                state.status = InvestigationStatus.BUDGET_LIMIT
                break
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

        if budget_hit is None:
            self.synthesise(state)
        else:
            state.plan_log.append("synthesis skipped: budget exhausted")
        if state.llm_degraded:
            logger.warning("%s: %s", case.case_id, state.llm_status)
        logger.info(
            "%s finished: %s after %d step(s); %d facts, %d inferences, "
            "%d hypotheses, %d rejected",
            case.case_id, state.status.value, state.step, len(state.facts),
            len(state.inferences), len(state.hypotheses), len(state.rejected_claims),
        )
        return state


def _budget_remaining(
    started: float, tokens_at_start: int, tokens_now: int | None,
    time_budget_seconds: float | None, token_budget: int | None,
) -> tuple[float | None, str | None]:
    """``(seconds left or None, why the budget is spent or None)``."""
    remaining: float | None = None
    if time_budget_seconds is not None:
        remaining = time_budget_seconds - (time.perf_counter() - started)
        if remaining <= 0:
            return 0.0, f"time budget exhausted ({time_budget_seconds:.0f}s)"
    if token_budget is not None and tokens_now is not None:
        spent = tokens_now - tokens_at_start
        if spent >= token_budget:
            return remaining, f"token budget exhausted ({spent} of {token_budget})"
    return remaining, None


def _clamp(value: object) -> float | None:
    """Coerce a model-supplied confidence into [0, 1], or drop it."""
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return max(0.0, min(1.0, number))
