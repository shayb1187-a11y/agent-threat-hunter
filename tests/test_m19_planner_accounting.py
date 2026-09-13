"""A row labelled as a model arm must be able to say what the model actually did.

The failure this file is about
-------------------------------
``plan()`` consults the model, validates the answer against the eligible candidates, and
falls back to a fixed priority order when anything is wrong with it. That fallback is
correct behaviour and it is also, until it is counted, indistinguishable from the
deterministic arm: the run completes, produces claims, and reports "model available and
used for planning/synthesis". Four different events lead there -- the call failed, the
reply was truncated, the reply was prose, the model declined -- and only the first two
are outages. So each is counted separately on the state, the two that mean *the model
was lost* degrade the row, and the two that mean *the model answered unhelpfully* do
not.

How each fails
---------------
*Truncated planner reply.* Must land in ``llm_errors`` and set ``llm_degraded``. Fails
if the client ever returns a truncated reply as a successful one with empty text, which
is what it did before M19 Phase 0.5 -- the row would then be a deterministic run wearing
a model arm's label.

*Unparseable reply.* Must increment ``llm_unparseable_responses`` and must **not**
degrade the run. Fails if prose is promoted to an outage (the degraded signal inflates
until nobody reads it) or if it stays invisible (a model arm whose every answer was
discarded looks exactly like one whose answers were all taken).

*A valid reply.* Must count as ``model-chosen``. Fails if the counter is wired to the
call rather than to the answer being used -- the distinction the whole file exists for.

*The budgets.* The planner and synthesis calls must ask for 8192 output tokens. Fails if
either reverts to the old 256/1500, which is how a reply gets truncated in the first
place.
"""

from __future__ import annotations

import json

import pytest

from ath.agent.claims import ClaimVerifier
from ath.agent.llm import LLMResponse, ScriptedLLM, textless_reply, truncated_reply
from ath.agent.orchestrator import (
    PLANNER_MAX_TOKENS,
    SYNTHESIS_MAX_TOKENS,
    InvestigationConfig,
    InvestigationOrchestrator,
)
from ath.agent.state import InvestigationState
from ath.agent.tools import ToolBox
from ath.correlation import correlate
from ath.hunting import run_hunt
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import load_telemetry


@pytest.fixture(scope="module")
def telemetry(tmp_path_factory):
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("planner_accounting")
    write_telemetry(tables, gt, out)
    return load_telemetry(out)


@pytest.fixture(scope="module")
def hunt_result(telemetry):
    return run_hunt(telemetry)


@pytest.fixture(scope="module")
def case(hunt_result, telemetry):
    return max(correlate(hunt_result.findings, telemetry), key=lambda c: len(c.findings))


@pytest.fixture
def toolbox(telemetry, hunt_result, case):
    return ToolBox(telemetry, hunt_result.findings, [case])


@pytest.fixture
def verifier(telemetry):
    return ClaimVerifier(telemetry)


def _orchestrator(toolbox, verifier, llm, **config):
    return InvestigationOrchestrator(
        toolbox, verifier, llm=llm,
        config=InvestigationConfig(use_llm_synthesis=False, **config),
    )


def _planning_state(case) -> InvestigationState:
    """A fresh state, on which more than one specialist is eligible."""
    return InvestigationState(case=case)


# --------------------------------------------------------------------------------------
# The two failures that must degrade the row
# --------------------------------------------------------------------------------------


def test_a_truncated_planner_reply_degrades_the_run(toolbox, verifier, case) -> None:
    llm = ScriptedLLM(responses=[truncated_reply(PLANNER_MAX_TOKENS)])
    orchestrator = _orchestrator(toolbox, verifier, llm)
    state = _planning_state(case)
    state.llm_requested = True

    specialist, reason = orchestrator.plan(state)

    assert specialist is not None, "the deterministic fallback must still choose"
    assert "deterministic priority order" in reason
    assert state.llm_errors and "max_tokens" in state.llm_errors[0]
    assert state.llm_degraded is True
    assert state.planner_decisions == {"model-error": 1}
    assert state.llm_unparseable_responses == 0
    assert any("model call failed" in line for line in state.plan_log)


def test_a_textless_planner_reply_degrades_the_run(toolbox, verifier, case) -> None:
    llm = ScriptedLLM(responses=[textless_reply()])
    orchestrator = _orchestrator(toolbox, verifier, llm)
    state = _planning_state(case)
    state.llm_requested = True

    orchestrator.plan(state)

    assert state.llm_degraded is True
    assert state.planner_decisions == {"model-error": 1}


# --------------------------------------------------------------------------------------
# The answers that are unhelpful rather than absent
# --------------------------------------------------------------------------------------


def test_an_unparseable_reply_is_counted_and_does_not_degrade(
    toolbox, verifier, case
) -> None:
    llm = ScriptedLLM(responses=["I think we should look at the endpoint first."])
    orchestrator = _orchestrator(toolbox, verifier, llm)
    state = _planning_state(case)
    state.llm_requested = True

    orchestrator.plan(state)

    assert state.llm_unparseable_responses == 1
    assert state.llm_unparseable_by_kind == {"planner": 1}
    assert state.llm_errors == []
    assert state.llm_degraded is False
    assert state.planner_decisions == {"model-unparseable": 1}
    assert state.planner_fallbacks == {"model-unparseable": 1}


def test_a_declined_answer_is_distinguished_from_an_off_menu_one(
    toolbox, verifier, case
) -> None:
    """"none" is the answer the system prompt asks for; a stray name is not."""
    declined = ScriptedLLM(responses=[json.dumps({"next_agent": "none", "reason": "x"})])
    state = _planning_state(case)
    _orchestrator(toolbox, verifier, declined).plan(state)
    assert state.planner_decisions == {"model-declined": 1}

    invented = ScriptedLLM(
        responses=[json.dumps({"next_agent": "exfiltration_agent", "reason": "x"})]
    )
    other = _planning_state(case)
    _orchestrator(toolbox, verifier, invented).plan(other)
    assert other.planner_decisions == {"model-invalid-name": 1}


def test_a_valid_answer_is_counted_as_chosen_by_the_model(
    toolbox, verifier, case
) -> None:
    llm = ScriptedLLM(
        responses=[json.dumps({"next_agent": "identity", "reason": "credentials"})]
    )
    state = _planning_state(case)

    specialist, reason = _orchestrator(toolbox, verifier, llm).plan(state)

    assert specialist.name == "identity"
    assert "planner:" in reason
    assert state.planner_chosen == 1
    assert state.planner_decisions == {"model-chosen": 1}
    assert state.multi_candidate_steps == 1
    assert state.planner_fallbacks == {}


def test_a_single_candidate_step_is_not_a_planning_decision(
    toolbox, verifier, case
) -> None:
    """The denominator must not count steps where there was nothing to decide."""
    llm = ScriptedLLM(responses=[])  # would report "exhausted" if consulted
    state = _planning_state(case)
    state.agents_run = ["endpoint", "identity", "network"]
    state.step = 3

    _orchestrator(toolbox, verifier, llm).plan(state)

    assert state.planner_decisions == {"only-eligible": 1}
    assert state.multi_candidate_steps == 0
    assert llm.calls == []


def test_a_deterministic_arm_records_that_the_planner_was_not_consulted(
    toolbox, verifier, case
) -> None:
    orchestrator = InvestigationOrchestrator(
        toolbox, verifier,
        config=InvestigationConfig(use_llm_planner=False, use_llm_synthesis=False),
    )
    state = orchestrator.investigate(case)

    assert state.planner_decisions.get("planner-not-consulted", 0) >= 1
    assert state.planner_chosen == 0
    # And it is not reported as anything else: no model was requested.
    assert state.llm_degraded is False
    assert state.llm_status == "deterministic mode (no model requested)"


# --------------------------------------------------------------------------------------
# What the row says
# --------------------------------------------------------------------------------------


def test_the_serialised_state_carries_the_planner_breakdown(
    toolbox, verifier, case
) -> None:
    responses = [json.dumps({"next_agent": "identity", "reason": "x"})]
    responses += ["not json"] * 8
    llm = ScriptedLLM(responses=responses)
    state = InvestigationOrchestrator(
        toolbox, verifier, llm=llm,
        config=InvestigationConfig(use_llm_synthesis=False),
    ).investigate(case)

    payload = json.loads(json.dumps(state.to_dict()))["llm"]
    assert payload["planner"]["chosen_by_model"] == 1
    assert payload["planner"]["multi_candidate_steps"] >= 1
    assert payload["planner"]["decisions"]["model-chosen"] == 1
    assert payload["unparseable_responses"] == state.llm_unparseable_responses
    assert payload["degraded"] is False
    assert "the planner chose 1 of" in payload["status"]


def test_llm_status_says_when_the_planner_was_never_asked(
    toolbox, verifier, case
) -> None:
    llm = ScriptedLLM(responses=[json.dumps({"claims": []})] * 4)
    state = InvestigationState(case=case)
    state.llm_requested = True
    state.note_planner_decision("only-eligible")

    assert "never asked" in state.llm_status
    assert llm.calls == []


def test_llm_status_reports_unparseable_replies_without_calling_them_failures(
    toolbox, verifier, case
) -> None:
    state = InvestigationState(case=case)
    state.llm_requested = True
    state.note_planner_decision("model-unparseable")
    state.note_unparseable("planner")

    status = state.llm_status
    assert "DEGRADED" not in status
    assert "1 complete reply(ies) were not parseable" in status


def test_an_unknown_planner_decision_is_refused() -> None:
    """The vocabulary is fixed: a typo must not create a silent new category."""
    state = InvestigationState(case=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="unknown planner decision"):
        state.note_planner_decision("model-probably-fine")


# --------------------------------------------------------------------------------------
# The budgets the truncation failure comes from
# --------------------------------------------------------------------------------------


class _RecordingLLM:
    """A client that answers everything and remembers what budget it was given."""

    name = "recording"
    available = True

    def __init__(self) -> None:
        self.budgets: list[tuple[str, int]] = []

    def complete(self, system: str, prompt: str, max_tokens: int = 1024):
        kind = "synthesis" if system.startswith("You are the synthesis") else "planner"
        self.budgets.append((kind, max_tokens))
        payload = (
            {"claims": []} if kind == "synthesis"
            else {"next_agent": "endpoint", "reason": "x"}
        )
        return LLMResponse(
            text=json.dumps(payload), model=self.name, parsed=payload,
            stop_reason="end_turn",
        )


def test_both_call_kinds_ask_for_the_frozen_output_budget(
    toolbox, verifier, case
) -> None:
    llm = _RecordingLLM()
    InvestigationOrchestrator(
        toolbox, verifier, llm=llm, config=InvestigationConfig(),
    ).investigate(case)

    kinds = {kind for kind, _ in llm.budgets}
    assert kinds == {"planner", "synthesis"}, "test is vacuous unless both ran"
    assert {budget for kind, budget in llm.budgets if kind == "planner"} == {
        PLANNER_MAX_TOKENS
    }
    assert {budget for kind, budget in llm.budgets if kind == "synthesis"} == {
        SYNTHESIS_MAX_TOKENS
    }
    assert PLANNER_MAX_TOKENS == SYNTHESIS_MAX_TOKENS == 8192


class _TruncatingSynthesisLLM(_RecordingLLM):
    """Answers the planner, and is cut off at the cap on synthesis.

    Written as a client rather than a fixed response list because the planner is asked
    a number of times that depends on the case: a list would put the truncated reply
    wherever the walk happened to end, which is how a test of synthesis quietly becomes
    a test of nothing.
    """

    name = "truncating-synthesis"

    def complete(self, system: str, prompt: str, max_tokens: int = 1024):
        if system.startswith("You are the synthesis"):
            self.budgets.append(("synthesis", max_tokens))
            return truncated_reply(max_tokens, model=self.name)
        return super().complete(system, prompt, max_tokens)


def test_a_truncated_synthesis_reply_degrades_the_run(toolbox, verifier, case) -> None:
    """Synthesis is the other call, and it truncates the same way."""
    llm = _TruncatingSynthesisLLM()
    state = InvestigationOrchestrator(
        toolbox, verifier, llm=llm, config=InvestigationConfig(),
    ).investigate(case)

    assert ("synthesis", SYNTHESIS_MAX_TOKENS) in llm.budgets, "synthesis never ran"
    assert state.llm_degraded is True
    assert any("max_tokens" in error for error in state.llm_errors)
