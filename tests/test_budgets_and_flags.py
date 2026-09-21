"""The opt-in agent behaviours: enforced wall-clock and token budgets, the remaining
budget as the per-request timeout, and cited-within-shown verification. Each is off by
default; these tests switch one on and check the row records it.

Scripted clients; the D1 world and the harness fixture corpus.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from _builders import at, failures, logon, proc  # noqa: E402
from _builders import telemetry as build_telemetry  # noqa: E402
from ath.agent.claims import ClaimVerifier  # noqa: E402
from ath.agent.investigator import D1Investigator, InvestigatorConfig  # noqa: E402
from ath.agent.llm import LLMResponse, ScriptedLLM, _attempt_timeout  # noqa: E402
from ath.agent.orchestrator import InvestigationConfig, InvestigationOrchestrator  # noqa: E402
from ath.agent.state import InvestigationStatus  # noqa: E402
from ath.agent.tools import ToolBox  # noqa: E402
from ath.correlation import correlate  # noqa: E402
from ath.evaluation.ablation.local import arm_d1, run_local_arm  # noqa: E402
from ath.hunting import run_hunt  # noqa: E402
from test_ablation_harness import corpus, manifest, pipeline  # noqa: F401,E402


@pytest.fixture(scope="module")
def world():
    logons = failures("u1", "HOST-B", "10.0.0.5", 12, start_minute=0, spacing_seconds=20) + [
        logon("u1", "HOST-B", logon_type=3, source_ip="10.0.0.5", source_device="HOST-A",
              action="success", when=at(5)),
    ]
    procs = [
        proc("services.exe", "C:\\Windows\\System32\\services.exe", "wininit.exe",
             device="HOST-B", user="SYSTEM", pid=400, ppid=300, when=at(0)),
        proc("cmd.exe", 'cmd.exe /Q /c net group "domain admins" /domain', "services.exe",
             device="HOST-B", user="SYSTEM", pid=500, ppid=400, when=at(6)),
        proc("net.exe", 'net group "domain admins" /domain', "cmd.exe",
             device="HOST-B", user="SYSTEM", pid=501, ppid=500, when=at(6, 5)),
    ]
    telemetry = build_telemetry(procs=procs, logons=logons)
    hunt = run_hunt(telemetry)
    cases = correlate(hunt.findings, telemetry)
    case = next(c for c in cases if "ATH-007" in c.rule_ids)
    return {
        "telemetry": telemetry, "findings": list(hunt.findings), "cases": list(cases),
        "case": case, "shell_id": procs[1]["event_id"], "child_id": procs[2]["event_id"],
    }


def _answer(explanations, *, probe="none", disposition="abstain") -> str:
    return json.dumps({
        "explanations": explanations, "evidence_gap": "gap", "next_probe": probe,
        "probe_reason": "because", "disposition": disposition,
    })


def _d1(world, responses, **config):
    tools = ToolBox(world["telemetry"], world["findings"], world["cases"], tool_call_budget=40)
    llm = ScriptedLLM(responses=list(responses), name="scripted")
    investigator = D1Investigator(
        tools, ClaimVerifier(world["telemetry"]), llm=llm, config=InvestigatorConfig(**config),
    )
    return investigator.investigate(world["case"]), llm


class _Recording(ScriptedLLM):
    """A scripted client that remembers the timeout each call was given."""

    def __init__(self, responses):
        super().__init__(responses=responses, name="recording")
        self.timeouts: list[float | None] = []

    def complete(self, system, prompt, max_tokens=1024, timeout_seconds=None) -> LLMResponse:
        self.timeouts.append(timeout_seconds)
        return super().complete(system, prompt, max_tokens=max_tokens)


# -- D1 --------------------------------------------------------------------------------------


def test_d1_rejects_an_unshown_existing_id_when_asked_instead_of_trimming(world) -> None:
    reply = _answer(
        [{"label": "malicious", "statement": "guessing", "evidence": [world["child_id"], world["shell_id"]]}],
        disposition="malicious",
    )
    default, _ = _d1(world, [reply])
    trimmed = [c for c in default.claims if c.source == "llm"]
    assert len(trimmed) == 1 and trimmed[0].evidence_ids == (world["shell_id"],)

    strict, _ = _d1(world, [reply], reject_unretrieved=True)
    assert [c for c in strict.claims if c.source == "llm"] == []
    reasons = [r.reason for r in strict.rejected_claims]
    assert len(reasons) == 1 and "exist but were not retrieved" in reasons[0]
    assert world["child_id"] in reasons[0]


def test_d1_stops_on_a_spent_time_budget_before_asking(world) -> None:
    state, llm = _d1(world, [_answer([])], time_budget_seconds=0)
    assert llm.calls == []
    assert state.investigation["stop_reason"].startswith("time budget exhausted")
    assert state.status is InvestigationStatus.BUDGET_LIMIT
    assert any("time budget exhausted" in e for e in state.llm_errors)
    assert state.llm_degraded


def test_d1_passes_the_remaining_time_budget_as_the_request_timeout(world) -> None:
    tools = ToolBox(world["telemetry"], world["findings"], world["cases"], tool_call_budget=40)
    llm = _Recording([_answer([])])
    investigator = D1Investigator(
        tools, ClaimVerifier(world["telemetry"]), llm=llm,
        config=InvestigatorConfig(time_budget_seconds=600),
    )
    investigator.investigate(world["case"])
    assert len(llm.timeouts) == 1 and 590 < llm.timeouts[0] <= 600
    plain = _Recording([_answer([])])
    D1Investigator(tools, ClaimVerifier(world["telemetry"]), llm=plain).investigate(world["case"])
    assert plain.timeouts == [None]


def test_d1_stops_on_a_spent_token_budget_between_rounds(world) -> None:
    first = _answer([{"label": "insufficient", "statement": "look", "evidence": []}], probe="P1")
    state, llm = _d1(world, [first, _answer([])], token_budget=1)
    assert len(llm.calls) == 1, "one call spends 150 fake tokens; the second round must not start"
    assert state.investigation["stop_reason"].startswith("token budget exhausted (150 of 1)")
    assert state.status is InvestigationStatus.BUDGET_LIMIT


# -- the orchestrator -------------------------------------------------------------------------


def test_the_orchestrator_stops_on_a_spent_time_budget_and_skips_synthesis(corpus, pipeline) -> None:
    findings, cases, environment = pipeline
    tools = ToolBox(corpus, findings, cases)
    llm = _Recording(['{"next_agent": "none"}'] * 8)
    orch = InvestigationOrchestrator(
        tools, ClaimVerifier(corpus), llm=llm, environment=environment,
        config=InvestigationConfig(time_budget_seconds=0),
    )
    state = orch.investigate(cases[0])
    assert state.status is InvestigationStatus.BUDGET_LIMIT and state.agents_run == []
    assert any("time budget exhausted" in e for e in state.llm_errors)
    assert "synthesis skipped: budget exhausted" in state.plan_log
    assert llm.timeouts == []


def test_the_orchestrator_hands_the_remaining_budget_to_every_call(corpus, pipeline) -> None:
    findings, cases, environment = pipeline
    tools = ToolBox(corpus, findings, cases)
    llm = _Recording(['{"next_agent": "none"}', '{"claims": []}'] * 8)
    orch = InvestigationOrchestrator(
        tools, ClaimVerifier(corpus), llm=llm, environment=environment,
        config=InvestigationConfig(time_budget_seconds=900),
    )
    state = orch.investigate(cases[0])
    assert state.status is not InvestigationStatus.BUDGET_LIMIT
    assert llm.timeouts and all(t is not None and 0 < t <= 900 for t in llm.timeouts)


def test_attempt_timeout_never_exceeds_the_client_or_the_remaining_budget() -> None:
    assert _attempt_timeout(60, None) == 60
    assert _attempt_timeout(60, 12.5) == 12.5
    assert _attempt_timeout(60, 900) == 60
    assert _attempt_timeout(60, 0) == 1.0


# -- the runner records what was set --------------------------------------------------------


def test_the_runner_records_opt_in_budgets_and_caps_only_when_set(manifest, corpus, pipeline) -> None:
    findings, cases, environment = pipeline
    abstain = _answer([{"label": "insufficient", "statement": "n", "evidence": []}])
    plain = run_local_arm(
        arm_d1("qwen3.5:4b"), manifest, corpus, cases, findings=findings, environment=environment,
        llm=ScriptedLLM(responses=[abstain] * 64, name="s"), scripted=True,
    )
    for result in plain:
        assert not {"tool_max_rows", "time_budget_seconds", "reject_unretrieved"} & set(result.budgets)
        assert "run_id" not in result.state

    opted = run_local_arm(
        arm_d1("qwen3.5:4b"), manifest, corpus, cases, findings=findings, environment=environment,
        llm=ScriptedLLM(responses=[abstain] * 64, name="s"), scripted=True,
        toolbox_factory=lambda *a, **k: ToolBox(*a, max_rows=5, ledger=True, **k),
        investigator_options={"time_budget_seconds": 0, "reject_unretrieved": True},
        run_id="run-xyz",
    )
    for result in opted:
        assert result.budgets["tool_max_rows"] == 5 and result.budgets["tool_max_chars"] is None
        assert result.budgets["time_budget_seconds"] == 0 and result.budgets["time_budget_hit"] is True
        assert result.budgets["token_budget_hit"] is False and result.budgets["reject_unretrieved"] is True
        assert result.state["run_id"] == "run-xyz" and result.state["status"] == "budget_limit"
