"""Exercise the operational composition through real tools and scripted models."""

from __future__ import annotations

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from ath import cli
from ath.agent import operational
from ath.agent.llm import LLMResponse, ScriptedLLM, truncated_reply
from ath.agent.operational import OperationalProfile, investigate_operational
from ath.agent.state import InvestigationStatus
from ath.agent.tools import ToolBox
from ath.reporting import build_report
from test_d1_investigator import _answer, world  # noqa: F401


def run(world, responses=None, **limits):
    client = ScriptedLLM(responses=responses) if responses is not None else None
    state = investigate_operational(
        world["case"], world["telemetry"], world["findings"], llm=client,
        profile=OperationalProfile(**limits),
    )
    return state, client


def explanation(world, probe="none"):
    return _answer(
        [{"label": "benign", "statement": "administration is a possible explanation",
          "evidence": [world["shell_id"]]}], probe=probe, disposition="benign",
    )


def test_healthy_d1_uses_existing_tools_and_records_effective_policy(world):
    state, client = run(world, [explanation(world)])
    assert state.status is InvestigationStatus.COMPLETE
    assert state.is_finished
    assert state.investigation["final_disposition"] == "benign"
    assert any(c.source == "llm" for c in state.claims)
    audit = state.to_dict()["investigation"]["operational"]
    assert audit["profile"]["version"] == "operational-v1"
    assert audit["profile_sha256"] == OperationalProfile().sha256()
    assert audit["tokens_used"] == 150
    assert len(client.calls) == 1
    assert all(c.args_sha256 and c.result_sha256 for c in state.tool_calls)


def test_deterministic_runs_have_fresh_budgets_and_ledgers(world):
    states = [run(world)[0] for _ in range(2)]
    assert all(s.status is InvestigationStatus.COMPLETE for s in states)
    assert states[0].run_id != states[1].run_id
    assert states[0].claims == states[1].claims
    assert [c.result_sha256 for c in states[0].tool_calls] == [c.result_sha256 for c in states[1].tool_calls]
    assert all(not s.llm_requested for s in states)


def test_reused_model_client_does_not_share_per_case_token_budget(world):
    client = ScriptedLLM(responses=[explanation(world)] * 2)
    states = [investigate_operational(
        world["case"], world["telemetry"], world["findings"], llm=client,
        profile=OperationalProfile(token_budget=200),
    ) for _ in range(2)]
    assert client.tokens_used == 300
    assert all(s.status is InvestigationStatus.COMPLETE for s in states)
    assert all(s.investigation["operational"]["tokens_used"] == 150 for s in states)


def test_unseen_existing_citation_is_rejected_without_silent_trimming(world):
    reply = _answer([{"label": "malicious", "statement": "a proposed relationship",
                      "evidence": [world["shell_id"], world["child_id"]]}], disposition="malicious")
    state, _ = run(world, [reply])
    assert state.status is InvestigationStatus.INCOMPLETE
    assert any("not retrieved" in r.reason for r in state.rejected_claims)
    assert state.investigation["final_disposition"] == "abstain"
    assert not any(c.source == "llm" for c in state.claims)


def test_tool_results_are_capped_and_truncation_is_auditable(world):
    state, _ = run(world, [_answer([])], tool_max_rows=1, tool_max_chars=20)
    truncated = [c for c in state.tool_calls if c.truncated]
    assert truncated
    assert all(len(c.shown_event_ids) <= 1 for c in truncated)
    assert all(c.result_sha256 for c in truncated)
    assert state.investigation["operational"]["tool_results_truncated"] == len(truncated)


def test_prompt_size_is_checked_before_contacting_the_model(world):
    state, client = run(world, [_answer([])], max_prompt_bytes=1)
    assert client.calls == []
    assert state.status is InvestigationStatus.INCOMPLETE
    assert "prompt byte budget exceeded" in state.llm_errors


def test_prompt_contract_is_enabled_at_the_actual_model_boundary(world):
    case = replace(world["case"], case_id="process_id")
    client = ScriptedLLM(responses=[_answer([])])
    state = investigate_operational(case, world["telemetry"], world["findings"], llm=client)
    assert client.calls == []
    assert state.status is InvestigationStatus.INCOMPLETE
    assert any("prompt contract violation" in error for error in state.llm_errors)


@pytest.mark.parametrize("failure", [
    LLMResponse(error="provider unavailable"),
    truncated_reply(768),
    "not JSON",
    "{}",
    '{"explanations": [42]}',
])
def test_failure_after_a_probe_cannot_publish_the_earlier_benign_verdict(world, failure):
    state, client = run(world, [explanation(world, probe="P1"), failure])
    assert len(client.calls) == 2
    assert state.status is InvestigationStatus.INCOMPLETE and state.is_finished
    assert state.investigation["final_disposition"] == "abstain"
    assert state.investigation["operational"]["model_disposition"] == "benign"
    assert not any(c.source == "llm" for c in state.claims)
    assert state.facts, "keep observed evidence when the model fails"
    report = build_report(state, world["telemetry"])
    assert report.status == "incomplete"
    assert any("Operational investigation incomplete" in note for note in report.limitations)


def test_tool_budget_refusal_is_incomplete_even_in_deterministic_mode(world):
    state, _ = run(world, tool_call_budget=1)
    assert state.status is InvestigationStatus.INCOMPLETE
    audit = state.investigation["operational"]
    assert audit["tool_calls_served"] == 1
    assert audit["tool_calls_refused"] > 0
    assert "tool budget exhausted" in audit["reasons"]


def test_token_budget_is_checked_after_the_last_reply(world):
    state, client = run(world, [explanation(world)], token_budget=100)
    assert len(client.calls) == 1
    assert state.status is InvestigationStatus.INCOMPLETE
    assert "token budget exhausted" in state.investigation["operational"]["reasons"]
    assert state.investigation["final_disposition"] == "abstain"


def test_missing_usage_is_not_treated_as_zero(world):
    reply = LLMResponse(text=explanation(world), input_tokens=100)
    state, client = run(world, [reply, explanation(world)])
    assert len(client.calls) == 1
    assert state.status is InvestigationStatus.INCOMPLETE
    assert state.investigation["operational"]["tokens_used"] is None
    assert "model token usage unavailable" in state.llm_errors


def test_late_final_reply_is_incomplete_and_receives_remaining_timeout(world, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(operational.time, "perf_counter", lambda: now[0])

    class LateClient(ScriptedLLM):
        def complete(self, system, prompt, max_tokens=1024, timeout_seconds=None):
            assert 0 < timeout_seconds <= 120
            now[0] = 121.0
            return super().complete(system, prompt, max_tokens, timeout_seconds)

    state = investigate_operational(
        world["case"], world["telemetry"], world["findings"],
        llm=LateClient(responses=[explanation(world)]),
    )
    assert state.status is InvestigationStatus.INCOMPLETE
    assert "time budget exhausted" in state.investigation["operational"]["reasons"]


def test_model_exceptions_preserve_evidence_without_leaking_exception_text(world):
    class BrokenClient(ScriptedLLM):
        def complete(self, *args, **kwargs):
            raise TimeoutError("sensitive transport details")

    state = investigate_operational(
        world["case"], world["telemetry"], world["findings"], llm=BrokenClient(),
    )
    assert state.status is InvestigationStatus.INCOMPLETE
    assert state.facts
    assert "model client raised TimeoutError" in state.llm_errors
    assert state.investigation["operational"]["tokens_used"] is None
    assert "sensitive transport" not in json.dumps(state.to_dict())


def test_unavailable_configured_model_is_not_an_intentional_deterministic_run(world):
    state = investigate_operational(
        world["case"], world["telemetry"], world["findings"],
        llm=ScriptedLLM(available=False),
    )
    assert state.llm_requested and state.status is InvestigationStatus.INCOMPLETE
    assert "configured model unavailable" in state.investigation["operational"]["reasons"]


@pytest.mark.parametrize("limits", [
    {"tool_call_budget": 0}, {"max_steps": 1}, {"token_budget": None},
    {"time_budget_seconds": float("nan")}, {"time_budget_seconds": float("inf")},
    {"max_probes": -1}, {"tool_max_rows": True},
])
def test_profile_rejects_unbounded_or_inconsistent_limits(limits):
    with pytest.raises(ValueError):
        OperationalProfile(**limits)


@pytest.mark.parametrize("profile", ["legacy", "operational-v1"])
def test_cli_profile_selection_and_json_output(world, monkeypatch, tmp_path, profile):
    monkeypatch.setattr(cli, "load_telemetry", lambda path: world["telemetry"])
    output = tmp_path / "investigations.json"
    args = cli.build_parser().parse_args([
        "investigate", "--profile", profile, "--no-llm", "--json", str(output),
    ])
    assert cli.cmd_investigate(args, SimpleNamespace(raw_data_dir=tmp_path)) == 0
    states = json.loads(output.read_text())
    assert states
    for state in states:
        assert ("operational" in state.get("investigation", {})) == (profile == "operational-v1")


def test_cli_incomplete_run_writes_evidence_and_returns_nonzero(world, monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "load_telemetry", lambda path: world["telemetry"])
    monkeypatch.setattr(cli, "build_llm", lambda: ScriptedLLM(responses=[]))
    output = tmp_path / "incomplete.json"
    args = cli.build_parser().parse_args([
        "investigate", "--profile", "operational-v1", "--json", str(output),
    ])
    assert cli.cmd_investigate(args, SimpleNamespace(raw_data_dir=tmp_path)) == 3
    states = json.loads(output.read_text())
    assert states and all(s["status"] == "incomplete" for s in states)


def test_budget_limit_is_a_terminal_state(world):
    state, _ = run(world)
    state.status = InvestigationStatus.BUDGET_LIMIT
    assert state.is_finished


def test_ledger_includes_empty_error_and_refused_results(world):
    tools = ToolBox(world["telemetry"], world["findings"], [world["case"]], ledger=True)
    tools.get_case("missing")
    tools.get_finding("missing")
    tools.lookup_technique("missing")
    tools.user_auth_history("missing")
    tools.process_tree("missing", pid=999)
    tools.process_tree("HOST-B", process_guid="missing")
    tools.analyse_beacon("missing", "192.0.2.1")
    assert all(c.args_sha256 and c.result_sha256 for c in tools.calls)
    tools.tool_call_budget = tools.calls_served
    tools.get_events([world["shell_id"]])
    assert tools.calls[-1].refused and tools.calls[-1].result_sha256


def test_ledger_distinguishes_arguments_beyond_the_legacy_summary(world):
    tools = ToolBox(world["telemetry"], world["findings"], [world["case"]], ledger=True)
    first_ten = list(world["telemetry"].logons["event_id"][:10])
    tools.get_events(first_ten + [world["shell_id"]])
    tools.get_events(first_ten + [world["child_id"]])
    assert tools.calls[-1].args_sha256 != tools.calls[-2].args_sha256
    tools.search_processes(device="missing", limit=1)
    tools.search_processes(device="missing", limit=2)
    assert tools.calls[-1].args_sha256 != tools.calls[-2].args_sha256
    assert tools.calls[-1].result_sha256 == tools.calls[-2].result_sha256
    tools.process_tree("missing", pid=999, depth=1)
    tools.process_tree("missing", pid=999, depth=2)
    assert tools.calls[-1].args_sha256 != tools.calls[-2].args_sha256


def test_probe_budget_cannot_publish_a_verdict_with_requested_work_remaining(world):
    state, client = run(world, [explanation(world, probe="P1")], max_probes=0)
    assert len(client.calls) == 1
    assert state.status is InvestigationStatus.INCOMPLETE
    assert "probe budget spent" in state.investigation["operational"]["reasons"]
    assert state.investigation["final_disposition"] == "abstain"


def test_invalid_probe_is_not_silently_treated_as_a_decision_to_finish(world):
    state, _ = run(world, [explanation(world, probe="invented-tool")])
    assert state.status is InvestigationStatus.INCOMPLETE
    assert "invalid investigation response shape" in state.llm_errors
