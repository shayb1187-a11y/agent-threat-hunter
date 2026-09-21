"""Bounded tool output, the shown-id set, the hashed ledger and the run id: each is off
by default and invisible in serialised rows until switched on.

A small built corpus (processes, connections, logons on one host); no model.
"""

from __future__ import annotations

import pytest
from tests._builders import at, logon, net, proc, telemetry

from ath.agent.claims import Claim, ClaimType, ClaimVerifier
from ath.agent.state import AgentResult, InvestigationState, shown_ids
from ath.agent.tools import ToolBox, ToolCall
from ath.correlation.chain import InvestigationCase

HOST = "PC01"
USER = "jdoe"
LONG = "powershell.exe -enc " + "A" * 200


@pytest.fixture(scope="module")
def corpus():
    procs = [proc("powershell.exe", LONG, "explorer.exe", when=at(i), device=HOST) for i in range(5)]
    nets = [net("powershell.exe", f"203.0.113.{i}", when=at(i), device=HOST) for i in range(6)]
    logons = [logon(USER, HOST, when=at(i)) for i in range(5)]
    return telemetry(procs, nets, logons)


def _toolbox(corpus, **kwargs) -> ToolBox:
    return ToolBox(corpus, [], [], **kwargs)


def _state(corpus) -> InvestigationState:
    case = InvestigationCase(case_id="CASE-001", findings=())
    return InvestigationState(case=case)


# -- defaults --------------------------------------------------------------------------------


def test_without_caps_nothing_is_marked_and_the_call_serialises_as_before(corpus) -> None:
    tools = _toolbox(corpus)
    result = tools.host_network_activity(HOST)
    assert "truncated" not in result and len(result["event_ids"]) == result["total"] == 6
    call = tools.calls[-1]
    assert not call.truncated and call.shown_event_ids == () and call.args_sha256 == "" and call.result_sha256 == ""
    assert set(call.to_dict()) == {"tool", "arguments", "agent", "result_summary", "event_ids", "called_at"}
    assert tools.truncations == 0


# -- caps ------------------------------------------------------------------------------------


def test_host_network_activity_under_a_row_cap_returns_the_shown_ids_and_records_the_rest(corpus) -> None:
    full = _toolbox(corpus).host_network_activity(HOST)
    tools = _toolbox(corpus, max_rows=2)
    result = tools.host_network_activity(HOST)
    assert result["truncated"] is True and result["total"] == 6
    assert result["event_ids"] == full["event_ids"][:2] and len(result["destinations"]) == 2
    call = tools.calls[-1]
    assert call.truncated and len(call.event_ids) == 6 and call.shown_event_ids == tuple(result["event_ids"])
    payload = call.to_dict()
    assert payload["truncated"] is True and payload["shown_event_ids"] == result["event_ids"]
    assert "truncated to 2 shown" in payload["result_summary"]
    assert tools.truncations == 1


def test_get_events_and_user_history_are_capped_the_same_way(corpus) -> None:
    ids = list(corpus.processes["event_id"])
    tools = _toolbox(corpus, max_rows=3)
    events = tools.get_events(ids)
    assert len(events["events"]) == 3 and events["truncated"] is True and events["total"] == 5
    assert tools.calls[-1].shown_event_ids == tuple(e["event_id"] for e in events["events"])
    assert len(tools.calls[-1].event_ids) == 5
    history = tools.user_auth_history(USER)
    assert history["summary"]["total"] == 5 and len(history["events"]) == 3
    assert history["truncated"] is True and history["total"] == 5
    assert tools.truncations == 2


def test_a_command_line_is_cut_at_max_chars_with_a_marker(corpus) -> None:
    tools = _toolbox(corpus, max_chars=16)
    result = tools.search_processes(device=HOST, limit=2)
    assert len(result["results"]) == 2 and result["total"] == 5 and "truncated" not in result
    for entry in result["results"]:
        assert entry["command_line"] == LONG[:16] + ToolBox.TRUNCATION_MARKER
    assert tools.calls[-1].truncated and tools.truncations == 1
    untouched = _toolbox(corpus).search_processes(device=HOST, limit=2)
    assert untouched["results"][0]["command_line"] == LONG and "total" in untouched


def test_caps_must_be_positive(corpus) -> None:
    with pytest.raises(ValueError):
        _toolbox(corpus, max_rows=0)
    with pytest.raises(ValueError):
        _toolbox(corpus, max_chars=0)


# -- the shown-id set and the verifier -----------------------------------------------------


def test_the_verifier_tells_never_retrieved_from_nonexistent(corpus) -> None:
    verifier = ClaimVerifier(corpus)
    real, other = (str(e) for e in corpus.processes["event_id"].iloc[:2])
    fabricated = Claim(ClaimType.INFERENCE, "x", ("no-such-event",), source="llm")
    unseen = Claim(ClaimType.INFERENCE, "x", (other,), source="llm")
    seen = Claim(ClaimType.INFERENCE, "x", (real,), source="llm")
    retrieved = frozenset({real})
    assert "do not exist" in verifier.check(fabricated)
    assert "do not exist" in verifier.check(fabricated, retrieved)
    assert verifier.check(unseen) is None, "the one-argument path is the existence oracle and must not move"
    assert "were not retrieved" in verifier.check(unseen, retrieved)
    assert verifier.check(seen, retrieved) is None
    result = verifier.verify([fabricated, unseen, seen], retrieved)
    assert len(result.accepted) == 1 and len(result.rejected) == 2
    reasons = sorted(r.reason for r in result.rejected)
    assert "do not exist" in reasons[0] and "were not retrieved" in reasons[1]


def test_shown_ids_reads_the_shown_set_when_a_call_was_truncated(corpus) -> None:
    capped = _toolbox(corpus, max_rows=2)
    capped.host_network_activity(HOST)
    state = _state(corpus)
    state.results.append(AgentResult(agent="t", ran_because="t", tool_calls=tuple(capped.calls)))
    assert shown_ids(state) == set(capped.calls[-1].shown_event_ids) and len(shown_ids(state)) == 2
    full = _toolbox(corpus)
    full.host_network_activity(HOST)
    state.results.append(AgentResult(agent="t", ran_because="t", tool_calls=tuple(full.calls)))
    assert shown_ids(state) == set(full.calls[-1].event_ids), "an uncapped call contributes everything it found"
    refused = ToolCall(tool="x", arguments={}, agent="t", result_summary="r", event_ids=("zzz",), refused=True)
    state.results.append(AgentResult(agent="t", ran_because="t", tool_calls=(refused,)))
    assert "zzz" not in shown_ids(state)


# -- the ledger and the run id ----------------------------------------------------------------


def test_the_ledger_hashes_the_same_sequence_twice(corpus) -> None:
    sequences = []
    for _ in range(2):
        tools = _toolbox(corpus, ledger=True)
        tools.host_network_activity(HOST)
        tools.search_processes(device=HOST, limit=3)
        tools.get_events(list(corpus.logons["event_id"][:2]))
        sequences.append([(c.args_sha256, c.result_sha256) for c in tools.calls])
    assert sequences[0] == sequences[1]
    assert all(len(a) == 64 and len(r) == 64 for a, r in sequences[0])
    payload = tools.calls[0].to_dict()
    assert payload["args_sha256"] == sequences[0][0][0] and payload["result_sha256"] == sequences[0][0][1]
    assert "args_sha256" not in _toolbox(corpus).host_network_activity(HOST)


def test_the_run_id_is_emitted_only_when_set(corpus) -> None:
    state = _state(corpus)
    assert "run_id" not in state.to_dict()
    state.run_id = "abc"
    assert state.to_dict()["run_id"] == "abc"
