"""The offline replay's oracle: it reads the prompt, cites only what was shown, and a row
it produces recovers the LINK-2 shape through the same scorer the runner uses.

Driven over the hand-built corpus of ``tests/test_d1_investigator.py`` (a credential
burst, a service-launched shell, one uncited child). No DEDALE data and no model.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import local_replay  # noqa: E402
from _builders import at, failures, logon, proc, telemetry as build_telemetry  # noqa: E402
from ath.agent.claims import ClaimType, ClaimVerifier  # noqa: E402
from ath.agent.investigator import D1Investigator, InvestigatorConfig, prompt_sha256  # noqa: E402
from ath.agent.tools import ToolBox  # noqa: E402
from ath.correlation import correlate  # noqa: E402
from ath.evaluation.ablation.local import link_recovery  # noqa: E402
from ath.evaluation.ablation.scoring import domain_of_telemetry  # noqa: E402
from ath.hunting import run_hunt  # noqa: E402


@pytest.fixture(scope="module")
def world():
    logons = failures("u1", "HOST-B", "10.0.0.5", 12, start_minute=0, spacing_seconds=20) + [
        logon("u1", "HOST-B", logon_type=3, source_ip="10.0.0.5", source_device="HOST-A",
              action="success", when=at(5)),
    ]
    procs = [
        proc("services.exe", "C:\\Windows\\System32\\services.exe", "wininit.exe",
             device="HOST-B", user="SYSTEM", pid=400, ppid=300, when=at(0)),
        proc("cmd.exe", 'cmd.exe /Q /c net group "domain admins" /domain 1> \\\\127.0.0.1\\ADMIN$\\__1 2>&1',
             "services.exe", device="HOST-B", user="SYSTEM", pid=500, ppid=400, when=at(6)),
        proc("net.exe", 'net group "domain admins" /domain', "cmd.exe",
             device="HOST-B", user="SYSTEM", pid=501, ppid=500, when=at(6, 5)),
    ]
    telemetry = build_telemetry(procs=procs, logons=logons)
    hunt = run_hunt(telemetry)
    cases = correlate(hunt.findings, telemetry)
    case = next(c for c in cases if "ATH-007" in c.rule_ids)
    return {
        "telemetry": telemetry, "findings": list(hunt.findings), "cases": list(cases), "case": case,
        "shell_id": procs[1]["event_id"], "child_id": procs[2]["event_id"], "success_id": logons[-1]["event_id"],
    }


def _run(world, oracle):
    tools = ToolBox(world["telemetry"], world["findings"], world["cases"], tool_call_budget=40)
    investigator = D1Investigator(tools, ClaimVerifier(world["telemetry"]), llm=oracle, config=InvestigatorConfig())
    return investigator.investigate(world["case"])


def _links(world):
    return [{
        "link_id": "T-LINK-2", "identity": {"event_id": world["success_id"]},
        "endpoint": {"event_id": world["child_id"]},
    }]


def test_the_link_path_probes_the_shell_and_recovers_the_link_through_the_runners_scorer(world) -> None:
    oracle = local_replay.OracleLLM("link", identity_id=world["success_id"], endpoint_id=world["child_id"])
    state = _run(world, oracle)
    assert state.investigation["probes_run"] == ["process_tree"]
    assert local_replay.menu_ref(oracle.calls[0][1], "process_tree", "cmd.exe") == "P1"
    assert world["child_id"] in local_replay.new_evidence_section(oracle.calls[1][1])
    assert world["child_id"] not in oracle.calls[0][1], "the child is shown only after the probe"
    claims = [c for c in state.claims if c.source == "llm"]
    assert len(claims) == 1 and claims[0].claim_type is ClaimType.INFERENCE
    assert set(claims[0].evidence_ids) == {world["success_id"], world["child_id"]}
    assert state.rejected_claims == [] and oracle.notes == []
    scored = link_recovery(
        state, _links(world), domain_of_telemetry(world["telemetry"]),
        manifest_digest="m", telemetry_digest="t",
    )
    assert scored["links"] == {"T-LINK-2": True}
    assert state.investigation["rounds"][1]["prompt_sha256"] == prompt_sha256(oracle.calls[1][1])


def test_the_abstain_path_takes_no_probe_and_recovers_nothing(world) -> None:
    oracle = local_replay.OracleLLM("abstain", identity_id=world["success_id"], endpoint_id=world["child_id"])
    state = _run(world, oracle)
    assert state.investigation["probes_run"] == [] and len(oracle.calls) == 1
    scored = link_recovery(state, _links(world), domain_of_telemetry(world["telemetry"]), manifest_digest="m", telemetry_digest="t")
    assert scored["links"] == {"T-LINK-2": False}


def test_the_auth_first_path_still_reaches_the_child_in_the_last_round(world) -> None:
    oracle = local_replay.OracleLLM("auth-first", identity_id=world["success_id"], endpoint_id=world["child_id"])
    state = _run(world, oracle)
    assert state.investigation["probes_run"] == ["user_auth_history", "process_tree"]
    assert world["child_id"] in local_replay.new_evidence_section(oracle.calls[2][1])
    scored = link_recovery(state, _links(world), domain_of_telemetry(world["telemetry"]), manifest_digest="m", telemetry_digest="t")
    assert scored["links"] == {"T-LINK-2": True}


def test_the_oracle_cites_only_what_the_prompt_shows(world) -> None:
    """A logon the prompt never rendered is not cited, and the omission is a note."""
    oracle = local_replay.OracleLLM("link", identity_id="evt-not-shown", endpoint_id=world["child_id"])
    state = _run(world, oracle)
    claims = [c for c in state.claims if c.source == "llm"]
    assert claims[0].evidence_ids == (world["child_id"],)
    assert any("not in the prompt" in note for note in oracle.notes)


def test_the_raw_reply_is_recorded_per_round(world) -> None:
    oracle = local_replay.OracleLLM("link", identity_id=world["success_id"], endpoint_id=world["child_id"])
    state = _run(world, oracle)
    for record in state.investigation["rounds"]:
        assert record["raw"].startswith('{"explanations"')
        assert record["prompt_chars"] > 0
