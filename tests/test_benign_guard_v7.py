"""Operational-v7: the structural benign guard, the v7 prompt, and the offline replay.

Why these tests matter
----------------------
On the pre-registered holdout (docs/holdout-v1-windows-results.md), qwen3.5:9b on
operational-v6 cleared three of six malicious Windows cases as benign; two of them on the
seed command alone, never asking what launched it. v7 makes "no benign on a process
without its ancestry" a rule the application enforces. These tests pin:

* **The refusal is real and visible.** A benign without the seed's parent retrieved is
  scored as abstain, the run stays complete (the model did answer), and the reason is in
  the operational audit and in the report's verdict -- never a silent downgrade.
* **The guard is narrow.** A benign whose ancestry was retrieved stands; malicious and
  abstain are untouched; seeds with no process record are not guarded, and say so.
* **v2-v6 do not move.** The same scripted run under v6 still returns benign, and every
  frozen profile's ``to_dict``/``sha256`` and the v5/v6 system prompt keep the digests
  sealed in earlier runs (v6's and the prompt's are the ones in the holdout rows).
* **The replay cannot diverge from the live path.** It calls the same pure function on
  the recorded row, and the test proves the two agree on scripted runs.

Every run here uses a ScriptedLLM labelled as scripted: plumbing, not evidence about any
model.
"""

from __future__ import annotations

import hashlib
import json
import re

import pytest

from _builders import at, ctrl, logon, proc, telemetry
from ath.agent.benign_guard import (
    GUARD_VERSION,
    NOT_PROCESS_SEED,
    benign_guard_decision,
    guard_from_row,
    retrieved_event_ids,
    seed_ancestry,
)
from ath.agent.llm import ScriptedLLM
from ath.agent.operational import (
    AncestryGuardProfile,
    ContextProfile,
    ControlPlaneProfile,
    EvidenceProfile,
    OperationalProfile,
    ReferenceProfile,
    StableContextProfile,
    investigate_operational,
)
from ath.agent.references import ANCESTRY_SYSTEM, STABLE_SYSTEM
from ath.agent.state import shown_ids
from ath.evaluation import auth_execution as pilot
from ath.evaluation import real_cases as real
from ath.reporting import render_html, render_markdown
from ath.reporting.verdict import GUARD_SOURCE, MODEL_SOURCE

# Development sample-02 (benign): a logon burst and one service-launched cmd.exe, whose
# parent services.exe is recorded in the scenario's telemetry.
SEED_CMD, SERVICES = "c1aa4d45ddf2102946f7", "98c80712635dec2f3738"


def _answer(disposition, probe="none", refs=("R1",)):
    label = {"abstain": "insufficient"}.get(disposition, disposition)
    return json.dumps({
        "explanations": [{"label": label, "statement": "Scripted.", "evidence": list(refs)}],
        "evidence_gap": "none", "next_probe": probe, "probe_reason": "Scripted.",
        "disposition": disposition})


@pytest.fixture(scope="module")
def scenario():
    return pilot.scenarios("dev")[1]


def _run(scenario, responses, profile=None):
    client = ScriptedLLM(list(responses))
    row, report = pilot.evaluate_case(scenario, "d1", client, scripted=True,
                                      profile=profile or AncestryGuardProfile())
    return row, report, client


def _audit(row):
    return row["state"]["investigation"]["operational"]


# -- the guard on live runs ---------------------------------------------------------------


def test_benign_without_the_parent_retrieved_becomes_a_recorded_abstain(scenario):
    """The h01/h03 shape: benign on the seed alone, no probe."""
    row, report, _ = _run(scenario, [_answer("benign")])
    audit = _audit(row)
    guard = audit["benign_guard"]
    assert guard["applied"] is True and guard["model_disposition"] == "benign"
    assert "no tool showed its parent services.exe" in guard["reason"] and SEED_CMD in guard["reason"]
    # Complete, not incomplete: the model answered; the system refused the clearance.
    assert audit["outcome"] == "complete" and audit["reasons"] == []
    assert audit["model_disposition"] == "benign"
    assert row["scores"]["complete"] and row["scores"]["decision"] == "abstain"
    assert row["state"]["investigation"]["final_disposition"] == "abstain"
    assert any(e.startswith("benign guard: ") for e in row["state"]["plan_log"])
    verdict = report.verdict
    assert verdict.disposition == "Abstain"
    assert verdict.disposition_source == GUARD_SOURCE.format(reason=guard["reason"])
    assert verdict.supporting_event_ids == ()  # the citations supported the withheld benign
    markdown = render_markdown(report)
    assert f"**Decided by:** {verdict.disposition_source}" in markdown
    assert "no tool showed its parent services.exe" in render_html(report)


def test_benign_with_the_parent_retrieved_stands(scenario):
    """A process_tree probe on the seed returns its ancestry, including services.exe."""
    row, report, _ = _run(scenario, [_answer("abstain", probe="P1"), _answer("benign")])
    guard = _audit(row)["benign_guard"]
    assert guard["applied"] is False and guard["seeds"][0]["parent_retrieved"] is True
    assert SERVICES in guard["seeds"][0]["parent_event_ids"]
    assert row["scores"]["decision"] == "benign"
    assert report.verdict.disposition == "Benign" and report.verdict.disposition_source == MODEL_SOURCE


@pytest.mark.parametrize("disposition", ["malicious", "abstain"])
def test_malicious_and_abstain_are_untouched(scenario, disposition):
    row, report, _ = _run(scenario, [_answer(disposition)])
    guard = _audit(row)["benign_guard"]
    assert guard["applied"] is False and guard["reason"].startswith(f"model disposition is {disposition}")
    assert row["scores"]["decision"] == disposition
    assert report.verdict.disposition == disposition.capitalize()
    assert report.verdict.disposition_source == MODEL_SOURCE


def test_an_incomplete_run_is_not_double_counted(scenario):
    # A benign naming a probe not on the menu: the run is incomplete for that reason alone.
    row, report, _ = _run(scenario, [_answer("benign", probe="P9")])
    audit = _audit(row)
    assert audit["outcome"] == "incomplete" and audit["model_disposition"] == "benign"
    assert audit["benign_guard"]["applied"] is False
    assert "already withheld" in audit["benign_guard"]["reason"]
    assert report.verdict.disposition == "Incomplete"


def test_deterministic_engine_records_the_guard_without_applying_it(scenario):
    row, _ = pilot.evaluate_case(scenario, "deterministic", profile=AncestryGuardProfile())
    guard = _audit(row)["benign_guard"]
    assert guard["applied"] is False and guard["model_disposition"] is None


def test_a_control_plane_seed_is_not_guarded():
    grant = ctrl("ops-admin", "create", "clusterrolebindings", "viewer-binding", target_actor="svc-reader",
                 role_ref="view", when=at(1))
    corpus = telemetry(ctrls=[grant, ctrl("ops-admin", "get", "pods", "app-0", when=at(2))])
    incident = real.analyst_incident(corpus, [grant["event_id"]])
    case = real.RealCase("k8s-grant", corpus, "benign", (), None, tuple(incident.event_ids),
                         real.ANALYST, (grant["event_id"],))

    class CitesFirstReference(ScriptedLLM):
        def complete(self, system, prompt, max_tokens=1024, timeout_seconds=None):
            refs = re.findall(r"^(R\d+):", prompt.split("CHECKED OBSERVATIONS", 1)[1], re.M)
            self.responses.append(_answer("benign", refs=refs[:1]))
            return super().complete(system, prompt, max_tokens, timeout_seconds)

    row, _ = real.evaluate_case(case, "d1", CitesFirstReference([]), scripted=True,
                                profile=AncestryGuardProfile())
    guard = _audit(row)["benign_guard"]
    assert guard == {"version": GUARD_VERSION, "applied": False, "reason": NOT_PROCESS_SEED}
    assert row["scores"]["complete"] and row["scores"]["decision"] == "benign"


# -- the pure decision --------------------------------------------------------------------


def _family():
    """explorer -> cmd (seed) -> whoami, each naming its creator's identity."""
    parent = proc("explorer.exe", "explorer.exe", "userinit.exe", guid="g:p", when=at(0))
    seed = proc("cmd.exe", "cmd /c whoami", "explorer.exe", guid="g:s", parent_guid="g:p", when=at(1))
    child = proc("whoami.exe", "whoami", "cmd.exe", guid="g:c", parent_guid="g:s", when=at(2))
    return parent, seed, child


def test_the_seed_row_itself_never_counts_as_the_parent():
    """The seed row records its parent's name; that is what h01/h03 were cleared on."""
    parent, seed, child = _family()
    ancestry = seed_ancestry(telemetry([parent, seed, child]), [seed["event_id"]])
    assert ancestry[0]["parent_event_ids"] == [parent["event_id"]]
    assert benign_guard_decision("benign", ancestry, {seed["event_id"], child["event_id"]})["applied"]
    assert not benign_guard_decision("benign", ancestry, {seed["event_id"], parent["event_id"]})["applied"]


def test_a_logon_seed_is_not_guarded():
    parent, seed, _ = _family()
    login = logon("jdoe", "PC01", when=at(0))
    ancestry = seed_ancestry(telemetry([parent, seed], logons=[login]), [login["event_id"]])
    assert benign_guard_decision("benign", ancestry, set()) == {
        "version": GUARD_VERSION, "applied": False, "reason": NOT_PROCESS_SEED}


def test_a_parent_missing_from_the_telemetry_is_named_as_a_data_gap():
    _, seed, child = _family()
    ancestry = seed_ancestry(telemetry([seed, child]), [seed["event_id"]])
    decision = benign_guard_decision("benign", ancestry, {seed["event_id"], child["event_id"]})
    assert decision["applied"] and "has no record in this telemetry" in decision["reason"]


def test_without_identities_the_parent_is_the_unique_pid_instance():
    parent = proc("explorer.exe", "explorer.exe", "userinit.exe", pid=700, when=at(0))
    seed = proc("cmd.exe", "cmd /c del x", "explorer.exe", pid=800, ppid=700, when=at(1))
    ancestry = seed_ancestry(telemetry([parent, seed]), [seed["event_id"]])
    assert ancestry[0]["parent_identified_by"] == "pid"
    assert ancestry[0]["parent_event_ids"] == [parent["event_id"]]


def test_retrieved_ids_follow_the_shown_ids_rule_on_objects_and_sealed_dicts(scenario):
    row, _, _ = _run(scenario, [_answer("abstain", probe="P1"), _answer("benign")])
    findings, case, environment = pilot.prepare(scenario)
    state = investigate_operational(case, scenario.telemetry, findings,
                                    llm=ScriptedLLM([_answer("abstain", probe="P1"), _answer("benign")]),
                                    profile=AncestryGuardProfile(), environment=environment)
    assert retrieved_event_ids(state.tool_calls) == shown_ids(state)
    sealed = [c for r in row["state"]["results"] for c in r["tool_calls"]]
    assert retrieved_event_ids(sealed) == shown_ids(state)


# -- the replay ---------------------------------------------------------------------------


@pytest.mark.parametrize("responses", [
    [_answer("benign")],
    [_answer("abstain", probe="P1"), _answer("benign")],
    [_answer("malicious")],
])
def test_the_replay_reaches_the_live_decision_from_the_sealed_row(scenario, responses):
    row, _, _ = _run(scenario, responses)
    _, case, _ = pilot.prepare(scenario)
    replayed = guard_from_row(json.loads(json.dumps(row["state"])), scenario.telemetry, case.event_ids)
    assert replayed == _audit(row)["benign_guard"]


# -- v6 and the other frozen profiles do not move ------------------------------------------


# Digests recorded before v7 existed; v6's is the one sealed in the holdout-v1 rows.
FROZEN_PROFILE_SHA256 = {
    OperationalProfile: "a95cad66f90a43582decac7ba5294bd474d5f3cc82f8a54e6904ca06c67b5c68",
    EvidenceProfile: "00a9d34a2a16870877a725e2f1e8d91d62c6fa983442b035856266fef8b53b7c",
    ReferenceProfile: "e51c123e3abbcbdb14b4bdd7b39523f26a1c48995cf355f8dd9da47a01f9da84",
    ContextProfile: "0fefffddedbfebd293b75d4a422cef8194522f4875df7fe70f41d8bfab32f204",
    StableContextProfile: "f0aff68a2136e5d181d43ab740787060b08f3399ed1ec2f2c86357267487eca1",
    ControlPlaneProfile: "2710d9dfa320856d24acd88a065ee9a7669b034c142a710baded25471f3f31ad",
}
# The v5/v6 system prompt, as recorded in the holdout rows' system_sha256.
STABLE_SYSTEM_SHA256 = "aadd0c29718e644e99b66b0a8782b33af4736a8388bd0d632b46a9b61f112c54"


@pytest.mark.parametrize("profile_class", list(FROZEN_PROFILE_SHA256))
def test_frozen_profiles_keep_their_digests(profile_class):
    profile = profile_class()
    assert profile.sha256() == FROZEN_PROFILE_SHA256[profile_class]
    assert "benign_guard" not in profile.to_dict()


def test_v7_names_its_guard_and_differs_from_v6():
    v7 = AncestryGuardProfile()
    assert v7.to_dict()["version"] == "operational-v7" and v7.to_dict()["benign_guard"] == GUARD_VERSION
    assert v7.sha256() not in FROZEN_PROFILE_SHA256.values()
    assert isinstance(pilot.profile_for("operational-v7"), AncestryGuardProfile)


def test_the_same_scripted_run_under_v6_is_not_downgraded(scenario):
    row, report, client = _run(scenario, [_answer("benign")], profile=ControlPlaneProfile())
    assert "benign_guard" not in _audit(row)
    assert row["scores"]["decision"] == "benign" and report.verdict.disposition == "Benign"
    assert client.calls[0][0] == STABLE_SYSTEM
    assert hashlib.sha256(STABLE_SYSTEM.encode()).hexdigest() == STABLE_SYSTEM_SHA256
    assert "the parent shown in the cited row is already known" in client.calls[0][1]


# -- the v7 prompt ------------------------------------------------------------------------


def test_v7_prompt_drops_the_signer_cue_and_absence_reasoning(scenario):
    assert "signed, standard operating-system" in STABLE_SYSTEM  # the v6 cue, still frozen there
    assert "signed, standard operating-system" not in ANCESTRY_SYSTEM
    sentences = re.split(r"(?<=[.;:])\s+", " ".join(ANCESTRY_SYSTEM.split()))
    for sentence in (s for s in sentences if re.search(r"\bsign(ed|ature)\b", s, re.I)):
        assert re.search(r"\b(not|never)\b", sentence), sentence
    assert "A valid code signature is not evidence of" in ANCESTRY_SYSTEM
    assert "is not evidence of benign intent; it never supports" in ANCESTRY_SYSTEM
    assert "inspect its ancestry" in ANCESTRY_SYSTEM
    lowered = ANCESTRY_SYSTEM.lower()
    for name in ("dedale", "svcmon", "whoami", "soffice", "taskkill", "conhost", "client1",
                 "breach", "job.cmd", "acct-", "ws-"):
        assert name not in lowered


def test_v7_sends_its_prompt_and_asks_for_ancestry_in_the_menu(scenario):
    _, _, client = _run(scenario, [_answer("abstain")])
    system, prompt = client.calls[0]
    assert system == ANCESTRY_SYSTEM
    assert "the parent shown in the cited row is already known" not in prompt
    assert "what launched this process (its parent and how that parent was started)" in prompt


def test_v7_is_selectable_wherever_profiles_are_chosen():
    from ath import workflow
    from ath.cli import build_parser

    assert build_parser().parse_args(["investigate", "--profile", "operational-v7"]).profile == "operational-v7"
    assert "operational-v7" in workflow.PROFILES
    run = build_parser().parse_args(["workflow", "run", "--profile", "operational-v7", "--out", "x"])
    assert run.profile == "operational-v7"
