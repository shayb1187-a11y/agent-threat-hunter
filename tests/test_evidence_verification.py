"""Counterexamples that citation existence alone cannot reject."""

from __future__ import annotations

import json
from dataclasses import replace

import pandas as pd
import pytest

from _builders import at, logon, net, proc, telemetry
from ath.agent.claims import Claim, ClaimType, ClaimVerifier
from ath.agent.evidence import AssertionKind as K
from ath.agent.evidence import EvidenceAssertion as A
from ath.agent.evidence import EvidenceStatus as S
from ath.agent.evidence import EvidenceVerifier
from ath.agent.llm import ScriptedLLM
from ath.agent.operational import EvidenceProfile, investigate_operational
from ath.reporting import build_report, render_markdown
from test_d1_investigator import world  # noqa: F401


@pytest.fixture
def evidence():
    parent = proc("cmd.exe", "cmd.exe", "services.exe", pid=101, when=at(1), guid="sysmon:parent")
    child = proc("whoami.exe", "whoami.exe", "cmd.exe", pid=102, ppid=101,
                 when=at(2), guid="sysmon:child", parent_guid="sysmon:parent")
    connection = net("whoami.exe", "192.0.2.1", pid=102, when=at(3), guid="sysmon:child")
    success = logon("alice", "PC01", action="success", when=at(0))
    failure = logon("alice", "PC01", action="failure", when=at(0, 10))
    corpus = telemetry(procs=[parent, child], nets=[connection], logons=[success, failure])
    return corpus, {k: v["event_id"] for k, v in locals().copy().items()
                    if k in ("parent", "child", "connection", "success", "failure")}


def test_failed_login_cannot_support_success_even_with_a_real_citation(evidence):
    corpus, ids = evidence
    assertion = A(K.AUTH_OUTCOME, ids["failure"], expected="success")
    claim = Claim(ClaimType.INFERENCE, "Authentication succeeded", (ids["failure"],),
                  source="llm", assertions=(assertion,))
    verifier = ClaimVerifier(corpus)
    assert verifier.check(replace(claim, assertions=())) is None
    assert "contradicted" in verifier.check(claim)
    assert verifier.evidence_checks(claim)[0].status is S.CONTRADICTED


@pytest.mark.parametrize("kind,left,right,expected", [
    (K.AUTH_OUTCOME, "success", "", "success"),
    (K.PROCESS_IDENTITY, "child", "", "sysmon:child"),
    (K.SAME_PROCESS, "child", "connection", ""),
    (K.PARENT_CHILD, "parent", "child", ""),
    (K.BEFORE, "success", "child", ""),
])
def test_supported_predicates(evidence, kind, left, right, expected):
    corpus, ids = evidence
    assertion = A(kind, ids[left], ids[right] if right else "", expected)
    assert EvidenceVerifier(corpus).check(assertion).status is S.SUPPORTED
    claim = Claim(ClaimType.FACT, assertion.render(), assertion.event_ids,
                  source="telemetry", assertions=(assertion,))
    assert ClaimVerifier(corpus).check(claim) is None
    assert json.loads(json.dumps(claim.to_dict()))["assertions"] == [assertion.to_dict()]


@pytest.mark.parametrize("change,status", [
    ({"process_guid": "sysmon:reused-pid"}, S.CONTRADICTED),
    ({"device": "other-host"}, S.CONTRADICTED),
    ({"process_guid": ""}, S.UNVERIFIABLE),
    ({"process_guid": "start:pc01|102|2026-08-17T08:02:00Z"}, S.UNVERIFIABLE),
    ({"process_guid": "unknown:child"}, S.UNVERIFIABLE),
    ({"process_id": 777}, S.CONTRADICTED),
])
def test_identity_never_promotes_pid_fallback_or_conflicting_fields(evidence, change, status):
    corpus, ids = evidence
    for field, value in change.items():
        corpus.network.loc[:, field] = value
    assert EvidenceVerifier(corpus).check(A(K.SAME_PROCESS, ids["child"], ids["connection"])).status is status


@pytest.mark.parametrize("change,status", [
    ({"parent_process_guid": "sysmon:someone-else"}, S.CONTRADICTED),
    ({"parent_process_guid": ""}, S.UNVERIFIABLE),
    ({"timestamp": at(0)}, S.CONTRADICTED),
    ({"parent_process_id": 333}, S.CONTRADICTED),
    ({"device": "other-host"}, S.CONTRADICTED),
])
def test_parent_child_requires_identity_host_and_chronology(evidence, change, status):
    corpus, ids = evidence
    for field, value in change.items():
        corpus.processes.loc[corpus.processes.event_id == ids["child"], field] = value
    assert EvidenceVerifier(corpus).check(A(K.PARENT_CHILD, ids["parent"], ids["child"])).status is status


def test_order_is_strict_and_missing_time_is_not_a_negative_result(evidence):
    corpus, ids = evidence
    verifier = EvidenceVerifier(corpus)
    assert verifier.check(A(K.BEFORE, ids["child"], ids["parent"])).status is S.CONTRADICTED
    assert verifier.check(A(K.BEFORE, ids["parent"], ids["parent"])).status is S.CONTRADICTED
    corpus.processes.loc[corpus.processes.event_id == ids["child"], "timestamp"] = pd.NaT
    assert verifier.check(A(K.BEFORE, ids["parent"], ids["child"])).status is S.UNVERIFIABLE


def test_duplicate_event_id_is_ambiguous_even_if_rows_agree(evidence):
    corpus, ids = evidence
    corpus.logons = pd.concat([corpus.logons, corpus.logons.iloc[:1]], ignore_index=True)
    check = EvidenceVerifier(corpus).check(A(K.AUTH_OUTCOME, ids["success"], expected="success"))
    assert check.status is S.UNVERIFIABLE and "duplicate" in check.reason


def test_missing_outcome_wrong_channel_and_unknown_event_have_distinct_results(evidence):
    corpus, ids = evidence
    corpus.logons.loc[corpus.logons.event_id == ids["success"], "action"] = "unknown"
    verifier = EvidenceVerifier(corpus)
    assert verifier.check(A(K.AUTH_OUTCOME, ids["success"], expected="success")).status is S.UNVERIFIABLE
    assert verifier.check(A(K.AUTH_OUTCOME, ids["parent"], expected="success")).status is S.CONTRADICTED
    assert verifier.check(A(K.AUTH_OUTCOME, "absent", expected="success")).status is S.UNVERIFIABLE


def test_predicate_references_must_be_cited_and_retrieved(evidence):
    corpus, ids = evidence
    assertion = A(K.BEFORE, ids["success"], ids["child"])
    claim = Claim(ClaimType.INFERENCE, "Possible relationship", (ids["success"],), source="llm", assertions=(assertion,))
    verifier = ClaimVerifier(corpus)
    assert "outside" in verifier.check(claim)
    cited = replace(claim, evidence_ids=assertion.event_ids)
    assert "not retrieved" in verifier.check(cited, retrieved=frozenset([ids["success"]]))


def test_valid_predicate_cannot_launder_arbitrary_prose_into_a_fact(evidence):
    corpus, ids = evidence
    assertion = A(K.AUTH_OUTCOME, ids["success"], expected="success")
    claim = Claim(ClaimType.FACT, "The attacker stole credentials", assertion.event_ids,
                  source="tool", assertions=(assertion,))
    assert "deterministic assertion wording" in ClaimVerifier(corpus).check(claim)


@pytest.mark.parametrize("payload", [
    {}, {"kind": "invented", "event_id": "x"},
    {"kind": "auth_outcome", "event_id": "x", "expected": "maybe"},
    {"kind": "before", "event_id": "x"},
    {"kind": "before", "event_id": "x", "other_event_id": "y", "expected": "malicious"},
    {"kind": "auth_outcome", "event_id": "x", "expected": "success", "ignored": True},
])
def test_assertion_schema_is_closed_and_rejects_malformed_payloads(payload):
    with pytest.raises(ValueError):
        A.from_dict(payload)


def response(event_id, expected):
    return json.dumps({
        "explanations": [{"label": "malicious", "statement": "The login succeeded and may support lateral movement",
                          "evidence": [event_id], "assertions": [
                              {"kind": "auth_outcome", "event_id": event_id, "expected": expected}]}],
        "evidence_gap": "intent", "next_probe": "none", "probe_reason": "", "disposition": "malicious",
    })


def test_operational_v2_rejects_a_false_authentication_premise_end_to_end(world):
    event_id = world["an_uncited_failure"]
    client = ScriptedLLM(responses=[response(event_id, "success")])
    state = investigate_operational(world["case"], world["telemetry"], world["findings"],
                                    llm=client, profile=EvidenceProfile())
    assert state.status.value == "incomplete"
    assert any("contradicted" in r.reason for r in state.rejected_claims)
    assert state.investigation["final_disposition"] == "abstain"
    assert all(c.assertions for c in state.facts)
    report = build_report(state, world["telemetry"])
    assert "contradicted" in render_markdown(report)
    assert report.to_dict()["evidence_verification"]["interpretation_verified"] is False


def test_supported_model_premises_do_not_promote_attack_interpretations_to_facts(world):
    client = ScriptedLLM(responses=[response(world["success_id"], "success")])
    state = investigate_operational(world["case"], world["telemetry"], world["findings"],
                                    llm=client, profile=EvidenceProfile())
    assert state.status.value == "complete"
    assert any(c.source == "llm" and c.assertions for c in state.inferences)
    assert all(c.source != "llm" and c.assertions for c in state.facts)
    assert all("lateral movement" not in c.statement for c in state.facts)
    assert state.investigation["rounds"][0]["system_sha256"]
    assert "auth_outcome" in client.calls[0][0]


def test_deterministic_v2_separates_detector_interpretations_from_observations(world):
    state = investigate_operational(world["case"], world["telemetry"], world["findings"], profile=EvidenceProfile())
    assert state.status.value == "complete"
    assert state.facts and all(c.assertions for c in state.facts)
    assert all(c.source != "detector" for c in state.facts)
    assert state.investigation["evidence_verification"]["summaries_reclassified"] > 0


def test_legacy_claim_serialization_has_no_new_keys(evidence):
    _, ids = evidence
    claim = Claim(ClaimType.FACT, "legacy summary", (ids["success"],))
    assert "assertions" not in claim.to_dict()


# -- operational-v6: control-plane actions ------------------------------------------------

from _builders import ctrl  # noqa: E402
from ath.agent.structured import EVIDENCE_RESPONSE_SCHEMA, V2_ASSERTION_KINDS  # noqa: E402


def test_control_action_is_supported_contradicted_or_unverifiable():
    binding = ctrl("alice", "create", "clusterrolebindings", "ops-admin", when=at(1))
    corpus = telemetry(ctrls=[binding], logons=[logon("alice", "PC01", action="success", when=at(0))])
    verifier = EvidenceVerifier(corpus)
    event = binding["event_id"]
    assert verifier.check(A(K.CONTROL_ACTION, event, expected="create clusterrolebindings")).status is S.SUPPORTED
    assert verifier.check(A(K.CONTROL_ACTION, event, expected="delete clusterrolebindings")).status is S.CONTRADICTED
    login = corpus.logons["event_id"].iloc[0]
    assert verifier.check(A(K.CONTROL_ACTION, login, expected="create clusterrolebindings")).status is S.CONTRADICTED
    assert verifier.check(A(K.CONTROL_ACTION, "missing", expected="create pods")).status is S.UNVERIFIABLE
    assert "records the action create on clusterrolebindings" in A(
        K.CONTROL_ACTION, event, expected="create clusterrolebindings").render()


@pytest.mark.parametrize("expected", ["", "create", "create pods now"])
def test_control_action_needs_a_verb_and_a_resource_type(expected):
    with pytest.raises(ValueError):
        A(K.CONTROL_ACTION, "e1", expected=expected)


def test_v2_evidence_contract_is_pinned_to_its_original_kinds():
    enum = EVIDENCE_RESPONSE_SCHEMA["properties"]["explanations"]["items"]["properties"]["assertions"]["items"]["properties"]["kind"]["enum"]
    assert enum == list(V2_ASSERTION_KINDS) and "control_action" not in enum
    # The operational-v2 freezes (4B and 9B Colab runs) recorded this schema digest.
    assert _format_schema_sha256() == "9bd1e78333e616d78e8e8adabb36608b0ba4807b2181537a7b2f387a48ed44f5"


def _format_schema_sha256():
    from ath.agent.operational import EvidenceProfile
    from ath.evaluation.auth_execution import _client
    return _client("qwen3.5:9b", EvidenceProfile()).configuration()["format_schema_sha256"]
