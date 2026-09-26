"""Operational-v6: control-plane evidence and probes, and the case that motivated them.

In the first real-data assessment a Kubernetes seed (one clusterrolebinding create) gave
v5 an empty checked-observation catalog; 9B cited a reference that did not exist, the
repair failed, and the case failed closed. These tests pin that behaviour for v5 and
the fix for v6. Scripted clients only: nothing here is a model score.
"""

import json
import re

import pytest

from _builders import at, ctrl, telemetry
from ath.agent.contract import check_prompt_contract, wrap_untrusted
from ath.agent.control_tools import TOOL_NAMES, ControlPlaneTools
from ath.agent.evidence import AssertionKind as K
from ath.agent.llm import ScriptedLLM
from ath.agent.operational import ControlPlaneProfile, StableContextProfile
from ath.agent.references import _ReferenceClient, observation_catalog
from ath.agent.tools import ToolBox
from ath.evaluation import real_cases as real


def _corpus():
    grant = ctrl("ops-admin", "create", "clusterrolebindings", "viewer-binding", target_actor="svc-reader",
                 role_ref="view", source_ip="198.51.100.20", when=at(1))
    other = ctrl("ops-admin", "get", "pods", "app-0", namespace="default", when=at(2))
    use = ctrl("svc-reader", "exec", "pods/exec", "app-0", namespace="default", when=at(5))
    earlier = ctrl("svc-reader", "get", "secrets", "db", namespace="default", when=at(0))
    return telemetry(ctrls=[grant, other, use, earlier]), grant, use, earlier


def _seeded_case(corpus, grant):
    incident = real.analyst_incident(corpus, [grant["event_id"]])
    return real.RealCase("k8s-grant", corpus, "benign", (), None, tuple(incident.event_ids),
                         real.ANALYST, (grant["event_id"],))


class CitesMissingReference(ScriptedLLM):
    """What 9B did on the real case: cite R2 whatever the catalog holds."""

    def complete(self, system, prompt, max_tokens=1024, timeout_seconds=None):
        self.responses.append(json.dumps({
            "explanations": [{"label": "insufficient", "statement": "Scripted.", "evidence": ["R2"]}],
            "evidence_gap": "intent", "next_probe": "none", "probe_reason": "Scripted.", "disposition": "abstain"}))
        return super().complete(system, prompt, max_tokens, timeout_seconds)


class CitesFirstReference(ScriptedLLM):
    def __init__(self, probe="none"):
        super().__init__([])
        self.probe = probe

    def complete(self, system, prompt, max_tokens=1024, timeout_seconds=None):
        catalog = prompt.split("CHECKED OBSERVATIONS", 1)[1]
        refs = re.findall(r"^(R\d+):", catalog, re.M)
        probe = self.probe if not self.calls else "none"
        self.responses.append(json.dumps({
            "explanations": [{"label": "insufficient", "statement": "Scripted.", "evidence": refs[:1]}],
            "evidence_gap": "intent", "next_probe": probe, "probe_reason": "Scripted.", "disposition": "abstain"}))
        return super().complete(system, prompt, max_tokens, timeout_seconds)


def test_v6_catalog_makes_a_lone_control_row_citable_and_v5_stays_unchanged():
    corpus, grant, _, _ = _corpus()
    assert observation_catalog(corpus, [grant["event_id"]]) == {}
    catalog = observation_catalog(corpus, [grant["event_id"]], include_control=True)
    (assertion,) = catalog.values()
    assert assertion.kind is K.CONTROL_ACTION and assertion.expected == "create clusterrolebindings"


def test_case_8_fails_closed_under_v5_and_completes_under_v6():
    corpus, grant, _, _ = _corpus()
    case = _seeded_case(corpus, grant)
    v5 = CitesMissingReference([])
    row, _ = real.evaluate_case(case, "d1", v5, scripted=True, profile=StableContextProfile())
    assert not row["scores"]["complete"] and row["scores"]["decision"] == "abstain"
    assert "(none)" in v5.calls[0][1] and "after repair" in row["state"]["investigation"]["rounds"][0]["error"]
    v6 = CitesFirstReference()
    row, _ = real.evaluate_case(case, "d1", v6, scripted=True, profile=ControlPlaneProfile())
    assert row["scores"]["complete"]
    assert "records the action create on clusterrolebindings" in v6.calls[0][1]
    assert any(a["kind"] == "control_action" for c in row["state"]["claims"] for a in c.get("assertions", []))


def test_v6_states_an_empty_catalog_plainly():
    client = _ReferenceClient(ScriptedLLM([json.dumps({})]), empty_note=True)
    client.complete("system", "prompt")
    assert "there are no citable observations yet; every evidence array must be empty" in client.client.calls[0][1]
    plain = _ReferenceClient(ScriptedLLM([json.dumps({})]))
    plain.complete("system", "prompt")
    assert plain.client.calls[0][1].rstrip().endswith("(none)")


def test_v6_menu_offers_control_probes_first_bounded_and_never_twice():
    corpus, grant, _, _ = _corpus()
    case = _seeded_case(corpus, grant)
    client = CitesFirstReference(probe="P1")
    row, _ = real.evaluate_case(case, "d1", client, scripted=True, profile=ControlPlaneProfile())
    rounds = row["state"]["investigation"]["rounds"]
    first = rounds[0]["menu"]
    assert first[:3] == ["P1:actor_control_history", "P2:resource_control_history", "P3:identity_grants"]
    assert len(first) <= 8 and len(set(first)) == len(first)
    assert "P1:actor_control_history" not in rounds[1]["menu"] or rounds[1]["menu"] == []
    assert row["scores"]["complete"]


def test_v6_prompts_keep_the_contract_with_recorded_values_marked_untrusted():
    corpus, grant, _, _ = _corpus()
    case = _seeded_case(corpus, grant)
    client = CitesFirstReference(probe="P3")
    row, _ = real.evaluate_case(case, "d1", client, scripted=True, profile=ControlPlaneProfile())
    assert row["scores"]["complete"]
    for _, prompt, *_ in client.calls:
        assert check_prompt_contract(prompt, ignore_untrusted=True) == []
        for banned in ("target_actor", "role_ref", "resource_namespace", "actor_groups", "decision"):
            assert not re.search(rf"(?<![A-Za-z0-9_]){banned}(?![A-Za-z0-9_])", prompt)
    assert "<untrusted control-plane records>" in client.calls[1][1]


def test_contract_ignores_untrusted_only_when_asked():
    prompt = "Observation " + wrap_untrusted("controller signer rotated", "records")
    assert check_prompt_contract(prompt) == ["signer"]
    assert check_prompt_contract(prompt, ignore_untrusted=True) == []
    assert check_prompt_contract("signer outside", ignore_untrusted=True) == ["signer"]


def test_control_tools_read_the_control_table_and_share_the_toolbox_ledger():
    corpus, grant, use, earlier = _corpus()
    box = ToolBox(corpus, [], [], max_rows=1, ledger=True)
    tools = ControlPlaneTools(box)
    history = tools.actor_control_history("ops-admin", agent="t")
    assert history["summary"]["total"] == 2 and history["truncated"] and len(history["events"]) == 1
    assert history["events"][0]["subject"] == "svc-reader" and history["events"][0]["role"] == "view"
    grants = tools.identity_grants("svc-reader", agent="t")
    assert grants["grants"] == 1 and grants["later_use"] == 1  # the earlier secrets read is before the grant
    assert grants["summary"]["roles_granted"] == ["view"]
    resource = tools.resource_control_history("pods/exec", "app-0", "default", agent="t")
    assert [e["event_id"] for e in resource["events"]] == [use["event_id"]]
    assert tools.actor_control_history("nobody", agent="t")["events"] == []
    assert [c.tool for c in box.calls] == [
        "actor_control_history", "identity_grants", "resource_control_history", "actor_control_history"]
    assert all(c.args_sha256 and c.result_sha256 for c in box.calls)
    assert box.calls[0].truncated and len(box.calls[0].event_ids) == 2
    assert set(TOOL_NAMES) == {c.tool for c in box.calls}
    assert earlier["event_id"] not in grants["events"][0].values()


def test_control_tools_respect_the_tool_budget():
    corpus, *_ = _corpus()
    box = ToolBox(corpus, [], [], tool_call_budget=1)
    tools = ControlPlaneTools(box)
    tools.actor_control_history("ops-admin")
    refused = tools.identity_grants("svc-reader")
    assert refused["refused"] and refused["events"] == [] and box.budget_hits == 1
    assert box.calls[-1].refused


def test_control_tools_are_not_part_of_the_frozen_toolbox_surface():
    assert not any(hasattr(ToolBox, name) for name in TOOL_NAMES)


@pytest.mark.parametrize("profile, expected", [(StableContextProfile(), False), (ControlPlaneProfile(), True)])
def test_only_v6_describes_control_rows_with_contract_safe_labels(profile, expected):
    corpus, grant, _, _ = _corpus()
    case = _seeded_case(corpus, grant)
    client = CitesFirstReference()
    real.evaluate_case(case, "d1", client, scripted=True, profile=profile)
    catalog = client.calls[0][1].split("CHECKED OBSERVATIONS", 1)[1]
    assert ("subject=svc-reader" in catalog) is expected
