"""The D1 bounded investigator: what it may do, what it may not, and how it is bounded.

Why these tests exist
----------------------
The first D1 preview measured a detector narrator (``reports/local/dev/D1_AUDIT.md``).
The loop in :mod:`ath.agent.investigator` exists to make one local model *seek*
evidence, and every property below is one the preview lacked. Each test is driven by a
scripted model over a hand-built corpus: a credential burst then a service-launched
shell whose child (a group enumeration) no detector cites. Ollama is never needed.

How each group fails
--------------------
*Behaviour.* The model can return a benign explanation and it survives as a claim; it can
abstain; at most one probe runs per round and at most ``MAX_PROBES`` in all; a
fabricated citation is a recorded rejection, never a silent drop; evidence a probe
returned can be cited and is counted as new; the path is the model's choice, not a
fixed sequence; a truncated reply degrades the row; findings reach the model as
observations with their benign causes, and no label ever does.

*Bounds.* More than three explanations, more than six ids, an unknown label or an
off-menu probe are dropped and counted; the schema states the same limits.
"""

from __future__ import annotations

import json

import pytest

from _builders import at, failures, logon, proc, telemetry as build_telemetry
from ath.agent.claims import ClaimType, ClaimVerifier
from ath.agent.investigator import (
    INVESTIGATOR_SYSTEM,
    MAX_EVIDENCE_PER_EXPLANATION,
    MAX_EXPLANATIONS,
    MAX_PROBES,
    RESPONSE_SCHEMA,
    D1Investigator,
    InvestigatorConfig,
    build_investigator,
    build_menu,
    parse_answer,
    prompt_hashes,
    prompt_sha256,
)
from ath.agent.llm import ScriptedLLM, truncated_reply
from ath.agent.tools import ToolBox
from ath.correlation import correlate
from ath.hunting import run_hunt

# --------------------------------------------------------------------------------------
# A corpus with an uncited child process
# --------------------------------------------------------------------------------------


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
        "telemetry": telemetry, "findings": list(hunt.findings), "cases": list(cases),
        "case": case, "shell_id": procs[1]["event_id"], "child_id": procs[2]["event_id"],
        "success_id": logons[-1]["event_id"], "an_uncited_failure": logons[0]["event_id"],
    }


def _answer(explanations, *, gap="the shell's children", probe="none", reason="", disposition="abstain") -> str:
    return json.dumps({
        "explanations": explanations, "evidence_gap": gap, "next_probe": probe,
        "probe_reason": reason, "disposition": disposition,
    })


def _run(world, responses, *, budget=40, max_probes=MAX_PROBES):
    tools = ToolBox(world["telemetry"], world["findings"], world["cases"], tool_call_budget=budget)
    llm = ScriptedLLM(responses=list(responses), name="scripted")
    investigator = D1Investigator(
        tools, ClaimVerifier(world["telemetry"]), llm=llm,
        config=InvestigatorConfig(max_probes=max_probes),
    )
    state = investigator.investigate(world["case"])
    return state, llm, tools


def _probe_ref(prompt: str, tool: str, needle: str = "") -> str:
    """The menu ref (``P<n>``) of the first probe naming ``tool`` (and ``needle``)."""
    for line in prompt.splitlines():
        if line.startswith("P") and f" {tool}(" in line and needle in line:
            return line.split()[0]
    raise AssertionError(f"no {tool} probe in the menu:\n{prompt}")


# --------------------------------------------------------------------------------------
# Behaviour
# --------------------------------------------------------------------------------------


def test_the_model_can_return_a_benign_explanation_and_it_becomes_a_claim(world) -> None:
    state, llm, _ = _run(world, [_answer(
        [{"label": "benign", "statement": "stale password retried from the owner's desk",
          "evidence": [world["success_id"]]}],
        disposition="benign",
    )])
    model_claims = [c for c in state.claims if c.source == "llm"]
    assert len(model_claims) == 1
    assert model_claims[0].claim_type is ClaimType.INFERENCE
    assert model_claims[0].statement.startswith("[benign]")
    assert model_claims[0].evidence_ids == (world["success_id"],)
    diagnostics = state.investigation
    assert diagnostics["benign_hypothesis_present_initial"] is True
    assert diagnostics["final_disposition"] == "benign" and diagnostics["abstained"] is False
    assert state.rejected_claims == []


def test_the_model_can_abstain_and_stop_without_a_probe(world) -> None:
    state, llm, tools = _run(world, [_answer(
        [{"label": "insufficient", "statement": "cannot tell yet", "evidence": []}],
        disposition="abstain",
    )])
    diagnostics = state.investigation
    assert diagnostics["abstained"] is True and diagnostics["final_disposition"] == "abstain"
    assert diagnostics["probes_run"] == [] and diagnostics["trajectory"] == ["seed"]
    assert diagnostics["model_calls"] == 1 and len(llm.calls) == 1
    assert diagnostics["stop_reason"] == "model chose no probe"
    hypotheses = [c for c in state.claims if c.source == "llm"]
    assert len(hypotheses) == 1 and hypotheses[0].claim_type is ClaimType.HYPOTHESIS


def test_at_most_one_probe_per_round_and_at_most_max_probes_in_all(world) -> None:
    """Three answers each asking for a probe: two probes run, three model calls, stop."""
    first_prompt_probe = None
    responses = []
    # The refs depend on the menu, which is deterministic: process_tree of the shell is
    # first, the account history follows. Ask for P1 every time; once it has run it is
    # no longer offered, so P1 becomes the next probe on the menu.
    for _ in range(MAX_PROBES + 2):
        responses.append(_answer(
            [{"label": "insufficient", "statement": "need more", "evidence": []}],
            probe="P1", reason="need it",
        ))
    state, llm, tools = _run(world, responses)
    diagnostics = state.investigation
    assert len(diagnostics["probes_run"]) == MAX_PROBES
    assert diagnostics["model_calls"] == MAX_PROBES + 1 == len(llm.calls)
    assert diagnostics["stop_reason"] == "probe budget spent"
    probe_steps = [r for r in state.results if r.agent == "investigator:probe"]
    assert len(probe_steps) == MAX_PROBES
    assert all(len(step.tool_calls) == 1 for step in probe_steps), "one tool call per probe"
    assert first_prompt_probe is None


def test_a_fabricated_citation_is_a_recorded_rejection(world) -> None:
    state, _, _ = _run(world, [_answer(
        [{"label": "malicious", "statement": "invented", "evidence": [world["shell_id"], "evt-999999"]}],
        disposition="malicious",
    )])
    assert [c for c in state.claims if c.source == "llm"] == []
    assert len(state.rejected_claims) == 1
    assert "evt-999999" in state.rejected_claims[0].reason
    assert state.investigation["final_disposition"] == "malicious"


def test_an_existing_id_the_model_was_not_shown_is_dropped_not_cited(world) -> None:
    state, _, _ = _run(world, [_answer(
        [{"label": "malicious", "statement": "guessing", "evidence": [world["child_id"], world["shell_id"]]}],
        disposition="malicious",
    )])
    # The child was never retrieved in this run (no probe), so it was never shown.
    claims = [c for c in state.claims if c.source == "llm"]
    assert len(claims) == 1 and claims[0].evidence_ids == (world["shell_id"],)
    assert any("the model was not shown" in line for line in state.plan_log)


def test_new_evidence_from_a_probe_can_be_cited_and_updates_the_hypotheses(world) -> None:
    """The LINK-2 shape without labels: the child of the service-launched shell is cited
    by no finding, appears only through ``process_tree``, and a claim may cite it only
    after the probe returned it."""
    first = _answer(
        [{"label": "malicious", "statement": "guessed then shell", "evidence": [world["shell_id"]]},
         {"label": "benign", "statement": "admin maintenance", "evidence": [world["shell_id"]]}],
        probe="P1", reason="need process-child evidence to separate maintenance from discovery",
    )
    second = _answer(
        [{"label": "malicious", "statement": "the shell's child enumerated domain admins",
          "evidence": [world["child_id"], world["success_id"]]}],
        disposition="malicious",
    )
    state, llm, _ = _run(world, [first, second])
    menu_line = _probe_ref(llm.calls[0][1], "process_tree", "cmd.exe")
    assert menu_line == "P1", "the cited shell's process tree is the first probe offered"
    diagnostics = state.investigation
    assert diagnostics["probes_run"] == ["process_tree"]
    assert diagnostics["new_evidence_ids_returned"] >= 1
    assert diagnostics["new_evidence_ids_shown"] >= 1
    assert diagnostics["new_evidence_ids_shown"] <= diagnostics["new_evidence_ids_returned"]
    assert diagnostics["rounds"][0]["new_evidence_ids_shown"] == diagnostics["new_evidence_ids_shown"]
    assert diagnostics["new_evidence_ids_used"] == 1
    assert diagnostics["hypothesis_changed_after_tool"] is True
    assert diagnostics["labels_changed_after_tool"] is True
    assert "admin maintenance" in diagnostics["rounds"][1]["dropped_explanations"]
    assert world["child_id"] in llm.calls[1][1], "the child row was shown after the probe"
    assert world["child_id"] not in llm.calls[0][1], "and not before"
    claims = [c for c in state.claims if c.source == "llm"]
    assert len(claims) == 1 and set(claims[0].evidence_ids) == {world["child_id"], world["success_id"]}
    assert claims[0].claim_type is ClaimType.INFERENCE
    assert state.rejected_claims == []


def test_a_probes_result_is_shown_as_new_evidence_in_the_next_round(world) -> None:
    """Pass 2 of the D1 tuning: in the smoke run the children were rendered but never
    cited, buried among the seed observations. The next round now separates them."""
    _, llm, _ = _run(world, [
        _answer([{"label": "insufficient", "statement": "s", "evidence": []}], probe="P1"),
        _answer([{"label": "insufficient", "statement": "s", "evidence": []}]),
    ])
    first, second = llm.calls[0][1], llm.calls[1][1]
    assert "NEW EVIDENCE" not in first
    assert "NEW EVIDENCE from your last probe" in second
    new_section = second[second.index("NEW EVIDENCE"):second.index("Probe menu")]
    assert world["child_id"] in new_section
    assert "Rewrite them against the new evidence" in second


def test_no_probe_is_offered_for_a_built_in_account(world) -> None:
    _, llm, _ = _run(world, [_answer([{"label": "insufficient", "statement": "s", "evidence": []}])])
    assert "user_auth_history(user='SYSTEM')" not in llm.calls[0][1]
    assert "user_auth_history(user='u1')" in llm.calls[0][1]


def test_the_system_prompt_carries_no_case_content_to_parrot() -> None:
    """The v2 examples named a mechanism ('stale cached password') and every smoke case
    repeated it. The prompt may describe shapes, never a story."""
    for phrase in ("stale cached password", "ev-410", "HOST-A", "acct u1", "-> disposition \"abstain\""):
        assert phrase not in INVESTIGATOR_SYSTEM, phrase
    assert "is not a default third entry" in INVESTIGATOR_SYSTEM
    assert "you must decide" in INVESTIGATOR_SYSTEM


def test_the_path_is_the_models_choice_not_a_fixed_sequence(world) -> None:
    lineage = _run(world, [_answer([{"label": "insufficient", "statement": "s", "evidence": []}], probe="P1")])
    prompt = lineage[1].calls[0][1]
    account = _probe_ref(prompt, "user_auth_history", "u1")
    history = _run(world, [_answer([{"label": "insufficient", "statement": "s", "evidence": []}], probe=account)])
    none = _run(world, [_answer([{"label": "insufficient", "statement": "s", "evidence": []}], probe="none")])
    trajectories = {
        tuple(lineage[0].investigation["trajectory"]),
        tuple(history[0].investigation["trajectory"]),
        tuple(none[0].investigation["trajectory"]),
    }
    assert trajectories == {("seed", "process_tree"), ("seed", "user_auth_history"), ("seed",)}
    assert lineage[0].investigation["tool_choice_reason"] == ""
    assert history[0].investigation["chosen_tool"] == "user_auth_history"


def test_an_off_menu_probe_is_recorded_and_runs_nothing(world) -> None:
    state, _, _ = _run(world, [_answer([{"label": "insufficient", "statement": "s", "evidence": []}], probe="P99")])
    assert state.investigation["probes_run"] == []
    assert state.investigation["rounds"][0]["invalid_probe"] == "P99"


def test_a_truncated_reply_degrades_the_row_and_concludes_nothing(world) -> None:
    state, _, _ = _run(world, [truncated_reply(768, text='{"explanations": [')])
    assert state.llm_degraded is True
    assert state.investigation["output_truncated"] is True
    assert state.investigation["final_disposition"] is None
    assert [c for c in state.claims if c.source == "llm"] == []
    assert state.investigation["stop_reason"] == "model call unusable"


def test_an_unparseable_reply_is_counted_not_a_model_failure(world) -> None:
    state, _, _ = _run(world, ["I think it is fine."])
    assert state.llm_degraded is False
    assert state.llm_unparseable_responses == 1
    assert state.llm_unparseable_by_kind == {"investigator": 1}
    assert state.investigation["final_disposition"] is None
    record = state.investigation["rounds"][0]
    assert record["raw"] == "I think it is fine.", "the unusable reply is the one a reader most needs recorded"


def test_the_raw_reply_and_the_prompt_digest_are_recorded_per_round(world) -> None:
    """Pass-1 rows could not say what the model wrote; the replay could not prove it
    rebuilt the same prompt. Both are now on the round record, and neither is hashed
    into the freeze, so rows before and after summarise together."""
    first = _answer([{"label": "insufficient", "statement": "s", "evidence": []}], probe="P1")
    second = _answer([{"label": "insufficient", "statement": "s", "evidence": []}])
    state, llm, _ = _run(world, [first, second])
    rounds = state.investigation["rounds"]
    assert [r["raw"] for r in rounds] == [first, second]
    assert [r["prompt_sha256"] for r in rounds] == [prompt_sha256(p) for _, p in llm.calls]
    assert [r["prompt_chars"] for r in rounds] == [len(p) for _, p in llm.calls]
    assert "raw" not in json.dumps(prompt_hashes())


def test_findings_reach_the_model_as_observations_with_benign_causes(world) -> None:
    _, llm, _ = _run(world, [_answer([{"label": "insufficient", "statement": "s", "evidence": []}])])
    system, prompt = llm.calls[0]
    assert "OBSERVATIONS, not conclusions" in system
    assert "Never force a malicious explanation" in system
    assert "[detector ATH-005" in prompt and "[detector ATH-007" in prompt
    assert "Known benign causes:" in prompt
    assert "[cited rows" in prompt, "the raw cited rows are shown, not only the detector's sentence"


def test_the_tail_of_a_long_evidence_list_is_shown_not_only_its_head(world) -> None:
    """A burst ends with the success and a case's rows end with the execution; a head-only
    rendering hid exactly those, and the first version of these tests caught it."""
    _, llm, _ = _run(world, [_answer([{"label": "insufficient", "statement": "s", "evidence": []}])])
    prompt = llm.calls[0][1]
    assert world["success_id"] in prompt and world["shell_id"] in prompt
    assert "more" in prompt, "the elided middle is counted, never silent"


def test_the_seed_facts_still_come_from_deterministic_sources(world) -> None:
    state, _, _ = _run(world, [_answer([{"label": "insufficient", "statement": "s", "evidence": []}])])
    seed = [c for c in state.claims if c.agent == "investigator:seed"]
    assert seed and all(c.claim_type is ClaimType.FACT for c in seed)
    assert {c.source for c in seed} <= {"detector", "tool", "mitre"}


def test_nothing_the_model_sees_names_a_label(world) -> None:
    _, llm, _ = _run(world, [_answer([{"label": "insufficient", "statement": "s", "evidence": []}], probe="P1"),
                             _answer([{"label": "insufficient", "statement": "s", "evidence": []}])])
    for system, prompt in llm.calls:
        text = system + prompt
        for forbidden in ("LINK-", "labels.json", "labelled", "ground truth", "scenario"):
            assert forbidden not in text, forbidden


def test_the_budgets_still_bind(world) -> None:
    state, _, tools = _run(world, [
        _answer([{"label": "insufficient", "statement": "s", "evidence": []}], probe="P1"),
        _answer([{"label": "insufficient", "statement": "s", "evidence": []}], probe="P1"),
        _answer([{"label": "insufficient", "statement": "s", "evidence": []}]),
    ], budget=2)
    assert tools.budget_hits >= 1
    assert state.investigation["stop_reason"] in ("step or tool budget spent", "model chose no probe", "probe budget spent")
    assert all(c.evidence_ids for c in state.facts)


# --------------------------------------------------------------------------------------
# Bounds
# --------------------------------------------------------------------------------------


def test_the_schema_states_the_same_limits_the_parser_enforces() -> None:
    explanations = RESPONSE_SCHEMA["properties"]["explanations"]
    assert explanations["maxItems"] == MAX_EXPLANATIONS == 3
    assert explanations["items"]["properties"]["evidence"]["maxItems"] == MAX_EVIDENCE_PER_EXPLANATION == 6
    assert explanations["items"]["properties"]["label"]["enum"] == ["malicious", "benign", "insufficient"]
    assert RESPONSE_SCHEMA["properties"]["disposition"]["enum"] == ["malicious", "benign", "abstain"]
    assert set(RESPONSE_SCHEMA["required"]) == {"explanations", "evidence_gap", "next_probe", "probe_reason", "disposition"}


def test_the_parser_drops_and_counts_everything_over_the_limits() -> None:
    answer = parse_answer({
        "explanations": [
            {"label": "malicious", "statement": "a", "evidence": [f"e{i}" for i in range(10)]},
            {"label": "benign", "statement": "b", "evidence": []},
            {"label": "insufficient", "statement": "c", "evidence": ["x", "x"]},
            {"label": "malicious", "statement": "d", "evidence": []},
        ],
        "evidence_gap": "g", "next_probe": "p2", "probe_reason": "r", "disposition": "MALICIOUS",
    })
    assert len(answer.explanations) == MAX_EXPLANATIONS
    assert len(answer.explanations[0].evidence) == MAX_EVIDENCE_PER_EXPLANATION
    assert answer.explanations[2].evidence == ("x",), "duplicate ids collapse"
    assert answer.dropped == {"explanations_over_limit": 1, "evidence_over_limit": 4}
    assert answer.next_probe == "P2" and answer.disposition == "malicious"
    assert answer.has_benign is True


def test_the_parser_rejects_unknown_labels_and_dispositions() -> None:
    answer = parse_answer({
        "explanations": [{"label": "suspicious", "statement": "a", "evidence": []}, "junk"],
        "evidence_gap": "", "next_probe": "", "probe_reason": "", "disposition": "guilty",
    })
    assert answer.explanations == []
    assert answer.dropped["malformed"] == 2 and answer.dropped["disposition_invalid"] == 1
    assert answer.next_probe == "none" and answer.disposition == "abstain"


def test_the_menu_is_deterministic_bounded_and_never_offers_a_probe_twice(world) -> None:
    case = world["case"]
    rows = [{"device": "HOST-B", "process_id": 500, "process_guid": "", "process_name": "cmd.exe"}]
    menu = build_menu(case, rows, [], [], already_run=set())
    assert [p.tool for p in menu][:1] == ["process_tree"]
    assert menu == build_menu(case, rows, [], [], already_run=set())
    again = build_menu(case, rows, [], [], already_run={menu[0].key})
    assert menu[0].key not in {p.key for p in again}
    assert [p.ref for p in again] == [f"P{i + 1}" for i in range(len(again))], "refs are renumbered"
    many = [dict(rows[0], process_id=500 + i) for i in range(20)]
    assert len(build_menu(case, many, many, [("HOST-B", "1.2.3.4")] * 5, already_run=set())) <= 8
    for probe in menu:
        text = probe.render()
        assert "retrieves" in text and "Use when" in text and "Not for" in text


def test_the_prompt_hashes_cover_the_prompts_the_schema_and_the_bounds() -> None:
    hashes = prompt_hashes()
    assert set(hashes) == {
        "investigator_version", "investigator_system", "investigator_user_template",
        "investigator_previous_template", "investigator_schema", "investigator_bounds",
    }
    assert all(len(v) == 64 for k, v in hashes.items() if k != "investigator_version")
    assert "Respond with JSON only" in INVESTIGATOR_SYSTEM


def test_build_investigator_carries_the_arms_step_budget(world) -> None:
    tools = ToolBox(world["telemetry"], world["findings"], world["cases"])
    investigator = build_investigator(tools, ClaimVerifier(world["telemetry"]), None, max_steps=3, max_probes=1)
    assert investigator.config.max_steps == 3 and investigator.config.max_probes == 1
    state = investigator.investigate(world["case"])
    assert state.llm_requested is False and state.investigation["stop_reason"] == "no model available"
