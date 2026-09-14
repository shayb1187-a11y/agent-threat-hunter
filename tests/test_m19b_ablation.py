"""M19b T8: the run-and-score harness, and the rules it may not be talked out of.

What each group is for, and how it fails
-----------------------------------------
*The freeze.* M19b's whole claim is that the arms ran under M19's conditions except for
one pre-registered byte budget. Two tests hold it: the freeze is refused when the M19
equality or the scoring reproduction fails, and it is refused when a live ``ArmConfig``
does not carry the ``tool_output_budget`` the pre-registration fixed -- in either
direction, so a bound that silently reaches arm A fails as loudly as one that vanishes
from arm C.

*The specificity rule.* The metric it repairs is the one that made arm A look like it had
recovered every cross-domain link: the ATT&CK mapper's inference cites 100% of the case's
evidence, satisfies "one claim cites both sides", and asserts nothing. The tests state the
three cases the pre-registration names -- a claim citing everything never recovers, a
claim citing two of thirty does, and a claim citing twenty-six ids does not even when
that is a small share of a large case -- and they fail if either constant moves.

*Stage recovery and discrimination.* Constructed claims with known ids, so the expected
answer is stated rather than observed. Discrimination is deliberately two-sided: an arm
that reaches the benign explanation *and* asserts the malicious reading as fact has
discriminated nothing, and the test fails if the second half is ever dropped.

*The grader.* Three constructed arm files drive every branch of the section-5 decision
rule. They contain no prose at all, which is the point: if the grader ever started
reading a statement, these files would stop being sufficient to grade.

*The substrings.* They are pre-registered, so the test is provenance, not taste: every
substring a case requires must appear in that case's own rubric text in ``MANIFEST.json``,
all nine cases must be covered, and the benign cases must carry the explanation the
pre-registration names and forbid the malicious reading.

*The paths.* ``reports/m19/`` is frozen and T5c's ``arm_A.json`` is committed. Both
refusals are by path, before any bytes are written.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import m19b_ablation as harness  # noqa: E402

from _builders import telemetry as build_telemetry  # noqa: E402

from ath.agent.claims import Claim, ClaimType  # noqa: E402
from ath.agent.llm import (  # noqa: E402
    ScriptedLLM,
    build_request_body,
    encode_request_body,
)
from ath.agent.orchestrator import InvestigationConfig  # noqa: E402
from ath.agent.state import InvestigationState  # noqa: E402
from ath.correlation import correlate  # noqa: E402
from ath.correlation.chain import InvestigationCase  # noqa: E402
from ath.evaluation.ablation import ARM_A, ARM_B, ARM_C, build_manifest, run_arm  # noqa: E402
from ath.evaluation.incidents import Incident, score_labels  # noqa: E402
from ath.hunting import run_hunt  # noqa: E402
from ath.telemetry.loader import Telemetry  # noqa: E402

M19_DIR = ROOT / "reports" / "m19" / "ablation"
MANIFEST = json.loads(
    (ROOT / "reports" / "m19b" / "MANIFEST.json").read_text(encoding="utf-8")
)
CASE_KEYS = [f"{c['corpus']}/{c['case_id']}" for c in MANIFEST["cases"]]


# --------------------------------------------------------------------------------------
# The freeze, and the one divergence
# --------------------------------------------------------------------------------------


def _payload(*, equal: bool = True, reproduces: bool = True, agrees: bool = True) -> dict:
    return {
        "m19": {"equal": equal, "differences": [] if equal else ["prompts: differs"]},
        "scoring": {
            "reproduces_grading": reproduces,
            "differences": [] if reproduces else ["arms.B_single_llm.overall: moved"],
        },
        "divergence": {"agrees_with_live_arms": agrees},
    }


def test_the_freeze_is_refused_when_m19_equality_fails() -> None:
    refusals = harness.freeze_refusals(_payload(equal=False))
    assert refusals and any("M19 equality" in r for r in refusals)


def test_the_freeze_is_refused_when_a_published_m19_number_moved() -> None:
    refusals = harness.freeze_refusals(_payload(reproduces=False))
    assert refusals and any("M19 scoring" in r for r in refusals)


def test_the_freeze_is_refused_on_a_wrong_tool_output_budget() -> None:
    """Both directions. A bound reaching arm A is as much a refusal as one leaving C."""
    from dataclasses import replace

    arms = harness.m19b_arms()
    assert not harness.budget_differences(arms, harness.FROZEN_TOOL_OUTPUT_BUDGET)

    wrong_c = [
        replace(arm, config=replace(arm.config, tool_output_budget=2048))
        if arm.name == ARM_C else arm
        for arm in arms
    ]
    differences = harness.budget_differences(wrong_c, harness.FROZEN_TOOL_OUTPUT_BUDGET)
    assert differences and ARM_C in differences[0] and "2048" in differences[0]
    assert harness.freeze_refusals(
        {**_payload(agrees=False), "divergence": {"agrees_with_live_arms": False}}
    )

    bounded_a = [
        replace(arm, config=replace(arm.config, tool_output_budget=4096))
        if arm.name == ARM_A else arm
        for arm in arms
    ]
    assert harness.budget_differences(bounded_a, harness.FROZEN_TOOL_OUTPUT_BUDGET), (
        "the deterministic baseline must carry M19's value; a divergence that quietly "
        "reached it would make it a different experiment from the one that produced "
        "arm_A.json"
    )


def test_the_live_arms_carry_the_pre_registered_budget() -> None:
    record = harness.divergence_record(harness.m19b_arms())
    assert record["count"] == 1
    assert record["field"] == "InvestigationConfig.tool_output_budget"
    assert record["m19b_value"] == {
        ARM_A: None, ARM_B: harness.TOOL_OUTPUT_BUDGET, ARM_C: harness.TOOL_OUTPUT_BUDGET,
    }
    assert record["agrees_with_live_arms"] is True
    assert record["default_unchanged"] is True, (
        "the library default stays unbounded; M19's frozen runs must keep meaning what "
        "they meant"
    )
    assert InvestigationConfig().tool_output_budget is None


def test_a_model_arm_is_refused_when_the_live_arm_left_the_frozen_budget() -> None:
    from dataclasses import replace

    frozen = {"divergence": {"m19b_value": {ARM_B: harness.TOOL_OUTPUT_BUDGET}}}
    arm = harness.m19b_arm("B")
    drifted = replace(arm, config=replace(arm.config, tool_output_budget=None))
    with pytest.raises(SystemExit) as excinfo:
        harness.guard_arm(drifted, frozen, "digest")
    assert "tool_output_budget" in str(excinfo.value)


def test_no_arm_may_run_before_the_environment_is_frozen(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as excinfo:
        harness.read_environment(tmp_path)
    assert "freeze" in str(excinfo.value)


# --------------------------------------------------------------------------------------
# The specificity rule
# --------------------------------------------------------------------------------------

LEFT, RIGHT = "id-identity", "id-endpoint"


def _domain_of(event_id: str):
    return "identity" if str(event_id).startswith("id-identity") else "endpoint"


def _case(links: list[tuple[str, str]], evidence: list[str]) -> dict:
    return {
        "case_id": "CASE-001",
        "cder": f"DEFINED ({len(links)} pre-registered link(s))",
        "evidence_ids": evidence,
        "links": [
            {
                "link_id": f"L{index + 1}",
                "identity": {"event_id": left},
                "endpoint": {"event_id": right},
            }
            for index, (left, right) in enumerate(links)
        ],
    }


def _claims(*claims: tuple[str, list[str]]) -> dict:
    return {
        "claims": [
            {"type": claim_type, "agent": "test", "source": "t",
             "statement": "s", "evidence_ids": list(ids)}
            for claim_type, ids in claims
        ]
    }


def test_a_claim_citing_the_whole_case_recovers_nothing() -> None:
    """The measured failure the rule exists for: arm A's blanket ATT&CK inference."""
    evidence = [LEFT, RIGHT] + [f"id-endpoint-{n:03d}" for n in range(28)]
    case = _case([(LEFT, RIGHT)], evidence)
    payload = _claims(("INFERENCE", evidence))

    block = harness.cder(payload, case, set(evidence), _domain_of)

    assert block["specific_recovered"] == 0
    assert block["any_recovered"] == 1
    assert block["blanket_recovered"] == 1
    assert block["blanket_link_ids"] == ["L1"]
    assert block["specific_link_ids"] == []


def test_a_claim_citing_two_of_thirty_recovers_the_link() -> None:
    evidence = [LEFT, RIGHT] + [f"id-endpoint-{n:03d}" for n in range(28)]
    assert len(evidence) == 30
    case = _case([(LEFT, RIGHT)], evidence)

    block = harness.cder(
        _claims(("INFERENCE", [LEFT, RIGHT])), case, set(evidence), _domain_of,
    )

    assert block["specific_recovered"] == 1
    assert block["specific"] == 1.0
    assert block["blanket_recovered"] == 0


def test_a_claim_citing_twenty_six_ids_is_not_specific_however_large_the_case() -> None:
    """The id cap is not a restatement of the fraction: here 26 of 100 is 26%."""
    evidence = [LEFT, RIGHT] + [f"id-endpoint-{n:03d}" for n in range(98)]
    assert len(evidence) == 100
    case = _case([(LEFT, RIGHT)], evidence)
    twenty_six = [LEFT, RIGHT] + [f"id-endpoint-{n:03d}" for n in range(24)]
    assert len(twenty_six) == 26

    assert harness.is_specific(set(twenty_six), set(evidence)) is False
    assert harness.is_specific(set(twenty_six[:25]), set(evidence)) is True

    block = harness.cder(
        _claims(("INFERENCE", twenty_six)), case, set(evidence), _domain_of,
    )
    assert block["specific_recovered"] == 0
    assert block["blanket_recovered"] == 1


def test_a_hypothesis_never_recovers_a_link_however_specific() -> None:
    evidence = [LEFT, RIGHT] + [f"id-endpoint-{n:03d}" for n in range(28)]
    case = _case([(LEFT, RIGHT)], evidence)
    block = harness.cder(
        _claims(("HYPOTHESIS", [LEFT, RIGHT])), case, set(evidence), _domain_of,
    )
    assert block["specific_recovered"] == 0
    assert block["any_recovered"] == 0


def test_the_constants_are_the_pre_registered_ones() -> None:
    assert harness.SPECIFIC_MAX_FRACTION == 0.5
    assert harness.SPECIFIC_MAX_IDS == 25
    assert harness.TOOL_OUTPUT_BUDGET == 4096


# --------------------------------------------------------------------------------------
# Stage recovery and completeness
# --------------------------------------------------------------------------------------

STAGES = {
    "1-credential-guessing": ["id-identity-a", "id-identity-b"],
    "2-successful-logon": [LEFT],
    "3-remote-service-execution": [RIGHT],
    "4-discovery": ["id-endpoint-z"],
}


def test_a_stage_is_recovered_by_one_specific_claim_citing_one_of_its_ids() -> None:
    evidence = [LEFT, RIGHT, "id-identity-a", "id-identity-b", "id-endpoint-z"] + [
        f"id-endpoint-{n:03d}" for n in range(25)
    ]
    block = harness.stage_recovery(
        _claims(("FACT", [LEFT, RIGHT])), STAGES, set(evidence),
    )
    assert block["recovered"] == 2
    assert block["recovered_stages"] == ["2-successful-logon", "3-remote-service-execution"]
    assert block["missed_stages"] == ["1-credential-guessing", "4-discovery"]


def test_a_blanket_claim_recovers_no_stage() -> None:
    evidence = [LEFT, RIGHT, "id-identity-a", "id-identity-b", "id-endpoint-z"]
    block = harness.stage_recovery(_claims(("FACT", evidence)), STAGES, set(evidence))
    assert block["recovered"] == 0, (
        "a claim citing the whole case touches every stage and singles out none"
    )


def test_stage_recovery_is_unavailable_without_an_answer_key() -> None:
    block = harness.stage_recovery(_claims(("FACT", [LEFT])), None, {LEFT})
    assert block["status"].startswith("UNAVAILABLE")
    assert block["defined"] == 0


def test_completeness_is_unavailable_for_a_real_unlabelled_case() -> None:
    cder = {"specific_recovered": 0, "defined": 0}
    stages = {"recovered": 0, "defined": 0}
    assert harness.completeness(cder, stages, labelled=False)["value"] is None
    assert harness.completeness(cder, stages, labelled=True)["value"] is None


def test_completeness_counts_links_and_stages_together() -> None:
    block = harness.completeness(
        {"specific_recovered": 1, "defined": 2},
        {"recovered": 3, "defined": 4},
        labelled=True,
    )
    assert (block["numerator"], block["denominator"]) == (4, 6)
    assert block["value"] == round(4 / 6, 4)


# --------------------------------------------------------------------------------------
# Conclusions and discrimination
# --------------------------------------------------------------------------------------


def test_conclusion_scoring_agrees_with_the_incident_harness() -> None:
    """One meaning of ``must_conclude`` in this repository, not two."""
    state = InvestigationState(
        case=InvestigationCase(case_id="CASE-001", findings=())
    )
    state.claims = [
        Claim(claim_type=ClaimType.FACT, statement="The account was LOCKED out",
              agent="t", source="tool", evidence_ids=["e1"]),
        Claim(claim_type=ClaimType.INFERENCE, statement="A scheduled job ran",
              agent="t", source="t", evidence_ids=["e2"]),
    ]
    incident = Incident(
        incident_id="INC", name="n", description="d",
        telemetry=build_telemetry(), malicious_event_ids=frozenset({"e1"}),
        must_conclude=("lock", "scheduled", "absent"),
        never_as_fact=("locked", "guess"),
    )
    reference = score_labels(incident, [], {}, state)
    ours = harness.conclusion_scores(
        state.to_dict(), incident.must_conclude, incident.never_as_fact,
    )
    assert tuple(ours["conclusions_hit"]) == reference.conclusions_hit
    assert tuple(ours["conclusions_missed"]) == reference.conclusions_missed
    assert tuple(ours["overclaimed_as_fact"]) == reference.overclaimed_as_fact


def test_a_benign_case_is_discriminated_only_when_both_halves_hold() -> None:
    must, never = ["lock", "unlock"], ["guess", "brute"]

    reached = harness.conclusion_scores(
        _claims(("INFERENCE", []))
        | {"claims": [
            {"type": "INFERENCE", "statement": "the account was locked and unlocked",
             "evidence_ids": []},
        ]},
        must, never,
    )
    assert harness.discrimination(reached, "benign")["discriminated"] is True

    also_overclaims = harness.conclusion_scores(
        {"claims": [
            {"type": "INFERENCE", "statement": "the account was locked and unlocked",
             "evidence_ids": []},
            {"type": "FACT", "statement": "the password was guessed",
             "evidence_ids": []},
        ]},
        must, never,
    )
    result = harness.discrimination(also_overclaims, "benign")
    assert result["discriminated"] is False
    assert result["malicious_reading_as_fact"] == ["guess"]

    silent = harness.conclusion_scores(
        {"claims": [{"type": "FACT", "statement": "a shell started", "evidence_ids": []}]},
        must, never,
    )
    assert harness.discrimination(silent, "benign")["discriminated"] is False


def test_discrimination_is_not_defined_for_a_malicious_case() -> None:
    conclusions = harness.conclusion_scores({"claims": []}, ["ADMIN$"], [])
    assert harness.discrimination(conclusions, "malicious")["discriminated"] is None


# --------------------------------------------------------------------------------------
# The pre-registered substrings
# --------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def substrings() -> dict:
    return json.loads(
        harness.RUBRIC_SUBSTRINGS_PATH.read_text(encoding="utf-8")
    )


def test_the_substrings_cover_all_nine_cases(substrings) -> None:
    assert sorted(substrings["cases"]) == sorted(CASE_KEYS)
    assert len(CASE_KEYS) == 9


def test_every_substring_appears_in_that_case_s_rubric_text(substrings) -> None:
    """The provenance rule. A substring that is not in the rubric was not derived from it."""
    rubrics = {
        f"{c['corpus']}/{c['case_id']}": harness.rubric_text(c["rubric"]).lower()
        for c in MANIFEST["cases"]
    }
    for key, case in substrings["cases"].items():
        for phrase in case["must_conclude"]:
            assert phrase.lower() in rubrics[key], (key, phrase)


def test_the_committed_substrings_are_what_the_manifest_derives_today(substrings) -> None:
    assert harness.substrings_drift(substrings, MANIFEST) == []


def test_the_benign_cases_carry_the_pre_registered_explanation(substrings) -> None:
    l1 = substrings["cases"]["dedale_injected:L1/CASE-001"]
    l2 = substrings["cases"]["dedale_injected:L2/CASE-001"]
    assert {"lock", "unlock"} <= set(l1["must_conclude"])
    assert {"scheduled", "backup", "stale"} <= set(l2["must_conclude"])
    for case in (l1, l2):
        assert case["never_as_fact"] == sorted(harness.MALICIOUS_READING)


def test_no_malicious_or_unlabelled_case_forbids_a_reading(substrings) -> None:
    """On a malicious case the malicious reading is the correct one; on an unlabelled
    one there is no answer key to be wrong about."""
    for key, case in substrings["cases"].items():
        if case["verdict"] != "benign":
            assert case["never_as_fact"] == [], key


def test_the_rubric_text_excludes_the_verdict_and_the_provenance() -> None:
    assert "verdict" not in harness.RUBRIC_TEXT_FIELDS
    assert "stages_source" not in harness.RUBRIC_TEXT_FIELDS
    for case in MANIFEST["cases"]:
        text = harness.rubric_text(case["rubric"])
        assert case["rubric"]["stages_source"] not in text


def test_a_run_is_refused_when_the_substrings_are_missing(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as excinfo:
        harness.read_substrings(tmp_path / "nothing.json")
    assert "pre-registered" in str(excinfo.value)


def test_a_run_is_refused_when_the_substrings_were_edited(substrings) -> None:
    tampered = json.loads(json.dumps(substrings))
    tampered["cases"]["dedale_injected:L1/CASE-001"]["must_conclude"] = ["whatever"]
    drift = harness.substrings_drift(tampered, MANIFEST)
    assert drift and "must_conclude" in drift[0]


# --------------------------------------------------------------------------------------
# The grader: three constructed arm files, no prose anywhere in them
# --------------------------------------------------------------------------------------


def _scored_row(
    key: str,
    *,
    completeness: float = 0.0,
    cross_domain: int = 0,
    tokens: int | None = None,
    wall: float = 1.0,
    duplicates: int = 0,
    new_evidence: int = 0,
    ucc_signatures: tuple[str, ...] = (),
    specific_links: int = 0,
    discriminated=None,
    degraded: bool = False,
    evidence_correctness: float = 1.0,
    rejected: int = 0,
) -> dict:
    return {
        "case": key,
        "labelled_corpus": not key.startswith("flaws_cloud"),
        "m19": {"evidence_correctness": evidence_correctness, "rejected_claims": rejected},
        "cder": {"specific_recovered": specific_links, "defined": 2},
        "stages": {"recovered": 0, "defined": 4},
        "completeness_h1": {"value": completeness},
        "conclusions": {},
        "discrimination": {"discriminated": discriminated},
        "cross_domain_claims_specific": {"count": cross_domain},
        "ucc": {"unique_and_matters": len(ucc_signatures)},
        "ucc_entries": [
            {"signature": signature, "matters": ["verdict"]}
            for signature in ucc_signatures
        ],
        "new_evidence_vs_arm_A": {
            "hypotheses_citing_evidence_A_claims_did_not": new_evidence,
            "hypotheses_citing_evidence_A_never_touched": new_evidence,
        },
        "planner": {"chosen_by_model": 0, "multi_candidate_steps": 2},
        "duplicate_tool_calls": {"duplicate_calls": duplicates},
        "context": {},
        "cost": {"tokens": tokens, "wall_seconds": wall, "model_calls": 0},
        "reliability": {"degraded": degraded},
    }


def _write_scores(directory: Path, letter: str, rows: list[dict]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"scores_{letter}.json").write_text(
        json.dumps({"arm": letter, "cases": rows}, indent=1), encoding="utf-8",
    )


def _grade(directory: Path) -> dict:
    assert harness.main([
        "grade", "--out-dir", str(directory),
        "--manifest-dir", str(ROOT / "reports" / "m19b"),
    ]) == 0
    return json.loads((directory / "GRADING.json").read_text(encoding="utf-8"))


def test_the_grader_selects_keep_crew_when_c_wins_everywhere(tmp_path: Path) -> None:
    a = [_scored_row(k) for k in CASE_KEYS]
    b = [_scored_row(k, completeness=0.1, tokens=100, ucc_signatures=()) for k in CASE_KEYS]
    c = [
        _scored_row(k, completeness=0.9, tokens=10, specific_links=2,
                    ucc_signatures=(f"sig-C-{k}",))
        for k in CASE_KEYS
    ]
    _write_scores(tmp_path, "A", a)
    _write_scores(tmp_path, "B", b)
    _write_scores(tmp_path, "C", c)

    grading = _grade(tmp_path)

    assert grading["hypotheses"]["H1"]["holds"] is True
    assert grading["hypotheses"]["H6"]["holds"] is True
    assert "KEEP CREW AS DEFAULT" in grading["decision_rule"]["selected"]
    assert "SIMPLIFY" not in grading["decision_rule"]["outcome"]


def test_the_grader_selects_hybrid_on_three_ucc_wins_with_the_trigger(tmp_path: Path) -> None:
    a = [_scored_row(k) for k in CASE_KEYS]
    b = [_scored_row(k, completeness=0.5, tokens=100) for k in CASE_KEYS]
    c = [
        _scored_row(
            k, completeness=0.1, tokens=10,
            ucc_signatures=(f"sig-C-{k}",) if index < 3 else (),
            specific_links=2 if index < 3 else 0,
        )
        for index, k in enumerate(CASE_KEYS)
    ]
    _write_scores(tmp_path, "A", a)
    _write_scores(tmp_path, "B", b)
    _write_scores(tmp_path, "C", c)

    grading = _grade(tmp_path)
    decision = grading["decision_rule"]

    assert grading["hypotheses"]["H1"]["holds"] is False
    assert len(decision["ucc_C_gt_B_cases"]) == 3
    assert all(decision["multi_domain_trigger"].values())
    assert "HYBRID (deterministic -> single LLM -> crew on multi-domain trigger)" in (
        decision["selected"]
    )
    assert "KEEP CREW AS DEFAULT" not in decision["selected"]


def test_the_grader_selects_single_llm_when_b_carries_the_advantage(tmp_path: Path) -> None:
    a = [_scored_row(k) for k in CASE_KEYS]
    b = [
        _scored_row(k, completeness=0.9, tokens=1000, new_evidence=2, specific_links=2,
                    ucc_signatures=(f"sig-B-{k}",))
        for k in CASE_KEYS
    ]
    c = [_scored_row(k, completeness=0.1, tokens=100) for k in CASE_KEYS]
    _write_scores(tmp_path, "A", a)
    _write_scores(tmp_path, "B", b)
    _write_scores(tmp_path, "C", c)

    grading = _grade(tmp_path)
    decision = grading["decision_rule"]

    assert grading["hypotheses"]["H5"]["holds"] is True
    assert "SINGLE LLM DEFAULT" in decision["selected"]
    assert decision["simplify_or_remove_crew"]["added"] is True, (
        "C contributed no link, UCC or discrimination arm A did not, on every case"
    )
    assert "SIMPLIFY / REMOVE CREW" in decision["outcome"]


def test_the_grader_selects_deterministic_when_no_model_arm_adds_anything(tmp_path: Path) -> None:
    a = [_scored_row(k, specific_links=1) for k in CASE_KEYS]
    b = [_scored_row(k, specific_links=1, tokens=1000) for k in CASE_KEYS]
    c = [_scored_row(k, specific_links=1, tokens=100) for k in CASE_KEYS]
    _write_scores(tmp_path, "A", a)
    _write_scores(tmp_path, "B", b)
    _write_scores(tmp_path, "C", c)

    grading = _grade(tmp_path)
    decision = grading["decision_rule"]

    assert decision["adds_over_arm_A"] == {"B": [], "C": []}
    assert "DETERMINISTIC DEFAULT + OPTIONAL LLM" in decision["selected"]
    assert "SIMPLIFY / REMOVE CREW" in decision["outcome"]


def test_the_grader_can_select_no_branch_at_all(tmp_path: Path) -> None:
    """Neither arm dominates and both add something: the rule declines to answer."""
    a = [_scored_row(k) for k in CASE_KEYS]
    b = [
        _scored_row(k, completeness=0.5, tokens=1000, specific_links=1,
                    ucc_signatures=(f"sig-B-{k}",))
        for k in CASE_KEYS
    ]
    c = [
        _scored_row(k, completeness=0.5, tokens=1000, specific_links=1,
                    ucc_signatures=(f"sig-C-{k}",))
        for k in CASE_KEYS
    ]
    _write_scores(tmp_path, "A", a)
    _write_scores(tmp_path, "B", b)
    _write_scores(tmp_path, "C", c)

    grading = _grade(tmp_path)
    decision = grading["decision_rule"]

    assert decision["selected"] == []
    assert decision["outcome"].startswith("NO BRANCH SELECTED")


def test_h6_disqualifies_an_arm_that_fabricated_a_citation(tmp_path: Path) -> None:
    a = [_scored_row(k) for k in CASE_KEYS]
    b = [_scored_row(k, tokens=100) for k in CASE_KEYS]
    c = [_scored_row(k, tokens=10) for k in CASE_KEYS]
    c[0] = _scored_row(CASE_KEYS[0], tokens=10, evidence_correctness=0.9, rejected=1)
    _write_scores(tmp_path, "A", a)
    _write_scores(tmp_path, "B", b)
    _write_scores(tmp_path, "C", c)

    grading = _grade(tmp_path)

    assert grading["hypotheses"]["H6"]["holds"] is False
    assert grading["hypotheses"]["H6"]["per_arm"][ARM_C]["holds"] is False
    assert "KEEP CREW AS DEFAULT" not in grading["decision_rule"]["selected"]


def test_h3_and_h4_read_only_numbers(tmp_path: Path) -> None:
    a = [_scored_row(k) for k in CASE_KEYS]
    b = [_scored_row(k, tokens=1000, wall=10.0, duplicates=0) for k in CASE_KEYS]
    c = [_scored_row(k, tokens=400, wall=20.0, duplicates=3) for k in CASE_KEYS]
    _write_scores(tmp_path, "A", a)
    _write_scores(tmp_path, "B", b)
    _write_scores(tmp_path, "C", c)

    grading = _grade(tmp_path)["hypotheses"]

    assert grading["H3"]["median_tokens_B"] == 1000
    assert grading["H3"]["median_tokens_C"] == 400
    assert grading["H3"]["holds"] is True
    assert grading["H4"]["duplication"]["holds"] is True
    assert grading["H4"]["latency"]["holds"] is True


def test_the_grader_refuses_an_incomplete_comparison(tmp_path: Path) -> None:
    _write_scores(tmp_path, "A", [_scored_row(k) for k in CASE_KEYS])
    with pytest.raises(SystemExit) as excinfo:
        harness.main([
            "grade", "--out-dir", str(tmp_path),
            "--manifest-dir", str(ROOT / "reports" / "m19b"),
        ])
    assert "compare arms" in str(excinfo.value)


def test_a_partial_grading_selects_no_branch_at_all(tmp_path: Path) -> None:
    """Every branch of section 5 compares B with C. With one missing there is no input,
    and a rule that answered anyway would let a half-run experiment pick an outcome."""
    _write_scores(tmp_path, "A", [_scored_row(k) for k in CASE_KEYS])
    assert harness.main([
        "grade", "--out-dir", str(tmp_path), "--partial",
        "--manifest-dir", str(ROOT / "reports" / "m19b"),
    ]) == 0
    decision = json.loads(
        (tmp_path / "GRADING.json").read_text(encoding="utf-8")
    )["decision_rule"]
    assert decision["comparable"] is False
    assert decision["selected"] == []
    assert decision["outcome"].startswith("UNAVAILABLE")
    assert all(b["numbers"].startswith("UNAVAILABLE") for b in decision["branches"])
    assert decision["simplify_or_remove_crew"]["added"] is False


def test_uniqueness_is_decided_across_the_arms_that_ran(tmp_path: Path) -> None:
    """A contribution both model arms produced is unique to neither."""
    shared = ("sig-shared",)
    by_arm = {
        "B": {k: _scored_row(k, ucc_signatures=shared) for k in CASE_KEYS},
        "C": {k: _scored_row(k, ucc_signatures=shared) for k in CASE_KEYS},
    }
    counts = harness.recompute_ucc(by_arm)
    assert set(counts["B"].values()) == {0}
    assert set(counts["C"].values()) == {0}

    by_arm["C"] = {k: _scored_row(k, ucc_signatures=("sig-C",)) for k in CASE_KEYS}
    counts = harness.recompute_ucc(by_arm)
    assert set(counts["C"].values()) == {1}
    assert set(counts["B"].values()) == {1}


# --------------------------------------------------------------------------------------
# The request observer, end to end, without a key
# --------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def corpus() -> Telemetry:
    from ath.telemetry.k8s_audit_source import K8sAuditSource

    tables = K8sAuditSource(
        ROOT / "tests" / "fixtures" / "k8s_audit", cluster="test-cluster",
    ).load().tables
    return Telemetry(
        processes=tables["process"], network=tables["network"],
        logons=tables["logon"], controls=tables["control"],
    )


@pytest.fixture(scope="module")
def pipeline(corpus):
    from ath.environment import build_environment_model
    from ath.triage import assess_findings, set_aside_ids

    hunt = run_hunt(corpus)
    environment = build_environment_model(corpus)
    assessments = assess_findings(hunt.findings, environment)
    cases = correlate(hunt.findings, corpus, set_aside=set_aside_ids(assessments))
    assert cases
    return list(hunt.findings), list(cases), environment


def test_the_observer_records_request_bytes_on_a_scripted_run(corpus, pipeline) -> None:
    """The M19b arm B, bound and all, records what each request weighed.

    Checked against ``build_request_body`` over the prompts the orchestrator actually
    assembled, so this fails if the recorded number stops being the number that would go
    on the wire -- which is what the whole context-size column rests on.
    """
    findings, cases, environment = pipeline
    manifest = build_manifest("fixture", corpus, cases, selection="every case")
    client = ScriptedLLM(responses=['{"claims": []}'] * 12, name="scripted-harness")

    rows = run_arm(
        harness.m19b_arm("B"), manifest, corpus, cases, findings=findings,
        environment=environment, llm=client, scripted=True,
    )

    requests = rows[0].to_dict()["state"]["llm"]["requests"]
    assert requests, "a scripted model arm sent requests and must have recorded them"
    expected = [
        len(encode_request_body(build_request_body(
            model=client.name, max_tokens=8192, system=system, prompt=prompt,
        )))
        for system, prompt in client.calls[: len(requests)]
    ]
    assert [r["request_bytes"] for r in requests] == expected
    assert rows[0].context["largest_request_bytes"] == max(expected)
    assert rows[0].footing["tool_call_cap"] == harness.TOOL_CALL_CAP


def test_the_scripted_row_cannot_be_aggregated_into_the_arm_it_imitates(corpus, pipeline):
    findings, cases, environment = pipeline
    manifest = build_manifest("fixture", corpus, cases, selection="every case")
    rows = run_arm(
        harness.m19b_arm("C"), manifest, corpus, cases, findings=findings,
        environment=environment,
        llm=ScriptedLLM(responses=['{"claims": []}'] * 12), scripted=True,
    )
    assert rows[0].labelled_arm.startswith(f"{ARM_C}_SCRIPTED")


# --------------------------------------------------------------------------------------
# reports/m19/ is never written, and T5c's baseline is never rewritten
# --------------------------------------------------------------------------------------


def test_every_output_path_lives_outside_reports_m19() -> None:
    paths = [
        harness.ABLATION_DIR / "ENVIRONMENT.json",
        harness.ABLATION_DIR / "ENVIRONMENT.md",
        harness.RUBRIC_SUBSTRINGS_PATH,
        harness.ORACLE_PATH,
        harness.GRADING_JSON,
        harness.GRADING_MD,
        harness.arm_path(harness.ABLATION_DIR, "A", 1),
        harness.arm_path(harness.ABLATION_DIR, "C"),
        harness.ABLATION_DIR / "scores_B.json",
    ]
    frozen = M19_DIR.resolve()
    for path in paths:
        assert frozen not in path.resolve().parents, path
        assert "m19b" in str(path).replace("\\", "/")


@pytest.mark.parametrize(
    "path",
    [
        M19_DIR / "arm_B.json",
        M19_DIR / "GRADING.json",
        ROOT / "reports" / "m19" / "anything.txt",
        ROOT / "reports" / "m19b" / ".." / "m19" / "sneaky.json",
    ],
)
def test_a_write_under_reports_m19_is_refused_by_path(path) -> None:
    with pytest.raises(SystemExit) as excinfo:
        harness.guarded(path)
    assert "reports/m19/" in str(excinfo.value)


def test_the_committed_arm_a_baseline_is_never_rewritten() -> None:
    with pytest.raises(SystemExit) as excinfo:
        harness.guarded(harness.ABLATION_DIR / "arm_A.json")
    assert "committed M19b artifact" in str(excinfo.value)
    assert harness.guarded(harness.ABLATION_DIR / "arm_A_rep1.json")


def test_the_refusal_leaves_the_frozen_artifacts_untouched() -> None:
    for target in (M19_DIR / "GRADING.json", harness.ABLATION_DIR / "arm_A.json"):
        before = target.read_bytes()
        with pytest.raises(SystemExit):
            harness.write_artifact(harness.guarded(target), {"clobbered": True})
        assert target.read_bytes() == before


# --------------------------------------------------------------------------------------
# The arm A reproduction assertion
# --------------------------------------------------------------------------------------


def test_the_reproduction_comparison_excludes_only_time_and_the_t6_fields() -> None:
    assert set(harness.T6_ROW_FIELDS) == {"footing", "context"}
    committed = json.loads(
        (harness.ABLATION_DIR / "arm_A.json").read_text(encoding="utf-8")
    )["cases"][0]
    rebuilt = harness.result_from_row(committed)
    assert rebuilt.corpus == committed["corpus"]
    assert rebuilt.scores.to_dict() == committed["scores"]
    assert harness.reproduction_differences([rebuilt], [committed]) == []


def test_a_moved_claim_is_reported_rather_than_absorbed() -> None:
    committed = json.loads(
        (harness.ABLATION_DIR / "arm_A.json").read_text(encoding="utf-8")
    )["cases"][0]
    moved = json.loads(json.dumps(committed))
    moved["state"]["claims"][0]["statement"] = "something else"
    differences = harness.reproduction_differences(
        [harness.result_from_row(moved)], [committed],
    )
    assert differences and "state" in differences[0]
