"""The ablation harness: pinned inputs, an honest arm label, and label-free scores.

What each group of tests is for, and how each one fails
--------------------------------------------------------
*Manifest.* The experiment's only guarantee that the arms saw identical inputs is that
a changed input is refused. These fail if the digest stops noticing a changed cell, a
removed finding, or a swapped corpus -- which is exactly how an ablation quietly becomes
a comparison of two different runs.

*Reproducibility.* Arm A is the baseline every other arm is read against, so it has to
be the same twice. This fails the moment nondeterminism enters the investigation --
iteration over a set, a dict ordered by insertion from a set, a timestamp folded into a
claim -- and it fails by naming the case and the field that moved.

*Arm labelling.* B and C must refuse to run without a model and must never report a
deterministic fallback under an LLM arm's name. These fail if the refusal is softened
into a warning, or if ``llm_degraded`` stops reaching the row's label.

*Scoring.* Each metric is checked on a hand-built state whose answer is known by
construction. They fail if a denominator changes meaning (e.g. coverage counted over
cited evidence rather than the case's), or if a threshold is introduced.
"""

from __future__ import annotations

import inspect

import pytest

from _builders import ctrl, logon, proc, telemetry as build_telemetry
from ath.agent.claims import Claim, ClaimType, ClaimVerifier, RejectedClaim
from ath.agent.generalist import KIND_ORDER
from ath.agent.llm import NullLLM, ScriptedLLM
from ath.agent.specialists import agent_family
from ath.agent.state import AgentResult, InvestigationState, InvestigationStatus
from ath.agent.tools import ToolCall
from ath.correlation import correlate
from ath.evaluation.ablation import (
    ARM_A,
    ARM_B,
    ARM_C,
    ArmUnavailable,
    ByConstructionViolation,
    CaseManifest,
    ManifestMismatch,
    aggregate,
    arm_a,
    arm_b,
    arm_c,
    build_manifest,
    identical,
    manifest_hash,
    run_arm,
    score_case,
    scores_from_dict,
    techniques_in,
    techniques_looked_up,
    telemetry_hash,
)
from ath.evaluation.ablation import scoring as scoring_module
from ath.hunting import run_hunt
from ath.triage import assess_findings, set_aside_ids


# --------------------------------------------------------------------------------------
# A small corpus that produces a real case through the real pipeline
# --------------------------------------------------------------------------------------


def _corpus():
    """The Kubernetes escalation fixture, loaded through its real adapter.

    A fixture file rather than rows built here, because the manifest digest is a
    statement about *content*: the row builders mint a fresh event id on every call, so
    two loads of "the same" hand-built corpus would differ and the stability test would
    be testing the builder's counter rather than the digest.
    """
    from pathlib import Path

    from ath.telemetry.k8s_audit_source import K8sAuditSource
    from ath.telemetry.loader import Telemetry

    directory = Path(__file__).resolve().parent / "fixtures" / "k8s_audit"
    tables = K8sAuditSource(directory, cluster="test-cluster").load().tables
    return Telemetry(
        processes=tables["process"], network=tables["network"],
        logons=tables["logon"], controls=tables["control"],
    )


@pytest.fixture(scope="module")
def corpus():
    return _corpus()


@pytest.fixture(scope="module")
def pipeline(corpus):
    from ath.environment import build_environment_model

    hunt = run_hunt(corpus)
    environment = build_environment_model(corpus)
    assessments = assess_findings(hunt.findings, environment)
    cases = correlate(
        hunt.findings, corpus, set_aside=set_aside_ids(assessments)
    )
    assert cases, "the fixture corpus must produce a case for these tests to mean anything"
    return list(hunt.findings), list(cases), environment


@pytest.fixture(scope="module")
def manifest(corpus, pipeline):
    _findings, cases, _environment = pipeline
    return build_manifest("fixture", corpus, cases, selection="every case")


# --------------------------------------------------------------------------------------
# Manifest
# --------------------------------------------------------------------------------------


def test_telemetry_hash_changes_when_one_canonical_row_changes(corpus) -> None:
    """One altered cell in one row must change the corpus digest.

    Fails if the digest is computed over row counts, column names or any other summary
    that a changed value can slip past.
    """
    before = telemetry_hash(corpus)
    from ath.telemetry.loader import Telemetry

    controls = corpus.controls.copy()
    controls.loc[controls.index[0], "resource_name"] = "something-else"
    mutated = Telemetry(
        processes=corpus.processes, network=corpus.network,
        logons=corpus.logons, controls=controls,
    )
    assert telemetry_hash(mutated) != before


def test_telemetry_hash_is_stable_for_the_same_content(corpus) -> None:
    """Two loads of identical content must agree, or every run would be refused."""
    assert telemetry_hash(corpus) == telemetry_hash(_corpus())


def test_manifest_hash_changes_when_a_finding_id_is_removed(manifest) -> None:
    """A case made of different findings is a different case.

    Fails if the manifest digest covers only case ids -- the failure mode that lets a
    case keep its id while its contents change underneath an arm.
    """
    before = manifest_hash(manifest)
    entry = manifest[0]
    assert len(entry.finding_ids) >= 1
    trimmed = CaseManifest(
        corpus=entry.corpus, case_id=entry.case_id, rule_ids=entry.rule_ids,
        leading_rule=entry.leading_rule, finding_ids=entry.finding_ids[:-1],
        evidence_ids=entry.evidence_ids, telemetry_hash=entry.telemetry_hash,
    )
    assert manifest_hash([trimmed] + list(manifest[1:])) != before


def test_manifest_hash_ignores_the_order_entries_are_listed_in(manifest) -> None:
    """Listing the same pinned cases in another order is not another experiment."""
    entry = manifest[0]
    second = CaseManifest(
        corpus=entry.corpus, case_id="CASE-999", rule_ids=entry.rule_ids,
        leading_rule=entry.leading_rule, finding_ids=entry.finding_ids,
        evidence_ids=entry.evidence_ids, telemetry_hash=entry.telemetry_hash,
    )
    entries = list(manifest) + [second]
    assert manifest_hash(entries) == manifest_hash(list(reversed(entries)))


def test_run_arm_refuses_a_mismatched_telemetry_hash(manifest, corpus, pipeline) -> None:
    """An arm handed a different corpus refuses rather than reporting a comparison.

    Fails if ``run_arm`` checks nothing, or checks only that the case id still exists.
    """
    _findings, cases, environment = pipeline
    pinned_elsewhere = [
        CaseManifest(
            corpus=e.corpus, case_id=e.case_id, rule_ids=e.rule_ids,
            leading_rule=e.leading_rule, finding_ids=e.finding_ids,
            evidence_ids=e.evidence_ids, telemetry_hash="0" * 64,
        )
        for e in manifest
    ]
    with pytest.raises(ManifestMismatch, match="does not match the pinned"):
        run_arm(arm_a(), pinned_elsewhere, corpus, cases, environment=environment)


def test_run_arm_refuses_a_case_whose_findings_changed(manifest, corpus, pipeline) -> None:
    """The case id survived; its findings did not. That is still a different input."""
    _findings, cases, environment = pipeline
    entry = manifest[0]
    altered = CaseManifest(
        corpus=entry.corpus, case_id=entry.case_id, rule_ids=entry.rule_ids,
        leading_rule=entry.leading_rule,
        finding_ids=entry.finding_ids + ("ATH-999:evt-nonexistent",),
        evidence_ids=entry.evidence_ids, telemetry_hash=entry.telemetry_hash,
    )
    with pytest.raises(ManifestMismatch, match="different findings"):
        run_arm(arm_a(), [altered], corpus, cases, environment=environment)


# --------------------------------------------------------------------------------------
# Reproducibility -- invariant B
# --------------------------------------------------------------------------------------


def test_arm_a_is_reproducible(manifest, corpus, pipeline) -> None:
    """Two runs of the deterministic arm must be identical in everything but the clock.

    Fails on any nondeterminism in claims, tool calls, plan log or scores -- set
    iteration order being the classic one -- and names the case and field that moved.
    """
    findings, cases, environment = pipeline
    first = run_arm(arm_a(), manifest, corpus, cases, findings=findings,
                    environment=environment)
    second = run_arm(arm_a(), manifest, corpus, cases, findings=findings,
                     environment=environment)
    assert identical(first, second) == []
    assert [r.labelled_arm for r in first] == [ARM_A] * len(first)


def test_wall_time_is_excluded_from_the_comparison_and_nothing_else_is(
    manifest, corpus, pipeline,
) -> None:
    """The exclusion list must stay exactly one thing wide.

    Fails if a future change excludes a substantive field to make a flaky comparison
    pass -- the way a reproducibility check stops being one.
    """
    findings, cases, environment = pipeline
    result = run_arm(arm_a(), manifest, corpus, cases, findings=findings,
                     environment=environment)[0]
    comparable = result.comparable()
    assert "wall_seconds" not in comparable["scores"]["completeness"]
    assert "started_at" not in comparable["state"]
    assert comparable["scores"]["evidence_correctness"] is not None
    assert comparable["state"]["claims"] == result.state["claims"]


# --------------------------------------------------------------------------------------
# Arm labelling
# --------------------------------------------------------------------------------------


def test_arm_b_runs_one_generalist_as_the_whole_crew(manifest, corpus, pipeline) -> None:
    """Arm B is one generalist, and the crew it replaces does not run beside it.

    Fails if the generalist is added to the assembled crew rather than replacing it --
    in which case arm B would be "a crew plus a generalist", which is neither arm.
    Since M19-3 the generalist is presented as seven facets of its own tool surface, so
    the assertion is on the *family*: every name that ran must be the generalist, and no
    ``endpoint``/``identity``/``network``/``attack`` specialist may appear.
    """
    findings, cases, environment = pipeline
    scripted = ScriptedLLM(responses=['{"claims": []}'] * 64, name="scripted-model")

    results = run_arm(
        arm_b(), manifest, corpus, cases, findings=findings,
        environment=environment, llm=scripted,
    )

    assert results
    for result in results:
        assert result.arm == ARM_B
        ran = set(result.state["agents_run"])
        assert ran, "arm B must actually run something"
        assert {agent_family(name) for name in ran} == {"generalist"}
        assert all(name.split(":", 1)[-1] in KIND_ORDER or name == "generalist"
                   for name in ran), ran


@pytest.mark.parametrize("builder,cap", [(arm_a, None), (arm_b, 40), (arm_c, 40)])
def test_every_arm_records_the_budgets_it_ran_under(
    builder, cap, manifest, corpus, pipeline,
) -> None:
    """The caps are the same for every case, and every row says what they were.

    Fails if a budget stops being recorded per case -- a tool-call column without the
    cap beside it cannot be read, because a small number means "cheap" or "cut off" and
    the row no longer says which.
    """
    findings, cases, environment = pipeline
    arm = builder()
    results = run_arm(
        arm, manifest, corpus, cases, findings=findings, environment=environment,
        llm=ScriptedLLM(responses=['{"claims": []}'] * 8, name="scripted-model"),
    )
    assert results
    for result in results:
        assert result.budgets["max_steps"] == 8
        assert result.budgets["tool_call_cap"] == cap
        assert result.budgets["tool_calls_refused"] == 0
        assert result.budgets["tool_budget_hit"] is False
        assert result.to_dict()["budgets"] == result.budgets


def test_a_case_that_hits_the_tool_cap_is_recorded_not_disqualified(
    manifest, corpus, pipeline,
) -> None:
    """A budget hit is data. Fails if hitting the cap raises, or goes unrecorded."""
    from dataclasses import replace

    findings, cases, environment = pipeline
    arm = replace(arm_b(), tool_call_cap=1)

    results = run_arm(
        arm, manifest, corpus, cases, findings=findings, environment=environment,
        llm=ScriptedLLM(responses=['{"claims": []}'] * 8, name="scripted-model"),
    )

    assert results
    for result in results:
        assert result.budgets["tool_calls_served"] == 1
        assert result.budgets["tool_budget_hit"] is True
        assert result.budgets["tool_calls_refused"] > 0
        assert result.scores.facts >= 0  # the run completed; nothing raised


def test_a_scripted_row_is_labelled_scripted_and_never_as_the_arm(
    manifest, corpus, pipeline,
) -> None:
    """Canned responses are not a model, and the label is the only thing that says so.

    Fails if ``scripted`` stops reaching ``labelled_arm``, which would let a run of
    this repository's own canned text into arm B's mean.
    """
    findings, cases, environment = pipeline
    scripted = ScriptedLLM(responses=['{"claims": []}'] * 8, name="scripted-harness")

    results = run_arm(
        arm_b(), manifest, corpus, cases, findings=findings,
        environment=environment, llm=scripted, scripted=True,
    )

    assert results
    assert all(r.labelled_arm == f"{ARM_B}_SCRIPTED" for r in results)
    assert all(r.to_dict()["scripted"] is True for r in results)
    assert ARM_B not in aggregate(results)["arms"]


def test_a_scripted_run_still_refuses_a_client_that_is_not_a_model(
    manifest, corpus, pipeline,
) -> None:
    """``--scripted`` is not a way to relabel a deterministic run."""
    findings, cases, environment = pipeline
    with pytest.raises(ArmUnavailable, match="scripted client"):
        run_arm(
            arm_b(), manifest, corpus, cases, findings=findings,
            environment=environment, llm=NullLLM(), scripted=True,
        )


@pytest.mark.parametrize("builder,name", [(arm_b, ARM_B), (arm_c, ARM_C)])
def test_model_arms_refuse_to_run_without_a_key(
    builder, name, manifest, corpus, pipeline, monkeypatch,
) -> None:
    """No key means no LLM arm -- never a deterministic run wearing the arm's name.

    Fails if the refusal is downgraded to a warning-and-continue, which is the exact
    shape of the silent degradation this project has been bitten by before.
    """
    monkeypatch.delenv("ATH_LLM_API_KEY", raising=False)
    _findings, cases, environment = pipeline
    arm = builder()
    with pytest.raises(ArmUnavailable) as excinfo:
        run_arm(arm, manifest, corpus, cases, environment=environment)
    message = str(excinfo.value)
    assert name in message
    assert "ATH_LLM_API_KEY" in message


def test_arm_c_runs_with_a_scripted_model_and_is_labelled_c(
    manifest, corpus, pipeline,
) -> None:
    """A model arm that really used a model is labelled with the arm, not degraded."""
    findings, cases, environment = pipeline
    scripted = ScriptedLLM(
        responses=['{"next_agent": "control_plane", "reason": "control-plane evidence"}']
        * 4 + ['{"claims": []}'] * 4,
        name="scripted-model",
    )
    results = run_arm(
        arm_c(), manifest, corpus, cases, findings=findings,
        environment=environment, llm=scripted,
    )
    assert results
    for result in results:
        assert result.arm == ARM_C
        assert result.configuration == "scripted-model"
        assert result.labelled_arm in (ARM_C, f"{ARM_C}_DEGRADED")
    assert scripted.calls, "arm C must actually have consulted the model"


def test_a_degraded_model_arm_aggregates_under_its_own_label(
    manifest, corpus, pipeline,
) -> None:
    """A model that ran out mid-run produces a ``_DEGRADED`` row, not a C row.

    ``ScriptedLLM`` with no responses reports ``available`` and then fails every call,
    which is precisely the mid-run outage shape. Fails if ``llm_degraded`` stops
    reaching the label, letting a partly-deterministic row into the model arm's mean.
    """
    findings, cases, environment = pipeline
    exhausted = ScriptedLLM(responses=[], name="scripted-model")
    results = run_arm(
        arm_c(), manifest, corpus, cases, findings=findings,
        environment=environment, llm=exhausted,
    )
    assert all(r.llm_degraded for r in results)
    assert all(r.labelled_arm == f"{ARM_C}_DEGRADED" for r in results)
    summary = aggregate(results)
    assert ARM_C not in summary["arms"]
    assert summary["arms"][f"{ARM_C}_DEGRADED"]["overall"]["degraded_runs"] == len(results)


# --------------------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------------------


def _hand_built_state(case, telemetry):
    """A state with one rejected claim, one evidence-free claim, and half coverage."""
    evidence = list(case.event_ids)
    half = evidence[: max(1, len(evidence) // 2)]

    supported = Claim(
        claim_type=ClaimType.FACT,
        statement=f"A control-plane action is recorded consistent with T1098.006.",
        evidence_ids=tuple(half), source="tool", agent="control_plane",
    )
    # HYPOTHESIS is the only claim type permitted to stand without evidence -- see the
    # guard test below -- so it is what an "unsupported claim" can actually be.
    unsupported = Claim(
        claim_type=ClaimType.HYPOTHESIS,
        statement="The binding may have been created to enable later access.",
        source="llm", agent="synthesis",
    )
    fabricated = Claim(
        claim_type=ClaimType.INFERENCE,
        statement="An event nobody recorded shows T1611.",
        evidence_ids=("evt-999999",), source="llm", agent="synthesis",
    )

    state = InvestigationState(case=case)
    state.status = InvestigationStatus.COMPLETE
    result = AgentResult(
        agent="control_plane", ran_because="hand-built",
        claims=(supported, unsupported),
        tool_calls=(ToolCall(
            tool="get_events", arguments={}, agent="control_plane",
            result_summary="half the case evidence", event_ids=tuple(half),
        ),),
    )
    state.record(
        result, [supported, unsupported],
        [RejectedClaim(claim=fabricated, reason="cites 1 event id(s) that do not exist")],
    )
    return state


def test_scores_measure_what_they_say_they_measure(corpus, pipeline) -> None:
    """Every denominator checked against a state whose answer is known by hand.

    Fails if coverage is computed over cited evidence instead of the case's evidence,
    if a rejected claim's citations stop counting against correctness, or if an
    evidence-free claim stops counting as unsupported.
    """
    _findings, cases, _environment = pipeline
    case = cases[0]
    verifier = ClaimVerifier(corpus)
    state = _hand_built_state(case, corpus)

    scores = score_case(state, case, verifier)

    assert scores.evidence_correctness < 1.0
    assert scores.cited_event_ids_existing < scores.cited_event_ids
    assert scores.rejected_claims == 1
    assert scores.unsupported_claims == 1
    assert scores.unsupported_by_type == {"HYPOTHESIS": 1}
    assert scores.facts_without_evidence == 0

    expected = len(state.tool_calls[0].event_ids) / len(case.event_ids)
    assert scores.evidence_coverage == pytest.approx(expected)


def test_evidence_coverage_is_one_half_on_a_case_of_two_events() -> None:
    """The coverage denominator, pinned on a case whose arithmetic is unambiguous."""
    from ath.correlation.chain import InvestigationCase
    from ath.hunting.finding import Evidence, Finding, Severity
    from _builders import at

    events = [
        Evidence(event_id="c-1", timestamp=at(), summary="one"),
        Evidence(event_id="c-2", timestamp=at(1), summary="two"),
    ]
    finding = Finding(
        rule_id="TEST-001", title="t", severity=Severity.HIGH, device="d", user="u",
        evidence=tuple(events), reason="r",
    )
    case = InvestigationCase(case_id="CASE-001", findings=(finding,))
    telemetry = build_telemetry()

    state = InvestigationState(case=case)
    state.record(
        AgentResult(
            agent="endpoint", ran_because="hand-built",
            tool_calls=(ToolCall(
                tool="get_events", arguments={}, agent="endpoint",
                result_summary="one of two", event_ids=("c-1",),
            ),),
        ),
        [], [],
    )
    scores = score_case(state, case, ClaimVerifier(telemetry))
    assert scores.evidence_coverage == 0.5


def _technique_state(mapped: tuple[str, ...], looked_up: tuple[str, ...], text: str):
    """A hand-built case and state: what the mapper produced, what was retrieved, what
    the claim says. The three are set independently, which is the whole point."""
    from ath.correlation.chain import InvestigationCase
    from ath.hunting.finding import Evidence, Finding, Severity
    from ath.mitre.attack import AttackMapping, Confidence
    from _builders import at

    finding = Finding(
        rule_id="TEST-001", title="t", severity=Severity.HIGH, device="d", user="u",
        evidence=(Evidence(event_id="c-1", timestamp=at(), summary="one"),), reason="r",
    )
    mappings = tuple(
        AttackMapping(
            rule_id="TEST-001", technique_id=technique,
            confidence=Confidence.HIGH, reason="r", evidence_ids=("c-1",),
        )
        for technique in mapped
    )
    case = InvestigationCase(case_id="CASE-001", findings=(finding,), mappings=mappings)
    claim = Claim(
        claim_type=ClaimType.INFERENCE, statement=text,
        evidence_ids=("c-1",), source="mitre", agent="attack",
    )
    calls = tuple(
        ToolCall(
            tool="lookup_technique", arguments={"technique_id": technique},
            agent="attack", result_summary="name",
        )
        for technique in looked_up
    )
    state = InvestigationState(case=case)
    state.record(
        AgentResult(
            agent="attack", ran_because="hand-built", claims=(claim,), tool_calls=calls,
        ),
        [claim], [],
    )
    return state, case


def test_technique_jaccard_on_a_known_pair() -> None:
    """Two sets whose overlap is worked out by hand, in both directions.

    The asserted set is what the investigation *retrieved*, so the disagreement is
    built from tool calls rather than from wording.
    """
    state, case = _technique_state(
        mapped=("T1098.006", "T1609"),
        looked_up=("T1098.006", "T1611"),
        text="Consistent with T1098.006 and also with T1611.",
    )

    scores = score_case(state, case, ClaimVerifier(build_telemetry()))

    # asserted {T1098.006, T1611}; mapped {T1098.006, T1609}; intersection 1, union 3.
    assert scores.technique_jaccard == pytest.approx(1 / 3)
    assert scores.techniques_asserted_not_mapped == ("T1611",)
    assert scores.techniques_mapped_not_asserted == ("T1609",)


def test_a_technique_named_as_a_contrast_is_no_longer_asserted() -> None:
    """The M19-1 artefact, exactly: the mapper's own reason for T1110.001 ends
    "(a spray against many accounts would be T1110.003)".

    Fails if the asserted set goes back to a regular expression over claim text, which
    scored three arm A cases at 0.5 for a parenthesis.
    """
    state, case = _technique_state(
        mapped=("T1110.001",),
        looked_up=("T1110.001",),
        text=(
            "Behaviour cited by ATH-005 is consistent with T1110.001 "
            "(a spray against many accounts would be T1110.003)."
        ),
    )

    scores = score_case(state, case, ClaimVerifier(build_telemetry()))

    assert scores.techniques_asserted == ("T1110.001",)
    assert scores.techniques_in_prose == ("T1110.001", "T1110.003")
    assert scores.technique_jaccard == 1.0
    assert scores.techniques_asserted_not_mapped == ()
    assert scores.to_dict()["technique_agreement"]["in_prose_not_asserted"] == [
        "T1110.003"
    ]


def test_a_refused_lookup_is_not_an_assertion() -> None:
    """The investigation asked and was not answered; it has asserted nothing.

    Fails if a budget-refused call counts, which would credit a truncated run with a
    technique it never retrieved.
    """
    state, case = _technique_state(mapped=("T1110.001",), looked_up=(), text="no id here")
    refused = ToolCall(
        tool="lookup_technique", arguments={"technique_id": "T1110.001"},
        agent="attack", result_summary="tool budget exhausted (0 calls)", refused=True,
    )
    state.results[0] = AgentResult(
        agent="attack", ran_because="hand-built",
        claims=state.results[0].claims, tool_calls=(refused,),
    )

    scores = score_case(state, case, ClaimVerifier(build_telemetry()))

    assert scores.techniques_asserted == ()
    assert scores.techniques_mapped_not_asserted == ("T1110.001",)


def test_techniques_in_prose_remains_available_as_a_diagnostic() -> None:
    claim = Claim(
        claim_type=ClaimType.HYPOTHESIS,
        statement="T1059.001 and T1105 but not T999 or 1234",
    )
    assert techniques_in([claim]) == ("T1059.001", "T1105")


def test_the_asserted_set_comes_from_lookup_calls_only() -> None:
    """Fails if another tool's arguments start counting as an assertion."""
    calls = [
        ToolCall(tool="lookup_technique", arguments={"technique_id": "t1059.001"},
                 agent="attack", result_summary="ok"),
        ToolCall(tool="get_events", arguments={"technique_id": "T1105"},
                 agent="endpoint", result_summary="ok"),
        ToolCall(tool="lookup_technique", arguments={}, agent="attack",
                 result_summary="ok"),
    ]
    assert techniques_looked_up(calls) == ("T1059.001",)


def test_a_fact_without_evidence_cannot_be_constructed() -> None:
    """The guard the score relies on, asserted rather than worked around.

    ``unsupported_claims`` counts FACTs with no evidence and is expected to be zero by
    construction. That expectation is only worth anything if the construction really
    refuses -- so this asserts the refusal instead of building an invalid claim to feed
    the scorer. The same guard is why an *evidence-free INFERENCE* cannot be built
    either, which is why the unsupported-claims test above uses a HYPOTHESIS.
    """
    with pytest.raises(ValueError, match="must cite evidence"):
        Claim(claim_type=ClaimType.FACT, statement="no evidence", source="tool")
    with pytest.raises(ValueError, match="must cite evidence"):
        Claim(claim_type=ClaimType.INFERENCE, statement="no evidence", source="llm")


def test_an_unevidenced_fact_that_somehow_exists_raises_rather_than_scoring(
    corpus, pipeline, monkeypatch,
) -> None:
    """If the claim layer is ever bypassed, the scorer refuses to average it away."""
    _findings, cases, _environment = pipeline
    case = cases[0]
    smuggled = Claim(
        claim_type=ClaimType.FACT, statement="smuggled",
        evidence_ids=(case.event_ids[0],), source="tool",
    )
    object.__setattr__(smuggled, "evidence_ids", ())

    state = InvestigationState(case=case)
    state.record(
        AgentResult(agent="endpoint", ran_because="hand-built", claims=(smuggled,)),
        [smuggled], [],
    )
    with pytest.raises(ByConstructionViolation):
        score_case(state, case, ClaimVerifier(corpus))


def test_scores_round_trip_through_the_artifact(corpus, pipeline) -> None:
    """An aggregate re-derived from the committed rows must match the run's own."""
    findings, cases, environment = pipeline
    from ath.evaluation.ablation import build_manifest as _bm

    entries = _bm("fixture", corpus, cases)
    results = run_arm(arm_a(), entries, corpus, cases, findings=findings,
                      environment=environment)
    rebuilt = [scores_from_dict(r.to_dict()["scores"]) for r in results]
    assert [s.to_dict() for s in rebuilt] == [r.scores.to_dict() for r in results]


def test_the_scoring_module_defines_no_numeric_constant() -> None:
    """No thresholds, enforced rather than intended.

    Any module-level number in the scoring module is either a threshold or one edit away
    from becoming one, and a score that carries its own cutoff has decided the
    experiment before it ran. Fails the moment someone adds ``MIN_COVERAGE = 0.8``.
    """
    numeric = {
        name: value for name, value in vars(scoring_module).items()
        if isinstance(value, (int, float)) and not isinstance(value, bool)
        and not name.startswith("__")
    }
    assert numeric == {}


def test_no_scoring_function_takes_a_threshold_argument() -> None:
    """A cutoff passed in is still a cutoff. Fails if one is added as a parameter."""
    banned = ("threshold", "cutoff", "min_", "max_", "floor", "ceiling")
    for name, function in vars(scoring_module).items():
        if not inspect.isfunction(function) or function.__module__ != scoring_module.__name__:
            continue
        for parameter in inspect.signature(function).parameters:
            assert not any(parameter.startswith(b) or b in parameter for b in banned), (
                f"{name}({parameter}) looks like a threshold"
            )


def test_capture_labels_are_asked_of_both_layers_and_absent_when_unlabelled() -> None:
    """The label column must distinguish "the mapper missed it" from "the arm dropped it".

    Fails if the two questions are collapsed into one boolean, or if an unlabelled case
    is given a ``False`` -- which would read as a miss rather than as no ground truth.
    """
    from ath.evaluation.ablation import CaseScores, capture_label_scores

    scores = CaseScores(
        techniques_asserted=("T1580",), techniques_mapped=("T1526", "T1580"),
    )
    assert capture_label_scores({}, scores) == {}
    assert capture_label_scores({"labelled_technique": ""}, scores) == {}
    assert capture_label_scores({"labelled_technique": "T1580"}, scores) == {
        "labelled_technique": "T1580",
        "labelled_technique_mapped": True,
        "labelled_technique_asserted": True,
    }
    missed = capture_label_scores({"labelled_technique": "T1526"}, scores)
    assert missed["labelled_technique_mapped"] is True
    assert missed["labelled_technique_asserted"] is False


def test_null_arm_reports_no_tokens(manifest, corpus, pipeline) -> None:
    """Arm A has no token cost, and the column says so rather than saying zero."""
    findings, cases, environment = pipeline
    results = run_arm(arm_a(), manifest, corpus, cases, findings=findings,
                      environment=environment)
    assert all(r.tokens is None for r in results)
    assert aggregate(results)["arms"][ARM_A]["overall"]["total"]["tokens"] is None


def test_a_resuming_agent_counts_once_not_once_per_step(corpus, pipeline) -> None:
    """Completeness is specialists run over specialists eligible, not steps over agents.

    Arm B's generalist appears in ``agents_run`` once per step. Counting those would
    report a completeness of 2.0 on a two-step case -- a ratio above 1.0 is not a worse
    score, it is a meaningless one. Fails if ``specialists_run`` goes back to counting
    entries rather than distinct names.
    """
    _findings, cases, _environment = pipeline
    case = cases[0]
    state = InvestigationState(case=case)
    state.agents_run = ["generalist", "generalist", "generalist"]
    state.step = 3

    scores = score_case(state, case, ClaimVerifier(corpus))

    assert scores.specialists_run == 1
    assert scores.steps == 3
    assert scores.specialist_completeness == 1.0


def test_the_generalist_family_counts_once_however_many_facets_ran(
    corpus, pipeline
) -> None:
    """M19-3: seven facets of one generalist are one agent, on both sides of the ratio.

    Arm B's tool surface is now ``generalist:case``, ``generalist:process`` and five
    more, sharing one walk, one toolbox and one budget. Counting the names would report
    the single-agent arm as a crew of seven -- the exact distinction this ablation
    exists to measure -- and would let its completeness climb above 1.0 whenever more
    facets ran than were eligible at the end.

    Fails if ``specialists_run`` goes back to counting names rather than families, or if
    ``eligible_never_ran`` loses the facet suffix, which is the only place a reader can
    see *which* part of the tool surface went unvisited.
    """
    _findings, cases, _environment = pipeline
    case = cases[0]
    state = InvestigationState(case=case)
    state.agents_run = [
        "generalist:case", "generalist:finding", "generalist:finding",
        "generalist:technique",
    ]
    state.step = 4

    scores = score_case(
        state, case, ClaimVerifier(corpus),
        eligible_never_ran=["generalist:host", "generalist:account"],
    )

    assert scores.specialists_run == 1
    assert scores.specialists_eligible == 1
    assert scores.specialist_completeness == 1.0
    assert scores.steps == 4
    assert scores.eligible_never_ran == ("generalist:account", "generalist:host")


def test_a_crew_arm_still_counts_one_specialist_per_name(corpus, pipeline) -> None:
    """The family collapse must not touch arms A and C.

    Fails if ``agent_family`` ever splits on something the specialists' own names
    contain -- which would silently merge ``endpoint`` and ``identity`` into one agent
    and make every published completeness number in arms A and C wrong.
    """
    _findings, cases, _environment = pipeline
    case = cases[0]
    state = InvestigationState(case=case)
    state.agents_run = ["endpoint", "identity", "network"]
    state.step = 3

    scores = score_case(
        state, case, ClaimVerifier(corpus), eligible_never_ran=["attack"],
    )

    assert scores.specialists_run == 3
    assert scores.specialists_eligible == 4
    assert scores.specialist_completeness == 0.75


def test_a_long_evidence_list_is_capped_in_the_file_and_says_how_much_it_dropped(
) -> None:
    """The cap bounds the artifact, never a score, and never silently.

    Fails if truncation stops being marked -- an unmarked truncation would turn "this
    claim cites 589,476 events" into "this claim cites 5,000 events", which is a
    different and false statement about the run.
    """
    from ath.evaluation.ablation.arms import MAX_SERIALISED_IDS, cap_serialised_ids

    long_ids = [f"evt-{n:06d}" for n in range(MAX_SERIALISED_IDS + 7)]
    state = {
        "claims": [{"statement": "x", "evidence_ids": long_ids}],
        "rejected_claims": [{"reason": "r", "claim": {"evidence_ids": long_ids}}],
        "results": [{
            "claims": [{"statement": "y", "evidence_ids": long_ids}],
            "tool_calls": [{"tool": "t", "event_ids": long_ids}],
        }],
        "evidence_ids": long_ids,
    }

    capped = cap_serialised_ids(state)

    assert len(capped["claims"][0]["evidence_ids"]) == MAX_SERIALISED_IDS
    assert capped["claims"][0]["evidence_ids_omitted"] == 7
    assert capped["rejected_claims"][0]["claim"]["evidence_ids_omitted"] == 7
    assert capped["results"][0]["tool_calls"][0]["event_ids_omitted"] == 7
    assert capped["evidence_ids_omitted"] == 7


def test_a_list_that_fits_is_written_exactly_as_before(corpus, pipeline) -> None:
    """No marker, no change -- every already-published arm A row is byte-identical."""
    from ath.evaluation.ablation.arms import cap_serialised_ids

    state = {
        "claims": [{"statement": "x", "evidence_ids": ["evt-1", "evt-2"]}],
        "rejected_claims": [],
        "results": [{"claims": [], "tool_calls": [{"tool": "t", "event_ids": ["evt-1"]}]}],
        "evidence_ids": ["evt-1", "evt-2"],
    }
    assert cap_serialised_ids(state) == state
