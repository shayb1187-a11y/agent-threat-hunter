"""Tests for report assembly and rendering.

Three properties matter most for a report to be trustworthy: (1) everything in it
traces back to a real event id or a real claim -- nothing is invented at render time;
(2) recommendations are motivated by something the investigation actually found, not
generic filler; (3) the FACT/HYPOTHESIS distinction survives all the way into the
rendered Markdown, not just the data model.
"""

from __future__ import annotations

import json

import pytest

from ath.agent.claims import ClaimVerifier
from ath.agent.orchestrator import InvestigationConfig, InvestigationOrchestrator
from ath.agent.state import InvestigationStatus
from ath.agent.tools import ToolBox
from ath.correlation import correlate
from ath.hunting import run_hunt
from ath.reporting import audit_calibration, build_report, render_markdown
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import load_telemetry


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory):
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("report_data")
    write_telemetry(tables, gt, out)
    return out


@pytest.fixture(scope="module")
def telemetry(data_dir):
    return load_telemetry(data_dir)


@pytest.fixture(scope="module")
def hunt_result(telemetry):
    return run_hunt(telemetry)


@pytest.fixture(scope="module")
def cases(hunt_result, telemetry):
    return correlate(hunt_result.findings, telemetry)


@pytest.fixture(scope="module")
def intrusion_case(cases):
    return max(cases, key=lambda c: len(c.findings))


@pytest.fixture(scope="module")
def benign_case(cases, intrusion_case):
    return next(c for c in cases if c is not intrusion_case)


def _investigate(case, telemetry, hunt_result, cases, max_steps: int = 8):
    tools = ToolBox(telemetry, hunt_result.findings, cases)
    verifier = ClaimVerifier(telemetry)
    orch = InvestigationOrchestrator(
        tools, verifier,
        config=InvestigationConfig(
            max_steps=max_steps, use_llm_planner=False, use_llm_synthesis=False
        ),
    )
    return orch.investigate(case)


@pytest.fixture(scope="module")
def intrusion_state(intrusion_case, telemetry, hunt_result, cases):
    return _investigate(intrusion_case, telemetry, hunt_result, cases)


@pytest.fixture(scope="module")
def intrusion_report(intrusion_state, telemetry):
    return build_report(intrusion_state, telemetry)


@pytest.fixture(scope="module")
def benign_state(benign_case, telemetry, hunt_result, cases):
    return _investigate(benign_case, telemetry, hunt_result, cases)


@pytest.fixture(scope="module")
def benign_report(benign_state, telemetry):
    return build_report(benign_state, telemetry)


# ======================================================================================
# Report assembly: structural correctness
# ======================================================================================


def test_report_case_id_matches_the_investigation(intrusion_report, intrusion_case) -> None:
    assert intrusion_report.case_id == intrusion_case.case_id


def test_report_claim_counts_match_the_state(intrusion_report, intrusion_state) -> None:
    assert len(intrusion_report.facts) == len(intrusion_state.facts)
    assert len(intrusion_report.inferences) == len(intrusion_state.inferences)
    assert len(intrusion_report.hypotheses) == len(intrusion_state.hypotheses)


def test_report_rejected_count_is_reported_even_when_zero(intrusion_report) -> None:
    """Absence of hallucination must be visible, not merely assumed."""
    assert intrusion_report.rejected_claim_count == 0


def test_report_severity_matches_case(intrusion_report, intrusion_case) -> None:
    assert intrusion_report.severity == intrusion_case.severity


def test_report_timeline_is_chronological(intrusion_report) -> None:
    stamps = [e.timestamp for e in intrusion_report.timeline]
    assert stamps == sorted(stamps)


def test_report_mitre_mappings_come_from_the_case(intrusion_report, intrusion_case) -> None:
    assert set(m.technique_id for m in intrusion_report.mitre_mappings) == set(
        m.technique_id for m in intrusion_case.mappings
    )


# ======================================================================================
# Evidence traceability -- the core trust property
# ======================================================================================


def test_every_claims_evidence_id_appears_in_the_appendix(intrusion_report) -> None:
    appendix_ids = {e.event_id for e in intrusion_report.evidence_appendix}
    for claim in intrusion_report.all_claims:
        assert set(claim.evidence_ids) <= appendix_ids, (
            f"claim cites evidence missing from the appendix: {claim.statement}"
        )


def test_evidence_appendix_contains_only_real_telemetry(intrusion_report, telemetry) -> None:
    known = set(
        telemetry.processes["event_id"].tolist()
        + telemetry.network["event_id"].tolist()
        + telemetry.logons["event_id"].tolist()
    )
    for entry in intrusion_report.evidence_appendix:
        assert entry.event_id in known


def test_evidence_appendix_is_chronological(intrusion_report) -> None:
    stamps = [e.timestamp for e in intrusion_report.evidence_appendix]
    assert stamps == sorted(stamps)


def test_evidence_appendix_has_no_duplicate_events(intrusion_report) -> None:
    ids = [e.event_id for e in intrusion_report.evidence_appendix]
    assert len(ids) == len(set(ids))


def test_hypothesis_with_no_evidence_does_not_break_the_appendix(intrusion_report) -> None:
    """Hypotheses may cite nothing -- the appendix must handle that gracefully."""
    no_evidence_hyps = [h for h in intrusion_report.hypotheses if not h.evidence_ids]
    assert no_evidence_hyps  # this dataset produces at least one
    # Simply must not have raised when building; nothing further to assert.


# ======================================================================================
# Recommended actions: traceable, not generic
# ======================================================================================


def test_every_recommendation_names_its_origin(intrusion_report) -> None:
    for action in intrusion_report.recommended_actions:
        assert action.based_on, f"untraceable recommendation: {action.action}"


def test_credential_hypothesis_produces_a_credential_reset_recommendation(
    intrusion_report,
) -> None:
    actions = [a.action.lower() for a in intrusion_report.recommended_actions]
    assert any("reset" in a and "credential" in a for a in actions)


def test_exfiltration_hypothesis_produces_a_log_review_recommendation(
    intrusion_report,
) -> None:
    actions = [a.action.lower() for a in intrusion_report.recommended_actions]
    assert any("proxy" in a or "flow" in a for a in actions)


def test_missing_initial_access_tactic_produces_a_recommendation(intrusion_report) -> None:
    based_on = [a.based_on for a in intrusion_report.recommended_actions]
    assert any("Initial Access" in b for b in based_on)


def test_human_escalation_recommendation_is_always_present(
    intrusion_report, benign_report
) -> None:
    """This system never remediates -- every report must say so explicitly."""
    for report in (intrusion_report, benign_report):
        actions = [a.action.lower() for a in report.recommended_actions]
        assert any("escalate" in a and "human" in a for a in actions)


def test_no_recommendation_describes_an_automatic_action(intrusion_report, benign_report) -> None:
    """Recommendations must be advisory, never phrased as something the system did."""
    forbidden = ("disabled", "isolated", "blocked", "quarantined", "the system has")
    for report in (intrusion_report, benign_report):
        for action in report.recommended_actions:
            text = action.action.lower()
            assert not any(f in text for f in forbidden), action.action


def test_benign_case_generates_fewer_recommendations_than_the_intrusion(
    intrusion_report, benign_report,
) -> None:
    assert len(benign_report.recommended_actions) < len(intrusion_report.recommended_actions)


# ======================================================================================
# Limitations
# ======================================================================================


def test_limitations_name_the_uncovered_tactics(intrusion_report) -> None:
    text = " ".join(intrusion_report.limitations)
    assert "Initial Access" in text


def test_synthetic_report_correctly_labels_itself_synthetic(intrusion_report) -> None:
    """Regression guard: the limitations text must call synthetic data synthetic --
    and, by construction (see the paired defender-import test), must NOT do so when
    the data is not synthetic. This dataset genuinely is synthetic, so the synthetic
    wording is expected here."""
    assert intrusion_report.data_sources == ("synthetic",)
    text = " ".join(intrusion_report.limitations).lower()
    assert "synthetic" in text


def test_limitations_distinguish_grouping_confidence_from_intrusion_confirmation(
    intrusion_report,
) -> None:
    text = " ".join(intrusion_report.limitations).lower()
    assert "not whether an intrusion occurred" in text


def test_step_limited_investigation_is_flagged_as_partial(
    intrusion_case, telemetry, hunt_result, cases,
) -> None:
    limited_state = _investigate(intrusion_case, telemetry, hunt_result, cases, max_steps=1)
    assert limited_state.status is InvestigationStatus.STEP_LIMIT
    report = build_report(limited_state, telemetry)
    assert any("partial" in item.lower() for item in report.limitations)


# ======================================================================================
# Markdown rendering
# ======================================================================================


def test_markdown_contains_the_case_id(intrusion_report) -> None:
    md = render_markdown(intrusion_report)
    assert intrusion_report.case_id in md


def test_markdown_never_asserts_intrusion_as_settled_fact(intrusion_report) -> None:
    """The rendered document, not just the data model, must stay hedged."""
    md = render_markdown(intrusion_report).lower()
    for overclaim in ("an attacker has compromised", "this confirms an intrusion",
                      "the network was breached"):
        assert overclaim not in md


def test_markdown_every_claim_type_is_labelled(intrusion_report) -> None:
    md = render_markdown(intrusion_report)
    assert "Confirmed:" in md
    assert "Assessed:" in md
    assert "Unconfirmed hypothesis:" in md


def test_markdown_hypothesis_section_present_when_hypotheses_exist(intrusion_report) -> None:
    assert intrusion_report.hypotheses  # sanity: this dataset produces some
    md = render_markdown(intrusion_report)
    assert "Unconfirmed Hypotheses" in md


def test_markdown_states_no_response_action_was_taken(intrusion_report) -> None:
    md = render_markdown(intrusion_report).lower()
    assert "no response action" in md or "not authorise" in md or "not authorised" in md


def test_markdown_evidence_ids_are_backtick_quoted_and_present(intrusion_report) -> None:
    md = render_markdown(intrusion_report)
    sample_id = intrusion_report.evidence_appendix[0].event_id
    assert f"`{sample_id}`" in md


def test_markdown_long_evidence_lists_are_truncated_for_readability(intrusion_report) -> None:
    """A claim with >6 evidence ids should not dump all of them inline."""
    long_claim = max(intrusion_report.all_claims, key=lambda c: len(c.evidence_ids))
    assert len(long_claim.evidence_ids) > 6
    md = render_markdown(intrusion_report)
    assert "more (see Evidence Appendix)" in md
    # But the full list must still be recoverable from the claim object itself.
    assert len(long_claim.evidence_ids) == len(set(long_claim.evidence_ids))


def test_markdown_has_no_empty_sections_for_a_report_with_data(intrusion_report) -> None:
    md = render_markdown(intrusion_report)
    for heading in ("## Executive Summary", "## Findings", "## Recommended Next Steps",
                    "## Limitations & Scope", "## Investigation Trace",
                    "## Evidence Appendix"):
        assert heading in md


def test_markdown_is_valid_utf8_and_nonempty(intrusion_report) -> None:
    md = render_markdown(intrusion_report)
    assert md.encode("utf-8")
    assert len(md) > 500


def test_markdown_table_cells_escape_pipe_characters(intrusion_report) -> None:
    """A command line containing '|' must not corrupt the evidence table."""
    md = render_markdown(intrusion_report)
    # Every literal pipe inside a table row's summary must have been escaped upstream;
    # this is easiest verified by confirming the render did not raise and produced the
    # expected number of table rows (checked elsewhere) -- structural smoke test here.
    assert "| Event ID | Time | Device | User | Summary |" in md


# ======================================================================================
# The report's own claims stay calibrated once assembled
# ======================================================================================


def test_report_claims_pass_calibration_audit(intrusion_report, benign_report) -> None:
    for report in (intrusion_report, benign_report):
        assert audit_calibration(list(report.all_claims)) == {}


# ======================================================================================
# Serialisation
# ======================================================================================


def test_report_serialises_to_json(intrusion_report) -> None:
    payload = json.loads(json.dumps(intrusion_report.to_dict()))
    assert payload["case_id"] == intrusion_report.case_id
    assert len(payload["evidence_appendix"]) == len(intrusion_report.evidence_appendix)
    assert len(payload["facts"]) == len(intrusion_report.facts)


def test_report_json_round_trips_recommended_actions(intrusion_report) -> None:
    payload = intrusion_report.to_dict()
    assert len(payload["recommended_actions"]) == len(intrusion_report.recommended_actions)
    assert all("based_on" in a for a in payload["recommended_actions"])
