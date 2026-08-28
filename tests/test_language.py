"""Tests for calibrated language.

The property under test: rendered prose must not silently drop the hedging that a
claim's epistemic type requires, and must not undersell a claim that IS directly
supported by telemetry. These tests operate on rendered sentences, not on Claim
objects, because that is where a careless template edit would actually surface.
"""

from __future__ import annotations

import pytest

from ath.agent.claims import Claim, ClaimType
from ath.correlation import correlate
from ath.hunting import run_hunt
from ath.reporting.language import (
    CLAIM_PREFIXES,
    audit_calibration,
    find_overclaiming,
    find_underclaiming,
    render_claim,
)
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import load_telemetry


@pytest.fixture(scope="module")
def telemetry(tmp_path_factory):
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("lang_data")
    write_telemetry(tables, gt, out)
    return load_telemetry(out)


@pytest.fixture(scope="module")
def real_id(telemetry) -> str:
    return telemetry.processes.iloc[0]["event_id"]


# ======================================================================================
# Rendering
# ======================================================================================


def test_fact_renders_with_confirmed_prefix(real_id) -> None:
    claim = Claim(ClaimType.FACT, "X happened", evidence_ids=(real_id,), source="tool")
    assert render_claim(claim).startswith("Confirmed:")


def test_inference_renders_with_assessed_prefix(real_id) -> None:
    claim = Claim(ClaimType.INFERENCE, "X is likely", evidence_ids=(real_id,), source="analysis")
    assert render_claim(claim).startswith("Assessed:")


def test_hypothesis_renders_with_unconfirmed_prefix() -> None:
    claim = Claim(ClaimType.HYPOTHESIS, "X might be true", source="analysis")
    assert render_claim(claim).startswith("Unconfirmed hypothesis:")


def test_every_claim_type_has_a_distinct_prefix() -> None:
    assert len(set(CLAIM_PREFIXES.values())) == len(CLAIM_PREFIXES)


def test_confidence_is_appended_when_present(real_id) -> None:
    claim = Claim(ClaimType.INFERENCE, "X", evidence_ids=(real_id,),
                  source="analysis", confidence=0.73)
    assert "0.73" in render_claim(claim)


def test_confidence_is_omitted_when_absent(real_id) -> None:
    claim = Claim(ClaimType.FACT, "X", evidence_ids=(real_id,), source="tool")
    assert "confidence" not in render_claim(claim)


# ======================================================================================
# Overclaiming lint
# ======================================================================================


@pytest.mark.parametrize("term", [
    "proves", "certainly", "definitely", "conclusively", "without doubt", "guaranteed",
])
def test_overclaiming_terms_are_flagged_on_inference(term: str, real_id) -> None:
    claim = Claim(ClaimType.INFERENCE, f"This {term} shows compromise",
                  evidence_ids=(real_id,), source="analysis")
    assert term in find_overclaiming(claim)


def test_overclaiming_terms_are_flagged_on_hypothesis() -> None:
    claim = Claim(ClaimType.HYPOTHESIS, "This conclusively shows compromise", source="analysis")
    assert find_overclaiming(claim)


def test_fact_is_exempt_from_overclaiming_check(real_id) -> None:
    """A FACT is allowed certainty language -- it earned it via telemetry."""
    claim = Claim(ClaimType.FACT, "This definitely happened",
                  evidence_ids=(real_id,), source="tool")
    assert find_overclaiming(claim) == []


def test_clean_inference_has_no_overclaiming_issues(real_id) -> None:
    claim = Claim(ClaimType.INFERENCE, "This is consistent with compromise",
                  evidence_ids=(real_id,), source="analysis")
    assert find_overclaiming(claim) == []


# ======================================================================================
# Underclaiming lint
# ======================================================================================


@pytest.mark.parametrize("term", ["might have", "may have", "possibly", "perhaps"])
def test_underclaiming_terms_are_flagged_on_fact(term: str, real_id) -> None:
    claim = Claim(ClaimType.FACT, f"The process {term} started",
                  evidence_ids=(real_id,), source="tool")
    assert term in find_underclaiming(claim)


def test_inference_is_exempt_from_underclaiming_check(real_id) -> None:
    """Hedging IS appropriate for an inference -- it should not be flagged there."""
    claim = Claim(ClaimType.INFERENCE, "This may have been the initial vector",
                  evidence_ids=(real_id,), source="analysis")
    assert find_underclaiming(claim) == []


def test_hypothesis_is_exempt_from_underclaiming_check() -> None:
    claim = Claim(ClaimType.HYPOTHESIS, "This might have happened", source="analysis")
    assert find_underclaiming(claim) == []


def test_clean_fact_has_no_underclaiming_issues(real_id) -> None:
    claim = Claim(ClaimType.FACT, "The process started", evidence_ids=(real_id,), source="tool")
    assert find_underclaiming(claim) == []


# ======================================================================================
# Batch audit
# ======================================================================================


def test_audit_calibration_reports_only_failing_claims(real_id) -> None:
    clean = Claim(ClaimType.INFERENCE, "This is consistent with X",
                  evidence_ids=(real_id,), source="analysis")
    dirty = Claim(ClaimType.HYPOTHESIS, "This certainly proves Y", source="analysis")
    issues = audit_calibration([clean, dirty])
    assert clean.statement not in issues
    assert dirty.statement in issues


def test_audit_calibration_empty_on_clean_batch(real_id) -> None:
    claims = [
        Claim(ClaimType.FACT, "A happened", evidence_ids=(real_id,), source="tool"),
        Claim(ClaimType.INFERENCE, "B is consistent with A", evidence_ids=(real_id,),
              source="analysis"),
        Claim(ClaimType.HYPOTHESIS, "C might explain B", source="analysis"),
    ]
    assert audit_calibration(claims) == {}


# ======================================================================================
# Regression: every claim this project actually produces passes calibration
# ======================================================================================


def test_all_specialist_claims_in_the_real_dataset_pass_calibration(telemetry) -> None:
    """The specialists' own hand-written templates must themselves stay calibrated.

    This is a regression guard: if a future edit to a specialist's phrasing
    accidentally introduces 'certainly' or 'proves', this test catches it even though
    no one wrote a claim-specific test for that exact sentence.
    """
    from ath.agent.claims import ClaimVerifier
    from ath.agent.orchestrator import InvestigationConfig, InvestigationOrchestrator
    from ath.agent.tools import ToolBox

    result = run_hunt(telemetry)
    cases = correlate(result.findings, telemetry)
    tools = ToolBox(telemetry, result.findings, cases)
    verifier = ClaimVerifier(telemetry)
    orch = InvestigationOrchestrator(
        tools, verifier,
        config=InvestigationConfig(use_llm_planner=False, use_llm_synthesis=False),
    )

    all_claims = []
    for case in cases:
        state = orch.investigate(case)
        all_claims.extend(state.claims)

    issues = audit_calibration(all_claims)
    assert issues == {}, f"calibration issues found: {issues}"
