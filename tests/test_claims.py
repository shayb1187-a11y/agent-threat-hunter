"""Tests for the Claim model and verifier.

This is the module that decides whether the agent layer is trustworthy. Every test here
either proves a bad claim cannot be constructed, or proves a bad claim cannot survive
verification. There is no test that merely checks "the code runs" -- each one guards a
specific epistemic guarantee the rest of the project depends on.
"""

from __future__ import annotations

import pytest

from ath.agent.claims import DETERMINISTIC_SOURCES, Claim, ClaimType, ClaimVerifier
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import load_telemetry


@pytest.fixture(scope="module")
def telemetry(tmp_path_factory):
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("claims_data")
    write_telemetry(tables, gt, out)
    return load_telemetry(out)


@pytest.fixture(scope="module")
def verifier(telemetry):
    return ClaimVerifier(telemetry)


@pytest.fixture(scope="module")
def real_event_id(telemetry) -> str:
    return telemetry.processes.iloc[0]["event_id"]


# ======================================================================================
# Construction-time guarantees
# ======================================================================================


def test_fact_requires_evidence() -> None:
    with pytest.raises(ValueError, match="must cite evidence"):
        Claim(ClaimType.FACT, "something happened", source="tool")


def test_inference_requires_evidence() -> None:
    with pytest.raises(ValueError, match="must cite evidence"):
        Claim(ClaimType.INFERENCE, "probably X", source="analysis")


def test_hypothesis_may_omit_evidence() -> None:
    """The one claim type allowed to stand on nothing -- that IS what makes it a hypothesis."""
    claim = Claim(ClaimType.HYPOTHESIS, "possibly Y", source="analysis")
    assert claim.evidence_ids == ()


def test_llm_cannot_author_a_fact(real_event_id) -> None:
    """The structural guarantee the whole agent design rests on."""
    with pytest.raises(ValueError, match="may not author a FACT"):
        Claim(ClaimType.FACT, "the attacker did X", evidence_ids=(real_event_id,), source="llm")


def test_analysis_source_cannot_author_a_fact(real_event_id) -> None:
    with pytest.raises(ValueError, match="may not author a FACT"):
        Claim(ClaimType.FACT, "x", evidence_ids=(real_event_id,), source="analysis")


@pytest.mark.parametrize("source", sorted(DETERMINISTIC_SOURCES))
def test_deterministic_sources_may_author_facts(source: str, real_event_id) -> None:
    claim = Claim(ClaimType.FACT, "x", evidence_ids=(real_event_id,), source=source)
    assert claim.source == source


def test_confidence_must_be_in_unit_range(real_event_id) -> None:
    with pytest.raises(ValueError, match="confidence must be in"):
        Claim(ClaimType.INFERENCE, "x", evidence_ids=(real_event_id,), confidence=1.5)
    with pytest.raises(ValueError, match="confidence must be in"):
        Claim(ClaimType.INFERENCE, "x", evidence_ids=(real_event_id,), confidence=-0.1)


def test_confidence_may_be_none(real_event_id) -> None:
    claim = Claim(ClaimType.FACT, "x", evidence_ids=(real_event_id,), source="tool")
    assert claim.confidence is None


# ======================================================================================
# Verifier: the anti-hallucination control
# ======================================================================================


def test_verifier_accepts_a_claim_citing_a_real_event(verifier, real_event_id) -> None:
    claim = Claim(ClaimType.INFERENCE, "x", evidence_ids=(real_event_id,), source="analysis")
    assert verifier.check(claim) is None


def test_verifier_rejects_a_fabricated_event_id(verifier) -> None:
    claim = Claim(ClaimType.INFERENCE, "the attacker exfiltrated data",
                   evidence_ids=("evt-999999",), source="llm")
    reason = verifier.check(claim)
    assert reason is not None
    assert "evt-999999" in reason


def test_verifier_rejects_if_any_cited_id_is_fake(verifier, real_event_id) -> None:
    """Partial fabrication is still fabrication -- one fake id sinks the whole claim."""
    claim = Claim(ClaimType.INFERENCE, "x",
                   evidence_ids=(real_event_id, "evt-999999"), source="llm")
    assert verifier.check(claim) is not None


def test_verify_partitions_a_batch(verifier, real_event_id) -> None:
    good = Claim(ClaimType.INFERENCE, "good", evidence_ids=(real_event_id,), source="llm")
    bad = Claim(ClaimType.HYPOTHESIS, "bad", evidence_ids=("evt-999999",), source="llm")
    hypothesis = Claim(ClaimType.HYPOTHESIS, "no evidence needed", source="llm")

    result = verifier.verify([good, bad, hypothesis])
    assert good in result.accepted and hypothesis in result.accepted
    assert len(result.rejected) == 1
    assert result.rejected[0].claim is bad
    assert result.rejection_rate == pytest.approx(1 / 3)


def test_verify_empty_batch_has_zero_rejection_rate(verifier) -> None:
    result = verifier.verify([])
    assert result.rejection_rate == 0.0
    assert result.accepted == [] and result.rejected == []


def test_verifier_known_event_count_matches_telemetry(verifier, telemetry) -> None:
    assert verifier.known_event_count == telemetry.event_count


def test_claim_serialises_to_json(real_event_id) -> None:
    import json

    claim = Claim(
        ClaimType.INFERENCE, "x", evidence_ids=(real_event_id,),
        source="analysis", agent="endpoint", confidence=0.7,
    )
    payload = json.loads(json.dumps(claim.to_dict()))
    assert payload["type"] == "INFERENCE"
    assert payload["confidence"] == 0.7


def test_rejected_claim_serialises(verifier) -> None:
    import json

    bad = Claim(ClaimType.HYPOTHESIS, "x", evidence_ids=("evt-999999",), source="llm")
    result = verifier.verify([bad])
    payload = json.loads(json.dumps(result.to_dict()))
    assert len(payload["rejected"]) == 1
    assert "evt-999999" in payload["rejected"][0]["reason"]


# ======================================================================================
# Claim type ranking (used for ordering/emphasis elsewhere)
# ======================================================================================


def test_claim_type_rank_orders_fact_above_hypothesis() -> None:
    assert ClaimType.FACT.rank > ClaimType.INFERENCE.rank > ClaimType.HYPOTHESIS.rank


def test_only_hypothesis_does_not_require_evidence() -> None:
    assert ClaimType.FACT.requires_evidence
    assert ClaimType.INFERENCE.requires_evidence
    assert not ClaimType.HYPOTHESIS.requires_evidence
