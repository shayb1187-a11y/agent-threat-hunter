"""Tests for ControlPlaneAgent, and Proof A: it adds real investigative value.

Proof A (M13 design decision 3) is deliberately independent of the capability registry
built in Phase B: it constructs both specialist rosters by hand and compares them,
exactly like the tests that motivated the specialist-eligibility redesign in the first
place (see test_orchestrator.py::test_specialists_activate_on_an_unknown_rule_catalogue).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ath.agent.claims import ClaimVerifier
from ath.agent.llm import NullLLM
from ath.agent.orchestrator import InvestigationConfig, InvestigationOrchestrator
from ath.agent.specialists import (
    AttackMappingAgent,
    ControlPlaneAgent,
    EndpointAgent,
    IdentityAgent,
    NetworkAgent,
)
from ath.agent.tools import ToolBox
from ath.correlation import correlate
from ath.hunting import run_hunt
from ath.telemetry.k8s_audit_source import K8sAuditSource
from ath.telemetry.loader import Telemetry

FIXTURE = Path(__file__).parent / "fixtures" / "k8s_audit"


@pytest.fixture(scope="module")
def telemetry() -> Telemetry:
    result = K8sAuditSource(FIXTURE, cluster="test-cluster").load()
    return Telemetry(
        processes=result.tables["process"], network=result.tables["network"],
        logons=result.tables["logon"], controls=result.tables["control"],
    )


@pytest.fixture(scope="module")
def hunt_result(telemetry):
    return run_hunt(telemetry)


@pytest.fixture(scope="module")
def cases(hunt_result, telemetry):
    return correlate(hunt_result.findings, telemetry)


@pytest.fixture(scope="module")
def escalation_case(cases):
    """The case containing the K8S-001/K8S-002 privilege-escalation chain."""
    return next(c for c in cases if "K8S-001" in c.rule_ids or "K8S-002" in c.rule_ids)


@pytest.fixture
def toolbox(telemetry, hunt_result, cases):
    return ToolBox(telemetry, hunt_result.findings, cases)


@pytest.fixture
def verifier(telemetry):
    return ClaimVerifier(telemetry)


def _deterministic(toolbox, verifier, specialists):
    return InvestigationOrchestrator(
        toolbox, verifier, llm=NullLLM(), specialists=specialists,
        config=InvestigationConfig(
            max_steps=8, use_llm_planner=False, use_llm_synthesis=False,
        ),
    )


# ======================================================================================
# The correlator actually produces a case for this incident
# ======================================================================================


def test_the_escalation_chain_correlates_into_one_case(cases) -> None:
    """K8S-001 and K8S-002 share the grant event, so `shared_evidence` links them."""
    matching = [c for c in cases if "K8S-001" in c.rule_ids and "K8S-002" in c.rule_ids]
    assert len(matching) == 1


# ======================================================================================
# Proof A: the old fixed roster produces nothing; adding ControlPlaneAgent does
# ======================================================================================


def test_the_old_fixed_roster_produces_no_facts_about_the_escalation(
    toolbox, verifier, escalation_case,
) -> None:
    """The failure this specialist exists to fix, measured rather than asserted.

    Endpoint/Identity/Network/ATT&CK are exactly `default_specialists()` -- the
    roster every case ran through before this milestone. None of them read
    ath.schema.EVENT_CONTROL, so a case built entirely from control-plane evidence
    gives every one of them nothing to do: same shape as the INC-002 zero-facts bug
    Milestone 11 found and fixed for cloud auth, now reappearing for cloud/Kubernetes
    control-plane activity because nothing in the old roster covers it either.
    """
    old_roster = [
        EndpointAgent(toolbox), IdentityAgent(toolbox), NetworkAgent(toolbox),
        AttackMappingAgent(toolbox),
    ]
    state = _deterministic(toolbox, verifier, old_roster).investigate(escalation_case)
    assert len(state.facts) == 0, (
        f"expected zero facts from the old roster, got {len(state.facts)}: "
        f"{[c.statement for c in state.facts]}"
    )


def test_adding_control_plane_agent_produces_real_facts(
    toolbox, verifier, escalation_case,
) -> None:
    new_roster = [
        EndpointAgent(toolbox), IdentityAgent(toolbox), NetworkAgent(toolbox),
        ControlPlaneAgent(toolbox), AttackMappingAgent(toolbox),
    ]
    state = _deterministic(toolbox, verifier, new_roster).investigate(escalation_case)
    assert len(state.facts) > 0
    assert "control_plane" in state.agents_run

    statements = " ".join(c.statement for c in state.facts)
    assert "ci-runner" in statements
    assert "cluster-admin" in statements


def test_control_plane_agent_infers_the_grant_was_used(
    toolbox, verifier, escalation_case,
) -> None:
    agent = ControlPlaneAgent(toolbox)
    state = _deterministic(
        toolbox, verifier,
        [EndpointAgent(toolbox), IdentityAgent(toolbox), NetworkAgent(toolbox), agent],
    ).investigate(escalation_case)

    inferences = [c.statement for c in state.inferences]
    assert any("acted on the granted privilege" in s for s in inferences)


def test_control_plane_agent_declines_on_a_windows_only_case(toolbox, verifier) -> None:
    """No control-plane evidence, no work -- declines cleanly, does not crash."""
    from ath.agent.state import InvestigationState
    from ath.correlation.chain import InvestigationCase

    empty_case = InvestigationCase(case_id="CASE-EMPTY", findings=())
    should, why = ControlPlaneAgent(toolbox).should_run(
        InvestigationState(case=empty_case)
    )
    assert not should
