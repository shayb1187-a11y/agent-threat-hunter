"""Proof B (M13 design decision 3): crew assembly selects/excludes capabilities correctly.

Deliberately separate from Proof A (tests/test_control_plane_agent.py), which shows
`ControlPlaneAgent` adds real investigative value on its own -- no registry involved.
This file only checks set membership: given an environment's measured telemetry, does
`assemble_crew` include and exclude the right capabilities, with a legible reason for
each exclusion? No investigation is run here.

The three environments below are the concrete version of this milestone's central
claim: the same platform, given genuinely different telemetry, assembles genuinely
different crews.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ath.agent.tools import ToolBox
from ath.capabilities import CAPABILITY_REGISTRY, assemble_crew
from ath.environment import build_environment_model
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.cloudtrail_source import CloudTrailSource
from ath.telemetry.k8s_audit_source import K8sAuditSource
from ath.telemetry.loader import Telemetry, load_telemetry, merge_telemetry

CLOUDTRAIL = Path(__file__).parent / "fixtures" / "cloudtrail"
K8S_AUDIT = Path(__file__).parent / "fixtures" / "k8s_audit"


@pytest.fixture(scope="module")
def windows_telemetry(tmp_path_factory) -> Telemetry:
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("crew_windows")
    write_telemetry(tables, gt, out)
    return load_telemetry(out)


@pytest.fixture(scope="module")
def cloud_telemetry() -> Telemetry:
    result = CloudTrailSource(CLOUDTRAIL).load()
    return Telemetry(
        processes=result.tables["process"], network=result.tables["network"],
        logons=result.tables["logon"], controls=result.tables["control"],
    )


@pytest.fixture(scope="module")
def k8s_telemetry() -> Telemetry:
    result = K8sAuditSource(K8S_AUDIT, cluster="test-cluster").load()
    return Telemetry(
        processes=result.tables["process"], network=result.tables["network"],
        logons=result.tables["logon"], controls=result.tables["control"],
    )


def _empty_toolbox(telemetry: Telemetry) -> ToolBox:
    return ToolBox(telemetry, findings=[], cases=[])


# ======================================================================================
# Windows-only: endpoint/identity/network/attack, control_plane excluded
# ======================================================================================


def test_windows_environment_assembles_the_endpoint_oriented_crew(windows_telemetry) -> None:
    environment = build_environment_model(windows_telemetry)
    crew = assemble_crew(environment, _empty_toolbox(windows_telemetry))

    names = {s.name for s in crew.specialists}
    assert names == {"endpoint", "identity", "network", "attack"}

    excluded_ids = {spec.id for spec, _ in crew.excluded}
    assert excluded_ids == {"control_plane"}
    reason = next(r for spec, r in crew.excluded if spec.id == "control_plane")
    assert "cloud_management_activity" in reason
    assert "container_audit" in reason


# ======================================================================================
# Cloud/Kubernetes-only: identity/control_plane/attack, endpoint+network excluded
# ======================================================================================


def test_cloud_environment_assembles_the_control_plane_oriented_crew(cloud_telemetry) -> None:
    environment = build_environment_model(cloud_telemetry)
    crew = assemble_crew(environment, _empty_toolbox(cloud_telemetry))

    names = {s.name for s in crew.specialists}
    assert names == {"identity", "control_plane", "attack"}

    excluded_ids = {spec.id for spec, _ in crew.excluded}
    assert excluded_ids == {"endpoint", "network"}
    endpoint_reason = next(r for spec, r in crew.excluded if spec.id == "endpoint")
    assert "process_execution" in endpoint_reason
    network_reason = next(r for spec, r in crew.excluded if spec.id == "network")
    assert "network_flow" in network_reason


def test_k8s_only_environment_also_assembles_control_plane_without_cloud(
    k8s_telemetry,
) -> None:
    """control_plane stands up on Kubernetes evidence alone -- `requires_any`, not both."""
    environment = build_environment_model(k8s_telemetry)
    crew = assemble_crew(environment, _empty_toolbox(k8s_telemetry))

    names = {s.name for s in crew.specialists}
    assert "control_plane" in names
    assert "endpoint" not in names
    assert "network" not in names


# ======================================================================================
# Hybrid: Windows + AWS + Kubernetes telemetry, all capabilities stand up at once
# ======================================================================================


def test_hybrid_environment_assembles_all_five_capabilities(
    windows_telemetry, cloud_telemetry, k8s_telemetry,
) -> None:
    """The concrete Windows+AWS+Kubernetes proof.

    Nothing about `assemble_crew` picks one platform -- it only ever asks whether
    each capability's required channels are observable, so a hybrid environment
    that genuinely has Windows endpoint telemetry AND AWS management activity AND
    Kubernetes audit activity simultaneously should stand up every capability at
    once, not average or choose between them.
    """
    hybrid = merge_telemetry([windows_telemetry, cloud_telemetry, k8s_telemetry])
    environment = build_environment_model(hybrid)

    assert environment.platforms == frozenset({"windows", "aws", "kubernetes"})

    crew = assemble_crew(environment, _empty_toolbox(hybrid))
    names = {s.name for s in crew.specialists}
    assert names == {"endpoint", "identity", "network", "control_plane", "attack"}
    assert crew.excluded == ()


# ======================================================================================
# The registry and Crew shape itself
# ======================================================================================


def test_assemble_crew_is_deterministic(windows_telemetry) -> None:
    """Same environment in, same crew out -- no randomness, no LLM."""
    environment = build_environment_model(windows_telemetry)
    tools = _empty_toolbox(windows_telemetry)
    first = {s.name for s in assemble_crew(environment, tools).specialists}
    second = {s.name for s in assemble_crew(environment, tools).specialists}
    assert first == second


def test_every_capability_produces_a_working_specialist(windows_telemetry) -> None:
    """Every registered factory actually builds a Specialist given just a ToolBox."""
    tools = _empty_toolbox(windows_telemetry)
    for spec in CAPABILITY_REGISTRY:
        specialist = spec.factory(tools)
        assert specialist.name == spec.id


def test_crew_serialises_to_a_plain_dict(cloud_telemetry) -> None:
    environment = build_environment_model(cloud_telemetry)
    crew = assemble_crew(environment, _empty_toolbox(cloud_telemetry))
    payload = crew.to_dict()
    assert set(payload["specialists"]) == {"identity", "control_plane", "attack"}
    assert {e["id"] for e in payload["excluded"]} == {"endpoint", "network"}
