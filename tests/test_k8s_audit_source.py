"""Tests for the Kubernetes audit-log adapter.

Deliberately mirrors tests/test_cloudtrail_source.py: this adapter is meant to be a
structural twin of the CloudTrail one, mapping into the same EVENT_CONTROL table for
the same reason -- and any real difference in behaviour between the two adapters should
show up as a real difference in these two test files, not be hidden by one of them
testing something the other doesn't bother with.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS
from ath.telemetry.k8s_audit_source import K8sAuditSource, _normalise_control_record

FIXTURE = Path(__file__).parent / "fixtures" / "k8s_audit"


@pytest.fixture(scope="module")
def result():
    return K8sAuditSource(FIXTURE, cluster="test-cluster").load()


def test_source_reports_honest_counts(result) -> None:
    # 10 items in the fixture, one of them an intermediate "RequestReceived" stage for
    # a request whose "ResponseComplete" is also present -- filtered before counting,
    # since it is a duplicate log line for one event, not a distinct record.
    assert result.rows_read == 9
    assert result.rows_kept == 4
    assert result.rows_dropped == 5


def test_only_process_and_network_are_empty(result) -> None:
    """Kubernetes audit events carry no process or network telemetry."""
    assert result.tables[EVENT_PROCESS].empty
    assert result.tables[EVENT_NETWORK].empty
    assert result.tables[EVENT_LOGON].empty


def test_rbac_grants_and_pod_exec_map_to_the_control_table(result) -> None:
    controls = result.tables[EVENT_CONTROL]
    assert len(controls) == 4
    assert set(controls["source"]) == {"k8s_audit"}
    assert set(controls["device"]) == {"k8s:test-cluster"}
    assert set(controls["resource_type"]) == {"rolebindings", "clusterrolebindings", "pods/exec"}


def test_intermediate_audit_stages_are_not_double_counted(result) -> None:
    """The RequestReceived/ResponseComplete pair for auditID ...0001 is one event."""
    controls = result.tables[EVENT_CONTROL]
    matches = controls[controls["resource_name"] == "alice-view-binding"]
    assert len(matches) == 1


def test_benign_grant_still_carries_a_distinct_target_actor(result) -> None:
    """An ordinary admin grant is still actor != target_actor -- this is not special-cased."""
    controls = result.tables[EVENT_CONTROL]
    grant = controls[controls["resource_name"] == "alice-view-binding"].iloc[0]
    assert grant["actor"] == "admin@example.com"
    assert grant["target_actor"] == "alice"
    assert grant["role_ref"] == "view"


def test_escalation_grant_targets_a_different_service_account(result) -> None:
    """The privilege-escalation scenario: ci-deployer grants cluster-admin to ci-runner.

    Exactly the mistake this schema exists to prevent: if `actor` were read as the
    identity gaining power, a later chain rule would look for ci-deployer's activity,
    not ci-runner's -- and ci-deployer never touches the pod that gets exec'd into.
    """
    controls = result.tables[EVENT_CONTROL]
    grant = controls[controls["resource_type"] == "clusterrolebindings"].iloc[0]
    assert grant["actor"] == "system:serviceaccount:ci:ci-deployer"
    assert grant["target_actor"] == "system:serviceaccount:ci:ci-runner"
    assert grant["actor"] != grant["target_actor"]
    assert grant["role_ref"] == "cluster-admin"
    assert grant["user"] == grant["target_actor"], (
        "the row's canonical user must name the identity gaining power, not the grantor"
    )


def test_pod_exec_by_the_newly_privileged_account_is_mapped(result) -> None:
    controls = result.tables[EVENT_CONTROL]
    execs = controls[controls["resource_type"] == "pods/exec"]
    assert len(execs) == 2
    escalated = execs[execs["actor"] == "system:serviceaccount:ci:ci-runner"]
    assert len(escalated) == 1
    assert escalated.iloc[0]["resource_name"] == "web-1"
    assert escalated.iloc[0]["resource_namespace"] == "prod"


def test_unmapped_verbs_and_resources_are_reported_with_a_reason(result) -> None:
    reasons = " ".join(i.reason for i in result.issues)
    assert "list on pods" in reasons
    assert "create on deployments" in reasons
    assert "list on configmaps" in reasons


def test_malformed_records_are_dropped_not_raised(result) -> None:
    reasons = [i.reason for i in result.issues]
    assert any("unparseable timestamp" in r for r in reasons)
    assert any("no usable principal" in r for r in reasons)


def test_missing_directory_fails_clearly() -> None:
    with pytest.raises(FileNotFoundError, match="No Kubernetes audit"):
        K8sAuditSource(FIXTURE.parent / "does-not-exist").load()


# ======================================================================================
# Unit-level: the actor/target_actor split, isolated from the fixture
# ======================================================================================


def test_normalise_control_record_splits_actor_from_target() -> None:
    item = {
        "auditID": "constructed-0001",
        "stage": "ResponseComplete",
        "verb": "create",
        "user": {"username": "ops-admin", "groups": ["ops", "system:authenticated"]},
        "sourceIPs": ["10.1.1.1"],
        "objectRef": {
            "resource": "clusterrolebindings", "name": "escalate", "apiVersion": "v1",
        },
        "requestObject": {
            "subjects": [{"kind": "ServiceAccount", "name": "worker-sa", "namespace": "batch"}],
            "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
        },
        "responseStatus": {"code": 201},
        "stageTimestamp": "2026-08-17T10:00:00.000000Z",
    }
    row, issue = _normalise_control_record(item, "constructed.json", 0, "clusterA")

    assert issue is None
    assert row["actor"] == "ops-admin"
    # The subject is spelled the way the audit log will later name the account as a
    # caller, so a grant and the grantee's next action can be joined (M14 step 2).
    assert row["target_actor"] == "system:serviceaccount:batch:worker-sa"
    assert row["actor"] != row["target_actor"]
    assert row["role_ref"] == "cluster-admin"
    assert row["decision"] == "allowed"
    # The caller's asserted groups travel with the row (M15-3): K8S-001 reads them to
    # tell a superuser's administrative grant from an escalation.
    assert row["actor_groups"] == "ops,system:authenticated"

    item["user"] = {"username": "bare"}
    row, _ = _normalise_control_record(item, "constructed.json", 1, "clusterA")
    assert row["actor_groups"] == ""
