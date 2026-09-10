"""Tests for the AWS and Kubernetes control-plane detection rules (AWS-001/002, K8S-001/002).

Every rule test philosophy from tests/test_hunting.py applies here too: a true-positive
case that the rule fires on, and a true-negative case proving it stays quiet -- plus,
specifically for these four rules, a dedicated case proving the actor/target_actor
distinction is load-bearing, not cosmetic: swapping which identity acted where must
change the verdict.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest

from ath.channels import TelemetryChannel
from ath.hunting.base import get_detector
from ath.hunting.rules.k8s_rules import HIGH_PRIVILEGE_ROLE_NAMES
from ath.schema import CONTROL_COLUMNS
from ath.telemetry.loader import Telemetry
from ath.telemetry.normalize import coerce_and_validate

UTC = timezone.utc
T0 = datetime(2026, 8, 17, 9, 0, 0, tzinfo=UTC)


def _control_telemetry(rows: list[dict]) -> Telemetry:
    """Build a schema-valid Telemetry with only the control table populated."""
    for i, row in enumerate(rows, start=1):
        row.setdefault("event_id", f"evt-control-{i:04d}")
        row.setdefault("event_type", "control")
        row.setdefault("source", "test")
        row.setdefault("source_ref", "")
        row.setdefault("resource_namespace", "")
        row.setdefault("target_actor", "")
        row.setdefault("role_ref", "")
        row.setdefault("decision", "allowed")
        row.setdefault("source_ip", "")
    df = pd.DataFrame(rows, columns=list(CONTROL_COLUMNS))
    controls = coerce_and_validate(df, "control")
    from ath.schema import EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS
    return Telemetry(
        processes=_empty_of(EVENT_PROCESS),
        network=_empty_of(EVENT_NETWORK),
        logons=_empty_of(EVENT_LOGON),
        controls=controls,
    )


def _empty_of(event_type: str) -> pd.DataFrame:
    from ath.schema import TABLE_COLUMNS
    return coerce_and_validate(pd.DataFrame(columns=list(TABLE_COLUMNS[event_type])), event_type)


# ======================================================================================
# AWS-001: IAM privilege-escalation chain
# ======================================================================================


def test_aws001_fires_when_the_beneficiary_creates_a_key_after_the_grant() -> None:
    rows = [
        {
            "timestamp": T0, "device": "aws:111/us-east-1", "user": "mallory",
            "actor": "mallory", "verb": "attach", "resource_type": "iam:user-policy",
            "resource_name": "mallory", "target_actor": "mallory",
            "role_ref": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
        {
            "timestamp": T0 + timedelta(minutes=2), "device": "aws:111/us-east-1",
            "user": "mallory", "actor": "mallory", "verb": "create",
            "resource_type": "iam:access-key", "resource_name": "mallory",
        },
    ]
    findings = get_detector("AWS-001").detect(_control_telemetry(rows))
    assert len(findings) == 1
    assert findings[0].user == "mallory"
    assert findings[0].event_count == 2


def test_aws001_stays_quiet_when_the_grantor_creates_the_key_not_the_beneficiary() -> None:
    """The grantor acting afterwards is not the chain this rule detects.

    If the rule matched on `actor` (the grantor) instead of `target_actor` (the
    beneficiary), an administrator's own routine access-key rotation shortly after
    granting someone else a policy would falsely read as escalation.
    """
    rows = [
        {
            "timestamp": T0, "device": "aws:111/us-east-1", "user": "admin",
            "actor": "admin", "verb": "attach", "resource_type": "iam:user-policy",
            "resource_name": "newhire", "target_actor": "newhire",
            "role_ref": "arn:aws:iam::aws:policy/ReadOnlyAccess",
        },
        {
            "timestamp": T0 + timedelta(minutes=2), "device": "aws:111/us-east-1",
            "user": "admin", "actor": "admin", "verb": "create",
            "resource_type": "iam:access-key", "resource_name": "admin",
        },
    ]
    findings = get_detector("AWS-001").detect(_control_telemetry(rows))
    assert findings == []


def test_aws001_stays_quiet_outside_the_escalation_window() -> None:
    rows = [
        {
            "timestamp": T0, "device": "aws:111/us-east-1", "user": "mallory",
            "actor": "mallory", "verb": "attach", "resource_type": "iam:user-policy",
            "resource_name": "mallory", "target_actor": "mallory",
            "role_ref": "AdministratorAccess",
        },
        {
            "timestamp": T0 + timedelta(hours=6), "device": "aws:111/us-east-1",
            "user": "mallory", "actor": "mallory", "verb": "create",
            "resource_type": "iam:access-key", "resource_name": "mallory",
        },
    ]
    findings = get_detector("AWS-001").detect(_control_telemetry(rows))
    assert findings == []


def test_aws001_declares_its_channel_explicitly() -> None:
    detector = get_detector("AWS-001")
    assert detector.channels == frozenset({TelemetryChannel.CLOUD_MANAGEMENT_ACTIVITY})


# ======================================================================================
# AWS-002: CloudTrail logging disabled
# ======================================================================================


def test_aws002_fires_on_stop_logging() -> None:
    rows = [{
        "timestamp": T0, "device": "aws:111/us-east-1", "user": "mallory",
        "actor": "mallory", "verb": "stop", "resource_type": "cloudtrail:trail",
        "resource_name": "org-trail",
    }]
    findings = get_detector("AWS-002").detect(_control_telemetry(rows))
    assert len(findings) == 1
    assert "disabling" in findings[0].reason.lower() or "removing" in findings[0].reason.lower()


def test_aws002_stays_quiet_on_unrelated_management_activity() -> None:
    rows = [{
        "timestamp": T0, "device": "aws:111/us-east-1", "user": "alice",
        "actor": "alice", "verb": "create", "resource_type": "iam:access-key",
        "resource_name": "alice",
    }]
    findings = get_detector("AWS-002").detect(_control_telemetry(rows))
    assert findings == []


# ======================================================================================
# K8S-001: RBAC privilege-escalation grant
# ======================================================================================


def test_k8s001_fires_on_a_cluster_admin_binding() -> None:
    rows = [{
        "timestamp": T0, "device": "k8s:c1", "user": "ci-runner",
        "actor": "ci-deployer", "verb": "create", "resource_type": "clusterrolebindings",
        "resource_name": "escalate", "target_actor": "ci-runner",
        "role_ref": "cluster-admin",
    }]
    findings = get_detector("K8S-001").detect(_control_telemetry(rows))
    assert len(findings) == 1
    assert findings[0].user == "ci-runner", "must report the beneficiary, not the grantor"


@pytest.mark.parametrize("role", sorted(HIGH_PRIVILEGE_ROLE_NAMES))
def test_k8s001_fires_for_every_high_privilege_role_name(role: str) -> None:
    rows = [{
        "timestamp": T0, "device": "k8s:c1", "user": "svc",
        "actor": "admin", "verb": "create", "resource_type": "rolebindings",
        "resource_name": "b", "target_actor": "svc", "role_ref": role,
    }]
    assert len(get_detector("K8S-001").detect(_control_telemetry(rows))) == 1


def test_k8s001_stays_quiet_on_an_ordinary_role_grant() -> None:
    rows = [{
        "timestamp": T0, "device": "k8s:c1", "user": "alice",
        "actor": "admin", "verb": "create", "resource_type": "rolebindings",
        "resource_name": "alice-view", "target_actor": "alice", "role_ref": "view",
    }]
    findings = get_detector("K8S-001").detect(_control_telemetry(rows))
    assert findings == []


# ======================================================================================
# K8S-002: exec shortly after a privilege grant
# ======================================================================================


def _grant_row(**overrides) -> dict:
    row = {
        "timestamp": T0, "device": "k8s:c1", "user": "ci-runner",
        "actor": "ci-deployer", "verb": "create", "resource_type": "clusterrolebindings",
        "resource_name": "escalate", "target_actor": "ci-runner",
        "role_ref": "cluster-admin",
    }
    row.update(overrides)
    return row


def _exec_row(**overrides) -> dict:
    row = {
        "timestamp": T0 + timedelta(minutes=3), "device": "k8s:c1", "user": "ci-runner",
        "actor": "ci-runner", "verb": "exec", "resource_type": "pods/exec",
        "resource_name": "web-1", "resource_namespace": "prod",
    }
    row.update(overrides)
    return row


def test_k8s002_fires_when_the_beneficiary_execs_after_the_grant() -> None:
    findings = get_detector("K8S-002").detect(_control_telemetry([_grant_row(), _exec_row()]))
    assert len(findings) == 1
    assert findings[0].user == "ci-runner"
    assert findings[0].metadata["pod"] == "web-1"


def test_k8s002_stays_quiet_when_the_grantor_execs_not_the_beneficiary() -> None:
    """The load-bearing case: the creator of the binding is not who received it.

    If K8S-002 matched exec against `actor` (the grantor, ci-deployer) instead of
    `target_actor` (the beneficiary, ci-runner), an unrelated exec by the admin who
    happened to grant the role would be misread as the escalation being used.
    """
    findings = get_detector("K8S-002").detect(
        _control_telemetry([_grant_row(), _exec_row(actor="ci-deployer", user="ci-deployer")])
    )
    assert findings == []


def test_k8s002_stays_quiet_when_the_grant_is_not_high_privilege() -> None:
    findings = get_detector("K8S-002").detect(_control_telemetry([
        _grant_row(role_ref="view"), _exec_row(),
    ]))
    assert findings == []


def test_k8s002_stays_quiet_outside_the_escalation_window() -> None:
    findings = get_detector("K8S-002").detect(_control_telemetry([
        _grant_row(), _exec_row(timestamp=T0 + timedelta(hours=6)),
    ]))
    assert findings == []


def test_k8s_rules_declare_container_audit_explicitly() -> None:
    assert get_detector("K8S-001").channels == frozenset({TelemetryChannel.CONTAINER_AUDIT})
    assert get_detector("K8S-002").channels == frozenset({TelemetryChannel.CONTAINER_AUDIT})


# ======================================================================================
# Findings carry their declared channels
# ======================================================================================


def test_findings_from_control_plane_rules_carry_explicit_channels() -> None:
    rows = [_grant_row()]
    finding = get_detector("K8S-001").detect(_control_telemetry(rows))[0]
    assert finding.channels == frozenset({TelemetryChannel.CONTAINER_AUDIT})


# ======================================================================================
# ATT&CK mapping
# ======================================================================================


def test_aws001_maps_to_both_escalation_stages() -> None:
    from ath.mitre.mapper import map_finding

    rows = [
        {
            "timestamp": T0, "device": "aws:111/us-east-1", "user": "mallory",
            "actor": "mallory", "verb": "attach", "resource_type": "iam:user-policy",
            "resource_name": "mallory", "target_actor": "mallory",
            "role_ref": "AdministratorAccess",
        },
        {
            "timestamp": T0 + timedelta(minutes=1), "device": "aws:111/us-east-1",
            "user": "mallory", "actor": "mallory", "verb": "create",
            "resource_type": "iam:access-key", "resource_name": "mallory",
        },
    ]
    finding = get_detector("AWS-001").detect(_control_telemetry(rows))[0]
    techniques = {m.technique_id for m in map_finding(finding)}
    assert techniques == {"T1098.003", "T1098.001"}


def test_aws002_maps_to_disable_or_modify_tools() -> None:
    from ath.mitre.mapper import map_finding

    rows = [{
        "timestamp": T0, "device": "aws:111/us-east-1", "user": "mallory",
        "actor": "mallory", "verb": "stop", "resource_type": "cloudtrail:trail",
        "resource_name": "org-trail",
    }]
    finding = get_detector("AWS-002").detect(_control_telemetry(rows))[0]
    techniques = {m.technique_id for m in map_finding(finding)}
    assert techniques == {"T1685"}


def test_k8s001_maps_to_additional_container_cluster_roles() -> None:
    from ath.mitre.mapper import map_finding

    finding = get_detector("K8S-001").detect(_control_telemetry([_grant_row()]))[0]
    techniques = {m.technique_id for m in map_finding(finding)}
    assert techniques == {"T1098.006"}


def test_k8s002_maps_to_both_grant_and_exec() -> None:
    from ath.mitre.mapper import map_finding

    finding = get_detector("K8S-002").detect(
        _control_telemetry([_grant_row(), _exec_row()])
    )[0]
    techniques = {m.technique_id for m in map_finding(finding)}
    assert techniques == {"T1098.006", "T1609"}
