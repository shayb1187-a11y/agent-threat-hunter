"""``kubectl exec`` as a real apiserver logs it: verb ``get``, status ``101``.

Found on the first real Kubernetes audit logs this project ingested (M14 step 2): every
one of 5,962 execs in a Kubernetes CI run was recorded with verb ``get`` and answered
``101 Switching Protocols``. The adapter mapped neither, so K8S-002 could not fire on a
real cluster and a successful exec would have been read as denied. Both are pinned here
in the shape the apiserver actually emits.
"""

from __future__ import annotations

import json

from ath.schema import EVENT_CONTROL
from ath.telemetry.k8s_audit_source import K8sAuditSource, _decision, _normalise_control_record


def _real_shaped_exec(verb: str = "get", code: int = 101) -> dict:
    return {
        "kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "RequestResponse",
        "auditID": "exec-1", "stage": "ResponseComplete", "verb": verb,
        "requestURI": "/api/v1/namespaces/prod/pods/web-1/exec?command=sh&command=-c&command=id",
        "user": {"username": "mfranzil", "groups": ["system:authenticated"]},
        "sourceIPs": ["10.0.0.5"], "userAgent": "kubectl/v1.30.2",
        "objectRef": {"resource": "pods", "subresource": "exec", "namespace": "prod", "name": "web-1"},
        "responseStatus": {"metadata": {}, "code": code},
        "stageTimestamp": "2024-05-28T09:30:00.000000Z",
    }


def test_get_verb_exec_maps_to_pods_exec() -> None:
    row, issue = _normalise_control_record(_real_shaped_exec(), "audit.log", 0, "c")
    assert issue is None
    assert row is not None
    assert row["resource_type"] == "pods/exec"
    assert row["verb"] == "exec"  # canonical action, whatever the apiserver logged
    assert row["actor"] == "mfranzil"


def test_switching_protocols_is_a_successful_exec_not_a_denied_one() -> None:
    """The 101 boundary, and the M18-7 tri-state around it.

    ``{}`` -- a response this adapter could not read a status out of -- asserted "denied"
    until M18-7 and now asserts "failed": a missing field is not the apiserver refusing an
    identity, and reading it as one manufactures authorization evidence from an absence.
    """
    assert _decision({"responseStatus": {"code": 101}}) == "allowed"
    assert _decision({"responseStatus": {"code": 200}}) == "allowed"
    assert _decision({"responseStatus": {"code": 403}}) == "denied"
    assert _decision({"responseStatus": {"code": 401}}) == "denied"
    assert _decision({"responseStatus": {"code": 404}}) == "failed"
    assert _decision({"responseStatus": {"code": 409}}) == "failed"
    assert _decision({"responseStatus": {"code": 500}}) == "failed"
    assert _decision({"responseStatus": {"code": 101, "status": "Failure"}}) == "allowed"
    assert _decision({}) == "failed"


def test_a_forbidden_exec_upgrade_is_still_denied() -> None:
    row, _ = _normalise_control_record(_real_shaped_exec(code=403), "audit.log", 0, "c")
    assert row is not None
    assert row["decision"] == "denied"


def test_get_on_pods_without_the_exec_subresource_is_still_unmapped() -> None:
    """The subresource makes it an exec; a plain pod read must stay unmapped."""
    item = _real_shaped_exec()
    item["objectRef"] = {"resource": "pods", "namespace": "prod", "name": "web-1"}
    item["responseStatus"] = {"code": 200}
    row, issue = _normalise_control_record(item, "audit.log", 0, "c")
    assert row is None
    assert issue is not None and "get on pods" in issue.reason


def test_exec_after_grant_rule_sees_real_shaped_execs(tmp_path) -> None:
    """End to end: a privileged grant, then a ``get``-verb exec by the grantee."""
    from ath.hunting import run_hunt
    from ath.telemetry.loader import Telemetry

    grant = {
        "kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "RequestResponse",
        "auditID": "grant-1", "stage": "ResponseComplete", "verb": "create",
        "user": {"username": "system:serviceaccount:ci:ci-deployer"}, "sourceIPs": ["10.0.0.9"],
        "objectRef": {"resource": "clusterrolebindings", "name": "runner-admin",
                      "apiGroup": "rbac.authorization.k8s.io"},
        "requestObject": {
            "subjects": [{"kind": "ServiceAccount", "name": "ci-runner", "namespace": "ci"}],
            "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
        },
        "responseStatus": {"code": 201}, "stageTimestamp": "2024-05-28T09:29:00.000000Z",
    }
    execute = _real_shaped_exec()
    execute["user"] = {"username": "system:serviceaccount:ci:ci-runner"}
    (tmp_path / "audit.log").write_text(
        json.dumps(grant) + "\n" + json.dumps(execute) + "\n", encoding="utf-8",
    )
    result = K8sAuditSource(tmp_path, cluster="c").load()
    assert len(result.tables[EVENT_CONTROL]) == 2
    telemetry = Telemetry(
        processes=result.tables["process"], network=result.tables["network"],
        logons=result.tables["logon"], controls=result.tables[EVENT_CONTROL],
    )
    fired = {f.rule_id for f in run_hunt(telemetry).findings}
    assert "K8S-002" in fired


def test_service_account_subjects_are_spelled_as_the_audit_log_will_name_them() -> None:
    """``{kind: ServiceAccount, name: ci-runner, namespace: ci}`` is the same identity as
    the later caller ``system:serviceaccount:ci:ci-runner``; only the adapter knows both."""
    from ath.telemetry.k8s_audit_source import _subject_identity

    item = {"objectRef": {"resource": "rolebindings", "namespace": "ci"}}
    assert _subject_identity(
        {"kind": "ServiceAccount", "name": "ci-runner", "namespace": "ci"}, item
    ) == "system:serviceaccount:ci:ci-runner"
    # No subject namespace: a namespaced RoleBinding's own namespace applies.
    assert _subject_identity({"kind": "ServiceAccount", "name": "ci-runner"}, item) == (
        "system:serviceaccount:ci:ci-runner"
    )
    # Users and groups are spelled the same in both places already.
    assert _subject_identity({"kind": "User", "name": "alice"}, item) == "alice"
    assert _subject_identity({"kind": "Group", "name": "system:masters"}, item) == "system:masters"
    # Already-canonical names are not double-prefixed.
    assert _subject_identity(
        {"kind": "ServiceAccount", "name": "system:serviceaccount:ci:ci-runner"}, item
    ) == "system:serviceaccount:ci:ci-runner"


def test_fixture_no_longer_hides_the_mismatch() -> None:
    """The fixture must carry the real RBAC subject shape, or these tests prove nothing."""
    from pathlib import Path

    raw = (Path(__file__).parent / "fixtures" / "k8s_audit" / "k8s-audit-2026-08-17.json").read_text()
    assert '"name": "ci-runner", "namespace": "ci"' in raw
    assert '{"kind": "ServiceAccount", "name": "system:serviceaccount' not in raw
