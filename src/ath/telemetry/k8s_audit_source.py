"""Import Kubernetes API server audit events.

Modeled directly on :mod:`ath.telemetry.cloudtrail_source`, which is the adapter this
one is deliberately kept structurally identical to: a Kubernetes audit event and an AWS
CloudTrail management event are the same shape at the level ``ath.schema.EVENT_CONTROL``
models -- an actor performs a verb on a resource, allowed or denied -- so the two
adapters differ only in *which* records they recognise and how they read that shape out
of a different wire format, not in the target table they populate.

What maps
---------
Two things, deliberately narrow (mirroring CloudTrail's own restraint): this project is
not attempting full Kubernetes audit coverage, only what
:mod:`ath.hunting.rules.k8s_rules` needs.

**RBAC grants.** A ``create`` on ``rolebindings``/``clusterrolebindings`` names a
*beneficiary* -- the binding's ``subjects`` -- that is a different identity from the
``user`` who created the binding. An administrator (or a compromised CI credential with
just enough RBAC-write access) granting ``cluster-admin`` to a service account is the
normal shape of this event, not an edge case. ``actor`` is always the caller; the
beneficiary is ``target_actor``, and the granted role is ``role_ref`` -- the identical
actor/target split :mod:`ath.telemetry.cloudtrail_source` draws for
``AttachUserPolicy``, and for the identical reason: conflating them would point a
privilege-escalation chain at the wrong identity.

**Pod exec.** A ``create`` (or ``connect``) against ``pods``, subresource ``exec``, is
someone opening a shell inside a running container -- the action
:mod:`ath.hunting.rules.k8s_rules` checks for shortly after an escalation grant. It
grants no identity, so ``target_actor`` is left empty.

What does not map
------------------
Everything else -- reads, deployments, config maps, service creation, and so on -- is
reported as a :class:`~ath.telemetry.source.NormalizationIssue` rather than silently
dropped or coerced. Intermediate audit stages (``RequestReceived``/``ResponseStarted``)
for the *same* request are filtered out before mapping, not reported as issues: they are
expected duplicate log lines for one event, not a normalisation failure.

Kubernetes has no cloud-account concept; a cluster identifier stands in for AWS's
``account/region`` in the synthesised ``device`` column, for the same reason CloudTrail
synthesises one: nothing downstream should have to special-case "no host" per source.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

from ath.logging_setup import get_logger
from ath.schema import (
    EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS, TABLE_COLUMNS,
)
from ath.telemetry.normalize import coerce_and_validate
from ath.telemetry.source import NormalizationIssue, SourceLoadResult, TelemetrySource

logger = get_logger(__name__)

SOURCE_NAME = "k8s_audit"

# Only the final stage of a request carries a response -- intermediate stages
# ("RequestReceived", "ResponseStarted") are the same event logged again, earlier.
_COMPLETE_STAGE = "ResponseComplete"

_RBAC_RESOURCES: frozenset[str] = frozenset({"rolebindings", "clusterrolebindings"})
_EXEC_VERBS: frozenset[str] = frozenset({"create", "connect"})


def _principal(user: dict[str, Any]) -> str:
    """Best available name for the acting identity.

    Kubernetes usernames are already a single string (unlike CloudTrail's union type),
    including the ``system:serviceaccount:<namespace>:<name>`` form for service
    accounts -- kept as-is rather than shortened, since the namespace is part of what
    identifies which service account this is.
    """
    return str(user.get("username") or "")


def _timestamp(item: dict[str, Any]) -> pd.Timestamp:
    raw = item.get("stageTimestamp") or item.get("requestReceivedTimestamp") or ""
    return pd.to_datetime(raw, utc=True, errors="coerce")


def _decision(item: dict[str, Any]) -> str:
    status = item.get("responseStatus") or {}
    code = status.get("code") if isinstance(status, dict) else None
    try:
        return "allowed" if code is not None and 200 <= int(code) < 300 else "denied"
    except (TypeError, ValueError):
        return "denied"


def _rbac_grant_fields(item: dict[str, Any]) -> tuple[str, str]:
    """``(target_actor, role_ref)`` for an RBAC binding create.

    Read from ``requestObject`` -- present when the audit policy captures request
    bodies (``level: RequestResponse``), which is what a binding's ``subjects`` and
    ``roleRef`` require; ``objectRef`` alone never carries them. Multiple subjects are
    joined, since a binding can name more than one beneficiary and dropping all but the
    first would silently narrow the finding's scope.
    """
    request_object = item.get("requestObject") or {}
    if not isinstance(request_object, dict):
        return "", ""
    subjects = request_object.get("subjects") or []
    names = [s.get("name") for s in subjects if isinstance(s, dict) and s.get("name")]
    target_actor = ",".join(sorted(names))
    role_ref = ""
    role = request_object.get("roleRef")
    if isinstance(role, dict):
        role_ref = str(role.get("name") or "")
    return target_actor, role_ref


@dataclass
class K8sAuditSource(TelemetrySource):
    """Read Kubernetes ``audit.k8s.io/v1`` event log files into canonical telemetry.

    Args:
        directory: Directory containing ``*.json`` audit log files. Each is expected to
            hold a top-level ``items`` array -- the shape ``kubectl`` and most log
            shippers produce (an ``EventList``). A file containing one JSON object per
            line (the raw ``--audit-log-path`` format) is not this shape; convert it to
            an ``items`` array first.
        cluster: Cluster identifier used to synthesise the ``device`` column
            (``k8s:<cluster>``) -- Kubernetes audit events have no "host" concept, the
            same gap CloudTrail's ``aws:<account>/<region>`` closes for AWS.
    """

    directory: Path
    cluster: str = "default"
    name: str = SOURCE_NAME

    def load(self) -> SourceLoadResult:
        files = sorted(self.directory.glob("*.json"))
        if not files:
            raise FileNotFoundError(
                f"No Kubernetes audit *.json files found in {self.directory}. Expected "
                "files containing a top-level 'items' array (an EventList)."
            )

        control_rows: list[dict[str, Any]] = []
        issues: list[NormalizationIssue] = []
        rows_read = 0

        for path in files:
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                issues.append(NormalizationIssue(
                    event_type=EVENT_CONTROL, reason=f"file is not valid JSON: {exc}",
                    raw_reference=path.name,
                ))
                continue

            items = payload.get("items")
            if not isinstance(items, list):
                issues.append(NormalizationIssue(
                    event_type=EVENT_CONTROL,
                    reason="file has no top-level 'items' array",
                    raw_reference=path.name,
                ))
                continue

            for index, item in enumerate(items):
                if not isinstance(item, dict):
                    rows_read += 1
                    issues.append(NormalizationIssue(
                        event_type=EVENT_CONTROL, reason="item is not a JSON object",
                        raw_reference=f"{path.name}#item={index}",
                    ))
                    continue

                # Intermediate stages are the same request logged again earlier --
                # filtered before counting as "read", since they are not a distinct
                # event this adapter is choosing not to map, only a duplicate line.
                if item.get("stage") not in (None, _COMPLETE_STAGE):
                    continue

                rows_read += 1
                row, issue = _normalise_control_record(item, path.name, index, self.cluster)
                if issue is not None:
                    issues.append(issue)
                if row is not None:
                    control_rows.append(row)

        for position, row in enumerate(control_rows, start=1):
            row["event_id"] = f"k8s-control-{position:06d}"

        controls = pd.DataFrame(control_rows, columns=list(TABLE_COLUMNS[EVENT_CONTROL]))
        tables = {
            EVENT_PROCESS: _empty(EVENT_PROCESS),
            EVENT_NETWORK: _empty(EVENT_NETWORK),
            EVENT_LOGON: _empty(EVENT_LOGON),
            EVENT_CONTROL: coerce_and_validate(controls, EVENT_CONTROL),
        }

        logger.info(
            "Kubernetes audit import: %d record(s) read, %d mapped, %d unmapped",
            rows_read, len(control_rows), len(issues),
        )
        return SourceLoadResult(tables=tables, issues=issues, rows_read=rows_read)


def _empty(event_type: str) -> pd.DataFrame:
    """An empty, schema-valid table for a channel this source carries none of."""
    return coerce_and_validate(
        pd.DataFrame(columns=list(TABLE_COLUMNS[event_type])), event_type
    )


def _normalise_control_record(
    item: dict[str, Any], file_name: str, index: int, cluster: str,
) -> tuple[dict[str, Any] | None, NormalizationIssue | None]:
    """Turn one Kubernetes audit event into a canonical control row, or explain why not."""
    audit_id = item.get("auditID", "?")
    reference = f"{file_name}#item={index}, auditID={audit_id}"

    verb = str(item.get("verb") or "")
    object_ref = item.get("objectRef") or {}
    if not isinstance(object_ref, dict):
        object_ref = {}
    resource = str(object_ref.get("resource") or "")
    subresource = str(object_ref.get("subresource") or "")

    if resource in _RBAC_RESOURCES and not subresource and verb == "create":
        resource_type = resource
        target_actor, role_ref = _rbac_grant_fields(item)
    elif resource == "pods" and subresource == "exec" and verb in _EXEC_VERBS:
        resource_type = "pods/exec"
        target_actor, role_ref = "", ""
    else:
        return None, NormalizationIssue(
            event_type=EVENT_CONTROL, field="objectRef", raw_reference=reference,
            reason=(
                f"{verb} on {resource or '<unknown>'}"
                f"{'/' + subresource if subresource else ''} is not in the RBAC-grant "
                "or pod-exec set this adapter maps (see ath.telemetry.k8s_audit_source)"
            ),
        )

    timestamp = _timestamp(item)
    if pd.isna(timestamp):
        return None, NormalizationIssue(
            event_type=EVENT_CONTROL, field="stageTimestamp", raw_reference=reference,
            reason=f"unparseable timestamp: {item.get('stageTimestamp')!r}",
        )

    user = item.get("user") or {}
    actor = _principal(user if isinstance(user, dict) else {})
    if not actor:
        return None, NormalizationIssue(
            event_type=EVENT_CONTROL, field="user", raw_reference=reference,
            reason=(
                "no usable principal name; a control-plane action that cannot be "
                "attributed to a caller would correlate against nothing"
            ),
        )

    source_ips = item.get("sourceIPs") or []
    source_ip = str(source_ips[0]) if source_ips else ""

    return {
        "event_id": "",  # assigned by the caller, densely and uniquely
        "timestamp": timestamp,
        "event_type": EVENT_CONTROL,
        "device": f"k8s:{cluster}",  # "host" is not a Kubernetes control-plane concept
        "user": target_actor or actor,
        "source": SOURCE_NAME,
        "source_ref": f"auditID={audit_id};File={file_name}",
        "actor": actor,
        "verb": verb,
        "resource_type": resource_type,
        "resource_name": str(object_ref.get("name") or ""),
        "resource_namespace": str(object_ref.get("namespace") or ""),
        "target_actor": target_actor,
        "role_ref": role_ref,
        "decision": _decision(item),
        "source_ip": source_ip,
    }, None
