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
# ``kubectl exec`` reaches the apiserver as a protocol-upgrade request. Older clients
# POSTed it (audit verb ``create``); the audit layer also names ``connect``; and every
# real apiserver log examined for Milestone 14 -- Kubernetes CI on 1.37, K8NTEXT on
# 1.28/1.30 -- recorded the upgrade GET as verb ``get``. Before ``get`` was added here,
# 5,962 of 5,962 execs in one CI run were dropped as unmapped and K8S-002 could never
# have fired on a real cluster. The subresource, not the verb, is what makes it an exec.
_EXEC_VERBS: frozenset[str] = frozenset({"create", "connect", "get"})


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
    """``allowed`` for a 2xx response, and for the 101 an exec upgrade succeeds with.

    A successful ``pods/exec`` is answered ``101 Switching Protocols``, not ``200``:
    the request became a streaming session. Reading 101 as "denied" -- which the 2xx
    test alone did -- would have recorded every successful shell into a container as a
    refused one, the exact inversion an exec-after-grant rule cannot survive.
    """
    status = item.get("responseStatus") or {}
    code = status.get("code") if isinstance(status, dict) else None
    try:
        code = int(code) if code is not None else None
    except (TypeError, ValueError):
        return "denied"
    if code is None:
        return "denied"
    return "allowed" if (200 <= code < 300 or code == 101) else "denied"


def _subject_identity(subject: dict[str, Any], item: dict[str, Any]) -> str:
    """The binding subject, spelled the way the audit log will later name it as a caller.

    A RoleBinding names a service account as ``{kind: ServiceAccount, name: ci-runner,
    namespace: ci}``. The same account, when it then does something, appears in
    ``user.username`` as ``system:serviceaccount:ci:ci-runner``. Those are one identity
    and the adapter is the only place that knows both spellings, so it emits the
    username form for ``target_actor`` -- otherwise a grant and the grantee's next
    action can never be joined, and K8S-002 is structurally blind. This project's own
    fixture had written the username form *into* the subject, which no real cluster
    does; it was corrected when this was found on real audit logs (M14 step 2).

    Users and groups are already spelled identically in both places and pass through.
    A subject with no namespace falls back to the binding's own namespace, which is
    what the API server does for a namespaced RoleBinding.
    """
    name = str(subject.get("name") or "")
    if subject.get("kind") != "ServiceAccount" or name.startswith("system:serviceaccount:"):
        return name
    object_ref = item.get("objectRef") or {}
    namespace = str(
        subject.get("namespace")
        or (object_ref.get("namespace") if isinstance(object_ref, dict) else "")
        or ""
    )
    return f"system:serviceaccount:{namespace}:{name}" if namespace else name


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
    names = [
        _subject_identity(s, item) for s in subjects if isinstance(s, dict) and s.get("name")
    ]
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
        directory: Directory containing audit log files (``*.json``, ``*.jsonl`` or
            ``*.log``). Two shapes are read: a top-level ``items`` array (an
            ``EventList``, what ``kubectl`` and most log shippers produce) and one JSON
            ``Event`` per line -- the raw ``--audit-log-path`` format, which is what
            every real apiserver log examined for Milestone 14 actually was (the
            Kubernetes CI logs and K8NTEXT both). A line that is not a JSON object is
            one :class:`~ath.telemetry.source.NormalizationIssue`, not a failed file.
            Unknown top-level keys on an event (K8NTEXT ships ``label`` and
            ``cplabel``) are ignored: this adapter never reads a label, by design.
        cluster: Cluster identifier used to synthesise the ``device`` column
            (``k8s:<cluster>``) -- Kubernetes audit events have no "host" concept, the
            same gap CloudTrail's ``aws:<account>/<region>`` closes for AWS.
    """

    directory: Path
    cluster: str = "default"
    name: str = SOURCE_NAME

    def load(self) -> SourceLoadResult:
        if not self.directory.is_dir():
            raise FileNotFoundError(
                f"No Kubernetes audit *.json, *.jsonl or *.log files found in "
                f"{self.directory}. Expected an EventList ('items' array) or one "
                "audit Event per line."
            )
        files = sorted(
            p for p in self.directory.iterdir()
            if p.is_file() and p.suffix.lower() in (".json", ".jsonl", ".log")
        )
        if not files:
            raise FileNotFoundError(
                f"No Kubernetes audit *.json, *.jsonl or *.log files found in "
                f"{self.directory}. Expected an EventList ('items' array) or one "
                "audit Event per line."
            )

        control_rows: list[dict[str, Any]] = []
        issues: list[NormalizationIssue] = []
        rows_read = 0

        for path in files:
            items, file_issues = _read_events(path)
            issues.extend(file_issues)
            if items is None:
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


def _read_events(path: Path) -> tuple[list[Any] | None, list[NormalizationIssue]]:
    """Return the audit events in ``path`` as a list, whichever of the two shapes it has.

    An ``EventList`` document is one JSON value; the raw apiserver format is one
    ``Event`` per line. The file is sniffed by parsing, not by extension: a ``.log``
    file holding an EventList and a ``.json`` file holding NDJSON are both real things.
    Line-level failures are reported per line so a single corrupt line in a 500 MB log
    does not cost the other 289,000.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    stripped = text.lstrip()
    if stripped.startswith("{") and '"items"' in stripped[:200]:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            items = payload.get("items")
            if isinstance(items, list):
                return items, []
            return None, [NormalizationIssue(
                event_type=EVENT_CONTROL,
                reason="file has no top-level 'items' array",
                raw_reference=path.name,
            )]

    items: list[Any] = []
    issues: list[NormalizationIssue] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError as exc:
            issues.append(NormalizationIssue(
                event_type=EVENT_CONTROL, reason=f"line is not valid JSON: {exc}",
                raw_reference=f"{path.name}#line={line_number}",
            ))
    if not items and issues:
        # Nothing parsed at all: report the file once rather than every line, since
        # the useful fact is "this is not an audit log", not 289,000 line errors.
        return None, [NormalizationIssue(
            event_type=EVENT_CONTROL, reason="file is not valid JSON (neither an "
            "EventList nor one Event per line)", raw_reference=path.name,
        )]
    return items, issues


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
        # The canonical action, not the HTTP-shaped audit verb: the same shell into a
        # container is logged as ``create``, ``connect`` or ``get`` depending on client
        # and server version, and the CloudTrail adapter already canonicalises
        # (``AttachUserPolicy`` -> ``attach``). ``exec`` is the verb the schema names.
        verb = "exec"
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
