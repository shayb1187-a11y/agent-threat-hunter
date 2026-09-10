"""Import AWS CloudTrail management events.

This adapter exists to stress-test the canonical schema against telemetry it was not
designed around. The Defender adapter proved the ``TelemetrySource`` seam works for a
*second Windows endpoint product*; that is a much weaker claim than it looks, because
Defender's advanced-hunting tables are the shape the canonical schema was modelled on.
CloudTrail is genuinely different, and the useful output of this module is as much the
**documented failure to map** as the mapping itself.

What maps cleanly
-----------------
**Authentication.** ``ConsoleLogin``, ``AssumeRole``, ``GetSessionToken`` and
``GetFederationToken`` are recognisably logon events: a principal, a source address, a
timestamp, and a success/failure verdict. These become canonical logon rows, and
``ATH-005`` (failed-logon burst followed by success) then fires on them **with no
change to the rule** -- because it keys on ``action``, ``user`` and ``source_ip`` and
never reads a Windows-specific field.

What now maps to the control-plane table
------------------------------------------
**Management API calls** -- ``CreateAccessKey``, ``AttachUserPolicy``, ``PutUserPolicy``,
``StopLogging``, ``DeleteTrail`` -- used to have no home in this schema, and the tempting
mapping was actively harmful::

    process_name        = "CreateAccessKey"      # not a process
    parent_process_name = "iam.amazonaws.com"    # not a parent process
    process_id          = <invented>             # no such concept

Beyond being a bad analogy, it would have corrupted the visibility model: filling the
process table would make :mod:`ath.environment.channels` report ``process_execution`` as
**available** for an environment with no endpoint telemetry whatsoever.

``ath.schema.EVENT_CONTROL`` exists precisely so this does not happen: an actor performs
a verb on a resource, allowed or denied -- the same shape AWS management events and
Kubernetes audit events both have, without borrowing endpoint vocabulary for either.
:data:`MANAGEMENT_EVENTS` names exactly the calls this adapter maps; anything else is
still reported as a :class:`NormalizationIssue` rather than silently coerced -- mapping
every possible AWS API call is not this project's goal, and an unmapped call staying
visibly unmapped is the honest outcome for the vast majority of CloudTrail's surface this
adapter does not attempt.

**Actor vs. target.** A grant-shaped call -- ``AttachUserPolicy``, ``PutUserPolicy`` --
names a *beneficiary* (the ``userName``/``roleName`` parameter) that is frequently a
different identity from the caller (``userIdentity``) making the API call: an
administrator attaching a policy to someone else's account is the normal case, not the
exception. ``actor`` is always the caller; ``target_actor`` is the beneficiary, left
empty for calls that grant nothing to a distinct identity (``StopLogging``,
``DeleteTrail``). Conflating the two would make a privilege-escalation chain match the
wrong identity's later activity -- see ``ath.hunting.rules.aws_rules``.

**Network flow.** CloudTrail records the *caller's* address, not connections a workload
opened. Mapping ``sourceIPAddress`` into the network table would describe traffic that
was never observed.

``logon_type`` has no cloud equivalent
---------------------------------------
The canonical schema stores the numeric **Windows** logon type. There is no such thing
for a console login, so this adapter leaves it null rather than inventing a code. That
is not a gap to paper over: it is why ``ATH-006`` (which infers host ownership from
interactive-vs-network logon types) correctly declines to fire here, while ``ATH-005``
correctly does. A forced value would have silently switched that off.

``device`` is a synthesised account/region identifier
------------------------------------------------------
"Host" is not a natural concept in control-plane telemetry -- an API call happens to an
*account*, not on a machine. Rows carry ``aws:<accountId>/<region>`` so downstream code
that groups by device still works, but the environment model will correctly classify it
as an unknown role: no interactive session, no inbound authentication, because neither
concept applies.
"""

from __future__ import annotations

import gzip
import json
import tarfile
from collections.abc import Iterator
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

SOURCE_NAME = "cloudtrail"
# Distinct provenance value for management-plane rows on the control table, so
# CLOUD_CONTROL_PLANE (authentication) and CLOUD_MANAGEMENT_ACTIVITY (everything below)
# stay measurably different channels -- see ath.environment.channels.
MANAGEMENT_SOURCE_NAME = "cloudtrail_mgmt"

# Events that genuinely represent an authentication decision, and how to read the
# verdict from each. CloudTrail is not uniform about this: ConsoleLogin reports its
# outcome in `responseElements.ConsoleLogin`, while STS calls signal failure only by
# the presence of `errorCode`.
AUTH_EVENTS: frozenset[str] = frozenset(
    {"ConsoleLogin", "AssumeRole", "GetSessionToken", "GetFederationToken"}
)


@dataclass(frozen=True)
class _ManagementEventSpec:
    """How to read one management-API event name into a control-plane row."""

    verb: str
    resource_type: str
    # Field in `requestParameters` naming the beneficiary identity, if any -- e.g.
    # AttachUserPolicy's `userName`. None for calls with no target identity.
    target_field: str | None = None
    # Field naming the specific role/policy granted, if any.
    role_field: str | None = None


# The management-API surface this adapter maps. Deliberately small: covers exactly what
# ath.hunting.rules.aws_rules needs (a policy-grant -> access-key-creation escalation
# chain, and logging tampering), not an attempt at full CloudTrail coverage. Anything
# else stays an unmapped NormalizationIssue, same as before this table existed.
MANAGEMENT_EVENTS: dict[str, _ManagementEventSpec] = {
    "AttachUserPolicy": _ManagementEventSpec(
        verb="attach", resource_type="iam:user-policy",
        target_field="userName", role_field="policyArn",
    ),
    "PutUserPolicy": _ManagementEventSpec(
        verb="attach", resource_type="iam:user-inline-policy",
        target_field="userName", role_field="policyName",
    ),
    "CreateAccessKey": _ManagementEventSpec(
        verb="create", resource_type="iam:access-key",
        target_field="userName",  # absent when a caller creates their own key
    ),
    "StopLogging": _ManagementEventSpec(verb="stop", resource_type="cloudtrail:trail"),
    "DeleteTrail": _ManagementEventSpec(verb="delete", resource_type="cloudtrail:trail"),
}


@dataclass
class CloudTrailSource(TelemetrySource):
    """Read CloudTrail JSON files from a directory into canonical telemetry.

    Args:
        directory: Directory containing CloudTrail files. Each is expected to hold a
            top-level ``Records`` array, which is the shape both the console export and
            the S3 delivery format use. Three on-disk forms are read, because that is
            how CloudTrail actually arrives: plain ``*.json``, the gzipped
            ``*.json.gz`` that S3 delivery writes per hour, and ``*.tar`` bundles of
            either (how public research dumps such as flaws.cloud are distributed).
            Nothing is extracted to disk; members are decoded in memory one at a time.
    """

    directory: Path
    name: str = SOURCE_NAME

    def load(self) -> SourceLoadResult:
        if not self.directory.is_dir():
            raise FileNotFoundError(
                f"No CloudTrail *.json, *.json.gz or *.tar files found in "
                f"{self.directory}. Expected files containing a top-level 'Records' "
                "array."
            )
        files = sorted(
            p for p in self.directory.iterdir()
            if p.is_file() and _classify(p.name) is not None
        )
        if not files:
            raise FileNotFoundError(
                f"No CloudTrail *.json, *.json.gz or *.tar files found in "
                f"{self.directory}. Expected files containing a top-level 'Records' "
                "array."
            )

        logon_rows: list[dict[str, Any]] = []
        control_rows: list[dict[str, Any]] = []
        issues: list[NormalizationIssue] = []
        rows_read = 0

        for file_name, payload_or_issue in _iter_payloads(files):
            if isinstance(payload_or_issue, NormalizationIssue):
                issues.append(payload_or_issue)
                continue
            payload = payload_or_issue

            records = payload.get("Records") if isinstance(payload, dict) else None
            if not isinstance(records, list):
                issues.append(NormalizationIssue(
                    event_type=EVENT_LOGON,
                    reason="file has no top-level 'Records' array",
                    raw_reference=file_name,
                ))
                continue

            for index, record in enumerate(records):
                rows_read += 1
                event_name = record.get("eventName", "") if isinstance(record, dict) else ""

                if event_name in AUTH_EVENTS:
                    row, issue = _normalise_auth_record(record, file_name, index)
                    target = logon_rows
                elif event_name in MANAGEMENT_EVENTS:
                    row, issue = _normalise_control_record(record, file_name, index)
                    target = control_rows
                else:
                    row, issue = None, _unmapped_issue(record, file_name, index)

                if issue is not None:
                    issues.append(issue)
                if row is not None:
                    target.append(row)

        # Mint ids after the fact so they are dense and unique by construction.
        for position, row in enumerate(logon_rows, start=1):
            row["event_id"] = f"cloudtrail-logon-{position:06d}"
        for position, row in enumerate(control_rows, start=1):
            row["event_id"] = f"cloudtrail-control-{position:06d}"

        logons = pd.DataFrame(logon_rows, columns=list(TABLE_COLUMNS[EVENT_LOGON]))
        controls = pd.DataFrame(control_rows, columns=list(TABLE_COLUMNS[EVENT_CONTROL]))
        tables = {
            EVENT_PROCESS: _empty(EVENT_PROCESS),
            EVENT_NETWORK: _empty(EVENT_NETWORK),
            EVENT_LOGON: coerce_and_validate(logons, EVENT_LOGON),
            EVENT_CONTROL: coerce_and_validate(controls, EVENT_CONTROL),
        }

        logger.info(
            "CloudTrail import: %d record(s) read, %d authentication row(s) + %d "
            "management-activity row(s) kept, %d unmapped",
            rows_read, len(logon_rows), len(control_rows), len(issues),
        )
        return SourceLoadResult(tables=tables, issues=issues, rows_read=rows_read)


def _classify(name: str) -> str | None:
    """Which reader a file name needs, or ``None`` when it is not CloudTrail input."""
    lowered = name.lower()
    if lowered.endswith(".json.gz"):
        return "gzip"
    if lowered.endswith(".json"):
        return "json"
    if lowered.endswith(".tar"):
        return "tar"
    return None


def _decode(name: str, raw: bytes) -> tuple[Any, NormalizationIssue | None]:
    """Parse one CloudTrail document from bytes, gunzipping first when the name says so."""
    try:
        if _classify(name) == "gzip":
            raw = gzip.decompress(raw)
        return json.loads(raw.decode("utf-8")), None
    except (OSError, EOFError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, NormalizationIssue(
            event_type=EVENT_LOGON, reason=f"file is not valid JSON: {exc}",
            raw_reference=name,
        )


def _iter_payloads(files: list[Path]) -> Iterator[tuple[str, Any]]:
    """Yield ``(file_name, parsed_payload | NormalizationIssue)`` for every document.

    A tar member is named ``<tar>:<member>`` so ``source_ref`` still points at one
    specific record inside one specific archive; an archive that cannot be opened is
    one issue, not a crash, for the same reason a malformed row is.
    """
    for path in files:
        kind = _classify(path.name)
        if kind == "tar":
            try:
                with tarfile.open(path) as archive:
                    for member in archive:
                        if not member.isfile() or _classify(member.name) not in ("json", "gzip"):
                            continue
                        handle = archive.extractfile(member)
                        if handle is None:
                            continue
                        name = f"{path.name}:{member.name}"
                        payload, issue = _decode(member.name, handle.read())
                        yield name, (issue if issue is not None else payload)
            except tarfile.TarError as exc:
                yield path.name, NormalizationIssue(
                    event_type=EVENT_LOGON, reason=f"tar archive cannot be read: {exc}",
                    raw_reference=path.name,
                )
            continue
        payload, issue = _decode(path.name, path.read_bytes())
        yield path.name, (issue if issue is not None else payload)


def _empty(event_type: str) -> pd.DataFrame:
    """An empty, schema-valid table.

    Returned for process and network rather than omitted, so the loader and every
    downstream consumer see the same three tables regardless of source -- and so the
    visibility model measures those channels as genuinely absent rather than erroring.
    """
    return coerce_and_validate(
        pd.DataFrame(columns=list(TABLE_COLUMNS[event_type])), event_type
    )


def _principal(identity: dict[str, Any]) -> str:
    """Best available name for the acting principal.

    CloudTrail's ``userIdentity`` is a union type: an IAM user has ``userName``, an
    assumed role has only an ARN whose last segment is the session name, and a service
    principal may have neither. Preferring the specific over the generic keeps
    correlation working without inventing an identity where none was recorded.

    ``invokedBy`` is the last resort, not a guess: when an AWS service calls STS on the
    account's behalf (``userIdentity.type == "AWSService"``), CloudTrail records the
    service (``ec2.amazonaws.com``, ``config.amazonaws.com``) there and nowhere else.
    Measured on the flaws.cloud public trail before this fallback existed, 57,912
    authentication records -- 3% of the trail -- were dropped as unattributable for
    exactly this reason. The service name is kept verbatim, so a service-invoked
    failure burst is attributed to the service rather than hidden or attributed to a
    human.
    """
    for key in ("userName",):
        value = identity.get(key)
        if value:
            return str(value)
    arn = identity.get("arn")
    if arn:
        return str(arn).rsplit("/", 1)[-1]
    session = identity.get("sessionContext", {}).get("sessionIssuer", {}).get("userName")
    if session:
        return str(session)
    invoked_by = identity.get("invokedBy")
    return str(invoked_by) if invoked_by else ""


def _verdict(record: dict[str, Any]) -> str:
    """Read success/failure, accounting for CloudTrail's two different conventions."""
    if record.get("errorCode") or record.get("errorMessage"):
        return "failure"
    response = record.get("responseElements") or {}
    console = response.get("ConsoleLogin") if isinstance(response, dict) else None
    if isinstance(console, str):
        return "success" if console.lower() == "success" else "failure"
    return "success"


def _unmapped_issue(record: Any, file_name: str, index: int) -> NormalizationIssue:
    """Explain why a record matched neither the auth nor the management event set.

    This is now the small, honest remainder: this adapter maps the specific calls
    ``AUTH_EVENTS`` and ``MANAGEMENT_EVENTS`` name, not every possible CloudTrail
    ``eventName``. Anything else stays visibly unmapped rather than being coerced.
    """
    event_name = str(record.get("eventName", "")) if isinstance(record, dict) else ""
    event_id = record.get("eventID", "?") if isinstance(record, dict) else "?"
    reference = f"{file_name}#record={index}, eventID={event_id}"
    if not isinstance(record, dict):
        return NormalizationIssue(
            event_type=EVENT_CONTROL, reason="record is not a JSON object",
            raw_reference=f"{file_name}#record={index}",
        )
    return NormalizationIssue(
        event_type=EVENT_CONTROL, field="eventName", raw_reference=reference,
        reason=(
            f"{event_name or '<unnamed>'} is not one of the authentication or "
            "management-API calls this adapter maps (see AUTH_EVENTS / "
            "MANAGEMENT_EVENTS in ath.telemetry.cloudtrail_source)"
        ),
    )


def _normalise_auth_record(
    record: Any, file_name: str, index: int
) -> tuple[dict[str, Any] | None, NormalizationIssue | None]:
    """Turn one CloudTrail authentication record into a canonical logon row."""
    if not isinstance(record, dict):
        return None, NormalizationIssue(
            event_type=EVENT_LOGON, reason="record is not a JSON object",
            raw_reference=f"{file_name}#record={index}",
        )

    event_id = record.get("eventID", "?")
    reference = f"{file_name}#record={index}, eventID={event_id}"

    raw_time = record.get("eventTime", "")
    timestamp = pd.to_datetime(raw_time, utc=True, errors="coerce")
    if pd.isna(timestamp):
        return None, NormalizationIssue(
            event_type=EVENT_LOGON, field="eventTime", raw_reference=reference,
            reason=f"unparseable timestamp: {raw_time!r}",
        )

    identity = record.get("userIdentity") or {}
    user = _principal(identity if isinstance(identity, dict) else {})
    if not user:
        return None, NormalizationIssue(
            event_type=EVENT_LOGON, field="userIdentity", raw_reference=reference,
            reason=(
                "no usable principal name; an authentication event that cannot be "
                "attributed to an identity would correlate against nothing"
            ),
        )

    account = str(record.get("recipientAccountId") or identity.get("accountId") or "unknown")
    region = str(record.get("awsRegion") or "unknown")
    verdict = _verdict(record)

    return {
        "event_id": "",  # assigned by the caller, densely and uniquely
        "timestamp": timestamp,
        "event_type": EVENT_LOGON,
        # "Host" is not a cloud concept; see the module docstring.
        "device": f"aws:{account}/{region}",
        "user": user,
        "source": SOURCE_NAME,
        "source_ref": f"eventID={event_id};File={file_name}",
        # Deliberately null: there is no Windows logon type for a console login, and
        # inventing one would silently re-enable ATH-006's ownership inference on
        # telemetry where the concept of an interactive host session does not exist.
        "logon_type": pd.NA,
        "source_ip": str(record.get("sourceIPAddress") or ""),
        "source_device": "",  # CloudTrail records no originating hostname
        "action": verdict,
        "failure_reason": str(record.get("errorMessage") or record.get("errorCode") or "")
        if verdict == "failure" else "",
    }, None


def _normalise_control_record(
    record: Any, file_name: str, index: int
) -> tuple[dict[str, Any] | None, NormalizationIssue | None]:
    """Turn one CloudTrail management-API record into a canonical control row.

    ``record["eventName"]`` is guaranteed to be a key of :data:`MANAGEMENT_EVENTS` by
    the caller's dispatch -- this function only interprets it.
    """
    event_id = record.get("eventID", "?")
    event_name = str(record.get("eventName", ""))
    reference = f"{file_name}#record={index}, eventID={event_id}"
    spec = MANAGEMENT_EVENTS[event_name]

    raw_time = record.get("eventTime", "")
    timestamp = pd.to_datetime(raw_time, utc=True, errors="coerce")
    if pd.isna(timestamp):
        return None, NormalizationIssue(
            event_type=EVENT_CONTROL, field="eventTime", raw_reference=reference,
            reason=f"unparseable timestamp: {raw_time!r}",
        )

    identity = record.get("userIdentity") or {}
    actor = _principal(identity if isinstance(identity, dict) else {})
    if not actor:
        return None, NormalizationIssue(
            event_type=EVENT_CONTROL, field="userIdentity", raw_reference=reference,
            reason=(
                "no usable principal name; a control-plane action that cannot be "
                "attributed to a caller would correlate against nothing"
            ),
        )

    params = record.get("requestParameters") or {}
    params = params if isinstance(params, dict) else {}

    # The beneficiary of a grant, as distinct from the caller. CreateAccessKey has no
    # explicit target when a caller creates their own key -- the beneficiary is then
    # the actor themself, not "no one", which matters for chaining it to a prior grant.
    target_actor = ""
    if spec.target_field:
        target_actor = str(params.get(spec.target_field) or "")
        if not target_actor and event_name == "CreateAccessKey":
            target_actor = actor

    role_ref = str(params.get(spec.role_field) or "") if spec.role_field else ""
    resource_name = target_actor or str(params.get("name") or "")

    account = str(record.get("recipientAccountId") or identity.get("accountId") or "unknown")
    region = str(record.get("awsRegion") or "unknown")
    verdict = _verdict(record)

    return {
        "event_id": "",  # assigned by the caller, densely and uniquely
        "timestamp": timestamp,
        "event_type": EVENT_CONTROL,
        "device": f"aws:{account}/{region}",  # "host" is not a cloud concept
        "user": target_actor or actor,
        "source": MANAGEMENT_SOURCE_NAME,
        "source_ref": f"eventID={event_id};File={file_name}",
        "actor": actor,
        "verb": spec.verb,
        "resource_type": spec.resource_type,
        "resource_name": resource_name,
        "resource_namespace": "",  # not a cloud concept
        "target_actor": target_actor,
        "role_ref": role_ref,
        "decision": "denied" if verdict == "failure" else "allowed",
        "source_ip": str(record.get("sourceIPAddress") or ""),
    }, None
