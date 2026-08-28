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

What does not map, and is deliberately dropped
-----------------------------------------------
**Management API calls** -- ``CreateAccessKey``, ``AttachUserPolicy``, ``StopLogging``
-- have no home in this schema, and the tempting mapping is actively harmful::

    process_name        = "CreateAccessKey"      # not a process
    parent_process_name = "iam.amazonaws.com"    # not a parent process
    process_id          = <invented>             # no such concept

Beyond being a bad analogy, it would corrupt the visibility model: filling the process
table would make :mod:`ath.environment.channels` report ``process_execution`` as
**available** for an environment with no endpoint telemetry whatsoever. The entire
point of that layer is to stop the system mistaking blindness for coverage, so an
adapter that manufactures false endpoint visibility to look more complete would defeat
it. These events are therefore reported as :class:`NormalizationIssue` -- counted,
explained, and visible -- rather than silently coerced or silently discarded.

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

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

from ath.logging_setup import get_logger
from ath.schema import EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS, TABLE_COLUMNS
from ath.telemetry.normalize import coerce_and_validate
from ath.telemetry.source import NormalizationIssue, SourceLoadResult, TelemetrySource

logger = get_logger(__name__)

SOURCE_NAME = "cloudtrail"

# Events that genuinely represent an authentication decision, and how to read the
# verdict from each. CloudTrail is not uniform about this: ConsoleLogin reports its
# outcome in `responseElements.ConsoleLogin`, while STS calls signal failure only by
# the presence of `errorCode`.
AUTH_EVENTS: frozenset[str] = frozenset(
    {"ConsoleLogin", "AssumeRole", "GetSessionToken", "GetFederationToken"}
)


@dataclass
class CloudTrailSource(TelemetrySource):
    """Read CloudTrail JSON files from a directory into canonical telemetry.

    Args:
        directory: Directory containing ``*.json`` CloudTrail files. Each is expected
            to hold a top-level ``Records`` array, which is the shape both the console
            export and the S3 delivery format use.
    """

    directory: Path
    name: str = SOURCE_NAME

    def load(self) -> SourceLoadResult:
        files = sorted(self.directory.glob("*.json"))
        if not files:
            raise FileNotFoundError(
                f"No CloudTrail *.json files found in {self.directory}. Expected files "
                "containing a top-level 'Records' array."
            )

        logon_rows: list[dict[str, Any]] = []
        issues: list[NormalizationIssue] = []
        rows_read = 0

        for path in files:
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                issues.append(NormalizationIssue(
                    event_type=EVENT_LOGON, reason=f"file is not valid JSON: {exc}",
                    raw_reference=path.name,
                ))
                continue

            records = payload.get("Records")
            if not isinstance(records, list):
                issues.append(NormalizationIssue(
                    event_type=EVENT_LOGON,
                    reason="file has no top-level 'Records' array",
                    raw_reference=path.name,
                ))
                continue

            for index, record in enumerate(records):
                rows_read += 1
                row, issue = _normalise_record(record, path.name, index)
                if issue is not None:
                    issues.append(issue)
                if row is not None:
                    logon_rows.append(row)

        # Mint ids after the fact so they are dense and unique by construction.
        for position, row in enumerate(logon_rows, start=1):
            row["event_id"] = f"cloudtrail-logon-{position:06d}"

        logons = pd.DataFrame(logon_rows, columns=list(TABLE_COLUMNS[EVENT_LOGON]))
        tables = {
            EVENT_PROCESS: _empty(EVENT_PROCESS),
            EVENT_NETWORK: _empty(EVENT_NETWORK),
            EVENT_LOGON: coerce_and_validate(logons, EVENT_LOGON),
        }

        logger.info(
            "CloudTrail import: %d record(s) read, %d authentication row(s) kept, "
            "%d unmapped", rows_read, len(logon_rows), len(issues),
        )
        return SourceLoadResult(tables=tables, issues=issues, rows_read=rows_read)


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
    """
    for key in ("userName",):
        value = identity.get(key)
        if value:
            return str(value)
    arn = identity.get("arn")
    if arn:
        return str(arn).rsplit("/", 1)[-1]
    session = identity.get("sessionContext", {}).get("sessionIssuer", {}).get("userName")
    return str(session) if session else ""


def _verdict(record: dict[str, Any]) -> str:
    """Read success/failure, accounting for CloudTrail's two different conventions."""
    if record.get("errorCode") or record.get("errorMessage"):
        return "failure"
    response = record.get("responseElements") or {}
    console = response.get("ConsoleLogin") if isinstance(response, dict) else None
    if isinstance(console, str):
        return "success" if console.lower() == "success" else "failure"
    return "success"


def _normalise_record(
    record: Any, file_name: str, index: int
) -> tuple[dict[str, Any] | None, NormalizationIssue | None]:
    """Turn one CloudTrail record into a canonical logon row, or explain why not."""
    if not isinstance(record, dict):
        return None, NormalizationIssue(
            event_type=EVENT_LOGON, reason="record is not a JSON object",
            raw_reference=f"{file_name}#record={index}",
        )

    event_name = str(record.get("eventName", ""))
    event_id = record.get("eventID", "?")
    reference = f"{file_name}#record={index}, eventID={event_id}"

    if event_name not in AUTH_EVENTS:
        # The documented gap, reported rather than forced. See the module docstring:
        # coercing these into the process table would manufacture endpoint visibility
        # this environment does not have.
        return None, NormalizationIssue(
            event_type=EVENT_LOGON, field="eventName", raw_reference=reference,
            reason=(
                f"{event_name or '<unnamed>'} is a management API call with no "
                "representation in the canonical schema (which models process, network "
                "and logon events only); mapping it to a process event would "
                "manufacture endpoint visibility that does not exist"
            ),
        )

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
