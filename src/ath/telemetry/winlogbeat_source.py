"""Import Windows telemetry shipped by Winlogbeat in Elastic Common Schema (ECS) form.

Why a third Windows-shaped adapter
-----------------------------------
The synthetic generator and the Defender export both produce the three-table split the
canonical schema was modelled on. Winlogbeat is how most non-Microsoft SIEM pipelines
actually see a Windows estate: one NDJSON stream of *every* channel -- Sysmon, Security,
System, PowerShell -- with the fields Elastic's ECS 1.x mapping chose. That is the shape
of the DEDALE dataset (Winlogbeat 7.10.2, ECS 1.5.0), the first real multi-week Windows
corpus this project ingests, and the field names below were read off its records, not
recalled.

What maps
---------
Three event classes, chosen because they are the three canonical tables:

* **Sysmon event 1 (process create)** -> ``process``. ``process.name`` / ``pid`` /
  ``command_line`` / ``executable``, ``process.parent.*``, ``process.hash.sha256``,
  ``user.name``. ``signature_status`` is ``unknown``: Sysmon 1 carries version-info
  ``Company`` (a string the binary makes about itself), never an Authenticode verdict,
  and the two are not the same claim. ``signer`` carries ``Company`` for the same reason
  the Defender adapter carries ``ProcessVersionInfoCompanyName`` -- as a label, marked
  unverified.
* **Sysmon event 3 (network connection)** -> ``network``. ``destination.ip`` / ``port``,
  ``network.transport``, ``network.direction`` (Winlogbeat derives it from Sysmon's
  ``Initiated``), the owning ``process.name`` / ``pid``. No URL: Sysmon 3 sees sockets.
* **Security 4624 / 4625 (logon success / failure)** -> ``logon``. ``LogonType`` is the
  numeric Windows code the canonical schema already stores, so unlike the Defender
  adapter there is no string vocabulary to translate; ``IpAddress`` and
  ``WorkstationName`` are ``-`` when absent and become empty. 4625's ``SubStatus`` is
  translated for the handful of NTSTATUS codes an analyst actually reads and kept raw
  otherwise.

What does not map, and how it is reported
------------------------------------------
Everything else -- Sysmon 7/10/11/22/26, Security 4634/4672, PowerShell 4103/4104 -- is
a channel the canonical schema has no table for, not a malformed row. A real hour of a
30-client estate holds ~650,000 such events against ~3,000 process creates; one
:class:`~ath.telemetry.source.NormalizationIssue` per row would cost more memory than
the telemetry. They are counted per ``channel:event_id`` in
:attr:`~ath.telemetry.source.SourceLoadResult.unmapped` and still add up to
``rows_dropped``. Rows in a *mapped* class that fail to normalise (no timestamp, no
process name) are per-row issues as everywhere else.

Provenance
----------
``source_ref`` is ``host=<host.name>;channel=<winlog.channel>;record_id=<winlog.record_id>;
File=<file>``. That triple is how DEDALE's own label files identify an event, which is
what lets :mod:`ath.evaluation.external_labels` resolve them without this adapter ever
reading a label.

Input forms
-----------
``*.jsonl`` / ``*.json`` / ``*.ndjson`` NDJSON, and ``*.jsonl.bz2``. The bz2 files inside
DEDALE's archive are zip-deflated on top of bz2; a file that does not start with the bz2
magic is inflated first, so the bytes fetched from the archive can be read as they are.
"""

from __future__ import annotations

import bz2
import json
import zlib
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

from ath.logging_setup import get_logger
from ath.schema import (
    EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS, SIG_UNKNOWN, TABLE_COLUMNS,
)
from ath.telemetry.admission import FileAdmission, admit_lines
from ath.telemetry.normalize import coerce_and_validate, coerce_validate_and_quarantine
from ath.telemetry.source import NormalizationIssue, SourceLoadResult, TelemetrySource

logger = get_logger(__name__)

SOURCE_NAME = "winlogbeat"

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SECURITY_CHANNEL = "Security"

# NTSTATUS sub-status codes on 4625 that an analyst reads by name. Anything else is kept
# as its raw hex so it is never silently lumped into "bad password".
LOGON_FAILURE_REASONS: dict[str, str] = {
    "0xc000006a": "bad_password",
    "0xc0000064": "unknown_user",
    "0xc0000234": "account_locked",
    "0xc0000072": "account_disabled",
    "0xc000006f": "outside_logon_hours",
    "0xc0000070": "workstation_restriction",
    "0xc0000193": "account_expired",
    "0xc0000071": "password_expired",
    "0xc000015b": "logon_type_not_granted",
}


def _get(record: dict[str, Any], dotted: str, default: Any = None) -> Any:
    """``record["a"]["b"]["c"]`` for ``"a.b.c"``, tolerating missing levels."""
    current: Any = record
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def _dash_empty(value: Any) -> str:
    """Windows writes ``-`` for "no value"; the canonical schema writes ``""``."""
    text = str(value) if value is not None else ""
    return "" if text in ("-", "") else text


def _short_host(record: dict[str, Any]) -> str:
    """``CLIENT7`` from ``CLIENT7.breach.local``; the synthetic and Defender data use short names."""
    name = str(_get(record, "host.name") or _get(record, "agent.hostname") or _get(record, "winlog.computer_name") or "")
    return name.split(".", 1)[0]


def _int_or_na(value: Any) -> Any:
    try:
        return int(value)
    except (TypeError, ValueError):
        return pd.NA


def _open_lines(path: Path) -> Iterator[str]:
    """Yield decoded lines from NDJSON, bz2 NDJSON, or zip-deflated bz2 NDJSON."""
    if path.name.lower().endswith(".bz2"):
        raw = path.read_bytes()
        if not raw.startswith(b"BZh"):
            raw = zlib.decompressobj(-15).decompress(raw)
        text = bz2.decompress(raw).decode("utf-8", errors="replace")
        yield from text.splitlines()
        return
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            yield line.rstrip("\n")


TELEMETRY_NAME = "Winlogbeat ECS Windows events"


def _looks_like_record(record: Any) -> bool:
    """Does this object carry the fields that identify a Winlogbeat ECS event?

    Exactly the fields :meth:`WinlogbeatSource.load` reads first: the ``winlog`` object
    (whose ``channel`` and ``event_id`` are the routing key) or ECS's ``event.code``
    fallback, plus the ``@timestamp`` :func:`_timestamp` requires. Presence only: a
    record with these keys and unusable values is Winlogbeat telemetry this adapter
    cannot normalise, which is a per-record issue, not a statement about the file.
    """
    if not isinstance(record, dict):
        return False
    if not isinstance(record.get("winlog"), dict) and _get(record, "event.code") is None:
        return False
    return bool(record.get("@timestamp"))


@dataclass
class WinlogbeatSource(TelemetrySource):
    """Read Winlogbeat ECS NDJSON files from a directory into canonical telemetry.

    Args:
        directory: Directory of ``*.jsonl`` / ``*.json`` / ``*.ndjson`` / ``*.jsonl.bz2``
            files, one ECS event per line.
    """

    directory: Path
    name: str = SOURCE_NAME

    def load(self) -> SourceLoadResult:
        if not self.directory.is_dir():
            raise FileNotFoundError(
                f"No Winlogbeat *.jsonl / *.json / *.ndjson / *.jsonl.bz2 files found in "
                f"{self.directory}."
            )
        files = sorted(
            p for p in self.directory.iterdir()
            if p.is_file() and p.name.lower().endswith(
                (".jsonl", ".json", ".ndjson", ".jsonl.bz2", ".json.bz2", ".ndjson.bz2")
            )
        )
        if not files:
            raise FileNotFoundError(
                f"No Winlogbeat *.jsonl / *.json / *.ndjson / *.jsonl.bz2 files found in "
                f"{self.directory}."
            )

        process_rows: list[dict[str, Any]] = []
        network_rows: list[dict[str, Any]] = []
        logon_rows: list[dict[str, Any]] = []
        issues: list[NormalizationIssue] = []
        unmapped: Counter[str] = Counter()
        admissions: list[FileAdmission] = []
        rows_read = 0

        for path in files:
            # Shape first: a manifest or index file written beside an export matches
            # these extensions too, and its lines are not events.
            admission, numbered = admit_lines(
                path.name, _open_lines(path), _looks_like_record,
                telemetry=TELEMETRY_NAME,
            )
            admissions.append(admission)
            for line_number, line in numbered:
                if not line.strip():
                    continue
                rows_read += 1
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    issues.append(NormalizationIssue(
                        event_type=EVENT_PROCESS, reason=f"line is not valid JSON: {exc}",
                        raw_reference=f"{path.name}#line={line_number}",
                    ))
                    continue
                if not isinstance(record, dict):
                    issues.append(NormalizationIssue(
                        event_type=EVENT_PROCESS, reason="line is not a JSON object",
                        raw_reference=f"{path.name}#line={line_number}",
                    ))
                    continue

                channel = str(_get(record, "winlog.channel") or "")
                event_id = _int_or_na(_get(record, "winlog.event_id", _get(record, "event.code")))
                reference = _reference(record, path.name)

                if channel == SYSMON_CHANNEL and event_id == 1:
                    row, issue = _process_row(record, reference)
                    target = process_rows
                elif channel == SYSMON_CHANNEL and event_id == 3:
                    row, issue = _network_row(record, reference)
                    target = network_rows
                elif channel == SECURITY_CHANNEL and event_id in (4624, 4625):
                    row, issue = _logon_row(record, reference, success=(event_id == 4624))
                    target = logon_rows
                else:
                    unmapped[f"{channel or '<no channel>'}:{event_id if event_id is not pd.NA else '?'}"] += 1
                    continue

                if issue is not None:
                    issues.append(issue)
                if row is not None:
                    target.append(row)

        for prefix, rows in (("process", process_rows), ("network", network_rows), ("logon", logon_rows)):
            for position, row in enumerate(rows, start=1):
                row["event_id"] = f"wlb-{prefix}-{position:07d}"

        tables: dict[str, pd.DataFrame] = {
            EVENT_CONTROL: coerce_and_validate(
                pd.DataFrame(columns=list(TABLE_COLUMNS[EVENT_CONTROL])), EVENT_CONTROL,
            ),
        }
        for event_type, built in (
            (EVENT_PROCESS, process_rows),
            (EVENT_NETWORK, network_rows),
            (EVENT_LOGON, logon_rows),
        ):
            table, quarantined = coerce_validate_and_quarantine(
                pd.DataFrame(built, columns=list(TABLE_COLUMNS[event_type])), event_type,
            )
            tables[event_type] = table
            issues.extend(quarantined)
        rejected = [a for a in admissions if not a.admitted]
        logger.info(
            "Winlogbeat import: %d file(s) admitted, %d rejected; %d line(s) read, "
            "%d process + %d network + %d logon row(s) kept, %d issue(s), %d unmapped "
            "across %d class(es)",
            len(admissions) - len(rejected), len(rejected), rows_read,
            len(process_rows), len(network_rows), len(logon_rows), len(issues),
            sum(unmapped.values()), len(unmapped),
        )
        for refusal in rejected:
            logger.warning("Winlogbeat import: %s", refusal)
        return SourceLoadResult(
            tables=tables, issues=issues, rows_read=rows_read, unmapped=dict(unmapped),
            admitted_files=tuple(admissions),
        )


def _reference(record: dict[str, Any], file_name: str) -> str:
    return (
        f"host={_get(record, 'host.name') or ''};channel={_get(record, 'winlog.channel') or ''};"
        f"record_id={_get(record, 'winlog.record_id') if _get(record, 'winlog.record_id') is not None else ''};"
        f"File={file_name}"
    )


def _timestamp(record: dict[str, Any], reference: str, event_type: str) -> tuple[Any, NormalizationIssue | None]:
    raw = record.get("@timestamp", "")
    stamp = pd.to_datetime(raw, utc=True, errors="coerce")
    if pd.isna(stamp):
        return None, NormalizationIssue(
            event_type=event_type, field="@timestamp", raw_reference=reference,
            reason=f"unparseable timestamp: {raw!r}",
        )
    return stamp, None


def _core(record: dict[str, Any], reference: str, event_type: str, stamp: Any, user: str) -> dict[str, Any]:
    return {
        "event_id": "",  # assigned by the caller, densely and uniquely
        "timestamp": stamp,
        "event_type": event_type,
        "device": _short_host(record),
        "user": user,
        "source": SOURCE_NAME,
        "source_ref": reference,
    }


def _process_row(record: dict[str, Any], reference: str) -> tuple[dict[str, Any] | None, NormalizationIssue | None]:
    stamp, issue = _timestamp(record, reference, EVENT_PROCESS)
    if issue is not None:
        return None, issue
    name = str(_get(record, "process.name") or "")
    if not name:
        executable = str(_get(record, "process.executable") or "")
        name = executable.replace("/", "\\").rsplit("\\", 1)[-1]
    if not name:
        return None, NormalizationIssue(
            event_type=EVENT_PROCESS, field="process.name", raw_reference=reference,
            reason="process-create event names no image",
        )
    row = _core(record, reference, EVENT_PROCESS, stamp, str(_get(record, "user.name") or ""))
    row.update({
        "process_name": name,
        "process_id": _int_or_na(_get(record, "process.pid")),
        "command_line": str(_get(record, "process.command_line") or ""),
        "parent_process_name": str(_get(record, "process.parent.name") or ""),
        "parent_process_id": _int_or_na(_get(record, "process.parent.pid")),
        "file_path": str(_get(record, "process.executable") or ""),
        "sha256": str(_get(record, "process.hash.sha256") or _get(record, "hash.sha256") or "").lower(),
        # Version-info company, not a signature. Marked unknown for exactly that reason.
        "signer": _dash_empty(_get(record, "winlog.event_data.Company")),
        "signature_status": SIG_UNKNOWN,
    })
    return row, None


def _network_row(record: dict[str, Any], reference: str) -> tuple[dict[str, Any] | None, NormalizationIssue | None]:
    stamp, issue = _timestamp(record, reference, EVENT_NETWORK)
    if issue is not None:
        return None, issue
    remote_ip = str(_get(record, "destination.ip") or _get(record, "winlog.event_data.DestinationIp") or "")
    if not remote_ip:
        return None, NormalizationIssue(
            event_type=EVENT_NETWORK, field="destination.ip", raw_reference=reference,
            reason="network-connection event names no destination",
        )
    direction = str(_get(record, "network.direction") or "").lower()
    if direction not in ("outbound", "inbound"):
        initiated = str(_get(record, "winlog.event_data.Initiated") or "").lower()
        direction = "outbound" if initiated == "true" else ("inbound" if initiated == "false" else "")
    row = _core(record, reference, EVENT_NETWORK, stamp, str(_get(record, "user.name") or ""))
    row.update({
        "process_name": str(_get(record, "process.name") or ""),
        "process_id": _int_or_na(_get(record, "process.pid")),
        "remote_ip": remote_ip,
        "remote_port": _int_or_na(_get(record, "destination.port") or _get(record, "winlog.event_data.DestinationPort")),
        "protocol": str(_get(record, "network.transport") or _get(record, "winlog.event_data.Protocol") or "").lower(),
        "direction": direction,
        "remote_url": "",  # Sysmon 3 sees sockets, never URLs
    })
    return row, None


def _logon_row(record: dict[str, Any], reference: str, *, success: bool) -> tuple[dict[str, Any] | None, NormalizationIssue | None]:
    stamp, issue = _timestamp(record, reference, EVENT_LOGON)
    if issue is not None:
        return None, issue
    data = _get(record, "winlog.event_data") or {}
    user = _dash_empty(data.get("TargetUserName"))
    if not user:
        return None, NormalizationIssue(
            event_type=EVENT_LOGON, field="winlog.event_data.TargetUserName", raw_reference=reference,
            reason="logon event names no target account",
        )
    logon_type = _int_or_na(data.get("LogonType"))
    failure_reason = ""
    if not success:
        sub_status = _dash_empty(data.get("SubStatus")).lower()
        status = _dash_empty(data.get("Status")).lower()
        code = sub_status or status
        failure_reason = LOGON_FAILURE_REASONS.get(code, code)
    row = _core(record, reference, EVENT_LOGON, stamp, user)
    row.update({
        "logon_type": logon_type,
        "source_ip": _dash_empty(data.get("IpAddress")),
        "source_device": _dash_empty(data.get("WorkstationName")),
        "action": "success" if success else "failure",
        "failure_reason": failure_reason,
    })
    return row, None
