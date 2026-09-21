"""Windows event telemetry exported from Elasticsearch, in the HELK/OTRF field layout.

What this reads, and why it is not one dataset's adapter
--------------------------------------------------------
A large family of public Windows corpora is published as an Elasticsearch export: NDJSON
where each line is a search hit and the event itself sits under ``_source``, with fields
already flattened to the naming the HELK pipeline and the OTRF Security-Datasets project
use -- ``process_name``, ``process_parent_name``, ``user_account``, ``dst_ip_addr``,
``hash_sha256``. COMISET is one such corpus; OTRF's Mordor/Security-Datasets releases are
another, in the same shape. So this adapter is written against **the schema**, not against
a dataset, and the field map below is the whole of its dataset-specific knowledge.

Why it is separate from :mod:`ath.telemetry.winlogbeat_source`
--------------------------------------------------------------
Winlogbeat emits ECS: nested, dotted, ``process.parent.name``, with the raw Windows fields
preserved under ``winlog.event_data``. This layout is flat and differently named, and the
two are not variants of one another -- an adapter trying to serve both would be a pile of
``or`` fallbacks in which neither schema is stated clearly. Two small readers that each
say plainly what they expect are easier to argue with than one that guesses.

What it deliberately does not do
---------------------------------
No field here is invented. Where this layout carries no equivalent of a canonical
column -- there is no code-signing verdict anywhere in it, only a version-info company
string -- the column is left empty and the signature status is ``unknown``, exactly as
the Winlogbeat reader does. Manufacturing a "signed" verdict from a ``Company`` field
would be worse than having none, because a later rule would trust it.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

from ath.instance_identity import start_identity, sysmon_identity
from ath.logging_setup import get_logger
from ath.schema import (
    EVENT_CONTROL,
    EVENT_LOGON,
    EVENT_NETWORK,
    EVENT_PROCESS,
    SIG_UNKNOWN,
    TABLE_COLUMNS,
)
from ath.telemetry.admission import FileAdmission, admit_lines
from ath.telemetry.normalize import coerce_validate_and_quarantine, parse_event_time
from ath.telemetry.source import NormalizationIssue, SourceLoadResult, TelemetrySource
from ath.telemetry.winlogbeat_source import LOGON_FAILURE_REASONS

logger = get_logger(__name__)

SOURCE_NAME = "elastic_winevent"

# (channel, event_id) -> canonical table. A record outside this map is counted as
# unmapped rather than guessed at.
EVENT_ROUTING: dict[tuple[str, str], str] = {
    ("sysmon", "1"): EVENT_PROCESS,
    ("sysmon", "3"): EVENT_NETWORK,
    ("security", "4624"): EVENT_LOGON,
    ("security", "4625"): EVENT_LOGON,
}


def _text(value: Any) -> str:
    """Elastic writes an absent value as ``-`` about as often as it omits the key."""
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text in ("-", "null") else text


def _int_or_na(value: Any) -> Any:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return pd.NA


def _short_host(value: Any) -> str:
    """``desktop-4pvps6e.phoenix.local`` -> ``desktop-4pvps6e``.

    Hosts appear both fully qualified and short across these corpora, and correlation
    keys on the device name; leaving both forms in circulation would split one machine
    into two and quietly halve every per-host measurement.
    """
    return _text(value).split(".", 1)[0].lower()


def _account(record: dict[str, Any]) -> str:
    """The acting account, preferring the bare name over ``DOMAIN\\name``."""
    for key in ("user_name", "user_account", "TargetUserName", "SubjectUserName"):
        value = _text(record.get(key))
        if value:
            return value.split("\\")[-1].lower()
    return ""


def _timestamp(record: dict[str, Any]) -> Any:
    for key in ("event_original_time", "@timestamp", "event_recorded_time"):
        raw = record.get(key)
        if raw:
            stamp = parse_event_time(raw)
            if not pd.isna(stamp):
                return stamp
    return pd.NaT


TELEMETRY_NAME = "Elastic-exported Windows events"


def _unwrap(record: Any) -> Any:
    """Strip the Elasticsearch search-hit envelope, when the export still carries it.

    A raw dump keeps the event under ``_source`` with the channel only derivable from
    ``_index``; a prepared slice is already unwrapped. Doing this in one place means the
    admission sniff and the record loop judge the same shape -- otherwise a raw dump
    would be refused at the boundary for lacking fields that are one level down.
    """
    if isinstance(record, dict) and isinstance(record.get("_source"), dict):
        inner = dict(record["_source"])
        inner.setdefault("_doc_id", record.get("_id", ""))
        index = str(record.get("_index", ""))
        inner.setdefault("_channel", index.rsplit("-", 1)[0].split("winevent-")[-1])
        return inner
    return record


def _looks_like_record(record: Any) -> bool:
    """Does this object carry the fields that identify an Elastic Windows event?

    Exactly the fields :meth:`ElasticWinEventSource.load` reads first and cannot proceed
    without: ``event_id`` (with ``_channel``, the routing key in :data:`EVENT_ROUTING`)
    and one of the timestamp keys :func:`_timestamp` tries. Presence only -- a record
    carrying these keys with unusable values *is* this source's telemetry, and is refused
    one record at a time by :func:`_build`, which is a different fact with a different
    denominator.
    """
    if not isinstance(record, dict):
        return False
    if not _text(record.get("event_id")):
        return False
    return any(
        record.get(key)
        for key in ("_channel", "event_original_time", "@timestamp", "event_recorded_time")
    )


@dataclass
class ElasticWinEventSource(TelemetrySource):
    """Read an NDJSON slice of Elastic-exported Windows events into canonical telemetry.

    Args:
        directory: Directory of ``*.jsonl`` / ``*.json`` files. Each line is one event,
            already unwrapped from the ``_source`` envelope, carrying ``_channel``
            (``sysmon`` / ``security`` / ...) and ``event_id``.
        name: Source name recorded on every row's ``source`` column.
    """

    directory: Path
    name: str = SOURCE_NAME

    def load(self) -> SourceLoadResult:
        files = sorted(
            p for p in self.directory.iterdir()
            if p.is_file() and p.suffix.lower() in (".jsonl", ".json")
        ) if self.directory.is_dir() else []
        if not files:
            raise FileNotFoundError(
                f"No *.jsonl or *.json files in {self.directory}. Expected one "
                "Elastic-exported Windows event per line."
            )

        # Windows endpoint telemetry carries no control plane. The table is still
        # emitted, empty and schema-valid, so every consumer sees the same four tables
        # from every source rather than having to know which ones exist per adapter.
        rows: dict[str, list[dict[str, Any]]] = {
            EVENT_PROCESS: [], EVENT_NETWORK: [], EVENT_LOGON: [], EVENT_CONTROL: [],
        }
        issues: list[NormalizationIssue] = []
        unmapped: dict[str, int] = {}
        admissions: list[FileAdmission] = []
        rows_read = 0

        for path in files:
            # Shape first. A statistics sidecar written next to a slice is a *.json file
            # in this same directory, and reading its lines as events put 513 non-events
            # into this corpus' denominator before this boundary existed.
            admission, numbered = admit_lines(
                path.name, _open_lines(path), _looks_like_record,
                telemetry=TELEMETRY_NAME, unwrap=_unwrap,
            )
            admissions.append(admission)
            for line_number, record in _iter_records(path.name, numbered, issues):
                rows_read += 1
                channel = _text(record.get("_channel")).lower()
                event_id = _text(record.get("event_id"))
                table = EVENT_ROUTING.get((channel, event_id))
                if table is None:
                    key = f"{channel}/{event_id}"
                    unmapped[key] = unmapped.get(key, 0) + 1
                    continue

                reference = f"{path.name}:{record.get('_doc_id') or line_number}"
                row, issue = _build(record, table, reference, event_id, self.name)
                if issue is not None:
                    issues.append(issue)
                    continue
                rows[table].append(row)

        tables: dict[str, pd.DataFrame] = {}
        for event_type in rows:
            table, quarantined = coerce_validate_and_quarantine(
                pd.DataFrame(rows[event_type], columns=list(TABLE_COLUMNS[event_type])),
                event_type,
            )
            tables[event_type] = table
            issues.extend(quarantined)
        rejected = [a for a in admissions if not a.admitted]
        logger.info(
            "%s: %d file(s) admitted, %d rejected; %d record(s) read, %d kept, "
            "%d unmapped class(es)",
            self.name, len(admissions) - len(rejected), len(rejected), rows_read,
            sum(len(v) for v in rows.values()), len(unmapped),
        )
        for refusal in rejected:
            logger.warning("%s: %s", self.name, refusal)
        return SourceLoadResult(
            tables=tables, issues=issues, rows_read=rows_read, unmapped=unmapped,
            admitted_files=tuple(admissions),
        )


def _open_lines(path: Path) -> Iterator[str]:
    """Yield the file's raw lines one at a time, so a 2 GB slice never lands in memory."""
    with path.open(encoding="utf-8", errors="replace") as handle:
        yield from handle


def _iter_records(
    file_name: str,
    numbered_lines: Iterable[tuple[int, str]],
    issues: list[NormalizationIssue],
) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield ``(line_number, record)``, reporting unparseable lines as issues.

    Takes the numbered lines of an *admitted* file (see
    :func:`ath.telemetry.admission.admit_lines`) rather than opening one itself: a file
    the boundary refused must produce no issues at all, and the cleanest way to guarantee
    that is for this loop never to see its lines.

    A bad line inside an admitted file is one issue, not a crash: a truncated export is a
    fact about the world, and losing the other million events over it would be the wrong
    failure mode.
    """
    for line_number, line in numbered_lines:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError as exc:
            issues.append(NormalizationIssue(
                event_type=EVENT_PROCESS,
                reason=f"line is not valid JSON: {exc}",
                raw_reference=f"{file_name}:{line_number}",
            ))
            continue
        # An export that still carries the search-hit envelope is unwrapped so a raw
        # dump works as well as a prepared slice -- the same unwrap the boundary used.
        yield line_number, _unwrap(record)


def _core(
    record: dict[str, Any], event_type: str, reference: str, stamp: Any, source: str
) -> dict[str, Any]:
    return {
        "event_id": reference,
        "timestamp": stamp,
        "event_type": event_type,
        "device": _short_host(record.get("host_name")),
        "user": _account(record),
        "source": source,
        "source_ref": reference,
    }


def _build(
    record: dict[str, Any], table: str, reference: str, event_id: str, source: str
) -> tuple[dict[str, Any] | None, NormalizationIssue | None]:
    stamp = _timestamp(record)
    if pd.isna(stamp):
        return None, NormalizationIssue(
            event_type=table, field="event_original_time", raw_reference=reference,
            reason="event carries no parseable timestamp",
        )
    device = _short_host(record.get("host_name"))
    if not device:
        return None, NormalizationIssue(
            event_type=table, field="host_name", raw_reference=reference,
            reason="event names no host",
        )

    if table == EVENT_PROCESS:
        return _process_row(record, reference, stamp, source, device)
    if table == EVENT_NETWORK:
        return _network_row(record, reference, stamp, source)
    return _logon_row(record, reference, stamp, source, success=event_id == "4624")


def _process_row(record, reference, stamp, source, device):
    name = _text(record.get("process_name")).lower()
    if not name:
        name = _text(record.get("process_path")).replace("/", "\\").rsplit("\\", 1)[-1].lower()
    if not name:
        return None, NormalizationIssue(
            event_type=EVENT_PROCESS, field="process_name", raw_reference=reference,
            reason="process-create event names no image",
        )
    row = _core(record, EVENT_PROCESS, reference, stamp, source)
    row.update({
        "process_name": name,
        "process_id": _int_or_na(record.get("process_id")),
        "command_line": _text(record.get("CommandLine")),
        "parent_process_name": _text(record.get("process_parent_name")).lower(),
        "parent_process_id": _int_or_na(record.get("process_parent_id")),
        "file_path": _text(record.get("process_path")),
        "sha256": _text(record.get("hash_sha256")).lower(),
        # Version-info company, not a signature verdict. Status stays unknown for that
        # reason -- see the module docstring.
        "signer": _text(record.get("Company")),
        "signature_status": SIG_UNKNOWN,
        # Instance identity. This layout's pipeline renames Sysmon's ProcessGuid and
        # ParentProcessGuid to `process_guid` / `process_parent_guid` and strips the
        # braces (see the `general_rename-ProcessGuid` and `process_guid-cleanup`
        # stages in every COMISET record's own `etl_pipeline`), so the GUID arrives
        # as bare upper-case hex and is lower-cased by `sysmon_identity`.
        #
        # The fallback is a `start` key and is *only* legitimate here: every record
        # routed to this table is a process-create event (Sysmon 1 today, Security 4688
        # if EVENT_ROUTING ever carries it), so its event time IS the creation time of
        # the process it names. That is the one case invariant A permits deriving an
        # identity from an event's own timestamp.
        "process_guid": (
            sysmon_identity(record.get("process_guid"))
            or start_identity(device, record.get("process_id"), stamp)
        ),
        # No fallback for the parent: a process-create event records when the *child*
        # started and never when its creator did. 4688 in particular names the creator's
        # PID and nothing else about it, so an empty value here is the honest answer and
        # a `start` key built from this row's time would be a different process's.
        "parent_process_guid": sysmon_identity(record.get("process_parent_guid")),
    })
    return row, None


def _network_row(record, reference, stamp, source):
    remote_ip = _text(record.get("dst_ip_addr"))
    if not remote_ip:
        return None, NormalizationIssue(
            event_type=EVENT_NETWORK, field="dst_ip_addr", raw_reference=reference,
            reason="network-connection event names no destination",
        )
    initiated = _text(record.get("network_initiated")).lower()
    direction = "outbound" if initiated == "true" else ("inbound" if initiated == "false" else "")
    row = _core(record, EVENT_NETWORK, reference, stamp, source)
    row.update({
        "process_name": _text(record.get("process_name")).lower(),
        "process_id": _int_or_na(record.get("process_id")),
        # Sysmon writes ProcessGuid on event 3 as well as event 1, which is the whole
        # reason a network row can name a process instance at all. No fallback: this
        # event's time is when the socket opened, not when the process started.
        "process_guid": sysmon_identity(record.get("process_guid")),
        "remote_ip": remote_ip,
        "remote_port": _int_or_na(record.get("dst_port")),
        "protocol": _text(record.get("network_protocol")).lower(),
        "direction": direction,
        "remote_url": "",  # Sysmon 3 sees sockets, never URLs
    })
    return row, None


def _logon_row(record, reference, stamp, source, *, success: bool):
    user = _text(record.get("TargetUserName")).split("\\")[-1].lower()
    if not user:
        return None, NormalizationIssue(
            event_type=EVENT_LOGON, field="TargetUserName", raw_reference=reference,
            reason="logon event names no target account",
        )
    failure_reason = ""
    if not success:
        code = (_text(record.get("SubStatus")) or _text(record.get("Status"))).lower()
        if code in ("0x0", ""):
            code = _text(record.get("Status")).lower()
        failure_reason = LOGON_FAILURE_REASONS.get(code, code)
    row = _core(record, EVENT_LOGON, reference, stamp, source)
    row["user"] = user
    row.update({
        "logon_type": _int_or_na(record.get("logon_type")),
        "source_ip": _text(record.get("IpAddress")) or _text(record.get("src_ip_addr")),
        "source_device": _short_host(record.get("WorkstationName")),
        "action": "success" if success else "failure",
        "failure_reason": failure_reason,
    })
    return row, None
