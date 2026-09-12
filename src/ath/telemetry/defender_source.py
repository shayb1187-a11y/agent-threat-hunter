"""Import real Microsoft Defender advanced-hunting exports.

Schema verified against Microsoft Learn (fetched directly, not from memory) on the date
this module was written:

* ``DeviceProcessEvents`` -- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table
* ``DeviceNetworkEvents`` -- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table
* ``DeviceLogonEvents``   -- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table

Two things worth knowing that are easy to get wrong
----------------------------------------------------
1. ``DeviceNetworkEvents`` has **no** ``AccountName`` column -- only
   ``InitiatingProcessAccountName``. Our own KQL files (``queries/ATH-003-*.kql``)
   already account for this; this adapter maps our ``user`` field for network events
   from ``InitiatingProcessAccountName`` for the same reason.
2. ``DeviceLogonEvents.LogonType`` is a **string**, and Microsoft's own documentation
   lists exactly five values: ``Interactive``, ``Remote interactive (RDP)``,
   ``Network``, ``Batch``, ``Service``. Our canonical schema stores logon type as the
   numeric Windows code (2/3/4/5/10) that Sysmon and Security-Event-Log-based
   telemetry use, so this adapter is the place that translates between the two
   vocabularies -- see :data:`LOGON_TYPE_STRING_TO_CODE`.

``ReportId`` is *not* a safe unique id on its own
---------------------------------------------------
Microsoft's own documentation for ``ReportId`` says it is "based on a repeating
counter" and "must be used in conjunction with the DeviceName and Timestamp columns" to
identify a unique event. Rather than reconstruct uniqueness from three fields, this
adapter mints its own ``event_id`` (guaranteed unique by construction, like the
synthetic generator's ``evt-NNNNNN``) and preserves the original ``ReportId`` --
alongside the source device, timestamp, and originating file -- in ``source_ref``,
so an analyst can still trace any finding back to the exact original Defender record.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

from ath.logging_setup import get_logger
from ath.schema import EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS, SIG_UNKNOWN
from ath.telemetry.admission import (
    ADMITTED,
    REASON_UNPARSEABLE,
    REASON_WRONG_SHAPE,
    REJECTED,
    FileAdmission,
)
from ath.telemetry.normalize import coerce_and_validate
from ath.telemetry.source import NormalizationIssue, SourceLoadResult, TelemetrySource

logger = get_logger(__name__)

SOURCE_NAME = "defender_export"

# Verified against learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table.
# Case-insensitive; Defender does not document a stable casing convention across export
# tools, and we would rather normalise generously than drop rows over capitalisation.
LOGON_TYPE_STRING_TO_CODE: dict[str, int] = {
    "interactive": 2,
    "network": 3,
    "batch": 4,
    "service": 5,
    "remote interactive (rdp)": 10,
    "remoteinteractive": 10,
    "remote interactive": 10,
    "rdp": 10,
}

# Verified ActionType values for DeviceLogonEvents' two possible outcomes.
LOGON_ACTION_TYPE_TO_ACTION: dict[str, str] = {
    "logonsuccess": "success",
    "logonfailed": "failure",
    "logonfailure": "failure",
}

# Column renames per table: Defender name -> our canonical name. Only columns our
# schema actually uses are mapped; everything else Defender exports (hashes, version
# info, signer info, session ids, ...) is simply not carried over -- this project's
# canonical schema does not model those fields, and mapping columns we would never read
# would only bloat the adapter for no benefit.
_PROCESS_RENAME: dict[str, str] = {
    "Timestamp": "timestamp",
    "DeviceName": "device",
    "AccountName": "user",
    "FileName": "process_name",
    "ProcessId": "process_id",
    "ProcessCommandLine": "command_line",
    "InitiatingProcessFileName": "parent_process_name",
    "InitiatingProcessId": "parent_process_id",
    "FolderPath": "file_path",
    # Process identity. `SHA256` and `ProcessVersionInfoCompanyName` are both columns of
    # DeviceProcessEvents, so they arrive with the row.
    #
    # Signature *status* deliberately does not appear here: Defender records it in the
    # separate DeviceFileCertificateInfo table, and a single-table export cannot carry
    # it. The adapter therefore leaves `signature_status` as `unknown` rather than
    # guessing -- "we did not evaluate the signature" and "the file is unsigned" support
    # completely different conclusions, and only one of them is evidence about the file.
    "SHA256": "sha256",
    "ProcessVersionInfoCompanyName": "signer",
}

_NETWORK_RENAME: dict[str, str] = {
    "Timestamp": "timestamp",
    "DeviceName": "device",
    "InitiatingProcessAccountName": "user",  # DeviceNetworkEvents has no AccountName
    "InitiatingProcessFileName": "process_name",
    "InitiatingProcessId": "process_id",
    "RemoteIP": "remote_ip",
    "RemotePort": "remote_port",
    "Protocol": "protocol",
    "RemoteUrl": "remote_url",
}

_LOGON_RENAME: dict[str, str] = {
    "Timestamp": "timestamp",
    "DeviceName": "device",
    "AccountName": "user",
    "FailureReason": "failure_reason",
    "RemoteDeviceName": "source_device",
    "RemoteIP": "source_ip",
}

REQUIRED_DEFENDER_COLUMNS: dict[str, tuple[str, ...]] = {
    EVENT_PROCESS: ("Timestamp", "DeviceName", "FileName"),
    EVENT_NETWORK: ("Timestamp", "DeviceName", "RemoteIP"),
    EVENT_LOGON: ("Timestamp", "DeviceName", "AccountName", "LogonType", "ActionType"),
}

TELEMETRY_NAME = "a Defender advanced-hunting export"


def _missing_identifying_columns(raw: pd.DataFrame, event_type: str) -> list[str]:
    """This adapter's recognition predicate, at header level rather than record level.

    A tabular export identifies itself by its **header**, not by its file name: the
    columns in :data:`REQUIRED_DEFENDER_COLUMNS` are the ones every downstream rename and
    every derived field read, and a CSV without them is not a Defender export of this
    table -- whatever ``*process*``/``*network*``/``*logon*`` happens to appear in its
    name. Returning the missing names rather than a bool so the refusal can say which
    columns it looked for, which is the difference between a usable report and "no".
    """
    return [c for c in REQUIRED_DEFENDER_COLUMNS[event_type] if c not in raw.columns]


def _read_export_file(path: Path) -> pd.DataFrame:
    """Read a Defender export in either CSV or JSON (array or NDJSON) format.

    Defender's "Export to CSV" and "Export to JSON" buttons in the Advanced Hunting UI
    produce, respectively, a plain comma-separated file and a JSON array of row
    objects; some automation pipelines instead emit newline-delimited JSON. All three
    are accepted.
    """
    if path.suffix.lower() == ".json":
        text = path.read_text(encoding="utf-8-sig")
        stripped = text.strip()
        try:
            records = json.loads(stripped)
            if isinstance(records, dict):
                records = [records]
        except json.JSONDecodeError:
            records = [json.loads(line) for line in stripped.splitlines() if line.strip()]
        return pd.DataFrame.from_records(records)

    return pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8-sig")


def _find_table_files(directory: Path, keyword: str) -> list[Path]:
    """Every file in ``directory`` whose name contains ``keyword`` (case-insensitive).

    All of them, not the first: a file name is a hint, and the header is the evidence.
    :meth:`DefenderExportSource.load` takes the first candidate whose header identifies
    it, so a statistics file called ``network_summary.csv`` sitting beside
    ``DeviceNetworkEvents.csv`` no longer displaces the export it describes.
    """
    return [
        candidate
        for candidate in sorted(directory.iterdir())
        if candidate.is_file()
        and keyword.lower() in candidate.name.lower()
        and candidate.suffix.lower() in (".csv", ".json")
    ]


@dataclass
class DefenderExportSource(TelemetrySource):
    """Reads a Microsoft Defender advanced-hunting export into canonical telemetry.

    Provide either a ``directory`` (files are discovered by name --
    ``*process*``/``*network*``/``*logon*``, case-insensitive) or explicit paths per
    table. A missing table is not an error: it becomes zero rows, exactly like a
    detection rule receiving an empty DataFrame, since a scoped export may legitimately
    cover only some tables.

    Attributes:
        directory: Directory to search for export files, when explicit paths are not given.
        process_path: Explicit path to a ``DeviceProcessEvents`` export.
        network_path: Explicit path to a ``DeviceNetworkEvents`` export.
        logon_path: Explicit path to a ``DeviceLogonEvents`` export.
    """

    directory: Path | None = None
    process_path: Path | None = None
    network_path: Path | None = None
    logon_path: Path | None = None
    name: str = SOURCE_NAME

    def _candidates(self, explicit: Path | None, keyword: str) -> list[Path]:
        if explicit is not None:
            return [explicit]
        if self.directory is not None:
            return _find_table_files(self.directory, keyword)
        return []

    def load(self) -> SourceLoadResult:
        candidates = {
            EVENT_PROCESS: self._candidates(self.process_path, "process"),
            EVENT_NETWORK: self._candidates(self.network_path, "network"),
            EVENT_LOGON: self._candidates(self.logon_path, "logon"),
        }

        tables: dict[str, pd.DataFrame] = {}
        issues: list[NormalizationIssue] = []
        admissions: list[FileAdmission] = []
        rows_read = 0

        for event_type, paths in candidates.items():
            admitted: tuple[Path, pd.DataFrame] | None = None
            for path in paths:
                admission, raw = _admit_export(path, event_type)
                admissions.append(admission)
                if admission.admitted and admitted is None and raw is not None:
                    admitted = (path, raw)

            if admitted is None:
                logger.info("No export file found for %s; treating as empty", event_type)
                tables[event_type] = _empty_canonical_frame(event_type)
                continue

            path, raw = admitted
            # Only now: a file the header did not identify contributes nothing to the
            # denominator, because it was never this export's telemetry to lose.
            rows_read += len(raw)
            df, table_issues = _normalize_table(raw, event_type, path.name)
            issues.extend(table_issues)
            tables[event_type] = coerce_and_validate(df, event_type)
            logger.info(
                "%s: %d/%d row(s) normalised from %s", event_type, len(df), len(raw), path.name
            )

        for refusal in (a for a in admissions if not a.admitted):
            logger.warning("Defender export: %s", refusal)
        return SourceLoadResult(
            tables=tables, issues=issues, ground_truth=None, rows_read=rows_read,
            admitted_files=tuple(admissions),
        )


def _empty_canonical_frame(event_type: str) -> pd.DataFrame:
    from ath.schema import TABLE_COLUMNS

    return coerce_and_validate(pd.DataFrame(columns=list(TABLE_COLUMNS[event_type])), event_type)


def _admit_export(path: Path, event_type: str) -> tuple[FileAdmission, pd.DataFrame | None]:
    """Read one candidate export and decide whether its header identifies it.

    The equivalent of :func:`ath.telemetry.admission.admit_lines` for a tabular file: the
    "first records" a CSV offers are its column names, so the sniff is the header and the
    predicate is :func:`_missing_identifying_columns`. A refused file yields no rows, no
    ``rows_read``, and no :class:`NormalizationIssue` -- the refusal itself is the report.
    """
    try:
        raw = _read_export_file(path)
    except Exception as exc:  # a non-tabular file with a matching name/extension
        return FileAdmission(
            path.name, REJECTED, f"{REASON_UNPARSEABLE}: {exc}", "", 0,
        ), None

    missing = _missing_identifying_columns(raw, event_type)
    if missing:
        return FileAdmission(
            path.name, REJECTED,
            f"{REASON_WRONG_SHAPE}: header carries no {', '.join(missing)}, so it is "
            f"not a Defender {event_type} export",
            TELEMETRY_NAME, len(raw),
        ), None
    return FileAdmission(
        path.name, ADMITTED,
        f"recognised as {TELEMETRY_NAME} for {event_type}: header carries "
        f"{', '.join(REQUIRED_DEFENDER_COLUMNS[event_type])}",
        TELEMETRY_NAME, len(raw),
    ), raw


def _normalize_table(
    raw: pd.DataFrame, event_type: str, file_name: str
) -> tuple[pd.DataFrame, list[NormalizationIssue]]:
    """Rename Defender columns, derive computed fields, and drop unparseable rows.

    Called only for a frame :func:`_admit_export` has already recognised, so the
    identifying columns are guaranteed present here -- the "is this a Defender export at
    all" question belongs to admission, one layer up, and asking it twice would put a
    refused file back into the issue list.
    """
    issues: list[NormalizationIssue] = []

    if event_type == EVENT_PROCESS:
        df, row_issues = _normalize_process(raw, file_name)
    elif event_type == EVENT_NETWORK:
        df, row_issues = _normalize_network(raw, file_name)
    else:
        df, row_issues = _normalize_logon(raw, file_name)

    issues.extend(row_issues)
    return df, issues


def _parse_timestamps(raw: pd.Series) -> tuple[pd.Series, pd.Series]:
    """Parse Defender's ISO-8601 timestamps; return (parsed, is_valid_mask)."""
    parsed = pd.to_datetime(raw, utc=True, format="mixed", errors="coerce")
    return parsed, parsed.notna()


def _base_frame(raw: pd.DataFrame, rename: dict[str, str], event_type: str) -> pd.DataFrame:
    """Apply the column rename and add the fields every canonical table needs."""
    df = raw.rename(columns=rename).copy()
    df["event_type"] = event_type
    df["source"] = SOURCE_NAME
    return df


def _normalize_process(
    raw: pd.DataFrame, file_name: str
) -> tuple[pd.DataFrame, list[NormalizationIssue]]:
    df = _base_frame(raw, _PROCESS_RENAME, EVENT_PROCESS)
    timestamps, valid = _parse_timestamps(df["timestamp"])
    df["timestamp"] = timestamps

    issues = [
        NormalizationIssue(
            event_type=EVENT_PROCESS, field="Timestamp",
            reason=f"unparseable timestamp: {raw.loc[i, 'Timestamp']!r}",
            raw_reference=f"{file_name}#row={i}, ReportId={raw.loc[i].get('ReportId', '?')}",
        )
        for i in df.index[~valid]
    ]
    df = df[valid].reset_index(drop=True)

    df["event_id"] = [f"defender-process-{n:06d}" for n in range(1, len(df) + 1)]
    df["source_ref"] = [
        f"ReportId={row.get('ReportId', '')};File={file_name}" for _, row in raw[valid].iterrows()
    ]
    # Identity columns, defaulted when the export did not include them. A scoped
    # advanced-hunting query commonly selects only a handful of columns, and an export
    # without `SHA256` is not malformed -- it simply carries less identity than a full
    # one. Absent is represented as empty, never as a fabricated value.
    for column in ("sha256", "signer"):
        if column not in df.columns:
            df[column] = ""

    # Signature status is never evaluated by this export, and says so explicitly.
    # Leaving it empty would let a downstream reader treat the blank as "unsigned",
    # which is a claim this data does not support.
    df["signature_status"] = SIG_UNKNOWN
    return df, issues


def _normalize_network(
    raw: pd.DataFrame, file_name: str
) -> tuple[pd.DataFrame, list[NormalizationIssue]]:
    df = _base_frame(raw, _NETWORK_RENAME, EVENT_NETWORK)
    timestamps, valid = _parse_timestamps(df["timestamp"])
    df["timestamp"] = timestamps

    issues = [
        NormalizationIssue(
            event_type=EVENT_NETWORK, field="Timestamp",
            reason=f"unparseable timestamp: {raw.loc[i, 'Timestamp']!r}",
            raw_reference=f"{file_name}#row={i}, ReportId={raw.loc[i].get('ReportId', '?')}",
        )
        for i in df.index[~valid]
    ]
    df = df[valid].reset_index(drop=True)

    # Direction is not a direct Defender field; it is derivable from ActionType.
    action_type = raw.loc[valid, "ActionType"].fillna("") if "ActionType" in raw.columns else (
        pd.Series([""] * valid.sum())
    )
    df["direction"] = ["inbound" if "inbound" in a.lower() else "outbound" for a in action_type]

    df["event_id"] = [f"defender-network-{n:06d}" for n in range(1, len(df) + 1)]
    df["source_ref"] = [
        f"ReportId={row.get('ReportId', '')};File={file_name}" for _, row in raw[valid].iterrows()
    ]
    return df, issues


def _normalize_logon(
    raw: pd.DataFrame, file_name: str
) -> tuple[pd.DataFrame, list[NormalizationIssue]]:
    df = _base_frame(raw, _LOGON_RENAME, EVENT_LOGON)
    timestamps, ts_valid = _parse_timestamps(df["timestamp"])
    df["timestamp"] = timestamps

    logon_type_raw = raw["LogonType"].fillna("").str.strip().str.lower()
    logon_type_codes = logon_type_raw.map(LOGON_TYPE_STRING_TO_CODE)
    logon_type_valid = logon_type_codes.notna()

    action_raw = raw["ActionType"].fillna("").str.strip().str.lower()
    action_mapped = action_raw.map(LOGON_ACTION_TYPE_TO_ACTION)
    action_valid = action_mapped.notna()

    valid = ts_valid & logon_type_valid & action_valid

    issues: list[NormalizationIssue] = []
    for i in df.index[~ts_valid]:
        issues.append(NormalizationIssue(
            event_type=EVENT_LOGON, field="Timestamp",
            reason=f"unparseable timestamp: {raw.loc[i, 'Timestamp']!r}",
            raw_reference=f"{file_name}#row={i}",
        ))
    for i in df.index[ts_valid & ~logon_type_valid]:
        issues.append(NormalizationIssue(
            event_type=EVENT_LOGON, field="LogonType",
            reason=f"unrecognised LogonType value: {raw.loc[i, 'LogonType']!r}",
            raw_reference=f"{file_name}#row={i}, ReportId={raw.loc[i].get('ReportId', '?')}",
        ))
    for i in df.index[ts_valid & logon_type_valid & ~action_valid]:
        issues.append(NormalizationIssue(
            event_type=EVENT_LOGON, field="ActionType",
            reason=f"unrecognised ActionType value: {raw.loc[i, 'ActionType']!r}",
            raw_reference=f"{file_name}#row={i}, ReportId={raw.loc[i].get('ReportId', '?')}",
        ))

    df["logon_type"] = logon_type_codes
    df["action"] = action_mapped
    df = df[valid].reset_index(drop=True)

    df["event_id"] = [f"defender-logon-{n:06d}" for n in range(1, len(df) + 1)]
    df["source_ref"] = [
        f"ReportId={row.get('ReportId', '')};File={file_name}" for _, row in raw[valid].iterrows()
    ]
    return df, issues
