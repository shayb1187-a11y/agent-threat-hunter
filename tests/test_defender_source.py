"""Tests for the Microsoft Defender export adapter.

These tests operate directly on ``DefenderExportSource`` and the fixture files in
``tests/fixtures/defender_export/`` -- a small export shaped exactly like a real
Defender advanced-hunting CSV export (verified column names, real value formats),
containing one coherent mini-intrusion plus two deliberately malformed rows.

The properties under test:

1. Every column mapping matches the *verified* Microsoft Learn schema, not a guess.
2. Value translation (LogonType string -> our numeric code, ActionType -> success/
   failure, ActionType -> inbound/outbound) is correct.
3. Malformed rows are dropped with a precise, actionable reason -- never silently
   miscoded, and never crash the whole import.
4. Provenance (source, source_ref) survives normalization.
5. Missing tables degrade to empty (not a crash), matching how every detection rule
   already handles an empty DataFrame.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from ath.schema import EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS, describe_logon_type
from ath.telemetry.defender_source import (
    LOGON_ACTION_TYPE_TO_ACTION,
    LOGON_TYPE_STRING_TO_CODE,
    SOURCE_NAME,
    DefenderExportSource,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "defender_export"


@pytest.fixture(scope="module")
def result():
    return DefenderExportSource(directory=FIXTURES).load()


# ======================================================================================
# Row counts and basic shape
# ======================================================================================


def test_reads_all_three_tables(result) -> None:
    assert set(result.tables) == {EVENT_PROCESS, EVENT_NETWORK, EVENT_LOGON}


def test_process_rows_all_kept(result) -> None:
    """All 3 fixture process rows are well-formed and should all survive."""
    assert len(result.tables[EVENT_PROCESS]) == 3


def test_network_rows_all_kept(result) -> None:
    assert len(result.tables[EVENT_NETWORK]) == 3


def test_logon_rows_partially_dropped(result) -> None:
    """1 good row + 2 deliberately malformed rows in the fixture."""
    assert len(result.tables[EVENT_LOGON]) == 1


def test_rows_read_counts_everything_including_dropped(result) -> None:
    assert result.rows_read == 9
    assert result.rows_kept == 7
    assert result.rows_dropped == 2


# ======================================================================================
# Column mapping correctness (verified against Microsoft Learn)
# ======================================================================================


def test_process_fields_mapped_correctly(result) -> None:
    procs = result.tables[EVENT_PROCESS]
    word_row = procs[procs["process_name"] == "WINWORD.EXE"].iloc[0]
    assert word_row["device"] == "CORP-WKS01"
    assert word_row["user"] == "rsmith"
    assert word_row["parent_process_name"] == "OUTLOOK.EXE"
    assert int(word_row["parent_process_id"]) == 2200
    assert ".docm" in word_row["command_line"]
    assert "Office16" in word_row["file_path"]


def test_network_user_comes_from_initiating_process_account(result) -> None:
    """DeviceNetworkEvents has NO AccountName column -- only InitiatingProcessAccountName.
    This is the single most important mapping correctness check in this file."""
    net = result.tables[EVENT_NETWORK]
    assert (net["user"] == "rsmith").all()
    assert (net["process_name"] == "powershell.exe").all()


def test_network_direction_derived_from_action_type(result) -> None:
    net = result.tables[EVENT_NETWORK]
    assert (net["direction"] == "outbound").all()


def test_logon_fields_mapped_correctly(result) -> None:
    logons = result.tables[EVENT_LOGON]
    row = logons.iloc[0]
    assert row["device"] == "CORP-WKS01"
    assert row["user"] == "rsmith"
    assert row["source_ip"] == "10.1.1.15"
    assert row["action"] == "success"
    assert int(row["logon_type"]) == 2  # Interactive


# ======================================================================================
# LogonType / ActionType translation tables
# ======================================================================================


@pytest.mark.parametrize("string_value,expected_code", [
    ("Interactive", 2), ("interactive", 2),
    ("Network", 3),
    ("Batch", 4),
    ("Service", 5),
    ("Remote interactive (RDP)", 10), ("RemoteInteractive", 10), ("rdp", 10),
])
def test_logon_type_translation_table(string_value: str, expected_code: int) -> None:
    assert LOGON_TYPE_STRING_TO_CODE[string_value.strip().lower()] == expected_code


def test_translated_logon_types_are_all_describable() -> None:
    """Every code we translate TO must be a code our own schema recognises."""
    for code in set(LOGON_TYPE_STRING_TO_CODE.values()):
        assert describe_logon_type(code) != f"Type {code}", (
            f"code {code} is not in ath.schema.LOGON_TYPE_NAMES"
        )


def test_action_type_translation_table() -> None:
    assert LOGON_ACTION_TYPE_TO_ACTION["logonsuccess"] == "success"
    assert LOGON_ACTION_TYPE_TO_ACTION["logonfailed"] == "failure"


# ======================================================================================
# Malformed rows: dropped with a precise, actionable reason -- never silently miscoded
# ======================================================================================


def test_unparseable_timestamp_is_dropped_with_a_clear_reason(result) -> None:
    ts_issues = [i for i in result.issues if i.field == "Timestamp"]
    assert len(ts_issues) == 1
    assert "not-a-timestamp" in ts_issues[0].reason
    assert ts_issues[0].event_type == EVENT_LOGON


def test_unrecognised_logon_type_is_dropped_with_a_clear_reason(result) -> None:
    logon_type_issues = [i for i in result.issues if i.field == "LogonType"]
    assert len(logon_type_issues) == 1
    assert "Explicit" in logon_type_issues[0].reason


def test_dropped_rows_are_not_silently_present_in_the_output(result) -> None:
    """The row with LogonType='Explicit' (svc_report/CORP-FS01) must not appear."""
    logons = result.tables[EVENT_LOGON]
    assert not (logons["device"] == "CORP-FS01").any()


def test_issues_carry_a_traceable_reference(result) -> None:
    for issue in result.issues:
        assert issue.raw_reference, f"issue with no traceability: {issue}"
        assert "DeviceLogonEvents.csv" in issue.raw_reference


def test_missing_table_produces_empty_frame_not_a_crash(tmp_path) -> None:
    """A directory with only a process export must not crash on the other two tables."""
    only_process = tmp_path
    (FIXTURES / "DeviceProcessEvents.csv").read_text()  # sanity: fixture exists
    import shutil

    shutil.copy(FIXTURES / "DeviceProcessEvents.csv", only_process / "DeviceProcessEvents.csv")

    result = DefenderExportSource(directory=only_process).load()
    assert len(result.tables[EVENT_PROCESS]) == 3
    assert len(result.tables[EVENT_NETWORK]) == 0
    assert len(result.tables[EVENT_LOGON]) == 0
    # Empty frames must still have the canonical columns, not just be missing/None.
    assert "remote_ip" in result.tables[EVENT_NETWORK].columns
    assert "logon_type" in result.tables[EVENT_LOGON].columns


def test_missing_required_defender_column_is_reported_not_crashed(tmp_path) -> None:
    """A CSV without the columns that identify a Defender process export is refused.

    Graceful degradation, as before -- a named reason, not a ``KeyError``. What changed
    is *where* the refusal is recorded: the header is this adapter's recognition
    predicate, so a file whose header does not identify it is refused at the boundary
    (with the column it looked for) rather than counted as one row of telemetry that
    failed to normalise. Its rows stay out of ``rows_read``, because they were never this
    export's rows.
    """
    bad_csv = tmp_path / "DeviceProcessEvents.csv"
    bad_csv.write_text("Timestamp,DeviceName\n2026-01-01T00:00:00Z,PC01\n")

    result = DefenderExportSource(directory=tmp_path).load()
    assert len(result.tables[EVENT_PROCESS]) == 0
    refused = [a for a in result.rejected_files if a.path == "DeviceProcessEvents.csv"]
    assert len(refused) == 1
    assert "FileName" in refused[0].reason
    assert refused[0].line_or_record_count == 1
    assert result.rows_read == 0
    assert not result.issues


# ======================================================================================
# Provenance
# ======================================================================================


def test_every_normalized_row_carries_source(result) -> None:
    for df in result.tables.values():
        if df.empty:
            continue
        assert (df["source"] == SOURCE_NAME).all()


def test_source_ref_preserves_the_original_report_id(result) -> None:
    procs = result.tables[EVENT_PROCESS]
    row = procs.iloc[0]
    assert "ReportId=" in row["source_ref"]
    assert "DeviceProcessEvents.csv" in row["source_ref"]


def test_event_ids_are_globally_unique_and_not_the_raw_report_id(result) -> None:
    """ReportId is documented by Microsoft as a repeating counter, not a safe unique
    id on its own -- our event_id must be independently guaranteed unique."""
    all_ids = pd.concat([df["event_id"] for df in result.tables.values() if not df.empty])
    assert all_ids.is_unique
    assert all(eid.startswith("defender-") for eid in all_ids)


# ======================================================================================
# JSON format support
# ======================================================================================


def test_json_array_format_is_supported(tmp_path) -> None:
    import json

    records = [
        {
            "Timestamp": "2026-01-01T00:00:00.0000000Z", "DeviceName": "PC99",
            "AccountName": "alice", "FileName": "whoami.exe", "FolderPath": r"C:\Windows\System32",
            "ProcessId": "1000", "ProcessCommandLine": "whoami.exe /all",
            "InitiatingProcessFileName": "cmd.exe", "InitiatingProcessId": "999",
            "ReportId": "1",
        }
    ]
    path = tmp_path / "DeviceProcessEvents.json"
    path.write_text(json.dumps(records))

    result = DefenderExportSource(directory=tmp_path).load()
    procs = result.tables[EVENT_PROCESS]
    assert len(procs) == 1
    assert procs.iloc[0]["device"] == "PC99"


def test_ndjson_format_is_supported(tmp_path) -> None:
    import json

    lines = [
        json.dumps({
            "Timestamp": "2026-01-01T00:00:00.0000000Z", "DeviceName": "PC99",
            "AccountName": "alice", "FileName": "whoami.exe", "FolderPath": r"C:\Windows\System32",
            "ProcessId": "1000", "ProcessCommandLine": "whoami.exe /all",
            "InitiatingProcessFileName": "cmd.exe", "InitiatingProcessId": "999",
            "ReportId": "1",
        }),
        json.dumps({
            "Timestamp": "2026-01-01T00:05:00.0000000Z", "DeviceName": "PC99",
            "AccountName": "alice", "FileName": "net.exe", "FolderPath": r"C:\Windows\System32",
            "ProcessId": "1001", "ProcessCommandLine": "net group \"Domain Admins\" /domain",
            "InitiatingProcessFileName": "cmd.exe", "InitiatingProcessId": "999",
            "ReportId": "2",
        }),
    ]
    path = tmp_path / "DeviceProcessEvents.json"
    path.write_text("\n".join(lines))

    result = DefenderExportSource(directory=tmp_path).load()
    assert len(result.tables[EVENT_PROCESS]) == 2


# ======================================================================================
# Explicit path construction (vs directory discovery)
# ======================================================================================


def test_explicit_paths_bypass_directory_discovery() -> None:
    result = DefenderExportSource(
        process_path=FIXTURES / "DeviceProcessEvents.csv",
        network_path=FIXTURES / "DeviceNetworkEvents.csv",
        logon_path=FIXTURES / "DeviceLogonEvents.csv",
    ).load()
    assert len(result.tables[EVENT_PROCESS]) == 3
    assert len(result.tables[EVENT_NETWORK]) == 3
    assert len(result.tables[EVENT_LOGON]) == 1


def test_source_load_result_summary_is_human_readable(result) -> None:
    assert "7" in result.summary() and "2" in result.summary() and "9" in result.summary()
