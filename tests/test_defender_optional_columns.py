"""A Defender export that omits an *optional* column must load, and say what it lost.

The defect these tests were written against
--------------------------------------------
``DeviceLogonEvents`` exports produced by a scoped advanced-hunting query routinely omit
``FailureReason`` and ``RemoteDeviceName`` -- neither is in
:data:`~ath.telemetry.defender_source.REQUIRED_DEFENDER_COLUMNS`, so the file was
correctly *admitted* as a logon export, and then the whole import died three stages later
with::

    ath.schema.SchemaError: logon table is missing required columns:
        ['failure_reason', 'source_device']

because the rename map had nothing to rename into those two canonical columns and
``coerce_and_validate`` checks for canonical columns before it reindexes. A structurally
valid export was refused over two fields it was never obliged to carry.

The invariant under test
-------------------------
An export missing an optional source column loads; the canonical column it would have
filled is **present and empty** (``""``, or ``<NA>`` for the nullable integer columns);
and the absence is **recorded** on
:attr:`~ath.telemetry.source.SourceLoadResult.field_gaps`, never repaired, never inferred
from a neighbouring field. A missing *required* column is still refused at the boundary
with the same message as before.

Absent is not the same as empty, and these tests hold the two apart
--------------------------------------------------------------------
Both read as ``""`` in the canonical table, and that is exactly why the distinction has
to live somewhere else. ``FailureReason`` present and blank on a successful logon is the
record's own content -- the canonical schema says a successful logon has no failure
reason (:data:`ath.environment.channels.FIELD_APPLICABILITY`) and nothing was lost.
``FailureReason`` absent from the export is a property of the *query*, it is invisible in
every row, and it is the one a reader cannot reconstruct. So the first is not a gap and
the second is one, and ``field_gaps`` is the only place that difference survives.
"""

from __future__ import annotations

import csv
from pathlib import Path

import pandas as pd
import pytest

from ath.schema import (
    EVENT_LOGON,
    EVENT_NETWORK,
    EVENT_PROCESS,
    SIG_UNKNOWN,
    TABLE_COLUMNS,
)
from ath.telemetry.defender_source import (
    _RENAMES,
    ABSENT_COLUMN_REASON,
    OPTIONAL_DEFENDER_COLUMNS,
    REQUIRED_DEFENDER_COLUMNS,
    DefenderExportSource,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "defender_export"

TABLE_FILE: dict[str, str] = {
    EVENT_PROCESS: "DeviceProcessEvents.csv",
    EVENT_NETWORK: "DeviceNetworkEvents.csv",
    EVENT_LOGON: "DeviceLogonEvents.csv",
}

# Rows the fixture export contributes to each table once normalisation has run. The
# logon fixture carries two deliberately malformed rows, which is what makes it the
# useful table for "a gap is counted per row *kept*".
KEPT_ROWS: dict[str, int] = {EVENT_PROCESS: 3, EVENT_NETWORK: 3, EVENT_LOGON: 1}

# The optional columns that also feed a *derived* column. These are outside the rename
# map -- ``process_guid`` is built from a (device, pid, creation time) triple, not
# renamed from one column -- so dropping one of them empties a second column as well,
# and a test asserting an exact gap dict without knowing that would assert the wrong
# thing.
DERIVED_FROM: dict[tuple[str, str], str] = {
    (EVENT_PROCESS, "ProcessId"): "process_guid",
    (EVENT_PROCESS, "InitiatingProcessId"): "parent_process_guid",
    (EVENT_NETWORK, "InitiatingProcessId"): "process_guid",
}


# ======================================================================================
# Building exports that are missing things
# ======================================================================================


def _rows(event_type: str) -> list[dict[str, str]]:
    path = FIXTURES / TABLE_FILE[event_type]
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def _write(
    directory: Path, event_type: str, fields: list[str], rows: list[dict[str, str]]
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / TABLE_FILE[event_type]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return path


def _export(
    directory: Path,
    event_type: str,
    *,
    drop: tuple[str, ...] = (),
    keep_only: tuple[str, ...] | None = None,
    blank: tuple[str, ...] = (),
    reverse: bool = False,
) -> Path:
    """Write the fixture export for ``event_type`` into ``directory``, minus some columns.

    ``drop`` removes columns from the header entirely (the export never offered them);
    ``blank`` keeps the column and empties every value in it (the export offered it and
    no row carried one). Those two are the pair this whole module is about.
    """
    rows = _rows(event_type)
    fields = [f for f in rows[0] if f not in drop]
    if keep_only is not None:
        fields = [f for f in fields if f in keep_only]
    if reverse:
        fields = list(reversed(fields))
    for row in rows:
        for column in blank:
            row[column] = ""
    return _write(directory, event_type, fields, rows)


def _load(directory: Path):
    return DefenderExportSource(directory=directory).load()


def _gap(event_type: str, canonical: str, source_columns: str) -> str:
    reason = ABSENT_COLUMN_REASON.format(columns=source_columns)
    return f"{event_type}.{canonical}: {reason}"


def _optional(event_type: str) -> list[tuple[str, str]]:
    return sorted(OPTIONAL_DEFENDER_COLUMNS[event_type].items())


ALL_OPTIONAL = [
    pytest.param(event_type, source_column, canonical, id=f"{event_type}-{source_column}")
    for event_type in (EVENT_PROCESS, EVENT_NETWORK, EVENT_LOGON)
    for source_column, canonical in _optional(event_type)
]


def _is_empty(series: pd.Series) -> bool:
    """Empty by the canonical schema's two representations of "no value"."""
    return bool((series.isna() | (series.astype("string").fillna("") == "")).all())


# ======================================================================================
# 1. The exact regression
# ======================================================================================


def test_logon_export_without_failure_reason_and_remote_device_loads(tmp_path) -> None:
    """The reported defect, verbatim: the two columns absent, and the import survives.

    Before the fix this raised ``SchemaError: logon table is missing required columns:
    ['failure_reason', 'source_device']`` from ``coerce_and_validate`` -- over two
    columns that are not in ``REQUIRED_DEFENDER_COLUMNS`` and never were.
    """
    _export(tmp_path, EVENT_LOGON, drop=("FailureReason", "RemoteDeviceName"))
    result = _load(tmp_path)

    logons = result.tables[EVENT_LOGON]
    assert len(logons) == KEPT_ROWS[EVENT_LOGON]
    assert list(logons.columns) == list(TABLE_COLUMNS[EVENT_LOGON])

    row = logons.iloc[0]
    assert row["failure_reason"] == ""
    assert row["source_device"] == ""
    # The rest of the row is untouched: this is a smaller export, not a broken one.
    assert row["user"] == "rsmith"
    assert row["device"] == "CORP-WKS01"
    assert row["action"] == "success"
    assert row["logon_type"] == 2

    assert result.field_gaps == {
        "logon.failure_reason: export carries no FailureReason column": 1,
        "logon.source_device: export carries no RemoteDeviceName column": 1,
    }
    assert "2 field gap(s) on kept rows" in result.summary()


def test_the_absence_is_never_repaired_into_a_value(tmp_path) -> None:
    """Nothing is invented to fill the hole -- not a default, not a neighbouring column.

    ``"unknown"`` and ``"success"`` are the two plausible-looking inventions for
    ``failure_reason``; deriving ``source_device`` from ``source_ip`` is the
    plausible-looking invention for the other, since the address is right there in the
    same row. Either would put a value this export does not contain into a column an
    analyst reads as observed.
    """
    _export(tmp_path, EVENT_LOGON, drop=("FailureReason", "RemoteDeviceName"))
    row = _load(tmp_path).tables[EVENT_LOGON].iloc[0]

    assert row["failure_reason"] == ""
    assert row["failure_reason"] not in ("unknown", "success", "none", "n/a")
    assert row["source_device"] == ""
    assert row["source_ip"] == "10.1.1.15"           # still carried, from RemoteIP
    assert row["source_device"] != row["source_ip"]  # and not copied into the other


def test_a_present_failure_reason_is_still_carried(tmp_path) -> None:
    """The other half of the same claim: when the column *is* there, its value survives.

    Without this, "the column is always empty" would pass every test above.
    """
    fields = ["AccountName", "ActionType", "DeviceName", "FailureReason", "LogonType",
              "RemoteDeviceName", "RemoteIP", "ReportId", "Timestamp"]
    row = {
        "AccountName": "rsmith", "ActionType": "LogonFailed", "DeviceName": "CORP-FS01",
        "FailureReason": "IncorrectPassword", "LogonType": "Network",
        "RemoteDeviceName": "CORP-WKS01", "RemoteIP": "10.1.1.15", "ReportId": "700099",
        "Timestamp": "2026-06-01T09:30:00.0000000Z",
    }
    _write(tmp_path / "with", EVENT_LOGON, fields, [row])
    _write(tmp_path / "without", EVENT_LOGON,
           [f for f in fields if f not in ("FailureReason", "RemoteDeviceName")], [row])

    with_columns = _load(tmp_path / "with")
    present = with_columns.tables[EVENT_LOGON].iloc[0]
    assert present["failure_reason"] == "IncorrectPassword"
    assert present["source_device"] == "CORP-WKS01"
    assert not with_columns.field_gaps

    absent = _load(tmp_path / "without").tables[EVENT_LOGON].iloc[0]
    assert absent["failure_reason"] == ""
    assert absent["source_device"] == ""


# ======================================================================================
# 2. Generalisation: every optional column, every table
# ======================================================================================


@pytest.mark.parametrize(("event_type", "source_column", "canonical"), ALL_OPTIONAL)
def test_each_optional_column_absent_alone_still_loads(
    tmp_path, event_type: str, source_column: str, canonical: str
) -> None:
    """One optional column at a time, across all three tables and all of them.

    Parametrised off ``OPTIONAL_DEFENDER_COLUMNS`` rather than off a list written here,
    so a column added to a rename map in future is covered the day it is added -- which
    is the failure mode that produced this defect: ``SHA256`` and
    ``ProcessVersionInfoCompanyName`` had been given a hand-written default and the next
    two optional columns had not.
    """
    _export(tmp_path, event_type, drop=(source_column,))
    result = _load(tmp_path)

    table = result.tables[event_type]
    kept = KEPT_ROWS[event_type]
    assert len(table) == kept
    assert list(table.columns) == list(TABLE_COLUMNS[event_type])
    assert _is_empty(table[canonical])
    # The rows are kept, so nothing here may show up as a dropped row.
    assert result.rows_kept == kept

    expected = {_gap(event_type, canonical, source_column): kept}
    derived = DERIVED_FROM.get((event_type, source_column))
    if derived is not None:
        assert _is_empty(table[derived])
        expected[_gap(event_type, derived, source_column)] = kept
    assert result.field_gaps == expected


@pytest.mark.parametrize("event_type", [EVENT_PROCESS, EVENT_NETWORK, EVENT_LOGON])
def test_export_of_only_the_required_columns_loads(tmp_path, event_type: str) -> None:
    """The extreme case: every optional column absent at once, nothing left but the
    header that identifies the table.

    Every optional canonical column comes back empty and every absence is counted, once
    per kept row. The derived instance-identity columns are in the expectation too,
    because their inputs went with everything else.
    """
    _export(tmp_path, event_type, keep_only=REQUIRED_DEFENDER_COLUMNS[event_type])
    result = _load(tmp_path)

    table = result.tables[event_type]
    kept = KEPT_ROWS[event_type]
    assert len(table) == kept
    for _source_column, canonical in _optional(event_type):
        assert _is_empty(table[canonical]), canonical

    derived_gaps = {
        EVENT_PROCESS: {
            _gap(EVENT_PROCESS, "process_guid", "ProcessId, ProcessCreationTime"): kept,
            _gap(EVENT_PROCESS, "parent_process_guid",
                 "InitiatingProcessId, InitiatingProcessCreationTime"): kept,
        },
        EVENT_NETWORK: {
            _gap(EVENT_NETWORK, "process_guid",
                 "InitiatingProcessId, InitiatingProcessCreationTime"): kept,
        },
        EVENT_LOGON: {},
    }[event_type]
    expected = {
        _gap(event_type, canonical, source_column): kept
        for source_column, canonical in _optional(event_type)
    }
    expected.update(derived_gaps)
    assert result.field_gaps == expected
    assert sum(result.field_gaps.values()) == len(expected) * kept


def test_a_required_only_process_export_still_reports_signature_as_unevaluated(
    tmp_path,
) -> None:
    """``signature_status`` is not an absent column -- it is a column this source never
    evaluates, and it keeps saying so rather than going empty along with the rest."""
    _export(tmp_path, EVENT_PROCESS, keep_only=REQUIRED_DEFENDER_COLUMNS[EVENT_PROCESS])
    table = _load(tmp_path).tables[EVENT_PROCESS]
    assert (table["signature_status"] == SIG_UNKNOWN).all()


def test_column_order_is_not_part_of_the_contract(tmp_path) -> None:
    """A header in a different order is the same export, with no gaps.

    The check that used to refuse a partial export sits one line before the ``reindex``
    that fixes column order, which is what made "absent" and "out of order" the same
    thing to everything downstream. They are not, and this pins the difference.
    """
    _export(tmp_path / "forward", EVENT_LOGON)
    _export(tmp_path / "reversed", EVENT_LOGON, reverse=True)

    forward = _load(tmp_path / "forward")
    backward = _load(tmp_path / "reversed")

    assert not forward.field_gaps
    assert not backward.field_gaps
    pd.testing.assert_frame_equal(forward.tables[EVENT_LOGON], backward.tables[EVENT_LOGON])


# ======================================================================================
# 3. Absent vs. empty -- the distinction the mechanism exists to preserve
# ======================================================================================


def test_absent_and_empty_produce_the_same_row_and_different_gaps(tmp_path) -> None:
    """Identical canonical values; only ``field_gaps`` can tell the two apart.

    This is the point of using ``field_gaps`` rather than a sentinel in the column
    itself: the canonical schema is not asked to carry a third state, downstream rules
    see the same ``""`` either way, and the fact that the export never offered the column
    is still recoverable -- from the load result, where it belongs, rather than from a
    population fraction, which cannot separate the two causes of an empty field.
    """
    _export(tmp_path / "empty", EVENT_LOGON, blank=("FailureReason", "RemoteDeviceName"))
    _export(tmp_path / "absent", EVENT_LOGON, drop=("FailureReason", "RemoteDeviceName"))

    empty = _load(tmp_path / "empty")
    absent = _load(tmp_path / "absent")

    pd.testing.assert_frame_equal(empty.tables[EVENT_LOGON], absent.tables[EVENT_LOGON])
    assert empty.field_gaps == {}
    assert absent.field_gaps == {
        _gap(EVENT_LOGON, "failure_reason", "FailureReason"): 1,
        _gap(EVENT_LOGON, "source_device", "RemoteDeviceName"): 1,
    }
    assert "field gap" not in empty.summary()
    assert "field gap" in absent.summary()


def test_a_gap_is_not_a_dropped_row(tmp_path) -> None:
    """Gaps count rows that were *kept*, and never touch the loss accounting.

    The logon fixture drops two rows for reasons of their own (an unparseable timestamp,
    an unrecognised ``LogonType``). Those are ``NormalizationIssue``s and stay exactly
    two; the gap count is over the one row that survived, not over the three that were
    read -- counting a dropped row's empty column too would report one lost row as two
    different kinds of loss.
    """
    _export(tmp_path, EVENT_LOGON, drop=("FailureReason",))
    result = _load(tmp_path)

    assert result.rows_read == 3
    assert result.rows_kept == 1
    assert result.rows_dropped == 2
    assert len(result.issues) == 2
    assert result.field_gaps == {_gap(EVENT_LOGON, "failure_reason", "FailureReason"): 1}


def test_an_absent_integer_column_is_na_and_never_zero(tmp_path) -> None:
    """``remote_port`` absent must not become ``0`` -- port 0 is a value, not a silence."""
    _export(tmp_path, EVENT_NETWORK, drop=("RemotePort",))
    table = _load(tmp_path).tables[EVENT_NETWORK]

    assert str(table["remote_port"].dtype) == "Int64"
    assert table["remote_port"].isna().all()
    assert not (table["remote_port"].fillna(-1) == 0).any()


# ======================================================================================
# 4. Required columns are still required
# ======================================================================================


@pytest.mark.parametrize(
    ("event_type", "required"),
    [
        pytest.param(event_type, column, id=f"{event_type}-{column}")
        for event_type in (EVENT_PROCESS, EVENT_NETWORK, EVENT_LOGON)
        for column in REQUIRED_DEFENDER_COLUMNS[event_type]
    ],
)
def test_a_missing_required_column_is_still_refused(
    tmp_path, event_type: str, required: str
) -> None:
    """Unweakened: a file without an identifying column is not this table, and is refused
    at the boundary with the name of the column it looked for.

    The whole risk of making optional columns optional is that "missing column" stops
    meaning anything. It still means this.
    """
    _export(tmp_path, event_type, drop=(required,))
    result = _load(tmp_path)

    assert len(result.tables[event_type]) == 0
    refused = [a for a in result.rejected_files if a.path == TABLE_FILE[event_type]]
    assert len(refused) == 1
    assert required in refused[0].reason
    assert result.rows_read == 0
    assert not result.issues
    assert not result.field_gaps


def test_a_refused_file_records_no_gaps_for_the_columns_it_also_lacked(tmp_path) -> None:
    """A refusal is not a partial load: no table, no rows, and no gap list either.

    A file missing both a required and an optional column must be reported once, as a
    file that is not this table -- not as an import that succeeded with two holes in it.
    """
    _export(tmp_path, EVENT_LOGON, drop=("LogonType", "FailureReason"))
    result = _load(tmp_path)

    assert len(result.tables[EVENT_LOGON]) == 0
    assert result.field_gaps == {}
    assert "LogonType" in result.rejected_files[0].reason


# ======================================================================================
# 5. The mechanism itself
# ======================================================================================


@pytest.mark.parametrize("event_type", [EVENT_PROCESS, EVENT_NETWORK, EVENT_LOGON])
def test_optional_columns_are_derived_from_the_two_existing_declarations(
    event_type: str,
) -> None:
    """No third hand-maintained list -- optional *is* "read by the adapter, not required".

    The defect was a per-column defaulting habit: ``SHA256`` and
    ``ProcessVersionInfoCompanyName`` had been remembered, ``FailureReason`` and
    ``RemoteDeviceName`` had not. This asserts the partition is computed, so there is no
    list for the next column to go missing from.
    """
    optional = set(OPTIONAL_DEFENDER_COLUMNS[event_type])
    required = set(REQUIRED_DEFENDER_COLUMNS[event_type])
    mapped = set(_RENAMES[event_type])

    assert optional == mapped - required
    assert optional.isdisjoint(required)
    # Both columns the defect was reported against, and the two that used to be
    # special-cased by name, are on the optional side of that partition.
    if event_type == EVENT_LOGON:
        assert {"FailureReason", "RemoteDeviceName"} <= optional
    if event_type == EVENT_PROCESS:
        assert {"SHA256", "ProcessVersionInfoCompanyName"} <= optional


def test_the_complete_fixture_export_reports_no_gaps_at_all() -> None:
    """The control: a full export loses nothing, so the gap list stays empty.

    A mechanism that reported a gap on a complete export would be worse than none --
    every import would carry noise, and a reader would learn to ignore it.
    """
    result = _load(FIXTURES)
    assert result.field_gaps == {}
    assert result.rows_kept == 7
    assert "field gap" not in result.summary()
