"""M18b-1: the identity of a process *instance*, carried from every source that has one.

What is being protected
-----------------------
``(device, process_id)`` names a slot, not a process. Measured on the held-out COMISET
slice (``reports/m17/H4_FROZEN.json``): 99.98% of network rows matched *a* process row by
that pair, and 86.5% of the pairs were ambiguous, the worst one covering 27 distinct
process instances. A join that succeeds almost always and means almost nothing is worse
than one that visibly fails, because only the second gets fixed.

The invariant these tests hold the sources to:

* the source's own instance identifier when it has one (``sysmon:<guid>``),
* otherwise a ``start:<device>|<pid>|<iso ms>`` key **only** where the source records the
  instance's creation time,
* otherwise ``""`` -- never a value inferred from an event's own timestamp unless that
  event *is* the creation of the process it names.

Each test states the failure it would catch. The ones worth reading twice are
:func:`test_a_network_event_never_invents_a_start_key_from_its_own_time` and
:func:`test_a_parent_identity_is_never_derived_from_the_child_s_event_time`: both guard
against a change that would make the columns look *more* populated while making every
join built on them wrong.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

from ath.instance_identity import (
    IDENTITY_SCHEMES,
    SCHEME_START,
    SCHEME_SYSMON,
    InstanceKey,
    UnknownIdentityScheme,
    instance_identity,
    instance_key,
    match_keys,
    scheme_of,
    start_identity,
    sysmon_identity,
)
from ath.schema import (
    EVENT_NETWORK,
    EVENT_PROCESS,
    NETWORK_COLUMNS,
    PROCESS_COLUMNS,
    SchemaError,
    validate_frame,
)
from ath.telemetry.defender_source import DefenderExportSource
from ath.telemetry.elastic_winevent_source import ElasticWinEventSource
from ath.telemetry.generator import GeneratorConfig, generate_telemetry
from ath.telemetry.loader import load_telemetry
from ath.telemetry.source import SourceLoadResult, write_normalized_telemetry
from ath.telemetry.winlogbeat_source import WinlogbeatSource

FIXTURES = Path(__file__).parent / "fixtures"

UTC = timezone.utc


# ======================================================================================
# The schema
# ======================================================================================


def test_the_three_identity_columns_are_declared() -> None:
    """Two on the process table, one on the network table.

    Failure mode: a column is added to a source and never to the schema, so
    ``coerce_and_validate`` drops it on the reindex and the value is lost between the
    adapter and the first reader -- silently, because the frame still validates.
    """
    assert "process_guid" in PROCESS_COLUMNS
    assert "parent_process_guid" in PROCESS_COLUMNS
    assert "process_guid" in NETWORK_COLUMNS
    # Deliberately not on the network table: a connection names the instance that opened
    # it, and that instance's parent is a fact about the process table.
    assert "parent_process_guid" not in NETWORK_COLUMNS


@pytest.mark.parametrize(("event_type", "columns", "dropped"), [
    (EVENT_PROCESS, PROCESS_COLUMNS, "process_guid"),
    (EVENT_PROCESS, PROCESS_COLUMNS, "parent_process_guid"),
    (EVENT_NETWORK, NETWORK_COLUMNS, "process_guid"),
])
def test_validate_frame_rejects_a_frame_without_the_identity_columns(
    event_type: str, columns: tuple, dropped: str,
) -> None:
    """Strictness is the point: a missing identity column is a loud failure.

    Failure mode: the validator is relaxed so an old artifact keeps loading, and every
    genuinely dropped field -- an adapter that stopped mapping one, a rename nobody
    noticed -- becomes acceptable everywhere at once.
    """
    frame = pd.DataFrame(columns=[c for c in columns if c != dropped])
    with pytest.raises(SchemaError, match=dropped):
        validate_frame(frame, event_type)


# ======================================================================================
# The helper
# ======================================================================================


def test_instance_identity_formats_scheme_then_parts() -> None:
    """The one shape, written in one place.

    Failure mode: a caller builds the string itself, omits the scheme prefix, and two
    authorities' identities become comparable.
    """
    assert instance_identity(SCHEME_SYSMON, "abc") == "sysmon:abc"
    assert instance_identity(SCHEME_START, "pc01", "4820", "t") == "start:pc01|4820|t"


def test_instance_identity_refuses_an_unknown_scheme() -> None:
    """A typo'd scheme mints identities that join to nothing and look like honest gaps.

    Failure mode: ``instance_identity("symon", guid)`` is accepted, the column populates
    fully, and every guid join silently returns zero matches.
    """
    with pytest.raises(UnknownIdentityScheme):
        instance_identity("symon", "abc")


def test_a_partial_identity_is_no_identity() -> None:
    """Any empty part empties the whole value.

    Failure mode: a missing creation time yields ``start:pc01|4820|`` for every process
    on the host whose time was lost, and they all collapse into one instance.
    """
    assert instance_identity(SCHEME_START, "pc01", "", "t") == ""
    assert instance_identity(SCHEME_SYSMON, "") == ""
    assert start_identity("PC01", 4820, None) == ""
    assert start_identity("", 4820, "2026-08-17T08:00:00Z") == ""
    assert start_identity("PC01", None, "2026-08-17T08:00:00Z") == ""
    assert start_identity("PC01", pd.NA, "2026-08-17T08:00:00Z") == ""
    assert start_identity("PC01", 4820, "not a time") == ""


def test_a_start_key_lower_cases_the_device_and_truncates_to_the_millisecond() -> None:
    """Casing and sub-millisecond digits are presentation, and must not split an instance.

    Failure mode: one adapter writes ``PC01`` and another ``pc01`` for the same machine,
    or a source with microsecond precision disagrees with one that reports milliseconds,
    and the same instance gets two identities.
    """
    moment = pd.Timestamp("2026-08-17T08:00:00.123456789Z")
    assert start_identity("PC01", 4820, moment) == "start:pc01|4820|2026-08-17T08:00:00.123Z"
    assert start_identity("pc01", "4820", moment) == start_identity("PC01", 4820, moment)
    # A naive datetime is read as UTC, which is what every adapter here produces.
    naive = datetime(2026, 8, 17, 8, 0, 0, 123000)
    assert start_identity("PC01", 4820, naive) == "start:pc01|4820|2026-08-17T08:00:00.123Z"
    # ...and a non-UTC offset is converted, not truncated to its local reading.
    other = pd.Timestamp("2026-08-17T10:00:00.123+02:00")
    assert start_identity("PC01", 4820, other) == "start:pc01|4820|2026-08-17T08:00:00.123Z"


def test_the_same_pid_on_the_same_device_at_two_start_times_is_two_identities() -> None:
    """The whole reason the column exists: PID reuse is not instance identity.

    Failure mode: the creation time is dropped from the key "because device and pid are
    enough", and the 86.5% ambiguity this milestone measured comes straight back.
    """
    first = start_identity("PC01", 4820, "2026-08-17T08:00:00Z")
    second = start_identity("PC01", 4820, "2026-08-17T09:30:00Z")
    assert first and second and first != second


def test_a_sysmon_guid_is_taken_verbatim_apart_from_braces_and_casing() -> None:
    """Two pipelines, one authority, one value.

    Failure mode: DEDALE's ``{416dd0c5-...}`` and COMISET's ``416DD0C5-...`` are treated
    as different instances, so a corpus that mixes exports cannot be joined at all.
    """
    assert (
        sysmon_identity("{416DD0C5-6A1F-676A-0300-000000000800}")
        == "sysmon:416dd0c5-6a1f-676a-0300-000000000800"
    )
    assert sysmon_identity("416dd0c5-6a1f-676a-0300-000000000800") == sysmon_identity(
        "{416DD0C5-6A1F-676A-0300-000000000800}"
    )
    for absent in ("", None, "-", "null"):
        assert sysmon_identity(absent) == ""


def test_identities_from_different_schemes_never_compare_equal() -> None:
    """Same id text, different authority, different value -- by construction.

    Failure mode: the scheme prefix is dropped as noise, and a ``start`` key built from
    a GUID-shaped string silently matches a real Sysmon identity.
    """
    text = "416dd0c5-6a1f-676a-0300-000000000800"
    assert instance_identity(SCHEME_SYSMON, text) != instance_identity(SCHEME_START, text)
    assert scheme_of(instance_identity(SCHEME_SYSMON, text)) == SCHEME_SYSMON
    assert scheme_of(instance_identity(SCHEME_START, text)) == SCHEME_START
    assert scheme_of("") == "" and scheme_of("nonsense:x") == ""
    assert set(IDENTITY_SCHEMES) == {SCHEME_SYSMON, SCHEME_START}


# ======================================================================================
# Elastic-exported Windows events (the COMISET layout)
# ======================================================================================


def _elastic_record(**overrides: object) -> dict:
    record = {
        "_channel": "sysmon", "event_id": "1", "_doc_id": "d1",
        "event_original_time": "2022-11-16T19:59:52.774Z",
        "host_name": "desktop-4pvps6e.phoenix.local", "user_name": "local service",
        "process_name": "audiodg.exe", "process_id": "6076",
        "process_parent_name": "svchost.exe", "process_parent_id": "824",
        "process_path": r"c:\windows\system32\audiodg.exe",
        "CommandLine": r"c:\windows\system32\audiodg.exe 0xf94",
        "process_guid": "4FD6B357-4138-6375-DB00-000000002900",
        "process_parent_guid": "4FD6B357-366A-6375-0F00-000000002900",
    }
    record.update(overrides)
    return {k: v for k, v in record.items() if v is not None}


def _load_elastic(tmp_path: Path, *records: dict) -> SourceLoadResult:
    (tmp_path / "slice.jsonl").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8",
    )
    return ElasticWinEventSource(tmp_path).load()


def test_elastic_sysmon_1_carries_both_guids_verbatim(tmp_path: Path) -> None:
    """The field names are the corpus', read off it: ``process_guid``/``process_parent_guid``.

    Failure mode: the pipeline's rename (``general_rename-ProcessGuid``) is assumed to
    leave the Sysmon spelling in place, the adapter reads ``ProcessGuid``, and the whole
    column is empty on the one corpus this was written for.
    """
    row = _load_elastic(tmp_path, _elastic_record()).tables[EVENT_PROCESS].iloc[0]
    assert row["process_guid"] == "sysmon:4fd6b357-4138-6375-db00-000000002900"
    assert row["parent_process_guid"] == "sysmon:4fd6b357-366a-6375-0f00-000000002900"


def test_elastic_sysmon_3_carries_the_opener_guid(tmp_path: Path) -> None:
    """Sysmon writes ProcessGuid on the network event too; that is the whole join.

    Failure mode: only event 1 is read, the network column is empty, and the
    cross-channel claim stays unsubstantiable exactly as M17 found it.
    """
    network = _elastic_record(
        event_id="3", process_guid="E3D58CDF-15D7-5EA3-0000-00100BA90000",
        dst_ip_addr="10.66.6.21", dst_port="389", network_protocol="tcp",
        network_initiated="true", process_parent_guid=None, process_parent_id=None,
        process_parent_name=None,
    )
    row = _load_elastic(tmp_path, network).tables[EVENT_NETWORK].iloc[0]
    assert row["process_guid"] == "sysmon:e3d58cdf-15d7-5ea3-0000-00100ba90000"


def test_a_network_event_never_invents_a_start_key_from_its_own_time(tmp_path: Path) -> None:
    """A connection's time is the socket's, not the process's.

    Failure mode, and it is the tempting one: the network column is "improved" with a
    ``start`` key from the row's timestamp. Population goes to 100%, every key is unique
    per connection, and the guid join returns nothing while looking healthy.
    """
    network = _elastic_record(
        event_id="3", process_guid=None, dst_ip_addr="10.66.6.21", dst_port="389",
        network_protocol="tcp", network_initiated="true", process_parent_guid=None,
        process_parent_id=None, process_parent_name=None,
    )
    row = _load_elastic(tmp_path, network).tables[EVENT_NETWORK].iloc[0]
    assert row["process_guid"] == ""


def test_a_process_create_without_a_guid_falls_back_to_its_own_event_time(
    tmp_path: Path,
) -> None:
    """The one permitted inference: this event *is* the creation it names.

    This is also the Security 4688 case. ``EVENT_ROUTING`` does not carry 4688 today (see
    :func:`test_security_4688_is_not_routed_by_either_windows_adapter`), so the path is
    exercised through a Sysmon 1 record with the GUID removed -- the same branch, the
    same code.

    Failure mode: the fallback is dropped as "guessing", and a source that records
    creation times loses them for no reason.
    """
    row = _load_elastic(
        tmp_path, _elastic_record(process_guid=None, process_parent_guid=None),
    ).tables[EVENT_PROCESS].iloc[0]
    assert row["process_guid"] == "start:desktop-4pvps6e|6076|2022-11-16T19:59:52.774Z"


def test_a_parent_identity_is_never_derived_from_the_child_s_event_time(
    tmp_path: Path,
) -> None:
    """A process-create event says when the *child* started, and nothing about the parent.

    Failure mode: ``parent_process_guid`` is filled with
    ``start:<device>|<parent pid>|<child's time>``. It would join to nothing, and worse,
    two children of one parent would disagree about their parent's identity.
    """
    row = _load_elastic(
        tmp_path, _elastic_record(process_parent_guid=None),
    ).tables[EVENT_PROCESS].iloc[0]
    assert row["parent_process_guid"] == ""


def test_security_4688_is_not_routed_by_either_windows_adapter(tmp_path: Path) -> None:
    """Recorded, because it is why a 4688 assertion cannot be made end to end here.

    Neither Windows adapter maps Security 4688 to the process table -- both route
    Sysmon 1/3 and Security 4624/4625 -- so a 4688 record is *unmapped*, not a process
    row, and the ``start``-from-event-time branch is reached only via a process-create
    event without a GUID. The branch is written so that routing 4688 later needs no
    identity change.

    Asserted behaviourally rather than by reading the routing table, because "does this
    adapter produce a process row for a 4688" is the question that matters and the one a
    future change would answer differently.

    Failure mode: 4688 is routed later, this test fails, and whoever routes it is pointed
    at the two identity tests above instead of discovering the question in production.
    """
    from ath.telemetry.elastic_winevent_source import EVENT_ROUTING

    assert ("security", "4688") not in EVENT_ROUTING

    elastic_dir = tmp_path / "elastic"
    elastic_dir.mkdir()
    elastic = _load_elastic(elastic_dir, _elastic_record(
        _channel="security", event_id="4688", NewProcessId="0x1210",
    ))
    assert elastic.tables[EVENT_PROCESS].empty
    assert "security/4688" in elastic.unmapped

    winlogbeat_dir = tmp_path / "winlogbeat"
    winlogbeat_dir.mkdir()
    beat = _load_winlogbeat(winlogbeat_dir, _winlogbeat_record(
        winlog={"channel": "Security", "event_id": 4688, "record_id": 3,
                "event_data": {"NewProcessId": "0x1210"}},
    ))
    assert beat.tables[EVENT_PROCESS].empty
    assert "Security:4688" in beat.unmapped


# ======================================================================================
# Winlogbeat ECS (the DEDALE layout)
# ======================================================================================


def _winlogbeat_record(**overrides: object) -> dict:
    record = {
        "@timestamp": "2024-12-24T08:00:31.576Z",
        "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 1,
                   "record_id": 9, "event_data": {"Company": "Microsoft Corporation"}},
        "host": {"name": "CLIENT26.breach.local"},
        "user": {"name": "SYSTEM"},
        "process": {
            "name": "smss.exe", "pid": 300,
            "executable": r"C:\Windows\System32\smss.exe",
            "entity_id": "{416dd0c5-6a1f-676a-0300-000000000800}",
            "parent": {"name": "System", "pid": 4,
                       "entity_id": "{416dd0c5-6a1f-676a-eb03-000000000000}"},
        },
    }
    record.update(overrides)
    return record


def _load_winlogbeat(tmp_path: Path, *records: dict) -> SourceLoadResult:
    (tmp_path / "wlb.ndjson").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8",
    )
    return WinlogbeatSource(tmp_path).load()


def test_winlogbeat_reads_the_guid_from_ecs_entity_id(tmp_path: Path) -> None:
    """Where DEDALE actually puts it.

    Verified against ``data/external/dedale/winlogbeat/D02``: every Sysmon 1 record there
    carries ``process.entity_id`` and a ``winlog.event_data`` whose keys are Company,
    Description, FileVersion, IntegrityLevel, LogonGuid, LogonId, OriginalFileName,
    ParentUser, Product, RuleName, TerminalSessionId -- and no ProcessGuid at all.

    Failure mode: the adapter reads ``winlog.event_data.ProcessGuid`` only, which is what
    the raw Sysmon field is called, and the column is empty on the corpus.
    """
    row = _load_winlogbeat(tmp_path, _winlogbeat_record()).tables[EVENT_PROCESS].iloc[0]
    assert row["process_guid"] == "sysmon:416dd0c5-6a1f-676a-0300-000000000800"
    assert row["parent_process_guid"] == "sysmon:416dd0c5-6a1f-676a-eb03-000000000000"


def test_winlogbeat_falls_back_to_the_raw_sysmon_field(tmp_path: Path) -> None:
    """A pipeline that ships ``winlog.event_data`` untouched must not lose the identity.

    Failure mode: only the ECS field is read, and an ``include_raw`` Winlogbeat
    configuration -- or any build without the sysmon module -- silently carries none.
    """
    record = _winlogbeat_record(
        process={"name": "smss.exe", "pid": 300,
                 "executable": r"C:\Windows\System32\smss.exe"},
        winlog={"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 1,
                "record_id": 9,
                "event_data": {"ProcessGuid": "{416DD0C5-6A1F-676A-0300-000000000800}",
                               "ParentProcessGuid": "{416dd0c5-6a1f-676a-eb03-000000000000}"}},
    )
    row = _load_winlogbeat(tmp_path, record).tables[EVENT_PROCESS].iloc[0]
    assert row["process_guid"] == "sysmon:416dd0c5-6a1f-676a-0300-000000000800"
    assert row["parent_process_guid"] == "sysmon:416dd0c5-6a1f-676a-eb03-000000000000"


def test_winlogbeat_process_create_without_a_guid_uses_its_own_time(tmp_path: Path) -> None:
    """Same permitted inference as the Elastic adapter, same reason.

    Failure mode: the two Windows adapters disagree about what a process-create event
    without a GUID is worth, so the same estate read through two pipelines produces two
    different population figures.
    """
    record = _winlogbeat_record(
        process={"name": "smss.exe", "pid": 300,
                 "executable": r"C:\Windows\System32\smss.exe"},
    )
    row = _load_winlogbeat(tmp_path, record).tables[EVENT_PROCESS].iloc[0]
    assert row["process_guid"] == "start:client26|300|2024-12-24T08:00:31.576Z"
    assert row["parent_process_guid"] == ""


def test_winlogbeat_network_row_carries_the_opener_guid_or_nothing(tmp_path: Path) -> None:
    """Sysmon 3 through ECS, and the refusal to guess when it is absent.

    Failure mode: either half -- the guid dropped, or a ``start`` key minted from the
    connection's time.
    """
    base = {
        "@timestamp": "2024-12-24T08:05:00.000Z",
        "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 3,
                   "record_id": 11},
        "host": {"name": "CLIENT26.breach.local"},
        "destination": {"ip": "203.0.113.9", "port": 443},
        "network": {"transport": "tcp", "direction": "outbound"},
    }
    with_guid = {**base, "process": {"name": "chrome.exe", "pid": 900,
                                     "entity_id": "{416dd0c5-6a1f-676a-9a03-000000000800}"}}
    without = {**base, "process": {"name": "chrome.exe", "pid": 900}}
    rows = _load_winlogbeat(tmp_path, with_guid, without).tables[EVENT_NETWORK]
    assert rows["process_guid"].tolist() == [
        "sysmon:416dd0c5-6a1f-676a-9a03-000000000800", "",
    ]


# ======================================================================================
# Defender advanced-hunting export
# ======================================================================================


def test_defender_builds_start_keys_from_the_creation_time_columns() -> None:
    """`ProcessCreationTime` and `InitiatingProcessCreationTime`, off the fixture header.

    The fixture is a three-generation chain -- explorer(900) -> OUTLOOK(2200) ->
    WINWORD(2340) -> powershell(2410) -- so the parent identity of each row is the
    process identity of the row above it, and that is asserted rather than described.

    Failure mode: the adapter maps ``InitiatingProcessParentCreationTime`` into
    ``parent_process_guid``, which is the *grandparent's* time, and every lineage join is
    off by one generation while every column looks fully populated.
    """
    tables = DefenderExportSource(directory=FIXTURES / "defender_export").load().tables
    processes = tables[EVENT_PROCESS].set_index("process_name")

    outlook = processes.loc["OUTLOOK.EXE"]
    winword = processes.loc["WINWORD.EXE"]
    powershell = processes.loc["powershell.exe"]

    assert outlook["process_guid"] == "start:corp-wks01|2200|2026-06-01T09:00:00.123Z"
    assert outlook["parent_process_guid"] == "start:corp-wks01|900|2026-06-01T08:55:03.000Z"
    assert winword["parent_process_guid"] == outlook["process_guid"]
    assert powershell["parent_process_guid"] == winword["process_guid"]

    # The connections are the powershell instance's, by identity and not by PID.
    network = tables[EVENT_NETWORK]
    assert set(network["process_guid"]) == {powershell["process_guid"]}


def test_defender_export_without_the_creation_columns_yields_empty_identities(
    tmp_path: Path,
) -> None:
    """A scoped advanced-hunting query selects fewer columns; that is not malformed.

    Failure mode: the adapter falls back to ``Timestamp``. It coincides with
    ``ProcessCreationTime`` on ``ProcessCreated`` rows and with nothing on a network row,
    so the fallback would be right by luck on one table and wrong on the other.
    """
    process_header = (
        "Timestamp,DeviceName,AccountName,FileName,FolderPath,ProcessId,"
        "ProcessCommandLine,InitiatingProcessFileName,InitiatingProcessId"
    )
    process_row = (
        "2026-06-01T09:00:00Z,CORP-WKS01,rsmith,cmd.exe,C:/Windows,4100,"
        "cmd.exe /c dir,explorer.exe,900"
    )
    (tmp_path / "DeviceProcessEvents.csv").write_text(
        process_header + "\n" + process_row + "\n", encoding="utf-8",
    )
    network_header = (
        "Timestamp,DeviceName,RemoteIP,RemotePort,RemoteUrl,Protocol,"
        "InitiatingProcessAccountName,InitiatingProcessFileName,"
        "InitiatingProcessId,ActionType"
    )
    network_row = (
        "2026-06-01T09:00:05Z,CORP-WKS01,203.0.113.4,443,,tcp,rsmith,"
        "cmd.exe,4100,ConnectionSuccess"
    )
    (tmp_path / "DeviceNetworkEvents.csv").write_text(
        network_header + "\n" + network_row + "\n", encoding="utf-8",
    )
    tables = DefenderExportSource(directory=tmp_path).load().tables
    assert tables[EVENT_PROCESS]["process_guid"].tolist() == [""]
    assert tables[EVENT_PROCESS]["parent_process_guid"].tolist() == [""]
    assert tables[EVENT_NETWORK]["process_guid"].tolist() == [""]


# ======================================================================================
# The synthetic generator
# ======================================================================================


def test_every_synthetic_network_row_names_the_instance_that_opened_it() -> None:
    """The generator builds both rows of a connection, so the join must be total.

    Failure mode, and it was the state of this corpus until M18b-1: benign traffic
    carries a freshly-invented PID belonging to no process row, so a network row whose
    opener is absent is indistinguishable from one whose opener was lost in ingestion --
    and the corpus cannot witness the join it is used to test.
    """
    tables, _ = generate_telemetry()
    processes, network = tables[EVENT_PROCESS], tables[EVENT_NETWORK]

    assert (network["process_guid"] != "").all()
    known = set(processes["process_guid"])
    unmatched = network[~network["process_guid"].isin(known)]
    assert unmatched.empty, unmatched[["device", "process_name", "process_id"]].to_dict()

    # Every process instance is distinct, which is what makes the guid join a function.
    assert not processes["process_guid"].duplicated().any()


def test_a_synthetic_network_row_agrees_with_its_opener_on_device_pid_and_account() -> None:
    """The identity is not a parallel invention: it names a row that matches it.

    Failure mode: the identity is attached to the connection but the PID or the account
    on the row is still drawn independently, so evidence text and the join disagree.
    """
    tables, _ = generate_telemetry()
    openers = tables[EVENT_PROCESS].set_index("process_guid")
    for _, row in tables[EVENT_NETWORK].iterrows():
        opener = openers.loc[row["process_guid"]]
        assert (opener["device"], opener["process_id"], opener["user"]) == (
            row["device"], row["process_id"], row["user"]
        )


def test_a_synthetic_parent_identity_always_resolves_to_a_row() -> None:
    """Populated only where the generator knows the parent instance, and then correctly.

    Failure mode: the generator reconstructs a parent by looking for the most recent row
    with a matching PID -- the guess the whole module exists to refuse -- and the column
    populates with values that are right most of the time.
    """
    tables, _ = generate_telemetry()
    processes = tables[EVENT_PROCESS]
    known = set(processes["process_guid"])
    named = processes[processes["parent_process_guid"] != ""]
    assert not named.empty
    assert named["parent_process_guid"].isin(known).all()

    by_guid = processes.set_index("process_guid")
    for _, row in named.iterrows():
        parent = by_guid.loc[row["parent_process_guid"]]
        assert parent["device"] == row["device"]
        assert parent["process_id"] == row["parent_process_id"]
        assert parent["timestamp"] <= row["timestamp"]


def test_the_generator_gives_two_runs_of_one_pid_two_identities() -> None:
    """The property the corpus is supposed to demonstrate, demonstrated on it.

    Failure mode: the generator's identity collapses to ``(device, pid)`` and the
    synthetic corpus stops being able to fail the way real data does.
    """
    config = GeneratorConfig()
    tables, _ = generate_telemetry(config)
    processes = tables[EVENT_PROCESS]
    later_tables, _ = generate_telemetry(
        GeneratorConfig(seed=config.seed, start=config.start + timedelta(days=1)),
    )
    later = later_tables[EVENT_PROCESS]
    first = processes.iloc[0]
    same_slot = later[
        (later["device"] == first["device"])
        & (later["process_id"] == first["process_id"])
    ]
    assert not same_slot.empty, "the two runs share no (device, pid) to compare"
    assert (same_slot["process_guid"] != first["process_guid"]).all()


# ======================================================================================
# Round trip and the frozen artifacts
# ======================================================================================


def test_write_then_load_preserves_the_three_columns(tmp_path: Path) -> None:
    """Through CSV and back, values included -- not merely the column names.

    Failure mode: the columns survive but the values do not (an empty string read back as
    ``NaN``, a rename on the way out), so a directory written by an import loses the
    identity the adapter worked to carry.
    """
    tables, ground_truth = generate_telemetry()
    write_normalized_telemetry(
        SourceLoadResult(tables=tables, issues=[]), tmp_path, ground_truth=ground_truth,
    )
    reloaded = load_telemetry(tmp_path)

    for column in ("process_guid", "parent_process_guid"):
        assert reloaded.processes[column].tolist() == tables[EVENT_PROCESS][column].tolist()
    assert reloaded.network["process_guid"].tolist() == tables[EVENT_NETWORK]["process_guid"].tolist()


def test_a_pre_schema_parquet_is_widened_with_a_notice(tmp_path: Path) -> None:
    """A frozen artifact stays readable, and says out loud that it is older than the column.

    Failure mode: the columns are added silently, and a zero population for them reads as
    "this corpus carried no identity" when it means "this file predates the column" --
    two facts with completely different consequences.
    """
    import sys

    sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
    from pre_schema_parquet import NOTICE_PREFIX, read_canonical_table

    old_columns = [c for c in PROCESS_COLUMNS
                   if c not in ("process_guid", "parent_process_guid")]
    frame = pd.DataFrame([{c: "" for c in old_columns}])
    frame["timestamp"] = pd.Timestamp("2022-11-16T19:59:52Z")
    frame["event_type"] = "process"
    frame["event_id"] = "e1"
    frame.to_parquet(tmp_path / "old_process.parquet")

    said: list[str] = []
    widened = read_canonical_table(tmp_path, "old", "process", EVENT_PROCESS,
                                   notice=said.append)
    assert list(widened.columns) == old_columns + ["process_guid", "parent_process_guid"]
    assert (widened["process_guid"] == "").all()
    assert len(said) == 1
    assert said[0].startswith(NOTICE_PREFIX)
    assert "process_guid" in said[0] and "parent_process_guid" in said[0]

    # A file that already matches the schema is returned untouched and says nothing.
    quiet: list[str] = []
    widened.to_parquet(tmp_path / "new_process.parquet")
    read_canonical_table(tmp_path, "new", "process", EVENT_PROCESS, notice=quiet.append)
    assert quiet == []


def test_a_source_with_no_endpoint_telemetry_still_emits_the_columns() -> None:
    """CloudTrail and Kubernetes emit empty process/network tables, schema-valid.

    Failure mode: an adapter builds its empty frames from a hand-written column list
    rather than from ``TABLE_COLUMNS``, and the day a column is added it stops loading.
    """
    from ath.telemetry.k8s_audit_source import K8sAuditSource

    tables = K8sAuditSource(FIXTURES / "k8s_audit", cluster="test").load().tables
    assert list(tables[EVENT_PROCESS].columns) == list(PROCESS_COLUMNS)
    assert list(tables[EVENT_NETWORK].columns) == list(NETWORK_COLUMNS)
    assert tables[EVENT_PROCESS].empty and tables[EVENT_NETWORK].empty


# ======================================================================================
# M18b-2: the key two rows are joined on, and when the join is only a pid
# ======================================================================================


def test_an_identity_key_can_never_collide_with_a_pid_fallback() -> None:
    """The fallback is tagged, so no ``(device, pid)`` can impersonate an identity.

    Would catch: a fallback rendered as a bare string (``"pc01|4444"``) that a source
    could, in principle, emit as an identity -- silently joining a slot to an instance.
    """
    identity = InstanceKey(identity="start:pc01|4444|t", device="pc01", process_id=4444)
    fallback = InstanceKey(identity="", device="pc01", process_id=4444)

    assert identity != fallback
    assert len({identity, fallback}) == 2
    assert fallback.tag[0] == "pid" and identity.tag[0] == "identity"


def test_equality_is_the_identity_and_not_the_slot_it_ran_in() -> None:
    """One instance seen through two rows is one key, whatever pid those rows carry.

    A Sysmon GUID is globally unique by construction, so the device and pid on the row
    are the fallback's raw material and never part of the identity.
    """
    left = InstanceKey(identity="sysmon:abc", device="pc01", process_id=4444)
    right = InstanceKey(identity="sysmon:abc", device="pc02", process_id=10)

    assert left == right
    assert len({left, right}) == 1


def test_two_identities_of_one_scheme_never_fall_back_to_the_pid() -> None:
    """The correctness half: two named instances on one slot are two processes.

    Would catch: a "try identity, then try pid" implementation, which is the obvious
    one, resurrects every false attribution this work removed, and still passes every
    test that only checks a join *succeeds*.
    """
    first = instance_key("start:pc01|4444|09:00", "pc01", 4444)
    second = instance_key("start:pc01|4444|10:00", "pc01", 4444)

    assert first.joins(second) == (False, False)
    assert match_keys({first}, {second}) == (False, False)


def test_a_missing_identity_falls_back_to_the_slot_and_says_so() -> None:
    identified = instance_key("sysmon:abc", "pc01", 4444)
    silent = instance_key("", "pc01", 4444)

    assert identified.joins(silent) == (True, True)
    assert silent.joins(silent) == (True, True)
    assert match_keys({identified}, {silent}) == (True, True)


def test_two_authorities_are_compared_as_slots_and_never_as_text() -> None:
    """``sysmon:X`` and ``start:X`` are two answers, not one agreement."""
    sysmon = instance_key(f"{SCHEME_SYSMON}:X", "pc01", 4444)
    start = instance_key(f"{SCHEME_START}:X", "pc01", 4444)
    elsewhere = instance_key(f"{SCHEME_START}:X", "pc02", 10)

    assert sysmon.joins(start) == (True, True), "same slot, so the fallback joins them"
    assert sysmon.joins(elsewhere) == (False, True), "different slot, nothing to join"


def test_one_identity_backed_match_is_not_downgraded_by_a_weaker_one() -> None:
    """A finding whose evidence spans several rows keeps its strongest witness."""
    identity = instance_key("sysmon:abc", "pc01", 4444)
    slot = instance_key("", "pc01", 4444)

    assert match_keys({identity, slot}, {identity}) == (True, False)
    assert match_keys({slot}, {slot}) == (True, True)


def test_a_row_that_names_no_instance_at_all_has_no_key() -> None:
    """Neither an identity nor a pid is not a weak witness; it is not a witness.

    Would catch: a key of ``("pid", device, None)``, which joins every other pid-less
    row on the host and inflates every attribution count downstream.
    """
    assert instance_key("", "pc01", None) is None
    assert instance_key(None, "pc01", pd.NA) is None
    assert instance_key("", "pc01", 4444) is not None


def test_a_value_of_no_known_scheme_is_treated_as_absent() -> None:
    """An identity nothing minted would compare equal to nothing and join nothing.

    Better to fall back to the slot and label it than to hold a value that silently
    matches no row anywhere -- which looks, in a population count, exactly like success.
    """
    key = instance_key("4fd6b357-no-scheme-prefix", "pc01", 4444)

    assert key.has_identity is False
    assert key.joins(instance_key("", "pc01", 4444)) == (True, True)
