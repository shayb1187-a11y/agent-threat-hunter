"""An impossible event time is quarantined, never repaired and never silently kept.

Why these tests exist
----------------------
A network row timestamped ``1990-12-18T16:48:25Z`` passed canonicalisation unflagged on
COMISET and became the lower bound of that corpus' observed network window
(``reports/m17/H4_FROZEN.json`` ``/observed_window/network``). Nothing downstream is
robust to that: ``Telemetry.time_range``, every sliding correlation window, and every
per-day rate are computed from the extremes, so one corrupt clock field silently
stretches the corpus by 35 years and divides every rate by the result.

The contract
-------------
A row is removed when its timestamp is ``NaT``, earlier than ``TIMESTAMP_FLOOR``, or
later than load time plus a day. It becomes one :class:`NormalizationIssue` with
``field="timestamp"``, a reason naming the bound it broke and the offending value, and
``raw_reference`` carrying the row's ``source_ref`` so it can be found in the original.
Nothing is clamped and nothing is substituted -- a repaired timestamp is a time this
project invented, and every window and chain downstream would treat it as observed.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pandas as pd
import pytest

from ath.schema import (
    EVENT_CONTROL,
    EVENT_LOGON,
    EVENT_NETWORK,
    EVENT_PROCESS,
    TABLE_COLUMNS,
)
from ath.telemetry.cloudtrail_source import CloudTrailSource
from ath.telemetry.defender_source import DefenderExportSource
from ath.telemetry.elastic_winevent_source import ElasticWinEventSource
from ath.telemetry.k8s_audit_source import K8sAuditSource
from ath.telemetry.loader import Telemetry
from ath.telemetry.normalize import (
    QUARANTINE_REASON_PREFIX,
    TIMESTAMP_CEILING_SLACK,
    TIMESTAMP_FLOOR,
    coerce_and_validate,
    quarantine_implausible_timestamps,
)
from ath.telemetry.synthetic_source import SyntheticTelemetrySource
from ath.telemetry.winlogbeat_source import WinlogbeatSource

NOW = pd.Timestamp.now(tz="UTC")

# The values a corrupt clock field actually takes, plus both sides of each bound.
# "admitted" here means "this is a plausible event time", not "this file was admitted".
# 1601-01-01 (Windows FILETIME zero) is deliberately absent: it is below
# ``pd.Timestamp.min`` (1677-09-21) at nanosecond resolution, so it can never *become* a
# canonical timestamp -- see test_filetime_zero_never_reaches_a_canonical_table.
def boundary_cases() -> list[tuple[str, pd.Timestamp, bool]]:
    """Built at call time, not import time.

    The ceiling is ``now + 1 day`` *at load time*, so a "one second past the ceiling"
    value fixed at import becomes plausible the moment the rest of the suite has taken a
    second to run. Evaluating here keeps the one-second edge a real edge instead of a
    flake that resolves in whichever direction the suite's runtime happens to fall.
    """
    now = pd.Timestamp.now(tz="UTC")
    return [
        ("comiset_1990", pd.Timestamp("1990-12-18T16:48:25Z"), False),
        ("unix_epoch_zero", pd.Timestamp("1970-01-01T00:00:00Z"), False),
        ("floor_exactly", TIMESTAMP_FLOOR, True),
        ("one_second_below_floor", TIMESTAMP_FLOOR - pd.Timedelta(seconds=1), False),
        ("one_second_past_ceiling",
         now + TIMESTAMP_CEILING_SLACK + pd.Timedelta(seconds=1), False),
        ("now", now, True),
    ]


# --------------------------------------------------------------------------------------
# The function itself, on two different tables built from different values
# --------------------------------------------------------------------------------------


FILETIME_ZERO = "1601-01-01T00:00:00Z"


def _network_table(stamps: list[pd.Timestamp]) -> pd.DataFrame:
    if not stamps:
        return coerce_and_validate(
            pd.DataFrame(columns=list(TABLE_COLUMNS[EVENT_NETWORK])), EVENT_NETWORK,
        )
    return coerce_and_validate(pd.DataFrame([
        {
            "event_id": f"n-{i:03d}", "timestamp": stamp, "event_type": EVENT_NETWORK,
            "device": "KIOSK-14", "user": "hana.mori", "source": "test",
            "source_ref": f"ReportId=net-{i:03d};File=kiosk.csv",
            "process_name": "curl.exe", "process_id": 700 + i,
            "remote_ip": "198.51.100.9", "remote_port": 4444, "protocol": "tcp",
            "direction": "outbound", "remote_url": "",
        }
        for i, stamp in enumerate(stamps)
    ]), EVENT_NETWORK)


def _control_table(stamps: list[pd.Timestamp]) -> pd.DataFrame:
    return coerce_and_validate(pd.DataFrame([
        {
            "event_id": f"c-{i:03d}", "timestamp": stamp, "event_type": EVENT_CONTROL,
            "device": "k8s:staging-us", "user": "svc-migrator", "source": "test",
            "source_ref": f"auditID=ctl-{i:03d};File=staging.log",
            "actor": "ops.kwan", "actor_groups": "system:authenticated",
            "verb": "attach", "resource_type": "clusterrolebindings",
            "resource_name": f"binding-{i}", "resource_namespace": "kube-system",
            "target_actor": "svc-migrator", "role_ref": "cluster-admin",
            "decision": "allowed", "source_ip": "10.7.0.4",
        }
        for i, stamp in enumerate(stamps)
    ]), EVENT_CONTROL)


TABLE_BUILDERS = {EVENT_NETWORK: _network_table, EVENT_CONTROL: _control_table}


@pytest.mark.parametrize("event_type", list(TABLE_BUILDERS), ids=list(TABLE_BUILDERS))
def test_each_bound_is_enforced_on_the_side_it_is_on(event_type) -> None:
    """How this fails: use ``<=`` for the floor and ``floor_exactly`` is quarantined; use
    ``<`` for the epoch values and 1970 survives as a real event time."""
    cases = boundary_cases()
    plausible = [c for c in cases if c[2]]
    implausible = [c for c in cases if not c[2]]
    table = TABLE_BUILDERS[event_type]([c[1] for c in cases])

    kept, issues = quarantine_implausible_timestamps(table, event_type)

    assert len(kept) == len(plausible)
    assert len(issues) == len(implausible)
    assert set(kept["timestamp"]) == {c[1] for c in plausible}
    # Quarantined rows are gone from the table, not merely flagged in it.
    for _, stamp, _ in implausible:
        assert stamp not in set(kept["timestamp"])


@pytest.mark.parametrize("event_type", list(TABLE_BUILDERS), ids=list(TABLE_BUILDERS))
def test_a_quarantined_row_keeps_its_reason_value_and_source_ref(event_type) -> None:
    """How this fails: drop ``raw_reference`` and the row is countable but unfindable --
    which is how an unexplained 35-year window becomes permanent."""
    table = TABLE_BUILDERS[event_type]([
        pd.Timestamp("1990-12-18T16:48:25Z"), NOW - pd.Timedelta(hours=1),
    ])

    kept, issues = quarantine_implausible_timestamps(table, event_type)

    assert len(kept) == 1 and len(issues) == 1
    issue = issues[0]
    assert issue.event_type == event_type
    assert issue.field == "timestamp"
    assert issue.reason.startswith(QUARANTINE_REASON_PREFIX)
    assert "earlier than the floor" in issue.reason
    assert "1990-12-18" in issue.reason            # the offending value, not a summary
    assert issue.raw_reference == table.iloc[0]["source_ref"]


@pytest.mark.parametrize("event_type", list(TABLE_BUILDERS), ids=list(TABLE_BUILDERS))
def test_the_quarantine_reason_is_countable_separately(event_type) -> None:
    """How this fails: reuse the "unparseable timestamp" wording and a corrupt-clock
    corpus is indistinguishable from a corpus whose timestamps would not parse."""
    table = TABLE_BUILDERS[event_type]([pd.Timestamp("1970-01-01T00:00:00Z")])
    _, issues = quarantine_implausible_timestamps(table, event_type)
    assert [i for i in issues if i.reason.startswith(QUARANTINE_REASON_PREFIX)]
    assert not [i for i in issues if "unparseable" in i.reason]


def test_a_missing_timestamp_is_quarantined_not_kept_as_nat() -> None:
    """How this fails: test only the two bounds and a NaT row stays in the table, where
    it silently drops out of every comparison instead of being reported."""
    table = _network_table([NOW - pd.Timedelta(minutes=5)])
    table.loc[0, "timestamp"] = pd.NaT

    kept, issues = quarantine_implausible_timestamps(table, EVENT_NETWORK)

    assert kept.empty and len(issues) == 1
    assert "NaT" in issues[0].reason


def test_nothing_is_repaired() -> None:
    """How this fails: clamp to the floor instead of quarantining, and the corrupt row
    stays in the table as a real 2000-01-01 event that nothing ever observed."""
    table = _network_table([pd.Timestamp("1990-12-18T16:48:25Z")])
    kept, _ = quarantine_implausible_timestamps(table, EVENT_NETWORK)
    assert kept.empty
    assert TIMESTAMP_FLOOR not in set(kept["timestamp"])


def test_an_empty_table_is_returned_untouched() -> None:
    kept, issues = quarantine_implausible_timestamps(_network_table([]), EVENT_NETWORK)
    assert kept.empty and issues == []


def test_filetime_zero_never_reaches_a_canonical_table(tmp_path) -> None:
    """A zeroed Windows FILETIME is caught one layer earlier, and that is worth pinning.

    ``1601-01-01`` is below ``pd.Timestamp.min``, so it cannot be represented at all: the
    adapter's own ``errors="coerce"`` turns it into ``NaT`` and reports it as unparseable
    before quarantine is reached. The two layers therefore cover the value between them --
    what must never happen is that it lands in the table, by either route.

    How this fails: parse timestamps without ``errors="coerce"`` and this raises
    ``OutOfBoundsDatetime`` mid-import, losing the whole file to one bad clock field.
    """
    directory = tmp_path / "filetime"
    directory.mkdir()
    (directory / "slice.jsonl").write_text(json.dumps({
        "_channel": "sysmon", "event_id": "3", "_doc_id": "ft0",
        "event_original_time": FILETIME_ZERO, "host_name": "OLD-PC.lab.local",
        "process_name": "svchost.exe", "dst_ip_addr": "203.0.113.7", "dst_port": 443,
    }) + "\n", encoding="utf-8")

    result = ElasticWinEventSource(directory).load()

    assert result.tables[EVENT_NETWORK].empty
    assert len(result.issues) == 1
    assert "no parseable timestamp" in result.issues[0].reason


# --------------------------------------------------------------------------------------
# Every source reaches quarantine
# --------------------------------------------------------------------------------------

CORRUPT = "1990-12-18T16:48:25Z"


def _elastic(directory: Path):
    (directory / "winevent.jsonl").write_text(json.dumps({
        "_channel": "sysmon", "event_id": "3", "_doc_id": "e1",
        "event_original_time": CORRUPT, "host_name": "TILL-02.retail.local",
        "user_name": "ana.pires", "process_name": "svchost.exe", "process_id": 812,
        "dst_ip_addr": "203.0.113.7", "dst_port": 443, "network_protocol": "tcp",
        "network_initiated": "true",
    }) + "\n", encoding="utf-8")
    return ElasticWinEventSource(directory), EVENT_NETWORK


def _winlogbeat(directory: Path):
    (directory / "winlogbeat.ndjson").write_text(json.dumps({
        "@timestamp": CORRUPT,
        "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 1,
                   "record_id": 9},
        "host": {"name": "LAB-7.eng.local"}, "user": {"name": "ruth.abebe"},
        "process": {"name": "wscript.exe", "pid": 4242,
                    "parent": {"name": "outlook.exe", "pid": 33}},
    }) + "\n", encoding="utf-8")
    return WinlogbeatSource(directory), EVENT_PROCESS


def _k8s(directory: Path):
    (directory / "audit.log").write_text(json.dumps({
        "kind": "Event", "apiVersion": "audit.k8s.io/v1", "auditID": "old-1",
        "stage": "ResponseComplete", "verb": "create",
        "user": {"username": "legacy-bot"}, "sourceIPs": ["10.1.2.3"],
        "objectRef": {"resource": "rolebindings", "namespace": "legacy", "name": "rb"},
        "requestObject": {"subjects": [{"kind": "User", "name": "mallory"}],
                          "roleRef": {"kind": "ClusterRole", "name": "admin"}},
        "responseStatus": {"code": 201}, "stageTimestamp": CORRUPT,
    }) + "\n", encoding="utf-8")
    return K8sAuditSource(directory, cluster="legacy-dc"), EVENT_CONTROL


def _cloudtrail(directory: Path):
    (directory / "CloudTrail_ap-south-1.json").write_text(json.dumps({"Records": [{
        "eventVersion": "1.08", "eventID": "old-ct-1", "eventTime": CORRUPT,
        "eventName": "ConsoleLogin", "awsRegion": "ap-south-1",
        "recipientAccountId": "111122223333", "sourceIPAddress": "198.51.100.2",
        "userIdentity": {"type": "IAMUser", "userName": "otto.kim"},
        "responseElements": {"ConsoleLogin": "Success"},
    }]}), encoding="utf-8")
    return CloudTrailSource(directory), EVENT_LOGON


def _defender(directory: Path):
    (directory / "DeviceLogonEvents.csv").write_text(
        "Timestamp,DeviceName,AccountName,LogonType,ActionType,RemoteIP,"
        "RemoteDeviceName,FailureReason,ReportId\n"
        f"{CORRUPT},DESK-31,viktor.sol,Network,LogonSuccess,192.0.2.55,JUMP-1,,88\n",
        encoding="utf-8",
    )
    return DefenderExportSource(directory=directory), EVENT_LOGON


SOURCE_BUILDERS = {
    "elastic_winevent": _elastic,
    "winlogbeat": _winlogbeat,
    "k8s_audit": _k8s,
    "cloudtrail": _cloudtrail,
    "defender": _defender,
}


@pytest.mark.parametrize("kind", list(SOURCE_BUILDERS), ids=list(SOURCE_BUILDERS))
def test_every_source_routes_its_rows_through_quarantine(kind, tmp_path) -> None:
    """How this fails: leave any one adapter on plain ``coerce_and_validate`` and its
    1990 row lands in the table, with the boundary reporting a clean import."""
    directory = tmp_path / kind
    directory.mkdir()
    source, table = SOURCE_BUILDERS[kind](directory)

    result = source.load()

    assert result.tables[table].empty, f"{kind} kept a 1990 row"
    quarantined = [i for i in result.issues
                   if i.reason.startswith(QUARANTINE_REASON_PREFIX)]
    assert len(quarantined) == 1, result.issues
    assert quarantined[0].field == "timestamp"
    assert quarantined[0].raw_reference    # findable in the original file


def test_the_synthetic_generator_passes_quarantine_untouched() -> None:
    """The bound has to be a statement about the world, not about the corpora it was
    written for. How this fails: raise the floor past 2026 and this goes red first."""
    result = SyntheticTelemetrySource().load()
    assert [i for i in result.issues
            if i.reason.startswith(QUARANTINE_REASON_PREFIX)] == []
    assert result.rows_kept == result.rows_read


# --------------------------------------------------------------------------------------
# The reason this matters downstream
# --------------------------------------------------------------------------------------


def test_time_range_no_longer_includes_the_corrupt_bound(tmp_path) -> None:
    """How this fails: keep the row and ``time_range`` spans 35 years, so every
    findings-per-day rate is divided by 12,700 and reads as nothing is happening."""
    directory = tmp_path / "winevent"
    directory.mkdir()
    good = NOW - pd.Timedelta(hours=2)
    lines = [
        {"_channel": "sysmon", "event_id": "3", "_doc_id": "corrupt",
         "event_original_time": CORRUPT, "host_name": "TILL-02",
         "process_name": "svchost.exe", "dst_ip_addr": "203.0.113.7", "dst_port": 443},
        {"_channel": "sysmon", "event_id": "3", "_doc_id": "good",
         "event_original_time": good.isoformat(), "host_name": "TILL-02",
         "process_name": "svchost.exe", "dst_ip_addr": "203.0.113.8", "dst_port": 443},
    ]
    (directory / "slice.jsonl").write_text(
        "\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8",
    )

    result = ElasticWinEventSource(directory).load()
    telemetry = Telemetry(
        processes=result.tables[EVENT_PROCESS], network=result.tables[EVENT_NETWORK],
        logons=result.tables[EVENT_LOGON], controls=result.tables[EVENT_CONTROL],
    )

    earliest, latest = telemetry.time_range
    assert earliest >= TIMESTAMP_FLOOR
    assert latest - earliest < timedelta(days=1)
