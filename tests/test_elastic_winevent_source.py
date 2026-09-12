"""Tests for the Elastic/HELK Windows-event adapter.

Written against the *schema*, not against COMISET: the fixtures below are hand-built
records in the HELK ``logs-endpoint-winevent-*`` layout, which is also what OTRF's
Security-Datasets publish. If they were slices of one corpus these tests would pass for
that corpus and say nothing about the next one.

The emphasis is on what the adapter refuses to do. An ingestion layer that invents a
field is worse than one that leaves it empty, because everything downstream treats a
populated column as evidence.
"""

from __future__ import annotations

import json

import pandas as pd
import pytest

from ath.schema import SIG_UNKNOWN
from ath.telemetry.elastic_winevent_source import ElasticWinEventSource


def _write(tmp_path, *records, name="events.jsonl"):
    path = tmp_path / name
    path.write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"
    )
    return tmp_path


PROCESS = {
    "_channel": "sysmon", "event_id": "1", "_doc_id": "abc",
    "event_original_time": "2022-11-16T19:59:52.774Z",
    "host_name": "desktop-4pvps6e.phoenix.local",
    "user_account": "PHOENIX\\a.moreau", "user_name": "a.moreau",
    "process_name": "powershell.exe", "process_id": 6076,
    "CommandLine": "powershell.exe -enc SQBFAFgA",
    "process_parent_name": "WINWORD.EXE", "process_parent_id": 824,
    "process_path": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
    "hash_sha256": "D86E12BAB29F92F7E6772543B7D0D93F",
    "Company": "Microsoft Corporation",
}

NETWORK = {
    "_channel": "sysmon", "event_id": "3",
    "event_original_time": "2022-11-16T20:00:02.000Z",
    "host_name": "desktop-4pvps6e.phoenix.local",
    "user_name": "a.moreau", "process_name": "powershell.exe", "process_id": 6076,
    "dst_ip_addr": "185.220.101.47", "dst_port": 443,
    "network_protocol": "tcp", "network_initiated": "true",
}

LOGON_FAIL = {
    "_channel": "security", "event_id": "4625",
    "event_original_time": "2022-11-25T14:27:53.749Z",
    "host_name": "desktop-4pvps6e.phoenix.local",
    "TargetUserName": "PHOENIX\\beer-guy", "logon_type": 3,
    "SubStatus": "0xC000006A", "Status": "0xc000018d",
    "WorkstationName": "KALI-BOX.phoenix.local", "IpAddress": "10.66.6.99",
}


# ======================================================================================
# Routing and normalisation
# ======================================================================================


def test_each_event_class_lands_in_its_own_table(tmp_path) -> None:
    result = ElasticWinEventSource(_write(tmp_path, PROCESS, NETWORK, LOGON_FAIL)).load()
    assert {k: len(v) for k, v in result.tables.items()} == {
        "process": 1, "network": 1, "logon": 1, "control": 0,
    }
    assert result.rows_read == 3
    assert not result.issues


def test_the_fully_qualified_host_is_shortened_consistently(tmp_path) -> None:
    """``desktop-4pvps6e.phoenix.local`` and ``desktop-4pvps6e`` are one machine.

    Correlation keys on the device name, so leaving both forms in circulation would
    split one host in two and quietly halve every per-host measurement.
    """
    result = ElasticWinEventSource(_write(tmp_path, PROCESS, NETWORK)).load()
    assert set(result.tables["process"]["device"]) == {"desktop-4pvps6e"}
    assert set(result.tables["network"]["device"]) == {"desktop-4pvps6e"}


def test_the_domain_is_stripped_from_the_account(tmp_path) -> None:
    result = ElasticWinEventSource(_write(tmp_path, PROCESS, LOGON_FAIL)).load()
    assert set(result.tables["process"]["user"]) == {"a.moreau"}
    assert set(result.tables["logon"]["user"]) == {"beer-guy"}


def test_process_lineage_and_command_line_survive(tmp_path) -> None:
    row = ElasticWinEventSource(_write(tmp_path, PROCESS)).load().tables["process"].iloc[0]
    assert row["process_name"] == "powershell.exe"
    assert row["parent_process_name"] == "winword.exe"
    assert int(row["parent_process_id"]) == 824
    assert "-enc" in row["command_line"]


def test_a_failure_code_becomes_a_name_an_analyst_reads(tmp_path) -> None:
    row = ElasticWinEventSource(_write(tmp_path, LOGON_FAIL)).load().tables["logon"].iloc[0]
    assert row["action"] == "failure"
    assert row["failure_reason"] == "bad_password"
    assert int(row["logon_type"]) == 3


def test_outbound_direction_is_read_from_initiated(tmp_path) -> None:
    row = ElasticWinEventSource(_write(tmp_path, NETWORK)).load().tables["network"].iloc[0]
    assert row["direction"] == "outbound"
    assert row["remote_ip"] == "185.220.101.47"
    assert int(row["remote_port"]) == 443


# ======================================================================================
# What it refuses to invent
# ======================================================================================


def test_signature_status_is_unknown_because_the_schema_carries_no_verdict(tmp_path) -> None:
    """``Company`` is version-info metadata that any binary can claim, not a signature.

    Promoting it to "signed" would put a value into a column later logic trusts, on
    evidence that does not support it.
    """
    row = ElasticWinEventSource(_write(tmp_path, PROCESS)).load().tables["process"].iloc[0]
    assert row["signature_status"] == SIG_UNKNOWN
    assert row["signer"] == "Microsoft Corporation"


def test_unmapped_event_classes_are_counted_not_guessed(tmp_path) -> None:
    """Sysmon 12 (registry) has no canonical home. It is reported, not coerced."""
    registry = {"_channel": "sysmon", "event_id": "12",
                "event_original_time": "2022-11-16T19:00:00Z", "host_name": "h.local"}
    result = ElasticWinEventSource(_write(tmp_path, PROCESS, registry)).load()
    assert result.unmapped == {"sysmon/12": 1}
    assert len(result.tables["process"]) == 1


def test_an_event_with_no_host_is_dropped_with_a_reason(tmp_path) -> None:
    headless = dict(PROCESS)
    headless.pop("host_name")
    result = ElasticWinEventSource(_write(tmp_path, headless)).load()
    assert len(result.tables["process"]) == 0
    assert result.issues and "names no host" in result.issues[0].reason


def test_an_unparseable_timestamp_is_dropped_with_a_reason(tmp_path) -> None:
    broken = dict(PROCESS, event_original_time="not-a-time", **{"@timestamp": "also-not"})
    broken.pop("event_recorded_time", None)
    result = ElasticWinEventSource(_write(tmp_path, broken)).load()
    assert len(result.tables["process"]) == 0
    assert result.issues and "timestamp" in result.issues[0].reason


def test_one_bad_line_does_not_lose_the_file(tmp_path) -> None:
    """A truncated export is a fact about the world, not a reason to drop a million rows."""
    path = tmp_path / "events.jsonl"
    path.write_text(
        json.dumps(PROCESS) + "\n{ not json\n" + json.dumps(NETWORK) + "\n",
        encoding="utf-8",
    )
    result = ElasticWinEventSource(tmp_path).load()
    assert len(result.tables["process"]) == 1
    assert len(result.tables["network"]) == 1
    assert any("not valid JSON" in i.reason for i in result.issues)


def test_a_raw_search_hit_still_loads(tmp_path) -> None:
    """A dump that still carries the ``_source`` envelope works as well as a slice."""
    hit = {
        "_index": "logs-endpoint-winevent-sysmon-2022.11.16",
        "_id": "deadbeef",
        "_source": {k: v for k, v in PROCESS.items() if not k.startswith("_")},
    }
    result = ElasticWinEventSource(_write(tmp_path, hit)).load()
    assert len(result.tables["process"]) == 1
    assert result.tables["process"].iloc[0]["source_ref"].endswith("deadbeef")


def test_an_empty_directory_fails_clearly(tmp_path) -> None:
    with pytest.raises(FileNotFoundError, match="Elastic-exported"):
        ElasticWinEventSource(tmp_path).load()


def test_timestamps_are_timezone_aware(tmp_path) -> None:
    frame = ElasticWinEventSource(_write(tmp_path, PROCESS)).load().tables["process"]
    assert pd.api.types.is_datetime64_any_dtype(frame["timestamp"])
    assert frame["timestamp"].dt.tz is not None
