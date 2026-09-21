"""Tests for the telemetry layer.

These are not box-ticking tests. Each one guards a property the rest of the project
depends on:

* the schema contract holds (or detections break silently)
* generation is deterministic (or the README's numbers become lies)
* the dataset is mostly benign (or the project is a toy)
* the encoded PowerShell is genuinely decodable (or our decoder is theatre)
* timestamps are timezone-aware (or time correlation raises at runtime)
"""

from __future__ import annotations

import base64
from pathlib import Path

import pandas as pd
import pytest

from ath.schema import (
    EVENT_LOGON,
    EVENT_PROCESS,
    TABLE_COLUMNS,
    SchemaError,
    describe_logon_type,
    validate_frame,
)
from ath.telemetry import (
    GeneratorConfig,
    generate_telemetry,
    load_ground_truth,
    load_telemetry,
    write_telemetry,
)
from ath.telemetry.generator import C2_IP, C2_STAGER_SCRIPT, encode_powershell


@pytest.fixture(scope="module")
def generated() -> tuple[dict[str, pd.DataFrame], dict]:
    """Generate telemetry once for the whole module."""
    return generate_telemetry(GeneratorConfig())


@pytest.fixture(scope="module")
def telemetry_dir(tmp_path_factory, generated) -> Path:
    """Write the generated telemetry to a temp dir and return it."""
    tables, ground_truth = generated
    out = tmp_path_factory.mktemp("telemetry")
    write_telemetry(tables, ground_truth, out)
    return out


# ----------------------------------------------------------------------------- schema


def test_every_table_matches_declared_schema(generated) -> None:
    tables, _ = generated
    for event_type, df in tables.items():
        validate_frame(df, event_type)
        assert list(df.columns) == list(TABLE_COLUMNS[event_type])


def test_validate_frame_rejects_missing_columns() -> None:
    df = pd.DataFrame({"event_id": ["evt-1"], "event_type": [EVENT_PROCESS]})
    with pytest.raises(SchemaError, match="missing required columns"):
        validate_frame(df, EVENT_PROCESS)


def test_validate_frame_rejects_duplicate_event_ids(generated) -> None:
    tables, _ = generated
    df = pd.concat([tables[EVENT_PROCESS].head(2)] * 2, ignore_index=True)
    with pytest.raises(SchemaError, match="duplicate event_ids"):
        validate_frame(df, EVENT_PROCESS)


def test_event_ids_are_globally_unique(generated) -> None:
    """IDs are the backbone of evidence traceability -- a collision corrupts a report."""
    tables, _ = generated
    all_ids = pd.concat([df["event_id"] for df in tables.values()])
    assert all_ids.is_unique


def test_describe_logon_type() -> None:
    assert describe_logon_type(3).startswith("Network")
    assert describe_logon_type(10).startswith("RemoteInteractive")
    assert describe_logon_type(None) == "Unknown"


# -------------------------------------------------------------------------- generator


def test_generation_is_deterministic() -> None:
    a, _ = generate_telemetry(GeneratorConfig(seed=42))
    b, _ = generate_telemetry(GeneratorConfig(seed=42))
    for event_type in a:
        pd.testing.assert_frame_equal(a[event_type], b[event_type])


def test_different_seeds_produce_different_noise() -> None:
    a, _ = generate_telemetry(GeneratorConfig(seed=1))
    b, _ = generate_telemetry(GeneratorConfig(seed=2))
    assert not a[EVENT_PROCESS].equals(b[EVENT_PROCESS])


def test_dataset_is_mostly_benign(generated) -> None:
    """The malicious signal must be a small minority, or hunting is trivial."""
    tables, ground_truth = generated
    total = sum(len(df) for df in tables.values())
    labelled = sum(len(s["event_ids"]) for s in ground_truth["scenarios"].values())
    assert labelled / total < 0.05, "labelled events should be <5% of the dataset"


def test_encoded_powershell_round_trips(generated) -> None:
    """The -enc blob must decode to the real script, using UTF-16LE as PowerShell does."""
    tables, _ = generated
    procs = tables[EVENT_PROCESS]
    encoded_rows = procs[procs["command_line"].str.contains("-enc ", na=False)]
    assert not encoded_rows.empty

    blob = encoded_rows.iloc[0]["command_line"].split("-enc ")[1].strip()
    decoded = base64.b64decode(blob).decode("utf-16-le")
    assert decoded == C2_STAGER_SCRIPT
    assert C2_IP in decoded


def test_encode_powershell_uses_utf16le() -> None:
    assert base64.b64decode(encode_powershell("hi")).decode("utf-16-le") == "hi"


def test_attack_chain_stages_are_all_present(generated) -> None:
    _, ground_truth = generated
    stages = ground_truth["scenarios"]["intrusion"]["stages"]
    expected = {
        "1-initial-access", "2-execution", "3-payload-download",
        "4-command-and-control", "5-discovery", "6-credential-access",
        "7-brute-force", "8-lateral-movement", "9-collection", "10-exfiltration",
    }
    assert expected.issubset(stages.keys())


def test_benign_lookalike_exists(generated) -> None:
    """Without a legitimate look-alike, false-positive analysis would be fiction."""
    _, ground_truth = generated
    assert "benign_lookalike" in ground_truth["scenarios"]


def test_benign_failed_logons_stay_below_bruteforce_threshold(generated) -> None:
    """Ordinary typos must not look like a brute force, or every rule cries wolf."""
    tables, ground_truth = generated
    attack_ids = set(ground_truth["scenarios"]["intrusion"]["event_ids"])
    logons = tables[EVENT_LOGON]
    benign_failures = logons[
        (logons["action"] == "failure") & (~logons["event_id"].isin(attack_ids))
    ]
    per_account = benign_failures.groupby(["device", "user"]).size()
    assert per_account.max() <= 3


def test_ground_truth_ids_exist_in_tables(generated) -> None:
    tables, ground_truth = generated
    all_ids = set(pd.concat([df["event_id"] for df in tables.values()]))
    for scenario in ground_truth["scenarios"].values():
        assert set(scenario["event_ids"]).issubset(all_ids)


# ----------------------------------------------------------------------------- loader


def test_load_telemetry_round_trips(telemetry_dir, generated) -> None:
    tables, _ = generated
    loaded = load_telemetry(telemetry_dir)
    assert loaded.event_count == sum(len(df) for df in tables.values())


def test_timestamps_are_timezone_aware(telemetry_dir) -> None:
    loaded = load_telemetry(telemetry_dir)
    for df in (loaded.processes, loaded.network, loaded.logons):
        assert isinstance(df["timestamp"].dtype, pd.DatetimeTZDtype)


def test_numeric_columns_are_nullable_ints(telemetry_dir) -> None:
    loaded = load_telemetry(telemetry_dir)
    assert loaded.network["remote_port"].dtype == "Int64"
    assert loaded.processes["parent_process_id"].dtype == "Int64"


def test_unified_view_is_chronological_and_complete(telemetry_dir) -> None:
    loaded = load_telemetry(telemetry_dir)
    unified = loaded.unified()
    assert len(unified) == loaded.event_count
    assert unified["timestamp"].is_monotonic_increasing
    assert unified["summary"].str.len().gt(0).all()


def test_load_telemetry_missing_dir_raises(tmp_path) -> None:
    with pytest.raises(FileNotFoundError, match="Missing telemetry file"):
        load_telemetry(tmp_path / "nope")


def test_ground_truth_loads(telemetry_dir) -> None:
    gt = load_ground_truth(telemetry_dir)
    assert "intrusion" in gt["scenarios"]
