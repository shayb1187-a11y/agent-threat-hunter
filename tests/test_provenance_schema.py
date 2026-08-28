"""Tests for the provenance columns and the shared normalize module.

The property under test: the canonical schema extension (``source``, ``source_ref``)
must be fully backward compatible with the existing synthetic pipeline, and the
coercion/validation logic extracted into ``normalize.py`` must behave identically
whether it is called from the CSV loader or from a `TelemetrySource` adapter.
"""

from __future__ import annotations

import pandas as pd
import pytest

from ath.schema import CORE_COLUMNS, TABLE_COLUMNS, SchemaError, validate_frame
from ath.telemetry import GeneratorConfig, generate_telemetry
from ath.telemetry.normalize import coerce_and_validate, coerce_types


def test_core_columns_include_provenance() -> None:
    assert "source" in CORE_COLUMNS
    assert "source_ref" in CORE_COLUMNS


def test_synthetic_generator_populates_provenance() -> None:
    tables, _ = generate_telemetry(GeneratorConfig())
    for event_type, df in tables.items():
        assert (df["source"] == "synthetic").all(), event_type
        assert (df["source_ref"] == "").all(), event_type


def test_provenance_columns_are_part_of_every_table_schema() -> None:
    for event_type, columns in TABLE_COLUMNS.items():
        assert "source" in columns, event_type
        assert "source_ref" in columns, event_type


# ======================================================================================
# normalize.coerce_and_validate: the shared funnel
# ======================================================================================


def _minimal_process_frame() -> pd.DataFrame:
    return pd.DataFrame([{
        "event_id": "evt-1", "timestamp": "2026-01-01T00:00:00+00:00",
        "event_type": "process", "device": "PC01", "user": "jdoe",
        "source": "test", "source_ref": "",
        "process_name": "cmd.exe", "process_id": "100", "command_line": "cmd.exe",
        "parent_process_name": "explorer.exe", "parent_process_id": "50",
        "file_path": r"C:\Windows\System32\cmd.exe",
        "sha256": "b" * 64, "signer": "Microsoft Corporation",
        "signature_status": "signed_valid",
    }])


def test_coerce_and_validate_produces_timezone_aware_timestamps() -> None:
    df = coerce_and_validate(_minimal_process_frame(), "process")
    assert isinstance(df["timestamp"].dtype, pd.DatetimeTZDtype)


def test_coerce_and_validate_produces_nullable_int_columns() -> None:
    df = coerce_and_validate(_minimal_process_frame(), "process")
    assert df["process_id"].dtype == "Int64"
    assert df["parent_process_id"].dtype == "Int64"


def test_coerce_and_validate_rejects_missing_columns() -> None:
    df = _minimal_process_frame().drop(columns=["command_line"])
    with pytest.raises(SchemaError, match="missing required columns"):
        coerce_and_validate(df, "process")


def test_coerce_and_validate_rejects_duplicate_event_ids() -> None:
    df = pd.concat([_minimal_process_frame()] * 2, ignore_index=True)
    with pytest.raises(SchemaError, match="duplicate event_ids"):
        coerce_and_validate(df, "process")


def test_coerce_types_handles_unparseable_numbers_as_null() -> None:
    df = _minimal_process_frame()
    df["process_id"] = "not-a-number"
    coerced = coerce_types(df, "process")
    assert coerced["process_id"].isna().all()


def test_coerce_and_validate_is_the_same_function_the_loader_uses() -> None:
    """Guards the architectural point: one funnel, not two independently written ones."""
    from ath.telemetry import loader

    assert loader.coerce_and_validate is coerce_and_validate
