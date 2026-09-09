"""Loader invariants that the per-table schema check cannot express.

``validate_frame`` guarantees ``event_id`` uniqueness only *within* one table. But
nothing downstream respects that boundary: :meth:`ath.agent.tools.ToolBox.get_events`
searches all three tables for an id, and :class:`~ath.agent.claims.ClaimVerifier`
pools all three into a single set of known ids. Evidence citation is therefore
*global*, and the loader -- the one place all three tables meet -- is where that
invariant has to be enforced.
"""

from __future__ import annotations

import pandas as pd
import pytest

from ath.schema import TABLE_FILES, SchemaError
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import load_telemetry, merge_telemetry


@pytest.fixture
def data_dir(tmp_path):
    tables, gt = generate_telemetry(GeneratorConfig())
    write_telemetry(tables, gt, tmp_path)
    return tmp_path


def test_loader_accepts_the_shipped_dataset(data_dir) -> None:
    """The guard must not fire on legitimate data -- otherwise it is just noise."""
    telemetry = load_telemetry(data_dir)
    assert telemetry.event_count > 0


def test_loader_rejects_event_id_reused_across_tables(data_dir) -> None:
    """A cross-table collision must fail loudly rather than mis-resolve evidence.

    Left unchecked, a claim citing the colliding id could render the wrong event in
    the evidence appendix -- the one output this project promises is traceable back
    to real telemetry.
    """
    processes = pd.read_csv(data_dir / TABLE_FILES["process"], dtype=str)
    network = pd.read_csv(data_dir / TABLE_FILES["network"], dtype=str)

    stolen = processes.loc[0, "event_id"]
    network.loc[0, "event_id"] = stolen
    network.to_csv(data_dir / TABLE_FILES["network"], index=False)

    with pytest.raises(SchemaError, match="unique across all telemetry tables"):
        load_telemetry(data_dir)


def test_collision_message_names_the_offending_id(data_dir) -> None:
    """The error has to be actionable: which id, and in which two tables."""
    processes = pd.read_csv(data_dir / TABLE_FILES["process"], dtype=str)
    logons = pd.read_csv(data_dir / TABLE_FILES["logon"], dtype=str)

    stolen = processes.loc[0, "event_id"]
    logons.loc[0, "event_id"] = stolen
    logons.to_csv(data_dir / TABLE_FILES["logon"], index=False)

    with pytest.raises(SchemaError) as excinfo:
        load_telemetry(data_dir)

    message = str(excinfo.value)
    assert stolen in message
    assert "process" in message and "logon" in message


# ======================================================================================
# merge_telemetry: combining sources into one (hybrid) environment
# ======================================================================================


def test_merge_telemetry_combines_event_counts(data_dir) -> None:
    from pathlib import Path

    from ath.telemetry.cloudtrail_source import CloudTrailSource

    windows = load_telemetry(data_dir)
    cloud_result = CloudTrailSource(
        Path(__file__).parent / "fixtures" / "cloudtrail"
    ).load()
    from ath.telemetry.loader import Telemetry

    cloud = Telemetry(
        processes=cloud_result.tables["process"], network=cloud_result.tables["network"],
        logons=cloud_result.tables["logon"], controls=cloud_result.tables["control"],
    )

    merged = merge_telemetry([windows, cloud])
    assert merged.event_count == windows.event_count + cloud.event_count
    assert len(merged.controls) == len(cloud.controls)


def test_merge_telemetry_rejects_id_collisions() -> None:
    from ath.schema import EVENT_LOGON, TABLE_COLUMNS
    from ath.telemetry.loader import Telemetry
    from ath.telemetry.normalize import coerce_and_validate

    def _one_logon(event_id: str) -> pd.DataFrame:
        row = {c: "" for c in TABLE_COLUMNS[EVENT_LOGON]}
        row.update({
            "event_id": event_id, "timestamp": "2026-08-17T09:00:00Z",
            "event_type": EVENT_LOGON, "device": "d", "user": "u", "action": "success",
        })
        return coerce_and_validate(pd.DataFrame([row]), EVENT_LOGON)

    def _empty_telemetry(logons: pd.DataFrame) -> Telemetry:
        empty = {
            t: coerce_and_validate(pd.DataFrame(columns=list(cols)), t)
            for t, cols in TABLE_COLUMNS.items() if t != EVENT_LOGON
        }
        return Telemetry(
            processes=empty["process"], network=empty["network"], logons=logons,
            controls=empty["control"],
        )

    a = _empty_telemetry(_one_logon("dup-0001"))
    b = _empty_telemetry(_one_logon("dup-0001"))

    with pytest.raises(SchemaError, match="unique across all telemetry tables"):
        merge_telemetry([a, b])


def test_merge_telemetry_requires_at_least_one_set() -> None:
    with pytest.raises(ValueError):
        merge_telemetry([])
