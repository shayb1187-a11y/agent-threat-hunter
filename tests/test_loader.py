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
from ath.telemetry.loader import load_telemetry


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
