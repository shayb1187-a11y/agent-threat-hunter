"""Load telemetry from disk into validated, correctly-typed DataFrames.

Everything downstream (hunting queries, MITRE mapping, agent tools) receives a
:class:`Telemetry` object rather than raw file paths. That gives us one place to
enforce dtypes -- particularly timezone-aware timestamps, which every time-window
correlation depends on.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

from ath.logging_setup import get_logger
from ath.schema import (
    EVENT_LOGON,
    EVENT_NETWORK,
    EVENT_PROCESS,
    TABLE_COLUMNS,
    TABLE_FILES,
    UNIFIED_COLUMNS,
    SchemaError,
    describe_logon_type,
    validate_frame,
)
from ath.telemetry.normalize import INT_COLUMNS as _INT_COLUMNS
from ath.telemetry.normalize import coerce_and_validate
from ath.telemetry.normalize import coerce_types

logger = get_logger(__name__)


@dataclass
class Telemetry:
    """An in-memory telemetry set.

    Attributes:
        processes: Process execution events.
        network: Network connection events.
        logons: Authentication events.
    """

    processes: pd.DataFrame
    network: pd.DataFrame
    logons: pd.DataFrame

    def table(self, event_type: str) -> pd.DataFrame:
        """Return the table for ``event_type``."""
        mapping = {
            EVENT_PROCESS: self.processes,
            EVENT_NETWORK: self.network,
            EVENT_LOGON: self.logons,
        }
        if event_type not in mapping:
            raise SchemaError(f"Unknown event_type {event_type!r}")
        return mapping[event_type]

    @property
    def event_count(self) -> int:
        """Total number of events across all tables."""
        return len(self.processes) + len(self.network) + len(self.logons)

    @property
    def time_range(self) -> tuple[pd.Timestamp, pd.Timestamp]:
        """The (earliest, latest) timestamp across all tables."""
        stamps = pd.concat(
            [self.processes["timestamp"], self.network["timestamp"], self.logons["timestamp"]]
        )
        return stamps.min(), stamps.max()

    def unified(self) -> pd.DataFrame:
        """Return a single chronological view across all three tables.

        This is the KQL ``union`` equivalent. Each row carries a one-line ``summary``
        so a human (or an LLM reading a tool result) can scan a timeline without
        needing every column of every table.
        """
        frames = []
        for event_type in (EVENT_PROCESS, EVENT_NETWORK, EVENT_LOGON):
            df = self.table(event_type).copy()
            df["summary"] = _summarise(df, event_type)
            frames.append(df[list(UNIFIED_COLUMNS)])

        unified = pd.concat(frames, ignore_index=True)
        return unified.sort_values("timestamp").reset_index(drop=True)


def _summarise(df: pd.DataFrame, event_type: str) -> pd.Series:
    """Build a compact one-line description for each row of a table."""
    if df.empty:
        return pd.Series(dtype="object")

    if event_type == EVENT_PROCESS:
        return (
            df["parent_process_name"].fillna("?")
            + " -> "
            + df["process_name"].fillna("?")
            + " | "
            + df["command_line"].fillna("").str.slice(0, 160)
        )

    if event_type == EVENT_NETWORK:
        return (
            df["process_name"].fillna("?")
            + " -> "
            + df["remote_ip"].fillna("?")
            + ":"
            + df["remote_port"].astype("string").fillna("?")
            + " ("
            + df["direction"].fillna("?")
            + ")"
        )

    # logon
    return (
        df["action"].fillna("?")
        + " logon ["
        + df["logon_type"].map(describe_logon_type)
        + "] from "
        + df["source_ip"].fillna("?")
        + df["failure_reason"].fillna("").map(lambda r: f" reason={r}" if r else "")
    )


def _coerce_types(df: pd.DataFrame, event_type: str) -> pd.DataFrame:
    """Deprecated alias kept for any external caller; use ``normalize.coerce_types``.

    Retained only so nothing that imported this private name directly breaks. New code
    should call :func:`ath.telemetry.normalize.coerce_types`.
    """
    return coerce_types(df, event_type)


def load_telemetry(data_dir: Path) -> Telemetry:
    """Load and validate all telemetry tables from ``data_dir``.

    Works identically whether ``data_dir`` was populated by the synthetic generator or
    by :func:`ath.telemetry.source.write_normalized_telemetry` after importing from a
    :class:`~ath.telemetry.source.TelemetrySource` such as a Microsoft Defender
    export -- both write the same canonical CSV shape, so this loader does not need to
    know or care which source produced the files it is reading.

    Args:
        data_dir: Directory containing the generated CSVs.

    Returns:
        A validated :class:`Telemetry` object.

    Raises:
        FileNotFoundError: if a required table is missing.
        SchemaError: if a table does not match the declared schema.
    """
    tables: dict[str, pd.DataFrame] = {}

    for event_type, filename in TABLE_FILES.items():
        path = data_dir / filename
        if not path.exists():
            raise FileNotFoundError(
                f"Missing telemetry file {path}. Run `python main.py generate` "
                "(synthetic) or `python main.py import-defender` (real export) first."
            )

        df = pd.read_csv(path, dtype=str, keep_default_na=False)
        df = coerce_and_validate(df, event_type)
        tables[event_type] = df
        logger.debug("Loaded %s rows from %s", len(df), filename)

    _assert_event_ids_globally_unique(tables)

    telemetry = Telemetry(
        processes=tables[EVENT_PROCESS],
        network=tables[EVENT_NETWORK],
        logons=tables[EVENT_LOGON],
    )
    logger.info(
        "Loaded %s events from %s (%s to %s)",
        telemetry.event_count,
        data_dir,
        *[t.isoformat() for t in telemetry.time_range],
    )
    return telemetry


def _assert_event_ids_globally_unique(tables: dict[str, pd.DataFrame]) -> None:
    """Enforce that ``event_id`` identifies one event across *all* tables.

    ``validate_frame`` only checks for duplicates *within* a table, but nothing
    downstream respects that boundary: :meth:`ath.agent.tools.ToolBox.get_events`
    searches all three tables for an id, and
    :class:`~ath.agent.claims.ClaimVerifier` pools all three into one set of known
    ids. A collision across tables would therefore make a claim cite one event and
    resolve to another -- silently, and in the evidence appendix, which is the one
    place this project promises is trustworthy.

    Both current sources satisfy this by construction (the generator mints a single
    ``evt-NNNNNN`` sequence; the Defender adapter namespaces per table), so this
    check costs nothing today. It is here because the invariant is *relied upon*
    rather than merely true, and because the obvious next step -- importing a second
    export into the same directory -- would break it: the adapter restarts numbering
    at ``defender-process-000001`` on every run.

    Raises:
        SchemaError: if any event id appears in more than one row, in any table.
    """
    seen: dict[str, str] = {}
    collisions: list[str] = []
    for event_type, df in tables.items():
        for event_id in df["event_id"]:
            previous = seen.get(event_id)
            if previous is not None:
                collisions.append(f"{event_id} (in both {previous} and {event_type})")
            else:
                seen[event_id] = event_type

    if collisions:
        raise SchemaError(
            f"event_id must be unique across all telemetry tables, but "
            f"{len(collisions)} collision(s) were found, e.g. {collisions[:5]}. "
            "Evidence citation resolves ids globally, so a collision would let a "
            "finding cite one event and render another. If this came from importing "
            "two Defender exports into one directory, import them into separate "
            "directories instead."
        )


def load_ground_truth(data_dir: Path) -> dict[str, Any]:
    """Load evaluation labels.

    Intended for tests and for measuring detection quality **only**. Detections and
    agent tools must not call this.
    """
    path = data_dir / "ground_truth.json"
    if not path.exists():
        raise FileNotFoundError(
            f"Missing {path}. `evaluate` requires labelled ground truth, which only "
            "the synthetic generator produces (`python main.py generate`). Telemetry "
            "imported via `import-defender` has no labels by design -- real data has "
            "no answer key -- so precision/recall cannot be computed for it; "
            "hunt/chains/investigate/report all work normally without this file."
        )
    return json.loads(path.read_text(encoding="utf-8"))
