"""Load telemetry from disk into validated, correctly-typed DataFrames.

Everything downstream (hunting queries, MITRE mapping, agent tools) receives a
:class:`Telemetry` object rather than raw file paths. That gives us one place to
enforce dtypes -- particularly timezone-aware timestamps, which every time-window
correlation depends on.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

from ath.logging_setup import get_logger
from ath.schema import (
    EVENT_CONTROL,
    EVENT_LOGON,
    EVENT_NETWORK,
    EVENT_PROCESS,
    TABLE_COLUMNS,
    TABLE_FILES,
    UNIFIED_COLUMNS,
    SchemaError,
    describe_logon_type,
)
from ath.telemetry.normalize import coerce_and_validate, coerce_types

logger = get_logger(__name__)


def _empty_table(event_type: str) -> pd.DataFrame:
    """An empty, schema-valid table for a channel this telemetry set carries none of.

    Used as ``Telemetry.controls``' default, so every existing caller that only ever
    supplied process/network/logon tables keeps working unchanged.
    """
    return coerce_and_validate(pd.DataFrame(columns=list(TABLE_COLUMNS[event_type])), event_type)


@dataclass
class Telemetry:
    """An in-memory telemetry set.

    Attributes:
        processes: Process execution events.
        network: Network connection events.
        logons: Authentication events.
        controls: Cloud/Kubernetes control-plane audit events. Empty (schema-valid) for
            telemetry with no such source -- every existing Windows-only caller keeps
            working unchanged, since this defaults to an empty, correctly-typed frame.
    """

    processes: pd.DataFrame
    network: pd.DataFrame
    logons: pd.DataFrame
    controls: pd.DataFrame = field(default_factory=lambda: _empty_table(EVENT_CONTROL))

    def table(self, event_type: str) -> pd.DataFrame:
        """Return the table for ``event_type``."""
        mapping = {
            EVENT_PROCESS: self.processes,
            EVENT_NETWORK: self.network,
            EVENT_LOGON: self.logons,
            EVENT_CONTROL: self.controls,
        }
        if event_type not in mapping:
            raise SchemaError(f"Unknown event_type {event_type!r}")
        return mapping[event_type]

    @property
    def event_count(self) -> int:
        """Total number of events across all tables."""
        return len(self.processes) + len(self.network) + len(self.logons) + len(self.controls)

    @property
    def time_range(self) -> tuple[pd.Timestamp, pd.Timestamp]:
        """The (earliest, latest) timestamp across all tables."""
        stamps = pd.concat([
            self.processes["timestamp"], self.network["timestamp"],
            self.logons["timestamp"], self.controls["timestamp"],
        ])
        return stamps.min(), stamps.max()

    def unified(self) -> pd.DataFrame:
        """Return a single chronological view across all four tables.

        This is the KQL ``union`` equivalent. Each row carries a one-line ``summary``
        so a human (or an LLM reading a tool result) can scan a timeline without
        needing every column of every table.
        """
        frames = []
        for event_type in (EVENT_PROCESS, EVENT_NETWORK, EVENT_LOGON, EVENT_CONTROL):
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

    if event_type == EVENT_CONTROL:
        return (
            df["actor"].fillna("?")
            + " "
            + df["verb"].fillna("?")
            + " "
            + df["resource_type"].fillna("?")
            + df["resource_name"].fillna("").map(lambda r: f" ({r})" if r else "")
            + df["target_actor"].fillna("").map(lambda t: f" -> {t}" if t else "")
            + " [" + df["decision"].fillna("?") + "]"
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
            if event_type == EVENT_CONTROL:
                # Optional: most existing telemetry directories (synthetic, Defender
                # export) predate this channel and have no cloud/K8s control-plane
                # activity at all -- that is a genuine, reportable absence, not an
                # error. An empty, schema-valid table lets the visibility model say so.
                tables[event_type] = _empty_table(event_type)
                continue
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
        controls=tables[EVENT_CONTROL],
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


def merge_telemetry(telemetries: Sequence[Telemetry]) -> Telemetry:
    """Combine several telemetry sets into one -- e.g. a hybrid Windows+AWS+Kubernetes
    environment assembled from separately-loaded sources.

    Every source this project ships namespaces its own ``event_id``s distinctly
    (``evt-``, ``defender-*-``, ``cloudtrail-*-``, ``k8s-control-``), so concatenation
    is safe by construction -- this still asserts global uniqueness rather than
    trusting that, the same way :func:`load_telemetry` does for a single directory, so
    a future source that does not follow the convention fails loudly instead of
    silently corrupting evidence citation.

    Args:
        telemetries: One or more :class:`Telemetry` sets to combine. Order is
            preserved within each table but does not otherwise matter.

    Raises:
        ValueError: if no telemetry sets are given.
        SchemaError: if any event id appears in more than one input set.
    """
    if not telemetries:
        raise ValueError("merge_telemetry requires at least one Telemetry set")

    merged = Telemetry(
        processes=pd.concat([t.processes for t in telemetries], ignore_index=True),
        network=pd.concat([t.network for t in telemetries], ignore_index=True),
        logons=pd.concat([t.logons for t in telemetries], ignore_index=True),
        controls=pd.concat([t.controls for t in telemetries], ignore_index=True),
    )
    _assert_event_ids_globally_unique({
        EVENT_PROCESS: merged.processes, EVENT_NETWORK: merged.network,
        EVENT_LOGON: merged.logons, EVENT_CONTROL: merged.controls,
    })
    logger.info(
        "Merged %d telemetry set(s) into %d events", len(telemetries), merged.event_count,
    )
    return merged


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
