"""Shared coercion and validation for canonical telemetry.

This is the single funnel every telemetry source passes through on the way to becoming
a validated :class:`~ath.telemetry.loader.Telemetry` object -- extracted from
``loader.py`` specifically so a new :class:`~ath.telemetry.source.TelemetrySource`
(such as the Microsoft Defender export adapter) does not need to reinvent dtype
handling or duplicate the schema validation the synthetic pipeline already relies on.

The architecture this enables::

    Defender export ─┐
                      ├─► adapter-specific column renaming ─► coerce_and_validate() ─► Telemetry
    our own CSVs   ───┘                                              │
                                                                       └─ same function,
                                                                          same guarantees,
                                                                          regardless of source
"""

from __future__ import annotations

import pandas as pd

from ath.schema import (
    EVENT_LOGON,
    EVENT_NETWORK,
    EVENT_PROCESS,
    TABLE_COLUMNS,
    SchemaError,
    validate_frame,
)

# Columns that must be integers where present. We use pandas' nullable Int64 so that
# a missing port stays missing instead of silently becoming 0.0 or NaN-as-float.
INT_COLUMNS: dict[str, tuple[str, ...]] = {
    EVENT_PROCESS: ("process_id", "parent_process_id"),
    EVENT_NETWORK: ("process_id", "remote_port"),
    EVENT_LOGON: ("logon_type",),
}


def coerce_types(df: pd.DataFrame, event_type: str) -> pd.DataFrame:
    """Apply the dtypes the rest of the project relies on.

    Args:
        df: A DataFrame already using canonical column *names* (whatever renaming an
            adapter needed to do must happen before this call).
        event_type: One of ``EVENT_PROCESS`` / ``EVENT_NETWORK`` / ``EVENT_LOGON``.

    Returns:
        A copy of ``df`` with timezone-aware UTC timestamps, nullable Int64 numeric
        columns, and every remaining column as a non-null string.
    """
    df = df.copy()

    # Timezone-aware UTC. Without this, comparing a naive and an aware timestamp
    # raises, and window-based correlation quietly fails.
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, format="mixed")

    for column in INT_COLUMNS.get(event_type, ()):  # nullable ints
        if column in df.columns:
            df[column] = pd.to_numeric(df[column], errors="coerce").astype("Int64")

    # Every remaining object column becomes a string with "" for missing values, so
    # detections can use .str.contains() without tripping over NaN.
    for column in df.columns:
        if column in ("timestamp",) or column in INT_COLUMNS.get(event_type, ()):
            continue
        df[column] = df[column].astype("string").fillna("")

    return df


def coerce_and_validate(df: pd.DataFrame, event_type: str) -> pd.DataFrame:
    """Coerce dtypes, restore canonical column order, and validate.

    This is the one function every telemetry source -- the synthetic generator's own
    CSVs and any imported adapter alike -- must pass through before a DataFrame is
    considered canonical telemetry.

    Missing required columns are checked *before* column-order restoration.
    ``DataFrame.reindex`` silently fills any column it doesn't find with ``NaN``, so
    calling it first would make a genuinely missing column indistinguishable from one
    that is merely out of order -- the schema's "missing columns" guarantee would never
    actually fire. Extra, unmapped columns (e.g. a Defender export's ``SHA1`` or
    ``ProcessVersionInfo*`` fields, which our canonical schema does not model) are still
    dropped by the subsequent reindex, which is the desired behaviour for an adapter
    that only maps the fields it needs.

    Raises:
        ath.schema.SchemaError: if a required column is missing, or if the resulting
            frame does not otherwise match the declared schema for ``event_type``
            (duplicate event ids, or a foreign ``event_type`` value).
    """
    expected = set(TABLE_COLUMNS[event_type])
    missing = expected - set(df.columns)
    if missing:
        raise SchemaError(
            f"{event_type} table is missing required columns: {sorted(missing)}"
        )

    df = df.reindex(columns=list(TABLE_COLUMNS[event_type]))
    df = coerce_types(df, event_type)
    validate_frame(df, event_type)
    return df
