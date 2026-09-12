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

from ath.logging_setup import get_logger
from ath.schema import (
    EVENT_LOGON,
    EVENT_NETWORK,
    EVENT_PROCESS,
    TABLE_COLUMNS,
    SchemaError,
    validate_frame,
)
from ath.telemetry.source import NormalizationIssue

logger = get_logger(__name__)

# The absolute floor on a plausible event time. Chosen as a round number comfortably
# before any telemetry this project can be given and comfortably after the values a
# corrupt timestamp actually takes: Windows FILETIME zero (1601-01-01), Unix epoch zero
# (1970-01-01), and the 1990-12-18 value observed on COMISET are all decades below it,
# and no real endpoint, cloud or Kubernetes telemetry predates it.
#
# One constant, not one per corpus. A per-dataset floor would make "is this timestamp
# plausible" a property of the dataset rather than of the world, which is the same
# mistake as a per-dataset field map.
TIMESTAMP_FLOOR = pd.Timestamp("2000-01-01T00:00:00Z")

# How far past "now" a batch import may reach. A file being imported cannot contain the
# future; a day of slack absorbs clock skew between a collector and this machine without
# admitting a timestamp that is wrong by design.
TIMESTAMP_CEILING_SLACK = pd.Timedelta(days=1)

# Greppable, so quarantine stays countable separately from a timestamp that simply did
# not parse -- "the field was unreadable" and "the field read as an impossible time" are
# different facts about a corpus and they have different fixes.
QUARANTINE_REASON_PREFIX = "timestamp quarantined:"

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


def quarantine_implausible_timestamps(
    df: pd.DataFrame, event_type: str
) -> tuple[pd.DataFrame, list[NormalizationIssue]]:
    """Remove rows whose timestamp cannot be a real event time, and say which and why.

    ``coerce_types`` guarantees a timestamp *parses*; it says nothing about whether the
    value means anything. A network row timestamped ``1990-12-18T16:48:25Z`` parsed
    cleanly on COMISET and became the lower bound of the corpus' observed network window
    (``reports/m17/H4_FROZEN.json`` ``/observed_window/network``) -- which then distorts
    ``Telemetry.time_range``, every sliding correlation window, and every per-day rate,
    because all of those are computed from the extremes.

    Three tests, all absolute, none derived from the data:

    * ``NaT`` -- no usable time at all;
    * earlier than :data:`TIMESTAMP_FLOOR` -- before any telemetry this project can be
      given, which is what a zeroed or byte-swapped clock field looks like;
    * later than now + :data:`TIMESTAMP_CEILING_SLACK` -- a batch import cannot contain
      the future.

    Nothing is repaired. A corrupt timestamp is not clamped to the floor and not
    substituted from a neighbouring field: either value would be a time this project
    invented, and every window, rate and chain downstream would treat it as observed.
    The row leaves the table and becomes one :class:`NormalizationIssue` carrying the
    offending value and the row's ``source_ref``, so it can be found in the original.

    Args:
        df: A canonical, already coerced table (post-:func:`coerce_and_validate`).
        event_type: Which table, for the issue's ``event_type``.

    Returns:
        ``(kept, issues)`` -- the table without the quarantined rows, reindexed from 0,
        and one issue per removed row.
    """
    if df.empty:
        return df, []

    ceiling = pd.Timestamp.now(tz="UTC") + TIMESTAMP_CEILING_SLACK
    stamps = df["timestamp"]

    missing = stamps.isna()
    too_early = ~missing & (stamps < TIMESTAMP_FLOOR)
    too_late = ~missing & (stamps > ceiling)
    implausible = missing | too_early | too_late
    if not implausible.any():
        return df, []

    bounds = {
        "no usable event time (NaT)": missing,
        f"earlier than the floor {TIMESTAMP_FLOOR.isoformat()}": too_early,
        f"later than load time plus {TIMESTAMP_CEILING_SLACK}": too_late,
    }
    issues: list[NormalizationIssue] = []
    for label, mask in bounds.items():
        for position in df.index[mask]:
            row = df.loc[position]
            value = row["timestamp"]
            issues.append(NormalizationIssue(
                event_type=event_type,
                field="timestamp",
                reason=f"{QUARANTINE_REASON_PREFIX} {label} (value {value!r})",
                raw_reference=str(row.get("source_ref") or row.get("event_id") or ""),
            ))

    logger.warning(
        "%s: %d row(s) quarantined for an implausible timestamp (%d NaT, %d before %s, "
        "%d after %s)",
        event_type, int(implausible.sum()), int(missing.sum()),
        int(too_early.sum()), TIMESTAMP_FLOOR.date(), int(too_late.sum()), ceiling.date(),
    )
    return df[~implausible].reset_index(drop=True), issues


def coerce_validate_and_quarantine(
    df: pd.DataFrame, event_type: str
) -> tuple[pd.DataFrame, list[NormalizationIssue]]:
    """The full adapter funnel: coerce, validate, then quarantine impossible event times.

    This is what every :class:`~ath.telemetry.source.TelemetrySource` calls, and the only
    reason it is a separate name from :func:`coerce_and_validate` is that quarantine has
    something to *report* and ``coerce_and_validate`` returns a frame. Those two facts
    must travel together: a row removed without an issue is exactly the silent gap this
    project keeps promising not to have.

    :func:`coerce_and_validate` remains the plain validator, for building the empty,
    schema-valid tables an adapter emits for channels it carries none of -- an empty
    frame has nothing to quarantine -- and for :func:`ath.telemetry.loader.load_telemetry`,
    which reads canonical files that have already been through this boundary.
    """
    validated = coerce_and_validate(df, event_type)
    return quarantine_implausible_timestamps(validated, event_type)
