"""Read a canonical parquet table that was frozen before a schema column existed.

Why this exists
---------------
``reports/m17/canonical`` holds the COMISET tables M17 froze, and a frozen artifact is
the thing a later measurement is compared *against*: rewriting it would destroy the
comparison the freeze was for. So when M18b-1 added ``process_guid`` /
``parent_process_guid`` to the process table and ``process_guid`` to the network table,
those files necessarily stopped matching the schema -- and ``coerce_and_validate``,
which is strict on purpose, refuses them.

Two wrong ways to resolve that, and why
----------------------------------------
Rewriting the artifact makes the frozen numbers unreproducible and quietly turns a
reporting script into a regeneration tool. Relaxing the validator makes every *real*
missing column -- an adapter that dropped a field, a rename nobody noticed -- silently
acceptable everywhere, which is precisely the failure mode ``validate_frame`` exists to
prevent.

So the widening happens here, at the point of reading one known-old artifact, it is
explicit about which columns it invented, and it **says so on stdout every time**. A
reader of the output can then see that the numbers for those columns are "this artifact
predates the column", not "this corpus lacks the value" -- two facts that a silently
filled column would render identically.

The added columns are empty strings, never a reconstruction. The information is not in
the file; the correct measurement is zero population, reported as pre-schema.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from ath.schema import TABLE_COLUMNS  # noqa: E402
from ath.telemetry.normalize import coerce_and_validate  # noqa: E402

NOTICE_PREFIX = "PRE-SCHEMA ARTIFACT"
"""Greppable, so a reader scanning a long run can find every widening in one pass."""


def empty_table(event_type: str) -> pd.DataFrame:
    """An empty but schema-valid table.

    A table with no columns is not a table with no rows: everything downstream reads
    columns by name, and a bare ``DataFrame()`` makes an absent corpus look like a
    broken one.
    """
    return coerce_and_validate(
        pd.DataFrame(columns=list(TABLE_COLUMNS[event_type])), event_type,
    )


def widen_to_schema(
    df: pd.DataFrame,
    event_type: str,
    label: str,
    notice: Callable[[str], None] = print,
) -> pd.DataFrame:
    """Add the canonical columns ``df`` lacks, as empty, and announce which.

    Args:
        df: A canonical table read from a frozen artifact.
        event_type: The canonical table it is (``ath.schema`` ``EVENT_*``).
        label: What to name in the notice -- normally the file it came from.
        notice: Where the announcement goes. ``print`` by default; a test passes a
            collector, which is the only reason this is a parameter.

    Returns:
        ``df`` unchanged when it already matches the schema, otherwise a copy carrying
        the missing columns as empty strings.
    """
    missing = [c for c in TABLE_COLUMNS[event_type] if c not in df.columns]
    if not missing:
        return df
    widened = df.copy()
    for column in missing:
        widened[column] = ""
    notice(
        f"{NOTICE_PREFIX}: {label} predates {', '.join(missing)} "
        f"on the {event_type} table; added as empty. Population measured for "
        f"{'those columns' if len(missing) > 1 else 'that column'} is a property of "
        f"the frozen artifact, not of the corpus."
    )
    return widened


def read_canonical_table(
    directory: Path,
    prefix: str,
    name: str,
    event_type: str,
    notice: Callable[[str], None] = print,
) -> pd.DataFrame:
    """One ``<prefix>_<name>.parquet`` from ``directory``, widened to today's schema.

    A table the corpus does not carry becomes an empty, schema-valid frame and no
    notice: there is no artifact to be out of date.
    """
    path = directory / f"{prefix}_{name}.parquet"
    if not path.exists():
        return empty_table(event_type)
    return widen_to_schema(pd.read_parquet(path), event_type, str(path), notice=notice)
