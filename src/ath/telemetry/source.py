"""The `TelemetrySource` abstraction: a pluggable front door onto canonical telemetry.

Why this exists
----------------
Every stage after this one -- detection, correlation, the investigation agent,
reporting -- was built and tested against the synthetic generator's output. None of
that code should need to change just because the telemetry now comes from somewhere
real. The way to guarantee that is architectural: define one canonical schema
(``ath.schema``), and require every source of telemetry to produce it. A source's only
job is to answer "how do I turn what I have into that schema", which is exactly the
``Normalization`` stage in::

    Microsoft Defender export
            |
      Telemetry adapter        <- ath.telemetry.defender_source.DefenderExportSource
            |
      Normalization            <- column renaming + value remapping, per source
            |
    Canonical telemetry schema <- ath.schema / ath.telemetry.normalize.coerce_and_validate
            |
    (existing detection engine, correlation, investigation agent, report -- unchanged)

Real-world data is messy in ways synthetic data never is
----------------------------------------------------------
The synthetic generator is trusted: if a row doesn't match the schema, that is a bug in
*our own* code and it is correct to crash loudly (``SchemaError``). An actual Defender
export is not trusted in the same way -- a genuinely unparseable timestamp, an
unrecognised ``LogonType`` string from a product update, or a truncated CSV row is a
fact about the world, not a bug in this project, and crashing the whole import over one
bad row would be the wrong failure mode. So a :class:`TelemetrySource` reports what it
could not normalise as a list of :class:`NormalizationIssue` objects and *drops* those
rows rather than raising, while everything that did parse still goes through the exact
same ``coerce_and_validate`` the synthetic path uses -- messiness is handled at
ingestion, not by weakening the canonical schema's guarantees.

A source vouches for what it admits
------------------------------------
"Messy" is not the same as "not mine". A directory of exports also holds the files the
pipeline wrote *about* the export, and an adapter that reads every file with a matching
extension counts those lines as telemetry it failed to normalise -- wrong denominator,
and one lucky key away from a wrong table. So a directory-reading source first decides,
per file, whether it recognises the file as carrying its own telemetry shape
(:mod:`ath.telemetry.admission`), and records that decision on
:attr:`SourceLoadResult.admitted_files`. Nothing a source has not positively recognised
reaches ``rows_read``, the issue list, or a table.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

from ath.schema import TABLE_FILES
from ath.telemetry.admission import FileAdmission


@dataclass(frozen=True)
class NormalizationIssue:
    """One row (or field) that could not be normalised into the canonical schema.

    Kept, not discarded, so "how much of the export did we actually manage to use" is a
    visible, reportable number rather than a silent gap.

    Attributes:
        event_type: Which table the row belonged to.
        reason: Human-readable explanation, specific enough to act on.
        raw_reference: Something identifying the offending row in the *original* file
            (a line number, a ReportId, a file name) -- the point of collecting issues
            at all is being able to go find the row.
        field: The specific field that failed to normalise, when known.
    """

    event_type: str
    reason: str
    raw_reference: str = ""
    field: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "reason": self.reason,
            "raw_reference": self.raw_reference,
            "field": self.field,
        }

    def __str__(self) -> str:
        ref = f" ({self.raw_reference})" if self.raw_reference else ""
        fld = f" [{self.field}]" if self.field else ""
        return f"{self.event_type}{fld}{ref}: {self.reason}"


@dataclass
class SourceLoadResult:
    """What a :class:`TelemetrySource` produced from one load.

    Attributes:
        tables: Canonical, validated DataFrames keyed by event type -- already passed
            through :func:`ath.telemetry.normalize.coerce_and_validate`.
        issues: Rows that could not be normalised, preserved for the record.
        ground_truth: Evaluation labels, when the source has any (only the synthetic
            source does; a real export has no labels, and callers must handle that).
        rows_read: Total raw rows the source attempted to process, across all tables --
            counted over **admitted files only**, so it is a count of records the source
            positively recognised as its own telemetry rather than of lines that
            happened to sit in the directory.
    """

    tables: dict[str, pd.DataFrame]
    issues: list[NormalizationIssue] = field(default_factory=list)
    ground_truth: dict[str, Any] | None = None
    rows_read: int = 0
    admitted_files: tuple[FileAdmission, ...] = ()
    """The boundary's decision about every candidate file the source listed.

    A directory-reading adapter used to treat every file with a matching extension as
    telemetry, which put a pipeline's own sidecar files into the denominator (and, one
    lucky key away, into the tables). Now each candidate is positively recognised or
    refused, and the refusals are *here* -- with a reason and a record count -- rather
    than as per-line normalisation issues that read as a lossy export. Empty for a source
    that reads no directory (the synthetic generator, an explicitly-pathed export).

    See :mod:`ath.telemetry.admission`.
    """
    unmapped: dict[str, int] = field(default_factory=dict)
    """Rows the source recognised but has no canonical home for, counted per class.

    A per-row :class:`NormalizationIssue` is the right record for a row that *should*
    have mapped and did not -- an unparseable timestamp, a missing principal. It is the
    wrong record for the 645,000 Sysmon image-load and file-create events in one hour of
    a real Windows estate: those are not failures, they are channels the schema does not
    model, and one object per row would cost more memory than the telemetry itself while
    saying the same thing 645,000 times. So a source may count them here instead, keyed by
    a stable class name (``"Microsoft-Windows-Sysmon/Operational:7"``), and
    :attr:`rows_dropped` still adds them up: the "how much of the export did we use"
    number stays honest either way.
    """

    field_gaps: dict[str, int] = field(default_factory=dict)
    """Rows the source *kept* whose field it could not fill, counted by reason.

    The third kind of loss, and the one nothing here could express before. A row that
    could not be normalised at all is a :class:`NormalizationIssue`; a row with no
    canonical home is counted in :attr:`unmapped`; a row that is fully represented except
    that one column it would normally derive came back empty was, until now, visible only
    as a dip in a population fraction -- and a fraction cannot tell the two causes of an
    empty field apart. Either the adapter dropped a value the record carried, which is
    blindness, or the record never carried one (a policy object names no principal; a
    denied request carries no parameters at all), which is not. The adapter is the only
    place that knows which, because it is the only place that still has the raw record.

    Keyed by ``"<table>.<column>: <reason>"`` -- a stable string, so two runs of the same
    corpus produce comparable keys and a ledger can diff them -- and counted rather than
    listed per row: 3,066 rows of the flaws.cloud trail say the same thing.

    These rows are **kept**. Nothing here is added to :attr:`rows_dropped`, and a gap must
    never be recorded instead of a row.
    """

    @property
    def rows_kept(self) -> int:
        return sum(len(df) for df in self.tables.values())

    @property
    def rows_dropped(self) -> int:
        return len(self.issues) + sum(self.unmapped.values())

    @property
    def rejected_files(self) -> tuple[FileAdmission, ...]:
        """Candidate files the boundary refused -- not telemetry, and reported as such."""
        return tuple(a for a in self.admitted_files if not a.admitted)

    def issues_for(self, event_type: str) -> list[NormalizationIssue]:
        return [i for i in self.issues if i.event_type == event_type]

    def summary(self) -> str:
        text = (
            f"{self.rows_kept} row(s) normalised, {self.rows_dropped} dropped "
            f"(of {self.rows_read} read)"
        )
        if self.field_gaps:
            total = sum(self.field_gaps.values())
            text += (
                f"; {total} field gap(s) on kept rows "
                f"({len(self.field_gaps)} reason(s))"
            )
        if not self.admitted_files:
            return text
        rejected = self.rejected_files
        text += f"; {len(self.admitted_files) - len(rejected)} file(s) admitted"
        if rejected:
            not_read = sum(a.line_or_record_count for a in rejected)
            text += (
                f", {len(rejected)} rejected as not this source's telemetry "
                f"({not_read} record(s) never read)"
            )
        return text


class TelemetrySource(ABC):
    """A pluggable origin of canonical telemetry.

    Every concrete source -- the synthetic generator, a Defender export, and any future
    one -- implements :meth:`load` and nothing else is required of it. Everything
    downstream of ``load()`` (detection, correlation, the agent, reporting) is written
    against :class:`~ath.telemetry.loader.Telemetry`, not against any particular source,
    which is what "Run the existing ATH rules unchanged on imported telemetry" means in
    practice: the rules only ever see the canonical schema.
    """

    name: str = ""

    @abstractmethod
    def load(self) -> SourceLoadResult:
        """Produce canonical, validated telemetry (plus any normalization issues)."""


def write_normalized_telemetry(
    result: SourceLoadResult, out_dir: Path, ground_truth: dict[str, Any] | None = None
) -> list[Path]:
    """Write a source's canonical tables to disk in the same layout the loader expects.

    This is the drop-in point: whether ``out_dir`` was populated by the synthetic
    generator's own :func:`~ath.telemetry.generator.write_telemetry` or by this
    function after importing a Defender export, :func:`ath.telemetry.loader.load_telemetry`
    reads the result identically, and so does every CLI command built on top of it.

    Args:
        result: The source's load result.
        out_dir: Directory to write into (created if missing).
        ground_truth: Labels to write as ``ground_truth.json``, if any. Real imports
            have none; callers must not assume this file will exist afterward.

    Returns:
        The list of files written.
    """
    import json

    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    for event_type, filename in TABLE_FILES.items():
        df = result.tables.get(event_type)
        if df is None:
            continue
        path = out_dir / filename
        out = df.copy()
        out["timestamp"] = pd.to_datetime(out["timestamp"], utc=True).dt.strftime(
            "%Y-%m-%dT%H:%M:%S%z"
        )
        out.to_csv(path, index=False)
        written.append(path)

    gt = ground_truth if ground_truth is not None else result.ground_truth
    if gt is not None:
        gt_path = out_dir / "ground_truth.json"
        gt_path.write_text(json.dumps(gt, indent=2), encoding="utf-8")
        written.append(gt_path)

    return written
