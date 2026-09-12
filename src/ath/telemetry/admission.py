"""File admission: the adapter boundary admits only files it can positively recognise.

The defect this closes
-----------------------
Every directory-reading adapter in this package used to answer "is this file mine?" with
"does its name end in an extension I read". A directory is not curated, and the files
that sit next to a telemetry export are exactly the files a pipeline writes about that
export -- manifests, progress sidecars, per-slice statistics. Measured on COMISET
(``reports/m17/H4_FROZEN.json``), the slice directory's own statistics sidecar was listed
as telemetry and 513 of its lines were counted as records and then rejected one by one.
Two things went wrong there, and only one of them was visible:

* the **denominator** was wrong -- 513 lines that were never telemetry were counted in
  ``rows_read`` and in the "rows dropped" total, so every "we used X% of the corpus"
  number was computed against bytes the corpus never claimed were events;
* the **table** was one lucky key away from being wrong -- a sidecar whose lines happened
  to carry ``event_id`` and a timestamp would have been ingested as telemetry silently,
  and nothing downstream can tell an invented event from a real one.

The rule
--------
A candidate file is ADMITTED when it parses in one of the shapes its source accepts *and*
at least one of its first :data:`SNIFF_RECORDS` records satisfies that source's
recognition predicate. Otherwise it is REJECTED, with a reason and with the number of
records it holds -- reported, never silently skipped, and contributing nothing to
``rows_read`` and no :class:`~ath.telemetry.source.NormalizationIssue`.

Two layers, not one
--------------------
Admission is about **shape**, not truth. A file whose records carry the right identifying
keys with nonsense values is admitted here and then rejected record by record by the
adapter's own normalisation, with one issue each -- which is the correct outcome: "this
file is not my telemetry" and "this record of my telemetry is unusable" are different
facts, they have different denominators, and collapsing them is how a corrupt sidecar
comes to look like a lossy export.

Shared, with a per-source predicate
------------------------------------
The decision rule lives here once. Each source contributes only ``looks_like_record``,
naming the fields that identify its telemetry -- the same fields its normalisation
already reads first. No file name appears anywhere in this module or in any predicate:
the boundary recognises a telemetry shape, never a dataset.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any, Callable

# How many records the sniff reads before deciding. Small enough that admission costs
# nothing on a 2 GB NDJSON slice, large enough that a file whose first record is a
# header, a blank, or a single malformed line is still recognised by its neighbours.
SNIFF_RECORDS = 20

ADMITTED = "admitted"
REJECTED = "rejected"

# Greppable reason prefixes. The three ways a file can fail to be recognised are kept
# distinct because they mean different things operationally: a wrong-shape file is
# somebody else's file in this directory, an unparseable one is a broken or truncated
# member, and an empty one is usually a placeholder.
REASON_WRONG_SHAPE = "extension matched but content is not this source's telemetry"
REASON_UNPARSEABLE = "file does not parse in any shape this source accepts"
REASON_EMPTY = "file holds no records"


@dataclass(frozen=True)
class FileAdmission:
    """The boundary's decision about one candidate file, kept for the record.

    Attributes:
        path: The file's name, as the adapter referred to it (a tar member is
            ``<archive>:<member>``, matching the ``source_ref`` of rows read from it).
        decision: :data:`ADMITTED` or :data:`REJECTED`.
        reason: Why -- which shape was recognised, or which of the three refusals fired.
        shape: The named on-disk shape the source recognised, empty when none was.
        line_or_record_count: For a REJECTED file, the exact number of records (NDJSON
            lines, or array members) it holds and which therefore did **not** enter
            ``rows_read``. For an ADMITTED file, the number of records the sniff
            examined -- its real total is what ``rows_read`` counts.
    """

    path: str
    decision: str
    reason: str
    shape: str = ""
    line_or_record_count: int = 0

    @property
    def admitted(self) -> bool:
        return self.decision == ADMITTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "decision": self.decision,
            "reason": self.reason,
            "shape": self.shape,
            "line_or_record_count": self.line_or_record_count,
        }

    def __str__(self) -> str:
        return f"{self.path}: {self.decision} -- {self.reason}"


@dataclass(frozen=True)
class ParsedFile:
    """What a source's own reader could make of a candidate file, before admission.

    Attributes:
        shape: Name of the on-disk shape recognised (``"a top-level 'Records' array"``,
            ``"one JSON record per line"``, ...). Empty means nothing parsed, which is
            the one condition admission cannot look past.
        records: Up to :data:`SNIFF_RECORDS` records, in file order, already unwrapped
            from any envelope the source strips.
        count: Records the file holds, exactly when known (an array's length, a counted
            line total); otherwise the number the sniff examined.
        error: Why nothing parsed, when ``shape`` is empty.
    """

    shape: str = ""
    records: tuple[Any, ...] = ()
    count: int = 0
    error: str = ""


Predicate = Callable[[Any], bool]


def admit_parsed(name: str, parsed: ParsedFile, looks_like_record: Predicate, *,
                 telemetry: str) -> FileAdmission:
    """Decide on one already-parsed candidate file.

    Args:
        name: How the adapter refers to the file (see :attr:`FileAdmission.path`).
        parsed: What the source's reader made of it.
        looks_like_record: The source's recognition predicate, applied to each sniffed
            record. Must test for the *fields* that identify this telemetry, never for
            plausible values -- record-level normalisation is the layer that judges
            values, and it reports each failure individually.
        telemetry: Human-readable name of what this source reads, used in the reason.

    Returns:
        The decision. A file with zero records but a positively recognised envelope is
        admitted: ``{"Records": []}`` is a real, correctly shaped CloudTrail file that
        happens to hold nothing, and calling it "not CloudTrail" would be a false
        statement about the export.
    """
    if not parsed.shape:
        if parsed.count == 0 and not parsed.error:
            return FileAdmission(name, REJECTED, REASON_EMPTY, "", 0)
        reason = REASON_UNPARSEABLE + (f": {parsed.error}" if parsed.error else "")
        return FileAdmission(name, REJECTED, reason, "", parsed.count)

    if not parsed.records:
        return FileAdmission(
            name, ADMITTED,
            f"recognised as {telemetry} ({parsed.shape}), carrying no records",
            parsed.shape, parsed.count,
        )

    matches = sum(1 for record in parsed.records if looks_like_record(record))
    if matches:
        return FileAdmission(
            name, ADMITTED,
            f"recognised as {telemetry} ({parsed.shape}): {matches} of the first "
            f"{len(parsed.records)} record(s) carry the identifying fields",
            parsed.shape, parsed.count,
        )
    return FileAdmission(
        name, REJECTED,
        f"{REASON_WRONG_SHAPE}: none of the first {len(parsed.records)} record(s) "
        f"carry the fields that identify {telemetry}",
        parsed.shape, parsed.count,
    )


def admit_lines(
    name: str,
    lines: Iterable[str],
    looks_like_record: Predicate,
    *,
    telemetry: str,
    shape: str = "one JSON record per line",
    unwrap: Callable[[Any], Any] | None = None,
) -> tuple[FileAdmission, Iterator[tuple[int, str]]]:
    """Admit a line-delimited file from its first records, reading it only once.

    The sniff buffers the lines it consumed and hands them back ahead of the rest, so an
    admitted file costs exactly one pass and the caller's existing per-line loop is
    unchanged. A rejected file's remaining lines are consumed *without parsing*, purely
    to count them: a file excluded from the denominator has to be able to say how much it
    was excluded by, or the exclusion is just a different silence.

    Args:
        name: How the adapter refers to the file.
        lines: The source's own line iterator (already decompressed/decoded by it).
        looks_like_record: The source's recognition predicate.
        telemetry: Human-readable name of what this source reads.
        shape: Name of the line-delimited shape, for the reason text.
        unwrap: Applied to each sniffed record before the predicate, when the source
            strips an envelope (an Elastic search hit's ``_source``) -- so the predicate
            sees the same record shape normalisation will.

    Returns:
        ``(admission, numbered_lines)``. ``numbered_lines`` yields ``(line_number,
        line)`` over the whole file when admitted, and nothing when rejected.
    """
    remaining = iter(lines)
    buffered: list[tuple[int, str]] = []
    sniffed: list[Any] = []
    records_seen = 0
    number = 0
    first_error = ""

    for line in remaining:
        number += 1
        buffered.append((number, line))
        stripped = line.strip()
        if not stripped:
            continue
        records_seen += 1
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError as exc:
            if not first_error:
                first_error = f"line {number} is not valid JSON: {exc}"
        else:
            sniffed.append(unwrap(record) if unwrap is not None else record)
        if records_seen >= SNIFF_RECORDS:
            break

    parsed = ParsedFile(
        shape=shape if sniffed else "",
        records=tuple(sniffed),
        count=records_seen,
        error=first_error,
    )
    admission = admit_parsed(name, parsed, looks_like_record, telemetry=telemetry)
    if admission.admitted:
        return admission, _chain(buffered, remaining, number)

    # Not telemetry: finish counting what we are refusing, then yield nothing.
    total = records_seen + sum(1 for line in remaining if line.strip())
    return (
        FileAdmission(
            admission.path, admission.decision, admission.reason, admission.shape, total,
        ),
        iter(()),
    )


def _chain(
    buffered: list[tuple[int, str]], remaining: Iterator[str], last_number: int
) -> Iterator[tuple[int, str]]:
    """The sniffed lines, then the rest, numbered continuously from 1."""
    yield from buffered
    number = last_number
    for line in remaining:
        number += 1
        yield number, line
