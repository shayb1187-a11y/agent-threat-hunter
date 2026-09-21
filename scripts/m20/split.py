"""M20 sealing: split delivered CloudTrail files into dev/ and holdout/ without reading them.

The one thing this script must never do
-----------------------------------------
``docs/m20-benign-cloud-validation-plan.md`` section 4: "The holdout is written to a
separate prefix on delivery and moved, unopened ... **No ATH code is run against the
holdout** -- not the adapter, not a probe, not a row count beyond the file sizes and
hashes -- until section 5's prediction is committed."

A row count is a read. So is a gzip member listing, and so is anything that would let the
operator learn "the holdout has 412 more events than I predicted" before the prediction
is committed. This module therefore decides the split from the **S3 object key** alone:

    <account>_CloudTrail_<region>_<YYYYMMDDTHHMMZ>_<hash>.json.gz

which is the name CloudTrail gives a delivered file, and whose timestamp is the *delivery*
window. ``eventTime`` -- the field that would be more precise -- is inside the file, and
reading it would require opening the file, which is exactly the thing being refused
(INV-1, :func:`classify`, :func:`split`). The cost of using the key instead is real and
is stated in the report: a delivery whose window straddles the boundary is assigned by
its key, so a handful of events either side may land on the "wrong" day. That error is
bounded by CloudTrail's delivery latency and it is symmetric; being unable to see it is
the price of not looking.

Hashing reads bytes, and that is the only read performed: ``hashlib`` over a binary
stream never decompresses, never parses and cannot fail on a corrupt member. The test
suite proves this by putting a deliberately invalid gzip file in the holdout: if anything
here ever opened a holdout file as gzip or JSON, that test fails.

What it writes
---------------
``dev/SHA256SUMS``, ``holdout/SHA256SUMS``, ``holdout/SIZES`` and a ``SPLIT.json``
recording the boundary, the counts and every file's name/size/hash. ``SPLIT.json`` is
also the run-once marker: a second run is refused rather than merged, because a split run
twice against a directory that has since received more deliveries would silently move
late-arriving day-9 files into the holdout.

Usage::

    python scripts/m20/split.py --source data/external/m20_benign_cloud/delivered \
        --out data/external/m20_benign_cloud --start-date 2026-10-01
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from datetime import datetime, timedelta
from pathlib import Path

#: ``<account>_CloudTrail_<region>_<YYYYMMDDTHHMMZ>_<hash>.json.gz``. Anchored, and the
#: timestamp group is the only part this module reads for the split decision.
KEY_PATTERN = re.compile(
    r"^(?P<account>\d{12})_CloudTrail_(?P<region>[a-z0-9-]+)_"
    r"(?P<timestamp>\d{8}T\d{4}Z)_(?P<hash>[0-9A-Za-z]+)\.json\.gz$"
)

KEY_TIME_FORMAT = "%Y%m%dT%H%MZ"

DEV_DIRNAME = "dev"
HOLDOUT_DIRNAME = "holdout"
SPLIT_RECORD = "SPLIT.json"

#: The plan's calendar boundary: "days 1-9 are the development split; days 10-14 are the
#: sealed holdout". Day 10 begins nine days after day 1 at 00:00 UTC.
HOLDOUT_FIRST_DAY = 10


def boundary_for(start_date: datetime) -> datetime:
    """Day 10, 00:00 UTC, from day 1's date. The only time arithmetic in the split."""
    return start_date + timedelta(days=HOLDOUT_FIRST_DAY - 1)


def key_timestamp(name: str) -> datetime:
    """The delivery timestamp encoded in a CloudTrail object key.

    Raises:
        SystemExit: if ``name`` is not a CloudTrail delivery name. A file whose name
            cannot be parsed cannot be assigned to a split without opening it, and
            opening it is the thing this module exists not to do -- so the whole run is
            refused and the operator is told which file to look at.
    """
    match = KEY_PATTERN.match(name)
    if match is None:
        raise SystemExit(
            f"{name!r} is not a CloudTrail delivery name "
            "(<account>_CloudTrail_<region>_<YYYYMMDDTHHMMZ>_<hash>.json.gz). Refusing "
            "to split: assigning it would mean reading it, and the holdout must stay "
            "unopened."
        )
    return datetime.strptime(match.group("timestamp"), KEY_TIME_FORMAT)


def classify(name: str, boundary: datetime) -> str:
    """``"dev"`` or ``"holdout"`` for one object key. Boundary is inclusive of holdout.

    A file stamped ``...T2359Z`` on day 9 is development; one stamped ``...T0000Z`` on
    day 10 is holdout. The boundary belongs to the holdout so that the sealed side is
    the one that grows if the operator is imprecise -- erring towards sealing more is
    conservative, erring the other way leaks.
    """
    return DEV_DIRNAME if key_timestamp(name) < boundary else HOLDOUT_DIRNAME


def sha256_of(path: Path) -> str:
    """Content hash, read as bytes in 1 MiB chunks.

    Deliberately not ``gzip.open``: hashing a holdout file must not be able to turn into
    reading one. See the module docstring (INV-1).
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_sums(path: Path, entries: list) -> None:
    """coreutils ``sha256sum`` format, so ``sha256sum -c SHA256SUMS`` verifies it."""
    lines = ["{0}  {1}\n".format(entry["sha256"], entry["name"]) for entry in entries]
    path.write_text("".join(lines), encoding="utf-8")


def _write_sizes(path: Path, entries: list) -> None:
    lines = ["{0}  {1}\n".format(entry["bytes"], entry["name"]) for entry in entries]
    path.write_text("".join(lines), encoding="utf-8")


def split(source: Path, out: Path, start_date: datetime, dry_run: bool = False) -> dict:
    """Move every delivered file into ``out/dev`` or ``out/holdout`` by its key timestamp.

    Two passes on purpose. The first classifies every name and refuses the whole run if
    any name is unparseable; only then does the second pass move anything. A run that
    moved half the corpus and then stopped would leave the operator to reconstruct which
    files had already moved -- by looking at them.

    Args:
        source: Directory of delivered ``*.json.gz`` files. Subdirectories are walked,
            because ``aws s3 sync`` of ``AWSLogs/`` produces a deep prefix layout.
        out: Directory to create ``dev/`` and ``holdout/`` under.
        start_date: Day 1 of the collection, UTC.
        dry_run: Classify and report, move nothing and write nothing.

    Returns:
        The split record, also written to ``out/SPLIT.json``.

    Raises:
        SystemExit: if ``out`` has already been split (INV-1's run-once marker), if the
            source holds no CloudTrail files, or if any name is unparseable.
    """
    boundary = boundary_for(start_date)
    record_path = out / SPLIT_RECORD
    dev_dir = out / DEV_DIRNAME
    holdout_dir = out / HOLDOUT_DIRNAME

    if not dry_run:
        already = [p for p in (record_path, dev_dir / "SHA256SUMS", holdout_dir / "SHA256SUMS")
                   if p.exists()]
        if already:
            raise SystemExit(
                f"{out} has already been split ({already[0]} exists). Refusing to split twice: a "
                "second run over a directory that has since received more deliveries "
                "would move late day-9 files into the sealed side."
            )

    if not source.is_dir():
        raise SystemExit(f"{source} is not a directory")

    candidates = sorted(
        p for p in source.rglob("*.json.gz") if p.is_file()
    )
    if not candidates:
        raise SystemExit(
            f"no *.json.gz files under {source}. Nothing to split -- check the `aws s3 sync` "
            "target."
        )

    # Pass 1: classify by name only. Any unparseable name aborts before a byte moves.
    planned = []
    for path in candidates:
        planned.append((path, classify(path.name, boundary)))

    duplicates = _duplicate_names(planned)
    if duplicates:
        raise SystemExit(
            f"delivered names are not unique across prefixes: {sorted(duplicates)[:5]}. Refusing to split, "
            "because one would overwrite the other in the flat output "
            "layout."
        )

    dev_entries = []
    holdout_entries = []
    if not dry_run:
        dev_dir.mkdir(parents=True, exist_ok=True)
        holdout_dir.mkdir(parents=True, exist_ok=True)

    # Pass 2: move, then hash the moved file. Size and hash are the only facts recorded
    # about a holdout file, and neither requires decoding it.
    for path, side in planned:
        destination_dir = dev_dir if side == DEV_DIRNAME else holdout_dir
        destination = destination_dir / path.name
        if not dry_run:
            shutil.move(str(path), str(destination))
        else:
            destination = path
        entry = {
            "name": path.name,
            "bytes": destination.stat().st_size,
            "sha256": sha256_of(destination),
            "key_timestamp": key_timestamp(path.name).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        (dev_entries if side == DEV_DIRNAME else holdout_entries).append(entry)

    record = {
        "_about": (
            "M20 calendar split. Side is decided from the CloudTrail object key's "
            "delivery timestamp, never from eventTime inside the file: the holdout is "
            "sealed and nothing here opens it. Holdout facts recorded are byte size and "
            "sha256 only."
        ),
        "plan": "docs/m20-benign-cloud-validation-plan.md section 4",
        "start_date_utc": start_date.strftime("%Y-%m-%d"),
        "boundary_utc": boundary.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "boundary_rule": "key timestamp < boundary -> dev; >= boundary -> holdout (sealed)",
        "dev_files": len(dev_entries),
        "holdout_files": len(holdout_entries),
        "dev_bytes": sum(entry["bytes"] for entry in dev_entries),
        "holdout_bytes": sum(entry["bytes"] for entry in holdout_entries),
        "dev": dev_entries,
        "holdout": holdout_entries,
    }

    if not dry_run:
        _write_sums(dev_dir / "SHA256SUMS", dev_entries)
        _write_sums(holdout_dir / "SHA256SUMS", holdout_entries)
        _write_sizes(holdout_dir / "SIZES", holdout_entries)
        record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record


def _duplicate_names(planned: list) -> set:
    seen = set()
    duplicates = set()
    for path, _side in planned:
        if path.name in seen:
            duplicates.add(path.name)
        seen.add(path.name)
    return duplicates


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--source", type=Path, required=True,
                        help="directory of delivered CloudTrail *.json.gz files")
    parser.add_argument("--out", type=Path, required=True,
                        help="directory to create dev/ and holdout/ under")
    parser.add_argument("--start-date", required=True, help="day 1, YYYY-MM-DD (UTC)")
    parser.add_argument("--dry-run", action="store_true",
                        help="classify and report; move nothing, write nothing")
    args = parser.parse_args(argv)

    try:
        start_date = datetime.strptime(args.start_date, "%Y-%m-%d")
    except ValueError as exc:
        raise SystemExit(f"--start-date must be YYYY-MM-DD: {exc}") from exc

    record = split(args.source, args.out, start_date, dry_run=args.dry_run)
    print("boundary {0} ({1})".format(record["boundary_utc"], record["boundary_rule"]))
    print("  dev     {0:5d} file(s)  {1:,} bytes".format(record["dev_files"], record["dev_bytes"]))
    print("  holdout {0:5d} file(s)  {1:,} bytes  SEALED -- not opened".format(
        record["holdout_files"], record["holdout_bytes"],
    ))
    if args.dry_run:
        print("dry run: nothing moved, nothing written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
