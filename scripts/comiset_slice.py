"""Stream an Elastic Windows-event export into a filtered NDJSON slice.

Why a slice and not the archive
--------------------------------
``Comiset23_Lab_Environment_Dataset.zip`` is 4.9 GB compressed and **159.7 GB
uncompressed**, in a single member, so it cannot be extracted and cannot be seeked --
the only access pattern available is one sequential decompressing pass. This script
makes that pass once and keeps the small fraction of records ATH has tables for,
exactly as ``dedale_fetch_hours.py`` does for the DEDALE archive.

The per-channel totals of what was *seen* are written alongside the slice, so the
denominator for an ingestion-coverage figure survives the filtering. Without that,
representability would silently be computed against the slice rather than against the
corpus, which would flatter every number derived from it.

Usage::

    python scripts/comiset_slice.py \\
        data/external/comiset/raw/Comiset23_Lab_Environment_Dataset.zip \\
        data/external/comiset/slice
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import time
import zipfile
from collections import Counter
from pathlib import Path

# Channel/event-id pairs ATH has a canonical home for. Everything else is counted and
# dropped. Sysmon 1 is process creation, Sysmon 3 network connection; 4624/4625 are
# Windows logon success and failure.
KEEP: frozenset[tuple[str, str]] = frozenset({
    ("sysmon", "1"),
    ("sysmon", "3"),
    ("security", "4624"),
    ("security", "4625"),
})


def channel_of(index: str) -> str:
    """``logs-endpoint-winevent-sysmon-2022.11.16`` -> ``sysmon``."""
    return index.rsplit("-", 1)[0].split("winevent-")[-1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("archive", type=Path)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--member", default="dataset_comillas2.json")
    parser.add_argument("--max-records", type=int, default=0,
                        help="Stop after this many records (0 = whole file).")
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    slice_path = args.out_dir / "comiset_slice.jsonl"
    stats_path = args.out_dir / "comiset_seen.json"

    seen: Counter[str] = Counter()
    kept_by: Counter[str] = Counter()
    total = kept = 0
    started = time.time()

    archive = zipfile.ZipFile(args.archive)
    with archive.open(args.member) as raw, slice_path.open("w", encoding="utf-8") as out:
        for line in io.TextIOWrapper(raw, encoding="utf-8", errors="replace"):
            total += 1
            if args.max_records and total > args.max_records:
                break
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                seen["<unparseable>"] += 1
                continue

            source = record.get("_source") or {}
            channel = channel_of(str(record.get("_index", "")))
            event_id = str(source.get("event_id", ""))
            seen[f"{channel}/{event_id}"] += 1

            if (channel, event_id) not in KEEP:
                continue

            # Flatten the Elastic envelope away: downstream only needs the event, plus
            # the channel it came from and a stable reference back to this record.
            source["_channel"] = channel
            source["_doc_id"] = record.get("_id", "")
            out.write(json.dumps(source, ensure_ascii=False) + "\n")
            kept += 1
            kept_by[f"{channel}/{event_id}"] += 1

            if kept % 50_000 == 0:
                print(f"  {total:,} read, {kept:,} kept, {time.time()-started:.0f}s",
                      flush=True)

    stats_path.write_text(
        json.dumps({
            "archive": args.archive.name,
            "member": args.member,
            "records_read": total,
            "records_kept": kept,
            "seen_by_channel_event": dict(seen.most_common()),
            "kept_by_channel_event": dict(kept_by.most_common()),
            "seconds": round(time.time() - started, 1),
        }, indent=2),
        encoding="utf-8",
    )
    print(f"read {total:,}, kept {kept:,} -> {slice_path} in {time.time()-started:.0f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
