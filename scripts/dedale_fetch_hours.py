"""Range-fetch DEDALE Winlogbeat hours from the archive and filter them to what ATH maps.

A busy DEDALE hour is ~1.8 GB of JSON, of which the process, network and logon channels
are under 1%. This script never lands the whole hour on disk: it range-fetches one member
of the 27 GB zip (by offset from the committed index), inflates and bz2-decodes it in
memory, keeps only the channels listed in ``KEEP``, appends them to a per-day NDJSON file under
``data/external/dedale/winlogbeat/D<day>/``,
and records the *full* per-channel event counts for the hour in a stats file -- so the
E0 denominator (what the estate produced) survives the filtering.

Usage::

    python scripts/dedale_fetch_hours.py --days 3 15         # benign day 3, attack day 15
    python scripts/dedale_fetch_hours.py --days 15-22         # the whole labelled window
    python scripts/dedale_fetch_hours.py --days 3 --dry-run   # list the hours only
"""

from __future__ import annotations

import argparse
import bz2
import collections
import json
import re
import struct
import sys
import time
import urllib.request
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXTERNAL = ROOT / "data" / "external"
MANIFEST = json.loads((EXTERNAL / "MANIFEST.json").read_text(encoding="utf-8"))
ARCHIVE = MANIFEST["datasets"]["dedale"]["archive"]
INDEX = json.loads((EXTERNAL / ARCHIVE["index_file"]).read_text(encoding="utf-8"))
OUT_DIR = EXTERNAL / "dedale" / "winlogbeat"
STATS = EXTERNAL / "dedale" / "hour_stats.json"

# (channel, event_id) classes kept in the slice. Sysmon 1 and 3 and Security 4624/4625
# are what the adapter maps; 4648/4672/4634 and PowerShell 4103/4104 are cheap and are
# the next channels the schema is likely to grow, so they are kept for later rather than
# re-fetched. Everything else (Sysmon 7/10/11/22/26 -- 99% of the volume) is counted and
# dropped.
KEEP: frozenset[tuple[str, int]] = frozenset({
    ("Microsoft-Windows-Sysmon/Operational", 1),
    ("Microsoft-Windows-Sysmon/Operational", 3),
    ("Security", 4624), ("Security", 4625), ("Security", 4634),
    ("Security", 4648), ("Security", 4672),
    ("Microsoft-Windows-PowerShell/Operational", 4103),
    ("Microsoft-Windows-PowerShell/Operational", 4104),
})

_NAME = re.compile(r"D(?P<day>\d+)_H(?P<hour>\d+)_(?P<date>\d{4}-\d{2}-\d{2})T(?P<h>\d{2})_")


def parse_days(specs: list[str]) -> set[int]:
    days: set[int] = set()
    for spec in specs:
        if "-" in spec:
            lo, hi = spec.split("-", 1)
            days.update(range(int(lo), int(hi) + 1))
        else:
            days.add(int(spec))
    return days


def http_range(url: str, start: int, end: int) -> bytes:
    request = urllib.request.Request(
        url, headers={"Range": f"bytes={start}-{end}", "User-Agent": "agentic-threat-hunter/m14"},
    )
    with urllib.request.urlopen(request, timeout=900) as response:
        if response.status != 206:
            raise RuntimeError(f"server ignored Range (HTTP {response.status})")
        return response.read()


def fetch_member(entry: dict) -> bytes:
    url = ARCHIVE["url"]
    offset = int(entry["offset"])
    header = http_range(url, offset, offset + 29)
    if struct.unpack("<I", header[:4])[0] != 0x04034B50:
        raise RuntimeError(f"{entry['name']}: no local header at {offset}")
    name_len, extra_len = struct.unpack("<HH", header[26:30])
    start = offset + 30 + name_len + extra_len
    raw = http_range(url, start, start + int(entry["usize"]) - 1)
    if not raw.startswith(b"BZh"):
        raw = zlib.decompressobj(-15).decompress(raw)
    return raw


def process_hour(entry: dict, stats: dict) -> None:
    member = entry["name"].split("/")[-1]
    match = _NAME.match(member)
    day = int(match.group("day"))
    started = time.perf_counter()
    raw = fetch_member(entry)
    text = bz2.decompress(raw).decode("utf-8", errors="replace")
    counts: collections.Counter[str] = collections.Counter()
    kept = 0
    # One directory per day, so a day is an adapter input on its own (the adapters take
    # a directory) and a benign day and an attack day never share a load.
    day_dir = OUT_DIR / f"D{day:02d}"
    day_dir.mkdir(parents=True, exist_ok=True)
    with (day_dir / f"D{day:02d}_{match.group('date')}.jsonl").open("a", encoding="utf-8") as out:
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                counts["<bad json>"] += 1
                continue
            winlog = event.get("winlog") or {}
            key = (str(winlog.get("channel")), winlog.get("event_id"))
            counts[f"{key[0]}:{key[1]}"] += 1
            if key in KEEP:
                out.write(line + "\n")
                kept += 1
    stats[member] = {
        "day": day, "date": match.group("date"), "hour": int(match.group("h")),
        "bz2_bytes": len(raw), "json_bytes": len(text), "events": sum(counts.values()),
        "kept": kept, "by_class": dict(counts), "seconds": round(time.perf_counter() - started, 1),
    }
    STATS.write_text(json.dumps(stats, indent=1), encoding="utf-8")
    print(f"  {member}: {sum(counts.values()):,} events, kept {kept:,} "
          f"in {stats[member]['seconds']}s", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--days", nargs="+", required=True, help="Day numbers, e.g. 3 15 or 15-22.")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    days = parse_days(args.days)

    stats = json.loads(STATS.read_text(encoding="utf-8")) if STATS.exists() else {}
    entries = []
    for entry in INDEX:
        member = entry["name"].split("/")[-1]
        match = _NAME.match(member)
        if not match or int(entry["usize"]) <= 14:
            continue
        if int(match.group("day")) in days:
            entries.append((int(match.group("day")), int(match.group("h")), entry))
    entries.sort()
    todo = [e for _, _, e in entries if e["name"].split("/")[-1] not in stats]
    print(f"{len(entries)} non-empty hour(s) in days {sorted(days)}; {len(todo)} not yet fetched; "
          f"{sum(int(e['usize']) for e in todo) / 1e6:,.0f} MB to download")
    if args.dry_run:
        for e in todo:
            print("  ", e["name"].split("/")[-1], f"{int(e['usize']) / 1e6:,.0f} MB")
        return 0
    for entry in todo:
        process_hour(entry, stats)
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
