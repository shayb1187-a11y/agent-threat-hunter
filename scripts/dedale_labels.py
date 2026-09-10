"""Convert DEDALE's label files into ATH's native-ref label format.

DEDALE labels are verbatim copies of the malicious Winlogbeat events. ATH's evaluation
resolves labels through ``source_ref`` (``host=...;channel=...;record_id=...``), so this
script emits one ref per labelled event -- for *every* channel, including the ones ATH
has no table for. That is deliberate: the refs the adapter cannot resolve are the count
of labelled attack activity ATH never ingested, and that number belongs in the report
next to recall.

Stages are the labelled day, because DEDALE's own narrative is week/day-granular and a
per-event stage would be invented. Nothing here is read by an adapter.

Usage::

    python scripts/dedale_labels.py <path-to-system_labels dir> data/external/dedale/labels
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path


def convert(labels_dir: Path, out_dir: Path) -> Path:
    files = sorted(labels_dir.rglob("malicious_events_class_1.jsonl"))
    if not files:
        raise SystemExit(f"no malicious_events_class_1.jsonl under {labels_dir}")
    by_day: dict[str, list[str]] = collections.defaultdict(list)
    by_class: collections.Counter[str] = collections.Counter()
    seen: set[str] = set()
    for path in files:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            event = json.loads(line)
            winlog = event.get("winlog") or {}
            host = (event.get("host") or {}).get("name") or ""
            ref = f"host={host};channel={winlog.get('channel', '')};record_id={winlog.get('record_id', '')}"
            if ref in seen:
                continue
            seen.add(ref)
            day = str(event.get("@timestamp", ""))[:10]
            by_day[day].append(ref)
            by_class[f"{winlog.get('channel')}:{winlog.get('event_id')}"] += 1

    payload = {
        "dataset": "dedale",
        "provenance": "emulated-testbed",
        "license": "CC BY 4.0 -- https://dedale.inria.fr/ (cite and link)",
        "source": "system_logs_labels.zip / clients_1_and_2 + internal_server, class 1 (Windows hosts only resolve)",
        "note": (
            "Labels cover Sysmon and PowerShell channels only; no Security-channel event is "
            "labelled, so a logon-based detection of the attack cannot be credited by these "
            "labels and will be scored as noise. Refs in channels ATH has no table for are "
            "included on purpose so the unresolved count measures what ATH cannot see."
        ),
        "labelled_event_classes": dict(by_class.most_common()),
        "scenarios": {
            "apt": {
                "malicious": True,
                "note": "DEDALE 8-day APT: macro document, Invoke-WebRequest, scvhost.exe/svcmon.exe implant, Run-key persistence, impacket lateral movement, collection, exfiltration.",
                "stages": {
                    day: {"note": f"labelled events on {day}", "refs": refs}
                    for day, refs in sorted(by_day.items())
                },
            }
        },
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "dedale_class1_labels.json"
    out.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    print(f"{len(seen)} labelled events across {len(by_day)} day(s) -> {out}")
    for cls, n in by_class.most_common(12):
        print(f"  {n:6d}  {cls}")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("labels_dir", type=Path)
    parser.add_argument("out_dir", type=Path)
    args = parser.parse_args()
    convert(args.labels_dir, args.out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
