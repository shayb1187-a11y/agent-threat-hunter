"""Produce one M14 evaluation-table row for an unlabelled external dataset.

Runs the adapter (E0: what was ingested and what was dropped, by reason), the
label-free profile (E1 analyst load, E5 singleton cases, E6 platforms), and a scaling
series (E8: stage timings against event count on time-ordered prefixes of the data).
Writes a JSON record under reports/m14/ so the number in the report can be regenerated
from the manifest rather than copied from a terminal.

Usage::

    python scripts/m14_profile.py cloudtrail data/external/flaws_cloud/raw flaws_cloud
    python scripts/m14_profile.py k8s data/external/k8s_ci/raw k8s_ci --cluster ci
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ath.evaluation.profile import profile_telemetry  # noqa: E402
from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS  # noqa: E402
from ath.telemetry.loader import Telemetry  # noqa: E402
from ath.telemetry.source import SourceLoadResult  # noqa: E402

SCALING_FRACTIONS = (0.1, 0.25, 0.5, 1.0)


def load(kind: str, directory: Path, cluster: str) -> SourceLoadResult:
    if kind == "cloudtrail":
        from ath.telemetry.cloudtrail_source import CloudTrailSource
        return CloudTrailSource(directory).load()
    if kind == "k8s":
        from ath.telemetry.k8s_audit_source import K8sAuditSource
        return K8sAuditSource(directory, cluster=cluster).load()
    if kind == "defender":
        from ath.telemetry.defender_source import DefenderExportSource
        return DefenderExportSource(directory).load()
    if kind == "winlogbeat":
        from ath.telemetry.winlogbeat_source import WinlogbeatSource
        return WinlogbeatSource(directory).load()
    raise SystemExit(f"unknown source kind {kind!r}")


def issue_classes(result: SourceLoadResult, top: int = 15) -> list[dict]:
    """Drop reasons collapsed to their stable prefix, so 1,233 eventNames are readable."""
    counter: Counter[tuple[str, str, str]] = Counter()
    for issue in result.issues:
        reason = issue.reason
        for cut in (" is not one of", " is not in the", "; a control-plane", "; an authentication"):
            if cut in reason:
                reason = reason.split(cut)[0]
                break
        counter[(issue.event_type, issue.field, reason[:80])] += 1
    return [
        {"event_type": k[0], "field": k[1], "reason": k[2], "rows": v}
        for k, v in counter.most_common(top)
    ]


def to_telemetry(result: SourceLoadResult) -> Telemetry:
    return Telemetry(
        processes=result.tables[EVENT_PROCESS], network=result.tables[EVENT_NETWORK],
        logons=result.tables[EVENT_LOGON], controls=result.tables[EVENT_CONTROL],
    )


def prefix(telemetry: Telemetry, fraction: float) -> Telemetry:
    """The earliest ``fraction`` of events, by time, across all four tables."""
    if fraction >= 1.0:
        return telemetry
    start, end = telemetry.time_range
    cutoff = start + (end - start) * fraction
    return Telemetry(
        processes=telemetry.processes[telemetry.processes["timestamp"] <= cutoff],
        network=telemetry.network[telemetry.network["timestamp"] <= cutoff],
        logons=telemetry.logons[telemetry.logons["timestamp"] <= cutoff],
        controls=telemetry.controls[telemetry.controls["timestamp"] <= cutoff],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("kind", choices=("cloudtrail", "k8s", "defender", "winlogbeat"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("dataset", help="Manifest key; names the output file.")
    parser.add_argument("--cluster", default="external")
    parser.add_argument("--no-scaling", action="store_true")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "reports" / "m14")
    args = parser.parse_args()

    t0 = time.perf_counter()
    result = load(args.kind, args.directory, args.cluster)
    load_seconds = time.perf_counter() - t0
    telemetry = to_telemetry(result)

    record = {
        "dataset": args.dataset,
        "source_kind": args.kind,
        "labels": "none",
        "e0_ingestion": {
            "rows_read": result.rows_read,
            "rows_kept": result.rows_kept,
            "rows_dropped": result.rows_dropped,
            "kept_fraction": round(result.rows_kept / result.rows_read, 4) if result.rows_read else 0.0,
            "kept_by_table": {k: int(len(v)) for k, v in result.tables.items()},
            "drop_classes": issue_classes(result),
            "unmapped_classes": dict(sorted(result.unmapped.items(), key=lambda kv: -kv[1])[:25]),
            "load_seconds": round(load_seconds, 1),
        },
        "profile_full": profile_telemetry(telemetry).to_dict(),
    }

    if not args.no_scaling:
        series = []
        for fraction in SCALING_FRACTIONS:
            sub = prefix(telemetry, fraction)
            p = profile_telemetry(sub)
            series.append({
                "fraction": fraction, "events": p.events, "findings": p.findings,
                "cases": p.cases, "seconds": p.to_dict()["cost_seconds"],
            })
        record["e8_scaling"] = series

    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f"{args.dataset}.json"
    out.write_text(json.dumps(record, indent=2), encoding="utf-8")

    e0 = record["e0_ingestion"]
    pf = record["profile_full"]
    print(f"{args.dataset}: read {e0['rows_read']:,} kept {e0['rows_kept']:,} "
          f"({e0['kept_fraction']:.2%}) in {e0['load_seconds']}s")
    print(f"  findings {pf['detection']['findings']} {pf['detection']['by_rule']}  "
          f"per day {pf['detection']['findings_per_day']}")
    print(f"  triage {pf['triage']['dispositions']}  after triage {pf['triage']['findings_after_triage']}")
    print(f"  cases {pf['correlation']['cases']} (singletons {pf['correlation']['singleton_cases']}, "
          f"links {pf['correlation']['links']})  platforms {pf['telemetry']['platforms']}")
    print(f"  cost {pf['cost_seconds']}")
    if "e8_scaling" in record:
        for row in record["e8_scaling"]:
            print(f"  scaling {row['fraction']:>4}: events {row['events']:>8,} findings {row['findings']:>4} "
                  f"cases {row['cases']:>4}  {row['seconds']}")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
