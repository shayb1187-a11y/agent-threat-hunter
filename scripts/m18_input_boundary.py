"""M18-2 measurement: what the adapter boundary admitted, and what it quarantined.

Four numbers that used to be one
---------------------------------
"We ingested N of M records" conflated things that fail for different reasons and need
different fixes. This script keeps them apart, per corpus:

1. **Files** listed, admitted, and rejected -- with the reason and the record count each
   rejected file therefore never contributed. A directory is not curated; the denominator
   has to say which files it is a denominator of.
2. **Rows** read and kept, over admitted files only.
3. **Quarantine** -- rows removed because their timestamp cannot be a real event time,
   per table and per bound, with examples and the table's new earliest/latest.
4. **Findings** per rule, printed beside all of the above, because the only interesting
   question about a boundary change is whether it moved a conclusion.

Report-only, alongside: the fraction of each table's rows more than 30 days from that
table's median timestamp. This exists to answer "would a *relative* outlier rule be worth
having", and deliberately does nothing else -- no row is dropped for being far from the
median. A quiet reading means the absolute bounds are enough; a loud one is an argument
for a follow-up, not licence to add one here.

Usage::

    python scripts/m18_input_boundary.py synthetic --raw data/raw
    python scripts/m18_input_boundary.py attack_data_aws --source cloudtrail \\
        --directory data/external/attack_data_aws/raw
    python scripts/m18_input_boundary.py k8s_ci --source k8s \\
        --directory data/external/k8s_ci/raw --cluster ci
    python scripts/m18_input_boundary.py flaws_cloud --source cloudtrail \\
        --directory data/external/flaws_cloud/raw

    # COMISET, without re-ingesting 20M records: admission on a small mirror of the
    # slice directory, quarantine applied directly to the frozen canonical tables.
    python scripts/m18_input_boundary.py comiset --canonical reports/m17/canonical \\
        --mini-from data/external/comiset/slice --mini-lines 5000 \\
        --admission-source elastic_winevent
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from pre_schema_parquet import read_canonical_table  # noqa: E402

from ath.hunting import run_hunt  # noqa: E402
from ath.schema import (  # noqa: E402
    EVENT_CONTROL,
    EVENT_LOGON,
    EVENT_NETWORK,
    EVENT_PROCESS,
)
from ath.telemetry.loader import Telemetry, load_telemetry  # noqa: E402
from ath.telemetry.normalize import (  # noqa: E402
    QUARANTINE_REASON_PREFIX,
    TIMESTAMP_FLOOR,
    quarantine_implausible_timestamps,
)
from ath.telemetry.source import NormalizationIssue, SourceLoadResult  # noqa: E402

TABLES = (EVENT_PROCESS, EVENT_NETWORK, EVENT_LOGON, EVENT_CONTROL)

# Report-only: how far from a table's own median a row has to sit to be counted.
FAR_FROM_MEDIAN = pd.Timedelta(days=30)

# How large a file may be and still be copied whole into a mini mirror. Anything bigger
# is head-sliced instead. Size, not name: the point of the mirror is to reproduce the
# *directory's shape* (a sidecar next to a bulk file) without its bulk.
MINI_COPY_WHOLE_BYTES = 1_000_000


def load_source(kind: str, directory: Path, cluster: str) -> SourceLoadResult:
    """The adapter dispatch, same shape as scripts/m18_field_usability.py's."""
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
    if kind == "elastic_winevent":
        from ath.telemetry.elastic_winevent_source import ElasticWinEventSource
        return ElasticWinEventSource(directory).load()
    raise SystemExit(f"unknown source kind {kind!r}")


def to_telemetry(tables: dict[str, pd.DataFrame]) -> Telemetry:
    return Telemetry(
        processes=tables[EVENT_PROCESS], network=tables[EVENT_NETWORK],
        logons=tables[EVENT_LOGON], controls=tables[EVENT_CONTROL],
    )


def read_canonical(directory: Path, prefix: str) -> dict[str, pd.DataFrame]:
    """The canonical parquet tables an earlier milestone froze (the M17 COMISET set).

    Read, never rewritten: this script reports on those artifacts and must not become a
    way of quietly regenerating them. Columns the schema has gained since the freeze are
    added empty, at read time, with a notice on stdout naming them -- see
    ``scripts/pre_schema_parquet``.
    """
    names = {EVENT_PROCESS: "process", EVENT_NETWORK: "network",
             EVENT_LOGON: "logon", EVENT_CONTROL: "control"}
    return {
        event_type: read_canonical_table(directory, prefix, name, event_type)
        for event_type, name in names.items()
    }


# --------------------------------------------------------------------------------------
# The four measurements
# --------------------------------------------------------------------------------------


def admission_record(result: SourceLoadResult | None) -> dict:
    if result is None or not result.admitted_files:
        return {"listed": 0, "admitted": 0, "rejected": 0, "rejections": [],
                "records_never_read": 0,
                "note": "source reads no directory, or admission not applicable"}
    rejected = list(result.rejected_files)
    return {
        "listed": len(result.admitted_files),
        "admitted": len(result.admitted_files) - len(rejected),
        "rejected": len(rejected),
        "records_never_read": sum(a.line_or_record_count for a in rejected),
        "rejections": [a.to_dict() for a in rejected],
        "admitted_files": [a.to_dict() for a in result.admitted_files if a.admitted][:25],
    }


def quarantine_record(
    tables: dict[str, pd.DataFrame], issues: list[NormalizationIssue]
) -> dict:
    """Quarantine counts per table per reason, plus each table's surviving window.

    ``issues`` are the quarantine issues the boundary already raised (an adapter run);
    for tables loaded from canonical files the caller applies the function first and
    passes what it returned.
    """
    quarantined = [i for i in issues if i.reason.startswith(QUARANTINE_REASON_PREFIX)]
    by_table: dict[str, dict] = {}
    for event_type in TABLES:
        mine = [i for i in quarantined if i.event_type == event_type]
        reasons = Counter(
            i.reason.split("(value", 1)[0].replace(QUARANTINE_REASON_PREFIX, "").strip()
            for i in mine
        )
        stamps = tables[event_type]["timestamp"]
        by_table[event_type] = {
            "rows_after": int(len(stamps)),
            "quarantined": len(mine),
            "by_reason": dict(reasons),
            "examples": [i.to_dict() for i in mine[:5]],
            "earliest": stamps.min().isoformat() if len(stamps) else None,
            "latest": stamps.max().isoformat() if len(stamps) else None,
        }
    return {
        "total_quarantined": len(quarantined),
        "floor": TIMESTAMP_FLOOR.isoformat(),
        "by_table": by_table,
    }


def far_from_median_record(tables: dict[str, pd.DataFrame]) -> dict:
    """Report-only: rows more than :data:`FAR_FROM_MEDIAN` from their table's median.

    A measurement, not a rule. Nothing here removes a row; the question it is here to
    answer is whether a *relative* outlier test would catch anything the absolute bounds
    do not, on corpora whose real spans range from one hour to four years.
    """
    out = {}
    for event_type in TABLES:
        stamps = tables[event_type]["timestamp"].dropna()
        if stamps.empty:
            out[event_type] = {"rows": 0, "median": None, "beyond_30d": 0,
                               "fraction": 0.0, "span_days": 0.0}
            continue
        median = stamps.median()
        beyond = (stamps - median).abs() > FAR_FROM_MEDIAN
        out[event_type] = {
            "rows": int(len(stamps)),
            "median": median.isoformat(),
            "beyond_30d": int(beyond.sum()),
            "fraction": round(float(beyond.mean()), 6),
            "span_days": round(
                float((stamps.max() - stamps.min()).total_seconds() / 86400), 3
            ),
        }
    return out


def findings_record(telemetry: Telemetry) -> dict:
    hunt = run_hunt(telemetry)
    return {
        "total": len(hunt.findings),
        "by_rule": dict(sorted(Counter(f.rule_id for f in hunt.findings).items())),
    }


# --------------------------------------------------------------------------------------
# A small mirror of a big directory, for admission only
# --------------------------------------------------------------------------------------


def build_mini_mirror(source_dir: Path, out_dir: Path, lines: int) -> list[str]:
    """Reproduce a directory's *shape* without its bulk.

    Every file small enough is copied verbatim -- which is what a sidecar, manifest or
    statistics file is -- and each larger file contributes its first ``lines`` lines. That
    is enough for the boundary to decide, because admission reads only the first records
    of a file by design, and it means a 2 GB slice does not have to be re-ingested to
    demonstrate what happens to the sidecar sitting beside it.

    Selection is by **size**, never by name: a mirror that hand-picked the sidecar would
    be demonstrating the author's knowledge of this corpus rather than the boundary.
    """
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    copied: list[str] = []
    for path in sorted(source_dir.iterdir()):
        if not path.is_file():
            continue
        if path.stat().st_size <= MINI_COPY_WHOLE_BYTES:
            shutil.copy2(path, out_dir / path.name)
            copied.append(f"{path.name} (whole, {path.stat().st_size} bytes)")
            continue
        target = out_dir / f"{path.stem}_head{path.suffix}"
        with path.open("r", encoding="utf-8", errors="replace") as handle, \
                target.open("w", encoding="utf-8") as out:
            for index, line in enumerate(handle):
                if index >= lines:
                    break
                out.write(line)
        copied.append(f"{target.name} (first {lines} lines of {path.name})")
    return copied


# --------------------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("corpus", help="Names the output file under reports/m18/input_boundary/.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--raw", type=Path, metavar="DIR",
                       help="Canonical CSVs (the synthetic data/raw layout).")
    group.add_argument("--canonical", type=Path, metavar="DIR",
                       help="Canonical parquet tables frozen by an earlier milestone.")
    group.add_argument("--source", choices=(
        "cloudtrail", "k8s", "defender", "winlogbeat", "elastic_winevent",
    ), help="Adapter to run over --directory.")
    parser.add_argument("--directory", type=Path, help="Raw source directory for --source.")
    parser.add_argument("--cluster", default="external")
    parser.add_argument("--prefix", default="comiset", help="Filename prefix for --canonical.")
    parser.add_argument("--mini-from", type=Path, metavar="DIR",
                        help="Build a small mirror of DIR and run --admission-source on it.")
    parser.add_argument("--mini-lines", type=int, default=5000)
    parser.add_argument("--mini-out", type=Path, default=None)
    parser.add_argument("--admission-source", choices=(
        "cloudtrail", "k8s", "defender", "winlogbeat", "elastic_winevent",
    ), help="Adapter to run over the mini mirror, for the admission measurement only.")
    parser.add_argument("--out-dir", type=Path,
                        default=ROOT / "reports" / "m18" / "input_boundary")
    args = parser.parse_args()

    started = time.time()
    record: dict = {"corpus": args.corpus}

    # -- tables, and the quarantine that produced them ---------------------------------
    if args.source:
        if not args.directory:
            raise SystemExit("--source requires --directory")
        result = load_source(args.source, args.directory, args.cluster)
        tables = result.tables
        issues = result.issues
        record["rows"] = {"rows_read": result.rows_read, "rows_kept": result.rows_kept,
                          "rows_dropped": result.rows_dropped}
        record["admission"] = admission_record(result)
        record["source"] = {"kind": args.source, "path": str(args.directory)}
        # Findings before quarantine are recoverable only when quarantine removed
        # nothing -- in which case they are identical by construction, which is the
        # claim this line makes explicit rather than assuming.
        quarantined_here = sum(
            1 for i in issues if i.reason.startswith(QUARANTINE_REASON_PREFIX)
        )
        record["findings_before_equal_after_by_construction"] = quarantined_here == 0
    else:
        directory = args.raw or args.canonical
        if args.raw:
            telemetry = load_telemetry(args.raw)
            before = {t: telemetry.table(t) for t in TABLES}
            kind = "canonical_csv"
        else:
            before = read_canonical(args.canonical, args.prefix)
            kind = "canonical_parquet"
        # Canonical files have already been through an adapter boundary, so quarantine is
        # applied here explicitly: for data/raw to prove the generator's own data passes
        # the bounds untouched, and for the frozen M17 tables to measure what the bounds
        # would have removed at ingestion time.
        record["findings_before"] = findings_record(to_telemetry(before))
        tables, issues = {}, []
        for event_type in TABLES:
            kept, quarantined = quarantine_implausible_timestamps(
                before[event_type], event_type,
            )
            tables[event_type] = kept
            issues.extend(quarantined)
        record["rows"] = {
            "rows_read": int(sum(len(df) for df in before.values())),
            "rows_kept": int(sum(len(df) for df in tables.values())),
            "rows_dropped": len(issues),
        }
        record["admission"] = admission_record(None)
        record["source"] = {"kind": kind, "path": str(directory)}
        record["findings_before_equal_after_by_construction"] = len(issues) == 0

    # -- admission on a small mirror, when the real corpus is too big to re-ingest ------
    if args.mini_from:
        if not args.admission_source:
            raise SystemExit("--mini-from requires --admission-source")
        # Under the system temp dir by default: the mirror is scaffolding for one
        # measurement, not an artifact, and a 20 MB head slice has no business living in
        # reports/ where the frozen JSON does.
        mini_out = args.mini_out or (
            Path(tempfile.gettempdir()) / f"ath_m18_mini_{args.corpus}"
        )
        mirrored = build_mini_mirror(args.mini_from, mini_out, args.mini_lines)
        mini_result = load_source(args.admission_source, mini_out, args.cluster)
        record["admission"] = admission_record(mini_result)
        record["admission"]["measured_on"] = {
            "note": "a small mirror of the real directory; admission reads only the "
                    "first records of a file, so the decision is the same one the full "
                    "directory produces",
            "mirror_of": str(args.mini_from),
            "mirror": str(mini_out),
            "files": mirrored,
            "rows_read": mini_result.rows_read,
            "rows_kept": mini_result.rows_kept,
        }

    telemetry = to_telemetry(tables)
    record["quarantine"] = quarantine_record(tables, issues)
    record["far_from_median"] = far_from_median_record(tables)
    record["findings"] = findings_record(telemetry)
    record["rows_by_table"] = {t: int(len(tables[t])) for t in TABLES}
    record["seconds"] = round(time.time() - started, 1)

    print_report(record)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f"{args.corpus}.json"
    out.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(f"\nwrote {out}")
    return 0


def print_report(record: dict) -> None:
    rows = record["rows"]
    adm = record["admission"]
    print(f"\n=== {record['corpus']} ({record['source']['kind']}) ===")
    print(f"files    listed {adm['listed']}  admitted {adm['admitted']}  "
          f"rejected {adm['rejected']}  ({adm.get('records_never_read', 0)} record(s) "
          "never read)")
    for rejection in adm["rejections"]:
        print(f"  x {rejection['path']}: {rejection['reason']} "
              f"[{rejection['line_or_record_count']} record(s)]")
    print(f"rows     read {rows['rows_read']:,}  kept {rows['rows_kept']:,}  "
          f"dropped {rows['rows_dropped']:,}")

    quarantine = record["quarantine"]
    print(f"quarantine  {quarantine['total_quarantined']} row(s) "
          f"(floor {quarantine['floor']})")
    for event_type, detail in quarantine["by_table"].items():
        if detail["rows_after"] == 0 and detail["quarantined"] == 0:
            continue
        print(f"  {event_type:<8} rows {detail['rows_after']:>8,}  "
              f"quarantined {detail['quarantined']:>4}  "
              f"window {detail['earliest']} .. {detail['latest']}")
        for reason, count in detail["by_reason"].items():
            print(f"      {count} x {reason}")
        for example in detail["examples"][:2]:
            print(f"      e.g. {example['reason']} ref={example['raw_reference']}")

    print("far-from-median (report only; >30d from the table's own median)")
    for event_type, detail in record["far_from_median"].items():
        if not detail["rows"]:
            continue
        print(f"  {event_type:<8} rows {detail['rows']:>8,}  span {detail['span_days']:>9} d"
              f"  beyond30d {detail['beyond_30d']:>8,}  fraction {detail['fraction']}")

    if "findings_before" in record:
        print(f"findings before quarantine {record['findings_before']['total']} "
              f"{record['findings_before']['by_rule']}")
    print(f"findings  {record['findings']['total']} {record['findings']['by_rule']}")
    if record.get("findings_before_equal_after_by_construction"):
        print("  (quarantine removed nothing, so before == after by construction)")


if __name__ == "__main__":
    sys.exit(main())
