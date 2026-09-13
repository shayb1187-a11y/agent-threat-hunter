"""M18 measurement: per-rule field usability against a corpus, reported next to detection.

Answers three questions separately for every registered rule, because collapsing any
two of them is how a zero comes to read as "clean data":

1. **Eligibility** -- how many rows exist in the tables the rule declares it reads.
   Zero means the rule had no input; nothing about the rule is in question.
2. **Usability** -- what fraction of those rows carry each field the rule declares,
   and whether that field gates detection (`fields_used`) or only sharpens or explains
   a finding (`optional_fields`). A required field populated on under 1% of the rows is
   reported UNUSABLE: the rule runs, matches nothing, and looks healthy.
3. **Detection** -- how many findings the rule actually produced, printed *beside* the
   verdict rather than merged into it.

The BEFORE verdict (the channel-level `support` grade that was the whole measurement
until now) is carried next to the AFTER verdict on every row, so the two can be
compared per rule per corpus without re-running an older checkout.

Usage::

    python scripts/m18_field_usability.py synthetic --raw data/raw
    python scripts/m18_field_usability.py comiset --canonical reports/m17/canonical
    python scripts/m18_field_usability.py attack_data_aws --source cloudtrail \\
        --directory data/external/attack_data_aws/raw
    python scripts/m18_field_usability.py k8s_ci --source k8s \\
        --directory data/external/k8s_ci/raw --cluster ci
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from pre_schema_parquet import read_canonical_table  # noqa: E402

from ath.environment import assess_coverage, build_environment_model  # noqa: E402
from ath.hunting import run_hunt  # noqa: E402
from ath.schema import (  # noqa: E402
    EVENT_CONTROL,
    EVENT_LOGON,
    EVENT_NETWORK,
    EVENT_PROCESS,
)
from ath.telemetry.loader import Telemetry, load_telemetry  # noqa: E402
from ath.telemetry.source import SourceLoadResult  # noqa: E402

TABLES = (EVENT_PROCESS, EVENT_NETWORK, EVENT_LOGON, EVENT_CONTROL)


def load_source(kind: str, directory: Path, cluster: str) -> SourceLoadResult:
    """The adapter dispatch, same shape as scripts/m14_profile.py's ``load()``."""
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


def to_telemetry(result: SourceLoadResult) -> Telemetry:
    return Telemetry(
        processes=result.tables[EVENT_PROCESS], network=result.tables[EVENT_NETWORK],
        logons=result.tables[EVENT_LOGON], controls=result.tables[EVENT_CONTROL],
    )


def load_canonical(directory: Path, prefix: str = "comiset") -> Telemetry:
    """Canonical tables already written to parquet (the M17 COMISET artifacts).

    A table the corpus does not carry becomes an *empty but schema-valid* frame rather
    than a bare ``DataFrame()``: a table with no columns is not the same thing as a
    table with no rows, and everything downstream reads columns by name.

    A table the corpus *does* carry but which predates a column added since the freeze
    is widened with that column empty, and the widening is announced on stdout -- so a
    zero population for it reads as "this artifact is older than the column" rather than
    as "the corpus never carried the value". See ``scripts/pre_schema_parquet``.
    """
    def read(name: str, event_type: str) -> pd.DataFrame:
        return read_canonical_table(directory, prefix, name, event_type)

    return Telemetry(
        processes=read("process", EVENT_PROCESS), network=read("network", EVENT_NETWORK),
        logons=read("logon", EVENT_LOGON), controls=read("control", EVENT_CONTROL),
    )


def measure(corpus: str, telemetry: Telemetry) -> dict:
    """Eligibility, usability and detection for every registered rule."""
    started = time.time()
    hunt = run_hunt(telemetry)
    findings_by_rule = Counter(f.rule_id for f in hunt.findings)
    hunt_seconds = time.time() - started

    report = assess_coverage(build_environment_model(telemetry))

    rules = []
    for rule in report.rules:
        rules.append({
            "rule_id": rule.rule_id,
            "title": rule.title,
            "declared_tables": {table: rows for table, rows in rule.tables},
            "eligible_rows": rule.eligible_rows,
            "verdict": rule.verdict.value,
            "verdict_before": rule.support.value,
            "runnable": rule.runnable,
            "missing_channels": [c.value for c in rule.missing_channels],
            "degraded_channels": [c.value for c in rule.degraded_channels],
            "fields": [f.to_dict() for f in rule.fields],
            "unpopulated_fields": list(rule.unpopulated_fields),
            "sparse_fields": list(rule.sparse_fields),
            # Optional fields too sparse to phrase evidence with. Carried separately
            # because they moved the verdict until M18-5 and now do not: an artifact
            # that merged them back into `sparse_fields` would make a USABLE rule look
            # like it had been graded on something it was not.
            "sparse_optional_fields": list(rule.sparse_optional_fields),
            # The third list, carried beside the other two rather than folded into
            # either: a field no row in this corpus could have carried a value on is
            # neither starved nor sparse, and an artifact that only recorded the first
            # two would leave a reader unable to tell "measured and fine" from
            # "the question does not arise here".
            "not_applicable_fields": list(rule.not_applicable_fields),
            "findings": findings_by_rule.get(rule.rule_id, 0),
            "detail": rule.detail,
        })

    return {
        "corpus": corpus,
        "rows": {table: int(len(telemetry.table(table))) for table in TABLES},
        "events": telemetry.event_count,
        "channels": {
            channel.value: assessment.state.value
            for channel, assessment in report.environment.channels.items()
        },
        "rules": rules,
        "total_findings": len(hunt.findings),
        "verdict_counts": dict(Counter(r["verdict"] for r in rules)),
        "before_counts": dict(Counter(r["verdict_before"] for r in rules)),
        "hunt_seconds": round(hunt_seconds, 1),
    }


def print_table(record: dict) -> None:
    print(
        f"\n{record['corpus']}: {record['events']:,} events "
        f"{record['rows']}  |  {record['total_findings']} finding(s)"
    )
    header = f"{'rule':<9} {'tables':<9} {'rows':>9} {'before':<12} {'after':<13} {'finds':>5}  starved/sparse fields"
    print(header)
    print("-" * len(header))
    for rule in record["rules"]:
        tables = ",".join(rule["declared_tables"]) or "-"
        named = set(rule["sparse_fields"]) | set(rule.get("sparse_optional_fields", []))
        starved = ", ".join(
            f"{f['column']}={f['fraction']:.5f}"
            f"[raw {f['raw_fraction']:.5f} of {f['rows']:,}]"
            f"{'' if f['required'] else ' (opt, no verdict effect)'}"
            for f in rule["fields"]
            if f["column"] in named
        )
        if rule["not_applicable_fields"]:
            starved += (
                ("; " if starved else "")
                + "n/a here: " + ", ".join(rule["not_applicable_fields"])
            )
        print(
            f"{rule['rule_id']:<9} {tables:<9} {rule['eligible_rows']:>9,} "
            f"{rule['verdict_before']:<12} {rule['verdict']:<13} "
            f"{rule['findings']:>5}  {starved}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("corpus", help="Names the output file under reports/m18/field_usability/.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--raw", type=Path, metavar="DIR",
                       help="Directory of canonical CSVs (the synthetic data/raw layout).")
    group.add_argument("--canonical", type=Path, metavar="DIR",
                       help="Directory of canonical parquet tables (M17 artifacts).")
    group.add_argument("--source", choices=(
        "cloudtrail", "k8s", "defender", "winlogbeat", "elastic_winevent",
    ), help="Adapter to run over --directory.")
    parser.add_argument("--directory", type=Path, help="Raw source directory for --source.")
    parser.add_argument("--cluster", default="external", help="Cluster name for --source k8s.")
    parser.add_argument("--prefix", default="comiset", help="Filename prefix for --canonical.")
    parser.add_argument("--out-dir", type=Path,
                        default=ROOT / "reports" / "m18" / "field_usability")
    args = parser.parse_args()

    started = time.time()
    if args.raw:
        telemetry = load_telemetry(args.raw)
    elif args.canonical:
        telemetry = load_canonical(args.canonical, args.prefix)
    else:
        if not args.directory:
            raise SystemExit("--source requires --directory")
        telemetry = to_telemetry(load_source(args.source, args.directory, args.cluster))
    load_seconds = time.time() - started

    record = measure(args.corpus, telemetry)
    record["load_seconds"] = round(load_seconds, 1)
    record["source"] = {
        "kind": args.source or ("canonical_parquet" if args.canonical else "canonical_csv"),
        "path": str(args.directory or args.canonical or args.raw),
    }

    print_table(record)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f"{args.corpus}.json"
    out.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
