"""M18-3 measurement: where cloud telemetry stops being visible, stage by stage.

The number this replaces is an ingestion percentage, and an ingestion percentage
conflates at least five different things. So every stage between "a file on disk" and "a
case an analyst reads" is counted separately, and the BEFORE value from the frozen M14 /
M16 / M18-1 artifacts is printed next to the AFTER value at each one::

    raw records in listed files
      -> records in admitted files        (the file boundary, M18-2 Part A)
      -> recognised as authentication / as management activity / as neither
      -> canonical rows per table         (what a rule can actually filter)
      -> quarantined                      (the timestamp boundary, M18-2 Part B)
      -> per-field population on the control table
      -> verb classes and resource types  (what the representation says)
      -> rule eligibility and usability   (M18-1's verdicts, recomputed)
      -> findings per rule
      -> cases

The point of the ledger is that a zero at the end can be read back to the stage that
produced it. Before M18-3, attack_data_aws lost 2,347 of 2,349 records at the *third*
stage -- recognition -- because the adapter named five API calls and refused the rest;
every stage after that was measuring an empty table.

Usage::

    python scripts/m18_cloud_representation.py attack_data_aws \\
        --directory data/external/attack_data_aws/raw \\
        --before reports/m16/attack_data_aws.json
    python scripts/m18_cloud_representation.py flaws_cloud \\
        --directory data/external/flaws_cloud/raw \\
        --before reports/m16/flaws_cloud.json --raw-lookup
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
import tarfile
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from ath.behavior.control_plane import verb_class  # noqa: E402
from ath.evaluation.profile import profile_telemetry  # noqa: E402
from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS  # noqa: E402
from ath.telemetry.cloudtrail_source import CloudTrailSource  # noqa: E402
from ath.telemetry.loader import Telemetry  # noqa: E402
from ath.telemetry.normalize import QUARANTINE_REASON_PREFIX  # noqa: E402
from ath.telemetry.source import SourceLoadResult  # noqa: E402
from m18_field_usability import measure  # noqa: E402

CONTROL_FIELDS = (
    "verb", "resource_type", "actor", "decision", "target_actor", "role_ref",
    "resource_name",
)

# Issue reasons, collapsed to the class of loss they describe. A per-record reason is the
# right artifact for an analyst and the wrong one for a ledger: 1,859,687 of them say the
# same four things.
ISSUE_CLASSES = (
    ("timestamp_quarantined", QUARANTINE_REASON_PREFIX),
    ("unparseable_timestamp", "unparseable timestamp"),
    ("no_principal", "no usable principal"),
    ("not_an_object", "record is not a JSON object"),
    ("no_event_name", "no event name"),
    ("name_has_no_verb", "does not begin with a capitalised word"),
    ("refused_as_unmapped", "is not one of"),
)

# How many original records a run will fetch back for review. A bound, not a sample of
# the corpus: it limits the evidence dump attached to findings whose count moved, and the
# scope it was applied under is written into the artifact beside it.
RAW_LOOKUP_CAP = 50

# How many evidence items per finding are written out with their canonical rows. A burst
# detection on a real trail cites thousands of logons; the finding is reviewable from the
# first few plus the total, and the total is always written.
EVIDENCE_CAP = 20


def classify_issue(reason: str) -> str:
    for name, marker in ISSUE_CLASSES:
        if marker in reason:
            return name
    return "other"


def to_telemetry(result: SourceLoadResult) -> Telemetry:
    return Telemetry(
        processes=result.tables[EVENT_PROCESS], network=result.tables[EVENT_NETWORK],
        logons=result.tables[EVENT_LOGON], controls=result.tables[EVENT_CONTROL],
    )


def ledger(result: SourceLoadResult) -> dict:
    """The per-stage account of what became a row and what did not, and why."""
    issues = Counter(classify_issue(i.reason) for i in result.issues)
    by_table = Counter((i.event_type, classify_issue(i.reason)) for i in result.issues)

    logons = result.tables[EVENT_LOGON]
    controls = result.tables[EVENT_CONTROL]

    # A record entered the authentication path iff its name is in AUTH_EVENTS, and the
    # management path otherwise, so each path's own issues plus its rows account for
    # every record it saw. The "name_has_no_verb" issue is the one that accompanies a
    # kept row rather than replacing it, so it is not a refusal.
    auth_refusals = sum(
        count for (table, klass), count in by_table.items() if table == EVENT_LOGON
    )
    control_refusals = sum(
        count for (table, klass), count in by_table.items()
        if table == EVENT_CONTROL and klass != "name_has_no_verb"
    )

    admissions = result.admitted_files
    rejected = result.rejected_files
    return {
        "files_listed": len(admissions),
        "files_admitted": len(admissions) - len(rejected),
        "files_rejected": [a.to_dict() for a in rejected],
        "records_in_rejected_files": sum(a.line_or_record_count for a in rejected),
        # Stage 1-2: the file boundary.
        "records_in_admitted_files": result.rows_read,
        # Stage 3: recognition. "neither" is empty by construction now -- no record is
        # refused for naming a call this adapter does not know.
        "recognised_authentication": int(len(logons)) + auth_refusals,
        "recognised_management": int(len(controls)) + control_refusals,
        "recognised_neither": 0,
        "refused_for_its_name": issues["refused_as_unmapped"],
        # Stage 4-5: canonical rows, and what fell out on the way.
        "rows_by_table": {k: int(len(v)) for k, v in result.tables.items()},
        "rows_kept": result.rows_kept,
        "issues_by_class": dict(issues.most_common()),
        "quarantined": issues["timestamp_quarantined"],
        "names_with_no_verb_token": issues["name_has_no_verb"],
        # rows_dropped counts every issue, and one class of issue now accompanies a row
        # that was kept. Stated rather than quietly netted off.
        "rows_dropped_reported": result.rows_dropped,
        "rows_dropped_excluding_kept_rows": result.rows_dropped - issues["name_has_no_verb"],
        # Stage 6: rows that were kept, and a column on them that could not be filled.
        # The stage the ledger had no line for: a population fraction below reports the
        # same number whether the adapter dropped a value the record carried or the
        # record never carried one, and only the adapter can tell those apart.
        "field_gaps": dict(sorted(result.field_gaps.items(), key=lambda kv: -kv[1])),
        "field_gaps_total": sum(result.field_gaps.values()),
    }


def control_shape(controls) -> dict:
    """What the control table says: field population, verb classes, resource types."""
    total = int(len(controls))
    if not total:
        return {"rows": 0, "population": {}, "verb_classes": {}, "top_resource_types": {}}
    verbs = Counter(controls["verb"])
    classes: Counter = Counter()
    for verb, count in verbs.items():
        classes[verb_class(verb)] += count
    return {
        "rows": total,
        "population": {
            field: round(float((controls[field].fillna("") != "").mean()), 4)
            for field in CONTROL_FIELDS
        },
        "distinct_verbs": len(verbs),
        "verb_classes": dict(classes.most_common()),
        "top_verbs": dict(verbs.most_common(15)),
        "distinct_resource_types": int(controls["resource_type"].nunique()),
        "top_resource_types": dict(Counter(controls["resource_type"]).most_common(25)),
    }


def finding_records(telemetry: Telemetry, findings: list) -> list[dict]:
    """Every finding with the canonical rows its evidence points at.

    Listed individually and unjudged: a finding that appears only after a representation
    change has to be reviewable against the records it rests on, not summarised into a
    count.
    """
    # Only the rows the evidence points at. Indexing the whole table would build a
    # million-entry dict of pandas rows to answer a question about a handful of them --
    # which is how a measurement ends up costing more than the thing it measures.
    wanted = {item.event_id for finding in findings for item in finding.evidence}
    unified = {}
    for table in (telemetry.logons, telemetry.controls):
        if len(table) and wanted:
            for _, row in table[table["event_id"].isin(wanted)].iterrows():
                unified[row["event_id"]] = row
    out = []
    for finding in findings:
        evidence = []
        for item in finding.evidence[:EVIDENCE_CAP]:
            row = unified.get(item.event_id)
            evidence.append({
                "event_id": item.event_id,
                "timestamp": str(item.timestamp),
                "summary": item.summary,
                "source_ref": str(row["source_ref"]) if row is not None else "",
                "row": {
                    column: str(row[column])
                    for column in ("actor", "verb", "resource_type", "resource_name",
                                   "target_actor", "role_ref", "decision", "device",
                                   "source_ip")
                    if row is not None and column in row
                },
            })
        out.append({
            "rule_id": finding.rule_id,
            "evidence_count": len(finding.evidence),
            "severity": finding.severity.value,
            "user": finding.user,
            "device": finding.device,
            "reason": finding.reason,
            "evidence": evidence,
        })
    return out


def raw_records_for(directory: Path, event_ids: set[str]) -> dict[str, dict]:
    """Fetch the original CloudTrail records behind a handful of event ids.

    One extra pass over the corpus, for evidence only: a finding is reviewable when the
    record it rests on can be read, not when its id can be quoted.
    """
    found: dict[str, dict] = {}
    if not event_ids:
        return found

    def scan(raw: bytes, name: str) -> None:
        try:
            if name.endswith(".gz"):
                raw = gzip.decompress(raw)
            payload = json.loads(raw.decode("utf-8"))
        except Exception:  # noqa: BLE001 -- evidence lookup must never fail a measurement
            return
        records = payload.get("Records") if isinstance(payload, dict) else None
        for record in records or []:
            if isinstance(record, dict) and record.get("eventID") in event_ids:
                found[record["eventID"]] = record

    for path in sorted(directory.iterdir()):
        if path.suffix == ".tar":
            with tarfile.open(path) as archive:
                for member in archive:
                    if member.isfile():
                        handle = archive.extractfile(member)
                        if handle is not None:
                            scan(handle.read(), member.name)
        elif path.suffix in (".json", ".gz"):
            scan(path.read_bytes(), path.name)
        if len(found) == len(event_ids):
            break
    return found


def before_from(path: Path | None, usability: Path | None) -> dict:
    """The frozen BEFORE numbers, read rather than remembered."""
    before: dict = {}
    if path and path.exists():
        record = json.loads(path.read_text(encoding="utf-8"))
        e0 = record.get("e0_ingestion", {})
        profile = record.get("profile_full", {})
        before["ingestion"] = {
            "rows_read": e0.get("rows_read"), "rows_kept": e0.get("rows_kept"),
            "rows_dropped": e0.get("rows_dropped"),
            "kept_fraction": e0.get("kept_fraction"),
            "kept_by_table": e0.get("kept_by_table"),
            "load_seconds": e0.get("load_seconds"),
            "top_drop_classes": e0.get("drop_classes", [])[:5],
        }
        before["detection"] = profile.get("detection", {})
        before["correlation"] = profile.get("correlation", {})
        before["source"] = str(path)
    if usability and usability.exists():
        record = json.loads(usability.read_text(encoding="utf-8"))
        before["usability"] = {
            "rows": record.get("rows"),
            "rules": {
                rule["rule_id"]: {
                    "eligible_rows": rule["eligible_rows"], "verdict": rule["verdict"],
                    "findings": rule["findings"],
                    "sparse_fields": rule["sparse_fields"],
                    "unpopulated_fields": rule["unpopulated_fields"],
                }
                for rule in record.get("rules", [])
                if rule["rule_id"].startswith("AWS-") or rule["eligible_rows"]
            },
        }
        before["usability_source"] = str(usability)
    return before


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("corpus")
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--before", type=Path, help="Frozen M14/M16 profile record.")
    parser.add_argument("--before-usability", type=Path,
                        help="Frozen M18-1 field-usability record (defaults by corpus name).")
    parser.add_argument("--raw-lookup", action="store_true",
                        help="Re-read the corpus to attach raw records to each finding.")
    parser.add_argument("--out-dir", type=Path,
                        default=ROOT / "reports" / "m18" / "cloud_representation")
    args = parser.parse_args()

    try:
        import psutil
        process = psutil.Process()
    except ImportError:  # pragma: no cover - psutil is present in this environment
        process = None

    started = time.perf_counter()
    result = CloudTrailSource(args.directory).load()
    load_seconds = time.perf_counter() - started
    telemetry = to_telemetry(result)

    hunt_started = time.perf_counter()
    usability = measure(args.corpus, telemetry)
    measure_seconds = time.perf_counter() - hunt_started

    from ath.hunting import run_hunt
    findings = run_hunt(telemetry).findings
    profile = profile_telemetry(telemetry).to_dict()

    peak_bytes = None
    if process is not None:
        info = process.memory_info()
        peak_bytes = int(getattr(info, "peak_wset", getattr(info, "rss", 0)))

    before_usability = args.before_usability or (
        ROOT / "reports" / "m18" / "field_usability" / f"{args.corpus}.json"
    )
    record = {
        "corpus": args.corpus,
        "directory": str(args.directory),
        "before": before_from(args.before, before_usability),
        "after": {
            "ledger": ledger(result),
            "control_table": control_shape(telemetry.controls),
            "rules": [
                {k: rule[k] for k in (
                    "rule_id", "eligible_rows", "verdict", "verdict_before", "findings",
                    "sparse_fields", "unpopulated_fields",
                )}
                for rule in usability["rules"]
                if rule["eligible_rows"] or rule["findings"]
            ],
            "findings_by_rule": dict(Counter(f.rule_id for f in findings).most_common()),
            "findings_total": len(findings),
            "cases": profile["correlation"],
            "triage": profile["triage"],
            "findings": finding_records(telemetry, findings),
        },
        "cost": {
            "load_seconds": round(load_seconds, 1),
            "measure_seconds": round(measure_seconds, 1),
            "peak_bytes": peak_bytes,
            "peak_gb": round(peak_bytes / 2**30, 3) if peak_bytes else None,
        },
    }

    if args.raw_lookup:
        # Scoped to the delta. A representation change has to be answerable for the
        # findings it *moved*, one by one, against the records they rest on -- and for
        # nothing else: dumping the raw records behind an unchanged burst detection is
        # 29MB of artifact that says "still the same".
        before_by_rule = record["before"].get("detection", {}).get("by_rule") or {}
        after_by_rule = record["after"]["findings_by_rule"]
        changed = {
            rule for rule in set(before_by_rule) | set(after_by_rule)
            if before_by_rule.get(rule, 0) != after_by_rule.get(rule, 0)
        }
        wanted = sorted({
            item["source_ref"].split(";")[0].removeprefix("eventID=")
            for finding in record["after"]["findings"]
            if finding["rule_id"] in changed
            for item in finding["evidence"] if item["source_ref"]
        })[:RAW_LOOKUP_CAP]
        record["after"]["raw_records_scope"] = {
            "rules_with_a_changed_count": sorted(changed),
            "event_ids_requested": len(wanted),
            "cap": RAW_LOOKUP_CAP,
        }
        record["after"]["raw_records"] = raw_records_for(args.directory, set(wanted))

    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f"{args.corpus}.json"
    out.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")

    led = record["after"]["ledger"]
    shape = record["after"]["control_table"]
    before_ingest = record["before"].get("ingestion", {})
    print(f"\n{args.corpus}")
    print(f"  files                {led['files_admitted']}/{led['files_listed']} admitted")
    print(f"  records admitted     {led['records_in_admitted_files']:,}")
    print(f"  recognised auth      {led['recognised_authentication']:,}")
    print(f"  recognised mgmt      {led['recognised_management']:,}")
    print(f"  refused for name     {led['refused_for_its_name']:,} "
          f"(before: {before_ingest.get('rows_dropped')})")
    print(f"  rows kept            {led['rows_kept']:,} "
          f"(before: {before_ingest.get('rows_kept')})  {led['rows_by_table']}")
    print(f"  issues               {led['issues_by_class']}")
    print(f"  field gaps           {led['field_gaps_total']:,} {led['field_gaps']}")
    print(f"  control population   {shape.get('population')}")
    print(f"  verb classes         {shape.get('verb_classes')}")
    print(f"  findings             {record['after']['findings_by_rule']} "
          f"(before: {record['before'].get('detection', {}).get('by_rule')})")
    print(f"  cases                {record['after']['cases']['cases']} "
          f"(before: {record['before'].get('correlation', {}).get('cases')})")
    print(f"  cost                 {record['cost']}")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
