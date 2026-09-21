"""M17 evaluation of ATH against the held-out COMISET slice.

Answers five questions separately, because a single headline number hides all of them:

1. **Detection.** Per rule: how many events were eligible, how many findings, what
   severity, and -- where a zero is reported -- *why* it is zero. "No findings" is not a
   result until it is attributed to one of: clean data, rule correctly silent, rule not
   eligible, required field lost in ingestion, channel never mapped, threshold too strict.
2. **Network fidelity.** Which of the nine attributes an analyst needs from a connection
   event survive canonicalisation, and whether the public/private classification agrees
   with the source pipeline's own verdict -- the corpus labels every address
   ``dst_ip_public``/``dst_ip_rfc``, which is an independent answer to compare against.
3. **Cross-channel joins.** Whether a process seen in process telemetry can be tied to its
   own connections using only the identifiers that survive ingestion, and how often that
   join is ambiguous.
4. **Provenance.** Whether a finding's evidence can be walked back to the original corpus
   record, which is what makes an investigation checkable rather than merely asserted.

Everything is written to a JSON artifact so the numbers can be regenerated rather than
quoted from a terminal.

Usage::

    python scripts/m17_comiset_eval.py reports/m17/canonical data/external/comiset/slice
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from ath.hunting import run_hunt  # noqa: E402
from ath.hunting.base import all_detectors  # noqa: E402
from ath.netaddr import is_public_ip  # noqa: E402
from ath.schema import (  # noqa: E402
    EVENT_CONTROL,
    EVENT_LOGON,
    EVENT_NETWORK,
    EVENT_PROCESS,
)
from ath.telemetry.loader import Telemetry  # noqa: E402
from pre_schema_parquet import read_canonical_table  # noqa: E402


def load_canonical(directory: Path) -> Telemetry:
    """The frozen COMISET tables, widened to whatever the schema says today.

    ``reports/m17/canonical`` is read and never rewritten, so it predates every column
    added after M17 -- the process-instance identities of M18b-1 among them. The
    widening is announced on stdout for each table it touches; see
    ``scripts/pre_schema_parquet``.
    """
    return Telemetry(
        processes=read_canonical_table(directory, "comiset", "process", EVENT_PROCESS),
        network=read_canonical_table(directory, "comiset", "network", EVENT_NETWORK),
        logons=read_canonical_table(directory, "comiset", "logon", EVENT_LOGON),
        controls=read_canonical_table(directory, "comiset", "control", EVENT_CONTROL),
    )


def rule_tables(detector) -> tuple[str, ...]:
    """The canonical tables a rule reads, read off the rule itself.

    This used to be a hard-coded rule-id-to-table map in this script, because a
    detector declared no such thing (defect M17-5). It does now -- and the map it
    replaces was already wrong: it credited ATH-007 with the logon table, which
    ATH-007 never reads, so the rule's "eligible events" counted 6,063 logon rows it
    cannot see. A table map that lives outside the rules drifts from them silently;
    this cannot.
    """
    return tuple(sorted(detector.tables))


def why_zero(detector, telemetry: Telemetry, findings: int) -> str:
    """Attribute a zero to a cause rather than letting it read as success."""
    if findings:
        return "n/a -- rule produced findings"
    tables = rule_tables(detector)
    sizes = {t: len(telemetry.table(t)) for t in tables}
    if not tables:
        return "unknown -- rule's input table is not declared"
    if all(size == 0 for size in sizes.values()):
        return f"NOT ELIGIBLE -- required table(s) empty: {sizes}"
    return f"ELIGIBLE AND SILENT -- input present {sizes}; clean data or threshold not met"


def detection_report(telemetry: Telemetry) -> dict:
    rows = []
    hunt = run_hunt(telemetry)
    by_rule: dict[str, list] = defaultdict(list)
    for finding in hunt.findings:
        by_rule[finding.rule_id].append(finding)

    for detector in all_detectors():
        rule_id = detector.rule_id
        found = by_rule.get(rule_id, [])
        tables = rule_tables(detector)
        eligible = sum(len(telemetry.table(t)) for t in tables) if tables else 0
        rows.append({
            "rule_id": rule_id,
            "input_tables": list(tables),
            "eligible_events": int(eligible),
            "findings": len(found),
            "severity": dict(Counter(f.severity.value for f in found)),
            "declares_channels": sorted(c.value for c in detector.channels),
            "zero_attribution": why_zero(detector, telemetry, len(found)),
            "examples": [
                {
                    "device": f.device, "user": f.user, "severity": f.severity.value,
                    "event_count": f.event_count,
                    "evidence": [str(e.summary)[:160] for e in f.evidence[:2]],
                    "event_ids": list(f.event_ids[:3]),
                }
                for f in found[:3]
            ],
        })
    return {"rules": rows, "total_findings": len(hunt.findings)}


NETWORK_ATTRIBUTES = [
    ("source host", "device"),
    ("initiating process name", "process_name"),
    ("initiating process id", "process_id"),
    ("source IP", None),
    ("destination IP", "remote_ip"),
    ("source port", None),
    ("destination port", "remote_port"),
    ("protocol", "protocol"),
    ("timestamp", "timestamp"),
    ("provenance", "source_ref"),
]


def network_report(telemetry: Telemetry, slice_dir: Path, sample: int) -> dict:
    net = telemetry.network
    if net.empty:
        return {"rows": 0, "note": "no network telemetry"}

    fidelity = []
    for label, column in NETWORK_ATTRIBUTES:
        if column is None:
            fidelity.append({"attribute": label, "canonical_column": None,
                             "preserved": False,
                             "reason": "no such column exists in the canonical schema"})
        else:
            populated = int(net[column].notna().sum()) if column in net else 0
            non_empty = int((net[column].astype(str).str.len() > 0).sum()) if column in net else 0
            fidelity.append({"attribute": label, "canonical_column": column,
                             "preserved": column in net.columns,
                             "populated_rows": min(populated, non_empty)})

    # Compare ATH's public/private verdict against the corpus pipeline's own labels.
    truth: dict[str, bool] = {}
    for path in sorted(slice_dir.glob("*.jsonl")):
        with path.open(encoding="utf-8", errors="replace") as handle:
            for index, line in enumerate(handle):
                if index >= sample:
                    break
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                addr = record.get("dst_ip_addr")
                flag = record.get("dst_ip_public")
                if addr and flag is not None:
                    truth[str(addr)] = str(flag).lower() == "true"

    agree = disagree = 0
    disagreements = []
    for addr, corpus_says_public in truth.items():
        ath_says_public = is_public_ip(addr)
        if ath_says_public == corpus_says_public:
            agree += 1
        else:
            disagree += 1
            if len(disagreements) < 12:
                disagreements.append({"ip": addr, "ath_public": ath_says_public,
                                      "corpus_public": corpus_says_public})

    examples = net.head(3)[
        ["timestamp", "device", "user", "process_name", "process_id",
         "remote_ip", "remote_port", "protocol", "direction", "source_ref"]
    ].astype(str).to_dict("records")

    return {
        "rows": int(len(net)),
        "attribute_fidelity": fidelity,
        "ip_classification": {
            "distinct_addresses_compared": len(truth),
            "agree": agree, "disagree": disagree,
            "agreement": round(agree / len(truth), 4) if truth else None,
            "disagreements": disagreements,
        },
        "canonical_examples": examples,
        "distinct_remote_ips": int(net["remote_ip"].nunique()),
        "public_remote_ips": int(sum(is_public_ip(ip) for ip in net["remote_ip"].unique())),
    }


def join_report(telemetry: Telemetry, slice_dir: Path, sample: int) -> dict:
    """Can a process be tied to its own connections after canonicalisation?"""
    procs, net = telemetry.processes, telemetry.network
    if procs.empty or net.empty:
        return {"note": "one side empty; join not measurable"}

    proc_keys = set(zip(procs["device"], procs["process_id"].astype("Int64")))
    net_keys = list(zip(net["device"], net["process_id"].astype("Int64")))
    matched = sum(1 for key in net_keys if key in proc_keys)

    # How ambiguous is (device, pid)? The corpus carries process_guid, which is unique
    # per process instance; canonicalisation drops it. Measuring how many (device, pid)
    # pairs cover more than one guid says exactly what that loss costs.
    guid_per_key: dict[tuple, set] = defaultdict(set)
    seen = 0
    for path in sorted(slice_dir.glob("*.jsonl")):
        with path.open(encoding="utf-8", errors="replace") as handle:
            for index, line in enumerate(handle):
                if index >= sample:
                    break
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                guid = record.get("process_guid")
                pid = record.get("process_id")
                host = str(record.get("host_name", "")).split(".", 1)[0].lower()
                if guid and pid is not None and host:
                    guid_per_key[(host, int(pid))].add(str(guid))
                    seen += 1

    ambiguous = {k: len(v) for k, v in guid_per_key.items() if len(v) > 1}
    return {
        "join_keys_available": ["device", "process_id", "process_name", "timestamp"],
        "join_key_lost_in_ingestion": ["process_guid (unique per process instance)"],
        "network_rows": int(len(net)),
        "network_rows_matching_a_known_process": int(matched),
        "join_success_rate": round(matched / len(net), 4) if len(net) else None,
        "records_examined_for_ambiguity": seen,
        "distinct_device_pid_keys": len(guid_per_key),
        "ambiguous_device_pid_keys": len(ambiguous),
        "ambiguity_rate": round(len(ambiguous) / len(guid_per_key), 4) if guid_per_key else None,
        "worst_key_guid_count": max(ambiguous.values()) if ambiguous else 1,
    }


def provenance_report(telemetry: Telemetry, slice_dir: Path, findings, sample: int) -> dict:
    """Walk finding -> canonical event -> source_ref -> original corpus record."""
    wanted: dict[str, str] = {}
    for finding in findings:
        for event_id in finding.event_ids[:2]:
            wanted[event_id] = finding.rule_id
    if not wanted:
        return {"checked": 0, "note": "no findings to trace"}

    doc_ids = {eid.split(":", 1)[1]: eid for eid in wanted if ":" in eid}
    found: dict[str, dict] = {}
    for path in sorted(slice_dir.glob("*.jsonl")):
        with path.open(encoding="utf-8", errors="replace") as handle:
            for index, line in enumerate(handle):
                if index >= sample or len(found) == len(doc_ids):
                    break
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                doc = str(record.get("_doc_id", ""))
                if doc in doc_ids:
                    found[doc] = record

    results = []
    for doc, event_id in doc_ids.items():
        record = found.get(doc)
        results.append({
            "finding_rule": wanted[event_id],
            "canonical_event_id": event_id,
            "source_doc_id": doc,
            "reconstructed": record is not None,
            "original_channel": (record or {}).get("_channel"),
            "original_event_id": (record or {}).get("event_id"),
            "original_time": (record or {}).get("event_original_time"),
        })
    reconstructed = sum(1 for r in results if r["reconstructed"])
    return {
        "checked": len(results),
        "reconstructed": reconstructed,
        "reconstruction_rate": round(reconstructed / len(results), 4) if results else None,
        "samples": results[:10],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("canonical", type=Path)
    parser.add_argument("slice_dir", type=Path)
    parser.add_argument("--out", type=Path, default=ROOT / "reports" / "m17" / "h4_comiset_eval.json")
    parser.add_argument("--scan", type=int, default=400_000,
                        help="Lines of the slice to scan for source-side look-ups.")
    args = parser.parse_args()

    started = time.time()
    telemetry = load_canonical(args.canonical)
    print(f"canonical: process={len(telemetry.processes):,} network={len(telemetry.network):,} "
          f"logon={len(telemetry.logons):,}", flush=True)

    detection = detection_report(telemetry)
    print(f"detection: {detection['total_findings']} finding(s)", flush=True)
    network = network_report(telemetry, args.slice_dir, args.scan)
    print("network: done", flush=True)
    joins = join_report(telemetry, args.slice_dir, args.scan)
    print("joins: done", flush=True)
    findings = run_hunt(telemetry).findings
    provenance = provenance_report(telemetry, args.slice_dir, findings, args.scan)
    print("provenance: done", flush=True)

    payload = {
        "detection": detection,
        "network": network,
        "cross_channel_joins": joins,
        "provenance": provenance,
        "seconds": round(time.time() - started, 1),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
