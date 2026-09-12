"""Assemble the frozen H4 result artifact from the measurement records.

Built from files rather than typed from a terminal, so every number in the artifact can
be regenerated. Run after `m17_comiset_eval.py`.
"""

from __future__ import annotations

import collections
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SYSMON = {
    "1": "process creation", "2": "file timestamp", "3": "network connection",
    "5": "process terminated", "6": "driver loaded", "7": "image loaded",
    "8": "remote thread", "9": "raw disk access", "10": "process access",
    "11": "file activity", "12": "registry", "13": "registry", "14": "registry",
    "15": "file stream", "16": "sysmon config", "17": "named pipe", "18": "named pipe",
    "22": "dns", "23": "file activity", "24": "clipboard", "25": "process tampering",
    "26": "file activity", "255": "sysmon error",
}
SECURITY = {
    "4624": "logon/authentication", "4625": "logon/authentication",
    "4634": "logon/authentication", "4648": "logon/authentication",
    "4672": "logon/authentication", "4768": "logon/authentication",
    "4769": "logon/authentication", "4776": "logon/authentication",
    "4688": "process creation", "4799": "group enumeration",
    "4907": "audit policy", "5140": "share access", "5145": "share access",
}


def category(channel: str, event_id: str) -> str:
    if channel == "sysmon":
        return SYSMON.get(event_id, f"sysmon other ({event_id})")
    if channel == "security":
        return SECURITY.get(event_id, "other windows security")
    if channel == "powershell":
        return "powershell/script"
    if channel == "application":
        return "application log"
    return "other windows event"


DEFECTS = [
    {
        "id": "M17-1", "severity": "medium",
        "summary": "ElasticWinEventSource globs *.json/*.jsonl and parses every line of "
                   "every file in the directory as an event, so sidecar metadata is read "
                   "as telemetry. Here it produced 513 spurious rejects from the slice's "
                   "own stats file; a sidecar containing valid-JSON lines with the right "
                   "keys would be silently ingested as real events.",
        "fixed_in_this_milestone": False,
    },
    {
        "id": "M17-2", "severity": "high",
        "summary": "Destination port, protocol and direction are lost on 589,476 of "
                   "589,477 network events. COMISET is mixed-schema: IP fields are "
                   "HELK-renamed (dst_ip_addr) while port/protocol/direction remain raw "
                   "Sysmon (DestinationPort/Protocol/Initiated). The adapter mapped only "
                   "the HELK names, inferred from a single sampled record that happened "
                   "to be the one record using them.",
        "consequence": "ATH-003's zero is 'required fields lost in ingestion', not "
                       "'clean data'. Network was 100% representable at event level and "
                       "approximately 0% at attribute level.",
        "fixed_in_this_milestone": False,
    },
    {
        "id": "M17-3", "severity": "medium",
        "summary": "process_guid, unique per process instance and present on both Sysmon "
                   "1 and Sysmon 3, is discarded by canonicalisation. Cross-channel joins "
                   "fall back to (device, pid), ambiguous for 86.5% of keys; the worst key "
                   "covers 27 distinct process instances.",
        "fixed_in_this_milestone": False,
    },
    {
        "id": "M17-4", "severity": "low",
        "summary": "A corrupt source timestamp (1990-12-18) passes through canonicalisation "
                   "unflagged into the network table.",
        "fixed_in_this_milestone": False,
    },
    {
        "id": "M17-5", "severity": "medium",
        "summary": "All twelve endpoint rules declare channels=frozenset(); only the cloud "
                   "and Kubernetes rules declare theirs. The visibility layer cannot "
                   "compute endpoint-rule eligibility, so 'why was this rule silent' is "
                   "not answerable from the detector itself.",
        "fixed_in_this_milestone": False,
    },
]

LIMITATIONS = [
    "Single host for process and logon telemetry; two hosts in network telemetry. Far "
    "narrower than DEDALE D02's 30 hosts, and narrower than the M16 conclusion implied.",
    "98.5% of the slice falls in three days (2022-11-16..18). The prefix is not "
    "time-diverse, and the slice was not changed after this was discovered.",
    "No usable ground truth. The corpus's technique fields are sysmon-modular RuleName "
    "annotations -- a competing heuristic's output attached at collection time -- not "
    "curated labels, so TP/FP/FN are not computable.",
    "Attribute-level network representability was not measured before the run and turns "
    "out to be near zero (M17-2). Event-level coverage flattered it.",
    "The IP-classification comparison uses the corpus's own dst_ip_public label, which is "
    "itself wrong on all five disagreements.",
]


def main() -> int:
    seen = json.loads((ROOT / "data/external/comiset/slice/comiset_seen.json").read_text(encoding="utf-8"))
    evaluation = json.loads((ROOT / "reports/m17/h4_comiset_eval.json").read_text(encoding="utf-8"))
    ingest = json.loads((ROOT / "reports/m17/comiset_ingest.json").read_text(encoding="utf-8"))

    source = collections.Counter()
    mapped = collections.Counter()
    for key, count in seen["seen_by_channel_event"].items():
        channel, _, event_id = key.partition("/")
        name = category(channel, event_id)
        source[name] += count
        mapped[name] += seen["kept_by_channel_event"].get(key, 0)

    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=ROOT,
    ).stdout.strip()

    artifact = {
        "milestone": "M17",
        "experiment": "H4",
        "status": "FROZEN",
        "freeze_note": "No ATH behaviour was modified in response to any result in this "
                       "artifact. Defects M17-1..M17-5 are recorded, not fixed.",
        "corpus": {
            "name": "COMISET Lab Environment Dataset",
            "publisher": "Universidad Pontificia Comillas",
            "record": "https://zenodo.org/records/15375146",
            "license": "CC BY 4.0",
            "archive": "Comiset23_Lab_Environment_Dataset.zip",
            "archive_bytes": 4912643312,
            "archive_member": "dataset_comillas2.json",
            "member_uncompressed_gb": 159.7,
            "schema": "Elasticsearch export, HELK/OTRF logs-endpoint-winevent-* layout, "
                      "MIXED field naming (see M17-2)",
        },
        "slice": {
            "definition": "first 20,000,000 records in file (time) order",
            "pre_declared": True,
            "declared_before_any_result_was_seen": True,
            "changed_after_seeing_results": False,
            "records_read": seen["records_read"],
            "records_kept": seen["records_kept"],
            "global_representability": round(seen["records_kept"] / 20_000_000, 4),
        },
        "observed_window": {
            "process": "2022-11-16T08:23:25Z .. 2022-11-19T20:26:11Z",
            "network": "1990-12-18T16:48:25Z (corrupt, M17-4) .. 2022-11-19T20:32:07Z",
            "logon": "2022-11-16T08:17:10Z .. 2022-11-25T22:56:31Z",
            "calendar_days_present": 10,
            "days_holding_98_5_percent_of_records": 3,
            "hosts_process_table": 1,
            "hosts_logon_table": 1,
            "hosts_network_table": 2,
            "time_diversity_verdict": "CONCENTRATED -- not time-diverse",
        },
        "channel_coverage": [
            {
                "category": name,
                "source_events": source[name],
                "mapped": mapped[name],
                "representability": round(mapped[name] / source[name], 4),
            }
            for name, _ in source.most_common()
        ],
        "ingestion": {
            "rows_read": ingest["rows_read"],
            "rejected": ingest["issues_total"],
            "rejection_cause": "All 513 rejects are lines of the sidecar "
                               "comiset_seen.json stats file, globbed as telemetry "
                               "(defect M17-1). No real event was lost.",
        },
        "detection": evaluation["detection"],
        "network": evaluation["network"],
        "cross_channel_joins": evaluation["cross_channel_joins"],
        "provenance": evaluation["provenance"],
        "defects_found": DEFECTS,
        "limitations": LIMITATIONS,
        "test_suite": {"passed": 860, "xfailed": 1,
                       "note": "state at freeze; M16-1 remains the strict xfail"},
        "code_revision": commit,
    }

    out = ROOT / "reports/m17/H4_FROZEN.json"
    out.write_text(json.dumps(artifact, indent=2, default=str), encoding="utf-8")
    print(f"wrote {out} at commit {commit[:8]}")
    print(f"channel categories: {len(artifact['channel_coverage'])}, "
          f"defects: {len(DEFECTS)}, limitations: {len(LIMITATIONS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
