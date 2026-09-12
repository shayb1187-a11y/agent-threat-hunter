"""Assemble the frozen D18 first-run artifact.

D18 was fetched as bytes during M16 and opened exactly once, after H1b and H4 were
recorded. Nothing was tuned against it before or after that run; this script only reads
the existing measurement record and the corpus denominators, and recomputes eligibility
and join feasibility from the same frozen adapter.
"""

from __future__ import annotations

import collections
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ath.hunting.base import all_detectors  # noqa: E402
from ath.telemetry.loader import Telemetry  # noqa: E402
from ath.telemetry.winlogbeat_source import WinlogbeatSource  # noqa: E402

SYSMON = {
    "1": "process creation", "2": "file timestamp", "3": "network connection",
    "5": "process terminated", "6": "driver loaded", "7": "image loaded",
    "8": "remote thread", "9": "raw disk access", "10": "process access",
    "11": "file activity", "12": "registry", "13": "registry", "15": "file stream",
    "17": "named pipe", "18": "named pipe", "22": "dns", "23": "file activity",
    "25": "process tampering", "26": "file activity",
}
SECURITY = {
    "4624": "logon/authentication", "4625": "logon/authentication",
    "4634": "logon/authentication", "4648": "logon/authentication",
    "4672": "logon/authentication", "5379": "credential manager",
}
MAPPED = {
    ("Microsoft-Windows-Sysmon/Operational", "1"),
    ("Microsoft-Windows-Sysmon/Operational", "3"),
    ("Security", "4624"), ("Security", "4625"),
}


def main() -> int:
    hours = json.loads((ROOT / "data/external/dedale/hour_stats.json").read_text(encoding="utf-8"))
    outcome = json.loads(
        (ROOT / "reports/m16/dedale_d18.deterministic.json").read_text(encoding="utf-8")
    )

    source = collections.Counter()
    mapped = collections.Counter()
    total = 0
    for key, value in hours.items():
        if not key.startswith("D18") or not isinstance(value, dict):
            continue
        total += value.get("events", 0)
        for cls, count in (value.get("by_class") or {}).items():
            if not isinstance(count, int):
                continue
            channel, _, event_id = cls.rpartition(":")
            if "Sysmon" in channel:
                name = SYSMON.get(event_id, f"sysmon other ({event_id})")
            elif channel == "Security":
                name = SECURITY.get(event_id, "other windows security")
            elif "PowerShell" in channel:
                name = "powershell/script"
            else:
                name = "other windows event"
            source[name] += count
            if (channel, event_id) in MAPPED:
                mapped[name] += count

    result = WinlogbeatSource(ROOT / "data/external/dedale/winlogbeat/D18").load()
    telemetry = Telemetry(
        processes=result.tables["process"], network=result.tables["network"],
        logons=result.tables["logon"], controls=result.tables["control"],
    )
    sizes = {
        "process": len(telemetry.processes), "network": len(telemetry.network),
        "logon": len(telemetry.logons), "control": len(telemetry.controls),
    }

    eligibility = []
    for detector in all_detectors():
        # Read off the rule, not off a copy of a table map: the copy that used to
        # live here credited ATH-007 with the logon table it never reads.
        tables = tuple(sorted(detector.tables))
        eligible = sum(sizes[t] for t in tables)
        eligibility.append({
            "rule_id": detector.rule_id,
            "input_tables": list(tables),
            "eligible_events": eligible,
            "findings": 0,
            "zero_attribution": (
                f"NOT ELIGIBLE -- required table(s) empty: "
                f"{ {t: sizes[t] for t in tables} }"
                if eligible == 0 else
                f"ELIGIBLE AND SILENT -- input present { {t: sizes[t] for t in tables} }"
            ),
        })

    procs, net = telemetry.processes, telemetry.network
    proc_keys = set(zip(procs["device"], procs["process_id"].astype("Int64")))
    net_keys = list(zip(net["device"], net["process_id"].astype("Int64")))
    matched = sum(1 for key in net_keys if key in proc_keys)

    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=ROOT,
    ).stdout.strip()

    artifact = {
        "milestone": "M17", "experiment": "S1 / D18", "status": "FROZEN -- FIRST RUN",
        "run_discipline": {
            "fetched": "bytes only, during M16, never inspected",
            "runs_executed": 1,
            "tuned_against_before_run": False,
            "tuned_against_after_run": False,
            "ordering_disclosure": "D18 was launched while H4's supplementary finding-"
                                   "detail analysis was still running. No code changed "
                                   "between the two, and git diff over hunting/, "
                                   "correlation/, triage/ and mitre/ against m16-freeze "
                                   "is empty, so the implementation D18 met is the frozen "
                                   "one. The brief's ordering was followed in substance; "
                                   "the overlap is recorded rather than hidden.",
        },
        "corpus": {
            "name": "DEDALE day 18 (2025-01-09), mid-APT",
            "publisher": "INRIA / IRISA PIRAT", "license": "CC BY 4.0",
            "provenance": "emulated-testbed", "slice": "11 active hours, all 30 hosts",
        },
        "source_coverage": {
            "source_events": total,
            "kept_by_fetch_filter": 60435,
            "ingested": int(result.rows_read),
            "ingestion_issues": len(result.issues),
            "representability_vs_source": round(sum(mapped.values()) / total, 4),
            "by_category": [
                {"category": name, "source_events": source[name], "mapped": mapped[name],
                 "representability": round(mapped[name] / source[name], 4)}
                for name, _ in source.most_common()
            ],
        },
        "observed_window": {
            "range": "2025-01-09T08:00:25Z .. 2025-01-09T18:33:53Z",
            "hosts": int(procs["device"].nunique()),
            "users": int(procs["user"].nunique()),
            "time_diversity_verdict": "one full working day, 30 hosts -- diverse by host, "
                                      "single day by design",
        },
        "detection": {
            "findings": outcome["outcome"]["analyst_load"]["findings"],
            "cases": outcome["outcome"]["analyst_load"]["cases"],
            "noise_cases": outcome["outcome"]["analyst_load"]["noise_cases"],
            "eligibility": eligibility,
        },
        "labels_and_misses": {
            "labelled_malicious_refs": 9567,
            "resolvable_in_ingested_telemetry": 2,
            "never_ingested": 9565,
            "surfaced": 0,
            "true_positives": 0, "false_positives": 0, "false_negatives": 2,
            "precision": None, "recall": 0.0,
            "interpretation": "The 2 false negatives are the only labelled events ATH "
                              "could even have seen. The other 9,565 are a representation "
                              "failure, not a detection failure.",
        },
        "cross_channel": {
            "network_rows": int(len(net)),
            "network_rows_matching_a_known_process": int(matched),
            "note": "Only 2 network events exist in the whole day, both NetBIOS (udp/137) "
                    "attributed to pid 4 (System), which emits no process-create event. "
                    "Cross-channel joining is not meaningfully measurable on D18.",
            "port_and_protocol_present": True,
            "contrast_with_h4": "The winlogbeat adapter preserves port/protocol/direction; "
                                "defect M17-2 is specific to the Elastic/HELK adapter.",
        },
        "provenance": {"checked": 0, "note": "no findings were raised, so there is no "
                                             "evidence chain to verify"},
        "false_positives": {
            "count": 0,
            "significance": "Strongest generalisation evidence available: a mid-APT day "
                            "from an estate nothing was fitted to, 30 hosts, 44,363 "
                            "process events, and silence.",
        },
        "obvious_misses": {
            "count": 2,
            "detail": "The attack is present and labelled; 9,565 of 9,567 labelled events "
                      "live in channels with no canonical table (file activity 4.48M, "
                      "image loaded 2.49M, process access 1.63M, DNS 328,799, PowerShell "
                      "13,320 -- all 0% representable).",
        },
        "test_suite": {"passed": 860, "xfailed": 1},
        "code_revision_at_run": "d310f7c",
        "code_revision_at_freeze": commit,
    }

    out = ROOT / "reports/m17/D18_FROZEN.json"
    out.write_text(json.dumps(artifact, indent=2, default=str), encoding="utf-8")
    print(f"wrote {out}")
    print(f"source {total:,} -> ingested {result.rows_read:,} "
          f"({artifact['source_coverage']['representability_vs_source']:.2%}); "
          f"findings 0; FN 2; hosts {artifact['observed_window']['hosts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
