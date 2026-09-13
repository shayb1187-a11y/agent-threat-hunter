"""M18b-1 measurement: what process-instance identity is carried, and what it resolves.

The question this answers
-------------------------
M17 reported that 589,359 of 589,477 COMISET network rows matched *a* process row by
``(device, process_id)`` -- 99.98% -- and, in the same artifact
(``reports/m17/H4_FROZEN.json``), that **86.5%** of those keys were ambiguous, the worst
one covering 27 distinct process instances. Those two numbers describe the same join and
only one of them is about evidence: a claim that "this process opened that connection" is
unsubstantiable whenever the key it rests on names more than one process.

So this script reports four things per corpus, separately, because pooling any two of
them reproduces exactly the confusion above:

1. **Population** -- how often each identity column carries a value, per source and per
   scheme. An empty identity is a measured gap, not a defect in the measurement.
2. **The pid join** -- what ``(device, process_id)`` matches, which is the number that
   looks good.
3. **Ambiguity** -- how many of those keys name more than one instance, and the worst
   one. This is the number that says what the first one is worth. Ambiguity is reported
   twice: over every key in the process table, and over only the keys network rows
   actually use -- the second is the M17 framing and the one comparable to 86.5%.
4. **The guid join** -- what the instance identity matches, and, for every row the pid
   join reached and the guid join did not, why.

Point 4 is expected to be *lower* than point 2 on real data, and that is a result rather
than a failure. A network row whose process started before the capture window has no
process row to match by any key; the pid join "succeeds" there by finding some other
process that happens to hold the number.

Usage::

    python scripts/m18b_process_identity.py synthetic
    python scripts/m18b_process_identity.py comiset [--max-lines N]
    python scripts/m18b_process_identity.py dedale_d02
    python scripts/m18b_process_identity.py defender_fixture
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ath.instance_identity import scheme_of  # noqa: E402
from ath.schema import EVENT_NETWORK, EVENT_PROCESS  # noqa: E402
from ath.telemetry.loader import Telemetry, load_telemetry  # noqa: E402

OUT_DIR = ROOT / "reports" / "m18b" / "process_identity"
CANONICAL_DIR = ROOT / "reports" / "m18b" / "canonical"

# The M17 numbers this milestone exists to sit next to. Quoted from the frozen artifact,
# with the path, so a reader can check them rather than trust them.
H4_FROZEN = {
    "artifact": "reports/m17/H4_FROZEN.json",
    "network_rows": 589477,
    "pid_matched_rows": 589359,
    "pid_match_rate": 0.9998,
    "ambiguous_key_rate": 0.865,
    "worst_key_instances": 27,
    "note": (
        "computed by scripts/m17_comiset_eval.py join_report from the RAW slice's "
        "process_guid/process_id/host_name fields, because ingestion discarded "
        "process_guid at the time (defect M17-3). The numbers below are computed from "
        "the canonical tables, which now carry it."
    ),
}


# --------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------


def load_corpus(corpus: str, max_lines: int | None) -> tuple[Telemetry, dict[str, Any]]:
    """One corpus, through the same adapters the CLI uses and no others."""
    started = time.time()
    if corpus == "synthetic":
        telemetry = load_telemetry(ROOT / "data" / "raw")
        detail: dict[str, Any] = {"path": "data/raw", "adapter": "canonical CSV"}
    elif corpus == "comiset":
        from ath.telemetry.elastic_winevent_source import ElasticWinEventSource

        directory = ROOT / "data" / "external" / "comiset" / "slice"
        result = ElasticWinEventSource(directory).load()
        telemetry = _telemetry_of(result)
        detail = {
            "path": "data/external/comiset/slice", "adapter": "ElasticWinEventSource",
            "rows_read": result.rows_read,
            "unmapped_classes": len(result.unmapped),
            "unmapped_rows": sum(result.unmapped.values()),
            "issues": len(result.issues),
        }
        _write_canonical(telemetry, "comiset")
    elif corpus == "dedale_d02":
        from ath.telemetry.winlogbeat_source import WinlogbeatSource

        directory = ROOT / "data" / "external" / "dedale" / "winlogbeat" / "D02"
        result = WinlogbeatSource(directory).load()
        telemetry = _telemetry_of(result)
        detail = {
            "path": "data/external/dedale/winlogbeat/D02", "adapter": "WinlogbeatSource",
            "rows_read": result.rows_read,
            "unmapped": dict(sorted(result.unmapped.items(), key=lambda kv: -kv[1])),
            "issues": len(result.issues),
        }
    elif corpus == "defender_fixture":
        from ath.telemetry.defender_source import DefenderExportSource

        directory = ROOT / "tests" / "fixtures" / "defender_export"
        result = DefenderExportSource(directory=directory).load()
        telemetry = _telemetry_of(result)
        detail = {
            "path": "tests/fixtures/defender_export", "adapter": "DefenderExportSource",
            "rows_read": result.rows_read,
        }
    else:
        raise SystemExit(f"unknown corpus {corpus!r}")
    detail["load_seconds"] = round(time.time() - started, 1)
    if max_lines is not None:
        detail["max_lines_requested"] = max_lines
    return telemetry, detail


def _telemetry_of(result) -> Telemetry:
    """A Telemetry from a load result, tolerating adapters that emit fewer tables.

    The Defender export has no control plane and does not emit that table at all, which
    is a legitimate shape -- an adapter says what it saw. The missing table becomes the
    empty, schema-valid frame ``Telemetry`` already defaults to.
    """
    from ath.schema import EVENT_CONTROL, EVENT_LOGON
    from ath.telemetry.loader import _empty_table

    def table(event_type: str) -> pd.DataFrame:
        frame = result.tables.get(event_type)
        return _empty_table(event_type) if frame is None else frame

    return Telemetry(
        processes=table(EVENT_PROCESS), network=table(EVENT_NETWORK),
        logons=table(EVENT_LOGON), controls=table(EVENT_CONTROL),
    )


def _write_canonical(telemetry: Telemetry, prefix: str) -> None:
    """Freeze the re-ingested tables so the numbers below can be recomputed.

    A new directory (``reports/m18b/canonical``), never ``reports/m17/canonical``: the
    M17 freeze is what these numbers are compared *against*, and overwriting it would
    destroy the comparison.
    """
    CANONICAL_DIR.mkdir(parents=True, exist_ok=True)
    for name, frame in (
        ("process", telemetry.processes), ("network", telemetry.network),
        ("logon", telemetry.logons), ("control", telemetry.controls),
    ):
        frame.to_parquet(CANONICAL_DIR / f"{prefix}_{name}.parquet", index=False)
    print(f"wrote canonical tables -> {CANONICAL_DIR}")


# --------------------------------------------------------------------------------------
# Population
# --------------------------------------------------------------------------------------


def population(frame: pd.DataFrame, column: str) -> dict[str, Any]:
    """How often ``column`` carries a value, split by source and by identity scheme."""
    total = len(frame)
    if total == 0 or column not in frame.columns:
        return {"total_rows": total, "populated": 0, "fraction": 0.0,
                "by_scheme": {}, "by_source": {}}
    values = frame[column].astype("string").fillna("")
    populated = int((values != "").sum())
    schemes = Counter(scheme_of(v) for v in values if v)
    by_source: dict[str, Any] = {}
    for source, group in frame.groupby(frame["source"].astype("string").fillna("")):
        group_values = group[column].astype("string").fillna("")
        filled = int((group_values != "").sum())
        by_source[str(source)] = {
            "rows": len(group), "populated": filled,
            "fraction": round(filled / len(group), 6) if len(group) else 0.0,
            "by_scheme": dict(Counter(scheme_of(v) for v in group_values if v)),
        }
    return {
        "total_rows": total, "populated": populated,
        "fraction": round(populated / total, 6),
        "by_scheme": dict(schemes), "by_source": by_source,
    }


# --------------------------------------------------------------------------------------
# The join study
# --------------------------------------------------------------------------------------


def _pid_key(frame: pd.DataFrame) -> pd.Series:
    device = frame["device"].astype("string").fillna("").str.lower()
    pid = frame["process_id"].astype("string").fillna("")
    return device + "|" + pid


def join_study(processes: pd.DataFrame, network: pd.DataFrame) -> dict[str, Any]:
    """Everything about how a network row reaches the process that opened it."""
    report: dict[str, Any] = {
        "process_rows": len(processes), "network_rows": len(network),
    }
    if processes.empty or network.empty:
        report["note"] = "one of the two tables is empty; no join is measurable"
        return report

    process_pid = _pid_key(processes)
    network_pid = _pid_key(network)
    process_guid = processes["process_guid"].astype("string").fillna("")
    network_guid = network["process_guid"].astype("string").fillna("")

    # -- what each key matches ---------------------------------------------------------
    pid_index = set(process_pid[processes["process_id"].notna()])
    guid_index = set(process_guid[process_guid != ""])
    pid_matched = network_pid.isin(pid_index) & network["process_id"].notna()
    guid_matched = (network_guid != "") & network_guid.isin(guid_index)

    report["pid_join"] = {
        "matched": int(pid_matched.sum()),
        "rate": round(float(pid_matched.mean()), 6),
    }
    report["guid_join"] = {
        "carries_identity": int((network_guid != "").sum()),
        "matched": int(guid_matched.sum()),
        "rate": round(float(guid_matched.mean()), 6),
        "rate_of_rows_carrying_identity": (
            round(float(guid_matched.sum() / max((network_guid != "").sum(), 1)), 6)
        ),
    }

    # -- ambiguity of (device, pid) ----------------------------------------------------
    # Distinct instances per key. Where the process rows carry an identity the count is
    # over identities; where they do not, every row is its own instance, which is the
    # most generous reading available and still the honest one.
    instances: dict[str, set[str]] = defaultdict(set)
    for key, guid, event_id in zip(process_pid, process_guid, processes["event_id"]):
        instances[key].add(guid if guid else f"<row {event_id}>")

    used_keys = set(network_pid[pid_matched])
    report["device_pid_ambiguity"] = {
        "all_process_keys": _ambiguity(instances, set(instances)),
        "keys_used_by_network_rows": _ambiguity(instances, used_keys),
    }

    # -- ambiguity of process_guid (expected: none, verified, not assumed) -------------
    guid_slots: dict[str, set[str]] = defaultdict(set)
    for guid, key in zip(process_guid, process_pid):
        if guid:
            guid_slots[guid].add(key)
    report["process_guid_ambiguity"] = _ambiguity(guid_slots, set(guid_slots), unit="(device, pid) slots")
    report["process_guid_repeated_rows"] = {
        "distinct_identities": len(guid_index),
        "rows_carrying_an_identity": int((process_guid != "").sum()),
        "identities_on_more_than_one_row": int(
            (process_guid[process_guid != ""].value_counts() > 1).sum()
        ),
    }

    # -- the rows the two joins disagree about -----------------------------------------
    disagree = pid_matched & ~guid_matched
    examples = []
    for _, row in network[disagree].head(3).iterrows():
        guid = str(row["process_guid"] or "")
        candidates = processes[process_pid.values == _pid_key(pd.DataFrame([row])).iloc[0]]
        examples.append({
            "event_id": str(row["event_id"]),
            "device": str(row["device"]),
            "process_name": str(row["process_name"]),
            "process_id": None if pd.isna(row["process_id"]) else int(row["process_id"]),
            "process_guid": guid,
            "timestamp": str(row["timestamp"]),
            "source_ref": str(row["source_ref"])[:160],
            "pid_candidates": int(len(candidates)),
            "distinct_instances_behind_that_pid": int(
                len(instances[_pid_key(pd.DataFrame([row])).iloc[0]])
            ),
            "reason": (
                "the network row carries no instance identity, so only the ambiguous "
                "pid key is available"
                if not guid else
                "the identity is present and no process row carries it: the process "
                "started before the capture window, so the pid match is a different "
                "instance holding the same number"
            ),
        })
    report["matched_by_pid_not_by_guid"] = {
        "count": int(disagree.sum()),
        "rate": round(float(disagree.mean()), 6),
        "examples": examples,
    }
    report["matched_by_guid_not_by_pid"] = int((guid_matched & ~pid_matched).sum())
    return report


def _ambiguity(
    mapping: dict[str, set[str]], keys: set[str], unit: str = "instances",
) -> dict[str, Any]:
    """How many of ``keys`` name more than one thing, and the worst offender."""
    sizes = {key: len(mapping.get(key, ())) for key in keys}
    if not sizes:
        return {"keys": 0, "ambiguous": 0, "rate": 0.0, "worst_key": None,
                "worst_count": 0, "unit": unit}
    ambiguous = sum(1 for size in sizes.values() if size > 1)
    worst_key = max(sizes, key=lambda k: sizes[k])
    return {
        "keys": len(sizes), "ambiguous": ambiguous,
        "rate": round(ambiguous / len(sizes), 6),
        "worst_key": worst_key, "worst_count": sizes[worst_key], "unit": unit,
    }


# --------------------------------------------------------------------------------------
# Assembly and output
# --------------------------------------------------------------------------------------


def measure(corpus: str, telemetry: Telemetry, detail: dict[str, Any]) -> dict[str, Any]:
    return {
        "corpus": corpus,
        "source": detail,
        "h4_frozen_before": H4_FROZEN,
        "population": {
            "process.process_guid": population(telemetry.processes, "process_guid"),
            "process.parent_process_guid": population(
                telemetry.processes, "parent_process_guid",
            ),
            "network.process_guid": population(telemetry.network, "process_guid"),
        },
        "join": join_study(telemetry.processes, telemetry.network),
    }


def print_report(record: dict[str, Any]) -> None:
    print(f"\n=== {record['corpus']} ({record['source'].get('adapter')}) ===")
    print(f"{'column':<32} {'rows':>9} {'populated':>10} {'fraction':>9}  schemes")
    for name, pop in record["population"].items():
        print(
            f"{name:<32} {pop['total_rows']:>9,} {pop['populated']:>10,} "
            f"{pop['fraction']:>9.4f}  {pop['by_scheme']}"
        )
    join = record["join"]
    if "pid_join" not in join:
        print(join.get("note", ""))
        return
    print(
        f"\npid join   {join['pid_join']['matched']:>9,} / {join['network_rows']:,}"
        f"  ({join['pid_join']['rate']:.4f})"
    )
    print(
        f"guid join  {join['guid_join']['matched']:>9,} / {join['network_rows']:,}"
        f"  ({join['guid_join']['rate']:.4f}); "
        f"{join['guid_join']['carries_identity']:,} rows carry an identity"
    )
    for label, block in join["device_pid_ambiguity"].items():
        print(
            f"(device,pid) ambiguity [{label}]: {block['ambiguous']:,}/{block['keys']:,} "
            f"= {block['rate']:.4f}; worst {block['worst_key']} -> "
            f"{block['worst_count']} instances"
        )
    guid_amb = join["process_guid_ambiguity"]
    print(
        f"process_guid ambiguity: {guid_amb['ambiguous']:,}/{guid_amb['keys']:,} "
        f"= {guid_amb['rate']:.4f}; worst {guid_amb['worst_key']} -> "
        f"{guid_amb['worst_count']} {guid_amb['unit']}"
    )
    print(
        f"matched by pid, not by guid: "
        f"{join['matched_by_pid_not_by_guid']['count']:,} "
        f"({join['matched_by_pid_not_by_guid']['rate']:.4f})"
    )
    print(
        f"BEFORE (H4_FROZEN, raw slice): pid match "
        f"{H4_FROZEN['pid_match_rate']:.4f}, ambiguous keys "
        f"{H4_FROZEN['ambiguous_key_rate']:.3f}, worst key "
        f"{H4_FROZEN['worst_key_instances']} instances"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("corpus", choices=(
        "synthetic", "comiset", "dedale_d02", "defender_fixture",
    ))
    parser.add_argument("--max-lines", type=int, default=None,
                        help="Recorded in the artifact; the adapters read whole files.")
    parser.add_argument("--out-dir", type=Path, default=OUT_DIR)
    args = parser.parse_args()

    telemetry, detail = load_corpus(args.corpus, args.max_lines)
    record = measure(args.corpus, telemetry, detail)
    print_report(record)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f"{args.corpus}.json"
    out.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
