"""Run a labelled external dataset through the incident benchmark, both arms.

Builds an :class:`ath.evaluation.incidents.Incident` from an adapter directory and an
external label file (native refs resolved through ``source_ref``), runs the deterministic
arm and -- when ``ATH_LLM_API_KEY`` is set and ``--llm`` is given -- the LLM arm, and
writes one JSON record per arm under ``reports/m14/``. The record carries the label
resolution counts next to the outcome, so recall is never read without the number of
labelled events ATH could not ingest beside it.

Usage::

    python scripts/m14_incident.py winlogbeat data/external/dedale/winlogbeat \\
        data/external/dedale/labels/dedale_class1_labels.json dedale_d15 \\
        --must-conclude scvhost.exe CLIENT2 --never-as-fact exfiltrat --llm --runs 3
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ath.agent.llm import build_llm  # noqa: E402
from ath.evaluation.external_labels import (  # noqa: E402
    incident_from_labels,
    load_external_labels,
    resolve_labels,
)
from ath.evaluation.incidents import run_incident  # noqa: E402
from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS  # noqa: E402
from ath.telemetry.loader import Telemetry  # noqa: E402


def load(kind: str, directory: Path, cluster: str) -> Telemetry:
    if kind == "winlogbeat":
        from ath.telemetry.winlogbeat_source import WinlogbeatSource
        result = WinlogbeatSource(directory).load()
    elif kind == "cloudtrail":
        from ath.telemetry.cloudtrail_source import CloudTrailSource
        result = CloudTrailSource(directory).load()
    elif kind == "k8s":
        from ath.telemetry.k8s_audit_source import K8sAuditSource
        result = K8sAuditSource(directory, cluster=cluster).load()
    else:
        raise SystemExit(f"unknown source kind {kind!r}")
    print(f"ingested: {result.summary()}", flush=True)
    return Telemetry(
        processes=result.tables[EVENT_PROCESS], network=result.tables[EVENT_NETWORK],
        logons=result.tables[EVENT_LOGON], controls=result.tables[EVENT_CONTROL],
    ), result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("kind", choices=("winlogbeat", "cloudtrail", "k8s"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("labels", type=Path)
    parser.add_argument("name", help="Names the output records.")
    parser.add_argument("--cluster", default="external")
    parser.add_argument("--incident-id", default=None)
    parser.add_argument("--description", default="")
    parser.add_argument("--expected-techniques", nargs="*", default=[])
    parser.add_argument("--must-conclude", nargs="*", default=[])
    parser.add_argument("--never-as-fact", nargs="*", default=[])
    parser.add_argument("--llm", action="store_true", help="Also run the LLM arm (needs ATH_LLM_API_KEY).")
    parser.add_argument("--runs", type=int, default=3, help="LLM-arm repetitions (it is not deterministic).")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "reports" / "m14")
    args = parser.parse_args()

    telemetry, load_result = load(args.kind, args.directory, args.cluster)
    labels = load_external_labels(args.labels)
    resolved = resolve_labels(labels, telemetry)
    print(
        f"labels: {resolved.resolved_refs}/{resolved.total_refs} refs resolved; "
        f"malicious unresolved {resolved.malicious_refs_unresolved}/{resolved.malicious_refs_total}",
        flush=True,
    )
    incident = incident_from_labels(
        resolved, telemetry,
        incident_id=args.incident_id or args.name.upper(),
        name=args.name, description=args.description,
        expected_techniques=frozenset(args.expected_techniques),
        must_conclude=tuple(args.must_conclude),
        never_as_fact=tuple(args.never_as_fact),
    )

    args.out_dir.mkdir(parents=True, exist_ok=True)
    common = {
        "dataset": labels.dataset, "provenance": labels.provenance,
        "ingestion": {
            "rows_read": load_result.rows_read, "rows_kept": load_result.rows_kept,
            "rows_dropped": load_result.rows_dropped,
            "kept_by_table": {k: int(len(v)) for k, v in load_result.tables.items()},
        },
        "labels": _compact(resolved.to_dict()),
    }

    outcome = run_incident(incident)
    record = {**common, "arm": "deterministic", "outcome": outcome.to_dict()}
    out = args.out_dir / f"{args.name}.deterministic.json"
    out.write_text(json.dumps(record, indent=2), encoding="utf-8")
    _print(outcome, resolved)
    print(f"wrote {out}")

    if args.llm:
        llm = build_llm()
        if not llm.available:
            print("LLM arm requested but no ATH_LLM_API_KEY is configured: arm NOT run, recorded as unavailable.")
            (args.out_dir / f"{args.name}.llm.json").write_text(json.dumps(
                {**common, "arm": "llm", "status": "unavailable: no ATH_LLM_API_KEY"}, indent=2,
            ), encoding="utf-8")
            return 0
        runs = []
        for _ in range(args.runs):
            o = run_incident(incident, llm=llm)
            runs.append(o.to_dict())
            _print(o, resolved)
        record = {**common, "arm": llm.name, "runs": runs,
                  "model": os.getenv("ATH_LLM_MODEL", "")}
        out = args.out_dir / f"{args.name}.llm.json"
        out.write_text(json.dumps(record, indent=2), encoding="utf-8")
        print(f"wrote {out}")
    return 0


def _compact(labels: dict, keep: int = 20) -> dict:
    """Counts stay exact; the ref lists are sampled, since 9,562 unresolved refs per
    record is a megabyte of the same fact repeated."""
    out = dict(labels)
    for key in ("unresolved", "ambiguous"):
        full = labels.get(key, {})
        out[key] = {k: v[:keep] for k, v in full.items()}
        out[f"{key}_counts"] = {k: len(v) for k, v in full.items()}
    return out


def _print(outcome, resolved) -> None:
    d = outcome.to_dict()
    print(f"[{d['configuration']}{' DEGRADED' if d['llm_degraded'] else ''}] passed={d['passed']} "
          f"detected={d['detection']['detected']} recall={d['detection']['event_recall']} "
          f"({d['detection']['malicious_events_surfaced']}/{d['detection']['malicious_events_total']} resolved; "
          f"{resolved.malicious_refs_unresolved} labelled never ingested)")
    print(f"   findings={d['analyst_load']['findings']} cases={d['analyst_load']['cases']} "
          f"noise={d['analyst_load']['noise_cases']} case_precision={d['analyst_load']['case_precision']} "
          f"chain R/P={d['chain_quality']['primary_case_recall']}/{d['chain_quality']['primary_case_purity']}")
    print(f"   triage: benign_identified={d['benign_discrimination']['benign_findings_identified']}/"
          f"{d['benign_discrimination']['benign_findings_total']} malicious_called_benign="
          f"{d['benign_discrimination']['malicious_findings_called_benign']} after_triage={d['benign_discrimination']['findings_after_triage']}")
    print(f"   conclusions hit={d['conclusions']['conclusions_hit']} missed={d['conclusions']['conclusions_missed']} "
          f"overclaimed={d['conclusions']['overclaimed_as_fact']} techniques found={d['conclusions']['techniques_found']}")
    print(f"   trust: {d['trust']}  cost: {d['cost']}  notes: {d['notes']}")


if __name__ == "__main__":
    sys.exit(main())
