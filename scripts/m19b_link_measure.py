"""M19b T-link: measure one arm of the cross-channel-link change, on every corpus.

What this script is for
------------------------
``src/ath/correlation/correlator.py`` gains a generic cross-channel link in place of the
hardcoded ``{ATH-005, ATH-006} x {ATH-007}`` allowlist that
``reports/m19b/necessity/AUDIT.md`` measured as the only structural signal able to join
two specialist domains. A change to the correlator changes which *cases exist*, so it
has to be measured on the same corpora the audit covered, before and after, with
nothing else moving.

This script measures **one arm**. It is run twice from the same file::

    # with src/ath/correlation/correlator.py unchanged
    python scripts/m19b_link_measure.py --arm before --out reports/m19b/link/before.json
    # after the correlator change
    python scripts/m19b_link_measure.py --arm after  --out reports/m19b/link/after.json

Running the identical script at two states of the tree -- rather than putting a "turn
the new link off" flag in ``CorrelationConfig`` -- is deliberate: the BEFORE arm must be
the pipeline as it actually was, not a new code path claiming to imitate it.

It loads corpora through ``scripts/m19b_necessity_audit.py``'s own loaders and reuses
``ath.evaluation.necessity.audit_case`` for per-case domain membership and step-0
eligibility, so the numbers line up with ``AUDIT.json`` row for row. It calls no model,
changes no rule, and writes only the file named by ``--out``.

``data/external`` is gitignored and lives in the primary checkout, so ``--external``
defaults to the sibling checkout's copy exactly as the audit script's does.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from m19b_necessity_audit import (  # noqa: E402
    SYNTHETIC,
    _capture_labels,
    _corpus_ground_truth,
    corpus_specs,
    row_counts,
)

from ath.correlation.correlator import correlate_with_stats  # noqa: E402
from ath.environment import build_environment_model  # noqa: E402
from ath.evaluation.necessity import (  # noqa: E402
    audit_case,
    audit_digest,
    event_id_index,
)
from ath.evaluation.suite import standard_suite  # noqa: E402
from ath.hunting import HuntConfig, run_hunt  # noqa: E402
from ath.schema import (  # noqa: E402
    EVENT_CONTROL,
    EVENT_LOGON,
    EVENT_NETWORK,
    EVENT_PROCESS,
)
from ath.telemetry.loader import Telemetry  # noqa: E402
from ath.triage import assess_findings, set_aside_ids  # noqa: E402

DEFAULT_EXTERNAL = ROOT.parent / "agentic-threat-hunter" / "data" / "external"

# Which columns of a row can name a principal. Taken from the correlator when it
# declares them (the AFTER arm), so this report cannot drift from the predicate it is
# reporting on; stated here for the BEFORE arm, whose correlator has no such notion and
# would otherwise be unable to answer "which principals do this case's rows name".
try:
    from ath.correlation.correlator import PRINCIPAL_COLUMNS  # noqa: E402
except ImportError:  # BEFORE arm
    PRINCIPAL_COLUMNS = {
        EVENT_PROCESS: ("user",),
        EVENT_NETWORK: ("user",),
        EVENT_LOGON: ("user",),
        EVENT_CONTROL: ("actor", "target_actor"),
    }


# --------------------------------------------------------------------------------------
# The pipeline: scripts/m19b_necessity_audit.py::pipeline, keeping the CorrelationStats
# because links_by_signal is how "which signal made this link" is answered.
# --------------------------------------------------------------------------------------


def pipeline(telemetry):
    hunt = run_hunt(telemetry, config=HuntConfig())
    environment = build_environment_model(telemetry)
    assessments = assess_findings(hunt.findings, environment)
    cases, stats = correlate_with_stats(
        hunt.findings, telemetry, set_aside=set_aside_ids(assessments),
    )
    return list(hunt.findings), list(cases), environment, stats


def principals_by_event(telemetry: Telemetry, wanted: set) -> dict:
    """Principals named by each wanted event id, one vectorised pass per table.

    Reporting only -- the predicate builds its own index. This exists so the BEFORE arm
    still reports the principals its cases name, which is what makes "these two cases
    name the same principal and did not link" a measurement rather than a claim.
    """
    out: dict = {}
    for event_type, columns in PRINCIPAL_COLUMNS.items():
        frame = telemetry.table(event_type)
        if frame.empty or "event_id" not in frame.columns:
            continue
        matched = frame[frame["event_id"].astype("string").isin(wanted)]
        if matched.empty:
            continue
        present = [c for c in columns if c in matched.columns]
        for record in matched[["event_id", *present]].to_dict("records"):
            names = sorted({
                str(record[c]).strip()
                for c in present
                if record[c] is not None
                and str(record[c]).strip()
                and str(record[c]).strip().lower() not in {"nan", "none"}
            })
            if names:
                out[str(record["event_id"])] = names
    return out


def case_record(case, audit, principals_of_event: dict) -> dict:
    principals = sorted({
        p for e in case.event_ids for p in principals_of_event.get(str(e), ())
    })
    signals: Counter = Counter()
    for link in case.links:
        for signal in link.signals:
            signals[signal.split("(")[0]] += 1
    start, end = case.start_time, case.end_time
    return {
        "case_id": case.case_id,
        "size": len(case.findings),
        "finding_ids": sorted(f.finding_id for f in case.findings),
        "rule_ids": sorted(case.rule_ids),
        "devices": sorted(case.devices),
        "users": sorted(case.users),
        "principals": principals,
        "event_count": len(case.event_ids),
        "start": str(start),
        "end": str(end),
        "span_seconds": (end - start).total_seconds(),
        "domains": list(audit.domains),
        "first_step_domain_specialists": audit.first_step_domain_specialists,
        "first_step_eligible": list(audit.first_step_eligible),
        "whole_run_specialists_eligible": audit.whole_run_specialists_eligible,
        "qualifies": audit.qualifies,
        "link_signals": dict(sorted(signals.items())),
    }


def summarise(name: str, provenance: str, records: Sequence) -> dict:
    sizes = Counter(r["size"] for r in records)
    return {
        "corpus": name,
        "provenance": provenance,
        "cases": len(records),
        "singletons": sum(1 for r in records if r["size"] == 1),
        "size_distribution": {str(k): v for k, v in sorted(sizes.items())},
        "max_case_size": max((r["size"] for r in records), default=0),
        "cases_with_2plus_domain_specialists_at_step0": sum(
            1 for r in records if r["first_step_domain_specialists"] >= 2
        ),
        "cases_with_2plus_domains": sum(1 for r in records if len(r["domains"]) >= 2),
        "qualifying_cases": sum(1 for r in records if r["qualifies"]),
    }


# --------------------------------------------------------------------------------------
# Chain quality on the labelled corpora
# --------------------------------------------------------------------------------------


def chain_quality(cases: Sequence, malicious: set) -> dict:
    """Primary-case recall and purity, by ``ath.evaluation.incidents.run_incident``'s
    definition: the case capturing the most of the labelled set is the primary one,
    recall is how much of the answer key it holds, purity how much of it is answer key.
    """
    if not cases or not malicious:
        return {
            "primary_case_recall": 0.0,
            "primary_case_purity": 0.0,
            "primary_case_size": 0,
        }
    primary = max(cases, key=lambda c: len(set(c.event_ids) & malicious))
    events = set(primary.event_ids)
    hit = events & malicious
    return {
        "primary_case_id": primary.case_id,
        "primary_case_size": len(primary.findings),
        "primary_case_events": len(events),
        "primary_case_recall": round(len(hit) / len(malicious), 4),
        "primary_case_purity": round(len(hit) / len(events), 4) if events else 0.0,
        "noise_cases": sum(1 for c in cases if not (set(c.event_ids) & malicious)),
    }


def capture_event_ids(telemetry: Telemetry) -> dict:
    """attack_data_aws: ingested event ids grouped by the capture file they came from.

    The capture file name carries the ATT&CK technique and each capture is one technique
    executed against a real account, so "every row of this capture" is the answer key --
    the same reading ``scripts/m19b_necessity_audit.py::_capture_labels`` takes.
    """
    out: dict = {}
    for event_type in (EVENT_PROCESS, EVENT_NETWORK, EVENT_LOGON, EVENT_CONTROL):
        frame = telemetry.table(event_type)
        if frame.empty:
            continue
        refs = frame["source_ref"].astype("string").fillna("")
        for event_id, ref in zip(frame["event_id"], refs):
            for part in str(ref).split(";"):
                if part.startswith("File="):
                    out.setdefault(part[len("File="):], set()).add(str(event_id))
    return out


# --------------------------------------------------------------------------------------
# Corpora
# --------------------------------------------------------------------------------------


def measure_corpus(spec: dict, external: Path) -> dict:
    name = spec["name"]
    path = Path(spec["path"])
    if not path.exists():
        return {
            "corpus": name,
            "provenance": spec["provenance"],
            "error": "UNAVAILABLE: {} does not exist in this checkout".format(path),
        }

    started = time.perf_counter()
    try:
        telemetry = spec["load"]()
    except Exception as exc:  # noqa: BLE001 -- a failed load is a reported result
        return {
            "corpus": name,
            "provenance": spec["provenance"],
            "error": "LOAD FAILED: {}: {}".format(type(exc).__name__, exc),
        }
    load_seconds = time.perf_counter() - started

    findings, cases, environment, stats = pipeline(telemetry)
    observable = environment.observable_channels
    ground_truth = _corpus_ground_truth(name, external)
    per_case = _capture_labels(telemetry, cases) if name == "attack_data_aws" else {}
    index = event_id_index(telemetry)
    cited = {str(e) for case in cases for e in case.event_ids}
    principals_of_event = principals_by_event(telemetry, cited)

    records = []
    for case in cases:
        audit = audit_case(
            case,
            corpus=name,
            provenance=spec["provenance"],
            telemetry=telemetry,
            findings=findings,
            cases=cases,
            environment=environment,
            corpus_channels=observable,
            ground_truth={**ground_truth, **per_case.get(case.case_id, {})},
            evidence_index=index,
        )
        records.append(case_record(case, audit, principals_of_event))

    payload = summarise(name, spec["provenance"], records)
    payload.update({
        "rows": row_counts(telemetry),
        "findings": len(findings),
        "load_seconds": round(load_seconds, 1),
        "links": stats.links,
        "links_by_signal": stats.to_dict()["links_by_signal"],
        "cases_detail": records,
    })
    if name == "attack_data_aws":
        payload["chain_quality"] = {
            capture: chain_quality(cases, ids)
            for capture, ids in sorted(capture_event_ids(telemetry).items())
        }
    return payload


def measure_synthetic() -> Iterator:
    for incident in standard_suite(
        ROOT / "data" / "raw",
        ROOT / "tests" / "fixtures" / "cloudtrail",
        ROOT / "tests" / "fixtures" / "k8s_audit",
    ):
        name = "synthetic:{}".format(incident.incident_id)
        telemetry = incident.telemetry
        findings, cases, environment, stats = pipeline(telemetry)
        cited = {str(e) for case in cases for e in case.event_ids}
        principals_of_event = principals_by_event(telemetry, cited)
        ground_truth = {"labelled": True, "incident_id": incident.incident_id}
        records = [
            case_record(
                case,
                audit_case(
                    case,
                    corpus=name,
                    provenance=SYNTHETIC,
                    telemetry=telemetry,
                    findings=findings,
                    cases=cases,
                    environment=environment,
                    corpus_channels=environment.observable_channels,
                    ground_truth=ground_truth,
                ),
                principals_of_event,
            )
            for case in cases
        ]
        payload = summarise(name, SYNTHETIC, records)
        payload.update({
            "rows": row_counts(telemetry),
            "findings": len(findings),
            "links": stats.links,
            "links_by_signal": stats.to_dict()["links_by_signal"],
            "chain_quality": {
                incident.incident_id: chain_quality(
                    cases, set(incident.malicious_event_ids),
                ),
            },
            "cases_detail": records,
        })
        yield payload


def head() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(ROOT), capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm", required=True, choices=("before", "after"))
    parser.add_argument("--external", type=Path, default=DEFAULT_EXTERNAL)
    parser.add_argument("--corpora", choices=("all", "fast", "dedale"), default="all")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    specs = corpus_specs(args.external.resolve())
    if args.corpora != "all":
        specs = [s for s in specs if s["group"] == args.corpora]

    corpora = []
    for spec in specs:
        started = time.perf_counter()
        print("[{}] {} ...".format(args.arm, spec["name"]), flush=True)
        corpus = measure_corpus(spec, args.external.resolve())
        corpora.append(corpus)
        print(
            "  {} cases, {} multi-domain, {:.1f}s{}".format(
                corpus.get("cases", 0),
                corpus.get("cases_with_2plus_domains", 0),
                time.perf_counter() - started,
                " [{}]".format(corpus["error"]) if corpus.get("error") else "",
            ),
            flush=True,
        )
    if args.corpora in ("all", "fast"):
        for corpus in measure_synthetic():
            corpora.append(corpus)
            print(
                "[{}] {} ... {} cases, {} multi-domain".format(
                    args.arm, corpus["corpus"], corpus["cases"],
                    corpus["cases_with_2plus_domains"],
                ),
                flush=True,
            )

    payload = {
        "arm": args.arm,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "head": head(),
        "corpora": corpora,
    }
    payload["digest"] = audit_digest(corpora)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    print("\nWrote {} ({})".format(args.out, payload["digest"][:12]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
