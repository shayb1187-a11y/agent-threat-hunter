"""M18-8 measurement: what the four pre-registered control-plane rules actually found.

The order this script depends on
---------------------------------
``reports/m18/cloud_detection/PREREGISTERED.md`` was committed at HEAD eb7d395, before
``src/ath/hunting/rules/cloud_behaviour_rules.py`` existed and before anything ran against
``data/external/attack_data_aws/raw``. This script runs second, measures, and changes no
threshold. If a prediction missed, the RESULTS section of that file records the miss next
to the prediction; the constant behind it does not move inside this milestone.

Why per capture, and not pooled
--------------------------------
The five attack_data_aws captures are one ATT&CK technique each, and the technique is in
the file name -- which is the only cloud ground truth this project has ever had. Pooling
them destroys it twice over: the label stops being attributable to a finding, and two
captures that share an actor merge into one episode, so a rule that fired on both reads
as having fired once. Recall is therefore computed per capture, over rows split by the
``File=`` half of ``source_ref``.

Recall is reported two ways, deliberately
------------------------------------------
``caught_any`` asks whether any rule fired on the capture at all. ``caught_with_labelled_
technique`` asks the stricter question: did the ATT&CK mapper assert the technique the
capture is *labelled with*. The gap between the two is the interesting number -- a rule
that fires for the wrong stated reason has found something and has not demonstrated what
it claims to.

flaws.cloud is a cost measurement, not a false-positive measurement
--------------------------------------------------------------------
The trail has no per-event labels and the account was deliberately vulnerable, so a
finding there is unlabelled, never "known benign". What is measured is alert volume --
findings, distinct actors, episodes, episodes per day, severity mix, triage dispositions
and case counts -- against the ceilings the pre-registration derived from the M18-7 grid.
The identity type behind each top actor is recovered with a second raw pass, using the
adapter's own readers, exactly as M18-7 did.

Usage::

    python scripts/m18_cloud_detection.py attack_data_aws
    python scripts/m18_cloud_detection.py flaws_cloud --investigate
    python scripts/m18_cloud_detection.py k8s_ci
    python scripts/m18_cloud_detection.py synthetic
    python scripts/m18_cloud_detection.py comiset
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

from ath.correlation import correlate  # noqa: E402
from ath.environment import build_environment_model  # noqa: E402
from ath.hunting import HuntConfig, run_hunt  # noqa: E402
from ath.hunting.rules.cloud_behaviour_rules import (  # noqa: E402
    denied_inclusive_rejected_identity_episodes,
)
from ath.mitre.mapper import map_finding  # noqa: E402
from ath.schema import (  # noqa: E402
    EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS,
)
from ath.telemetry.loader import Telemetry  # noqa: E402
from ath.triage import assess_findings, set_aside_ids  # noqa: E402

# The four rules M18-8 added. "Before" is the rule set without them, which is what makes
# "0 new findings" on a corpus a checkable statement rather than a recollection.
NEW_RULES: tuple[str, ...] = ("AWS-003", "AWS-004", "AWS-005", "AWS-006")

TOP_ACTORS = 5

OUT_DIR = ROOT / "reports" / "m18" / "cloud_detection"


# --------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------


def _telemetry_of(tables: dict[str, pd.DataFrame]) -> Telemetry:
    return Telemetry(
        processes=tables[EVENT_PROCESS], network=tables[EVENT_NETWORK],
        logons=tables[EVENT_LOGON], controls=tables[EVENT_CONTROL],
    )


def load_corpus(corpus: str) -> Telemetry:
    """One corpus, through the same adapters the CLI uses and no others."""
    if corpus == "attack_data_aws":
        from ath.telemetry.cloudtrail_source import CloudTrailSource
        return _telemetry_of(
            CloudTrailSource(ROOT / "data" / "external" / "attack_data_aws" / "raw")
            .load().tables
        )
    if corpus == "flaws_cloud":
        from ath.telemetry.cloudtrail_source import CloudTrailSource
        return _telemetry_of(
            CloudTrailSource(ROOT / "data" / "external" / "flaws_cloud" / "raw")
            .load().tables
        )
    if corpus == "k8s_ci":
        from ath.telemetry.k8s_audit_source import K8sAuditSource
        return _telemetry_of(
            K8sAuditSource(ROOT / "data" / "external" / "k8s_ci" / "raw", cluster="ci")
            .load().tables
        )
    if corpus == "synthetic":
        from ath.telemetry.loader import load_telemetry
        return load_telemetry(ROOT / "data" / "raw")
    if corpus == "comiset":
        directory = ROOT / "reports" / "m17" / "canonical"

        def read(name: str) -> pd.DataFrame:
            path = directory / f"comiset_{name}.parquet"
            return pd.read_parquet(path) if path.exists() else pd.DataFrame()

        return Telemetry(
            processes=read("process"), network=read("network"),
            logons=read("logon"), controls=read("control"),
        )
    raise SystemExit(f"unknown corpus {corpus!r}")


def _capture_of(source_ref: str) -> str:
    """Which capture file a canonical row came from: ``eventID=...;File=<name>``."""
    for part in str(source_ref).split(";"):
        if part.startswith("File="):
            return part[len("File="):]
    return "(unknown)"


def _technique_of(capture: str) -> str:
    """The ATT&CK technique in the capture's file name -- the label, and the only one."""
    return capture.split("__", 1)[0]


# --------------------------------------------------------------------------------------
# Finding records
# --------------------------------------------------------------------------------------


def _finding_record(finding) -> dict[str, Any]:
    metadata = finding.metadata
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "actor": str(metadata.get("actor", finding.user)),
        "user": finding.user,
        "device": finding.device,
        "evidence_count": len(finding.evidence),
        "evidence_truncated": bool(metadata.get("evidence_truncated", False)),
        "window_start": str(metadata.get("window_start", finding.first_seen)),
        "window_end": str(metadata.get("window_end", finding.last_seen)),
        "magnitude": {
            key: metadata[key] for key in (
                "call_count", "distinct_services", "distinct_resource_types",
                "denied_count", "denied_fraction", "removal_count", "rejected_count",
            ) if key in metadata
        },
        "techniques": [
            {"technique_id": m.technique_id, "confidence": m.confidence.value}
            for m in map_finding(finding)
        ],
    }


def _split_new_old(findings: list) -> tuple[list, list]:
    new = [f for f in findings if f.rule_id in NEW_RULES]
    old = [f for f in findings if f.rule_id not in NEW_RULES]
    return new, old


# --------------------------------------------------------------------------------------
# attack_data_aws: per-capture, label-aware
# --------------------------------------------------------------------------------------


def measure_attack_corpus(telemetry: Telemetry) -> dict[str, Any]:
    """One record per capture, with the capture-level label and both recall verdicts."""
    controls = telemetry.controls
    captures = sorted({
        _capture_of(ref) for ref in controls["source_ref"].astype("string").fillna("")
    }) if not controls.empty else []

    # Captures with no control rows still have to appear: T1078.004 is two ConsoleLogins
    # and produces none, and a report that silently omitted it would turn a known,
    # pre-registered miss into an absence nobody could see.
    logon_captures = sorted({
        _capture_of(ref)
        for ref in telemetry.logons["source_ref"].astype("string").fillna("")
    }) if not telemetry.logons.empty else []

    per_capture: dict[str, Any] = {}
    for capture in sorted(set(captures) | set(logon_captures)):
        rows = controls[
            controls["source_ref"].astype("string").fillna("").map(_capture_of) == capture
        ]
        logons = telemetry.logons[
            telemetry.logons["source_ref"].astype("string").fillna("").map(_capture_of)
            == capture
        ] if not telemetry.logons.empty else telemetry.logons

        slice_ = Telemetry(
            processes=telemetry.processes.iloc[0:0],
            network=telemetry.network.iloc[0:0],
            logons=logons,
            controls=rows,
        )
        hunt = run_hunt(slice_, config=HuntConfig())
        new, old = _split_new_old(hunt.findings)
        technique = _technique_of(capture)
        asserted = sorted({
            m.technique_id for finding in new for m in map_finding(finding)
        })

        per_capture[capture] = {
            "labelled_technique": technique,
            "control_rows": int(len(rows)),
            "logon_rows": int(len(logons)),
            "actors": sorted({str(a) for a in rows["actor"].astype("string").fillna("")}),
            "findings_new": [_finding_record(f) for f in new],
            "findings_pre_existing": [_finding_record(f) for f in old],
            "by_rule": dict(Counter(f.rule_id for f in new)),
            "techniques_asserted": asserted,
            "caught_any": bool(new),
            "caught_with_labelled_technique": technique in asserted,
        }

    total = len(per_capture)
    caught_any = sum(1 for r in per_capture.values() if r["caught_any"])
    caught_labelled = sum(
        1 for r in per_capture.values() if r["caught_with_labelled_technique"]
    )
    return {
        "per_capture": per_capture,
        "recall": {
            "captures": total,
            "caught_any": caught_any,
            "caught_any_recall": round(caught_any / total, 4) if total else 0.0,
            "caught_with_labelled_technique": caught_labelled,
            "labelled_technique_recall": (
                round(caught_labelled / total, 4) if total else 0.0
            ),
            "missed_any": sorted(
                c for c, r in per_capture.items() if not r["caught_any"]
            ),
            "missed_labelled": sorted(
                c for c, r in per_capture.items()
                if not r["caught_with_labelled_technique"]
            ),
        },
    }


# --------------------------------------------------------------------------------------
# flaws_cloud: volume, and what it costs downstream
# --------------------------------------------------------------------------------------


def raw_identity_types(directory: Path) -> dict[str, dict[str, int]]:
    """``userIdentity.type`` per actor, read with the adapter's own private readers.

    A second implementation of "who is the caller" here would be a second answer to that
    question; M18-7 made the same call for the same reason.
    """
    from ath.telemetry.cloudtrail_source import (  # noqa: PLC0415
        AUTH_EVENTS, _classify, _iter_payloads, _principal,
    )

    types: dict[str, Counter] = defaultdict(Counter)
    files = sorted(
        p for p in directory.iterdir() if p.is_file() and _classify(p.name) is not None
    )
    for _name, _parsed, records in _iter_payloads(files):
        for record in records:
            if not isinstance(record, dict):
                continue
            if str(record.get("eventName") or "") in AUTH_EVENTS:
                continue
            identity = record.get("userIdentity") or {}
            identity = identity if isinstance(identity, dict) else {}
            actor = _principal(identity)
            if actor:
                types[actor][str(identity.get("type") or "")] += 1
    return {actor: dict(counter) for actor, counter in types.items()}


def measure_background(
    telemetry: Telemetry, identity_types: dict[str, dict[str, int]],
) -> dict[str, Any]:
    """Volume per rule, what triage made of it, and what correlation made of that."""
    hunt = run_hunt(telemetry, config=HuntConfig())
    new, old = _split_new_old(hunt.findings)

    environment = build_environment_model(telemetry)
    assessments_before = assess_findings(old, environment)
    cases_before = correlate(old, telemetry, set_aside=set_aside_ids(assessments_before))
    assessments_after = assess_findings(hunt.findings, environment)
    cases_after = correlate(
        hunt.findings, telemetry, set_aside=set_aside_ids(assessments_after)
    )

    start, end = telemetry.time_range
    days = max((end - start).total_seconds() / 86400.0, 1.0)

    per_rule: dict[str, Any] = {}
    for rule_id in NEW_RULES:
        rule_findings = [f for f in new if f.rule_id == rule_id]
        actors = Counter(str(f.metadata.get("actor", f.user)) for f in rule_findings)
        per_rule[rule_id] = {
            "findings": len(rule_findings),
            "episodes": len(rule_findings),  # one finding per episode, by construction
            "distinct_actors": len(actors),
            "episodes_per_day": round(len(rule_findings) / days, 4),
            "severity": dict(Counter(f.severity.value for f in rule_findings)),
            "top_actors": [
                {
                    "actor": actor,
                    "episodes": count,
                    "identity_types": identity_types.get(actor, {}),
                }
                for actor, count in actors.most_common(TOP_ACTORS)
            ],
        }

    # The report-only variant: measured, never emitted as a finding.
    wider = denied_inclusive_rejected_identity_episodes(
        telemetry,
        HuntConfig().cloud_identity_failed_min_count,
        HuntConfig().cloud_identity_change_window,
    )

    return {
        "span_days": round(days, 2),
        "findings_before": len(old),
        "findings_after": len(hunt.findings),
        "by_rule_before": dict(Counter(f.rule_id for f in old)),
        "by_rule_after": dict(Counter(f.rule_id for f in hunt.findings)),
        "severity_before": dict(Counter(f.severity.value for f in old)),
        "severity_after": dict(Counter(f.severity.value for f in hunt.findings)),
        "new_rules": per_rule,
        "triage_before": dict(
            Counter(a.disposition.value for a in assessments_before.values())
        ),
        "triage_after": dict(
            Counter(a.disposition.value for a in assessments_after.values())
        ),
        "cases_before": len(cases_before),
        "cases_after": len(cases_after),
        "singleton_cases_after": sum(1 for c in cases_after if len(c.findings) == 1),
        "aws006_denied_inclusive_report_only": {
            "episodes": len(wider),
            "distinct_actors": len({e["actor"] for e in wider}),
            "top": sorted(wider, key=lambda e: -e["count"])[:TOP_ACTORS],
        },
    }


# --------------------------------------------------------------------------------------
# The corpora where the prediction is zero
# --------------------------------------------------------------------------------------


def measure_before_after(telemetry: Telemetry) -> dict[str, Any]:
    hunt = run_hunt(telemetry, config=HuntConfig())
    new, old = _split_new_old(hunt.findings)
    return {
        "rows": {
            "process": int(len(telemetry.processes)),
            "network": int(len(telemetry.network)),
            "logon": int(len(telemetry.logons)),
            "control": int(len(telemetry.controls)),
        },
        "findings_before": len(old),
        "findings_after": len(hunt.findings),
        "new_findings": len(new),
        "by_rule_before": dict(Counter(f.rule_id for f in old)),
        "new_by_rule": dict(Counter(f.rule_id for f in new)),
    }


# --------------------------------------------------------------------------------------
# The agent layer, deterministic arm
# --------------------------------------------------------------------------------------


def investigate_cases(telemetry: Telemetry, limit: int) -> dict[str, Any]:
    """Run the deterministic (NullLLM) investigation over the cases these rules produce.

    The same objects ``main.py investigate --no-llm`` builds; the CLI itself reads only
    the configured synthetic data directory, so an external corpus is driven through the
    library API rather than the command. Nothing is tuned here and no model is called:
    what is reported is how many claims of each type the deterministic planner produced,
    how many tool calls it made, and whether every FACT verified.
    """
    from ath.agent.claims import ClaimVerifier  # noqa: PLC0415
    from ath.agent.llm import NullLLM  # noqa: PLC0415
    from ath.agent.orchestrator import (  # noqa: PLC0415
        InvestigationConfig, InvestigationOrchestrator,
    )
    from ath.agent.tools import ToolBox  # noqa: PLC0415

    hunt = run_hunt(telemetry, config=HuntConfig())
    environment = build_environment_model(telemetry)
    assessments = assess_findings(hunt.findings, environment)
    cases = correlate(hunt.findings, telemetry, set_aside=set_aside_ids(assessments))
    if not cases:
        return {"cases": 0}

    tools = ToolBox(telemetry, hunt.findings, cases)
    verifier = ClaimVerifier(telemetry)
    orchestrator = InvestigationOrchestrator(
        tools, verifier, llm=NullLLM(),
        config=InvestigationConfig(use_llm_planner=False, use_llm_synthesis=False),
        environment=environment,
    )

    totals: Counter = Counter()
    example: dict[str, Any] | None = None
    for case in cases[:limit]:
        state = orchestrator.investigate(case)
        payload = state.to_dict()
        counts = payload["counts"]
        totals["cases"] += 1
        totals["facts"] += counts["facts"]
        totals["inferences"] += counts["inferences"]
        totals["hypotheses"] += counts["hypotheses"]
        # Claims the verifier REFUSED. Every claim in `state.claims` survived
        # verification by construction -- a FACT cannot be constructed without evidence
        # and cannot be accepted citing an event id that is not in the telemetry -- so
        # the number worth reporting is how many were thrown out, not how many passed.
        totals["rejected_claims"] += counts["rejected"]
        totals["tool_calls"] += counts["tool_calls"]
        totals["steps"] += payload["steps"]
        for agent in payload["agents_run"]:
            totals[f"agent_{agent}"] += 1
        if example is None:
            example = {
                "case_id": case.case_id,
                "rules": sorted({f.rule_id for f in case.findings}),
                "findings": len(case.findings),
                "agents_run": list(payload["agents_run"]),
                "counts": dict(counts),
                "tool_calls": [str(call) for call in state.tool_calls],
                "plan_log": list(payload["plan_log"]),
                "claims": [
                    {
                        "type": str(c.get("type", "")),
                        "statement": str(c.get("statement", ""))[:240],
                        "source": c.get("source"),
                        "evidence_ids": list(c.get("evidence_ids", []))[:4],
                    }
                    for c in payload["claims"]
                ],
                "rejected_claims": list(payload["rejected_claims"]),
            }
    return {"totals": dict(totals), "example_case": example}


# --------------------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("corpus", choices=(
        "attack_data_aws", "flaws_cloud", "k8s_ci", "synthetic", "comiset",
    ))
    parser.add_argument("--investigate", action="store_true",
                        help="Also run the deterministic (NullLLM) investigation over "
                             "the cases this corpus produces.")
    parser.add_argument("--investigate-limit", type=int, default=10)
    parser.add_argument("--out-dir", type=Path, default=OUT_DIR)
    args = parser.parse_args()

    started = time.perf_counter()
    telemetry = load_corpus(args.corpus)
    load_seconds = time.perf_counter() - started

    record: dict[str, Any] = {
        "corpus": args.corpus,
        "preregistered": "reports/m18/cloud_detection/PREREGISTERED.md",
        "thresholds": {
            "cloud_discovery_min_services": HuntConfig().cloud_discovery_min_services,
            "cloud_discovery_window_minutes":
                HuntConfig().cloud_discovery_window.total_seconds() / 60,
            "cloud_denial_min_count": HuntConfig().cloud_denial_min_count,
            "cloud_denial_window_minutes":
                HuntConfig().cloud_denial_window.total_seconds() / 60,
            "cloud_identity_change_window_minutes":
                HuntConfig().cloud_identity_change_window.total_seconds() / 60,
            "cloud_identity_failed_min_count":
                HuntConfig().cloud_identity_failed_min_count,
        },
    }

    measure_started = time.perf_counter()
    if args.corpus == "attack_data_aws":
        record.update(measure_attack_corpus(telemetry))
    elif args.corpus == "flaws_cloud":
        identity_types = raw_identity_types(
            ROOT / "data" / "external" / "flaws_cloud" / "raw"
        )
        record.update(measure_background(telemetry, identity_types))
    else:
        record.update(measure_before_after(telemetry))

    if args.investigate:
        record["agent_deterministic"] = investigate_cases(
            telemetry, args.investigate_limit
        )

    record["cost"] = {
        "load_seconds": round(load_seconds, 1),
        "measure_seconds": round(time.perf_counter() - measure_started, 1),
    }

    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f"{args.corpus}.json"
    out.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
    print(f"wrote {out}")
    print(json.dumps(
        {k: v for k, v in record.items() if k not in ("per_capture", "new_rules")},
        indent=2, default=str,
    )[:4000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
