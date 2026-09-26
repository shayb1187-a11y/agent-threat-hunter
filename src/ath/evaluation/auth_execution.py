"""Frozen, resumable authentication-to-execution evaluation, separate from M19/D1.

Generated data is a mechanism-level pilot, not an external-corpus validation. Labels
are read here, after investigation; neither tools nor prompts receive a Scenario.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import random
import statistics
import sys
import traceback
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from ath.agent.claims import ClaimVerifier
from ath.agent.evidence import AssertionKind, EvidenceAssertion
from ath.agent.llm import ScriptedLLM
from ath.agent.ollama_llm import OllamaLLM
from ath.agent.operational import (
    AncestryGuardProfile,
    ContextProfile,
    ControlPlaneProfile,
    EvidenceProfile,
    ReferenceProfile,
    StableContextProfile,
    investigate_operational,
)
from ath.agent.references import REFERENCE_SCHEMA, STABLE_SCHEMA
from ath.agent.state import shown_ids
from ath.agent.structured import EVIDENCE_RESPONSE_SCHEMA
from ath.correlation import correlate
from ath.environment import build_environment_model
from ath.evaluation.ablation.local import (
    available_ram_bytes,
    check_ram,
    ram_floor_for,
    refuse_frozen_path,
)
from ath.evaluation.ablation.manifest import telemetry_digest
from ath.experiments.identity import sha256_json
from ath.hunting import run_hunt
from ath.reporting import build_report, render_markdown
from ath.reporting.html import render_html
from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS, TABLE_COLUMNS
from ath.telemetry.loader import Telemetry
from ath.telemetry.normalize import coerce_and_validate
from ath.triage import Disposition, assess_findings

ROOT = Path(__file__).resolve().parents[3]
VERSION = "auth-execution-pilot-v1"
PROTOCOL = {
    "question": "Can bounded D1 recover unflagged follow-up evidence and discriminate remote administration from suspicious credential export?",
    "data": "Fully synthetic, canonically normalized Windows-shaped telemetry with routine background activity.",
    "splits": "Three development scenarios; six held-out scenarios using different follow-up commands and independent seeds. Shared mechanism family; not independent external data.",
    "baseline": "Existing deterministic operational-v2 specialists. Incident disposition: malicious if any existing triage assessment is likely_malicious; benign only if all are likely_benign; otherwise abstain. Incomplete execution always abstains.",
    "d1": "Same detections, cases, telemetry, tools, profile and evidence verifier; D1 chooses bounded probes and supplies its explicit disposition.",
    "metrics": "Decision accuracy (incomplete rows cannot be correct), benign false accusations, malicious false clearances, missing-data abstention, useful new evidence retrieved/cited, typed link recovery, rejected premises, unverified prose count, latency, reported tokens and local API charges.",
    "decision_rule": "A promising pilot requires paired decision-accuracy improvement AND more useful-evidence recovery, with zero false benign decisions on malicious cases, zero accepted invalid typed predicates, no additional benign false accusations, and all expected rows complete. Otherwise report value not demonstrated. Even a passing pilot is not statistically conclusive.",
    "holdout": "Freeze code, data, configuration, model identity and this protocol before model calls. No tuning on held-out results. Failures and abstentions remain in denominators. Repeats are not independent incidents.",
    "limits": "Simulator intent is known; telemetry may not establish intent. The unknown cases deliberately omit the discriminating child process. Free-text semantic correctness and analyst time savings require human review and are not scored as zero errors.",
}


@dataclass(frozen=True)
class Scenario:
    key: str
    telemetry: Telemetry
    expected_decision: str
    useful_ids: tuple[str, ...]
    link: EvidenceAssertion | None


def scenarios(split: str) -> list[Scenario]:
    if split not in ("dev", "heldout"):
        raise ValueError("split must be dev or heldout")
    commands = (
        (("reg.exe", r"reg.exe save HKLM\SAM C:\ProgramData\sam.hiv /y"),
         ("dism.exe", r"dism.exe /Online /Cleanup-Image /ScanHealth"))
        if split == "dev" else
        (("reg.exe", r"reg.exe save HKLM\SECURITY C:\ProgramData\security.hiv /y"),
         ("sfc.exe", r"sfc.exe /verifyonly"),
         ("esentutl.exe", r"esentutl.exe /y C:\Windows\NTDS\ntds.dit /d C:\ProgramData\cache.db /o"),
         ("dism.exe", r"dism.exe /Online /Get-Packages /Format:Table"))
    )
    outcomes = ("malicious", "benign", "abstain") * (1 if split == "dev" else 2)
    result = []
    for ordinal, outcome in enumerate(outcomes):
        seed = (7001 if split == "dev" else 93017) + ordinal * 137
        rng = random.Random(seed)
        target, source, user = f"WS-{rng.randrange(1000, 9999)}", f"WS-{rng.randrange(1000, 9999)}", f"acct-{rng.randrange(1000, 9999)}"
        start = datetime(2026, 8, 1 if split == "dev" else 9, 8, tzinfo=timezone.utc)
        rows = {kind: [] for kind in (EVENT_PROCESS, EVENT_NETWORK, EVENT_LOGON, EVENT_CONTROL)}
        counter = 0

        def event(kind, seconds, *, seed=seed, start=start, target=target, user=user, rows=rows, **fields):
            nonlocal counter
            counter += 1
            event_id = hashlib.sha256(f"{seed}:{counter}".encode()).hexdigest()[:20]
            row = {"event_id": event_id, "timestamp": start + timedelta(seconds=seconds),
                   "event_type": kind, "device": target, "user": user,
                   "source": "generated_auth_execution", "source_ref": "generated:" + event_id,
                   **fields}
            rows[kind].append(row)
            return row

        # Routine activity lives on a third host, with the same volume in each class.
        for i in range(12):
            event(EVENT_PROCESS, i * 31, device="OFFICE-01", process_name="notepad.exe",
                  process_id=2000 + i, parent_process_id=1500, parent_process_name="explorer.exe",
                  command_line=r"notepad.exe C:\Users\staff\notes.txt", signature_status="signed_valid",
                  signer="Microsoft Corporation")
            event(EVENT_LOGON, i * 29, device="OFFICE-01", action="success", logon_type=2,
                  source_device="OFFICE-01", source_ip="10.10.1.5")
        service = event(EVENT_PROCESS, 0, process_name="services.exe", process_id=400,
                        parent_process_id=300, parent_process_name="wininit.exe", command_line="services.exe",
                        process_guid=f"sysmon:{rng.getrandbits(128):032x}")
        for i in range(12):
            event(EVENT_LOGON, i * 20, action="failure", failure_reason="bad_password", logon_type=3,
                  source_device=source, source_ip="10.10.2.8")
        event(EVENT_LOGON, 300, action="success", logon_type=3, source_device=source, source_ip="10.10.2.8")
        shell = event(EVENT_PROCESS, 360, process_name="cmd.exe", process_id=500, parent_process_id=400,
                      parent_process_name="services.exe", process_guid=f"sysmon:{rng.getrandbits(128):032x}",
                      parent_process_guid=service["process_guid"],
                      command_line=r"cmd.exe /Q /c job.cmd 1> \\127.0.0.1\ADMIN$\job.log 2>&1")
        child = None
        if outcome != "abstain":
            command_index = (ordinal // 3) * 2 + (0 if outcome == "malicious" else 1)
            name, command = commands[command_index]
            child = event(EVENT_PROCESS, 365, process_name=name, process_id=501, parent_process_id=500,
                          parent_process_name="cmd.exe", process_guid=f"sysmon:{rng.getrandbits(128):032x}",
                          parent_process_guid=shell["process_guid"], command_line=command,
                          signer="Microsoft Corporation", signature_status="signed_valid")
        frames = {kind: coerce_and_validate(pd.DataFrame(values, columns=list(TABLE_COLUMNS[kind])), kind)
                  for kind, values in rows.items()}
        corpus = Telemetry(frames[EVENT_PROCESS], frames[EVENT_NETWORK], frames[EVENT_LOGON], frames[EVENT_CONTROL])
        result.append(Scenario(
            f"sample-{ordinal + 1:02d}", corpus, outcome,
            (child["event_id"],) if child else (),
            EvidenceAssertion(AssertionKind.PARENT_CHILD, shell["event_id"], child["event_id"]) if child else None,
        ))
    return result


def prepare(scenario):
    hunt = run_hunt(scenario.telemetry)
    cases = correlate(hunt.findings, scenario.telemetry)
    candidates = [case for case in cases if "ATH-007" in case.rule_ids]
    if len(candidates) != 1:
        raise ValueError("benchmark requires exactly one remote-execution incident per scenario")
    case = candidates[0]
    if set(scenario.useful_ids) & set(case.event_ids):
        raise ValueError("follow-up evidence was already flagged; this is not a discovery benchmark")
    return list(hunt.findings), case, build_environment_model(scenario.telemetry)


def source_hash():
    # as_posix: identical to str() on Linux (existing Colab freezes), and portable to Windows.
    return sha256_json({p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
                        for p in sorted((ROOT / "src" / "ath").rglob("*.py"))})


def manifest(split):
    entries = []
    for scenario in scenarios(split):
        findings, case, _ = prepare(scenario)
        entries.append({"key": scenario.key, "telemetry_sha256": telemetry_digest(scenario.telemetry, 2),
                        "expected_decision": scenario.expected_decision, "useful_ids": list(scenario.useful_ids),
                        "link": scenario.link.to_dict() if scenario.link else None,
                        "finding_ids": sorted(f.finding_id for f in findings), "case_ids": list(case.event_ids)})
    return entries


EVIDENCE_CEILING_RULE = "v2-evidence-ceiling-tie"


def profile_for(version):
    if version == "operational-v2":
        return EvidenceProfile()
    if version == "operational-v3":
        return ReferenceProfile()
    if version == "operational-v4":
        return ContextProfile()
    if version == "operational-v5":
        return StableContextProfile()
    if version == "operational-v6":
        return ControlPlaneProfile()
    if version == "operational-v7":
        return AncestryGuardProfile()
    raise ValueError("unknown operational profile")


def make_freeze(split, model_description, model_configuration, repeats=2, profile=None):
    if repeats < 1:
        raise ValueError("repeats must be positive")
    profile = profile or EvidenceProfile()
    protocol = PROTOCOL
    if isinstance(profile, ReferenceProfile):
        protocol = {**PROTOCOL,
                    "baseline": PROTOCOL["baseline"].replace("operational-v2", "operational-v3"),
                    "d1": "Operational-v3: D1 selects verified observation references; predicates and citations are bound deterministically. Both arms use the same evidence verifier and 300-second profile.",
                    "holdout": "Exploratory follow-up on previously inspected synthetic cases; not fresh held-out validation. New source/profile/model freezes; preserve all failures. No tuning within a freeze."}
    if isinstance(profile, ContextProfile):
        protocol = {**protocol,
                    "baseline": PROTOCOL["baseline"].replace("operational-v2", "operational-v4"),
                    "d1": "Operational-v4: as v3, but each checked observation also shows its recorded host, account, program, command line and signer, and the system prompt asks D1 to judge observed commands. Both arms use the same evidence verifier and 300-second profile.",
                    "decision_rule": PROTOCOL["decision_rule"].replace("AND more useful-evidence recovery", "AND more useful-evidence recovery, or equal recovery when the baseline already cites every available useful event (declared before this run because the v2/v3 splits cap recovery)"),
                    "decision_rule_version": EVIDENCE_CEILING_RULE,
                    "holdout": "Exploratory: v4 prompt and catalog were written after inspecting v3 results on all nine synthetic cases. Not fresh held-out validation; no claim of generalization. New freezes; preserve all failures. No tuning within a freeze."}
    if isinstance(profile, StableContextProfile):
        protocol = {**protocol,
                    "baseline": PROTOCOL["baseline"].replace("operational-v2", "operational-v5"),
                    "d1": "Operational-v5: as v4, but checked observations are numbered R1, R2, ... once per investigation and never renumbered; a reply citing an unknown reference gets one repair request naming the error (unknown references never bind); and the prompt judges a wrapper script by its observed children. Both arms use the same evidence verifier and 300-second profile.",
                    "holdout": "Exploratory: v5 changes were written after inspecting v3 results on all nine synthetic cases and the v4 development run. Not fresh held-out validation; no claim of generalization. New freezes; preserve all failures. No tuning within a freeze."}
    if isinstance(profile, ControlPlaneProfile):
        protocol = {**protocol,
                    "baseline": PROTOCOL["baseline"].replace("operational-v2", "operational-v6"),
                    "d1": "Operational-v6: as v5, plus control-plane evidence and probes. A recorded control-plane action is a citable checked observation; the menu adds actor_control_history, resource_control_history and identity_grants over the control table; an empty catalog is stated in the prompt. The v5 system prompt is unchanged. Both arms use the same evidence verifier and 300-second profile.",
                    "holdout": "Exploratory: v6 adds tooling after the first real-data assessment; DEDALE and the Kubernetes events it used were inspected. Development/regression only; no claim of generalization. New freezes; preserve all failures. No tuning within a freeze."}
    if isinstance(profile, AncestryGuardProfile):
        protocol = {**protocol,
                    "baseline": PROTOCOL["baseline"].replace("operational-v2", "operational-v7"),
                    "d1": "Operational-v7: as v6, plus a benign guard in code: a model benign on a case whose seed holds a process-creation record becomes abstain, with the reason recorded, unless a tool showed that process's parent during the run. The v7 system prompt drops the signed-program benign cue, says absence of evidence of harm is not evidence of benign intent, and asks for the ancestry before a benign. Both arms use the same evidence verifier and 300-second profile.",
                    "holdout": "Exploratory: v7 was written after reading the holdout-v1-windows rows, which are now seen. Development/regression only; any claim needs a fresh holdout. New freezes; preserve all failures. No tuning within a freeze."}
    body = {"version": VERSION, "protocol": protocol, "split": split, "repeats": repeats,
            "source_sha256": source_hash(), "manifest": manifest(split),
            "profile": profile.to_dict(), "profile_sha256": profile.sha256(),
            "model": model_description, "model_configuration": model_configuration,
            "runtime": {"python": platform.python_version(), "pandas": pd.__version__, "platform": platform.platform()}}
    return {**body, "freeze_sha256": sha256_json(body)}


def validate_freeze(freeze):
    body = {k: v for k, v in freeze.items() if k != "freeze_sha256"}
    if sha256_json(body) != freeze["freeze_sha256"]:
        raise ValueError("freeze contents were altered")
    if freeze["source_sha256"] != source_hash() or freeze["manifest"] != manifest(freeze["split"]):
        raise ValueError("code or telemetry changed; create a new freeze and output directory")
    profile = profile_for(freeze["profile"]["version"])
    if freeze["profile_sha256"] != profile.sha256() or freeze["profile"] != profile.to_dict():
        raise ValueError("operational profile changed")
    if (freeze["runtime"]["python"] != platform.python_version()
            or freeze["runtime"]["pandas"] != pd.__version__):
        raise ValueError("Python or pandas version differs from the freeze")


def deterministic_disposition(case, environment):
    assessments = list(assess_findings(list(case.findings), environment).values())
    if any(a.disposition is Disposition.LIKELY_MALICIOUS for a in assessments):
        return "malicious"
    if assessments and all(a.disposition is Disposition.LIKELY_BENIGN for a in assessments):
        return "benign"
    return "abstain"


def _model_name(client):
    """The answering model's name for the report, or None when the client does not say."""
    return getattr(client, "model", None) or None


def evaluate_case(scenario, arm, client=None, *, scripted=False, profile=None, prepared=None):
    if arm not in ("deterministic", "d1") or (arm == "d1" and client is None):
        raise ValueError("d1 requires a client; arm must be deterministic or d1")
    if isinstance(client, ScriptedLLM) and not scripted:
        raise ValueError("scripted clients must be explicitly labelled; they cannot produce live evidence")
    findings, case, environment = prepared if prepared is not None else prepare(scenario)
    state = investigate_operational(case, scenario.telemetry, findings,
                                    llm=client if arm == "d1" else None, profile=profile or EvidenceProfile(), environment=environment)
    audit = state.investigation["operational"]
    complete = audit["outcome"] == "complete"
    triage = deterministic_disposition(case, environment) if arm == "deterministic" else None
    decision = (triage if arm == "deterministic"
                else state.investigation.get("final_disposition", "abstain")) if complete else "abstain"
    verifier = ClaimVerifier(scenario.telemetry)
    invalid = [c for c in state.claims if c.assertions and verifier.check(c) is not None]
    assertions = {a for c in state.claims for a in c.assertions}
    surfaced = shown_ids(state)
    cited = set(state.evidence_ids)
    useful = set(scenario.useful_ids)
    scores = {
        "expected_decision": scenario.expected_decision, "decision": decision,
        "complete": complete, "correct": complete and decision == scenario.expected_decision,
        "false_malicious": scenario.expected_decision == "benign" and decision == "malicious",
        "false_benign": scenario.expected_decision == "malicious" and decision == "benign",
        "missing_data_abstained": scenario.expected_decision == "abstain" and complete and decision == "abstain",
        "useful_available": len(useful), "useful_retrieved": len(useful & surfaced),
        "useful_cited": len(useful & cited),
        "link_available": scenario.link is not None, "link_recovered": scenario.link in assertions if scenario.link else False,
        "rejected_claims": len(state.rejected_claims), "accepted_invalid_predicates": len(invalid),
        "unverified_prose": sum(c.source == "llm" for c in state.claims),
        "semantic_prose_correctness": None, "elapsed_seconds": audit["elapsed_seconds"],
        "tokens": audit["tokens_used"] if arm == "d1" else 0,
        "local_api_charge_usd": 0.0 if arm == "deterministic" or isinstance(client, OllamaLLM) else None,
        "hardware_energy_cost_usd": None,
    }
    return {"sample": scenario.key, "arm": arm, "scripted": scripted, "scores": scores, "state": state.to_dict()}, build_report(
        state, scenario.telemetry, model=_model_name(client) if arm == "d1" else None,
        triage_disposition=triage)


def write_new(path, payload):
    """Write ``payload`` to a new file, atomically; an existing file is never replaced.

    The bytes go to ``<name>.partial`` first and are renamed into place, so a session
    killed mid-write (a Colab disconnect) leaves at most a ``.partial`` leftover, never a
    truncated row that would stop the resumed run. Leftovers are not rows: ``*.json``
    does not match them, and the next attempt overwrites them.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(path)
    partial = path.with_name(path.name + ".partial")
    with partial.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    if path.exists():
        raise FileExistsError(path)
    os.replace(partial, path)


def seal_row(row):
    body = {k: v for k, v in row.items() if k != "row_sha256"}
    return {**body, "row_sha256": sha256_json(body)}


def validate_row(row, freeze):
    if row.get("row_sha256") != seal_row(row)["row_sha256"]:
        raise ValueError("row contents were altered")
    if row.get("freeze_sha256") != freeze["freeze_sha256"]:
        raise ValueError("cannot compare rows from different freezes")
    entry = next((e for e in freeze["manifest"] if e["key"] == row["sample"]), None)
    if entry is None or row["scores"]["expected_decision"] != entry["expected_decision"]:
        raise ValueError("row label does not match the frozen manifest")
    if "case_metadata" in row and row["case_metadata"] != case_metadata(entry):
        raise ValueError("row case metadata does not match the frozen manifest")


CASE_METADATA_FIELDS = ("platform", "provenance_class", "quadrant", "holdout_role", "seed_type")
DECISION_LABELS = ("malicious", "benign", "abstain")


def case_metadata(case):
    """Grouping metadata a case carries (object attribute or manifest key); absent fields omitted."""
    get = case.get if isinstance(case, dict) else (lambda name: getattr(case, name, None))
    return {name: get(name) for name in CASE_METADATA_FIELDS if get(name) is not None}


def _nearest_rank(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def _total(rows, read):
    """Sum of ``read(row)`` over rows, and how many rows could not say (``None``)."""
    values = [read(r) for r in rows]
    return sum(v for v in values if v is not None), sum(v is None for v in values)


def arm_metrics(rows, expected_labels):
    """Decision, safety, latency, tool and evidence figures for one arm's rows.

    ``expected_labels`` holds one label per row the freeze expects in this group, so the
    denominators are the frozen manifest, not the rows that happened to finish: a
    missing, blocked or errored row counts as not correct. ``recall`` counts only correct
    decisions (an abstention on a labelled case is not a recall), and balanced accuracy is
    the mean of malicious and benign recall, ``None`` when either class is absent from the
    group -- a single-class group cannot show discrimination. p90 is nearest-rank.
    """
    scores = [r["scores"] for r in rows]
    expected_by_label = {label: expected_labels.count(label) for label in DECISION_LABELS}
    correct_by_label = {label: sum(s["correct"] and s["expected_decision"] == label for s in scores)
                        for label in DECISION_LABELS}
    recall = {label: (correct_by_label[label] / expected_by_label[label] if expected_by_label[label] else None)
              for label in ("malicious", "benign")}
    latencies = [s["elapsed_seconds"] for s in scores]
    operational = [r["state"]["investigation"].get("operational", {}) for r in rows]
    tools = {name: _total(operational, lambda audit, name=name: audit.get(name))
             for name in ("tool_calls_served", "tool_calls_refused", "tool_results_truncated")}
    # Deterministic rows have no model rounds; they ran zero probes, not an unknown number.
    probes = [len(r["state"]["investigation"].get("probes_run", [])) for r in rows]
    return {
        "expected_rows": len(expected_labels), "rows": len(rows),
        "complete": sum(s["complete"] for s in scores), "correct": sum(s["correct"] for s in scores),
        "abstained": sum(s["decision"] == "abstain" for s in scores),
        "correct_abstentions": sum(s["correct"] and s["decision"] == "abstain" for s in scores),
        "unsafe_clears": sum(s["false_benign"] for s in scores),
        "false_accusations": sum(s["false_malicious"] for s in scores),
        "expected_by_label": expected_by_label, "correct_by_label": correct_by_label,
        "recall": recall,
        "balanced_accuracy": (None if None in recall.values()
                              else (recall["malicious"] + recall["benign"]) / 2),
        "latency_seconds": {"median": statistics.median(latencies) if latencies else None,
                            "p90": _nearest_rank(latencies, 0.9), "max": max(latencies, default=None)},
        "tool_usage": {**{name: total for name, (total, _) in tools.items()},
                       "unknown_rows": max(unknown for _, unknown in tools.values()),
                       "probes_run": sum(probes),
                       "probes_per_row": sum(probes) / len(probes) if probes else None},
        "evidence": {metric: sum(s[metric] for s in scores) for metric in (
            "useful_available", "useful_retrieved", "useful_cited", "link_available", "link_recovered",
            "rejected_claims", "accepted_invalid_predicates")},
    }



def _grouped_metrics(freeze, rows, arm, field):
    entries = {e["key"]: e for e in freeze["manifest"]}
    values = sorted({e[field] for e in entries.values() if e.get(field) is not None})
    return {value: arm_metrics(
        [r for r in rows if r["arm"] == arm and entries[r["sample"]].get(field) == value],
        [e["expected_decision"] for e in entries.values() if e.get(field) == value] * freeze["repeats"])
        for value in values}


def attempt_status(freeze, keys, expected, attempts):
    """Rows that never completed, split by what their latest recorded attempt says.

    ``missing_rows`` keeps its meaning (every expected row without a completed row); these
    lists say why: ``blocked_rows`` (RAM guard), ``errored_rows`` (exception), and
    ``unattempted_rows`` (no attempt on record). Stubs of rows that later completed are
    counted as ``recovered_rows``, so a flaky case stays visible after it succeeds.
    """
    latest = {}
    for stub in attempts:
        if stub.get("row_sha256") != seal_row(stub)["row_sha256"]:
            raise ValueError("attempt record was altered")
        if stub.get("freeze_sha256") != freeze["freeze_sha256"]:
            raise ValueError("cannot mix attempt records from different freezes")
        identity = row_identity(stub)
        if identity not in expected or stub["status"] not in (BLOCKED, ERRORED):
            raise ValueError("unexpected attempt record")
        if identity not in latest or stub["attempt"] > latest[identity]["attempt"]:
            latest[identity] = stub
    absent = expected - set(keys)
    return {"blocked_rows": sorted(i for i in absent if i in latest and latest[i]["status"] == BLOCKED),
            "errored_rows": sorted(i for i in absent if i in latest and latest[i]["status"] == ERRORED),
            "unattempted_rows": sorted(i for i in absent if i not in latest),
            "recovered_rows": sorted(i for i in set(keys) if i in latest),
            "attempt_records": len(attempts)}


def summarise(freeze, rows, attempts=()):
    for row in rows:
        validate_row(row, freeze)
    expected = {(entry["key"], arm, repeat) for entry in freeze["manifest"]
                for arm in ("deterministic", "d1") for repeat in range(1, freeze["repeats"] + 1)}
    keys = [(r["sample"], r["arm"], r["repeat"]) for r in rows]
    if len(keys) != len(set(keys)) or set(keys) - expected:
        raise ValueError("duplicate or unexpected comparison rows")
    labels = [e["expected_decision"] for e in freeze["manifest"]] * freeze["repeats"]
    groups = {}
    for arm in ("deterministic", "d1"):
        scores = [r["scores"] for r in rows if r["arm"] == arm]
        n = len(scores)
        groups[arm] = {
            "rows": n, "complete": sum(s["complete"] for s in scores),
            "accuracy": sum(s["correct"] for s in scores) / n if n else None,
            **{metric: sum(s[metric] for s in scores) for metric in (
                "false_malicious", "false_benign", "missing_data_abstained", "useful_retrieved",
                "useful_cited", "useful_available", "link_available", "link_recovered",
                "rejected_claims", "accepted_invalid_predicates")},
            "label_counts": {label: sum(s["expected_decision"] == label for s in scores)
                             for label in ("malicious", "benign", "abstain")},
            "median_seconds": statistics.median(s["elapsed_seconds"] for s in scores) if n else None,
            "max_seconds": max((s["elapsed_seconds"] for s in scores), default=None),
            "known_tokens": sum(s["tokens"] or 0 for s in scores),
            "unknown_usage_rows": sum(s["tokens"] is None for s in scores),
            "metrics": arm_metrics([r for r in rows if r["arm"] == arm], labels),
        }
        for field, name in (("platform", "by_platform"), ("quadrant", "by_quadrant"), ("holdout_role", "by_role"),
                            ("seed_type", "by_seed_type")):
            if any(e.get(field) is not None for e in freeze["manifest"]):
                groups[arm][name] = _grouped_metrics(freeze, rows, arm, field)
    a, d = groups["deterministic"], groups["d1"]
    full = set(keys) == expected
    scripted = any(r["scripted"] for r in rows)
    ceiling_tie = freeze.get("protocol", {}).get("decision_rule_version") == EVIDENCE_CEILING_RULE
    evidence_improved = (d["useful_cited"] > a["useful_cited"]
                         or (ceiling_tie and d["useful_cited"] == a["useful_cited"] == a["useful_available"]))
    promising = (full and not scripted and a["complete"] == a["rows"] and d["complete"] == d["rows"]
                 and d["accuracy"] > a["accuracy"] and evidence_improved
                 and d["false_benign"] == 0 and d["false_malicious"] <= a["false_malicious"]
                 and d["accepted_invalid_predicates"] == 0)
    return {"freeze_sha256": freeze["freeze_sha256"], "split": freeze["split"],
            "complete_comparison": full, "missing_rows": sorted(expected - set(keys)),
            **attempt_status(freeze, keys, expected, attempts),
            "scripted": scripted, "arms": groups,
            "conclusion": "scripted plumbing test only" if scripted else
                "promising synthetic pilot; not statistically conclusive" if promising else "investigative value not demonstrated",
            "limitations": PROTOCOL["limits"], "analyst_time_savings": None}


def process_rss_bytes():
    """Resident memory of this Python process, or ``None`` when the platform cannot say.

    Recorded beside the host's available RAM on every row, so a slow or killed row can be
    attributed to the evaluator's own growth (a leak across cases) or to the host.
    psutil when installed; otherwise ``/proc/self/status`` on Linux (Colab) and
    ``GetProcessMemoryInfo`` on Windows. Nothing here may fail a row.
    """
    try:
        import psutil  # optional; not a project dependency
        return int(psutil.Process().memory_info().rss)
    except Exception:  # noqa: BLE001 -- absent or unreadable: fall through
        pass
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            class _Counters(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                            *((name, ctypes.c_size_t) for name in (
                                "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                                "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                                "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage"))]

            counters = _Counters()
            counters.cb = ctypes.sizeof(_Counters)
            process = ctypes.windll.kernel32.GetCurrentProcess()  # type: ignore[attr-defined]
            if ctypes.windll.psapi.GetProcessMemoryInfo(process, ctypes.byref(counters), counters.cb):  # type: ignore[attr-defined]
                return int(counters.WorkingSetSize)
        except Exception:  # noqa: BLE001 -- a probe that cannot read says None
            return None
        return None
    try:
        with open("/proc/self/status", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def host_memory():
    """Evaluator RSS and host available RAM now; either figure may be ``None`` (unmeasured)."""
    return {"process_rss_bytes": process_rss_bytes(), "available_ram_bytes": available_ram_bytes()}


ATTEMPTS_DIR = "attempts"
BLOCKED, ERRORED = "blocked", "errored"
TRACEBACK_CHARS = 4000


def row_identity(row):
    return (row["sample"], row["arm"], row["repeat"])


def write_attempt(out, freeze, key, arm, repeat, status, **details):
    """Seal a stub for a row that did not complete, under ``rows/attempts/``.

    A stub is a record of an attempt, not a row: it lives outside ``rows/*.json``, so a
    resumed run still sees the row as missing and retries it, and the real row is later
    written to its own never-yet-used path (``write_new`` refuses to replace anything).
    Stubs are attempt-numbered and never overwritten, so every block and every error
    stays on disk after the row finally completes.
    """
    directory = out / "rows" / ATTEMPTS_DIR
    prefix = f"{key}_{arm}_{repeat}.attempt-"
    taken = [int(p.name[len(prefix):-len(".json")]) for p in directory.glob(prefix + "*.json")
             if p.name[len(prefix):-len(".json")].isdigit()] if directory.exists() else []
    number = max(taken, default=0) + 1
    stub = seal_row({"sample": key, "arm": arm, "repeat": repeat, "attempt": number, "status": status,
                     "freeze_sha256": freeze["freeze_sha256"],
                     "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                     "host_memory": host_memory(), **details})
    path = directory / f"{prefix}{number}.json"
    write_new(path, stub)
    return path


def read_attempts(out):
    directory = Path(out) / "rows" / ATTEMPTS_DIR
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(directory.glob("*.json"))]


def _client(model, profile=None):
    profile = profile or EvidenceProfile()
    schema = (STABLE_SCHEMA if isinstance(profile, StableContextProfile) else
              REFERENCE_SCHEMA if isinstance(profile, ReferenceProfile) else EVIDENCE_RESPONSE_SCHEMA)
    return OllamaLLM(model, format=schema, max_attempts=1, timeout_seconds=profile.time_budget_seconds)


def run_rows(out, freeze, cases, client, profile, arm_choice, evaluate):
    """Run every missing sealed row for ``cases``; existing rows are validated, never redone.

    Returns 3 when the RAM guard blocks a model row, else 0. No row is lost silently:

    * a RAM-guard block seals a ``blocked`` stub (guard figures included) under
      ``rows/attempts/`` and then returns 3, as before;
    * an exception while evaluating seals an ``errored`` stub (type, message, truncated
      traceback) and is then **re-raised**. A raise, not a return code, because an
      exception here is a harness or infrastructure fault (daemon gone, bundle broken)
      that would repeat for every remaining row; stopping loudly leaves the trace on disk
      instead of a directory of identical stubs. ``KeyboardInterrupt`` and similar are
      not recorded: an interrupted session is not a row fault.

    Neither stub is a completed row, so a resumed run retries the case. Completed rows
    record ``host_memory`` (evaluator RSS and host available RAM) after evaluation.
    """
    if arm_choice != "deterministic":
        description = client.describe()
        if (client.configuration() != freeze["model_configuration"]
                or any(description[k] != freeze["model"][k] for k in ("digest", "daemon_version"))):
            raise ValueError("model identity or configuration differs from the freeze")
    arms = ("deterministic", "d1") if arm_choice == "both" else (arm_choice,)
    for repeat in range(1, freeze["repeats"] + 1):
        for scenario in cases:
            for arm in arms:
                path = out / "rows" / f"{scenario.key}_{arm}_{repeat}.json"
                if path.exists():
                    old = json.loads(path.read_text(encoding="utf-8"))
                    validate_row(old, freeze)
                    if (old["sample"], old["arm"], old["repeat"]) != (scenario.key, arm, repeat):
                        raise ValueError("existing row identity does not match its filename")
                    continue
                guard = None
                if arm == "d1":
                    guard = check_ram(ram_floor_for(freeze["model"].get("parameter_size")),
                                      available_ram_bytes(), client.resident_bytes()).to_dict()
                    if guard["ok"] is not True:
                        # ok None (unmeasurable, or no floor) blocks too, as it always has;
                        # the stub's reason keeps the two apart.
                        reason = "RAM guard" if guard["ok"] is False else "RAM guard could not decide"
                        stub = write_attempt(out, freeze, scenario.key, arm, repeat, BLOCKED,
                                             reason=reason, ram_guard=guard)
                        print(json.dumps({"blocked": "RAM guard", "stub": stub.name, **guard}), flush=True)
                        return 3
                try:
                    row, report = evaluate(scenario, arm, client if arm == "d1" else None, profile=profile)
                except Exception as error:
                    trace = traceback.format_exc()
                    stub = write_attempt(out, freeze, scenario.key, arm, repeat, ERRORED,
                                         reason="exception during evaluation", ram_guard=guard,
                                         error={"type": type(error).__name__, "message": str(error)[:TRACEBACK_CHARS],
                                                "traceback_tail": trace[-TRACEBACK_CHARS:],
                                                "traceback_truncated": len(trace) > TRACEBACK_CHARS})
                    print(json.dumps({"errored": type(error).__name__, "stub": stub.name}), flush=True)
                    raise
                row.update({"repeat": repeat, "freeze_sha256": freeze["freeze_sha256"], "ram_guard": guard,
                            "host_memory": host_memory()})
                metadata = case_metadata(scenario)
                if metadata:
                    row["case_metadata"] = metadata
                write_new(path, seal_row(row))
                report_path = path.with_suffix(".md")
                with report_path.open("x", encoding="utf-8") as handle:
                    handle.write(render_markdown(report))
                with path.with_suffix(".html").open("x", encoding="utf-8") as handle:
                    handle.write(render_html(report))
                print(json.dumps({"sample": scenario.key, "arm": arm, "repeat": repeat, **row["scores"]}), flush=True)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("freeze", "run", "summarise"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--split", choices=("dev", "heldout"), default="dev")
    parser.add_argument("--model", default="qwen3.5:4b")
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--profile", choices=("operational-v2", "operational-v3", "operational-v4", "operational-v5", "operational-v6", "operational-v7"), default="operational-v2",
                        help="Profile for a new freeze; saved runs always use their frozen profile")
    parser.add_argument("--arm", choices=("both", "deterministic", "d1"), default="both")
    args = parser.parse_args(argv)
    refuse_frozen_path(args.out, ROOT)
    if args.command == "freeze":
        profile = profile_for(args.profile)
        client = _client(args.model, profile)
        freeze = make_freeze(args.split, client.describe(), client.configuration(), args.repeats, profile)
        write_new(args.out / "FREEZE.json", freeze)
        print(json.dumps({"freeze_sha256": freeze["freeze_sha256"], "split": args.split, "cases": len(freeze["manifest"])}), flush=True)
        return 0
    freeze = json.loads((args.out / "FREEZE.json").read_text(encoding="utf-8"))
    validate_freeze(freeze)
    if args.command == "run":
        profile = profile_for(freeze["profile"]["version"])
        client = _client(freeze["model_configuration"]["model"], profile)
        code = run_rows(args.out, freeze, scenarios(freeze["split"]), client, profile, args.arm, evaluate_case)
        if code:
            return code
    rows = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((args.out / "rows").glob("*.json"))]
    summary = summarise(freeze, rows, read_attempts(args.out))
    # Summary is derived; raw rows and the freeze are never overwritten.
    (args.out / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
