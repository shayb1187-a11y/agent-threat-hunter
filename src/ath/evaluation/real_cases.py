"""Frozen evaluation of an operational profile on real, externally labelled telemetry.

The auth-execution pilot scores investigations on generated scenarios whose intent the
generator defines. This module scores the same two arms -- deterministic specialists and
bounded D1 -- on cases cut from telemetry this project did not generate, with labels
set by whoever ran or recorded the activity.

Two steps, deliberately separate:

``build`` (local, needs the raw exports)
    Reads a case spec, loads each real export through its adapter, cuts the case's time
    window and hosts, writes the slice as canonical CSV, **reloads it**, resolves the
    spec's native label refs against the reloaded slice, and finds the one correlated
    incident the anchor refs fall in. Everything downstream is computed from the
    reloaded slice, so evaluation sees exactly what was built (the canonical writer
    keeps whole seconds). The bundle is small, hashed, and never overwritten.

``freeze`` / ``run`` / ``summarise`` (local or Colab, needs only the bundle)
    The same freeze, sealed rows, RAM guard and summary as the auth-execution pilot,
    with the bundle digest and every case's identity in the freeze.

A case whose anchors fall in no correlated incident is **undetected**; one whose anchors
span several is **ambiguous**; one whose anchor refs resolve to nothing has
**unresolved labels**. None can be investigated, all are kept in the freeze and reported
beside the comparison, so a detection miss is never silently dropped from the table.

Seed modes (spec-level ``seed_mode``; one mode per bundle, never mixed)
------------------------------------------------------------------------
``detection`` (default) is end-to-end ATH: a case exists only if ATH's own detection
and correlation raised the incident.

``analyst`` is **analyst-seeded investigation, not end-to-end ATH**. Each case starts
from one neutral alert built from the resolved anchor events, as if an analyst had
handed them over for review. ATH detection still runs, and its status is recorded per
case, but it does not decide which cases exist.

**Seed invariant.** An analyst seed is exactly one initial suspicious record. Every
later labelled record of the incident belongs in ``useful_refs``, hidden behind
investigation and scored as follow-up evidence. Seeding with several labelled records
hands the investigator the answer and measures recognition, not investigation; the
spec validator and the builder both refuse it. This measures investigation quality on
real incidents separately from detection coverage. The seed carries no label, note or
expected decision: its title, reason and evidence summaries use the same wording for
every case. The anchor choice itself is the analyst's; it says where to look, not what
happened.

Spec shape (paths relative to the spec file)::

    {
      "spec_version": "real-cases-v1",
      "name": "my-real-set",
      "cases": [{
        "key": "case-01",
        "source": {"kind": "winlogbeat", "path": "../data/external/x"},
        "window": {"start": "2020-05-01T02:00:00Z", "end": "2020-05-01T03:00:00Z"},
        "devices": ["HOST-A"],                        # optional
        "expected_decision": "malicious",             # malicious | benign | abstain
        "provenance": "emulated-testbed",             # see external_labels.PROVENANCES
        "label_source": "who labelled it, and where",
        "anchor_refs": ["host.name=HOST-A;winlog.record_id=123"],
        "useful_refs": [],                            # optional follow-up evidence
        "link": {"kind": "parent_child", "refs": ["...", "..."]},   # optional
        "note": "",
        "platform": "windows",                        # optional: windows | k8s
        "provenance_class": "real",                   # optional: real | injected
        "quadrant": "windows-malicious"               # optional: grouping label
      }],
      "seed_mode": "detection",                       # or "analyst"; see above
      "protocol": "holdout-v1"                        # optional; see below
    }

Holdout protocol (spec-level ``"protocol": "holdout-v1"``)
-----------------------------------------------------------
Selects :data:`HOLDOUT_PROTOCOL`: every case must carry ``platform``,
``provenance_class`` and ``quadrant``, and ``quadrant`` must be
``f"{platform}-{expected_decision}"``. The machine-checkable rules
(:data:`HOLDOUT_RULES`) are sealed in the freeze, before any model call, and
:func:`holdout_verdict` applies the sealed copy, not the module constants. The point of
criterion 4 (every platform discriminated) is that raw accuracy cannot be bought by a
constant answer per platform when platforms and labels are correlated in the case set.

``"protocol": "holdout-v1-windows"`` (:data:`HOLDOUT_WINDOWS_PROTOCOL`) was re-declared
before any model result, after no fresh labelled Kubernetes attack data could be
obtained. It adds a required ``holdout_role`` per case. The verdict is computed over the
``primary`` cases (Windows, malicious and benign) with a gain of 3 of 12, and criterion 4
applies on Windows only. The ``secondary`` cases are benign only and are reported
separately (:func:`secondary_check`). The freeze seals :data:`K8S_NOT_EVALUATED`,
stating that Kubernetes malicious discrimination was not evaluated.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from ath.agent.evidence import AssertionKind, EvidenceAssertion, EvidenceVerifier
from ath.agent.operational import StableContextProfile
from ath.correlation import correlate
from ath.correlation.chain import InvestigationCase
from ath.environment import build_environment_model
from ath.environment.channels import channels_of_row
from ath.evaluation import auth_execution as pilot
from ath.evaluation.ablation.local import refuse_frozen_path
from ath.evaluation.ablation.manifest import telemetry_digest
from ath.evaluation.external_labels import PROVENANCES, RESOLVED, resolve_refs
from ath.experiments.identity import sha256_json
from ath.hunting import run_hunt
from ath.hunting.finding import Evidence, Finding, Severity
from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS
from ath.telemetry.loader import Telemetry, load_telemetry
from ath.telemetry.source import SourceLoadResult, write_normalized_telemetry

SPEC_VERSION = "real-cases-v1"
BUNDLE_VERSION = "real-case-bundle-v1"
VERSION = "real-cases-eval-v1"
SPLIT = "real"
SOURCE_KINDS = ("winlogbeat", "elastic-winevent", "cloudtrail", "k8s", "defender", "canonical")
DECISIONS = ("malicious", "benign", "abstain")
LINK_KINDS = {"parent_child": AssertionKind.PARENT_CHILD,
              "same_process": AssertionKind.SAME_PROCESS,
              "before": AssertionKind.BEFORE}
INVESTIGABLE, UNDETECTED, AMBIGUOUS, UNRESOLVED_LABELS = (
    "investigable", "undetected", "ambiguous", "labels_unresolved")
DETECTION, ANALYST = "detection", "analyst"
SEED_MODES = (DETECTION, ANALYST)
SEED_RULE_ID = "ANALYST-SEED"
SEED_CASE_ID = "CASE-SEED"
SEED_TITLE = "Analyst-selected activity for investigation"
SEED_REASON = ("An analyst selected these events for review. The selection says where to "
               "look; it is not a detection and carries no verdict.")
SEED_POLICY = "single-initial-record"
HOLDOUT = "holdout-v1"
HOLDOUT_WINDOWS = "holdout-v1-windows"
PROTOCOLS = (HOLDOUT, HOLDOUT_WINDOWS)
PLATFORMS = ("windows", "k8s")
PROVENANCE_CLASSES = ("real", "injected")
HOLDOUT_FIELDS = ("platform", "provenance_class", "quadrant")
"""Case metadata every holdout protocol requires; ``holdout_role`` is added by the Windows one."""
PRIMARY, SECONDARY = "primary", "secondary"
HOLDOUT_ROLES = (PRIMARY, SECONDARY)
HOLDOUT_MIN_CORRECT_GAIN = 6
"""D1 must be correct on at least this many more cases than the deterministic arm.
Declared for a 24-case holdout (a quarter of the cases); :func:`holdout_verdict` notes
when the frozen case count differs, and does not rescale."""
HOLDOUT_DESIGN_CASES = 24
HOLDOUT_WINDOWS_MIN_CORRECT_GAIN = 3
"""The Windows-only re-declaration: a quarter of the 12 primary cases, as before."""
HOLDOUT_WINDOWS_DESIGN_CASES = 12
HOLDOUT_WINDOWS_PLATFORM = "windows"
K8S_NOT_EVALUATED = (
    "Kubernetes malicious discrimination was not evaluated: no suitable fresh, labelled "
    "Kubernetes attack dataset was available, and recording malicious Kubernetes activity "
    "could not be completed. Kubernetes cases appear only as a secondary benign "
    "false-accusation check, and no claim about discriminating Kubernetes attacks is made.")
_KEY = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

PROTOCOL = {
    "question": "On real, externally labelled incidents, does bounded D1 decide better than the deterministic specialists without clearing malicious activity?",
    "data": "Slices of real or emulated-testbed telemetry loaded through ATH adapters; labels come from the dataset publisher or the person who recorded the activity, named per case.",
    "cases": "Each case is one correlated incident selected by its anchor refs. Undetected, ambiguous and unresolved cases cannot be investigated; they are listed, not dropped.",
    "baseline": "Existing deterministic specialists under the frozen profile. Malicious if any triage assessment is likely_malicious; benign only if all are likely_benign; otherwise abstain. Incomplete execution always abstains.",
    "d1": "Same detections, case, telemetry, tools, profile and evidence verifier; D1 chooses bounded probes and supplies its disposition.",
    "metrics": "Decision accuracy (incomplete rows cannot be correct), malicious cleared as benign, benign or abstain cases called malicious, correct abstentions, useful evidence retrieved/cited, link recovery, rejected claims, latency and tokens; label resolution and detection status per case.",
    "decision_rule": pilot.PROTOCOL["decision_rule"].replace(
        "AND more useful-evidence recovery",
        "AND more useful-evidence recovery, or equal recovery when the baseline already cites every available useful event"),
    "decision_rule_version": pilot.EVIDENCE_CEILING_RULE,
    "holdout": "Freeze the bundle, code, profile and model before model calls. Cases must be sealed before any prompt change. Failures, abstentions and uninvestigable cases stay in the record.",
    "limits": "Labels mark activity the publisher or recorder vouches for; telemetry may still not establish intent. Adapter coverage bounds what is visible: label resolution counts are part of every result. Free-text correctness requires human review.",
}

ANALYST_PROTOCOL = {
    **PROTOCOL,
    "evaluation": "Analyst-seeded investigation, not end-to-end ATH.",
    "question": "Given a real incident, seeded by an analyst from its labelled anchor events, and the real telemetry around it, does bounded D1 investigate it better than the deterministic pipeline without clearing malicious activity?",
    "cases": "Each case starts from one neutral analyst seed built from exactly one initial suspicious record, whether or not ATH detection raised it; later labelled records are hidden behind investigation and scored as follow-up evidence. ATH's detection status is recorded per case but does not select cases. Cases whose anchor resolves to nothing cannot be investigated and are listed.",
    "baseline": "Deterministic specialists investigate the same seeded case under the frozen profile. Disposition comes from existing triage of the seed: malicious if likely_malicious, benign if likely_benign, otherwise abstain. Incomplete execution always abstains.",
    "d1": "Same seeded case, detections, telemetry, tools, profile and evidence verifier; D1 chooses bounded probes and supplies its disposition.",
    "limits": PROTOCOL["limits"] + " Seeded results measure investigation given where to look; they say nothing about whether ATH would have raised the incident.",
}
DETECTION_PROTOCOL = {**PROTOCOL, "evaluation": "End-to-end ATH: detection selects the case."}

HOLDOUT_RULES = {
    "version": HOLDOUT,
    "repeats": 1,
    "rows_count_only_if_complete": True,
    "absent_rows_count_as_incorrect": True,
    "complete_requires_all_rows": True,
    "min_correct_gain": HOLDOUT_MIN_CORRECT_GAIN,
    "min_correct_gain_declared_for_cases": HOLDOUT_DESIGN_CASES,
    "max_d1_unsafe_clears": 1,
    "max_d1_false_accusations": 1,
    "per_platform_balanced_accuracy_above": 0.5,
    "per_platform_min_correct_malicious": 1,
    "per_platform_min_correct_benign": 1,
}
HOLDOUT_WINDOWS_RULES = {
    **HOLDOUT_RULES,
    "version": HOLDOUT_WINDOWS,
    "min_correct_gain": HOLDOUT_WINDOWS_MIN_CORRECT_GAIN,
    "min_correct_gain_declared_for_cases": HOLDOUT_WINDOWS_DESIGN_CASES,
    "primary_role": PRIMARY,
    "primary_platforms": [HOLDOUT_WINDOWS_PLATFORM],
    "secondary_counts_toward_conclusion": False,
}
HOLDOUT_PROTOCOL = {
    "holdout": "Holdout-v1: cases, labels, platform, provenance class and quadrant were sealed before any model call on them; no prompt, profile or tool change after sealing. One repeat. A row counts only if its investigation completed; missing, blocked, errored and uninvestigable rows count as incorrect. The result is complete only when every expected row is present.",
    "decision_rule": f"Investigative value is demonstrated only if ALL hold: (1) D1 correct minus deterministic correct >= {HOLDOUT_MIN_CORRECT_GAIN} (declared for {HOLDOUT_DESIGN_CASES} cases); (2) D1 unsafe clears (malicious called benign) <= 1; (3) D1 false accusations (benign called malicious) <= 1; (4) on each platform, D1 balanced accuracy (mean of malicious and benign recall, abstention not correct) > 0.5 with at least one correct malicious and one correct benign case. Otherwise not demonstrated, naming every failing criterion. A scripted or incomplete result demonstrates nothing.",
    "decision_rule_version": HOLDOUT,
    "holdout_rules": HOLDOUT_RULES,
}
HOLDOUT_WINDOWS_PROTOCOL = {
    "holdout": "Holdout-v1-windows, re-declared before any model result on these cases: the headline cases are the primary role only -- real Windows telemetry, malicious and benign. Cases, labels, platform, provenance class, quadrant and role were sealed before any model call on them; no prompt, profile or tool change after sealing. One repeat. A row counts only if its investigation completed; missing, blocked, errored and uninvestigable primary rows count as incorrect. The result is complete only when every primary row is present.",
    "decision_rule": f"Investigative value on Windows is demonstrated only if ALL hold over the primary cases: (1) D1 correct minus deterministic correct >= {HOLDOUT_WINDOWS_MIN_CORRECT_GAIN} (declared for {HOLDOUT_WINDOWS_DESIGN_CASES} cases); (2) D1 unsafe clears (malicious called benign) <= 1; (3) D1 false accusations (benign called malicious) <= 1; (4) on Windows, D1 balanced accuracy (mean of malicious and benign recall, abstention not correct) > 0.5 with at least one correct malicious and one correct benign case. Otherwise not demonstrated, naming every failing criterion. A scripted or incomplete result demonstrates nothing.",
    "secondary": "Secondary cases (Kubernetes, benign only) are a false-accusation and generalization check. They are reported per arm -- benign called malicious, called benign, abstained, incomplete -- and never enter the conclusion.",
    "not_evaluated": K8S_NOT_EVALUATED,
    "decision_rule_version": HOLDOUT_WINDOWS,
    "holdout_rules": HOLDOUT_WINDOWS_RULES,
}
_HOLDOUTS = {HOLDOUT: HOLDOUT_PROTOCOL, HOLDOUT_WINDOWS: HOLDOUT_WINDOWS_PROTOCOL}


def protocol_for(seed_mode):
    return ANALYST_PROTOCOL if seed_mode == ANALYST else DETECTION_PROTOCOL


# -- spec -------------------------------------------------------------------------------


def load_spec(path: Path) -> dict:
    """Read and validate a case spec. Fails loudly: a malformed answer key is a bug."""
    spec = json.loads(Path(path).read_text(encoding="utf-8"))
    if spec.get("spec_version") != SPEC_VERSION:
        raise ValueError(f"spec_version must be {SPEC_VERSION!r}")
    if spec.get("seed_mode", DETECTION) not in SEED_MODES:
        raise ValueError(f"seed_mode must be one of {SEED_MODES}")
    if spec.get("protocol") is not None and spec["protocol"] not in PROTOCOLS:
        raise ValueError(f"protocol must be one of {PROTOCOLS} when given")
    holdout = spec.get("protocol")
    cases = spec.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("spec needs a non-empty cases list")
    seen = set()
    for case in cases:
        key = case.get("key", "")
        if not _KEY.match(str(key)) or key in seen:
            raise ValueError(f"case key {key!r} must be unique, lowercase, [a-z0-9_-]")
        seen.add(key)
        where = f"case {key!r}"
        source = case.get("source") or {}
        if source.get("kind") not in SOURCE_KINDS or not source.get("path"):
            raise ValueError(f"{where}: source needs kind in {SOURCE_KINDS} and a path")
        if case.get("expected_decision") not in DECISIONS:
            raise ValueError(f"{where}: expected_decision must be one of {DECISIONS}")
        if case.get("provenance") not in PROVENANCES:
            raise ValueError(f"{where}: provenance must be one of {PROVENANCES}")
        if not str(case.get("label_source", "")).strip():
            raise ValueError(f"{where}: label_source must say who labelled the case")
        anchors = case.get("anchor_refs")
        if not isinstance(anchors, list) or not anchors or not all(isinstance(r, str) and r for r in anchors):
            raise ValueError(f"{where}: anchor_refs needs at least one native ref")
        if not isinstance(case.get("useful_refs", []), list):
            raise ValueError(f"{where}: useful_refs must be a list")
        if spec.get("seed_mode", DETECTION) == ANALYST:
            if len(anchors) != 1:
                raise ValueError(f"{where}: an analyst seed is exactly one initial record "
                                 f"({SEED_POLICY}); put later labelled records in useful_refs")
            if anchors[0] in case.get("useful_refs", []):
                raise ValueError(f"{where}: the seed record cannot also be follow-up evidence")
        _validate_case_metadata(case, where, holdout)
        _validate_holdout_role(case, where, holdout)
        link = case.get("link")
        if link is not None and (link.get("kind") not in LINK_KINDS or len(link.get("refs", [])) != 2):
            raise ValueError(f"{where}: link needs kind in {tuple(LINK_KINDS)} and exactly two refs")
        window = case.get("window")
        if window is not None:
            start, end = _stamp(window.get("start")), _stamp(window.get("end"))
            if start is None or end is None or start > end:
                raise ValueError(f"{where}: window needs ISO start <= end with a timezone")
    if holdout == HOLDOUT_WINDOWS:
        _validate_windows_design(cases)
    return spec


def _validate_holdout_role(case, where, holdout):
    """Under the Windows re-declaration a role says whether a case can move the verdict."""
    role = case.get("holdout_role")
    if role is not None and role not in HOLDOUT_ROLES:
        raise ValueError(f"{where}: holdout_role must be one of {HOLDOUT_ROLES}")
    if holdout != HOLDOUT_WINDOWS:
        return
    if role is None:
        raise ValueError(f"{where}: the {HOLDOUT_WINDOWS} protocol needs holdout_role on every case")
    if role == PRIMARY and (case["platform"] != HOLDOUT_WINDOWS_PLATFORM
                            or case["expected_decision"] not in ("malicious", "benign")):
        raise ValueError(f"{where}: primary cases are Windows, labelled malicious or benign")
    if role == SECONDARY and case["expected_decision"] != "benign":
        # A secondary malicious case would be a discrimination claim by the back door.
        raise ValueError(f"{where}: secondary cases are a benign false-accusation check only")


def _validate_windows_design(cases):
    primary = [c for c in cases if c.get("holdout_role") == PRIMARY]
    labels = {label: sum(c["expected_decision"] == label for c in primary) for label in ("malicious", "benign")}
    if not labels["malicious"] or not labels["benign"]:
        raise ValueError(f"the {HOLDOUT_WINDOWS} protocol needs primary cases of both labels, not {labels}")


def _validate_case_metadata(case, where, holdout):
    """Grouping metadata is optional, but checked when present and required under holdout."""
    if case.get("platform") is not None and case["platform"] not in PLATFORMS:
        raise ValueError(f"{where}: platform must be one of {PLATFORMS}")
    if case.get("provenance_class") is not None and case["provenance_class"] not in PROVENANCE_CLASSES:
        raise ValueError(f"{where}: provenance_class must be one of {PROVENANCE_CLASSES}")
    if case.get("quadrant") is not None and not (isinstance(case["quadrant"], str) and case["quadrant"].strip()):
        raise ValueError(f"{where}: quadrant must be a non-empty string")
    if not holdout:
        return
    missing = [name for name in HOLDOUT_FIELDS if case.get(name) is None]
    if missing:
        raise ValueError(f"{where}: the {holdout} protocol needs {', '.join(missing)} on every case")
    if case["quadrant"] != f"{case['platform']}-{case['expected_decision']}":
        raise ValueError(f"{where}: quadrant {case['quadrant']!r} must be "
                         f"'{case['platform']}-{case['expected_decision']}' (platform-expected_decision)")


def _stamp(value):
    try:
        stamp = pd.Timestamp(value)
    except (TypeError, ValueError):
        return None
    return None if stamp is pd.NaT or stamp.tzinfo is None else stamp.tz_convert("UTC")


# -- build ------------------------------------------------------------------------------


def load_source(kind: str, path: Path, cluster: str = "default") -> tuple[Telemetry, dict]:
    if kind == "canonical":
        telemetry = load_telemetry(path)
        return telemetry, {"kind": kind, "rows_kept": int(telemetry.event_count)}
    if kind == "winlogbeat":
        from ath.telemetry.winlogbeat_source import WinlogbeatSource as source_class
    elif kind == "elastic-winevent":
        from ath.telemetry.elastic_winevent_source import ElasticWinEventSource as source_class
    elif kind == "cloudtrail":
        from ath.telemetry.cloudtrail_source import CloudTrailSource as source_class
    elif kind == "defender":
        from ath.telemetry.defender_source import DefenderExportSource as source_class
    else:
        from ath.telemetry.k8s_audit_source import K8sAuditSource
        result = K8sAuditSource(path, cluster=cluster).load()
        return _telemetry(result.tables), _ingestion(kind, result)
    result = source_class(path).load()
    return _telemetry(result.tables), _ingestion(kind, result)


def _telemetry(tables) -> Telemetry:
    return Telemetry(processes=tables[EVENT_PROCESS], network=tables[EVENT_NETWORK],
                     logons=tables[EVENT_LOGON], controls=tables[EVENT_CONTROL])


def _ingestion(kind, result) -> dict:
    return {"kind": kind, "rows_read": int(result.rows_read),
            "rows_kept": int(sum(len(t) for t in result.tables.values())),
            "unmapped": {k: int(v) for k, v in sorted(result.unmapped.items())}}


def slice_telemetry(telemetry: Telemetry, window=None, devices=None) -> Telemetry:
    """Rows inside ``window`` (inclusive) and, when given, on ``devices``."""
    start = _stamp(window["start"]) if window else None
    end = _stamp(window["end"]) if window else None
    hosts = set(devices) if devices else None

    def cut(frame):
        keep = pd.Series(True, index=frame.index)
        if start is not None:
            stamps = pd.to_datetime(frame["timestamp"], utc=True)
            keep &= (stamps >= start) & (stamps <= end)
        if hosts is not None:
            keep &= frame["device"].astype(str).isin(hosts)
        return frame[keep].reset_index(drop=True)

    return Telemetry(processes=cut(telemetry.processes), network=cut(telemetry.network),
                     logons=cut(telemetry.logons), controls=cut(telemetry.controls))


def _write_slice(telemetry: Telemetry, out_dir: Path) -> Telemetry:
    tables = {EVENT_PROCESS: telemetry.processes, EVENT_NETWORK: telemetry.network,
              EVENT_LOGON: telemetry.logons, EVENT_CONTROL: telemetry.controls}
    write_normalized_telemetry(SourceLoadResult(tables=tables), out_dir)
    return load_telemetry(out_dir)


def _one(resolved, ref):
    item = resolved[ref]
    return item.event_id if item.status == RESOLVED else ""


def select_incident(telemetry: Telemetry, anchor_ids):
    """The single correlated incident containing an anchor, and the detection status."""
    hunt = run_hunt(telemetry)
    cases = correlate(hunt.findings, telemetry)
    if not anchor_ids:
        return UNRESOLVED_LABELS, None, hunt, cases
    matches = [case for case in cases if set(case.event_ids) & set(anchor_ids)]
    if not matches:
        return UNDETECTED, None, hunt, cases
    if len(matches) > 1:
        return AMBIGUOUS, None, hunt, cases
    return INVESTIGABLE, matches[0], hunt, cases


def analyst_incident(telemetry: Telemetry, anchor_ids) -> InvestigationCase:
    """One neutral seed finding over the single anchor event, worded the same for every case."""
    if len(set(anchor_ids)) != 1:
        raise ValueError(f"an analyst seed is exactly one initial record ({SEED_POLICY}); "
                         f"got {len(set(anchor_ids))}. Rebuild the bundle from a single-anchor spec.")
    verifier = EvidenceVerifier(telemetry)
    rows = []
    for event_id in sorted(set(anchor_ids)):
        row, reason = verifier.row(event_id)
        if row is None:
            raise ValueError(f"anchor {event_id!r}: {reason}")
        rows.append(row)
    rows.sort(key=lambda r: (pd.Timestamp(r["timestamp"]), r["event_id"]))
    first = rows[0]
    channels = frozenset().union(*(channels_of_row(r["event_type"], r) for r in rows))
    others = sorted({str(r["device"]) for r in rows} - {str(first["device"])})
    evidence = tuple(
        Evidence(str(r["event_id"]), pd.Timestamp(r["timestamp"]).to_pydatetime(),
                 f"Analyst-selected {r['event_type']} event on {r['device']}")
        for r in rows)
    seed = Finding(rule_id=SEED_RULE_ID, title=SEED_TITLE, severity=Severity.MEDIUM,
                   device=str(first["device"]), user=str(first.get("user") or ""),
                   evidence=evidence, reason=SEED_REASON, channels=channels,
                   metadata={"seed": ANALYST, **({"target_devices": others} if others else {})})
    return InvestigationCase(case_id=SEED_CASE_ID, findings=(seed,))


def build_bundle(spec_path: Path, out_dir: Path) -> dict:
    """Build a sealed case bundle. Refuses to write into an existing directory."""
    spec_path = Path(spec_path)
    spec = load_spec(spec_path)
    seed_mode = spec.get("seed_mode", DETECTION)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=False)
    spec_bytes = spec_path.read_bytes()
    (out_dir / "SPEC.json").write_bytes(spec_bytes)
    loaded = {}
    entries = []
    for spec_case in spec["cases"]:
        key = spec_case["key"]
        source = spec_case["source"]
        path = (spec_path.parent / source["path"]).resolve()
        cache_key = (source["kind"], str(path), source.get("cluster", "default"))
        if cache_key not in loaded:
            loaded[cache_key] = load_source(source["kind"], path, source.get("cluster", "default"))
        full, ingestion = loaded[cache_key]
        cut = slice_telemetry(full, spec_case.get("window"), spec_case.get("devices"))
        telemetry = _write_slice(cut, out_dir / "cases" / key)
        refs = list(spec_case["anchor_refs"]) + list(spec_case.get("useful_refs", []))
        if spec_case.get("link"):
            refs += list(spec_case["link"]["refs"])
        resolved = resolve_refs(refs, telemetry)
        anchor_ids = sorted({_one(resolved, r) for r in spec_case["anchor_refs"]} - {""})
        useful_ids = sorted({_one(resolved, r) for r in spec_case.get("useful_refs", [])} - {""})
        link = None
        if spec_case.get("link"):
            left, right = (_one(resolved, r) for r in spec_case["link"]["refs"])
            if left and right:
                link = EvidenceAssertion(LINK_KINDS[spec_case["link"]["kind"]], left, right).to_dict()
        detection_status, incident, hunt, cases = select_incident(telemetry, anchor_ids)
        status = detection_status
        if seed_mode == ANALYST and set(anchor_ids) & set(useful_ids):
            raise ValueError(f"case {key!r}: the seed record resolves to follow-up evidence too")
        if seed_mode == ANALYST:
            incident = analyst_incident(telemetry, anchor_ids) if anchor_ids else None
            status = INVESTIGABLE if incident else UNRESOLVED_LABELS
        entry = {
            "key": key, "status": status, "seed_mode": seed_mode, "detection_status": detection_status, "expected_decision": spec_case["expected_decision"],
            "provenance": spec_case["provenance"], "label_source": spec_case["label_source"],
            "note": spec_case.get("note", ""), "ingestion": ingestion,
            "window": spec_case.get("window"), "devices": spec_case.get("devices"),
            "telemetry_sha256": telemetry_digest(telemetry, 2),
            "events": int(telemetry.event_count),
            "refs": {ref: {"status": r.status, "event_ids": list(r.event_ids)} for ref, r in resolved.items()},
            "anchor_ids": anchor_ids, "useful_ids": useful_ids, "link": link,
            "correlated_incidents": len(cases), "finding_ids": sorted(f.finding_id for f in hunt.findings),
            "case_ids": list(incident.event_ids) if incident else [],
            "rule_ids": sorted(incident.rule_ids) if incident else [],
            "useful_preflagged": sorted(set(useful_ids) & set(incident.event_ids)) if incident else [],
            **pilot.case_metadata(spec_case),
        }
        (out_dir / "cases" / key / "CASE.json").write_text(json.dumps(entry, indent=2) + "\n", encoding="utf-8")
        entries.append(entry)
        print(json.dumps({"key": key, "status": status, "events": entry["events"],
                          "anchors_resolved": f"{len(anchor_ids)}/{len(spec_case['anchor_refs'])}"}), flush=True)
    bundle = {"version": BUNDLE_VERSION, "name": spec.get("name", spec_path.stem), "seed_mode": seed_mode,
              "seed_policy": SEED_POLICY if seed_mode == ANALYST else None,
              "spec_sha256": hashlib.sha256(spec_bytes).hexdigest(), "cases": entries}
    if spec.get("protocol") is not None:  # absent otherwise, so older specs rebuild identically
        bundle["protocol"] = spec["protocol"]
    bundle["bundle_sha256"] = sha256_json(bundle)
    with (out_dir / "BUNDLE.json").open("x", encoding="utf-8") as handle:
        json.dump(bundle, handle, indent=2)
        handle.write("\n")
    return bundle


# -- evaluate ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RealCase:
    """Duck-types :class:`ath.evaluation.auth_execution.Scenario` for scoring."""

    key: str
    telemetry: Telemetry
    expected_decision: str
    useful_ids: tuple[str, ...]
    link: EvidenceAssertion | None
    case_ids: tuple[str, ...]
    seed_mode: str = DETECTION
    anchor_ids: tuple[str, ...] = ()
    platform: str | None = None
    provenance_class: str | None = None
    quadrant: str | None = None
    holdout_role: str | None = None
    seed_type: str | None = None


def read_bundle(bundle_dir: Path) -> dict:
    bundle = json.loads((Path(bundle_dir) / "BUNDLE.json").read_text(encoding="utf-8"))
    body = {k: v for k, v in bundle.items() if k != "bundle_sha256"}
    if bundle.get("version") != BUNDLE_VERSION or sha256_json(body) != bundle.get("bundle_sha256"):
        raise ValueError("bundle is not a sealed real-case bundle, or it was altered")
    if hashlib.sha256((Path(bundle_dir) / "SPEC.json").read_bytes()).hexdigest() != bundle["spec_sha256"]:
        raise ValueError("bundle spec was altered")
    return bundle


def real_cases(bundle_dir: Path) -> list[RealCase]:
    """Investigable cases, each re-verified against its sealed telemetry digest."""
    bundle = read_bundle(bundle_dir)
    out = []
    for entry in bundle["cases"]:
        if entry["status"] != INVESTIGABLE:
            continue
        telemetry = load_telemetry(Path(bundle_dir) / "cases" / entry["key"])
        if telemetry_digest(telemetry, 2) != entry["telemetry_sha256"]:
            raise ValueError(f"case {entry['key']!r}: telemetry differs from the sealed bundle")
        link = entry["link"]
        out.append(RealCase(
            entry["key"], telemetry, entry["expected_decision"], tuple(entry["useful_ids"]),
            EvidenceAssertion.from_dict(link) if link else None, tuple(entry["case_ids"]),
            bundle.get("seed_mode", DETECTION), tuple(entry["anchor_ids"]),
            **pilot.case_metadata(entry),
        ))
    return out


def prepare(case: RealCase):
    """Re-derive the incident from the sealed slice; it must be the one the bundle recorded."""
    hunt = run_hunt(case.telemetry)
    if case.seed_mode == ANALYST:
        incident = analyst_incident(case.telemetry, case.anchor_ids)
        if tuple(incident.event_ids) != case.case_ids:
            raise ValueError(f"case {case.key!r}: the analyst seed no longer matches the sealed bundle")
        # Detector findings stay available as context, as an analyst's other alerts would.
        return [*hunt.findings, *incident.findings], incident, build_environment_model(case.telemetry)
    incidents = [c for c in correlate(hunt.findings, case.telemetry) if tuple(c.event_ids) == case.case_ids]
    if len(incidents) != 1:
        raise ValueError(f"case {case.key!r}: the sealed incident no longer correlates identically")
    return list(hunt.findings), incidents[0], build_environment_model(case.telemetry)


def manifest(bundle_dir: Path) -> list[dict]:
    return [{"key": c.key, "telemetry_sha256": telemetry_digest(c.telemetry, 2),
             "expected_decision": c.expected_decision, "useful_ids": list(c.useful_ids),
             "link": c.link.to_dict() if c.link else None, "case_ids": list(c.case_ids),
             "seed_mode": c.seed_mode, **pilot.case_metadata(c)}
            for c in real_cases(bundle_dir)]


def _not_investigable(bundle):
    return [{"key": e["key"], "status": e["status"], "expected_decision": e["expected_decision"],
             **pilot.case_metadata(e)}
            for e in bundle["cases"] if e["status"] != INVESTIGABLE]


def _detection_statuses(bundle):
    return {e["key"]: e.get("detection_status", e["status"]) for e in bundle["cases"]}


def make_freeze(bundle_dir, model_description, model_configuration, repeats=1, profile=None):
    if repeats < 1:
        raise ValueError("repeats must be positive")
    profile = profile or StableContextProfile()
    bundle = read_bundle(bundle_dir)
    seed_mode = bundle.get("seed_mode", DETECTION)
    protocol = protocol_for(seed_mode)
    holdout = _HOLDOUTS.get(bundle.get("protocol"))
    if holdout is not None:
        name, rules = bundle["protocol"], holdout["holdout_rules"]
        if repeats != rules["repeats"]:
            raise ValueError(f"the {name} protocol runs exactly {rules['repeats']} repeat")
        required = HOLDOUT_FIELDS + (("holdout_role",) if name == HOLDOUT_WINDOWS else ())
        if any(not all(e.get(f) is not None for f in required) for e in bundle["cases"]):
            raise ValueError(f"the {name} protocol needs {', '.join(required)} on every case")
        # Sealed here, before any row exists: the verdict reads these rules from the freeze.
        protocol = {**protocol, **holdout}
    body = {"version": VERSION, "protocol": protocol, "split": SPLIT, "repeats": repeats,
            "seed_mode": seed_mode, "seed_policy": bundle.get("seed_policy"),
            "bundle_name": bundle["name"], "bundle_sha256": bundle["bundle_sha256"],
            "not_investigable": _not_investigable(bundle), "detection_status": _detection_statuses(bundle),
            "source_sha256": pilot.source_hash(), "manifest": manifest(bundle_dir),
            "profile": profile.to_dict(), "profile_sha256": profile.sha256(),
            "model": model_description, "model_configuration": model_configuration,
            "runtime": {"python": platform.python_version(), "pandas": pd.__version__, "platform": platform.platform()}}
    return {**body, "freeze_sha256": sha256_json(body)}


def validate_freeze(freeze, bundle_dir):
    body = {k: v for k, v in freeze.items() if k != "freeze_sha256"}
    if sha256_json(body) != freeze["freeze_sha256"]:
        raise ValueError("freeze contents were altered")
    if freeze.get("version") != VERSION:
        raise ValueError("not a real-case freeze")
    if read_bundle(bundle_dir)["bundle_sha256"] != freeze["bundle_sha256"]:
        raise ValueError("bundle differs from the one frozen")
    if freeze["source_sha256"] != pilot.source_hash() or freeze["manifest"] != manifest(bundle_dir):
        raise ValueError("code or telemetry changed; create a new freeze and output directory")
    profile = pilot.profile_for(freeze["profile"]["version"])
    if freeze["profile_sha256"] != profile.sha256() or freeze["profile"] != profile.to_dict():
        raise ValueError("operational profile changed")
    if (freeze["runtime"]["python"] != platform.python_version()
            or freeze["runtime"]["pandas"] != pd.__version__):
        raise ValueError("Python or pandas version differs from the freeze")


def evaluate_case(case: RealCase, arm, client=None, *, scripted=False, profile=None):
    return pilot.evaluate_case(case, arm, client, scripted=scripted, profile=profile,
                               prepared=prepare(case))


def holdout_verdict(rules, cases, rows, *, scripted=False):
    """Apply sealed holdout ``rules`` to ``rows``; pure, so each criterion is testable alone.

    ``cases`` is every sealed case (``key``, ``platform``, ``expected_decision``),
    investigable or not: a case with no row for an arm counts as incorrect for that arm,
    never as absent from the denominator. The protocol runs one repeat, so a row is
    identified by (case, arm).
    """
    arms = ("deterministic", "d1")
    by_identity = {(r["sample"], r["arm"]): r["scores"] for r in rows}
    missing = sorted((c["key"], arm) for c in cases for arm in arms if (c["key"], arm) not in by_identity)
    tallies = {}
    for arm in arms:
        scores = [by_identity[(c["key"], arm)] for c in cases if (c["key"], arm) in by_identity]
        platforms = {}
        for platform_name in sorted({c["platform"] for c in cases}):
            counts = {}
            for label in ("malicious", "benign"):
                labelled = [c for c in cases if c["platform"] == platform_name and c["expected_decision"] == label]
                # scores["correct"] already requires a complete investigation.
                correct = sum(bool(by_identity.get((c["key"], arm), {}).get("correct")) for c in labelled)
                counts[label] = {"cases": len(labelled), "correct": correct,
                                 "recall": correct / len(labelled) if labelled else None}
            recalls = [counts[label]["recall"] for label in ("malicious", "benign")]
            platforms[platform_name] = {**counts,
                                        "balanced_accuracy": None if None in recalls else sum(recalls) / 2}
        tallies[arm] = {"rows": len(scores), "correct": sum(s["correct"] for s in scores),
                        "unsafe_clears": sum(s["false_benign"] for s in scores),
                        "false_accusations": sum(s["false_malicious"] for s in scores),
                        "by_platform": platforms}
    d1, baseline = tallies["d1"], tallies["deterministic"]
    gain = d1["correct"] - baseline["correct"]
    floor = rules["per_platform_balanced_accuracy_above"]
    criteria = [
        {"criterion": "complete", "rule": "every expected row present",
         "observed": f"{len(missing)} missing", "passed": not missing},
        {"criterion": "live-model", "rule": "no scripted rows", "observed": scripted, "passed": not scripted},
        {"criterion": "1-correct-gain",
         "rule": f"d1 correct - deterministic correct >= {rules['min_correct_gain']}",
         "observed": gain, "passed": gain >= rules["min_correct_gain"]},
        {"criterion": "2-unsafe-clears", "rule": f"d1 unsafe clears <= {rules['max_d1_unsafe_clears']}",
         "observed": d1["unsafe_clears"], "passed": d1["unsafe_clears"] <= rules["max_d1_unsafe_clears"]},
        {"criterion": "3-false-accusations",
         "rule": f"d1 false accusations <= {rules['max_d1_false_accusations']}",
         "observed": d1["false_accusations"],
         "passed": d1["false_accusations"] <= rules["max_d1_false_accusations"]},
    ]
    for platform_name, figures in d1["by_platform"].items():
        balanced = figures["balanced_accuracy"]
        criteria.append({
            "criterion": f"4-discrimination:{platform_name}",
            "rule": (f"d1 balanced accuracy > {floor}, correct malicious >= {rules['per_platform_min_correct_malicious']}, "
                     f"correct benign >= {rules['per_platform_min_correct_benign']}"),
            "observed": {"balanced_accuracy": balanced, "correct_malicious": figures["malicious"]["correct"],
                         "correct_benign": figures["benign"]["correct"]},
            "passed": (balanced is not None and balanced > floor
                       and figures["malicious"]["correct"] >= rules["per_platform_min_correct_malicious"]
                       and figures["benign"]["correct"] >= rules["per_platform_min_correct_benign"])})
    failing = [c["criterion"] for c in criteria if not c["passed"]]
    notes = []
    if len(cases) != rules["min_correct_gain_declared_for_cases"]:
        notes.append(f"the correct-gain threshold was declared for {rules['min_correct_gain_declared_for_cases']} "
                     f"cases; this freeze has {len(cases)}. It was applied unscaled.")
    return {"protocol": rules["version"], "result": "incomplete" if missing else "complete",
            "missing": missing, "tallies": tallies, "criteria": criteria, "failing_criteria": failing,
            "notes": notes,
            "conclusion": "investigative value not demonstrated" if failing else "investigative value demonstrated"}


def summarise(freeze, rows, attempts=()):
    summary = pilot.summarise(freeze, rows, attempts)
    counts = {}
    for item in freeze["not_investigable"]:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    detected = sum(status == INVESTIGABLE for status in freeze["detection_status"].values())
    return {**summary, "evaluation": freeze["protocol"]["evaluation"], "seed_mode": freeze["seed_mode"],
            "seed_policy": freeze.get("seed_policy"),
            "detected_by_ath": f"{detected}/{len(freeze['detection_status'])}",
            "bundle_sha256": freeze["bundle_sha256"],
            "investigable_cases": len(freeze["manifest"]),
            "not_investigable": freeze["not_investigable"], "not_investigable_counts": counts,
            "limitations": freeze["protocol"]["limits"],
            **_holdout_summary(freeze, rows, summary)}


def _holdout_summary(freeze, rows, summary):
    rules = freeze["protocol"].get("holdout_rules")
    if rules is None:
        return {}
    cases = [{"key": e["key"], "platform": e["platform"], "expected_decision": e["expected_decision"],
              "holdout_role": e.get("holdout_role")}
             for e in [*freeze["manifest"], *freeze["not_investigable"]]]
    extra = {}
    primary_role = rules.get("primary_role")
    if primary_role is not None:
        secondary = [c for c in cases if c["holdout_role"] != primary_role]
        cases = [c for c in cases if c["holdout_role"] == primary_role]
        extra = {"secondary_check": secondary_check(secondary, rows),
                 "not_evaluated": freeze["protocol"].get("not_evaluated")}
    verdict = holdout_verdict(rules, cases, rows, scripted=summary["scripted"])
    # The pilot's rule is not this protocol's rule; its verdict is kept, labelled, beside it.
    return {"holdout": verdict, "conclusion": verdict["conclusion"],
            "pilot_rule_conclusion": summary["conclusion"], **extra}


def secondary_check(cases, rows):
    """Per arm, what each secondary (benign-only) case was called. Reported, never scored
    into the conclusion: these cases cannot show discrimination, only false accusation."""
    by_identity = {(r["sample"], r["arm"]): r["scores"] for r in rows}
    keys = [c["key"] for c in cases]
    report = {"cases": len(keys), "counts_toward_conclusion": False}
    for arm in ("deterministic", "d1"):
        present = [by_identity[(k, arm)] for k in keys if (k, arm) in by_identity]
        complete = [s for s in present if s.get("complete")]
        report[arm] = {
            "rows": len(present), "missing": sorted(k for k in keys if (k, arm) not in by_identity),
            "incomplete": len(present) - len(complete),
            "false_accusations": sum(s["decision"] == "malicious" for s in complete),
            "called_benign": sum(s["decision"] == "benign" for s in complete),
            "abstained": sum(s["decision"] == "abstain" for s in complete),
        }
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("build", "freeze", "run", "summarise"))
    parser.add_argument("--spec", type=Path, help="Case spec (build only)")
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--out", type=Path, help="Results directory (freeze/run/summarise)")
    parser.add_argument("--model", default="qwen3.5:9b")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--profile", choices=("operational-v2", "operational-v3", "operational-v4", "operational-v5", "operational-v6", "operational-v7"),
                        default="operational-v5", help="Profile for a new freeze; runs use the frozen profile")
    parser.add_argument("--arm", choices=("both", "deterministic", "d1"), default="both")
    args = parser.parse_args(argv)
    if args.command == "build":
        if args.spec is None:
            parser.error("build needs --spec")
        refuse_frozen_path(args.bundle, pilot.ROOT)
        bundle = build_bundle(args.spec, args.bundle)
        statuses = {}
        for entry in bundle["cases"]:
            statuses[entry["status"]] = statuses.get(entry["status"], 0) + 1
        print(json.dumps({"bundle_sha256": bundle["bundle_sha256"], "seed_mode": bundle["seed_mode"],
                          "cases": statuses}), flush=True)
        return 0
    if args.out is None:
        parser.error(f"{args.command} needs --out")
    refuse_frozen_path(args.out, pilot.ROOT)
    if args.command == "freeze":
        profile = pilot.profile_for(args.profile)
        client = pilot._client(args.model, profile)
        freeze = make_freeze(args.bundle, client.describe(), client.configuration(), args.repeats, profile)
        pilot.write_new(args.out / "FREEZE.json", freeze)
        print(json.dumps({"freeze_sha256": freeze["freeze_sha256"], "investigable": len(freeze["manifest"]),
                          "not_investigable": len(freeze["not_investigable"])}), flush=True)
        return 0
    freeze = json.loads((args.out / "FREEZE.json").read_text(encoding="utf-8"))
    validate_freeze(freeze, args.bundle)
    if args.command == "run":
        profile = pilot.profile_for(freeze["profile"]["version"])
        client = pilot._client(freeze["model_configuration"]["model"], profile)
        code = pilot.run_rows(args.out, freeze, real_cases(args.bundle), client, profile, args.arm, evaluate_case)
        if code:
            return code
    rows = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((args.out / "rows").glob("*.json"))]
    summary = summarise(freeze, rows, pilot.read_attempts(args.out))
    (args.out / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
