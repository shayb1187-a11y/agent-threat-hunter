"""M19-1: build the frozen case manifest, run an arm against it, and score it.

The order this script depends on
---------------------------------
``build`` runs first and writes ``reports/m19/ablation/MANIFEST.json``, which is
committed before any arm other than A runs. ``run`` re-loads every corpus from its
original source, re-derives findings and cases, and refuses to investigate anything
whose telemetry hash or finding ids differ from what the manifest pinned. That refusal
is the experiment's only guarantee that the arms saw identical inputs -- a guarantee
nobody can give by being careful, because the corpora are loaded hours apart from paths
that are not themselves frozen.

The case set
-------------
* ``attack_data_aws`` -- every case. Two of them, from 33 findings, and each carries the
  capture's ATT&CK technique as a label because that label is in the file name.
* ``comiset`` -- every case, read from the M18b canonical freeze.
* ``synthetic:INC-00n`` -- the case ``ath.evaluation.incidents.run_incident``
  investigates, built the way it builds it (hunt, triage, correlate, then the case with
  the most malicious overlap). Each incident is its own corpus because each carries its
  own telemetry and therefore its own hash.
* ``flaws_cloud`` -- a seeded stratified sample: up to five cases per *leading rule*,
  drawn by one ``random.Random(SEED)`` consumed in ascending rule order over case ids
  sorted ascending, plus every case that predates M18-8's four rules. flaws.cloud has
  281 cases and no labels; investigating all of them would spend the budget on the one
  corpus where nothing can be checked against ground truth.

Usage::

    python scripts/m19_ablation.py build
    python scripts/m19_ablation.py run --arm A --repeat 2
    python scripts/m19_ablation.py score --arm A
    python scripts/m19_ablation.py run --arm B --scripted   # harness proof, not a result

Scripted runs
--------------
``--scripted`` runs an arm that requires a model against
:class:`~ath.agent.llm.ScriptedLLM` responses written in this file. It exists to prove
that arm B's and arm C's path executes end to end while no key exists in this
environment. **A scripted run is not a result about any model.** Its rows are labelled
``*_SCRIPTED``, they are written under ``reports/m19/ablation/scripted/``, and
:func:`arm_output_path` refuses to write them next to the real arm files.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from m18_cloud_detection import NEW_RULES  # noqa: E402
from m18_cloud_detection import load_corpus as _cloud_corpus  # noqa: E402
from pre_schema_parquet import read_canonical_table  # noqa: E402

from ath.agent.llm import NullLLM, ScriptedLLM  # noqa: E402
from ath.correlation import correlate  # noqa: E402
from ath.correlation.chain import InvestigationCase  # noqa: E402
from ath.environment import build_environment_model  # noqa: E402
from ath.evaluation.ablation import (  # noqa: E402
    ARM_BUILDERS,
    CaseManifest,
    CaseResult,
    aggregate,
    build_manifest,
    identical,
    label_scores_from_outcome,
    leading_rule_of,
    load_manifest,
    manifest_hash,
    run_arm,
    scores_from_dict,
    telemetry_hash,
    telemetry_rows,
)
from ath.evaluation.incidents import Incident, run_incident  # noqa: E402
from ath.evaluation.suite import standard_suite  # noqa: E402
from ath.hunting import HuntConfig, run_hunt  # noqa: E402
from ath.hunting.finding import Finding  # noqa: E402
from ath.schema import (  # noqa: E402
    EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS,
)
from ath.telemetry.loader import Telemetry  # noqa: E402
from ath.triage import assess_findings, set_aside_ids  # noqa: E402

OUT_DIR = ROOT / "reports" / "m19" / "ablation"
MANIFEST_PATH = OUT_DIR / "MANIFEST.json"

# Scripted rows live in their own directory, never beside a real arm's results. The
# separation is enforced by arm_output_path rather than by remembering to pass a flag.
SCRIPTED_DIR_NAME = "scripted"

SCRIPTED_WARNING = (
    "SCRIPTED RUN -- the responses in this file were written by this repository, not by "
    "a model. These rows prove that the arm's planner and synthesis path executes end to "
    "end; they say nothing whatever about model quality, and they must never be "
    "aggregated with, or compared against, a real arm's results."
)

# The sample seed. Fixed, recorded in the manifest, and never re-drawn: a sample that
# can be re-drawn until it looks convenient is not a sample.
SEED = 19

# Cases per leading rule for the unlabelled flaws.cloud corpus.
FLAWS_CASES_PER_RULE = 5

CORPORA = ("attack_data_aws", "comiset", "synthetic", "flaws_cloud")

SELECTION_RULE = (
    "attack_data_aws and comiset: every case the corpus produces. "
    "synthetic:<incident>: the single case ath.evaluation.incidents.run_incident "
    "investigates for that incident (most malicious overlap; most findings for the "
    "benign scenario). "
    f"flaws_cloud: up to {FLAWS_CASES_PER_RULE} cases per leading rule -- the rule of "
    "the case's highest-severity, earliest finding -- drawn with one "
    f"random.Random({SEED}) consumed in ascending rule order over each stratum's case "
    f"ids sorted ascending; then up to {FLAWS_CASES_PER_RULE} cases per rule that fires "
    "on the corpus but leads no case, from the same generator in ascending rule order; "
    "plus every case containing a finding from a rule that predates M18-8 (any rule "
    f"outside {sorted(NEW_RULES)})."
)


# --------------------------------------------------------------------------------------
# The scripted client -- a harness proof, never a result
# --------------------------------------------------------------------------------------


_EVIDENCE_IN_PROMPT = re.compile(r"evidence: ([^)]*)\)")


@dataclass
class ScriptedArmLLM(ScriptedLLM):
    """:class:`~ath.agent.llm.ScriptedLLM`, answering in the shape the stage asked for.

    The double this project already has consumes a fixed list in order, which is exactly
    right for a test that drives one path and wrong for a whole-manifest run: the planner
    and the synthesiser interleave, so a fixed list hands planner JSON to the synthesiser
    on whichever case runs an extra step. This subclass keeps everything ScriptedLLM does
    -- recording every (system, prompt) pair so a test can prove no telemetry was sent,
    parsing the response, and reporting deterministic fake usage -- and only chooses
    *which* canned answer it is handed, from the system prompt.

    What the canned answers are chosen to exercise, and nothing more:

    * **Planner.** It names the *last* eligible candidate. The deterministic planner
      takes the first name in its priority order, so a plan log that follows the last
      candidate proves the model's choice actually steered the run rather than
      coinciding with the fallback.
    * **Synthesis.** Three claims: an INFERENCE citing an event id the orchestrator
      actually showed it (accepted), a HYPOTHESIS citing nothing (accepted -- the one
      claim type allowed to stand without evidence), and an INFERENCE citing a
      fabricated id (discarded as out-of-scope before the verifier ever sees it). All
      three guardrails therefore execute on every scripted case.

    **None of this is a measurement of a model.** The text is written here.
    """

    name: str = "scripted-harness"

    def complete(self, system: str, prompt: str, max_tokens: int = 1024):
        self.responses = [self._canned(system, prompt)]
        self._index = 0
        return super().complete(system, prompt, max_tokens)

    def _canned(self, system: str, prompt: str) -> str:
        if system.startswith("You are the synthesis component"):
            return self._synthesis(prompt)
        return self._plan(prompt)

    @staticmethod
    def _plan(prompt: str) -> str:
        candidates = [
            line.strip().split(":", 1)[0]
            for line in prompt.splitlines()
            if line.startswith("  ") and ":" in line
        ]
        if not candidates:
            return json.dumps({
                "next_agent": "none",
                "reason": "the prompt named no candidate; the deterministic order stands",
            })
        return json.dumps({
            "next_agent": candidates[-1],
            "reason": (
                "scripted: the last eligible candidate, chosen so the plan log shows "
                "the planner path was taken rather than the fallback"
            ),
        })

    @staticmethod
    def _synthesis(prompt: str) -> str:
        shown = [
            eid.strip()
            for group in _EVIDENCE_IN_PROMPT.findall(prompt)
            for eid in group.split(",")
            if eid.strip()
        ]
        claims: list[dict[str, Any]] = []
        if shown:
            claims.append({
                "type": "INFERENCE",
                "statement": (
                    "SCRIPTED: two of the verified claims cite the same event, so they "
                    "describe one activity rather than two."
                ),
                "evidence_ids": [shown[0]],
                "confidence": 0.5,
            })
        claims.append({
            "type": "HYPOTHESIS",
            "statement": (
                "SCRIPTED: the activity in this case may continue outside the evidence "
                "window. Unverified: nothing in the telemetry shows it."
            ),
            "evidence_ids": [],
            "confidence": 0.3,
        })
        claims.append({
            "type": "INFERENCE",
            "statement": (
                "SCRIPTED: a claim citing an event id that was never shown to the "
                "model, so that the out-of-scope guard is exercised on every case."
            ),
            "evidence_ids": ["evt-does-not-exist"],
            "confidence": 0.9,
        })
        return json.dumps({"claims": claims})


def arm_output_path(out_dir: Path, letter: str, scripted: bool) -> Path:
    """Where an arm's rows may be written -- scripted rows never beside real ones.

    A directory rule rather than a filename suffix, because the thing that must not
    happen is a scripted file being read by the aggregator that reads
    ``arm_*.json``. Enforced here, in one place, instead of at each call site.
    """
    directory = out_dir / SCRIPTED_DIR_NAME if scripted else out_dir
    return directory / f"arm_{letter}.json"


def refuse_mislabelled_output(path: Path, results: Sequence[Any]) -> None:
    """Refuse to write scripted rows outside the scripted directory, or vice versa.

    The check is on the rows, not on the flag that produced them: a row knows whether
    it came from canned text, and that is the only thing a reader of the file can
    verify afterwards.
    """
    scripted_rows = [r for r in results if getattr(r, "scripted", False)]
    in_scripted_dir = path.parent.name == SCRIPTED_DIR_NAME
    if scripted_rows and not in_scripted_dir:
        raise SystemExit(
            f"refusing to write {len(scripted_rows)} scripted row(s) to {path}: "
            "scripted rows are a proof that the harness runs, not a result about a "
            f"model, and belong under {SCRIPTED_DIR_NAME}/."
        )
    if in_scripted_dir and results and not scripted_rows:
        raise SystemExit(
            f"refusing to write real arm rows to {path}: the {SCRIPTED_DIR_NAME}/ "
            "directory is reserved for canned-response runs."
        )


# --------------------------------------------------------------------------------------
# Loading and the deterministic pipeline every arm shares
# --------------------------------------------------------------------------------------


@dataclass
class Bundle:
    """One corpus: its telemetry, everything the deterministic layer made of it."""

    name: str
    telemetry: Telemetry
    findings: list[Finding]
    cases: list[InvestigationCase]
    environment: Any
    labels: dict[str, dict[str, Any]] = field(default_factory=dict)
    incident: Incident | None = None
    load_seconds: float = 0.0
    pipeline_seconds: float = 0.0


def _load_telemetry(corpus: str) -> Telemetry:
    """One corpus, through the same loaders M18 and M18b used and no others."""
    if corpus == "comiset":
        directory = ROOT / "reports" / "m18b" / "canonical"
        return Telemetry(
            processes=read_canonical_table(directory, "comiset", "process", EVENT_PROCESS),
            network=read_canonical_table(directory, "comiset", "network", EVENT_NETWORK),
            logons=read_canonical_table(directory, "comiset", "logon", EVENT_LOGON),
            controls=read_canonical_table(directory, "comiset", "control", EVENT_CONTROL),
        )
    return _cloud_corpus(corpus)


def _pipeline(telemetry: Telemetry) -> tuple[list[Finding], list[InvestigationCase], Any]:
    """Hunt, triage, correlate -- exactly as ``run_incident`` and the M18 scripts do."""
    hunt = run_hunt(telemetry, config=HuntConfig())
    environment = build_environment_model(telemetry)
    assessments = assess_findings(hunt.findings, environment)
    cases = correlate(
        hunt.findings, telemetry, set_aside=set_aside_ids(assessments)
    )
    return list(hunt.findings), list(cases), environment


def _capture_labels(telemetry: Telemetry, cases: Sequence[InvestigationCase]) -> dict:
    """The attack_data_aws capture label, per case.

    The technique is the first ``__``-separated component of the capture file name, and
    the capture is the ``File=`` half of a row's ``source_ref``. A case drawing evidence
    from more than one capture gets no label rather than an arbitrary one -- the label
    belongs to a capture, and a case that spans two captures has no single answer.
    """
    capture_of: dict[str, str] = {}
    for event_type in (EVENT_PROCESS, EVENT_NETWORK, EVENT_LOGON, EVENT_CONTROL):
        frame = telemetry.table(event_type)
        if frame.empty:
            continue
        for event_id, ref in zip(frame["event_id"], frame["source_ref"].astype("string").fillna("")):
            for part in str(ref).split(";"):
                if part.startswith("File="):
                    capture_of[str(event_id)] = part[len("File="):]

    labels: dict[str, dict[str, Any]] = {}
    for case in cases:
        captures = sorted({capture_of.get(e, "") for e in case.event_ids} - {""})
        labels[case.case_id] = {
            "captures": captures,
            "labelled_technique": (
                captures[0].split("__", 1)[0] if len(captures) == 1 else ""
            ),
        }
    return labels


def _select_flaws(cases: Sequence[InvestigationCase]) -> tuple[list[InvestigationCase], dict]:
    """The seeded stratified sample, plus every pre-M18 case.

    Two strata kinds, kept separate because they answer different questions. The
    *leading-rule* strata sample cases by what the case is about. A rule can fire on
    this corpus and never lead a case, though -- AWS-005 does exactly that: all of its
    findings land in cases whose most severe finding belongs to another rule -- so a
    sample drawn only over leading rules would leave that rule entirely unrepresented
    and the ablation would have no evidence about it at all. A second, separately
    labelled stratum therefore samples cases that *contain* such a rule. Both are drawn
    from one ``random.Random(SEED)`` consumed in a fixed order, so the whole selection
    is reproducible from the seed alone.
    """
    by_leading: dict[str, list[str]] = defaultdict(list)
    by_containing: dict[str, list[str]] = defaultdict(list)
    for case in cases:
        by_leading[leading_rule_of(case)].append(case.case_id)
        for rule_id in case.rule_ids:
            by_containing[rule_id].append(case.case_id)

    rng = random.Random(SEED)
    chosen: dict[str, str] = {}
    strata: dict[str, Any] = {}
    for rule in sorted(by_leading):
        ids = sorted(by_leading[rule])
        take = (
            list(ids) if len(ids) <= FLAWS_CASES_PER_RULE
            else sorted(rng.sample(ids, FLAWS_CASES_PER_RULE))
        )
        strata[rule] = {"cases_in_stratum": len(ids), "sampled": take}
        for case_id in take:
            chosen[case_id] = (
                f"stratified sample: up to {FLAWS_CASES_PER_RULE} cases led by {rule}"
            )

    present_only: dict[str, Any] = {}
    for rule in sorted(set(by_containing) - set(by_leading)):
        ids = sorted(by_containing[rule])
        take = (
            list(ids) if len(ids) <= FLAWS_CASES_PER_RULE
            else sorted(rng.sample(ids, FLAWS_CASES_PER_RULE))
        )
        present_only[rule] = {"cases_containing": len(ids), "sampled": take}
        for case_id in take:
            chosen.setdefault(case_id, (
                f"stratified sample: up to {FLAWS_CASES_PER_RULE} cases containing "
                f"{rule}, which leads no case on this corpus"
            ))

    pre_m18 = [
        c for c in cases if any(f.rule_id not in NEW_RULES for f in c.findings)
    ]
    for case in pre_m18:
        chosen.setdefault(
            case.case_id,
            "pre-M18 case: contains a finding from a rule that predates M18-8",
        )

    selected = [c for c in cases if c.case_id in chosen]
    detail = {
        "seed": SEED,
        "per_rule": FLAWS_CASES_PER_RULE,
        "strata_by_leading_rule": strata,
        "strata_by_rule_present_but_never_leading": present_only,
        "cases_containing_rule": {
            rule: len(set(ids)) for rule, ids in sorted(by_containing.items())
        },
        "pre_m18_cases": sorted(c.case_id for c in pre_m18),
        "reasons": chosen,
    }
    return selected, detail


def load_bundles(names: Iterable[str]) -> Iterator[Bundle]:
    """Every corpus named, each already through the deterministic pipeline."""
    for name in names:
        if name == "synthetic":
            for incident in standard_suite(
                ROOT / "data" / "raw",
                ROOT / "tests" / "fixtures" / "cloudtrail",
                ROOT / "tests" / "fixtures" / "k8s_audit",
            ):
                started = time.perf_counter()
                findings, cases, environment = _pipeline(incident.telemetry)
                yield Bundle(
                    name=f"synthetic:{incident.incident_id}",
                    telemetry=incident.telemetry,
                    findings=findings, cases=cases, environment=environment,
                    incident=incident,
                    labels={
                        c.case_id: {"incident_id": incident.incident_id} for c in cases
                    },
                    pipeline_seconds=time.perf_counter() - started,
                )
            continue

        started = time.perf_counter()
        telemetry = _load_telemetry(name)
        load_seconds = time.perf_counter() - started
        started = time.perf_counter()
        findings, cases, environment = _pipeline(telemetry)
        pipeline_seconds = time.perf_counter() - started
        labels = (
            _capture_labels(telemetry, cases) if name == "attack_data_aws" else {}
        )
        yield Bundle(
            name=name, telemetry=telemetry, findings=findings, cases=cases,
            environment=environment, labels=labels,
            load_seconds=load_seconds, pipeline_seconds=pipeline_seconds,
        )


def select(bundle: Bundle) -> tuple[list[InvestigationCase], str, dict[str, Any]]:
    """Which of a corpus's cases go in the manifest, and why."""
    if bundle.name.startswith("synthetic:"):
        incident = bundle.incident
        assert incident is not None
        if not bundle.cases:
            return [], "no case was raised for this incident", {}
        malicious = set(incident.malicious_event_ids)
        target = (
            max(bundle.cases, key=lambda c: len(set(c.event_ids) & malicious))
            if malicious else max(bundle.cases, key=lambda c: len(c.findings))
        )
        return (
            [target],
            "the case run_incident investigates for this incident",
            {"cases_in_corpus": len(bundle.cases)},
        )
    if bundle.name == "flaws_cloud":
        selected, detail = _select_flaws(bundle.cases)
        return selected, "", detail
    return list(bundle.cases), "every case this corpus produced", {}


# --------------------------------------------------------------------------------------
# build
# --------------------------------------------------------------------------------------


def _head() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:  # noqa: BLE001 -- a missing git is not a reason to lose the run
        return "unknown"


def cmd_build(args: argparse.Namespace) -> int:
    entries: list[CaseManifest] = []
    corpora: dict[str, Any] = {}

    for bundle in load_bundles(args.corpus):
        selected, selection, detail = select(bundle)
        if bundle.name == "flaws_cloud":
            reasons = detail.pop("reasons", {})
            bundle_entries = build_manifest(
                bundle.name, bundle.telemetry, selected, labels=bundle.labels,
            )
            bundle_entries = [
                CaseManifest(
                    corpus=e.corpus, case_id=e.case_id, rule_ids=e.rule_ids,
                    leading_rule=e.leading_rule, finding_ids=e.finding_ids,
                    evidence_ids=e.evidence_ids, telemetry_hash=e.telemetry_hash,
                    selection=reasons.get(e.case_id, ""), labels=e.labels,
                )
                for e in bundle_entries
            ]
        else:
            bundle_entries = build_manifest(
                bundle.name, bundle.telemetry, selected,
                selection=selection, labels=bundle.labels,
            )
        entries += bundle_entries

        corpora[bundle.name] = {
            "telemetry_hash": telemetry_hash(bundle.telemetry),
            "rows": telemetry_rows(bundle.telemetry),
            "findings": len(bundle.findings),
            "findings_by_rule": dict(
                sorted(Counter(f.rule_id for f in bundle.findings).items())
            ),
            "cases": len(bundle.cases),
            "cases_selected": len(bundle_entries),
            "selection": selection,
            "selection_detail": detail,
            "load_seconds": round(bundle.load_seconds, 1),
            "pipeline_seconds": round(bundle.pipeline_seconds, 1),
            "evidence_ids_selected": sum(len(e.evidence_ids) for e in bundle_entries),
            "finding_ids_selected": sum(len(e.finding_ids) for e in bundle_entries),
        }
        print(
            f"{bundle.name}: {len(bundle.findings)} finding(s), {len(bundle.cases)} "
            f"case(s), {len(bundle_entries)} pinned"
        )

    digest = manifest_hash(entries)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "head": _head(),
        "seed": SEED,
        "selection_rule": SELECTION_RULE,
        "manifest_hash": digest,
        "corpora": corpora,
        "cases": [e.to_dict() for e in entries],
    }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    path = args.out_dir / MANIFEST_PATH.name
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    print(f"\nmanifest_hash {digest}")
    print(f"wrote {path} ({len(entries)} case(s))")
    return 0


# --------------------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------------------


def _read_manifest(out_dir: Path) -> tuple[dict[str, Any], list[CaseManifest], str]:
    payload = json.loads((out_dir / MANIFEST_PATH.name).read_text(encoding="utf-8"))
    entries = load_manifest(payload)
    recomputed = manifest_hash(entries)
    recorded = str(payload.get("manifest_hash", ""))
    if recomputed != recorded:
        raise SystemExit(
            f"MANIFEST.json records {recorded[:12]} but its entries hash to "
            f"{recomputed[:12]}. The file has been edited since it was frozen; refusing "
            "to run an arm against a manifest that does not describe itself."
        )
    return payload, entries, recorded


def cmd_run(args: argparse.Namespace) -> int:
    payload, entries, digest = _read_manifest(args.out_dir)
    arm = ARM_BUILDERS[_arm_name(args.arm)]()
    scripted = bool(getattr(args, "scripted", False))
    if scripted:
        print(SCRIPTED_WARNING)

    wanted = set(args.corpus) if args.corpus else None
    by_corpus: dict[str, list[CaseManifest]] = defaultdict(list)
    for entry in entries:
        family = entry.corpus.split(":", 1)[0]
        if wanted is None or entry.corpus in wanted or family in wanted:
            by_corpus[entry.corpus].append(entry)

    runs: list[list[CaseResult]] = [[] for _ in range(args.repeat)]
    timing: dict[str, Any] = {}

    for bundle in load_bundles(_families(by_corpus)):
        if bundle.name not in by_corpus:
            continue
        corpus_entries = by_corpus[bundle.name]
        started = time.perf_counter()
        for index in range(args.repeat):
            results = run_arm(
                arm, corpus_entries, bundle.telemetry, bundle.cases,
                manifest_digest=digest, findings=bundle.findings,
                environment=bundle.environment,
                llm=ScriptedArmLLM() if scripted else None,
                scripted=scripted,
            )
            if bundle.incident is not None:
                outcome = run_incident(bundle.incident, llm=_arm_llm(arm, scripted))
                labelled = label_scores_from_outcome(outcome)
                for result in results:
                    result.label_scores = labelled
            runs[index] += results
        timing[bundle.name] = {
            "load_seconds": round(bundle.load_seconds, 1),
            "pipeline_seconds": round(bundle.pipeline_seconds, 1),
            "arm_seconds_all_repeats": round(time.perf_counter() - started, 1),
            "cases": len(corpus_entries),
            "findings": len(bundle.findings),
            "corpus_cases": len(bundle.cases),
        }
        print(
            f"{bundle.name}: {len(corpus_entries)} case(s) x {args.repeat} "
            f"run(s) in {timing[bundle.name]['arm_seconds_all_repeats']}s"
        )

    differences = identical(runs[0], runs[-1]) if args.repeat > 1 else []
    reproducibility = {
        "repeats": args.repeat,
        "compared": args.repeat > 1,
        "identical": args.repeat > 1 and not differences,
        "differences": differences,
        "note": (
            "wall seconds and wall-clock timestamps are excluded from the comparison; "
            "every claim, tool call, plan-log line and score is included"
        ),
    }

    out = arm_output_path(args.out_dir, _arm_letter(args.arm), scripted)
    refuse_mislabelled_output(out, runs[0])
    out.parent.mkdir(parents=True, exist_ok=True)
    record: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "head": _head(),
        "arm": arm.to_dict(),
        "scripted": scripted,
        "manifest_hash": digest,
        "manifest_head": payload.get("head"),
        "reproducibility": reproducibility,
        "budgets": {
            "max_steps": arm.config.max_steps,
            "tool_call_cap": arm.tool_call_cap,
            "cases_hitting_tool_cap": sum(
                1 for r in runs[0] if r.budgets.get("tool_budget_hit")
            ),
            "cases_hitting_step_budget": sum(
                1 for r in runs[0] if r.budgets.get("step_budget_hit")
            ),
            "tool_calls_refused": sum(
                int(r.budgets.get("tool_calls_refused", 0)) for r in runs[0]
            ),
        },
        "timing": timing,
        "cases": [r.to_dict() for r in runs[0]],
    }
    if scripted:
        record["warning"] = SCRIPTED_WARNING
    out.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
    print(f"wrote {out} ({len(runs[0])} case row(s))")

    if args.repeat > 1:
        print(
            "reproducibility: IDENTICAL" if not differences
            else f"reproducibility: {len(differences)} DIFFERENCE(S): {differences[:5]}"
        )
    _write_scores(args, runs[0], digest, scripted=scripted)
    return 0


def _families(by_corpus: dict[str, list[CaseManifest]]) -> list[str]:
    """Corpus names to load: the family name, because synthetic loads as a suite."""
    return list(dict.fromkeys(name.split(":", 1)[0] for name in by_corpus))


def _arm_llm(arm: Any, scripted: bool = False) -> Any:
    """The client an arm's label-based benchmark row must be produced with."""
    if not arm.requires_model:
        return NullLLM()
    return ScriptedArmLLM() if scripted else arm.llm_factory()


def _arm_name(letter: str) -> str:
    for name in ARM_BUILDERS:
        if name.startswith(letter.upper() + "_") or name == letter:
            return name
    raise SystemExit(f"unknown arm {letter!r}; known: {sorted(ARM_BUILDERS)}")


def _arm_letter(letter: str) -> str:
    return _arm_name(letter).split("_", 1)[0]


# --------------------------------------------------------------------------------------
# score
# --------------------------------------------------------------------------------------


@dataclass
class _Row:
    """A committed per-case row, read back for aggregation."""

    labelled_arm: str
    corpus: str
    case_id: str
    llm_degraded: bool
    scores: Any


def _write_scores(
    args: argparse.Namespace, results: Sequence[Any], digest: str,
    scripted: bool = False,
) -> None:
    summary = aggregate(results)
    directory = args.out_dir / SCRIPTED_DIR_NAME if scripted else args.out_dir
    directory.mkdir(parents=True, exist_ok=True)
    out = directory / f"scores_{_arm_letter(args.arm)}.json"
    payload: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "head": _head(),
        "manifest_hash": digest,
        "summary": summary,
    }
    if scripted:
        payload["warning"] = SCRIPTED_WARNING
    out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    print(f"wrote {out}")
    print(json.dumps(summary, indent=2, default=str)[:3000])


def cmd_score(args: argparse.Namespace) -> int:
    scripted = bool(getattr(args, "scripted", False))
    source = arm_output_path(args.out_dir, _arm_letter(args.arm), scripted)
    payload = json.loads(source.read_text(encoding="utf-8"))
    rows = [
        _Row(
            labelled_arm=str(row["labelled_arm"]),
            corpus=str(row["corpus"]),
            case_id=str(row["case_id"]),
            llm_degraded=bool(row["llm_degraded"]),
            scores=scores_from_dict(row["scores"]),
        )
        for row in payload.get("cases", [])
    ]
    _write_scores(args, rows, str(payload.get("manifest_hash", "")), scripted=scripted)
    return 0


# --------------------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out-dir", type=Path, default=OUT_DIR)
    sub = parser.add_subparsers(dest="command", required=True)

    p_build = sub.add_parser("build", help="freeze the case manifest")
    p_build.add_argument("--corpus", nargs="*", default=list(CORPORA))
    p_build.add_argument("--out-dir", type=Path, default=OUT_DIR)
    p_build.set_defaults(func=cmd_build)

    p_run = sub.add_parser("run", help="run one arm over the frozen manifest")
    p_run.add_argument("--arm", default="A")
    p_run.add_argument("--repeat", type=int, default=1)
    p_run.add_argument("--corpus", nargs="*", default=[])
    p_run.add_argument("--out-dir", type=Path, default=OUT_DIR)
    p_run.add_argument(
        "--scripted", action="store_true",
        help="Run a model arm against canned ScriptedLLM responses. Proves the path "
             "executes; says nothing about any model. Rows are labelled *_SCRIPTED and "
             f"written under {SCRIPTED_DIR_NAME}/.",
    )
    p_run.set_defaults(func=cmd_run)

    p_score = sub.add_parser("score", help="re-aggregate a committed arm result")
    p_score.add_argument("--arm", default="A")
    p_score.add_argument("--out-dir", type=Path, default=OUT_DIR)
    p_score.add_argument("--scripted", action="store_true",
                         help=f"read and write under {SCRIPTED_DIR_NAME}/")
    p_score.set_defaults(func=cmd_score)

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
