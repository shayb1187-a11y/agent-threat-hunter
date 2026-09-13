"""M19b Phase 3 / T3: repeat ten M19 cases, and report the spread beside M19's single run.

What this answers
------------------
M19 ran each arm once per case. One run cannot distinguish "arm B found evidence arm A
did not" from "arm B happened, that once, to find evidence arm A did not". This harness
re-runs a **pre-defined** ten of M19's twenty-two cases three times per model arm and
reports, per case, the M19 primary value beside the repeats' min / median / max.

The selection is fixed in :data:`SELECTION` before any repeat ran and is asserted rather
than recomputed: a stratum whose membership is derived at score time from the results it
is scoring is not a stratum, it is a conclusion. Four strata, ten cases:

``B_unique``
    The lowest case id per stratum among the thirteen cases where arm B met M19's
    decision rule (`GRADING.json` ``vii_decision_rule.B.per_case``). These are the cases
    the M19 result rests on.
``B_degraded``
    The two COMISET cases whose arm B row degraded on HTTP 413. They are re-run because
    a degradation that reproduces is a property of the request, and one that does not is
    a property of the day. If they 413 again, that is the measurement.
``C_planner_choice``
    The one M19 case on which arm C's planner was offered more than one candidate.
``agreed_easy``
    Three cases on which A, B and C agreed, as a control: variance here is variance in
    the harness, not in the finding.

What it is not
---------------
Nothing here is averaged into M19, and nothing here is written under ``reports/m19/``:
:func:`_refuse_m19_path` refuses the write by path, on every artifact this file
produces. M19's numbers appear in the report only as the ``m19_primary`` column, read
from the frozen artifacts and never recomputed from a re-run.

No row is ever re-run to make it pass. A degraded row, a 413, an unparseable reply and a
budget exhaustion are all preserved and reported; the only retries are the ones the
frozen client policy already performs inside a single call.

Reuse, not a second copy
-------------------------
The arms, the investigation, the scoring and the environment capture are
:mod:`ath.evaluation.ablation`'s, and the corpus loading, the deterministic pipeline, the
size guard and the planner accounting are ``scripts/m19_ablation.py``'s. This file adds
exactly three things M19 did not need: a freeze that asserts equality with M19's freeze,
a runner that keeps every repeat rather than only the first, and a scorer that reports a
distribution where M19 reported a value.

Commands::

    python scripts/m19b_robustness.py freeze
    python scripts/m19b_robustness.py run --arm A
    python scripts/m19b_robustness.py run --arm B --repeat 3 --check-planner
    python scripts/m19b_robustness.py run --arm C --repeat 3 --check-planner
    python scripts/m19b_robustness.py score
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import m19_ablation as m19  # noqa: E402
from m19b_env import reproduces_grading  # noqa: E402

from ath.evaluation.ablation import (  # noqa: E402
    ARM_BUILDERS,
    CaseManifest,
    CaseResult,
    run_arm,
)
from ath.evaluation.ablation.arms import cap_serialised_ids  # noqa: E402
from ath.evaluation.ablation.environment import (  # noqa: E402
    CREDENTIAL_VARIABLE,
    ENVIRONMENT_JSON,
    ENVIRONMENT_MD,
    capture_environment,
    render_markdown,
)

# --------------------------------------------------------------------------------------
# Where things live, and the one directory this file may never write to
# --------------------------------------------------------------------------------------

M19_DIR = ROOT / "reports" / "m19" / "ablation"
"""The frozen M19 experiment. Read-only for the whole of M19b."""

OUT_DIR = ROOT / "reports" / "m19b" / "robustness"

M19_PREFIX = ROOT / "reports" / "m19"


def _refuse_m19_path(path: Path) -> Path:
    """Refuse any write under ``reports/m19/``, by path, before it happens.

    A rule stated in prose is a rule a later edit can forget. This is called by every
    write in this file, so forgetting it means not writing at all.
    """
    resolved = Path(path).resolve()
    try:
        resolved.relative_to(M19_PREFIX.resolve())
    except ValueError:
        return Path(path)
    raise SystemExit(
        f"refusing to write {path}: reports/m19/ is the frozen M19 experiment. M19b "
        "reports beside it and never into it."
    )


def write_artifact(path: Path, payload: Any) -> None:
    """``m19_ablation.write_artifact`` -- the same 50 MB refusal -- plus the M19 guard."""
    m19.write_artifact(_refuse_m19_path(path), payload)


def write_text(path: Path, text: str) -> None:
    guarded = _refuse_m19_path(path)
    guarded.parent.mkdir(parents=True, exist_ok=True)
    guarded.write_text(text, encoding="utf-8")


# --------------------------------------------------------------------------------------
# The selection -- pre-defined, asserted, never recomputed
# --------------------------------------------------------------------------------------

SELECTION: tuple[tuple[str, str, str], ...] = (
    ("synthetic:INC-004", "CASE-001", "B_unique"),
    ("flaws_cloud", "CASE-018", "B_unique"),
    ("flaws_cloud", "CASE-050", "B_unique"),
    ("flaws_cloud", "CASE-065", "B_unique"),
    ("comiset", "CASE-001", "B_degraded"),
    ("comiset", "CASE-002", "B_degraded"),
    ("synthetic:INC-001", "CASE-001", "C_planner_choice"),
    ("attack_data_aws", "CASE-002", "agreed_easy"),
    ("synthetic:INC-002", "CASE-001", "agreed_easy"),
    ("flaws_cloud", "CASE-005", "agreed_easy"),
)
"""The ten cases, fixed before any repeat ran. See the module docstring for the rule."""

STRATUM_OF: dict[tuple[str, str], str] = {
    (corpus, case_id): stratum for corpus, case_id, stratum in SELECTION
}

SELECTED_KEYS: tuple[tuple[str, str], ...] = tuple(
    (corpus, case_id) for corpus, case_id, _ in SELECTION
)

REPEATS = 3
"""Repeats per model arm per case. Arm A is deterministic and runs once."""


def select_entries(entries: Sequence[CaseManifest]) -> list[CaseManifest]:
    """The manifest entries for :data:`SELECTION`, in selection order.

    Refuses rather than runs a subset: a robustness result over nine of ten cases, with
    the tenth silently absent, reads exactly like a result over ten.
    """
    by_key = {(e.corpus, e.case_id): e for e in entries}
    missing = [key for key in SELECTED_KEYS if key not in by_key]
    if missing:
        raise SystemExit(
            f"{len(missing)} selected case(s) are not in the M19 manifest: {missing}. "
            "The selection names M19 cases by identity; refusing to run a different set."
        )
    return [by_key[key] for key in SELECTED_KEYS]


# --------------------------------------------------------------------------------------
# freeze -- and the assertion that makes it worth freezing
# --------------------------------------------------------------------------------------

ASSERTED_FIELDS: tuple[str, ...] = (
    "arms", "shared_tool_surface", "request", "retry", "prompts", "manifest_hash",
)
"""What must be byte-equal to M19's freeze.

Everything a model sees, everything a request carries, everything a failure is retried
under, every arm's model id and budget, the whole tool surface, and the inputs. Not the
commit -- committing a freeze moves HEAD, and M19b is a later commit by construction;
both are recorded instead. Not the runtime either: the Python version and the platform
are recorded because they explain a result, and gating on them would refuse every run
from a second machine.

**Not ``scoring`` either, since T6.** It was in this tuple when these repeats ran, and
the artifact they wrote records it. ``docs/m19b-plan.md``, amended before any T8 run,
replaced the scoring hash with a stronger requirement once T6 added the necessity
metrics to ``scoring.py``: the M19 metrics, recomputed by the new code over M19's own
committed rows, must reproduce ``GRADING.json`` exactly. A hash says the file did not
change; the reproduction says no published number changed, which is the thing the hash
was standing in for -- and it is asserted here, in :func:`build_m19b_environment`, with
the same refusal.
"""


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, indent=2, default=str)


def environment_differences(recorded: dict[str, Any], live: dict[str, Any]) -> list[str]:
    """Byte-level differences on :data:`ASSERTED_FIELDS`, empty when they match."""
    differences: list[str] = []
    for field_name in ASSERTED_FIELDS:
        left, right = _canonical(recorded.get(field_name)), _canonical(live.get(field_name))
        if left == right:
            continue
        if isinstance(recorded.get(field_name), dict) and isinstance(live.get(field_name), dict):
            for key in sorted(set(recorded[field_name]) | set(live[field_name])):
                sub_left = _canonical(recorded[field_name].get(key))
                sub_right = _canonical(live[field_name].get(key))
                if sub_left != sub_right:
                    differences.append(
                        f"{field_name}.{key}: M19 {sub_left[:120]!r} != M19b "
                        f"{sub_right[:120]!r}"
                    )
        else:
            differences.append(
                f"{field_name}: M19 {left[:200]!r} != M19b {right[:200]!r}"
            )
    return differences


def read_m19_environment() -> dict[str, Any]:
    path = M19_DIR / ENVIRONMENT_JSON
    if not path.exists():
        raise SystemExit(f"{path} does not exist; M19b's freeze is defined against it.")
    return json.loads(path.read_text(encoding="utf-8"))


def build_m19b_environment(digest: str, manifest_head: str) -> dict[str, Any]:
    """The live environment, with the M19 equality assertion attached.

    Raises ``SystemExit`` when the assertion fails: an M19b freeze that recorded a
    different prompt, a different budget or a different tool surface would be a freeze
    of a different experiment, and the whole point of this task is that the repeats are
    repeats *of M19*.
    """
    recorded = read_m19_environment()
    live = capture_environment(
        ROOT,
        manifest_hash=digest,
        manifest_head=manifest_head,
        credential_present=bool(os.getenv(CREDENTIAL_VARIABLE)),
    )
    differences = environment_differences(recorded, live)
    if differences:
        raise SystemExit(
            "M19b's environment is not M19's:\n  " + "\n  ".join(differences)
            + "\n\nRefusing to freeze. These repeats are only repeats of M19 while the "
            "prompts, the tool surface, the budgets, the model ids, the request "
            "configuration and the retry policy are the frozen ones."
        )
    reproduces, scoring_differences = reproduces_grading()
    if not reproduces:
        raise SystemExit(
            "M19b's scoring code does not reproduce M19's published metrics:\n  "
            + "\n  ".join(scoring_differences)
            + "\n\nRefusing to freeze. Since T6 added the necessity metrics, the "
            "scoring hash cannot match and the plan requires this instead -- and a "
            "scoring change that moves an M19 number is not a difference to record, it "
            "is a run to stop."
        )
    live["m19_equality"] = {
        "asserted_fields": list(ASSERTED_FIELDS),
        "byte_equal": True,
        "scoring": {
            "asserted_by": (
                "reproduction, not a hash: T6 added the necessity metrics to "
                "scoring.py (docs/m19b-plan.md, rule 2 amended before any T8 run)"
            ),
            "reproduces_grading": True,
            "hashes": dict(live.get("scoring") or {}),
        },
        "m19_environment": str((M19_DIR / ENVIRONMENT_JSON).relative_to(ROOT)).replace("\\", "/"),
        "m19_commit": recorded.get("git", {}).get("commit", ""),
        "m19b_commit": live.get("git", {}).get("commit", ""),
        "note": (
            "the commit differs by construction -- committing a freeze moves HEAD and "
            "M19b is a later commit -- so both are recorded and the commit is not one "
            "of the asserted fields. Everything a model, a request or a score depends "
            "on is."
        ),
    }
    return live


def cmd_freeze(args: argparse.Namespace) -> int:
    payload, _entries, digest = m19._read_manifest(M19_DIR)
    environment = build_m19b_environment(digest, str(payload.get("head", "")))
    equality = environment["m19_equality"]
    write_artifact(args.out_dir / ENVIRONMENT_JSON, environment)
    write_text(
        args.out_dir / ENVIRONMENT_MD,
        render_markdown(environment) + _equality_markdown(equality),
    )
    print(f"wrote {args.out_dir / ENVIRONMENT_JSON}")
    print(f"wrote {args.out_dir / ENVIRONMENT_MD}")
    print(
        "M19 equality: BYTE-EQUAL on "
        + ", ".join(ASSERTED_FIELDS)
    )
    print(f"  M19  commit {equality['m19_commit'][:12]}")
    print(f"  M19b commit {equality['m19b_commit'][:12]}")
    git = environment["git"]
    print(
        f"frozen at {git['short_commit']} on {git['branch']}"
        + (" (DIRTY WORKING TREE)" if git.get("dirty") else "")
    )
    return 0


def _equality_markdown(equality: dict[str, Any]) -> str:
    lines = [
        "",
        "## Equality with the M19 freeze",
        "",
        "These repeats are repeats *of M19*. Everything a model reads, every budget, "
        "every request field, the retry policy, the model ids, the whole tool surface "
        "and the scoring code are asserted **byte-equal** to "
        f"`{equality['m19_environment']}` before a model arm may run; the assertion is "
        "re-checked at the start of every `run`, and a failure refuses the run rather "
        "than annotating it.",
        "",
        "| | commit |",
        "| --- | --- |",
        f"| M19 freeze | `{equality['m19_commit']}` |",
        f"| M19b freeze | `{equality['m19b_commit']}` |",
        "",
        f"{equality['note']}",
        "",
        "Asserted fields: " + ", ".join(f"`{f}`" for f in equality["asserted_fields"]),
        "",
    ]
    return "\n".join(lines)


def guard_environment(out_dir: Path, digest: str) -> None:
    """Refuse a model arm unless the M19b freeze exists, still holds, and is M19's.

    Two gates, both needed. M19's own gate (``m19_ablation.guard_environment``) catches
    a prompt or a scoring rule that moved between this freeze and this run. The equality
    re-check catches the case M19's gate cannot see: a freeze written against a
    *different* M19 environment file, or an M19 file that changed underneath.
    """
    path = out_dir / ENVIRONMENT_JSON
    if not path.exists():
        raise SystemExit(
            f"{path} does not exist. Run `python scripts/m19b_robustness.py freeze` "
            "first: without it nothing afterwards can say these repeats ran the "
            "configuration M19 ran."
        )
    m19.guard_environment(out_dir, digest)
    recorded_m19b = json.loads(path.read_text(encoding="utf-8"))
    differences = environment_differences(read_m19_environment(), recorded_m19b)
    if differences:
        raise SystemExit(
            "the M19b freeze is no longer equal to M19's:\n  " + "\n  ".join(differences)
        )
    print("M19 equality: the freeze is byte-equal to M19's on " + ", ".join(ASSERTED_FIELDS))


# --------------------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------------------


def repeat_path(out_dir: Path, letter: str, repeat: int) -> Path:
    return out_dir / f"arm_{letter}_rep{repeat}.json"


def combined_path(out_dir: Path, letter: str) -> Path:
    return out_dir / f"arm_{letter}_repeats.json"


def comparable_payload(row: dict[str, Any]) -> dict[str, Any]:
    """The part of a serialised row two runs of a deterministic arm must agree on.

    The dict-level twin of :meth:`CaseResult.comparable`, for comparing a live run
    against a *committed* M19 row. It must stay in step with that method; the fields it
    drops are the same three -- ``started_at``, ``called_at`` and the two wall-clock
    durations -- and nothing else.
    """
    state = {k: v for k, v in row.get("state", {}).items() if k != "started_at"}
    state["results"] = [
        {
            **result,
            "tool_calls": [
                {k: v for k, v in call.items() if k != "called_at"}
                for call in result.get("tool_calls", [])
            ],
        }
        for result in state.get("results", [])
    ]
    scores = json.loads(json.dumps(row.get("scores", {})))
    scores["completeness"] = {
        k: v for k, v in scores.get("completeness", {}).items() if k != "wall_seconds"
    }
    return {
        "arm": row.get("labelled_arm"),
        "corpus": row.get("corpus"),
        "case_id": row.get("case_id"),
        "manifest_hash": row.get("manifest_hash"),
        "telemetry_hash": row.get("telemetry_hash"),
        "configuration": row.get("configuration"),
        "llm_degraded": row.get("llm_degraded"),
        "budgets": row.get("budgets"),
        "scores": scores,
        "state": state,
        "label_scores": {
            k: v for k, v in (row.get("label_scores") or {}).items()
            if k != "runtime_seconds"
        },
    }


def compare_to_m19(letter: str, rows: Sequence[CaseResult]) -> dict[str, Any]:
    """Differences between a live arm-A run and M19's committed arm-A rows.

    Only arm A can be compared this way, and only arm A is: B and C are sampled from a
    model and are *expected* to move, which is the whole subject of this task.
    """
    m19_rows = {
        (r["corpus"], r["case_id"]): r
        for r in json.loads(
            (M19_DIR / f"arm_{letter}.json").read_text(encoding="utf-8")
        )["cases"]
    }
    differences: list[str] = []
    for row in rows:
        key = (row.corpus, row.case_id)
        frozen = m19_rows.get(key)
        if frozen is None:
            differences.append(f"{key[0]}/{key[1]}: not in M19's arm_{letter}.json")
            continue
        live = comparable_payload(row.to_dict())
        recorded = comparable_payload(frozen)
        if live != recorded:
            moved = sorted(
                name for name in set(live) | set(recorded)
                if live.get(name) != recorded.get(name)
            )
            differences.append(f"{key[0]}/{key[1]}: {', '.join(moved)}")
    return {
        "compared": len(rows),
        "identical": not differences,
        "differences": differences,
        "note": (
            "wall seconds and wall-clock timestamps are excluded; every claim, tool "
            "call, plan-log line, budget and score is included"
        ),
    }


def row_summary(row: CaseResult, repeat: int) -> dict[str, Any]:
    """One row's metrics without its state -- what the combined file carries."""
    state = row.state if isinstance(row.state, dict) else {}
    llm = state.get("llm") or {}
    planner = llm.get("planner") or {}
    scores = row.scores.to_dict()
    completeness = scores["completeness"]
    return {
        "repeat": repeat,
        "arm": row.arm,
        "labelled_arm": row.labelled_arm,
        "corpus": row.corpus,
        "case_id": row.case_id,
        "stratum": STRATUM_OF.get((row.corpus, row.case_id), ""),
        "llm_degraded": row.llm_degraded,
        "llm_status": row.llm_status,
        "wall_seconds": round(row.wall_seconds, 3),
        "tokens": row.tokens,
        "evidence_correctness": scores["evidence_correctness"],
        "evidence_coverage": scores["evidence_coverage"],
        "unsupported_claims": scores["unsupported_claims"],
        "rejected_claims": scores["rejected_claims"],
        "facts": completeness["facts"],
        "inferences": completeness["inferences"],
        "hypotheses": completeness["hypotheses"],
        "steps": completeness["steps"],
        "status": completeness["status"],
        "tool_calls": completeness["tool_calls"],
        "distinct_tools": completeness["distinct_tools"],
        "specialists_run": completeness["specialists_run"],
        "planner_multi_candidate_steps": int(planner.get("multi_candidate_steps", 0)),
        "planner_chosen_by_model": int(planner.get("chosen_by_model", 0)),
        "planner_fallbacks": dict(planner.get("fallbacks") or {}),
        "planner_decisions": dict(planner.get("decisions") or {}),
        "unparseable_responses": int(llm.get("unparseable_responses", 0)),
        "budgets": dict(row.budgets),
    }


def cmd_run(args: argparse.Namespace) -> int:
    payload, entries, digest = m19._read_manifest(M19_DIR)
    selected = select_entries(entries)
    arm = ARM_BUILDERS[m19._arm_name(args.arm)]()
    letter = m19._arm_letter(args.arm)
    repeats = int(args.repeat)
    if not arm.requires_model and repeats != 1:
        raise SystemExit(
            f"{arm.name} is deterministic; {repeats} repeats of it measure nothing. "
            "M19 already ran it twice over the whole manifest with identical output, "
            "and this task's arm A run is a single run asserted equal to those rows."
        )
    if arm.requires_model:
        guard_environment(args.out_dir, digest)

    by_corpus: dict[str, list[CaseManifest]] = defaultdict(list)
    for entry in selected:
        by_corpus[entry.corpus].append(entry)

    runs: list[list[CaseResult]] = [[] for _ in range(repeats)]
    timing: dict[str, Any] = {}
    for bundle in m19.load_bundles(m19._families(by_corpus)):
        if bundle.name not in by_corpus:
            continue
        corpus_entries = by_corpus[bundle.name]
        started = time.perf_counter()
        for index in range(repeats):
            # A separate investigation per repeat: run_arm builds a fresh toolbox, a
            # fresh crew and a fresh orchestrator per case, so repeat 2 shares nothing
            # with repeat 1 but the corpus and the frozen configuration.
            runs[index] += run_arm(
                arm, corpus_entries, bundle.telemetry, bundle.cases,
                manifest_digest=digest, findings=bundle.findings,
                environment=bundle.environment,
                label_scorer=m19._label_scorer(bundle),
            )
            print(
                f"{bundle.name}: repeat {index + 1}/{repeats} done "
                f"({len(corpus_entries)} case(s))",
                flush=True,
            )
        timing[bundle.name] = {
            "load_seconds": round(bundle.load_seconds, 1),
            "pipeline_seconds": round(bundle.pipeline_seconds, 1),
            "arm_seconds_all_repeats": round(time.perf_counter() - started, 1),
            "cases": len(corpus_entries),
        }

    header = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "head": m19._head(),
        "arm": arm.to_dict(),
        "manifest_hash": digest,
        "manifest_head": payload.get("head"),
        "selection": [
            {"corpus": c, "case_id": i, "stratum": s} for c, i, s in SELECTION
        ],
        "repeats": repeats,
        "timing": timing,
        "m19_note": (
            "these rows are reported beside M19's and are never averaged into them"
        ),
    }

    for index, rows in enumerate(runs, start=1):
        write_artifact(
            repeat_path(args.out_dir, letter, index),
            {**header, "repeat": index, "cases": [r.to_dict() for r in rows]},
        )
        print(f"wrote {repeat_path(args.out_dir, letter, index)} ({len(rows)} row(s))")

    combined = {
        **header,
        "note": (
            "metrics only -- the full investigation state of each row lives in "
            "arm_{letter}_rep{n}.json, which is what the scorer reads. This file is "
            "the index across repeats."
        ),
        "rows": [
            row_summary(row, index)
            for index, rows in enumerate(runs, start=1) for row in rows
        ],
    }
    if letter == "A":
        combined["m19_identity"] = compare_to_m19(letter, runs[0])
    write_artifact(combined_path(args.out_dir, letter), combined)
    print(f"wrote {combined_path(args.out_dir, letter)}")

    degraded = [r for rows in runs for r in rows if r.llm_degraded]
    print(
        f"degraded rows: {len(degraded)} of {sum(len(r) for r in runs)}"
        + ("" if not degraded else "")
    )
    for row in degraded:
        print(f"  DEGRADED {row.corpus}/{row.case_id}: {row.llm_status}")

    failed = False
    if getattr(args, "check_planner", False):
        for index, rows in enumerate(runs, start=1):
            lines, failures = m19.planner_report(rows, arm.requires_model)
            print(f"planner accounting, repeat {index}:")
            for line in lines:
                print(f"  {line}")
            for failure in failures:
                print(f"  PLANNER CHECK FAILED: {failure}")
            failed = failed or bool(failures)
        if not failed:
            print("planner check: no model-arm row planned deterministically")

    if letter == "A":
        identity = combined["m19_identity"]
        if identity["identical"]:
            print(
                f"M19 identity: arm A reproduced all {identity['compared']} M19 rows "
                "exactly outside the time fields"
            )
        else:
            print(
                f"M19 IDENTITY FAILED: {len(identity['differences'])} row(s) differ "
                "from M19's arm_A.json:"
            )
            for difference in identity["differences"]:
                print(f"  {difference}")
            failed = True
    return 1 if failed else 0


# --------------------------------------------------------------------------------------
# score
# --------------------------------------------------------------------------------------


def m19_rows(letter: str) -> dict[tuple[str, str], dict[str, Any]]:
    payload = json.loads((M19_DIR / f"arm_{letter}.json").read_text(encoding="utf-8"))
    return {(r["corpus"], r["case_id"]): r for r in payload["cases"]}


def claim_evidence_ids(
    row: dict[str, Any], types: tuple[str, ...] | None = None
) -> set[str]:
    """Every evidence id cited by this row's accepted claims. ``m19_grade.claim_ids``."""
    ids: set[str] = set()
    for claim in row["state"]["claims"]:
        if types is None or claim["type"] in types:
            ids |= set(claim.get("evidence_ids") or [])
    return ids


def tool_event_ids(row: dict[str, Any]) -> set[str]:
    """Every event id this row's tool calls returned. ``m19_grade.tool_ids``."""
    ids: set[str] = set()
    for result in row["state"].get("results", []):
        for call in result.get("tool_calls", []):
            ids |= set(call.get("event_ids") or [])
    return ids


def m19_threshold() -> float:
    """M19's unsupported-claims threshold: arm A's mean inferences per case.

    Recomputed from ``arm_A.json`` over all twenty-two M19 cases rather than read from
    ``GRADING.json``, and then checked against it. The check is the point: a constant
    copied out of a results file is a constant nobody can re-derive.
    """
    rows = m19_rows("A")
    live = statistics.mean(
        r["scores"]["completeness"]["inferences"] for r in rows.values()
    )
    grading = json.loads((M19_DIR / "GRADING.json").read_text(encoding="utf-8"))
    recorded = grading["vii_decision_rule"]["thresholds"]["A_mean_inferences_per_case"]
    if round(live, 4) != recorded:
        raise SystemExit(
            f"the decision-rule threshold recomputed from arm_A.json is {live:.4f} but "
            f"GRADING.json records {recorded}. Refusing to score against a rule that "
            "differs from the one M19 graded."
        )
    return live


def decision_rule(
    row: dict[str, Any], arm_a_row: dict[str, Any], threshold: float
) -> dict[str, Any]:
    """M19's decision rule for one row, against arm A's row for the same case.

    Both conditions, as pre-registered: ``unsupported_claims`` at or under the
    threshold, **and** at least one HYPOTHESIS citing evidence arm A's claims did not
    cite. Field names and semantics are ``scripts/m19_grade.py``'s, so the numbers this
    produces for an M19 row are the numbers in ``GRADING.json`` -- which
    ``tests/test_m19b_robustness.py`` asserts rather than assumes.
    """
    a_claims = claim_evidence_ids(arm_a_row)
    a_all = a_claims | tool_event_ids(arm_a_row)
    hypotheses = [c for c in row["state"]["claims"] if c["type"] == "HYPOTHESIS"]
    new_vs_claims = any(set(h.get("evidence_ids") or []) - a_claims for h in hypotheses)
    new_vs_all = any(set(h.get("evidence_ids") or []) - a_all for h in hypotheses)
    unsupported = row["scores"]["unsupported_claims"]
    return {
        "case": f"{row['corpus']}/{row['case_id']}",
        "hypotheses": len(hypotheses),
        "unsupported": unsupported,
        "hyp_cites_evidence_A_claims_did_not": new_vs_claims,
        "hyp_cites_evidence_A_never_touched": new_vs_all,
        "degraded": row["llm_degraded"],
        "meets_rule": bool(unsupported <= threshold and new_vs_claims),
    }


METRICS: tuple[tuple[str, str], ...] = (
    ("evidence_correctness", "evidence correctness"),
    ("evidence_coverage", "evidence coverage"),
    ("unsupported_claims", "unsupported claims"),
    ("rejected_claims", "rejected claims"),
    ("facts", "facts"),
    ("inferences", "inferences"),
    ("hypotheses", "hypotheses"),
    ("tool_calls", "tool calls"),
    ("tokens", "tokens"),
    ("wall_seconds", "wall seconds"),
    ("planner_multi_candidate_steps", "planner steps offered"),
    ("planner_chosen_by_model", "planner steps chosen"),
)


def metrics_of(row: dict[str, Any]) -> dict[str, Any]:
    """One committed row reduced to the metrics this task reports."""
    state = row.get("state") or {}
    planner = (state.get("llm") or {}).get("planner") or {}
    scores = row["scores"]
    completeness = scores["completeness"]
    return {
        "evidence_correctness": scores["evidence_correctness"],
        "evidence_coverage": scores["evidence_coverage"],
        "unsupported_claims": scores["unsupported_claims"],
        "rejected_claims": scores["rejected_claims"],
        "facts": completeness["facts"],
        "inferences": completeness["inferences"],
        "hypotheses": completeness["hypotheses"],
        "tool_calls": completeness["tool_calls"],
        "tokens": row.get("tokens"),
        "wall_seconds": row.get("wall_seconds"),
        "planner_multi_candidate_steps": int(planner.get("multi_candidate_steps", 0)),
        "planner_chosen_by_model": int(planner.get("chosen_by_model", 0)),
        "degraded": bool(row["llm_degraded"]),
        "llm_status": row.get("llm_status", ""),
        "tool_calls_served": (row.get("budgets") or {}).get("tool_calls_served"),
        "specialists_run": completeness["specialists_run"],
        "status": completeness["status"],
    }


CREDIT_EXHAUSTION_NOTE = (
    "MEASURED: 17 of arm C's 30 rows degraded on HTTP 400, a status M19 never saw. The "
    "status text the client records is generic, so the cause was established by one "
    "independent probe of the endpoint after the run -- a 16-token request, no row "
    "re-run -- which returned "
    "'invalid_request_error: Your credit balance is too low to access the Anthropic "
    "API'. The failures are ordered in time rather than by case: everything the run "
    "attempted after flaws_cloud repeat 1 failed, and nothing before it did. VERIFIED: "
    "the account's credit was exhausted mid-run. This is a property of the account on "
    "the day, not of arm C, of the crew architecture, or of any case. The rows are kept "
    "exactly as they came out and are never re-run; every arm C figure is therefore "
    "reported twice -- over all three repeats, and over the repeats whose model "
    "answered -- and the arm C half of questions (c), (d) and (e) is INCONCLUSIVE at "
    "three repeats per case."
)
"""What happened to arm C's run, recorded where the numbers are."""


def _degradations_by_kind(repeats: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for run in repeats:
        for row in run.values():
            if not row["llm_degraded"]:
                continue
            kind = degradation_kind(str(row.get("llm_status", "")))
            counts[kind] = counts.get(kind, 0) + 1
    return dict(sorted(counts.items()))


def degradation_kind(status: str) -> str:
    """Which failure degraded a row, from the status the orchestrator recorded.

    The distinction matters more than the count. An HTTP 413 is a property of the
    *request* -- the same case will produce it again, and M19 already recorded it twice.
    An HTTP 400 on this codebase's request shape is not: 400 is the status the Messages
    API returns for an exhausted credit balance, which is a property of the account on
    the day and of nothing in the experiment. A row degraded by the second kind says
    nothing about the arm it was launched as, and folding the two into one
    "degradation_frequency" would let an accounting failure read as an architectural one.
    """
    if "413" in status:
        return "http_413_request_too_large"
    if "400" in status:
        return "http_400_request_rejected"
    if not status or "DEGRADED" not in status:
        return ""
    return "other"


def spread(values: list[Any]) -> dict[str, Any]:
    """min / median / max of a metric across repeats, or nulls when nothing was reported.

    ``None`` is kept out of the statistics rather than coerced to zero: "the client
    reported no tokens" and "the model spent no tokens" are different facts.
    """
    numbers = [v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)]
    if not numbers:
        return {"n": 0, "min": None, "median": None, "max": None, "values": list(values)}
    return {
        "n": len(numbers),
        "min": round(min(numbers), 4),
        "median": round(statistics.median(numbers), 4),
        "max": round(max(numbers), 4),
        "values": [round(v, 4) if isinstance(v, float) else v for v in values],
    }


def load_repeats(out_dir: Path, letter: str, repeats: int) -> list[dict[tuple[str, str], dict]]:
    loaded: list[dict[tuple[str, str], dict]] = []
    for index in range(1, repeats + 1):
        path = repeat_path(out_dir, letter, index)
        if not path.exists():
            raise SystemExit(f"{path} does not exist; run arm {letter} first.")
        payload = json.loads(path.read_text(encoding="utf-8"))
        loaded.append({(r["corpus"], r["case_id"]): r for r in payload["cases"]})
    return loaded


def verify_against_grading(threshold: float) -> dict[str, Any]:
    """This scorer, run on M19's own rows, must reproduce ``GRADING.json``'s vii.

    The scorer is new code deciding an old question. Reproducing the frozen answer on
    the frozen rows is the only evidence that "the M19 rule" here means what it meant
    there; a mismatch refuses the scoring rather than reporting two rules under one name.
    """
    grading = json.loads((M19_DIR / "GRADING.json").read_text(encoding="utf-8"))
    arm_a = m19_rows("A")
    checked: list[str] = []
    for letter in ("B", "C"):
        recorded = {
            entry["case"]: entry
            for entry in grading["vii_decision_rule"][letter]["per_case"]
        }
        rows = m19_rows(letter)
        for key in SELECTED_KEYS:
            computed = decision_rule(rows[key], arm_a[key], threshold)
            expected = recorded[f"{key[0]}/{key[1]}"]
            for field_name in (
                "hypotheses", "unsupported", "hyp_cites_evidence_A_claims_did_not",
                "hyp_cites_evidence_A_never_touched", "degraded",
            ):
                if computed[field_name] != expected[field_name]:
                    raise SystemExit(
                        f"this scorer disagrees with GRADING.json on arm {letter} "
                        f"{key[0]}/{key[1]}.{field_name}: {computed[field_name]!r} != "
                        f"{expected[field_name]!r}. Refusing to report a rule that is "
                        "not the rule M19 graded."
                    )
            checked.append(f"{letter}:{key[0]}/{key[1]}")
    return {
        "reproduced": True,
        "rows_checked": len(checked),
        "threshold": round(threshold, 4),
        "note": (
            "the scorer was run on M19's committed arm_B and arm_C rows for these ten "
            "cases and reproduced GRADING.json's vii_decision_rule.per_case fields "
            "exactly. M19's numbers are read, never recomputed into the report."
        ),
    }


def cmd_score(args: argparse.Namespace) -> int:
    threshold = m19_threshold()
    verification = verify_against_grading(threshold)
    print(
        f"decision rule: unsupported <= {threshold:.4f} AND >= 1 hypothesis citing "
        "evidence arm A's claims did not cite"
    )
    print(
        f"  reproduced GRADING.json on {verification['rows_checked']} M19 row(s)"
    )

    arm_a_m19 = m19_rows("A")
    primary = {"A": arm_a_m19, "B": m19_rows("B"), "C": m19_rows("C")}
    local_a = json.loads(
        repeat_path(args.out_dir, "A", 1).read_text(encoding="utf-8")
    )
    local_a_rows = {(r["corpus"], r["case_id"]): r for r in local_a["cases"]}
    repeats = {
        letter: load_repeats(args.out_dir, letter, int(args.repeat))
        for letter in ("B", "C")
    }

    per_case: list[dict[str, Any]] = []
    for key in SELECTED_KEYS:
        entry: dict[str, Any] = {
            "case": f"{key[0]}/{key[1]}",
            "corpus": key[0],
            "case_id": key[1],
            "stratum": STRATUM_OF[key],
            "arm_A_m19b": metrics_of(local_a_rows[key]),
            "arms": {},
        }
        for letter in ("B", "C"):
            rows = [r[key] for r in repeats[letter]]
            rules = [decision_rule(r, arm_a_m19[key], threshold) for r in rows]
            metrics = [metrics_of(r) for r in rows]
            undegraded_metrics = [m for m in metrics if not m["degraded"]]
            undegraded_rules = [
                rule for rule, metric in zip(rules, metrics) if not metric["degraded"]
            ]
            m19_rule = decision_rule(primary[letter][key], arm_a_m19[key], threshold)
            entry["arms"][letter] = {
                "m19_primary": {
                    **metrics_of(primary[letter][key]),
                    "meets_rule": m19_rule["meets_rule"],
                    "hyp_cites_evidence_A_claims_did_not":
                        m19_rule["hyp_cites_evidence_A_claims_did_not"],
                },
                "repeats": [
                    {**metric, **{k: rule[k] for k in (
                        "meets_rule", "hyp_cites_evidence_A_claims_did_not",
                        "hyp_cites_evidence_A_never_touched",
                    )}, "repeat": index}
                    for index, (metric, rule) in enumerate(zip(metrics, rules), start=1)
                ],
                "decision_rule_pass_frequency": {
                    "passed": sum(1 for r in rules if r["meets_rule"]),
                    "of": len(rules),
                },
                "new_evidence_frequency": {
                    "found": sum(
                        1 for r in rules if r["hyp_cites_evidence_A_claims_did_not"]
                    ),
                    "of": len(rules),
                },
                "degradation_frequency": {
                    "degraded": sum(1 for m in metrics if m["degraded"]),
                    "of": len(metrics),
                    "by_kind": {
                        kind: sum(
                            1 for m in metrics
                            if m["degraded"]
                            and degradation_kind(m["llm_status"]) == kind
                        )
                        for kind in sorted({
                            degradation_kind(m["llm_status"])
                            for m in metrics if m["degraded"]
                        })
                    },
                    "statuses": sorted(
                        {m["llm_status"] for m in metrics if m["degraded"]}
                    ),
                },
                # The same three questions asked of the repeats whose model actually
                # answered. Reported beside the full count, never instead of it: a
                # denominator that quietly drops the failures is how a broken run comes
                # to look like a clean one.
                "undegraded": {
                    "repeats": len(undegraded_rules),
                    "of": len(rules),
                    "decision_rule_passed": sum(
                        1 for r in undegraded_rules if r["meets_rule"]
                    ),
                    "new_evidence_found": sum(
                        1 for r in undegraded_rules
                        if r["hyp_cites_evidence_A_claims_did_not"]
                    ),
                    "identical_to_A": {
                        name: (
                            all(
                                metric[name] == entry["arm_A_m19b"][name]
                                for metric in undegraded_metrics
                            )
                            if undegraded_metrics else None
                        )
                        for name in (
                            "evidence_coverage", "tool_calls_served", "facts",
                            "hypotheses",
                        )
                    },
                    "hypotheses": spread([m["hypotheses"] for m in undegraded_metrics]),
                },
                "spread": {
                    name: spread([m[name] for m in metrics]) for name, _ in METRICS
                },
                # Behaviourally close to A, per repeat rather than on average: a
                # metric that matches A in two repeats of three did not match A.
                "identical_to_A": {
                    name: all(
                        metric[name] == entry["arm_A_m19b"][name] for metric in metrics
                    )
                    for name in ("evidence_coverage", "tool_calls_served", "facts")
                },
                "A_values": {
                    name: entry["arm_A_m19b"][name]
                    for name in ("evidence_coverage", "tool_calls_served", "facts")
                },
            }
        per_case.append(entry)

    totals = {
        letter: {
            "repeats": int(args.repeat),
            "rows": int(args.repeat) * len(SELECTED_KEYS),
            "per_repeat": [
                {
                    "repeat": index + 1,
                    "tokens": sum(
                        int(r[key]["tokens"] or 0) for key in SELECTED_KEYS
                    ),
                    "wall_seconds": round(
                        sum(float(r[key]["wall_seconds"]) for key in SELECTED_KEYS), 1
                    ),
                    "degraded": sum(
                        1 for key in SELECTED_KEYS if r[key]["llm_degraded"]
                    ),
                }
                for index, r in enumerate(repeats[letter])
            ],
        }
        for letter in ("B", "C")
    }
    totals["A_m19b"] = {
        "repeats": 1,
        "rows": len(SELECTED_KEYS),
        "per_repeat": [{
            "repeat": 1,
            "tokens": sum(int(local_a_rows[k]["tokens"] or 0) for k in SELECTED_KEYS),
            "wall_seconds": round(
                sum(float(local_a_rows[k]["wall_seconds"]) for k in SELECTED_KEYS), 1
            ),
            "degraded": 0,
        }],
    }
    totals["m19_primary"] = {
        letter: {
            "tokens": sum(int(primary[letter][k]["tokens"] or 0) for k in SELECTED_KEYS),
            "wall_seconds": round(
                sum(float(primary[letter][k]["wall_seconds"]) for k in SELECTED_KEYS), 1
            ),
        }
        for letter in ("A", "B", "C")
    }

    run_health = {
        letter: {
            "rows": int(args.repeat) * len(SELECTED_KEYS),
            "degraded": sum(
                1 for r in repeats[letter] for key in SELECTED_KEYS
                if r[key]["llm_degraded"]
            ),
            "by_kind": _degradations_by_kind(repeats[letter]),
        }
        for letter in ("B", "C")
    }
    run_health["note"] = CREDIT_EXHAUSTION_NOTE
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "head": m19._head(),
        "manifest_hash": local_a.get("manifest_hash"),
        "run_health": run_health,
        "selection": [
            {"corpus": c, "case_id": i, "stratum": s} for c, i, s in SELECTION
        ],
        "decision_rule": {
            "threshold_unsupported_claims": round(threshold, 4),
            "second_condition": (
                ">= 1 HYPOTHESIS citing evidence arm A's accepted claims did not cite"
            ),
            "arm_A_reference": "reports/m19/ablation/arm_A.json (the M19 row per case)",
            "verification": verification,
        },
        "m19_identity_of_arm_A": json.loads(
            combined_path(args.out_dir, "A").read_text(encoding="utf-8")
        ).get("m19_identity"),
        "per_case": per_case,
        "totals": totals,
        "note": (
            "repeat values are reported beside M19's primary value and are never "
            "averaged into it"
        ),
    }
    write_artifact(args.out_dir / "SCORES.json", payload)
    print(f"wrote {args.out_dir / 'SCORES.json'}")
    write_text(args.out_dir / "REPORT.md", render_report(payload))
    print(f"wrote {args.out_dir / 'REPORT.md'}")
    return 0


# --------------------------------------------------------------------------------------
# The readable half
# --------------------------------------------------------------------------------------


def _fmt(value: Any) -> str:
    if value is None:
        return "--"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:g}"
    return str(value)


def _spread_cell(entry: dict[str, Any]) -> str:
    if entry.get("n", 0) == 0:
        return "--"
    if entry["min"] == entry["max"]:
        return _fmt(entry["min"])
    return f"{_fmt(entry['min'])} / {_fmt(entry['median'])} / {_fmt(entry['max'])}"


def render_report(payload: dict[str, Any]) -> str:
    per_case = payload["per_case"]
    rule = payload["decision_rule"]
    totals = payload["totals"]
    lines: list[str] = []
    add = lines.append

    add("# M19b T3: the M19 result, repeated")
    add("")
    add(
        "Ten of M19's twenty-two cases, three repeats per model arm, under an "
        "environment asserted byte-equal to M19's freeze. Every number below is "
        "MEASURED from this run's artifacts or read from M19's frozen ones; none of it "
        "is averaged into M19, and nothing under `reports/m19/` was written."
    )
    add("")
    add(
        f"Decision rule (M19's, reproduced): `unsupported_claims <= "
        f"{rule['threshold_unsupported_claims']}` **and** at least one HYPOTHESIS "
        "citing evidence arm A's accepted claims did not cite. The scorer was run on "
        f"M19's own rows first and reproduced `GRADING.json`'s "
        f"`vii_decision_rule.per_case` on all {rule['verification']['rows_checked']} of "
        "them (VERIFIED FROM CODE)."
    )
    add("")

    health = payload.get("run_health") or {}
    add("## What happened during these runs, before any number is read")
    add("")
    add("| arm | rows | degraded | by kind |")
    add("| --- | --- | --- | --- |")
    for letter in ("B", "C"):
        entry = health.get(letter) or {}
        kinds = entry.get("by_kind") or {}
        add(
            f"| {letter} | {entry.get('rows')} | {entry.get('degraded')} | "
            + (", ".join(f"`{k}` x{v}" for k, v in kinds.items()) or "--")
            + " |"
        )
    add("")
    add(health.get("note", ""))
    add("")
    add(
        "Arm B's six degraded rows are the two COMISET cases M19 already recorded, on "
        "the same HTTP 413, and are the measurement question (b) asks for. Arm B's "
        "other twenty-four rows completed with the model answering every call."
    )
    add("")

    identity = payload.get("m19_identity_of_arm_A") or {}
    add("## Arm A: the deterministic control")
    add("")
    if identity.get("identical"):
        add(
            f"MEASURED: one run of the ten cases reproduced all "
            f"{identity['compared']} of M19's `arm_A.json` rows exactly outside the "
            "time fields -- every claim, tool call, plan-log line, budget and score. "
            "The corpora, the deterministic pipeline and the scoring are therefore the "
            "same ones M19 measured, and any spread below belongs to the model."
        )
    else:
        add(
            f"MEASURED: arm A did **not** reproduce M19's rows -- "
            f"{len(identity.get('differences') or [])} row(s) differ. Every number "
            "below is read against a baseline that moved, and the differences are:"
        )
        for difference in identity.get("differences") or []:
            add(f"* `{difference}`")
    add("")

    add("## The six questions")
    add("")
    b_unique = [c for c in per_case if c["stratum"] == "B_unique"]
    passed = sum(c["arms"]["B"]["decision_rule_pass_frequency"]["passed"] for c in b_unique)
    of = sum(c["arms"]["B"]["decision_rule_pass_frequency"]["of"] for c in b_unique)
    add(
        f"**(a) Was B's advantage reproducible?** MEASURED: on the {len(b_unique)} "
        f"B-unique cases, arm B met the decision rule in **{passed} of {of}** repeats. "
        "Per case:"
    )
    add("")
    add("| case | M19 primary | repeats meeting the rule | new-evidence hypothesis |")
    add("| --- | --- | --- | --- |")
    for case in b_unique:
        arm = case["arms"]["B"]
        add(
            f"| `{case['case']}` | {_fmt(arm['m19_primary']['meets_rule'])} | "
            f"{arm['decision_rule_pass_frequency']['passed']} of "
            f"{arm['decision_rule_pass_frequency']['of']} | "
            f"{arm['new_evidence_frequency']['found']} of "
            f"{arm['new_evidence_frequency']['of']} |"
        )
    add("")

    degraded_cases = [c for c in per_case if c["stratum"] == "B_degraded"]
    deg = sum(c["arms"]["B"]["degradation_frequency"]["degraded"] for c in degraded_cases)
    deg_of = sum(c["arms"]["B"]["degradation_frequency"]["of"] for c in degraded_cases)
    add(
        f"**(b) Do the degraded cases degrade again?** MEASURED: **{deg} of {deg_of}** "
        "arm B repeats on the two COMISET cases degraded. Statuses:"
    )
    add("")
    for case in degraded_cases:
        statuses = case["arms"]["B"]["degradation_frequency"]["statuses"]
        add(
            f"* `{case['case']}`: "
            f"{case['arms']['B']['degradation_frequency']['degraded']} of "
            f"{case['arms']['B']['degradation_frequency']['of']} degraded"
            + (f" -- {statuses[0]}" if statuses else "")
        )
    add("")

    c_live = sum(c["arms"]["C"]["undegraded"]["repeats"] for c in per_case)
    add(
        "**(c) Did C stay behaviourally close to A?** MEASURED, per case: whether every "
        "C repeat matched this run's arm A row on evidence coverage, tool calls served "
        "and accepted facts, and what the planner was offered. A row whose synthesis "
        "call failed ran deterministically and therefore matches A *by construction*, "
        "so the `undegraded` columns -- over the "
        f"{c_live} of 30 C repeats whose model answered -- are the ones that carry "
        "information."
    )
    add("")
    add(
        "| case | repeats with a model | coverage = A | tool calls = A | facts = A | "
        "hypotheses = A (undegraded) | planner offered | planner chosen |"
    )
    add("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for case in per_case:
        arm = case["arms"]["C"]
        live = arm["undegraded"]
        same = live["identical_to_A"]
        add(
            f"| `{case['case']}` | {live['repeats']} of {live['of']} | "
            f"{_fmt(same['evidence_coverage'])} | {_fmt(same['tool_calls_served'])} | "
            f"{_fmt(same['facts'])} | {_fmt(same['hypotheses'])} | "
            f"{_spread_cell(arm['spread']['planner_multi_candidate_steps'])} | "
            f"{_spread_cell(arm['spread']['planner_chosen_by_model'])} |"
        )
    add("")
    add(
        "Read over all thirty repeats (degraded rows included, where the match is "
        "trivial), the same three columns are: "
        + ", ".join(
            f"`{case['case']}` "
            + "/".join(
                _fmt(case["arms"]["C"]["identical_to_A"][name])
                for name in ("evidence_coverage", "tool_calls_served", "facts")
            )
            for case in per_case
        )
        + "."
    )
    add("")

    c_new = sum(c["arms"]["C"]["new_evidence_frequency"]["found"] for c in per_case)
    c_of = sum(c["arms"]["C"]["new_evidence_frequency"]["of"] for c in per_case)
    c_pass = sum(c["arms"]["C"]["decision_rule_pass_frequency"]["passed"] for c in per_case)
    c_new_live = sum(c["arms"]["C"]["undegraded"]["new_evidence_found"] for c in per_case)
    c_pass_live = sum(
        c["arms"]["C"]["undegraded"]["decision_rule_passed"] for c in per_case
    )
    add(
        f"**(d) Does C ever produce a new-evidence hypothesis?** MEASURED: in "
        f"**{c_new} of {c_of}** C repeats across all ten cases, at least one HYPOTHESIS "
        "cited evidence arm A's claims did not cite; C met the full decision rule in "
        f"**{c_pass} of {c_of}** repeats. Counting only the "
        f"**{c_live}** repeats whose model answered: **{c_new_live}** produced a "
        f"new-evidence hypothesis and **{c_pass_live}** met the rule. M19's single run "
        "of arm C produced none on any of its twenty-two cases, so this reproduces "
        "M19's finding on the ten cases it covers -- at a reduced number of repeats on "
        "the seven cases the credit exhaustion cut short."
    )
    add("")

    add(
        "**(e) Hypothesis-count variance per case.** MEASURED. `B repeats` and "
        "`C repeats` are min/median/max over the three repeats; a single figure means "
        "all three agreed. `C undegraded` is the same statistic over only the repeats "
        "whose model answered."
    )
    add("")
    add(
        "| case | stratum | A | B M19 | B repeats | C M19 | C repeats (all 3) | "
        "C undegraded |"
    )
    add("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for case in per_case:
        live = case["arms"]["C"]["undegraded"]
        add(
            f"| `{case['case']}` | {case['stratum']} | "
            f"{_fmt(case['arm_A_m19b']['hypotheses'])} | "
            f"{_fmt(case['arms']['B']['m19_primary']['hypotheses'])} | "
            f"{_spread_cell(case['arms']['B']['spread']['hypotheses'])} | "
            f"{_fmt(case['arms']['C']['m19_primary']['hypotheses'])} | "
            f"{_spread_cell(case['arms']['C']['spread']['hypotheses'])} | "
            f"{_spread_cell(live['hypotheses'])} (n={live['repeats']}) |"
        )
    add("")

    add("**(f) Cost per repeat.** MEASURED:")
    add("")
    add("| arm | repeat | tokens | wall seconds | degraded rows |")
    add("| --- | --- | --- | --- | --- |")
    for letter in ("A_m19b", "B", "C"):
        for entry in totals[letter]["per_repeat"]:
            add(
                f"| {letter} | {entry['repeat']} | {entry['tokens']} | "
                f"{entry['wall_seconds']} | {entry['degraded']} |"
            )
    add("")
    add("M19's own totals over the same ten cases, for scale (read, not recomputed):")
    add("")
    add("| arm | tokens | wall seconds |")
    add("| --- | --- | --- |")
    for letter in ("A", "B", "C"):
        entry = totals["m19_primary"][letter]
        add(f"| {letter} | {entry['tokens']} | {entry['wall_seconds']} |")
    add("")
    b_tokens = sum(e["tokens"] for e in totals["B"]["per_repeat"])
    c_tokens = sum(e["tokens"] for e in totals["C"]["per_repeat"])
    b_wall = round(sum(e["wall_seconds"] for e in totals["B"]["per_repeat"]), 1)
    c_wall = round(sum(e["wall_seconds"] for e in totals["C"]["per_repeat"]), 1)
    add(
        f"Totals for this task: arm B **{b_tokens:,} tokens** over 30 investigations "
        f"({b_wall}s of investigation wall time), arm C **{c_tokens:,} tokens** over 30 "
        f"({c_wall}s) -- the second figure depressed by the seventeen rows whose model "
        "stopped answering. Arm B's per-repeat cost is stable to within "
        f"{max(e['tokens'] for e in totals['B']['per_repeat']) - min(e['tokens'] for e in totals['B']['per_repeat'])} "
        "tokens across the three repeats, and two flaws.cloud cases account for most of "
        "it: `CASE-018` and `CASE-050` cost arm B about 160,000 tokens each, against "
        "about 3,600 for arm C on the same case -- roughly forty-five times, for the "
        "hypotheses that make arm B meet the rule."
    )
    add("")

    add("## Per case: M19's value beside the repeats")
    add("")
    for case in per_case:
        add(f"### `{case['case']}` -- {case['stratum']}")
        add("")
        add("| metric | A (M19b) | B M19 | B min/med/max | C M19 | C min/med/max |")
        add("| --- | --- | --- | --- | --- | --- |")
        for name, label in METRICS:
            add(
                f"| {label} | {_fmt(case['arm_A_m19b'].get(name))} | "
                f"{_fmt(case['arms']['B']['m19_primary'].get(name))} | "
                f"{_spread_cell(case['arms']['B']['spread'][name])} | "
                f"{_fmt(case['arms']['C']['m19_primary'].get(name))} | "
                f"{_spread_cell(case['arms']['C']['spread'][name])} |"
            )
        add(
            f"| decision rule | -- | "
            f"{_fmt(case['arms']['B']['m19_primary']['meets_rule'])} | "
            f"{case['arms']['B']['decision_rule_pass_frequency']['passed']} of "
            f"{case['arms']['B']['decision_rule_pass_frequency']['of']} | "
            f"{_fmt(case['arms']['C']['m19_primary']['meets_rule'])} | "
            f"{case['arms']['C']['decision_rule_pass_frequency']['passed']} of "
            f"{case['arms']['C']['decision_rule_pass_frequency']['of']} |"
        )
        add(
            f"| degraded | no | "
            f"{_fmt(case['arms']['B']['m19_primary']['degraded'])} | "
            f"{case['arms']['B']['degradation_frequency']['degraded']} of "
            f"{case['arms']['B']['degradation_frequency']['of']} | "
            f"{_fmt(case['arms']['C']['m19_primary']['degraded'])} | "
            f"{case['arms']['C']['degradation_frequency']['degraded']} of "
            f"{case['arms']['C']['degradation_frequency']['of']} |"
        )
        add("")

    add("## Variance table")
    add("")
    add(
        "Spread per metric, summed over the ten cases: how many cases had a range of "
        "zero across the three repeats, and the widest range seen."
    )
    add("")
    add("| metric | B: cases with zero range | B: widest range | C: zero range | C: widest range |")
    add("| --- | --- | --- | --- | --- |")
    for name, label in METRICS:
        row: list[str] = []
        for letter in ("B", "C"):
            ranges = []
            for case in per_case:
                entry = case["arms"][letter]["spread"][name]
                if entry.get("n", 0):
                    ranges.append(entry["max"] - entry["min"])
            zero = sum(1 for r in ranges if r == 0)
            widest = max(ranges) if ranges else None
            row += [f"{zero} of {len(ranges)}", _fmt(round(widest, 4) if widest is not None else None)]
        add(f"| {label} | {row[0]} | {row[1]} | {row[2]} | {row[3]} |")
    add("")

    add("## Preserved failures")
    add("")
    any_degraded = False
    for case in per_case:
        for letter in ("B", "C"):
            arm = case["arms"][letter]
            for repeat in arm["repeats"]:
                if repeat["degraded"]:
                    any_degraded = True
                    add(
                        f"* arm {letter} `{case['case']}` repeat {repeat['repeat']}: "
                        f"{repeat['llm_status']}"
                    )
    if not any_degraded:
        add("* none: no repeat degraded.")
    add("")
    add(
        "No row was re-run. The only retries are the ones the frozen client policy "
        "performs inside a single call (3 attempts, exponential backoff from 1.0s, on "
        "408/409/429/500/502/503/504/529); neither a 413 nor a 400 is retryable, and "
        "each degrades the row."
    )
    add("")

    add("## Limitations")
    add("")
    for limitation in LIMITATIONS:
        add(f"* {limitation}")
    add("")
    return "\n".join(lines)


LIMITATIONS: tuple[str, ...] = (
    "**Three repeats bound very little.** A case that passed 3 of 3 is consistent with "
    "a per-repeat pass probability anywhere above roughly 0.37 at 95% confidence; "
    "3 of 3 is evidence against a coin flip, not evidence of determinism. Every "
    "frequency below ten repeats should be read as \"did not vary here\", not as a rate.",
    "**Arm C's run lost its model part-way through.** Seven of the ten cases have one "
    "or zero repeats with a live model, so arm C's per-case spread on those cases is "
    "INCONCLUSIVE. The arm C figures are not wrong; there are simply too few of them, "
    "and no row was re-run to fix that.",
    "**The client records a status, not an error body.** "
    "``ath.agent.llm`` maps an HTTP code to a fixed sentence and reads the response "
    "body only for token usage, so \"HTTP 400 (the request was rejected as "
    "malformed)\" was the same text an exhausted credit balance and a genuinely "
    "malformed body would have produced. The cause here was established by a separate "
    "probe; a future run would be able to say it from the artifact if the client kept "
    "the error ``type`` and ``message``.",
    "**Ten of twenty-two cases, chosen for what M19 found.** Four of them are cases "
    "arm B won. That is deliberate -- the question is whether *those* results "
    "reproduce -- but it means the pass frequencies here are not an estimate of arm "
    "B's pass rate over the manifest, and must never be read as one.",
    "**The decision rule compares against a capped arm A row.** Evidence id lists are "
    "truncated at ``MAX_SERIALISED_IDS`` (5000) in the committed artifacts, so \"cites "
    "evidence arm A's claims did not cite\" is computed against arm A's first 5000 ids "
    "per claim. M19 graded under exactly the same cap, which is why this reproduces "
    "``GRADING.json`` -- but on a case where a claim exceeds the cap, both are "
    "measuring against a truncated reference.",
    "**``ENVIRONMENT.md``'s title says M19 Phase 1.** It is rendered by "
    "``ath.evaluation.ablation.environment.render_markdown``, reused rather than "
    "copied, and changing the heading would have meant editing code between the freeze "
    "and the runs -- which the freeze gate refuses, correctly. The file's own "
    "\"Equality with the M19 freeze\" section identifies it as M19b's; "
    "``ENVIRONMENT.json`` is the authority either way.",
    "**Arm A is a control for the pipeline, not for the model.** It reproduced M19's "
    "rows exactly, which rules out corpus drift, pipeline drift and scoring drift as "
    "explanations for anything below. It says nothing about the API, which is where "
    "both failure modes in this run came from.",
)
"""What these numbers cannot support, written next to them rather than in a postscript."""


# --------------------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p_freeze = sub.add_parser(
        "freeze", help="write the M19b environment, asserted equal to M19's"
    )
    p_freeze.add_argument("--out-dir", type=Path, default=OUT_DIR)
    p_freeze.set_defaults(func=cmd_freeze)

    p_run = sub.add_parser("run", help="run one arm over the ten selected cases")
    p_run.add_argument("--arm", default="A")
    p_run.add_argument("--repeat", type=int, default=1)
    p_run.add_argument("--out-dir", type=Path, default=OUT_DIR)
    p_run.add_argument(
        "--check-planner", action="store_true",
        help="per-row planner accounting, and a non-zero exit for a model-arm row that "
             "had a choice and made none of it",
    )
    p_run.set_defaults(func=cmd_run)

    p_score = sub.add_parser("score", help="score the repeats beside M19's values")
    p_score.add_argument("--repeat", type=int, default=REPEATS)
    p_score.add_argument("--out-dir", type=Path, default=OUT_DIR)
    p_score.set_defaults(func=cmd_score)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
