"""V1 local tier: freeze, run and summarise a local arm over the dev split, resumably.

Three commands, in order::

    python scripts/local_ablation.py freeze    --model qwen3.5:4b
    python scripts/local_ablation.py run       --model qwen3.5:4b --arm D1 [--repeat 1 --seed 0]
    python scripts/local_ablation.py summarise --model qwen3.5:4b --arm D1

What is reused and what is new
-------------------------------
The arms, the run loop, the equal-footing assertion, the scoring, the corpus loaders and the
hosted freeze are all imported: ``run_arm`` runs one case exactly as it ran every M19 and
M19b row. New is only what the V1 plan added: a local arm (``arm_d1``), a local section in
the freeze (model digest, daemon version, sampling), a **row store** (one file per
``RowKey``; a key whose file already parses is skipped; a degraded row is written and never
retried), a **RAM guard** before every row, and a summary that reports the V1 guardrails.

Nothing here writes under ``reports/m19/`` or ``reports/m19b/``; every path goes through
``refuse_frozen_path``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import local_manifest  # noqa: E402
import m19_ablation as m19  # noqa: E402
from m19b_ablation import required_footing_for  # noqa: E402

from ath.agent.llm import LLMClient  # noqa: E402
from ath.agent.ollama_llm import OllamaLLM, OllamaUnavailable, Sampling  # noqa: E402
from ath.agent.orchestrator import PLANNER_SYSTEM  # noqa: E402
from ath.evaluation.ablation import CaseManifest, CaseResult, build_client, run_arm  # noqa: E402
from ath.evaluation.ablation.environment import tool_surface  # noqa: E402
from ath.evaluation.ablation.local import (  # noqa: E402
    ARM_D1,
    GIB,
    LOCAL_ARM_BUILDERS,
    ModelSpec,
    RamVerdict,
    RowKey,
    available_ram_bytes,
    check_local_environment,
    check_ram,
    completed_rows,
    is_complete,
    local_environment,
    ram_floor_for,
    refuse_frozen_path,
    row_path,
    write_row,
)
from ath.evaluation.ablation.scoring import (  # noqa: E402
    aggregate,
    planner_activation,
    scores_from_dict,
)

DEV_DIR = local_manifest.DEV_DIR
ENVIRONMENT_JSON = "ENVIRONMENT.json"
ARM_LETTERS = {"D1": ARM_D1}

COMPLETION_TARGET = 0.95
"""The V1 guardrail: completed-case rate >= 95 %."""
CORRECTNESS_FLOOR = 0.99
"""The V1 guardrail: evidence correctness >= 0.99 on every row."""


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


def _head() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def model_slug(model: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in model)


def rows_dir(out_dir: Path, arm_letter: str, model: str) -> Path:
    return Path(out_dir) / "rows" / f"{arm_letter}_{model_slug(model)}"


def environment_path(out_dir: Path, model: str) -> Path:
    return Path(out_dir) / f"ENVIRONMENT_{model_slug(model)}.json"


def build_arm(letter: str, model: str, sampling: Sampling):
    try:
        builder = LOCAL_ARM_BUILDERS[ARM_LETTERS[letter]]
    except KeyError as exc:
        raise SystemExit(f"unknown local arm {letter!r}; known: {sorted(ARM_LETTERS)}") from exc
    return builder(model, sampling=sampling)


def _write_json(path: Path, payload: Any) -> None:
    path = refuse_frozen_path(path, ROOT)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path = refuse_frozen_path(path, ROOT)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")


# --------------------------------------------------------------------------------------
# freeze
# --------------------------------------------------------------------------------------


def cmd_freeze(args: argparse.Namespace) -> int:
    payload, entries, digest = local_manifest.read_manifest(args.out_dir)
    client = OllamaLLM(args.model, base_url=args.base_url, sampling=Sampling(args.temperature, args.seed), think=args.think)
    try:
        described = client.describe()
    except OllamaUnavailable as exc:
        raise SystemExit(f"REFUSED: {exc}") from exc
    arm = build_arm(args.arm, args.model, Sampling(args.temperature, args.seed))
    frozen = local_environment(
        ROOT, manifest_hash=digest, arm=arm, described=described,
        manifest_head=str(payload.get("head", "")), available_ram=available_ram_bytes(),
    )
    frozen["frozen_at"] = _now()
    frozen["arm_letter"] = args.arm
    path = environment_path(args.out_dir, args.model)
    _write_json(path, frozen)
    print(
        f"froze {args.model} (digest {str(described.get('digest'))[:12]}, daemon "
        f"{described.get('daemon_version')}) against manifest {digest[:12]} -> {path}",
        file=sys.stderr,
    )
    return 0


def read_environment(out_dir: Path, model: str) -> dict[str, Any]:
    path = environment_path(out_dir, model)
    if not path.exists():
        raise SystemExit(f"{path} does not exist; run `freeze --model {model}` first")
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------------------


class Interrupted(RuntimeError):
    """The run stopped on purpose (``--stop-after``) or on Ctrl-C; rows written stay."""


GUARD_EVENTS = "GUARD_EVENTS.jsonl"
"""One line per RAM-guard refusal or override, beside the rows. A refusal writes no row, so
without this file the summary could not say how often the guard fired."""


def record_guard_event(path: Path, case_key: str, repeat: int, verdict: RamVerdict, *, overridden: bool) -> None:
    path = refuse_frozen_path(path, ROOT)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({
            "at": _now(), "case": case_key, "repeat": repeat, "overridden": overridden, **verdict.to_dict(),
        }) + "\n")


def guard_events(directory: Path) -> list[dict[str, Any]]:
    path = Path(directory) / GUARD_EVENTS
    if not path.exists():
        return []
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


def _classify_calls(calls: Sequence[dict[str, Any]], requests: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each token-log entry with the kind of call it was, read off the paired request size.

    Planner and synthesis are told apart by the system prompt's length, which the request
    observer records and the two frozen system prompts differ in. Paired by position, as
    ``request_records`` pairs them; when the lists do not align the kind is ``unknown``.
    """
    aligned = len(calls) == len(requests)
    out: list[dict[str, Any]] = []
    for index, call in enumerate(calls):
        kind = "unknown"
        if aligned:
            kind = "planner" if requests[index].get("system_chars") == len(PLANNER_SYSTEM) else "synthesis"
        out.append({"kind": kind, **call})
    return out


def run_rows(
    *,
    arm: Any,
    client: LLMClient,
    spec: ModelSpec,
    entries: Sequence[CaseManifest],
    bundles: Iterable[Any],
    manifest_digest: str,
    rows_directory: Path,
    header: dict[str, Any],
    repeats: Sequence[int],
    seed: int | None,
    surface: Sequence[str],
    ram_floor: int | None,
    ram_reader: Callable[[], int | None] = available_ram_bytes,
    resident_reader: Callable[[], int] | None = None,
    stop_after: int | None = None,
    ignore_ram_floor: bool = False,
    log: Callable[[str], None] = lambda text: print(text, file=sys.stderr, flush=True),
) -> dict[str, int]:
    """The resumable loop. Returns ``{"ran", "skipped", "degraded"}``.

    Pure with respect to configuration: every knob is an argument, so a test can drive it
    with a scripted client over a fixture corpus and a temporary directory.
    """
    by_corpus: dict[str, list[CaseManifest]] = defaultdict(list)
    for entry in entries:
        by_corpus[entry.corpus].append(entry)
    counts = {"ran": 0, "skipped": 0, "degraded": 0, "ram_guard_events": 0}
    events_path = Path(rows_directory) / GUARD_EVENTS

    for bundle in bundles:
        corpus_entries = by_corpus.get(bundle.name)
        if not corpus_entries:
            continue
        footing = required_footing_for(arm, corpus_entries[0].telemetry_hash, list(surface))
        for entry in corpus_entries:
            for repeat in repeats:
                key = RowKey(
                    corpus=entry.corpus, case_id=entry.case_id, arm=arm.name,
                    provider=spec.provider, model=spec.model, quantization=spec.quant_label,
                    repeat=repeat, seed=seed,
                )
                path = row_path(rows_directory, key)
                if is_complete(path):
                    counts["skipped"] += 1
                    log(f"skip  {entry.key} rep{repeat}: row exists ({path.name})")
                    continue
                resident = resident_reader() if resident_reader is not None else 0
                verdict = check_ram(ram_floor, ram_reader(), resident)
                if verdict.ok is False:
                    counts["ram_guard_events"] += 1
                    record_guard_event(events_path, entry.key, repeat, verdict, overridden=ignore_ram_floor)
                    if not ignore_ram_floor:
                        raise SystemExit(f"REFUSED before {entry.key}: {verdict.message}")
                    log(f"RAM guard overridden before {entry.key}: {verdict.message}")
                started = time.perf_counter()
                results = run_arm(
                    arm, [entry], bundle.telemetry, bundle.cases,
                    manifest_digest=manifest_digest, findings=bundle.findings,
                    environment=bundle.environment, llm=client,
                    label_scorer=m19._label_scorer(bundle), required_footing=footing,
                )
                result: CaseResult = results[0]
                calls = list(getattr(client, "token_log", None) or [])
                row_header = {
                    **header,
                    "written_at": _now(),
                    "repeat": repeat,
                    "seed": seed,
                    "ram_preflight": {**verdict.to_dict(), "overridden": bool(verdict.ok is False and ignore_ram_floor)},
                    "ram_after_bytes": ram_reader(),
                    "loop_wall_seconds": round(time.perf_counter() - started, 3),
                    "calls": _classify_calls(calls, result.state.get("llm", {}).get("requests", [])),
                }
                write_row(rows_directory, key, result, row_header, root=ROOT)
                counts["ran"] += 1
                if result.llm_degraded:
                    counts["degraded"] += 1
                log(
                    f"ran   {entry.key} rep{repeat}: {result.labelled_arm}, {len(calls)} call(s), "
                    f"{result.wall_seconds:.1f}s, tokens {result.tokens}, "
                    f"unparseable {result.state.get('llm', {}).get('unparseable_responses')}"
                )
                if stop_after is not None and counts["ran"] >= stop_after:
                    raise Interrupted(f"stopped after {counts['ran']} newly completed row(s), as asked")
    return counts


def cmd_run(args: argparse.Namespace) -> int:
    payload, entries, digest = local_manifest.read_manifest(args.out_dir)
    frozen = read_environment(args.out_dir, args.model)
    sampling = Sampling(args.temperature, args.seed)
    arm = build_arm(args.arm, args.model, sampling)
    client = build_client(arm)
    if args.base_url != client.base_url:  # type: ignore[attr-defined]
        client = OllamaLLM(args.model, base_url=args.base_url, sampling=sampling, think=args.think)
    try:
        described = client.describe()  # type: ignore[attr-defined]
    except OllamaUnavailable as exc:
        raise SystemExit(f"REFUSED: {exc}") from exc
    drift = check_local_environment(frozen, manifest_hash=digest, described=described)
    if drift:
        raise SystemExit(
            "REFUSED: the live world differs from the freeze:\n  " + "\n  ".join(drift)
            + "\n\nEither restore it or freeze again and record why."
        )
    spec = ModelSpec.from_description(described)
    directory = refuse_frozen_path(rows_dir(args.out_dir, args.arm, args.model), ROOT)
    header = {
        "head": _head(),
        "frozen_head": (frozen.get("git") or {}).get("short_commit"),
        "arm": arm.to_dict(),
        "model": spec.to_dict(),
        "daemon_version": described.get("daemon_version"),
        "client_configuration": described.get("configuration"),
        "manifest_hash": digest,
        "manifest_head": payload.get("head"),
    }
    repeats = list(range(1, args.repeat + 1))
    log = lambda text: print(text, file=sys.stderr, flush=True)  # noqa: E731
    started = time.perf_counter()
    try:
        counts = run_rows(
            arm=arm, client=client, spec=spec, entries=entries,
            bundles=local_manifest.dev_bundles(args.external, corpora={e.corpus for e in entries}),
            manifest_digest=digest, rows_directory=directory, header=header, repeats=repeats,
            seed=args.seed, surface=tool_surface(), ram_floor=ram_floor_for(spec.parameter_size),
            resident_reader=client.resident_bytes,  # type: ignore[attr-defined]
            stop_after=args.stop_after, ignore_ram_floor=args.ignore_ram_floor, log=log,
        )
    except Interrupted as exc:
        log(f"INTERRUPTED: {exc}; completed rows are on disk and a rerun will skip them")
        return 3
    except KeyboardInterrupt:
        log("INTERRUPTED by Ctrl-C; completed rows are on disk and a rerun will skip them")
        return 130
    log(
        f"done in {time.perf_counter() - started:.0f}s: ran {counts['ran']}, skipped "
        f"{counts['skipped']}, degraded {counts['degraded']}, RAM guard events "
        f"{counts['ram_guard_events']} -> {directory}"
    )
    return 0


# --------------------------------------------------------------------------------------
# summarise
# --------------------------------------------------------------------------------------


def _median(values: Sequence[float | None]) -> float | None:
    present = [v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)]
    return round(statistics.median(present), 3) if present else None


def _p95(values: Sequence[float | None]) -> float | None:
    present = sorted(v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool))
    if not present:
        return None
    index = max(0, min(len(present) - 1, int(round(0.95 * (len(present) - 1)))))
    return round(present[index], 3)


def row_summary(payload: dict[str, Any]) -> dict[str, Any]:
    """One row's reportable facts, read from integers and sets; never from prose."""
    row = payload["row"]
    header = payload.get("header") or {}
    state = row.get("state") or {}
    llm = state.get("llm") or {}
    calls = header.get("calls") or []
    scores = scores_from_dict(row["scores"])
    errors = list(llm.get("errors") or [])
    context_refusals = [e for e in errors if "exceeds num_ctx" in e]
    by_kind: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for call in calls:
        by_kind[call.get("kind", "unknown")].append(call)

    def kind_stats(kind: str) -> dict[str, Any]:
        entries = by_kind.get(kind, [])
        return {
            "calls": len(entries),
            "median_total_seconds": _median([c.get("total_seconds") for c in entries]),
            "median_prompt_eval_seconds": _median([c.get("prompt_eval_seconds") for c in entries]),
            "median_eval_seconds": _median([c.get("eval_seconds") for c in entries]),
            "median_prompt_tokens_per_second": _median([c.get("prompt_tokens_per_second") for c in entries]),
            "median_eval_tokens_per_second": _median([c.get("eval_tokens_per_second") for c in entries]),
            "prompt_tokens": sum(c.get("input_tokens") or 0 for c in entries),
            "completion_tokens": sum(c.get("output_tokens") or 0 for c in entries),
            "unsent": sum(1 for c in entries if c.get("sent") is False),
        }

    unparseable = int(llm.get("unparseable_responses") or 0)
    model_calls = len(calls)
    degraded = bool(row.get("llm_degraded"))
    completed_strict = not degraded and unparseable == 0 and not context_refusals
    return {
        "key": payload["key"],
        "labelled_arm": row.get("labelled_arm"),
        "status": state.get("status"),
        "degraded": degraded,
        "degradation_reason": errors[0] if errors else None,
        "errors": errors,
        "context_refusals": len(context_refusals),
        "unparseable_responses": unparseable,
        "unparseable_by_kind": dict(llm.get("unparseable_by_kind") or {}),
        "model_calls": model_calls,
        "parse_ok_calls": max(0, model_calls - unparseable - len(context_refusals)),
        "completed_strict": completed_strict,
        "wall_seconds": row.get("wall_seconds"),
        "tokens": row.get("tokens"),
        "planner": kind_stats("planner"),
        "synthesis": kind_stats("synthesis"),
        "planner_activation": planner_activation(state) if state else {},
        "ram": {
            "preflight_available_bytes": (header.get("ram_preflight") or {}).get("available_bytes"),
            "preflight_resident_bytes": (header.get("ram_preflight") or {}).get("resident_bytes"),
            "after_bytes": header.get("ram_after_bytes"),
            "guard_ok": (header.get("ram_preflight") or {}).get("ok"),
        },
        "scores": {
            "evidence_correctness": scores.evidence_correctness,
            "evidence_coverage": scores.evidence_coverage,
            "rejected_claims": scores.rejected_claims,
            "unsupported_claims": sum((scores.unsupported_claims or {}).values()) if isinstance(scores.unsupported_claims, dict) else scores.unsupported_claims,
            "facts": scores.facts, "inferences": scores.inferences, "hypotheses": scores.hypotheses,
            "tool_calls": scores.tool_calls,
            "technique_jaccard": scores.technique_jaccard,
        },
        "label_scores": {k: v for k, v in (row.get("label_scores") or {}).items() if k in ("passed", "event_recall", "verdict_correct", "incident_id")},
        "budgets": row.get("budgets"),
        "counts": state.get("counts"),
    }


def summarise(rows: Sequence[dict[str, Any]], expected_cases: int, events: Sequence[dict[str, Any]] = ()) -> dict[str, Any]:
    per_row = [row_summary(r) for r in rows]
    walls = [r["wall_seconds"] for r in per_row]
    model_calls = sum(r["model_calls"] for r in per_row)
    parse_ok = sum(r["parse_ok_calls"] for r in per_row)
    completed = sum(1 for r in per_row if r["completed_strict"])
    ec = [r["scores"]["evidence_correctness"] for r in per_row]
    all_calls = [c for r in rows for c in ((r.get("header") or {}).get("calls") or [])]
    failure_types: Counter = Counter()
    for r in per_row:
        for error in r["errors"]:
            if "exceeds num_ctx" in error:
                failure_types["context_budget_refusal"] += 1
            elif error.startswith("HTTP"):
                failure_types["http_" + error.split()[1]] += 1
            elif "truncated" in error:
                failure_types["generation_cap"] += 1
            elif "no text" in error:
                failure_types["no_text"] += 1
            else:
                failure_types["other:" + error[:40]] += 1
    return {
        "rows_written": len(per_row),
        "expected_cases": expected_cases,
        "completed_strict": completed,
        "completion_rate": round(completed / expected_cases, 3) if expected_cases else None,
        "meets_completion_target": (completed / expected_cases >= COMPLETION_TARGET) if expected_cases else None,
        "degraded_rows": sum(1 for r in per_row if r["degraded"]),
        "rows_with_unparseable": sum(1 for r in per_row if r["unparseable_responses"]),
        "rows_with_context_refusals": sum(1 for r in per_row if r["context_refusals"]),
        "model_calls": model_calls,
        "unparseable_responses": sum(r["unparseable_responses"] for r in per_row),
        "context_refusals": sum(r["context_refusals"] for r in per_row),
        "parse_rate": round(parse_ok / model_calls, 3) if model_calls else None,
        "total_wall_seconds": round(sum(w or 0 for w in walls), 1),
        "median_case_wall_seconds": _median(walls),
        "p95_case_wall_seconds": _p95(walls),
        "tokens_total": sum(r["tokens"] or 0 for r in per_row),
        "prompt_tokens_total": sum(c.get("input_tokens") or 0 for c in all_calls),
        "completion_tokens_total": sum(c.get("output_tokens") or 0 for c in all_calls),
        "median_prompt_tokens_per_second": _median([c.get("prompt_tokens_per_second") for c in all_calls]),
        "median_eval_tokens_per_second": _median([c.get("eval_tokens_per_second") for c in all_calls]),
        "planner_median_seconds": _median([c.get("total_seconds") for c in all_calls if c.get("kind") == "planner"]),
        "synthesis_median_seconds": _median([c.get("total_seconds") for c in all_calls if c.get("kind") == "synthesis"]),
        "ram_min_available_bytes": min(
            (v for r in per_row for v in (r["ram"]["preflight_available_bytes"], r["ram"]["after_bytes"]) if isinstance(v, int)),
            default=None,
        ),
        "ram_guard_events": len(events),
        "ram_guard_refusals": sum(1 for e in events if not e.get("overridden")),
        "ram_guard_overrides": sum(1 for e in events if e.get("overridden")),
        "rows_run_under_override": sum(1 for r in rows if ((r.get("header") or {}).get("ram_preflight") or {}).get("overridden")),
        "evidence_correctness_min": min((v for v in ec if v is not None), default=None),
        "evidence_correctness_all_at_least_floor": all(v is not None and v >= CORRECTNESS_FLOOR for v in ec) if ec else None,
        "rejected_claims_total": sum(r["scores"]["rejected_claims"] or 0 for r in per_row),
        "planner_model_chosen_steps": sum((r["planner_activation"] or {}).get("chosen_by_model", 0) or 0 for r in per_row),
        "planner_multi_candidate_steps": sum((r["planner_activation"] or {}).get("multi_candidate_steps", 0) or 0 for r in per_row),
        "failure_types": dict(failure_types),
        "rows": per_row,
    }


def render_summary(summary: dict[str, Any], *, arm: str, model: str, head: str) -> str:
    def gib(value: Any) -> str:
        return f"{value / GIB:.2f}" if isinstance(value, int) else "--"

    lines = [
        f"# D1 baseline summary: arm {arm}, `{model}`",
        "",
        f"Generated {_now()} at `{head}` from {summary['rows_written']} row file(s). MEASURED; no interpretation.",
        "",
        "| aggregate | value |", "| --- | --- |",
        [f"completed (strict: not degraded, 0 unparseable, 0 context refusals)", f"{summary['completed_strict']} / {summary['expected_cases']} ({summary['completion_rate']})"],
        [f"meets >= {COMPLETION_TARGET:.0%} completion target", summary["meets_completion_target"]],
        ["rows written / degraded", f"{summary['rows_written']} / {summary['degraded_rows']}"],
        ["model calls / unparseable / context refusals", f"{summary['model_calls']} / {summary['unparseable_responses']} / {summary['context_refusals']}"],
        ["parse rate", summary["parse_rate"]],
        ["total wall s", summary["total_wall_seconds"]],
        ["median / p95 case wall s", f"{summary['median_case_wall_seconds']} / {summary['p95_case_wall_seconds']}"],
        ["planner / synthesis median call s", f"{summary['planner_median_seconds']} / {summary['synthesis_median_seconds']}"],
        ["tokens total (prompt / completion)", f"{summary['tokens_total']} ({summary['prompt_tokens_total']} / {summary['completion_tokens_total']})"],
        ["median prompt / gen tok/s", f"{summary['median_prompt_tokens_per_second']} / {summary['median_eval_tokens_per_second']}"],
        ["min available RAM seen (GiB)", gib(summary["ram_min_available_bytes"])],
        ["RAM guard events (refusals / overrides) / rows run under override", f"{summary['ram_guard_events']} ({summary['ram_guard_refusals']} / {summary['ram_guard_overrides']}) / {summary['rows_run_under_override']}"],
        ["evidence correctness min / all >= 0.99", f"{summary['evidence_correctness_min']} / {summary['evidence_correctness_all_at_least_floor']}"],
        ["rejected claims total", summary["rejected_claims_total"]],
        ["planner steps chosen by model / multi-candidate", f"{summary['planner_model_chosen_steps']} / {summary['planner_multi_candidate_steps']}"],
        ["failure types", json.dumps(summary["failure_types"])],
    ]
    out = []
    for line in lines:
        out.append(f"| {line[0]} | {line[1]} |" if isinstance(line, list) else line)
    out += [
        "",
        "## Per case",
        "",
        "| case | arm label | status | calls | unparse | ctx ref | wall s | tokens | ec | rejected | coverage | facts/inf/hyp | model-chosen steps | degradation |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | --- |",
    ]
    for r in summary["rows"]:
        k = r["key"]
        s = r["scores"]
        out.append(
            f"| {k['corpus']}/{k['case_id']} | {r['labelled_arm']} | {r['status']} | {r['model_calls']} | "
            f"{r['unparseable_responses']} | {r['context_refusals']} | {r['wall_seconds']} | {r['tokens']} | "
            f"{s['evidence_correctness']} | {s['rejected_claims']} | {s['evidence_coverage']} | "
            f"{s['facts']}/{s['inferences']}/{s['hypotheses']} | {(r['planner_activation'] or {}).get('chosen_by_model')} | "
            f"{(r['degradation_reason'] or '')[:60]} |"
        )
    return "\n".join(out)


def cmd_summarise(args: argparse.Namespace) -> int:
    payload, entries, digest = local_manifest.read_manifest(args.out_dir)
    directory = rows_dir(args.out_dir, args.arm, args.model)
    wanted = {(e.corpus, e.case_id) for e in entries}
    rows = [
        r for r in completed_rows(directory)
        if (r["key"]["corpus"], r["key"]["case_id"]) in wanted
        and r["key"]["model"] == args.model and r["key"]["repeat"] == args.repeat
        and r["row"].get("manifest_hash") == digest
    ]
    summary = summarise(rows, expected_cases=len(entries), events=guard_events(directory))
    summary.update({"arm": args.arm, "model": args.model, "manifest_hash": digest, "repeat": args.repeat, "head": _head()})
    stem = f"SUMMARY_{args.arm}_{model_slug(args.model)}_rep{args.repeat}"
    _write_json(args.out_dir / f"{stem}.json", summary)
    _write_text(args.out_dir / f"{stem}.md", render_summary(summary, arm=args.arm, model=args.model, head=summary["head"]))
    print(json.dumps({k: v for k, v in summary.items() if k != "rows"}, indent=1, default=str))
    return 0


# --------------------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--model", default="qwen3.5:4b")
        p.add_argument("--arm", default="D1", choices=sorted(ARM_LETTERS))
        p.add_argument("--out-dir", type=Path, default=DEV_DIR)
        p.add_argument("--base-url", default="http://127.0.0.1:11434")
        p.add_argument("--temperature", type=float, default=0.0)
        p.add_argument("--seed", type=int, default=0)
        p.add_argument("--think", action="store_true")

    p_freeze = sub.add_parser("freeze"); common(p_freeze); p_freeze.set_defaults(func=cmd_freeze)
    p_run = sub.add_parser("run"); common(p_run)
    p_run.add_argument("--external", type=Path, default=local_manifest.DEFAULT_EXTERNAL)
    p_run.add_argument("--repeat", type=int, default=1)
    p_run.add_argument("--stop-after", type=int, default=None, help="stop after N newly completed rows (a controlled interruption)")
    p_run.add_argument("--ignore-ram-floor", action="store_true", help="run below the RAM floor; every such row and event is recorded as overridden")
    p_run.set_defaults(func=cmd_run)
    p_sum = sub.add_parser("summarise"); common(p_sum)
    p_sum.add_argument("--repeat", type=int, default=1)
    p_sum.set_defaults(func=cmd_summarise)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
