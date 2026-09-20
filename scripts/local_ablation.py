"""V1 local tier: freeze, run and summarise a local arm over the dev split, resumably.

Three commands, in order::

    python scripts/local_ablation.py freeze    --model qwen3.5:4b
    python scripts/local_ablation.py run       --model qwen3.5:4b --arm D1 [--repeat 1 --seed 0]
    python scripts/local_ablation.py summarise --model qwen3.5:4b --arm D1

What is reused and what is new
-------------------------------
The equal-footing assertion, the scoring, the corpus loaders and the hosted freeze are all
imported. ``run_local_arm`` runs one case with the D1 investigator under the same
manifest check, footing, accounting and row shape as ``run_arm``. New since the first
preview: rows live under a directory named by the manifest hash and the investigator
prompt version, the row key carries the manifest hash, the freeze gates the investigator's
prompts and bounds, LINK scores are computed on the row's own state and stamped with the
hashes they were scored under, and the summary reports the investigation metrics
(discrimination, abstention, tool-choice diversity, new-evidence retrieval and use).

``run --only <corpus>/<case_id> ...`` runs a subset (the smoke set); the rows it writes
are ordinary rows and a later full run skips them.

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

from ath.agent.investigator import D1_PROMPT_VERSION, INVESTIGATOR_SYSTEM  # noqa: E402
from ath.agent.llm import LLMClient  # noqa: E402
from ath.agent.ollama_llm import OllamaUnavailable, Sampling  # noqa: E402
from ath.agent.orchestrator import PLANNER_SYSTEM  # noqa: E402
from ath.evaluation.ablation import CaseManifest, CaseResult, build_client  # noqa: E402
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
    investigator_environment,
    is_complete,
    local_environment,
    read_row,
    ram_floor_for,
    refuse_frozen_path,
    row_path,
    run_local_arm,
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


def rows_dir(out_dir: Path, arm_letter: str, model: str, manifest_digest: str = "", version: str = D1_PROMPT_VERSION) -> Path:
    """Where rows go: one directory per (arm, model, manifest, investigator version).

    The 2026-09-15 preview rows sit in the flat ``rows/D1_<model>/`` directory; they are
    keyed on a superseded manifest and are never read by a summary of this one. A change
    of manifest or of investigator prompts starts an empty directory, so rows produced
    under different prompts can never be summarised together.
    """
    base = Path(out_dir) / "rows" / f"{arm_letter}_{model_slug(model)}"
    if not manifest_digest:
        return base
    return base / f"m{manifest_digest[:12]}_{model_slug(version)}"


def environment_path(out_dir: Path, model: str) -> Path:
    return Path(out_dir) / f"ENVIRONMENT_{model_slug(model)}.json"


def build_arm(letter: str, model: str, sampling: Sampling, **client_kwargs: Any):
    try:
        builder = LOCAL_ARM_BUILDERS[ARM_LETTERS[letter]]
    except KeyError as exc:
        raise SystemExit(f"unknown local arm {letter!r}; known: {sorted(ARM_LETTERS)}") from exc
    return builder(model, sampling=sampling, **client_kwargs)


def links_by_case(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """The manifest's cross-domain links by ``corpus/case_id``. Labels for scoring only;
    they are handed to the runner beside the rows and never to the model."""
    out: dict[str, list[dict[str, Any]]] = {}
    for case in payload.get("cases") or ():
        links = case.get("links") or []
        if links:
            out[f"{case['corpus']}/{case['case_id']}"] = list(links)
    return out


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
    arm = build_arm(args.arm, args.model, Sampling(args.temperature, args.seed), base_url=args.base_url, think=args.think)
    client = build_client(arm)
    try:
        described = client.describe()  # type: ignore[attr-defined]
    except OllamaUnavailable as exc:
        raise SystemExit(f"REFUSED: {exc}") from exc
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
    by_length = {len(INVESTIGATOR_SYSTEM): "investigator", len(PLANNER_SYSTEM): "planner"}
    out: list[dict[str, Any]] = []
    for index, call in enumerate(calls):
        kind = "unknown"
        if aligned:
            kind = by_length.get(requests[index].get("system_chars"), "synthesis")
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
    residency_reader: Callable[[], dict[str, Any]] | None = None,
    stop_after: int | None = None,
    ignore_ram_floor: bool = False,
    links: dict[str, Sequence[dict[str, Any]]] | None = None,
    only: set[str] | None = None,
    log: Callable[[str], None] = lambda text: print(text, file=sys.stderr, flush=True),
) -> dict[str, int]:
    """The resumable loop. Returns ``{"ran", "skipped", "degraded"}``.

    Pure with respect to configuration: every knob is an argument, so a test can drive it
    with a scripted client over a fixture corpus and a temporary directory. ``only``
    restricts the run to the named ``corpus/case_id`` keys (the smoke set).
    """
    by_corpus: dict[str, list[CaseManifest]] = defaultdict(list)
    for entry in entries:
        if only is not None and entry.key not in only:
            continue
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
                    repeat=repeat, seed=seed, manifest_hash=manifest_digest,
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
                results = run_local_arm(
                    arm, [entry], bundle.telemetry, bundle.cases,
                    manifest_digest=manifest_digest, findings=bundle.findings,
                    environment=bundle.environment, llm=client,
                    label_scorer=m19._label_scorer(bundle), required_footing=footing,
                    links=links,
                )
                result: CaseResult = results[0]
                calls = list(getattr(client, "token_log", None) or [])
                row_header = {
                    **header,
                    "investigator": investigator_environment(),
                    "written_at": _now(),
                    "repeat": repeat,
                    "seed": seed,
                    "ram_preflight": {**verdict.to_dict(), "overridden": bool(verdict.ok is False and ignore_ram_floor)},
                    "model_residency": dict(residency_reader()) if residency_reader is not None else None,
                    "ram_after_bytes": ram_reader(),
                    "loop_wall_seconds": round(time.perf_counter() - started, 3),
                    "calls": _classify_calls(calls, result.state.get("llm", {}).get("requests", [])),
                }
                write_row(rows_directory, key, result, row_header, root=ROOT)
                counts["ran"] += 1
                if result.llm_degraded:
                    counts["degraded"] += 1
                investigation = result.state.get("investigation") or {}
                log(
                    f"ran   {entry.key} rep{repeat}: {result.labelled_arm}, {len(calls)} call(s), "
                    f"{result.wall_seconds:.1f}s, tokens {result.tokens}, "
                    f"unparseable {result.state.get('llm', {}).get('unparseable_responses')}, "
                    f"probes {investigation.get('probes_run')}, disposition "
                    f"{investigation.get('final_disposition')}, truncated {investigation.get('output_truncated')}"
                )
                if stop_after is not None and counts["ran"] >= stop_after:
                    raise Interrupted(f"stopped after {counts['ran']} newly completed row(s), as asked")
    return counts


def cmd_run(args: argparse.Namespace) -> int:
    payload, entries, digest = local_manifest.read_manifest(args.out_dir)
    frozen = read_environment(args.out_dir, args.model)
    sampling = Sampling(args.temperature, args.seed)
    arm = build_arm(args.arm, args.model, sampling, base_url=args.base_url, think=args.think)
    client = build_client(arm)
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
    directory = refuse_frozen_path(rows_dir(args.out_dir, args.arm, args.model, digest), ROOT)
    only = set(args.only) if args.only else None
    if only is not None:
        unknown = sorted(only - {e.key for e in entries})
        if unknown:
            raise SystemExit(f"--only names case(s) not in the manifest: {unknown}")
    header = {
        "head": _head(),
        "frozen_head": (frozen.get("git") or {}).get("short_commit"),
        "arm": arm.to_dict(),
        "model": spec.to_dict(),
        "daemon_version": described.get("daemon_version"),
        "client_configuration": described.get("configuration"),
        "manifest_hash": digest,
        "manifest_head": payload.get("head"),
        "prompt_version": D1_PROMPT_VERSION,
    }
    repeats = list(range(1, args.repeat + 1))
    log = lambda text: print(text, file=sys.stderr, flush=True)  # noqa: E731
    started = time.perf_counter()
    wanted_corpora = {e.corpus for e in entries if only is None or e.key in only}
    try:
        counts = run_rows(
            arm=arm, client=client, spec=spec, entries=entries,
            bundles=local_manifest.dev_bundles(args.external, corpora=wanted_corpora),
            manifest_digest=digest, rows_directory=directory, header=header, repeats=repeats,
            seed=args.seed, surface=tool_surface(), ram_floor=ram_floor_for(spec.parameter_size),
            resident_reader=client.resident_bytes,  # type: ignore[attr-defined]
            residency_reader=client.residency,  # type: ignore[attr-defined]
            stop_after=args.stop_after, ignore_ram_floor=args.ignore_ram_floor,
            links=links_by_case(payload), only=only, log=log,
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
# validate-rows: restored rows against the live freeze and manifest
# --------------------------------------------------------------------------------------


def row_provenance_problems(
    payload: dict[str, Any], *, model: str, manifest_digest: str, entries: Sequence[CaseManifest],
    frozen: dict[str, Any],
) -> list[str]:
    """Why this row is not a row of the experiment the live freeze and manifest describe.

    Empty when it is. Every check reads what the row recorded when it was written --
    the key, the header's model digest, daemon version, gated client configuration,
    prompt version and investigator hashes -- against what the freeze and the manifest
    say now. ``run`` skips any parseable row by path alone, so a row copied in from
    another session must pass this before it may stand in for a case.
    """
    key = payload["key"]
    row = payload["row"]
    header = payload.get("header") or {}
    by_key = {(e.corpus, e.case_id): e for e in entries}
    problems: list[str] = []
    entry = by_key.get((key.get("corpus"), key.get("case_id")))
    if entry is None:
        problems.append("case not in the manifest")
    elif row.get("telemetry_hash") != entry.telemetry_hash:
        problems.append("telemetry hash differs from the one the manifest pins for this case")
    if key.get("model") != model:
        problems.append(f"model {key.get('model')!r} is not {model!r}")
    if row.get("manifest_hash") != manifest_digest or key.get("manifest_hash") not in (manifest_digest, ""):
        problems.append("manifest hash differs from the live manifest")
    if header.get("prompt_version") != D1_PROMPT_VERSION:
        problems.append(f"prompt version {header.get('prompt_version')!r} is not {D1_PROMPT_VERSION!r}")
    if dict(header.get("investigator") or {}) != investigator_environment():
        problems.append("investigator prompt/schema/bounds hashes differ from the live code")
    local = frozen.get("local") or {}
    frozen_model = local.get("model") or {}
    row_model = header.get("model") or {}
    if row_model.get("digest") != frozen_model.get("digest"):
        problems.append("model digest differs from the freeze (different weights)")
    if header.get("daemon_version") != (local.get("daemon") or {}).get("version"):
        problems.append("daemon version differs from the freeze")
    frozen_conf = _gated_configuration_view(local.get("client_configuration") or {})
    row_conf = _gated_configuration_view(header.get("client_configuration") or {})
    for name in sorted(set(frozen_conf) | set(row_conf)):
        if frozen_conf.get(name) != row_conf.get(name):
            problems.append(f"client configuration {name}: row {row_conf.get(name)!r}, freeze {frozen_conf.get(name)!r}")
    return problems


def _gated_configuration_view(configuration: dict[str, Any]) -> dict[str, Any]:
    ungated = {"base_url", "timeout_seconds_per_attempt", "max_attempts", "backoff_seconds"}
    return {k: v for k, v in configuration.items() if k not in ungated}


def validate_rows(
    directory: Path, *, model: str, manifest_digest: str, entries: Sequence[CaseManifest],
    frozen: dict[str, Any], quarantine: bool = False,
) -> dict[str, Any]:
    """Every row file under ``directory``: valid, or the reasons it is not.

    With ``quarantine``, a row that fails is *moved* to a sibling directory
    (``<rows_dir>.quarantine/``), never deleted and never overwritten there: a row is a
    record of a run even when it is not this run's.
    """
    directory = Path(directory)
    report: dict[str, Any] = {"directory": str(directory), "valid": [], "invalid": {}, "unreadable": [], "quarantined": []}
    if not directory.is_dir():
        return report
    quarantine_dir = directory.with_name(directory.name + ".quarantine")
    for path in sorted(directory.glob("*.json")):
        payload = read_row(path)
        if payload is None:
            report["unreadable"].append(path.name)
            continue
        problems = row_provenance_problems(payload, model=model, manifest_digest=manifest_digest, entries=entries, frozen=frozen)
        if not problems:
            report["valid"].append(path.name)
            continue
        report["invalid"][path.name] = problems
        if quarantine:
            refuse_frozen_path(quarantine_dir, ROOT).mkdir(parents=True, exist_ok=True)
            target = quarantine_dir / path.name
            if target.exists():
                target = quarantine_dir / f"{path.stem}.{int(time.time())}{path.suffix}"
            path.replace(target)
            report["quarantined"].append(str(target.relative_to(directory.parent)))
    return report


def cmd_validate(args: argparse.Namespace) -> int:
    payload, entries, digest = local_manifest.read_manifest(args.out_dir)
    frozen = read_environment(args.out_dir, args.model)
    directory = rows_dir(args.out_dir, args.arm, args.model, digest)
    report = validate_rows(
        directory, model=args.model, manifest_digest=digest, entries=entries, frozen=frozen,
        quarantine=args.quarantine,
    )
    print(json.dumps(report, indent=1))
    invalid = len(report["invalid"])
    print(
        f"{len(report['valid'])} valid row(s), {invalid} invalid, {len(report['unreadable'])} unreadable, "
        f"{len(report['quarantined'])} quarantined under {directory}",
        file=sys.stderr,
    )
    return 0 if (invalid == 0 or args.quarantine) else 1


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


INVESTIGATION_FIELDS: tuple[str, ...] = (
    "initial_hypothesis_count", "final_hypothesis_count",
    "benign_hypothesis_present_initial", "benign_hypothesis_present_final",
    "evidence_gap", "chosen_tool", "tool_choice_reason", "chosen_tools", "trajectory",
    "new_evidence_ids_returned", "new_evidence_ids_shown", "new_evidence_ids_used", "hypothesis_changed_after_tool",
    "labels_changed_after_tool", "abstained", "final_disposition", "output_truncated",
    "model_calls", "probes_run", "stop_reason",
)
"""The per-case diagnostics the investigator records and the summary reports."""


def links_are_scorable(payload: dict[str, Any], manifest_digest: str | None, telemetry_hashes: dict[str, str] | None) -> bool:
    """Whether this row's LINK scores may be read beside the current manifest.

    Every one of these must hold, or the scores are not this experiment's: the row was
    run against the current manifest, the scores were stamped with that manifest and
    with the row's own telemetry hash, and the manifest still pins that telemetry hash
    for this case. A stale row fails the first test; a row whose corpus was regenerated
    fails the last. No score is ever computed here -- a row that carries none has none.
    """
    row = payload["row"]
    key = payload["key"]
    label_scores = row.get("label_scores") or {}
    scoring = label_scores.get("link_scoring") or {}
    if not manifest_digest or row.get("manifest_hash") != manifest_digest:
        return False
    if scoring.get("manifest_hash") != manifest_digest:
        return False
    if scoring.get("telemetry_hash") != row.get("telemetry_hash"):
        return False
    if telemetry_hashes is not None:
        pinned = telemetry_hashes.get(f"{key['corpus']}/{key['case_id']}")
        if pinned != row.get("telemetry_hash"):
            return False
    return isinstance(label_scores.get("links"), dict)


def row_summary(
    payload: dict[str, Any], *, manifest_digest: str | None = None,
    telemetry_hashes: dict[str, str] | None = None,
) -> dict[str, Any]:
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
    investigation = state.get("investigation") or {}
    labels = row.get("labels") or {}
    links_valid = links_are_scorable(payload, manifest_digest, telemetry_hashes)
    links = dict((row.get("label_scores") or {}).get("links") or {}) if links_valid else None

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
        "investigator": kind_stats("investigator"),
        "planner_activation": planner_activation(state) if state else {},
        "investigation": {k: investigation.get(k) for k in INVESTIGATION_FIELDS},
        "verdict_label": labels.get("verdict"),
        "disposition": investigation.get("final_disposition"),
        "output_truncated": bool(investigation.get("output_truncated")) or any("truncated" in e for e in errors),
        "links": links,
        "links_valid": links_valid,
        "ram": {
            "preflight_available_bytes": (header.get("ram_preflight") or {}).get("available_bytes"),
            "preflight_resident_bytes": (header.get("ram_preflight") or {}).get("resident_bytes"),
            "model_size_bytes": (header.get("model_residency") or {}).get("size"),
            "model_vram_bytes": (header.get("model_residency") or {}).get("size_vram"),
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


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 3) if denominator else None


def investigation_metrics(per_row: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """The stage's preview metrics, from the per-row diagnostics and the row labels.

    Verdict metrics use the row's ``labels.verdict`` -- written by the harness beside
    the row, never shown to the model -- against the investigator's own disposition.
    Unlabelled rows (flaws.cloud) are counted only in the label-free metrics. LINK
    metrics read only rows :func:`links_are_scorable` accepted; the count of rows that
    carried no scorable links is reported beside them, never folded into a mean.
    """
    inv = [r["investigation"] for r in per_row]
    labelled = [r for r in per_row if r["verdict_label"] in ("malicious", "benign")]
    malicious = [r for r in labelled if r["verdict_label"] == "malicious"]
    benign = [r for r in labelled if r["verdict_label"] == "benign"]
    with_disposition = [r for r in per_row if r["disposition"] in ("malicious", "benign", "abstain")]
    first_tools = [i["chosen_tool"] for i in inv if i.get("chosen_tool")]
    tool_counts: Counter = Counter(first_tools)
    all_tools: Counter = Counter(t for i in inv for t in (i.get("chosen_tools") or []))
    trajectories = Counter(tuple(i.get("trajectory") or []) for i in inv)
    link_rows = [r for r in per_row if r["links_valid"]]
    link_1 = [v for r in link_rows for k, v in r["links"].items() if k.endswith("LINK-1")]
    link_2 = [v for r in link_rows for k, v in r["links"].items() if k.endswith("LINK-2")]
    return {
        "truncated_rows": sum(1 for r in per_row if r["output_truncated"]),
        "truncation_rate": _rate(sum(1 for r in per_row if r["output_truncated"]), len(per_row)),
        "labelled_rows": len(labelled),
        "malicious_cases": len(malicious),
        "benign_cases": len(benign),
        "malicious_called_malicious": sum(1 for r in malicious if r["disposition"] == "malicious"),
        "malicious_called_benign": sum(1 for r in malicious if r["disposition"] == "benign"),
        "malicious_abstained": sum(1 for r in malicious if r["disposition"] == "abstain"),
        "benign_called_malicious": sum(1 for r in benign if r["disposition"] == "malicious"),
        "benign_called_benign": sum(1 for r in benign if r["disposition"] == "benign"),
        "benign_abstained": sum(1 for r in benign if r["disposition"] == "abstain"),
        "benign_false_narrative_rate": _rate(sum(1 for r in benign if r["disposition"] == "malicious"), len(benign)),
        "benign_retaining_benign_alternative": sum(1 for r in benign if r["investigation"].get("benign_hypothesis_present_final")),
        "rows_with_benign_alternative_initial": sum(1 for i in inv if i.get("benign_hypothesis_present_initial")),
        "rows_with_benign_alternative_final": sum(1 for i in inv if i.get("benign_hypothesis_present_final")),
        "abstentions": sum(1 for r in with_disposition if r["disposition"] == "abstain"),
        "abstention_rate": _rate(sum(1 for r in with_disposition if r["disposition"] == "abstain"), len(with_disposition)),
        "rows_with_disposition": len(with_disposition),
        "cases_with_tool_call": sum(1 for i in inv if i.get("probes_run")),
        "probes_total": sum(len(i.get("probes_run") or []) for i in inv),
        "first_tool_distribution": dict(sorted(tool_counts.items())),
        "tool_distribution": dict(sorted(all_tools.items())),
        "tool_choice_diversity": len(tool_counts),
        "unique_trajectories": len(trajectories),
        "trajectory_distribution": {" > ".join(k) or "(none)": v for k, v in sorted(trajectories.items())},
        "cases_retrieving_new_evidence": sum(1 for i in inv if (i.get("new_evidence_ids_returned") or 0) > 0),
        "cases_using_new_evidence": sum(1 for i in inv if (i.get("new_evidence_ids_used") or 0) > 0),
        "new_evidence_ids_returned_total": sum(i.get("new_evidence_ids_returned") or 0 for i in inv),
        "new_evidence_ids_shown_total": sum(i.get("new_evidence_ids_shown") or 0 for i in inv if i.get("new_evidence_ids_shown") is not None),
        "rows_recording_shown_ids": sum(1 for i in inv if i.get("new_evidence_ids_shown") is not None),
        "new_evidence_ids_used_total": sum(i.get("new_evidence_ids_used") or 0 for i in inv),
        "hypothesis_changed_after_tool": sum(1 for i in inv if i.get("hypothesis_changed_after_tool")),
        "labels_changed_after_tool": sum(1 for i in inv if i.get("labels_changed_after_tool")),
        "link_scorable_rows": len(link_rows),
        "link_unscorable_rows": sum(1 for r in per_row if not r["links_valid"] and r["verdict_label"] in ("malicious", "benign")),
        "link_1_recovered": sum(1 for v in link_1 if v),
        "link_1_defined": len(link_1),
        "link_1_score": _rate(sum(1 for v in link_1 if v), len(link_1)),
        "link_2_recovered": sum(1 for v in link_2 if v),
        "link_2_defined": len(link_2),
        "link_2_score": _rate(sum(1 for v in link_2 if v), len(link_2)),
        "investigator_median_seconds": _median([r["investigator"]["median_total_seconds"] for r in per_row]),
        "tool_calls_total": sum(r["scores"]["tool_calls"] or 0 for r in per_row),
    }


def summarise(
    rows: Sequence[dict[str, Any]], expected_cases: int, events: Sequence[dict[str, Any]] = (),
    *, manifest_digest: str | None = None, telemetry_hashes: dict[str, str] | None = None,
) -> dict[str, Any]:
    per_row = [row_summary(r, manifest_digest=manifest_digest, telemetry_hashes=telemetry_hashes) for r in rows]
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
        "investigation": investigation_metrics(per_row),
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
    inv = summary.get("investigation") or {}
    if inv:
        lines += [
            "",
            "## Investigation (D1 v2 preview metrics)",
            "",
            "| metric | value |", "| --- | --- |",
            ["truncated rows / rate", f"{inv['truncated_rows']} / {inv['truncation_rate']}"],
            ["labelled cases (malicious / benign)", f"{inv['labelled_rows']} ({inv['malicious_cases']} / {inv['benign_cases']})"],
            ["malicious called malicious / benign / abstained", f"{inv['malicious_called_malicious']} / {inv['malicious_called_benign']} / {inv['malicious_abstained']}"],
            ["benign called malicious / benign / abstained", f"{inv['benign_called_malicious']} / {inv['benign_called_benign']} / {inv['benign_abstained']}"],
            ["benign false-narrative rate", inv["benign_false_narrative_rate"]],
            ["benign cases retaining a benign alternative (final)", f"{inv['benign_retaining_benign_alternative']} / {inv['benign_cases']}"],
            ["rows with a benign alternative (initial / final)", f"{inv['rows_with_benign_alternative_initial']} / {inv['rows_with_benign_alternative_final']}"],
            ["abstentions / rate (rows with a disposition)", f"{inv['abstentions']} / {inv['abstention_rate']} ({inv['rows_with_disposition']})"],
            ["cases with a chosen tool call / probes total", f"{inv['cases_with_tool_call']} / {inv['probes_total']}"],
            ["first-tool distribution", json.dumps(inv["first_tool_distribution"])],
            ["tool distribution (all probes)", json.dumps(inv["tool_distribution"])],
            ["tool-choice diversity (distinct first tools)", inv["tool_choice_diversity"]],
            ["unique trajectories", f"{inv['unique_trajectories']} {json.dumps(inv['trajectory_distribution'])}"],
            ["cases retrieving / USING evidence outside the findings' citations", f"{inv['cases_retrieving_new_evidence']} / {inv['cases_using_new_evidence']} (ids returned {inv['new_evidence_ids_returned_total']} / shown {inv['new_evidence_ids_shown_total']} on {inv['rows_recording_shown_ids']} row(s) / used {inv['new_evidence_ids_used_total']})"],
            ["hypothesis changed after a tool (any / labels or disposition)", f"{inv['hypothesis_changed_after_tool']} / {inv['labels_changed_after_tool']}"],
            ["LINK-1 recovered / defined (score)", f"{inv['link_1_recovered']} / {inv['link_1_defined']} ({inv['link_1_score']})"],
            ["LINK-2 recovered / defined (score)", f"{inv['link_2_recovered']} / {inv['link_2_defined']} ({inv['link_2_score']})"],
            ["link-scorable rows / labelled rows without scorable links", f"{inv['link_scorable_rows']} / {inv['link_unscorable_rows']}"],
            ["investigator median call s / tool calls total", f"{inv['investigator_median_seconds']} / {inv['tool_calls_total']}"],
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
    if inv:
        out += [
            "",
            "## Per case: investigation",
            "",
            "| case | label | disposition | evidence gap | chosen tool(s) | new ids returned / used | benign alt (init / final) | changed after tool | LINK-1 | LINK-2 | truncated |",
            "| --- | --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- |",
        ]
        for r in summary["rows"]:
            k = r["key"]
            i = r["investigation"]
            links = r["links"] or {}
            l1 = next((v for name, v in links.items() if name.endswith("LINK-1")), None)
            l2 = next((v for name, v in links.items() if name.endswith("LINK-2")), None)
            out.append(
                f"| {k['corpus']}/{k['case_id']} | {r['verdict_label'] or 'unlabelled'} | {r['disposition']} | "
                f"{(i.get('evidence_gap') or '')[:70]} | {', '.join(i.get('chosen_tools') or []) or 'none'} | "
                f"{i.get('new_evidence_ids_returned')} / {i.get('new_evidence_ids_used')} | "
                f"{i.get('benign_hypothesis_present_initial')} / {i.get('benign_hypothesis_present_final')} | "
                f"{i.get('hypothesis_changed_after_tool')} | {'-' if l1 is None else l1} | {'-' if l2 is None else l2} | "
                f"{r['output_truncated']} |"
            )
    return "\n".join(out)


def select_rows(
    rows: Sequence[dict[str, Any]], entries: Sequence[CaseManifest], manifest_digest: str,
    *, model: str, repeat: int,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """The rows that belong to this experiment identity, and why the others do not.

    A row is in when its key names a manifest case, its model and repeat are the ones
    asked for, its manifest hash is the current one, its telemetry hash is the one the
    manifest pins for that case, and its header records the live investigator prompts
    and bounds. Everything else is counted by the reason it was excluded and never
    summarised: a stale row is not a weaker data point, it is another experiment's.
    """
    by_key = {(e.corpus, e.case_id): e for e in entries}
    live = investigator_environment()
    kept: list[dict[str, Any]] = []
    excluded: Counter = Counter()
    for row in rows:
        key = row["key"]
        entry = by_key.get((key["corpus"], key["case_id"]))
        header = row.get("header") or {}
        if entry is None:
            excluded["not_in_manifest"] += 1
        elif key.get("model") != model or key.get("repeat") != repeat:
            excluded["other_model_or_repeat"] += 1
        elif row["row"].get("manifest_hash") != manifest_digest or key.get("manifest_hash") not in (manifest_digest, ""):
            excluded["stale_manifest"] += 1
        elif row["row"].get("telemetry_hash") != entry.telemetry_hash:
            excluded["telemetry_hash_mismatch"] += 1
        elif dict(header.get("investigator") or {}) != live:
            excluded["investigator_prompt_drift"] += 1
        else:
            kept.append(row)
    return kept, dict(excluded)


def cmd_summarise(args: argparse.Namespace) -> int:
    payload, entries, digest = local_manifest.read_manifest(args.out_dir)
    directory = rows_dir(args.out_dir, args.arm, args.model, digest)
    rows, excluded = select_rows(completed_rows(directory), entries, digest, model=args.model, repeat=args.repeat)
    telemetry_hashes = {e.key: e.telemetry_hash for e in entries}
    summary = summarise(
        rows, expected_cases=len(entries), events=guard_events(directory),
        manifest_digest=digest, telemetry_hashes=telemetry_hashes,
    )
    summary.update({
        "arm": args.arm, "model": args.model, "manifest_hash": digest, "repeat": args.repeat,
        "head": _head(), "rows_directory": str(directory.relative_to(ROOT)).replace("\\", "/"),
        "investigator": investigator_environment(), "rows_excluded": excluded,
    })
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
    p_run.add_argument("--only", nargs="*", default=None, metavar="CORPUS/CASE", help="run only these manifest keys (the smoke set)")
    p_run.set_defaults(func=cmd_run)
    p_sum = sub.add_parser("summarise"); common(p_sum)
    p_sum.add_argument("--repeat", type=int, default=1)
    p_sum.set_defaults(func=cmd_summarise)
    p_val = sub.add_parser("validate-rows", help="check every row in this model's rows directory against the live freeze and manifest"); common(p_val)
    p_val.add_argument("--quarantine", action="store_true", help="move rows that fail into <rows_dir>.quarantine/ (never delete)")
    p_val.set_defaults(func=cmd_validate)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
