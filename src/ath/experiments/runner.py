"""The resumable case loop, and the ``run`` command around it.

``run_rows`` is pure with respect to configuration: every knob is an argument, so a test
drives it with a scripted client over a fixture corpus and a temporary directory. The
``run`` command resolves the manifest, the freeze and the daemon, opens a
:class:`~ath.experiments.runs.RunRecord`, and hands the loop everything it needs.

Exit codes: 0 done; 3 a controlled interruption (``--stop-after``); 130 Ctrl-C; a
``SystemExit("REFUSED: ...")`` for anything the freeze or the guard will not allow.
"""

from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any

from ath.agent.investigator import D1_PROMPT_VERSION, INVESTIGATOR_SYSTEM
from ath.agent.llm import LLMClient
from ath.agent.ollama_llm import Sampling
from ath.agent.orchestrator import PLANNER_SYSTEM
from ath.evaluation.ablation import CaseManifest, CaseResult, build_client
from ath.evaluation.ablation.environment import tool_surface
from ath.evaluation.ablation.local import (
    ModelSpec,
    RamVerdict,
    RowKey,
    available_ram_bytes,
    check_local_environment,
    check_ram,
    investigator_environment,
    is_complete,
    ram_floor_for,
    refuse_frozen_path,
    row_path,
    run_local_arm,
    write_row,
)
from ath.experiments.bundles import label_scorer, required_footing_for
from ath.experiments.freeze import describe_or_refuse, read_environment
from ath.experiments.local_arms import build_arm
from ath.experiments.manifest_build import dev_bundles, links_by_case, read_manifest
from ath.experiments.paths import GUARD_EVENTS, ROOT, Layout
from ath.experiments.runs import RunRecord, now

Log = Callable[[str], None]


def _stderr(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


def _head() -> str:
    from ath.experiments.manifest_build import head

    return head()


class Interrupted(RuntimeError):
    """The run stopped on purpose (``--stop-after``); rows written stay."""


def record_guard_event(path: Path, case_key: str, repeat: int, verdict: RamVerdict, *, overridden: bool) -> None:
    path = refuse_frozen_path(path, ROOT)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({
            "at": now(), "case": case_key, "repeat": repeat, "overridden": overridden, **verdict.to_dict(),
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


def classify_calls(calls: Sequence[dict[str, Any]], requests: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each token-log entry with the kind of call it was, read off the paired request size.

    Planner, investigator and synthesis are told apart by the system prompt's length,
    which the request observer records and the frozen system prompts differ in. Paired
    by position, as ``request_records`` pairs them; a call whose request is missing is
    ``unknown`` on its own, not the whole list.
    """
    by_length = {len(INVESTIGATOR_SYSTEM): "investigator", len(PLANNER_SYSTEM): "planner"}
    aligned = len(calls) == len(requests)
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
    record: RunRecord | None = None,
    log: Log = _stderr,
) -> dict[str, int]:
    """The resumable loop. Returns ``{"ran", "skipped", "degraded", "ram_guard_events"}``.

    ``only`` restricts the run to the named ``corpus/case_id`` keys (the smoke set).
    ``record`` receives every row written or skipped, by file and key digest.
    """
    by_corpus: dict[str, list[CaseManifest]] = defaultdict(list)
    for entry in entries:
        if only is not None and entry.key not in only:
            continue
        by_corpus[entry.corpus].append(entry)
    counts = {"ran": 0, "skipped": 0, "degraded": 0, "ram_guard_events": 0}
    events_path = Path(rows_directory) / GUARD_EVENTS
    stamp = record.header_stamp() if record is not None else None

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
                    if record is not None:
                        record.add_row(path.name, key.digest, skipped=True)
                    log(f"skip  {entry.key} rep{repeat}: row exists ({path.name})")
                    continue
                resident = resident_reader() if resident_reader is not None else 0
                verdict = check_ram(ram_floor, ram_reader(), resident)
                if verdict.ok is False:
                    counts["ram_guard_events"] += 1
                    record_guard_event(events_path, entry.key, repeat, verdict, overridden=ignore_ram_floor)
                    if record is not None:
                        record.guard_events += 1
                    if not ignore_ram_floor:
                        raise SystemExit(f"REFUSED before {entry.key}: {verdict.message}")
                    log(f"RAM guard overridden before {entry.key}: {verdict.message}")
                started = time.perf_counter()
                results = run_local_arm(
                    arm, [entry], bundle.telemetry, bundle.cases,
                    manifest_digest=manifest_digest, findings=bundle.findings,
                    environment=bundle.environment, llm=client,
                    label_scorer=label_scorer(bundle), required_footing=footing,
                    links=links,
                )
                result: CaseResult = results[0]
                calls = list(getattr(client, "token_log", None) or [])
                row_header = {
                    **header,
                    "investigator": investigator_environment(),
                    "written_at": now(),
                    "repeat": repeat,
                    "seed": seed,
                    "ram_preflight": {**verdict.to_dict(), "overridden": bool(verdict.ok is False and ignore_ram_floor)},
                    "model_residency": dict(residency_reader()) if residency_reader is not None else None,
                    "ram_after_bytes": ram_reader(),
                    "loop_wall_seconds": round(time.perf_counter() - started, 3),
                    "calls": classify_calls(calls, result.state.get("llm", {}).get("requests", [])),
                    **({"runner": stamp} if stamp is not None else {}),
                }
                write_row(rows_directory, key, result, row_header, root=ROOT)
                counts["ran"] += 1
                if record is not None:
                    record.add_row(path.name, key.digest)
                    record.write()
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


def warn_about_siblings(layout: Layout, log: Log) -> None:
    """Say out loud when other row sets sit beside the target directory.

    A manifest whose telemetry digest depends on the runtime starts an empty directory
    beside a full one; naming the difference before twenty cases rerun is cheaper than
    finding it after.
    """
    siblings = layout.sibling_row_dirs()
    if not siblings or layout.rows_dir.is_dir():
        return
    log(f"note: {layout.rows_dir} does not exist yet, but rows exist beside it:")
    for path, count in siblings:
        log(f"  {path.name}: {count} row file(s)")
    log("  a different manifest hash or prompt version; validate-rows explains which")


def run(
    *,
    out_dir: Path,
    arm_letter: str,
    model: str,
    sampling: Sampling,
    base_url: str,
    external: Path,
    think: bool = False,
    repeat: int = 1,
    stop_after: int | None = None,
    ignore_ram_floor: bool = False,
    only: Sequence[str] | None = None,
    spec: Any = None,
    argv: list[str] | None = None,
    log: Log = _stderr,
) -> int:
    payload, entries, digest = read_manifest(out_dir)
    frozen = read_environment(out_dir, model)
    arm = build_arm(arm_letter, model, sampling, base_url=base_url, think=think)
    client = build_client(arm)
    described = describe_or_refuse(client)
    drift = check_local_environment(frozen, manifest_hash=digest, described=described)
    if drift:
        raise SystemExit(
            "REFUSED: the live world differs from the freeze:\n  " + "\n  ".join(drift)
            + "\n\nEither restore it or freeze again and record why."
        )
    model_spec = ModelSpec.from_description(described)
    layout = Layout(Path(out_dir), arm_letter, model, digest)
    directory = refuse_frozen_path(layout.rows_dir, ROOT)
    wanted = set(only) if only else None
    if wanted is not None:
        unknown = sorted(wanted - {e.key for e in entries})
        if unknown:
            raise SystemExit(f"--only names case(s) not in the manifest: {unknown}")
    warn_about_siblings(layout, log)
    header = {
        "head": _head(),
        "frozen_head": (frozen.get("git") or {}).get("short_commit"),
        "arm": arm.to_dict(),
        "model": model_spec.to_dict(),
        "daemon_version": described.get("daemon_version"),
        "client_configuration": described.get("configuration"),
        "manifest_hash": digest,
        "manifest_head": payload.get("head"),
        "prompt_version": D1_PROMPT_VERSION,
    }
    record = RunRecord.start(
        layout, "run", argv=argv, spec=spec, model=model_spec.to_dict(),
        daemon_version=described.get("daemon_version"),
    )
    log(f"run {record.run_id[:12]} -> {record.path}")
    repeats = list(range(1, repeat + 1))
    started = time.perf_counter()
    wanted_corpora = {e.corpus for e in entries if wanted is None or e.key in wanted}
    counts: dict[str, int] = {}
    exit_code = 0
    try:
        counts = run_rows(
            arm=arm, client=client, spec=model_spec, entries=entries,
            bundles=dev_bundles(external, corpora=wanted_corpora),
            manifest_digest=digest, rows_directory=directory, header=header, repeats=repeats,
            seed=sampling.seed, surface=tool_surface(), ram_floor=ram_floor_for(model_spec.parameter_size),
            resident_reader=client.resident_bytes,  # type: ignore[attr-defined]
            residency_reader=client.residency,  # type: ignore[attr-defined]
            stop_after=stop_after, ignore_ram_floor=ignore_ram_floor,
            links=links_by_case(payload), only=wanted, record=record, log=log,
        )
    except Interrupted as exc:
        log(f"INTERRUPTED: {exc}; completed rows are on disk and a rerun will skip them")
        record.note(str(exc))
        exit_code = 3
    except KeyboardInterrupt:
        log("INTERRUPTED by Ctrl-C; completed rows are on disk and a rerun will skip them")
        record.note("Ctrl-C")
        exit_code = 130
    except SystemExit as exc:
        record.note(str(exc))
        record.finish(1 if exc.code is None else (exc.code if isinstance(exc.code, int) else 1))
        raise
    if exit_code == 0:
        log(
            f"done in {time.perf_counter() - started:.0f}s: ran {counts['ran']}, skipped "
            f"{counts['skipped']}, degraded {counts['degraded']}, RAM guard events "
            f"{counts['ram_guard_events']} -> {directory}"
        )
    record.finish(exit_code, counts)
    return exit_code
