"""The local run loop: resumable, honest about failures, and summarised from integers.

Why these tests exist
----------------------
An overnight D1 run is the first artifact of the V1 study and the baseline everything after
it is compared to. Three ways it could be quietly wrong:

*Resumability.* A rerun must skip every complete row and redo only an incomplete one. Fails
if a row is executed twice (its file rewritten) or if a corrupt file is left in place.

*Failures retried into successes.* A degraded row is a result. Fails if a rerun executes it
again.

*Summary arithmetic.* The completion rate, the parse rate and the guardrail verdict are what
the exit criterion is read from. Fails if the strict completion definition loosens (a row
with an unparseable reply counting as complete), or if a context refusal is not counted.

Driven with a scripted client over the harness's fixture corpus; no daemon.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import local_ablation as run_script  # noqa: E402
import m19_ablation as m19  # noqa: E402

from ath.agent.llm import ScriptedLLM  # noqa: E402
from ath.evaluation.ablation import build_manifest, manifest_hash  # noqa: E402
from ath.evaluation.ablation.environment import tool_surface  # noqa: E402
from ath.evaluation.ablation.local import (  # noqa: E402
    ARM_D1,
    ModelSpec,
    arm_d1,
    completed_rows,
    row_path,
    RowKey,
)
from test_ablation_harness import corpus, manifest, pipeline  # noqa: F401,E402

SPEC = ModelSpec("scripted", "fake:1b", "Q4", "1.0B", "d" * 64)


def _bundle(corpus, pipeline):
    findings, cases, environment = pipeline
    return m19.Bundle(
        name="fixture", telemetry=corpus, findings=findings, cases=cases,
        environment=environment,
    )


def _run(tmp_path, corpus, pipeline, manifest, *, client, stop_after=None, ram=None, seed=0):
    return run_script.run_rows(
        arm=arm_d1("fake:1b"), client=client, spec=SPEC, entries=manifest,
        bundles=[_bundle(corpus, pipeline)], manifest_digest=manifest_hash(manifest),
        rows_directory=tmp_path / "rows", header={"head": "test"}, repeats=[1], seed=seed,
        surface=tool_surface(), ram_floor=ram, ram_reader=lambda: 8 * run_script.GIB,
        stop_after=stop_after, log=lambda _text: None,
    )


def _digests(directory: Path) -> dict[str, str]:
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.glob("*.json"))}


def test_a_run_writes_one_row_per_case_and_a_rerun_skips_them_all(tmp_path, corpus, pipeline, manifest) -> None:
    first = _run(tmp_path, corpus, pipeline, manifest,
                 client=ScriptedLLM(responses=['{"claims": []}'] * 64, name="scripted"))
    assert first["ran"] == len(manifest) and first["skipped"] == 0
    rows = completed_rows(tmp_path / "rows")
    assert len(rows) == len(manifest)
    before = _digests(tmp_path / "rows")

    second = _run(tmp_path, corpus, pipeline, manifest,
                  client=ScriptedLLM(responses=['{"claims": []}'] * 64, name="scripted"))
    assert second == {"ran": 0, "skipped": len(manifest), "degraded": 0, "ram_guard_events": 0}
    assert _digests(tmp_path / "rows") == before, "a skipped row's bytes must not change"


def test_a_corrupt_row_is_the_only_one_redone(tmp_path, corpus, pipeline, manifest) -> None:
    _run(tmp_path, corpus, pipeline, manifest,
         client=ScriptedLLM(responses=['{"claims": []}'] * 64, name="scripted"))
    files = sorted((tmp_path / "rows").glob("*.json"))
    files[0].write_text("{", encoding="utf-8")
    counts = _run(tmp_path, corpus, pipeline, manifest,
                  client=ScriptedLLM(responses=['{"claims": []}'] * 64, name="scripted"))
    assert counts["ran"] == 1 and counts["skipped"] == len(manifest) - 1
    assert completed_rows(tmp_path / "rows")


def test_a_degraded_row_is_written_and_never_rerun(tmp_path, corpus, pipeline, manifest) -> None:
    exhausted = ScriptedLLM(responses=[], name="scripted-dead")  # available, every call fails
    counts = _run(tmp_path, corpus, pipeline, manifest, client=exhausted)
    assert counts["degraded"] == len(manifest) == counts["ran"]
    rows = completed_rows(tmp_path / "rows")
    assert all(r["row"]["llm_degraded"] for r in rows)
    assert all(r["row"]["labelled_arm"].endswith("_DEGRADED") for r in rows)
    again = _run(tmp_path, corpus, pipeline, manifest, client=exhausted)
    assert again == {"ran": 0, "skipped": len(manifest), "degraded": 0, "ram_guard_events": 0}


def test_stop_after_is_a_controlled_interruption_that_leaves_rows_on_disk(tmp_path, corpus, pipeline, manifest) -> None:
    if len(manifest) < 2:
        pytest.skip("the fixture corpus forms one case; the interruption needs two")
    with pytest.raises(run_script.Interrupted):
        _run(tmp_path, corpus, pipeline, manifest, stop_after=1,
             client=ScriptedLLM(responses=['{"claims": []}'] * 64, name="scripted"))
    assert len(completed_rows(tmp_path / "rows")) == 1


def test_the_ram_guard_refuses_a_row_below_the_floor_and_logs_the_event(tmp_path, corpus, pipeline, manifest) -> None:
    with pytest.raises(SystemExit, match="refusing to start"):
        _run(tmp_path, corpus, pipeline, manifest, ram=100 * run_script.GIB,
             client=ScriptedLLM(responses=['{"claims": []}'] * 64, name="scripted"))
    assert not completed_rows(tmp_path / "rows")
    events = run_script.guard_events(tmp_path / "rows")
    assert len(events) == 1 and events[0]["overridden"] is False and events[0]["ok"] is False


def test_an_overridden_guard_runs_the_row_and_marks_it(tmp_path, corpus, pipeline, manifest) -> None:
    counts = run_script.run_rows(
        arm=arm_d1("fake:1b"), client=ScriptedLLM(responses=['{"claims": []}'] * 64, name="scripted"),
        spec=SPEC, entries=manifest, bundles=[_bundle(corpus, pipeline)],
        manifest_digest=manifest_hash(manifest), rows_directory=tmp_path / "rows",
        header={"head": "test"}, repeats=[1], seed=0, surface=tool_surface(),
        ram_floor=100 * run_script.GIB, ram_reader=lambda: 8 * run_script.GIB,
        ignore_ram_floor=True, log=lambda _t: None,
    )
    assert counts["ran"] == len(manifest) and counts["ram_guard_events"] == len(manifest)
    rows = completed_rows(tmp_path / "rows")
    assert all(r["header"]["ram_preflight"]["overridden"] for r in rows)
    summary = run_script.summarise(rows, expected_cases=len(manifest), events=run_script.guard_events(tmp_path / "rows"))
    assert summary["ram_guard_overrides"] == len(manifest) and summary["rows_run_under_override"] == len(manifest)


def test_the_row_key_carries_provider_model_quant_repeat_and_seed(tmp_path, corpus, pipeline, manifest) -> None:
    _run(tmp_path, corpus, pipeline, manifest, seed=7,
         client=ScriptedLLM(responses=['{"claims": []}'] * 64, name="scripted"))
    row = completed_rows(tmp_path / "rows")[0]
    key = RowKey.from_dict(row["key"])
    assert (key.arm, key.provider, key.model, key.quantization, key.repeat, key.seed) == (
        ARM_D1, "scripted", "fake:1b", "Q4", 1, 7,
    )
    assert row_path(tmp_path / "rows", key).exists()
    assert "calls" in row["header"] and "ram_preflight" in row["header"]


# --------------------------------------------------------------------------------------
# Summary arithmetic, on constructed rows
# --------------------------------------------------------------------------------------


def _row(*, degraded=False, unparseable=0, errors=(), wall=10.0, tokens=100, ec=1.0, calls=None):
    return {
        "key": {"corpus": "c", "case_id": "CASE-001", "arm": ARM_D1, "provider": "ollama",
                "model": "m", "quantization": "Q4", "repeat": 1, "seed": 0},
        "header": {"calls": calls or [], "ram_preflight": {"available_bytes": 5 * run_script.GIB, "ok": True},
                   "ram_after_bytes": 4 * run_script.GIB},
        "row": {
            "arm": ARM_D1, "labelled_arm": ARM_D1 + ("_DEGRADED" if degraded else ""),
            "llm_degraded": degraded, "wall_seconds": wall, "tokens": tokens,
            "scores": {"cited_event_ids": 10, "cited_event_ids_existing": int(10 * ec),
                       "rejected_claims": 0, "unsupported_claims": 0,
                       "completeness": {"tool_calls": 3}},
            "state": {"status": "complete", "counts": {},
                      "llm": {"errors": list(errors), "unparseable_responses": unparseable,
                              "unparseable_by_kind": {}, "planner": {}}},
        },
    }


def test_the_strict_completion_definition_counts_parse_and_context_failures(tmp_path) -> None:
    calls = [{"kind": "planner", "total_seconds": 3.0, "input_tokens": 300, "output_tokens": 30,
              "eval_tokens_per_second": 10.0, "prompt_tokens_per_second": 40.0, "sent": True}]
    rows = [
        _row(calls=calls),
        _row(unparseable=1, calls=calls),
        _row(degraded=True, errors=["prompt (~9000 tokens estimated) plus num_predict=2048 exceeds num_ctx=10240; refused"], calls=calls),
        _row(degraded=True, errors=["HTTP 500 (the daemon failed)"], calls=calls),
    ]
    summary = run_script.summarise(rows, expected_cases=4)
    assert summary["rows_written"] == 4
    assert summary["completed_strict"] == 1
    assert summary["completion_rate"] == 0.25
    assert summary["meets_completion_target"] is False
    assert summary["context_refusals"] == 1 and summary["rows_with_context_refusals"] == 1
    assert summary["failure_types"] == {"context_budget_refusal": 1, "http_500": 1}
    assert summary["parse_rate"] == round((4 - 1 - 1) / 4, 3)
    assert summary["total_wall_seconds"] == 40.0
    assert summary["median_case_wall_seconds"] == 10.0 and summary["p95_case_wall_seconds"] == 10.0
    assert summary["prompt_tokens_total"] == 1200 and summary["completion_tokens_total"] == 120
    assert summary["evidence_correctness_all_at_least_floor"] is True
    assert summary["ram_min_available_bytes"] == 4 * run_script.GIB


def test_twenty_clean_rows_meet_the_target_and_nineteen_do_not() -> None:
    clean = [_row() for _ in range(20)]
    assert run_script.summarise(clean, expected_cases=20)["meets_completion_target"] is True
    assert run_script.summarise(clean[:19], expected_cases=20)["meets_completion_target"] is True  # 0.95 exactly
    assert run_script.summarise(clean[:18], expected_cases=20)["meets_completion_target"] is False


def test_medians_and_p95_are_never_invented() -> None:
    assert run_script._median([]) is None and run_script._p95([None]) is None
    assert run_script._p95([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]) == 10
