"""Parallel cases: one client per worker, the same rows as a serial run, the RAM floor
scaled per slot and recorded, and a refusal or a controlled stop that ends the pool."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from ath.agent.investigator import D1_PROMPT_VERSION  # noqa: E402
from ath.agent.llm import ScriptedLLM  # noqa: E402
from ath.evaluation.ablation import manifest_hash  # noqa: E402
from ath.evaluation.ablation.environment import tool_surface  # noqa: E402
from ath.evaluation.ablation.local import (  # noqa: E402
    DEFAULT_CONTEXT_ALLOWANCE_BYTES,
    GIB,
    ModelSpec,
    arm_d1,
    check_ram,
    completed_rows,
    ram_floor_for,
)
from ath.experiments.bundles import Bundle  # noqa: E402
from ath.experiments.paths import Layout  # noqa: E402
from ath.experiments.runner import Interrupted, run_rows  # noqa: E402
from ath.experiments.runs import RunRecord  # noqa: E402
from test_ablation_harness import corpus, manifest, pipeline  # noqa: F401,E402

MODEL = "fake:4b"
SPEC = ModelSpec("ollama", MODEL, "Q4_K_M", "4.7B", "a" * 64)


def _client() -> ScriptedLLM:
    return ScriptedLLM(responses=['{"claims": []}'] * 64, name="s")


def _run(tmp_path, corpus, pipeline, manifest, **kwargs):
    findings, cases, environment = pipeline
    digest = manifest_hash(manifest)
    layout = Layout(tmp_path, "D1", MODEL, digest)
    defaults = dict(
        arm=arm_d1(MODEL), client=_client(), spec=SPEC, entries=manifest,
        bundles=[Bundle(name="fixture", telemetry=corpus, findings=findings, cases=cases, environment=environment)],
        manifest_digest=digest, rows_directory=layout.rows_dir,
        header={"head": "t", "prompt_version": D1_PROMPT_VERSION}, repeats=[1], seed=0,
        surface=tool_surface(), ram_floor=None, ram_reader=lambda: 8 * GIB, log=lambda _t: None,
    )
    return run_rows(**{**defaults, **kwargs}), layout


def _rows_by_case(layout):
    return {(r["key"]["case_id"], r["key"]["repeat"]): r for r in completed_rows(layout.rows_dir)}


def test_two_workers_write_the_same_rows_as_one(tmp_path, corpus, pipeline, manifest) -> None:
    # The fixture forms one case; two repeats are two independent rows to fan out.
    serial, serial_layout = _run(tmp_path / "serial", corpus, pipeline, manifest, repeats=[1, 2])
    record = RunRecord.start(Layout(tmp_path / "parallel", "D1", MODEL, manifest_hash(manifest)), "run", argv=[], workers=2, write=False)
    parallel, parallel_layout = _run(tmp_path / "parallel", corpus, pipeline, manifest, workers=2, client_factory=_client, record=record, repeats=[1, 2])
    expected = 2 * len(manifest)
    assert parallel["ran"] == serial["ran"] == expected
    a, b = _rows_by_case(serial_layout), _rows_by_case(parallel_layout)
    assert a.keys() == b.keys()
    for case_id in a:
        assert a[case_id]["row"]["state"]["claims"] == b[case_id]["row"]["state"]["claims"]
        def timeless(scores):
            return {k: ({kk: vv for kk, vv in v.items() if kk not in ("wall_seconds", "tokens")} if k == "completeness" else v) for k, v in scores.items()}
        assert timeless(a[case_id]["row"]["scores"]) == timeless(b[case_id]["row"]["scores"])
        assert b[case_id]["header"]["runner"]["workers"] == 2
        assert b[case_id]["header"]["runner"]["worker_index"] in (0, 1)
    assert {r["header"]["runner"]["worker_index"] for r in b.values()} == {0, 1}
    assert len(record.rows_written) == expected
    again, _ = _run(tmp_path / "parallel", corpus, pipeline, manifest, workers=2, client_factory=_client, repeats=[1, 2])
    assert again["ran"] == 0 and again["skipped"] == expected


def test_workers_above_one_need_a_client_factory(tmp_path, corpus, pipeline, manifest) -> None:
    with pytest.raises(ValueError):
        _run(tmp_path, corpus, pipeline, manifest, workers=2)
    with pytest.raises(ValueError):
        _run(tmp_path, corpus, pipeline, manifest, workers=0)


def test_a_refusal_in_one_worker_stops_the_pool_and_is_logged(tmp_path, corpus, pipeline, manifest) -> None:
    with pytest.raises(SystemExit, match="REFUSED"):
        _run(tmp_path, corpus, pipeline, manifest, workers=2, client_factory=_client,
             ram_floor=ram_floor_for("4.7B", slots=2), ram_reader=lambda: 1 * GIB, slots=2, repeats=[1, 2])
    layout = Layout(tmp_path, "D1", MODEL, manifest_hash(manifest))
    assert not list(layout.rows_dir.glob("*.json")) or len(list(layout.rows_dir.glob("*.json"))) < len(manifest)
    events = [json.loads(line) for line in layout.guard_events_path.read_text(encoding="utf-8").splitlines()]
    assert events and events[0]["ok"] is False and events[0]["slots"] == 2


def test_stop_after_ends_a_parallel_run_as_a_controlled_interruption(tmp_path, corpus, pipeline, manifest) -> None:
    with pytest.raises(Interrupted):
        _run(tmp_path, corpus, pipeline, manifest, workers=2, client_factory=_client, stop_after=1, repeats=[1, 2, 3])
    layout = Layout(tmp_path, "D1", MODEL, manifest_hash(manifest))
    written = len(list(layout.rows_dir.glob("*.json")))
    assert 1 <= written <= 2, "at most the cases already in flight finish after the stop"


def test_the_floor_scales_per_slot_and_the_verdict_records_it() -> None:
    single = ram_floor_for("4.7B")
    assert ram_floor_for("4.7B", slots=1) == single
    assert ram_floor_for("4.7B", slots=3) == single + 2 * DEFAULT_CONTEXT_ALLOWANCE_BYTES
    assert ram_floor_for("4.7B", slots=3, context_allowance_bytes=GIB) == single + 2 * GIB
    assert ram_floor_for("70B", slots=4) is None
    plain = check_ram(single, 8 * GIB).to_dict()
    assert "slots" not in plain
    scaled = check_ram(ram_floor_for("4.7B", slots=2), 8 * GIB, slots=2).to_dict()
    assert scaled["slots"] == 2 and scaled["context_allowance_source"] == "default-unmeasured"
    measured = check_ram(ram_floor_for("4.7B", slots=2, context_allowance_bytes=GIB), 8 * GIB, slots=2, context_allowance_bytes=GIB).to_dict()
    assert measured["context_allowance_source"] == "measured" and "2 parallel slot" in measured["message"]
