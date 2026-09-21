"""What the experiment layer adds: run records, row stamps, quarantine reasons, the
silent-zero refusal, runner-owned paths and the spec file. Scripted client, fixture
corpus, temporary directories; no daemon.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import local_ablation as shim  # noqa: E402
from ath.agent.investigator import D1_PROMPT_VERSION  # noqa: E402
from ath.agent.llm import ScriptedLLM  # noqa: E402
from ath.evaluation.ablation import manifest_hash  # noqa: E402
from ath.evaluation.ablation.environment import tool_surface  # noqa: E402
from ath.evaluation.ablation.local import (  # noqa: E402
    GIB,
    ModelSpec,
    RowKey,
    arm_d1,
    completed_rows,
)
from ath.experiments.bundles import Bundle  # noqa: E402
from ath.experiments.cli import build_parser, resolve  # noqa: E402
from ath.experiments.paths import Layout, model_slug  # noqa: E402
from ath.experiments.runner import run_rows  # noqa: E402
from ath.experiments.runs import RunRecord  # noqa: E402
from ath.experiments.spec import ExperimentSpec  # noqa: E402
from ath.experiments.summarise import (  # noqa: E402
    NothingToSummarise,
    refuse_silent_zero,
    select_rows,
)
from ath.experiments.validate import validate_rows  # noqa: E402
from test_ablation_harness import corpus, manifest, pipeline  # noqa: F401,E402

MODEL = "fake:4b"
SPEC = ModelSpec("ollama", MODEL, "Q4_K_M", "4.7B", "a" * 64)
CONF = {"model": MODEL, "num_ctx": 10240, "num_predict_cap": 2048, "think": False, "format": "schema", "base_url": "http://x"}


def _frozen(digest: str) -> dict:
    return {"manifest_hash": digest, "local": {
        "model": SPEC.to_dict(), "daemon": {"version": "0.34.2"},
        "client_configuration": dict(CONF, base_url="http://elsewhere"),
    }}


def _layout(tmp_path: Path, digest: str) -> Layout:
    return Layout(tmp_path, "D1", MODEL, digest)


def _write_rows(tmp_path, corpus, pipeline, manifest, *, record: RunRecord | None = None):
    findings, cases, environment = pipeline
    digest = manifest_hash(manifest)
    header = {"head": "t", "prompt_version": D1_PROMPT_VERSION, "manifest_hash": digest, "model": SPEC.to_dict(),
              "daemon_version": "0.34.2", "client_configuration": CONF}
    layout = _layout(tmp_path, digest)
    counts = run_rows(
        arm=arm_d1(MODEL), client=ScriptedLLM(responses=['{"claims": []}'] * 64, name="s"), spec=SPEC,
        entries=manifest, bundles=[Bundle(name="fixture", telemetry=corpus, findings=findings, cases=cases, environment=environment)],
        manifest_digest=digest, rows_directory=layout.rows_dir, header=header, repeats=[1], seed=0,
        surface=tool_surface(), ram_floor=None, ram_reader=lambda: 8 * GIB, log=lambda _t: None, record=record,
    )
    return layout, digest, counts


# -- paths ------------------------------------------------------------------------------


def test_the_layout_agrees_with_the_shim_on_every_path(tmp_path) -> None:
    digest = "c" * 64
    layout = _layout(tmp_path, digest)
    assert layout.rows_dir == shim.rows_dir(tmp_path, "D1", MODEL, digest)
    assert layout.rows_base == shim.rows_dir(tmp_path, "D1", MODEL)
    assert layout.environment_path == shim.environment_path(tmp_path, MODEL)
    assert layout.summary_stem(1) == f"SUMMARY_D1_{model_slug(MODEL)}_rep1"
    assert layout.compare_stem("other:9b", 2) == f"COMPARE_D1_{model_slug(MODEL)}_vs_{model_slug('other:9b')}_rep2"
    assert layout.quarantine_dir.name == layout.rows_dir.name + ".quarantine"
    assert layout.quarantine_dir.parent == layout.rows_dir.parent


def test_sibling_row_directories_are_found_flat_and_nested(tmp_path) -> None:
    layout = _layout(tmp_path, "c" * 64)
    other = layout.rows_base / ("m" + "d" * 12 + "_d1-investigator-v2")
    other.mkdir(parents=True)
    (other / "row.json").write_text("{}", encoding="utf-8")
    (layout.rows_base / "flat.json").write_text("{}", encoding="utf-8")
    (layout.rows_base / "x.quarantine").mkdir()
    (layout.rows_base / "x.quarantine" / "q.json").write_text("{}", encoding="utf-8")
    found = {path.name: count for path, count in layout.sibling_row_dirs()}
    assert found == {layout.rows_base.name: 1, other.name: 1}


# -- run records and row stamps -----------------------------------------------------------


def test_a_run_record_lists_every_row_by_file_and_key_digest_and_stamps_the_header(tmp_path, corpus, pipeline, manifest) -> None:
    digest = manifest_hash(manifest)
    record = RunRecord.start(_layout(tmp_path, digest), "run", argv=["run", "--model", MODEL], workers=1)
    layout, _, counts = _write_rows(tmp_path, corpus, pipeline, manifest, record=record)
    record.finish(0, counts)

    assert record.path is not None and record.path.exists()
    written = json.loads(record.path.read_text(encoding="utf-8"))
    assert written["status"] == "done" and written["exit_code"] == 0 and written["counts"]["ran"] == len(manifest)
    assert written["argv"] == ["run", "--model", MODEL]
    assert set(written["git"]) >= {"commit", "tree", "dirty", "dirty_paths"}
    assert written["frozen_surface_sha256"] and written["runtime"]["python"]
    assert len(written["rows_written"]) == len(manifest)

    rows = completed_rows(layout.rows_dir)
    by_file = {entry["file"]: entry["key_digest"] for entry in written["rows_written"]}
    for row in rows:
        stamp = row["header"]["runner"]
        assert stamp["run_id"] == record.run_id and stamp["workers"] == 1 and stamp["worker_index"] == 0
        digest_of_key = RowKey(**row["key"]).digest
        assert digest_of_key in by_file.values()


def test_a_rerun_records_the_skipped_rows_separately(tmp_path, corpus, pipeline, manifest) -> None:
    layout, digest, first = _write_rows(tmp_path, corpus, pipeline, manifest)
    record = RunRecord.start(layout, "run", argv=[], write=False)
    _, _, second = _write_rows(tmp_path, corpus, pipeline, manifest, record=record)
    assert second["ran"] == 0 and second["skipped"] == len(manifest)
    assert len(record.rows_skipped) == len(manifest) and record.rows_written == []


def test_rows_without_a_runner_stamp_still_validate(tmp_path, corpus, pipeline, manifest) -> None:
    layout, digest, _ = _write_rows(tmp_path, corpus, pipeline, manifest)
    report = validate_rows(layout.rows_dir, model=MODEL, manifest_digest=digest, entries=manifest, frozen=_frozen(digest))
    assert len(report["valid"]) == len(manifest) and not report["invalid"]
    kept, excluded = select_rows(completed_rows(layout.rows_dir), manifest, digest, model=MODEL, repeat=1)
    assert len(kept) == len(manifest) and excluded == {}


# -- quarantine reasons ---------------------------------------------------------------------


def test_a_quarantined_row_gets_a_reason_file_and_the_record_names_it(tmp_path, corpus, pipeline, manifest) -> None:
    layout, digest, _ = _write_rows(tmp_path, corpus, pipeline, manifest)
    files = sorted(layout.rows_dir.glob("*.json"))
    tampered = json.loads(files[0].read_text(encoding="utf-8"))
    tampered["header"]["prompt_version"] = "d1-investigator-v9"
    tampered["row"]["manifest_hash"] = "f" * 64
    files[0].write_text(json.dumps(tampered), encoding="utf-8")

    record = RunRecord.start(layout, "validate-rows", argv=[], write=False)
    report = validate_rows(
        layout.rows_dir, model=MODEL, manifest_digest=digest, entries=manifest, frozen=_frozen(digest),
        quarantine=True, record=record,
    )
    assert len(report["quarantined"]) == 1 and report["run_id"] == record.run_id
    moved = layout.quarantine_dir / files[0].name
    reason_path = moved.with_name(moved.stem + ".reason.json")
    assert moved.exists() and reason_path.exists() and not files[0].exists()
    reason = json.loads(reason_path.read_text(encoding="utf-8"))
    assert reason["run_id"] == record.run_id
    assert reason["manifest_hash_expected"] == digest and reason["manifest_hash_found"] == "f" * 64
    assert reason["prompt_version_expected"] == D1_PROMPT_VERSION and reason["prompt_version_found"] == "d1-investigator-v9"
    assert any("manifest hash" in p for p in reason["problems"]) and any("prompt version" in p for p in reason["problems"])
    assert reason["key_digest"] == RowKey(**tampered["key"]).digest
    assert record.quarantined[0]["reasons"] == reason["problems"]
    assert record.quarantined[0]["key_digest"] == reason["key_digest"]


# -- the silent-zero summary ----------------------------------------------------------------


def test_summarising_zero_rows_beside_a_full_sibling_directory_is_refused(tmp_path, corpus, pipeline, manifest) -> None:
    layout, digest, _ = _write_rows(tmp_path, corpus, pipeline, manifest)
    other_manifest = Layout(tmp_path, "D1", MODEL, "e" * 64)
    with pytest.raises(NothingToSummarise) as caught:
        refuse_silent_zero(other_manifest, [])
    assert layout.rows_dir.name in str(caught.value) and "REFUSED" in str(caught.value)
    refuse_silent_zero(other_manifest, [], allow_empty=True)
    refuse_silent_zero(layout, completed_rows(layout.rows_dir))


def test_summarising_zero_rows_with_nothing_beside_them_is_just_empty(tmp_path) -> None:
    refuse_silent_zero(_layout(tmp_path, "e" * 64), [])


# -- the spec ---------------------------------------------------------------------------------


def test_a_spec_round_trips_and_hashes_stably(tmp_path) -> None:
    spec = ExperimentSpec(name="t", models=("a:1b", "b:2b"), smoke_cases=("x/CASE-001",), notes=("n",))
    path = spec.save(tmp_path / "t.json")
    again = ExperimentSpec.load(path)
    assert again == spec and again.sha256() == spec.sha256()
    assert spec.with_overrides(seed=None, repeat=3).repeat == 3
    with pytest.raises(ValueError):
        ExperimentSpec.from_dict({"name": "t", "commit": "abc"})


def test_the_committed_spec_names_the_current_frozen_surface() -> None:
    from ath.experiments.identity import frozen_surface_sha256
    from ath.experiments.spec import SPECS_DIR

    spec = ExperimentSpec.load(SPECS_DIR / "d1_model_comparison.json")
    assert spec.frozen_surface_sha256 == frozen_surface_sha256()
    assert spec.models == ("qwen3.5:4b", "qwen3.5:9b") and spec.arm == "D1"


def test_flags_override_the_spec_and_the_spec_overrides_the_defaults(tmp_path) -> None:
    spec = ExperimentSpec(name="t", models=("m:1b",), seed=7, out_dir=str(tmp_path))
    path = spec.save(tmp_path / "t.json")
    args = build_parser().parse_args(["run", "--spec", str(path), "--seed", "9"])
    resolved, loaded = resolve(args)
    assert loaded == spec
    assert resolved.model == "m:1b" and resolved.seed == 9 and Path(resolved.out_dir) == tmp_path
    args = build_parser().parse_args(["run"])
    resolved, loaded = resolve(args)
    assert loaded is None and resolved.model == "qwen3.5:4b" and resolved.seed == 0
