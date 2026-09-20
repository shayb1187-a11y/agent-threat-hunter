"""`validate-rows`: a row restored from elsewhere is accepted only when everything it
recorded matches the live freeze and manifest; otherwise it is named, and with
``--quarantine`` moved aside, never deleted. Scripted client, fixture corpus."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import local_ablation as run_script  # noqa: E402
import m19_ablation as m19  # noqa: E402
from ath.agent.investigator import D1_PROMPT_VERSION  # noqa: E402
from ath.agent.llm import ScriptedLLM  # noqa: E402
from ath.evaluation.ablation import manifest_hash  # noqa: E402
from ath.evaluation.ablation.environment import tool_surface  # noqa: E402
from ath.evaluation.ablation.local import ModelSpec, arm_d1, completed_rows  # noqa: E402
from test_ablation_harness import corpus, manifest, pipeline  # noqa: F401,E402

MODEL = "fake:4b"
SPEC = ModelSpec("ollama", MODEL, "Q4_K_M", "4.7B", "a" * 64)
CONF = {"model": MODEL, "num_ctx": 10240, "num_predict_cap": 2048, "think": False, "format": "schema", "base_url": "http://x"}


def _frozen(digest: str) -> dict:
    return {"manifest_hash": digest, "local": {
        "model": SPEC.to_dict(), "daemon": {"version": "0.34.2"},
        "client_configuration": dict(CONF, base_url="http://elsewhere"),
    }}


def _write_rows(tmp_path, corpus, pipeline, manifest):
    findings, cases, environment = pipeline
    digest = manifest_hash(manifest)
    header = {"head": "t", "prompt_version": D1_PROMPT_VERSION, "manifest_hash": digest, "model": SPEC.to_dict(),
              "daemon_version": "0.34.2", "client_configuration": CONF}
    directory = run_script.rows_dir(tmp_path, "D1", MODEL, digest)
    run_script.run_rows(
        arm=arm_d1(MODEL), client=ScriptedLLM(responses=['{"claims": []}'] * 64, name="s"), spec=SPEC,
        entries=manifest, bundles=[m19.Bundle(name="fixture", telemetry=corpus, findings=findings, cases=cases, environment=environment)],
        manifest_digest=digest, rows_directory=directory, header=header, repeats=[1], seed=0,
        surface=tool_surface(), ram_floor=None, ram_reader=lambda: 8 * run_script.GIB, log=lambda _t: None,
    )
    return directory, digest


def test_rows_written_by_this_freeze_are_valid(tmp_path, corpus, pipeline, manifest) -> None:
    directory, digest = _write_rows(tmp_path, corpus, pipeline, manifest)
    report = run_script.validate_rows(directory, model=MODEL, manifest_digest=digest, entries=manifest, frozen=_frozen(digest))
    assert len(report["valid"]) == len(manifest) and report["invalid"] == {} and report["quarantined"] == []


def test_a_row_from_other_weights_or_prompts_is_named_and_quarantined_not_deleted(tmp_path, corpus, pipeline, manifest) -> None:
    directory, digest = _write_rows(tmp_path, corpus, pipeline, manifest)
    files = sorted(directory.glob("*.json"))
    tampered = json.loads(files[0].read_text(encoding="utf-8"))
    tampered["header"]["model"]["digest"] = "b" * 64
    tampered["header"]["prompt_version"] = "d1-investigator-v9"
    tampered["header"]["client_configuration"] = dict(CONF, num_predict_cap=4096)
    files[0].write_text(json.dumps(tampered), encoding="utf-8")

    report = run_script.validate_rows(directory, model=MODEL, manifest_digest=digest, entries=manifest, frozen=_frozen(digest))
    assert list(report["invalid"]) == [files[0].name]
    reasons = " ".join(report["invalid"][files[0].name])
    assert "model digest" in reasons and "prompt version" in reasons and "num_predict_cap" in reasons
    assert files[0].exists(), "without --quarantine nothing moves"

    report = run_script.validate_rows(directory, model=MODEL, manifest_digest=digest, entries=manifest, frozen=_frozen(digest), quarantine=True)
    assert not files[0].exists()
    moved = directory.with_name(directory.name + ".quarantine") / files[0].name
    assert moved.exists() and json.loads(moved.read_text(encoding="utf-8"))["header"]["prompt_version"] == "d1-investigator-v9"
    assert len(completed_rows(directory)) == len(manifest) - 1
    again = run_script.validate_rows(directory, model=MODEL, manifest_digest=digest, entries=manifest, frozen=_frozen(digest))
    assert again["invalid"] == {}


def test_a_row_under_another_manifest_or_model_is_invalid(tmp_path, corpus, pipeline, manifest) -> None:
    directory, digest = _write_rows(tmp_path, corpus, pipeline, manifest)
    frozen = _frozen(digest)
    report = run_script.validate_rows(directory, model="other:9b", manifest_digest=digest, entries=manifest, frozen=frozen)
    assert all("is not 'other:9b'" in " ".join(v) for v in report["invalid"].values()) and len(report["invalid"]) == len(manifest)
    report = run_script.validate_rows(directory, model=MODEL, manifest_digest="f" * 64, entries=manifest, frozen=frozen)
    assert all("manifest hash" in " ".join(v) for v in report["invalid"].values())
