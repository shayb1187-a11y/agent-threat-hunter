"""The paired model comparison: reads two row sets, refuses anything but a model
difference, and orders each dimension by a stated rule. Driven end to end with two
scripted clients over the fixture corpus; no model, no DEDALE data."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import local_ablation as run_script  # noqa: E402
import local_compare as compare_script  # noqa: E402
import m19_ablation as m19  # noqa: E402
from ath.agent.llm import ScriptedLLM  # noqa: E402
from ath.evaluation.ablation import manifest_hash  # noqa: E402
from ath.evaluation.ablation.environment import tool_surface  # noqa: E402
from ath.evaluation.ablation.local import (  # noqa: E402
    ModelSpec,
    arm_d1,
    completed_rows,
    investigator_environment,
)
from test_ablation_harness import corpus, manifest, pipeline  # noqa: F401,E402


def _bundle(corpus, pipeline):
    findings, cases, environment = pipeline
    return m19.Bundle(name="fixture", telemetry=corpus, findings=findings, cases=cases, environment=environment)


def _abstain() -> str:
    return json.dumps({"explanations": [{"label": "insufficient", "statement": "s", "evidence": []}],
                       "evidence_gap": "g", "next_probe": "none", "probe_reason": "", "disposition": "abstain"})


def _probe_then_decide() -> list[str]:
    first = json.dumps({"explanations": [{"label": "malicious", "statement": "s", "evidence": []}],
                        "evidence_gap": "g", "next_probe": "P1", "probe_reason": "look", "disposition": "abstain"})
    second = json.dumps({"explanations": [{"label": "malicious", "statement": "s", "evidence": []}],
                         "evidence_gap": "g", "next_probe": "none", "probe_reason": "", "disposition": "malicious"})
    return [first, second]


def _run(tmp_path, corpus, pipeline, manifest, *, model: str, responses: list[str], header_extra=None):
    spec = ModelSpec("scripted", model, "Q4", "1.0B", "d" * 64)
    digest = manifest_hash(manifest)
    header = {
        "head": "test", "prompt_version": "d1-investigator-v3", "manifest_hash": digest,
        "model": spec.to_dict(), "daemon_version": "0.0", "frozen_head": "test",
        "client_configuration": {"model": model, "num_ctx": 10240, "num_predict_cap": 2048, "think": False, "format": "schema"},
        **(header_extra or {}),
    }
    run_script.run_rows(
        arm=arm_d1(model), client=ScriptedLLM(responses=list(responses) * 64, name="scripted"), spec=spec,
        entries=manifest, bundles=[_bundle(corpus, pipeline)], manifest_digest=digest,
        rows_directory=run_script.rows_dir(tmp_path, "D1", model, digest), header=header, repeats=[1], seed=0,
        surface=tool_surface(), ram_floor=None, ram_reader=lambda: 8 * run_script.GIB, log=lambda _t: None,
    )
    rows = completed_rows(run_script.rows_dir(tmp_path, "D1", model, digest))
    # run_rows stamps the live investigator hashes on every header, as cmd_run does.
    return rows


def test_two_models_under_one_investigator_pair_by_case_and_order_by_rule(tmp_path, corpus, pipeline, manifest) -> None:
    rows_a = _run(tmp_path, corpus, pipeline, manifest, model="fake:1b", responses=[_abstain()])
    rows_b = _run(tmp_path, corpus, pipeline, manifest, model="fake:9b", responses=_probe_then_decide())
    assert all(r["header"]["investigator"] == investigator_environment() for r in rows_a + rows_b)
    result = compare_script.compare(rows_a, rows_b)
    assert result["model_a"] == "fake:1b" and result["model_b"] == "fake:9b"
    assert result["paired_cases"] == len(manifest) and result["unpaired_cases"] == []
    agg_a, agg_b = result["aggregate"]["fake:1b"], result["aggregate"]["fake:9b"]
    assert agg_a["probes_total"] == 0 and agg_b["probes_total"] == len(manifest)
    assert agg_b["productive_probes"] + agg_b["unproductive_probes"] == agg_b["probes_total"]
    assert agg_a["decisions"] == {} or set(agg_a["decisions"]) <= {"abstain"}
    tallies = result["tallies_b_vs_a"]
    assert sum(tallies["productive"].values()) == len(manifest)
    assert tallies["tokens"].get("worse", 0) == len(manifest), "B spent more tokens (two calls to A's one)"
    text = compare_script.render(result)
    assert "paired model comparison" in text and "fake:9b" in text and "## Per case" in text
    assert "B vs A" in text


def test_rows_from_different_prompt_versions_are_refused(tmp_path, corpus, pipeline, manifest) -> None:
    rows_a = _run(tmp_path, corpus, pipeline, manifest, model="fake:1b", responses=[_abstain()])
    rows_b = _run(tmp_path, corpus, pipeline, manifest, model="fake:9b", responses=[_abstain()],
                  header_extra={"prompt_version": "d1-investigator-v4"})
    with pytest.raises(compare_script.NotComparable, match="prompt_version"):
        compare_script.compare(rows_a, rows_b)


def test_rows_with_a_different_token_budget_are_refused(tmp_path, corpus, pipeline, manifest) -> None:
    rows_a = _run(tmp_path, corpus, pipeline, manifest, model="fake:1b", responses=[_abstain()])
    rows_b = _run(tmp_path, corpus, pipeline, manifest, model="fake:9b", responses=[_abstain()],
                  header_extra={"client_configuration": {"model": "fake:9b", "num_ctx": 10240, "num_predict_cap": 4096, "think": False, "format": "schema"}})
    with pytest.raises(compare_script.NotComparable, match="num_predict_cap"):
        compare_script.compare(rows_a, rows_b)


def test_the_same_model_twice_is_not_a_model_comparison(tmp_path, corpus, pipeline, manifest) -> None:
    rows = _run(tmp_path, corpus, pipeline, manifest, model="fake:1b", responses=[_abstain()])
    with pytest.raises(compare_script.NotComparable, match="needs two models"):
        compare_script.compare(rows, rows)


def test_the_orderings_are_the_stated_rules() -> None:
    base = {"decision": None, "link_2": None, "new_used": 0, "productive_probes": 0, "rejected": 0,
            "invalid_refs": 0, "tokens": 100, "wall_seconds": 10.0}
    a = dict(base, decision="abstain", link_2=False, rejected=2, tokens=100)
    b = dict(base, decision="correct", link_2=True, rejected=0, tokens=300)
    assert compare_script._order("decision", a, b) == "better"
    assert compare_script._order("decision", b, a) == "worse"
    assert compare_script._order("link_2", a, b) == "better"
    assert compare_script._order("rejected", a, b) == "better"
    assert compare_script._order("tokens", a, b) == "worse"
    assert compare_script._order("wall", a, b) == "same"
    assert compare_script._order("decision", dict(base), b) is None, "unlabelled rows are not ordered"
    assert compare_script._order("link_2", dict(base), b) is None
