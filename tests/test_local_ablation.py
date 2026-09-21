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
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import local_ablation as run_script  # noqa: E402
import m19_ablation as m19  # noqa: E402
from ath.agent.llm import ScriptedLLM  # noqa: E402
from ath.evaluation.ablation import manifest_hash  # noqa: E402
from ath.evaluation.ablation.environment import tool_surface  # noqa: E402
from ath.evaluation.ablation.local import (  # noqa: E402
    ARM_D1,
    ModelSpec,
    RowKey,
    arm_d1,
    completed_rows,
    row_path,
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


# --------------------------------------------------------------------------------------
# Provenance: which rows a summary may read
# --------------------------------------------------------------------------------------

ABSTAIN = (
    '{"explanations": [{"label": "insufficient", "statement": "not enough", "evidence": []}], '
    '"evidence_gap": "g", "next_probe": "none", "probe_reason": "", "disposition": "abstain"}'
)


def test_the_row_key_and_the_rows_directory_carry_the_manifest_hash(tmp_path, corpus, pipeline, manifest) -> None:
    """The 2026-09-15 rows were keyed without the manifest, so a rerun against the
    regenerated manifest would have skipped every case as already complete."""
    digest = manifest_hash(manifest)
    _run(tmp_path, corpus, pipeline, manifest, client=ScriptedLLM(responses=[ABSTAIN] * 64, name="scripted"))
    row = completed_rows(tmp_path / "rows")[0]
    key = RowKey.from_dict(row["key"])
    assert key.manifest_hash == digest
    assert f"m{digest[:12]}" in row_path(tmp_path / "rows", key).name
    other = RowKey.from_dict({**row["key"], "manifest_hash": "f" * 64})
    assert other.filename != key.filename, "a different manifest is a different row"
    directory = run_script.rows_dir(tmp_path, "D1", "fake:1b", digest)
    assert directory.name.startswith(f"m{digest[:12]}_")
    assert run_script.rows_dir(tmp_path, "D1", "fake:1b", "e" * 64) != directory


def test_a_stale_manifest_row_is_rejected_and_a_matching_one_accepted(tmp_path, corpus, pipeline, manifest) -> None:
    digest = manifest_hash(manifest)
    _run(tmp_path, corpus, pipeline, manifest, client=ScriptedLLM(responses=[ABSTAIN] * 64, name="scripted"))
    rows = completed_rows(tmp_path / "rows")
    for row in rows:
        row["header"]["investigator"] = run_script.investigator_environment()
    kept, excluded = run_script.select_rows(rows, manifest, digest, model="fake:1b", repeat=1)
    assert len(kept) == len(rows) and excluded == {}
    kept, excluded = run_script.select_rows(rows, manifest, "f" * 64, model="fake:1b", repeat=1)
    assert kept == [] and excluded == {"stale_manifest": len(rows)}


def test_a_telemetry_hash_mismatch_is_rejected(tmp_path, corpus, pipeline, manifest) -> None:
    digest = manifest_hash(manifest)
    _run(tmp_path, corpus, pipeline, manifest, client=ScriptedLLM(responses=[ABSTAIN] * 64, name="scripted"))
    rows = completed_rows(tmp_path / "rows")
    for row in rows:
        row["header"]["investigator"] = run_script.investigator_environment()
    rows[0]["row"]["telemetry_hash"] = "0" * 64
    kept, excluded = run_script.select_rows(rows, manifest, digest, model="fake:1b", repeat=1)
    assert len(kept) == len(rows) - 1 and excluded == {"telemetry_hash_mismatch": 1}


def test_a_row_under_different_investigator_prompts_is_rejected(tmp_path, corpus, pipeline, manifest) -> None:
    digest = manifest_hash(manifest)
    _run(tmp_path, corpus, pipeline, manifest, client=ScriptedLLM(responses=[ABSTAIN] * 64, name="scripted"))
    rows = completed_rows(tmp_path / "rows")
    for row in rows:
        row["header"]["investigator"] = {**run_script.investigator_environment(), "investigator_system": "0" * 64}
    kept, excluded = run_script.select_rows(rows, manifest, digest, model="fake:1b", repeat=1)
    assert kept == [] and excluded == {"investigator_prompt_drift": len(rows)}


def _link_row(*, manifest_hash: str, scored_under: str, telemetry: str = "t" * 64, links=None) -> dict:
    row = _row()
    row["row"]["manifest_hash"] = manifest_hash
    row["row"]["telemetry_hash"] = telemetry
    row["row"]["labels"] = {"verdict": "malicious"}
    row["row"]["label_scores"] = {} if links is None else {
        "links": links, "link_scoring": {"manifest_hash": scored_under, "telemetry_hash": telemetry},
    }
    return row


def test_link_scores_are_never_synthesised_or_read_for_stale_rows() -> None:
    current = "a" * 64
    links = {"X-LINK-1": True, "X-LINK-2": False}
    pinned = {"c/CASE-001": "t" * 64}
    # Scored under the current manifest, run against it, telemetry pinned: readable.
    good = run_script.row_summary(_link_row(manifest_hash=current, scored_under=current, links=links),
                                  manifest_digest=current, telemetry_hashes=pinned)
    assert good["links_valid"] is True and good["links"] == links
    # Run against a stale manifest: refused, and nothing is computed in its place.
    stale = run_script.row_summary(_link_row(manifest_hash="b" * 64, scored_under="b" * 64, links=links),
                                   manifest_digest=current, telemetry_hashes=pinned)
    assert stale["links_valid"] is False and stale["links"] is None
    # Scored under another manifest than the one it was run against: refused.
    mixed = run_script.row_summary(_link_row(manifest_hash=current, scored_under="b" * 64, links=links),
                                   manifest_digest=current, telemetry_hashes=pinned)
    assert mixed["links_valid"] is False
    # Telemetry no longer pinned by the manifest for this case: refused.
    moved = run_script.row_summary(_link_row(manifest_hash=current, scored_under=current, links=links),
                                   manifest_digest=current, telemetry_hashes={"c/CASE-001": "u" * 64})
    assert moved["links_valid"] is False
    # A row that carries no link scores has none; nothing is invented.
    none = run_script.row_summary(_link_row(manifest_hash=current, scored_under=current),
                                  manifest_digest=current, telemetry_hashes=pinned)
    assert none["links_valid"] is False and none["links"] is None
    summary = run_script.summarise([good["key"] and _link_row(manifest_hash=current, scored_under=current, links=links),
                                    _link_row(manifest_hash="b" * 64, scored_under="b" * 64, links=links)],
                                   expected_cases=2, manifest_digest=current, telemetry_hashes=pinned)
    inv = summary["investigation"]
    assert inv["link_scorable_rows"] == 1 and inv["link_unscorable_rows"] == 1
    assert (inv["link_1_recovered"], inv["link_1_defined"], inv["link_1_score"]) == (1, 1, 1.0)
    assert (inv["link_2_recovered"], inv["link_2_defined"], inv["link_2_score"]) == (0, 1, 0.0)


def _labelled(verdict, disposition, *, benign_final=False, tools=(), returned=0, used=0, truncated=False, changed=False):
    row = _row()
    row["row"]["labels"] = {"verdict": verdict} if verdict else {}
    row["row"]["state"]["investigation"] = {
        "final_disposition": disposition, "abstained": disposition == "abstain",
        "benign_hypothesis_present_initial": benign_final, "benign_hypothesis_present_final": benign_final,
        "chosen_tool": tools[0] if tools else None, "chosen_tools": list(tools), "probes_run": list(tools),
        "trajectory": ["seed", *tools], "new_evidence_ids_returned": returned, "new_evidence_ids_used": used,
        "output_truncated": truncated, "hypothesis_changed_after_tool": changed, "labels_changed_after_tool": changed,
        "evidence_gap": "g", "tool_choice_reason": "r", "model_calls": 1 + len(tools),
    }
    return row


def test_the_investigation_metrics_are_counted_from_labels_and_dispositions() -> None:
    rows = [
        _labelled("malicious", "malicious", tools=("process_tree",), returned=2, used=1, changed=True),
        _labelled("malicious", "abstain"),
        _labelled("benign", "malicious", tools=("user_auth_history",), returned=3),
        _labelled("benign", "benign", benign_final=True, tools=("process_tree",), returned=1, used=1),
        _labelled(None, "abstain", truncated=True),
    ]
    inv = run_script.summarise(rows, expected_cases=5)["investigation"]
    assert inv["labelled_rows"] == 4 and inv["malicious_cases"] == 2 and inv["benign_cases"] == 2
    assert inv["malicious_called_malicious"] == 1 and inv["malicious_abstained"] == 1
    assert inv["benign_called_malicious"] == 1 and inv["benign_called_benign"] == 1
    assert inv["benign_false_narrative_rate"] == 0.5
    assert inv["benign_retaining_benign_alternative"] == 1
    assert inv["abstentions"] == 2 and inv["abstention_rate"] == 0.4
    assert inv["cases_with_tool_call"] == 3 and inv["probes_total"] == 3
    assert inv["first_tool_distribution"] == {"process_tree": 2, "user_auth_history": 1}
    assert inv["tool_choice_diversity"] == 2
    assert inv["unique_trajectories"] == 3
    assert inv["cases_retrieving_new_evidence"] == 3 and inv["cases_using_new_evidence"] == 2
    assert inv["truncated_rows"] == 1 and inv["truncation_rate"] == 0.2
    assert inv["hypothesis_changed_after_tool"] == 1
    assert inv["link_1_defined"] == 0 and inv["link_1_score"] is None
