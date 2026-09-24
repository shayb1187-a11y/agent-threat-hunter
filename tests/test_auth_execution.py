"""Evaluation integrity, failure denominators and observation recovery."""

import json
from copy import deepcopy

import pytest

from ath.agent.llm import ScriptedLLM
from ath.evaluation import auth_execution as pilot


@pytest.fixture(scope="module")
def development():
    return pilot.scenarios("dev")


def answer(disposition="abstain", explanations=None):
    return json.dumps({"explanations": explanations or [], "evidence_gap": "intent not established",
                       "next_probe": "none", "probe_reason": "", "disposition": disposition})


def test_generated_followup_is_unflagged_but_baseline_retrieves_it(development):
    scenario = development[0]
    _, case, _ = pilot.prepare(scenario)
    assert not set(case.event_ids) & set(scenario.useful_ids)
    row, report = pilot.evaluate_case(scenario, "deterministic")
    assert row["scores"]["complete"]
    assert row["scores"]["useful_retrieved"] == row["scores"]["useful_cited"] == 1
    assert row["scores"]["link_recovered"]
    assert row["scores"]["accepted_invalid_predicates"] == 0
    assert report.evidence_verification["observations_verified"] > 0


def test_labels_are_scoring_only_and_scripted_results_are_marked(development):
    client = ScriptedLLM(responses=[answer()])
    with pytest.raises(ValueError, match="explicitly labelled"):
        pilot.evaluate_case(development[2], "d1", client)
    row, _ = pilot.evaluate_case(development[2], "d1", client, scripted=True)
    assert row["scripted"] and row["scores"]["missing_data_abstained"]
    assert row["scores"]["semantic_prose_correctness"] is None
    for system, prompt, *_ in client.calls:
        assert "expected_decision" not in system + prompt
        assert "sample-03" not in system + prompt


def test_runtime_failure_is_not_counted_as_correct_abstention(development):
    row, _ = pilot.evaluate_case(development[2], "d1", ScriptedLLM(responses=["invalid JSON"]), scripted=True)
    assert row["scores"]["decision"] == "abstain"
    assert not row["scores"]["complete"]
    assert not row["scores"]["correct"]
    assert not row["scores"]["missing_data_abstained"]


def test_freeze_detects_changed_code_and_tampering(monkeypatch):
    monkeypatch.setattr(pilot, "source_hash", lambda: "original")
    freeze = pilot.make_freeze("dev", {"digest": "fake"}, {}, repeats=1)
    pilot.validate_freeze(freeze)
    altered = deepcopy(freeze)
    altered["repeats"] = 8
    with pytest.raises(ValueError, match="altered"):
        pilot.validate_freeze(altered)
    monkeypatch.setattr(pilot, "source_hash", lambda: "different")
    with pytest.raises(ValueError, match="code or telemetry changed"):
        pilot.validate_freeze(freeze)


def test_summary_preserves_missing_rows_and_refuses_modified_rows(development):
    freeze = pilot.make_freeze("dev", {"digest": "fake"}, {}, repeats=1)
    row, _ = pilot.evaluate_case(development[0], "deterministic")
    row = pilot.seal_row({**row, "repeat": 1, "freeze_sha256": freeze["freeze_sha256"]})
    summary = pilot.summarise(freeze, [row])
    assert not summary["complete_comparison"] and len(summary["missing_rows"]) == 5
    assert summary["conclusion"] == "investigative value not demonstrated"
    with pytest.raises(ValueError, match="duplicate"):
        pilot.summarise(freeze, [row, row])
    row["scores"]["correct"] = False
    with pytest.raises(ValueError, match="altered"):
        pilot.summarise(freeze, [row])
    row = pilot.seal_row({**row, "freeze_sha256": "different"})
    with pytest.raises(ValueError, match="different freezes"):
        pilot.summarise(freeze, [row])


def test_full_scripted_comparison_cannot_demonstrate_ai_value(development):
    freeze = pilot.make_freeze("dev", {"digest": "fake"}, {}, repeats=1)
    rows = []
    for scenario in development:
        for arm in ("deterministic", "d1"):
            client = ScriptedLLM(responses=[answer(scenario.expected_decision)]) if arm == "d1" else None
            row, _ = pilot.evaluate_case(scenario, arm, client, scripted=arm == "d1")
            rows.append(pilot.seal_row({**row, "repeat": 1, "freeze_sha256": freeze["freeze_sha256"]}))
    summary = pilot.summarise(freeze, rows)
    assert summary["complete_comparison"]
    assert summary["conclusion"] == "scripted plumbing test only"


def test_raw_artifacts_cannot_be_overwritten(tmp_path):
    target = tmp_path / "rows" / "one.json"
    pilot.write_new(target, {"x": 1})
    with pytest.raises(FileExistsError):
        pilot.write_new(target, {"x": 2})
    assert json.loads(target.read_text())["x"] == 1


@pytest.mark.parametrize("profile", ["operational-v2", "operational-v3", "operational-v4", "operational-v5"])
def test_cli_freeze_baseline_and_resume_without_model_calls(tmp_path, monkeypatch, capsys, profile):
    class MetadataOnly:
        def describe(self):
            return {"digest": "fake", "daemon_version": "test"}

        def configuration(self):
            return {"model": "test"}

    monkeypatch.setattr(pilot, "_client", lambda model, profile=None: MetadataOnly())
    out = tmp_path / "pilot"
    assert pilot.main(["freeze", "--out", str(out), "--repeats", "1", "--profile", profile]) == 0
    assert pilot.main(["run", "--out", str(out), "--arm", "deterministic"]) == 0
    saved = {p.name: p.read_bytes() for p in (out / "rows").glob("*.json")}
    assert len(saved) == 3
    assert pilot.main(["run", "--out", str(out), "--arm", "deterministic"]) == 0
    assert saved == {p.name: p.read_bytes() for p in (out / "rows").glob("*.json")}
    assert not json.loads((out / "SUMMARY.json").read_text())["complete_comparison"]
