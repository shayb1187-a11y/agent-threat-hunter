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


# -- no silent row loss: blocked and errored attempts --------------------------------------


class GuardedClient:
    """Model identity only; the guard reads ``resident_bytes`` and nothing is ever called."""

    def describe(self):
        return {"digest": "fake", "daemon_version": "test", "parameter_size": "9B"}

    def configuration(self):
        return {"model": "test"}

    def resident_bytes(self):
        return 0


def _scripted_d1(scenario, arm, client, *, profile=None):
    return pilot.evaluate_case(scenario, arm, ScriptedLLM(responses=[answer()]), scripted=True, profile=profile)


def _run(out, freeze, cases, evaluate):
    return pilot.run_rows(out, freeze, cases, GuardedClient(), None, "d1", evaluate)


def _stubs(out):
    return sorted(p.name for p in (out / "rows" / pilot.ATTEMPTS_DIR).glob("*.json"))


def test_ram_block_leaves_a_sealed_stub_and_resume_retries_the_row(development, tmp_path, monkeypatch):
    """A blocked row used to vanish: one line on stdout, nothing on disk. On Colab that line
    scrolls away and the summary could not say *why* a row was missing. Now the block is a
    sealed record -- and it must not stand in for the row, or a resume would skip a case the
    model never saw. The retry writes the real row; both records survive."""
    freeze = pilot.make_freeze("dev", GuardedClient().describe(), GuardedClient().configuration(), repeats=1)
    out = tmp_path / "run"
    monkeypatch.setattr(pilot, "available_ram_bytes", lambda: 0)
    assert _run(out, freeze, development[:1], _scripted_d1) == 3
    assert _run(out, freeze, development[:1], _scripted_d1) == 3  # a second block is a second record
    assert not list((out / "rows").glob("*.json"))
    assert _stubs(out) == ["sample-01_d1_1.attempt-1.json", "sample-01_d1_1.attempt-2.json"]
    stub = pilot.read_attempts(out)[0]
    assert stub["status"] == pilot.BLOCKED and stub["reason"] == "RAM guard"
    assert stub["ram_guard"]["ok"] is False and stub["ram_guard"]["available_bytes"] == 0
    assert set(stub["host_memory"]) == {"process_rss_bytes", "available_ram_bytes"}
    summary = pilot.summarise(freeze, [], pilot.read_attempts(out))
    assert ("sample-01", "d1", 1) in summary["blocked_rows"] and ("sample-01", "d1", 1) in summary["missing_rows"]
    assert ("sample-01", "d1", 1) not in summary["unattempted_rows"]

    monkeypatch.setattr(pilot, "available_ram_bytes", lambda: 1 << 50)
    assert _run(out, freeze, development[:1], _scripted_d1) == 0
    row = json.loads((out / "rows" / "sample-01_d1_1.json").read_text(encoding="utf-8"))
    assert set(row["host_memory"]) == {"process_rss_bytes", "available_ram_bytes"}
    assert len(_stubs(out)) == 2  # history is kept after the row completes
    summary = pilot.summarise(freeze, [row], pilot.read_attempts(out))
    assert summary["blocked_rows"] == [] and summary["recovered_rows"] == [("sample-01", "d1", 1)]


def test_evaluation_error_is_recorded_then_raised(development, tmp_path, monkeypatch):
    """An exception is a harness fault that would repeat on every remaining row, so the run
    stops loudly -- but only after the stub says which row, what type, what message. The
    stub is not a row: the next run retries and succeeds, and the summary separates errored
    from blocked from never attempted."""
    freeze = pilot.make_freeze("dev", GuardedClient().describe(), GuardedClient().configuration(), repeats=1)
    out = tmp_path / "run"
    monkeypatch.setattr(pilot, "available_ram_bytes", lambda: 1 << 50)

    def broken(*args, **kwargs):
        raise RuntimeError("daemon went away " + "x" * 10000)

    with pytest.raises(RuntimeError, match="daemon went away"):
        _run(out, freeze, development[:2], broken)
    (stub,) = pilot.read_attempts(out)
    assert stub["status"] == pilot.ERRORED and stub["error"]["type"] == "RuntimeError"
    assert len(stub["error"]["message"]) <= pilot.TRACEBACK_CHARS and stub["error"]["traceback_truncated"]
    summary = pilot.summarise(freeze, [], pilot.read_attempts(out))
    assert summary["errored_rows"] == [("sample-01", "d1", 1)] and summary["blocked_rows"] == []
    assert ("sample-02", "d1", 1) in summary["unattempted_rows"]
    tampered = {**stub, "status": pilot.BLOCKED}
    with pytest.raises(ValueError, match="altered"):
        pilot.summarise(freeze, [], [tampered])

    assert _run(out, freeze, development[:2], _scripted_d1) == 0
    rows = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((out / "rows").glob("*.json"))]
    summary = pilot.summarise(freeze, rows, pilot.read_attempts(out))
    assert summary["errored_rows"] == [] and summary["recovered_rows"] == [("sample-01", "d1", 1)]


# -- summary metrics ------------------------------------------------------------------------


def _hand_row(freeze, key, expected, arm, decision, *, seconds=1.0, complete=True, served=4, probes=()):
    correct = complete and decision == expected
    scores = {"expected_decision": expected, "decision": decision, "complete": complete, "correct": correct,
              "false_malicious": expected == "benign" and decision == "malicious",
              "false_benign": expected == "malicious" and decision == "benign",
              "missing_data_abstained": expected == "abstain" and complete and decision == "abstain",
              "useful_available": 1, "useful_retrieved": 1, "useful_cited": int(correct),
              "link_available": True, "link_recovered": correct, "rejected_claims": 0,
              "accepted_invalid_predicates": 0, "unverified_prose": 0, "semantic_prose_correctness": None,
              "elapsed_seconds": seconds, "tokens": 0, "local_api_charge_usd": 0.0, "hardware_energy_cost_usd": None}
    investigation = {"operational": {"tool_calls_served": served, "tool_calls_refused": 0, "tool_results_truncated": 1}}
    if arm == "d1":
        investigation["probes_run"] = list(probes)
    return pilot.seal_row({"sample": key, "arm": arm, "scripted": False, "scores": scores,
                           "state": {"investigation": investigation}, "repeat": 1,
                           "freeze_sha256": freeze["freeze_sha256"]})


def test_summary_metrics_use_frozen_denominators_and_split_by_platform():
    """Figures computed by hand on four cases. The design claims under test: a missing
    row counts against recall (denominators come from the freeze, not from whatever
    finished); an abstention is never a correct decision on a labelled case; balanced
    accuracy is reported per platform and is None for a single-class group, since one
    class cannot show discrimination."""
    cases = [("w-mal", "malicious", "windows"), ("w-ben", "benign", "windows"),
             ("k-mal", "malicious", "k8s"), ("k-ben", "benign", "k8s")]
    freeze = {"freeze_sha256": "hand", "split": "hand", "repeats": 1, "protocol": {},
              "manifest": [{"key": k, "expected_decision": e, "platform": p, "quadrant": f"{p}-{e}"}
                           for k, e, p in cases]}
    rows = [_hand_row(freeze, k, e, "deterministic", e) for k, e, _ in cases]
    rows += [_hand_row(freeze, "w-mal", "malicious", "d1", "malicious", seconds=1, probes=["process_tree"]),
             _hand_row(freeze, "w-ben", "benign", "d1", "abstain", seconds=2, served=6, probes=["a", "b"]),
             _hand_row(freeze, "k-mal", "malicious", "d1", "benign", seconds=10)]
    summary = pilot.summarise(freeze, rows)  # k-ben/d1 never ran
    d1 = summary["arms"]["d1"]["metrics"]
    assert (d1["expected_rows"], d1["rows"], d1["correct"], d1["abstained"]) == (4, 3, 1, 1)
    assert (d1["unsafe_clears"], d1["false_accusations"], d1["correct_abstentions"]) == (1, 0, 0)
    assert d1["recall"] == {"malicious": 0.5, "benign": 0.0} and d1["balanced_accuracy"] == 0.25
    assert d1["latency_seconds"] == {"median": 2, "p90": 10, "max": 10}
    assert d1["tool_usage"] == {"tool_calls_served": 14, "tool_calls_refused": 0, "tool_results_truncated": 3,
                                "unknown_rows": 0, "probes_run": 3, "probes_per_row": 1.0}
    assert d1["evidence"]["useful_cited"] == 1 and d1["evidence"]["link_recovered"] == 1
    by_platform = summary["arms"]["d1"]["by_platform"]
    assert by_platform["windows"]["balanced_accuracy"] == 0.5
    assert by_platform["k8s"]["balanced_accuracy"] == 0.0 and by_platform["k8s"]["expected_rows"] == 2
    assert summary["arms"]["d1"]["by_quadrant"]["windows-malicious"]["balanced_accuracy"] is None
    assert summary["arms"]["deterministic"]["metrics"]["balanced_accuracy"] == 1.0
    assert summary["arms"]["deterministic"]["metrics"]["tool_usage"]["probes_run"] == 0
    # The pre-existing fields keep their meaning: accuracy is over the rows present.
    assert summary["arms"]["d1"]["accuracy"] == 1 / 3 and summary["missing_rows"] == [("k-ben", "d1", 1)]


def test_summary_without_case_metadata_has_no_platform_breakdown(development):
    """Pilot freezes carry no platform; the summary must not invent an empty grouping."""
    freeze = pilot.make_freeze("dev", {"digest": "fake"}, {}, repeats=1)
    row, _ = pilot.evaluate_case(development[0], "deterministic")
    summary = pilot.summarise(freeze, [pilot.seal_row({**row, "repeat": 1, "freeze_sha256": freeze["freeze_sha256"]})])
    assert "by_platform" not in summary["arms"]["deterministic"]
    assert summary["arms"]["deterministic"]["metrics"]["expected_rows"] == 3
