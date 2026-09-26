"""Checkpointed investigation workflow: sealed stages, honest resume, one model load per batch.

Fixtures push generated telemetry through the ``canonical`` source path, as
``test_real_cases`` does; no test here is a model score, and every model run is a
:class:`ScriptedLLM` labelled scripted.
"""

import json
import shutil
from types import SimpleNamespace

import pytest

from ath import cli
from ath import workflow as wf
from ath.agent.llm import ScriptedLLM
from ath.evaluation import auth_execution as pilot
from ath.evaluation import real_cases as real
from ath.evaluation.ablation.local import GIB, check_ram
from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS
from ath.telemetry.source import SourceLoadResult, write_normalized_telemetry


def _write_source(scenario, directory):
    t = scenario.telemetry
    write_normalized_telemetry(SourceLoadResult(tables={
        EVENT_PROCESS: t.processes, EVENT_NETWORK: t.network,
        EVENT_LOGON: t.logons, EVENT_CONTROL: t.controls}), directory)


def _ref(event_id):
    return f"generated:{event_id}"


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    root = tmp_path_factory.mktemp("workflow")
    malicious, benign, _ = pilot.scenarios("dev")
    _write_source(malicious, root / "src-mal")
    _write_source(benign, root / "src-ben")
    routine = malicious.telemetry.processes
    notepad = routine[routine["device"] == "OFFICE-01"]["event_id"].iloc[0]
    return {"root": root, "malicious": malicious, "benign": benign, "notepad": notepad,
            "mal_src": str(root / "src-mal"), "ben_src": str(root / "src-ben")}


def _detect(world, key="case", **extra):
    return wf.CaseInputs(key, world["mal_src"], "canonical", real.DETECTION, **extra)


def _seeded(world, key="case", source="mal_src", event_id=None):
    event_id = event_id or world["malicious"].link.event_id
    return wf.CaseInputs(key, world[source], "canonical", real.ANALYST, (_ref(event_id),))


def _snapshot(run_dir, stages=wf.STAGES):
    """Bytes and mtimes of every file in ``stages``: what "not recomputed" means on disk."""
    return {p.relative_to(run_dir).as_posix(): (p.read_bytes(), p.stat().st_mtime_ns)
            for name in stages for p in sorted((run_dir / name).rglob("*")) if p.is_file()}


class Abstains(ScriptedLLM):
    """Always concludes at once with an abstention; never a live-model score."""

    def complete(self, system, prompt, max_tokens=1024, timeout_seconds=None):
        self.responses.append(json.dumps({
            "explanations": [{"label": "insufficient", "statement": "Scripted.", "evidence": []}],
            "evidence_gap": "intent", "next_probe": "none", "probe_reason": "Scripted.", "disposition": "abstain"}))
        return super().complete(system, prompt, max_tokens, timeout_seconds)


# -- one case -------------------------------------------------------------------------


def test_deterministic_run_seals_every_stage_and_reports_the_verdict(world, tmp_path):
    """The end-to-end claim: from a canonical export to md/html/json reports whose verdict
    is the evaluator's decision, with run.json naming the exact stage seals it came from."""
    run_dir = tmp_path / "run"
    outcome = wf.Workflow("deterministic").run_case(run_dir, _detect(world))
    assert outcome["status"] == wf.COMPLETE and outcome["stages_run"] == list(wf.STAGES)
    assert outcome["verdict"]["disposition"] == "Malicious" and outcome["verdict"]["complete"]

    state = json.loads((run_dir / wf.STAGE_INVESTIGATION / "state.json").read_text(encoding="utf-8"))
    assert state["verdict_inputs"]["decision"] == state["verdict_inputs"]["triage_disposition"] == "malicious"
    assert state["operational"]["engine"] == "deterministic" and state["state"]["investigation"]["operational"]
    report = json.loads((run_dir / wf.STAGE_REPORT / "report.json").read_text(encoding="utf-8"))
    assert report["verdict"]["disposition"] == "Malicious"
    assert "Malicious" in (run_dir / wf.STAGE_REPORT / "report.md").read_text(encoding="utf-8")
    assert "Malicious" in (run_dir / wf.STAGE_REPORT / "report.html").read_text(encoding="utf-8")

    record = json.loads((run_dir / wf.RUN).read_text(encoding="utf-8"))
    assert record["stages"] == {name: wf.read_stage(run_dir, name)["stage_sha256"] for name in wf.STAGES}
    assert record["profile"]["version"] == "operational-v5" and record["model"] is None
    assert record["load_seconds"] is None  # nothing was loaded, and it says so rather than 0
    telemetry = json.loads((run_dir / wf.STAGE_TELEMETRY / "telemetry.json").read_text(encoding="utf-8"))
    assert telemetry["events"] > 0 and telemetry["telemetry_sha256"]
    assert not list(run_dir.glob("*.partial"))


def test_analyst_seed_is_one_neutral_record_and_detection_status_is_kept(world, tmp_path):
    """The analyst path reuses the evaluator's seed invariant: one record, the neutral
    seed wording, and ATH's own detection status recorded beside it."""
    run_dir = tmp_path / "run"
    outcome = wf.Workflow("deterministic").run_case(run_dir, _seeded(world))
    assert outcome["status"] == wf.COMPLETE
    seed = json.loads((run_dir / wf.STAGE_SEED / "seed.json").read_text(encoding="utf-8"))
    assert seed["seed_policy"] == real.SEED_POLICY and seed["case_ids"] == seed["anchor_ids"]
    assert [f["rule_id"] for f in seed["seed_findings"]] == [real.SEED_RULE_ID]
    assert seed["seed_findings"][0]["title"] == real.SEED_TITLE
    assert seed["detection_status"] == real.INVESTIGABLE
    with pytest.raises(ValueError, match="exactly one initial record"):
        wf.CaseInputs("x", world["mal_src"], "canonical", real.ANALYST, ("a", "b"))


def test_detection_without_one_incident_is_recorded_not_investigated(world, tmp_path):
    """A slice with no incident ends at the seed stage with that status on record; there
    is no investigation or report to mistake for a benign verdict."""
    run_dir = tmp_path / "run"
    outcome = wf.Workflow("deterministic").run_case(run_dir, _detect(world, devices=("OFFICE-01",)))
    assert outcome["status"] == real.UNDETECTED and outcome["verdict"] is None
    assert not (run_dir / wf.STAGE_INVESTIGATION).exists() and not (run_dir / wf.STAGE_REPORT).exists()
    record = json.loads((run_dir / wf.RUN).read_text(encoding="utf-8"))
    assert record["status"] == real.UNDETECTED and set(record["stages"]) == {wf.STAGE_TELEMETRY, wf.STAGE_SEED}


# -- resume ---------------------------------------------------------------------------


def test_rerun_reuses_every_sealed_stage_without_touching_it(world, tmp_path):
    """Resume is validation, not recomputation: nothing is rewritten, byte or mtime."""
    run_dir = tmp_path / "run"
    flow = wf.Workflow("deterministic")
    flow.run_case(run_dir, _detect(world))
    before = _snapshot(run_dir, (*wf.STAGES,)) | {wf.RUN: ((run_dir / wf.RUN).read_bytes(), 0)}
    outcome = wf.Workflow("deterministic").run_case(run_dir, _detect(world))
    assert outcome["stages_run"] == [] and outcome["status"] == wf.COMPLETE
    assert _snapshot(run_dir, (*wf.STAGES,)) | {wf.RUN: ((run_dir / wf.RUN).read_bytes(), 0)} == before


def test_missing_report_stage_alone_is_rebuilt_from_a_reproducing_rerun(world, tmp_path, monkeypatch):
    """A crash between sealing 03 and 04 leaves 03 and no run.json. Only 04 is built: the
    source is not reloaded, stages 01-03 keep their bytes and mtimes, and 04's seal says
    it came from a deterministic re-run that reproduced the sealed state."""
    run_dir = tmp_path / "run"
    wf.Workflow("deterministic").run_case(run_dir, _detect(world))
    shutil.rmtree(run_dir / wf.STAGE_REPORT)
    (run_dir / wf.RUN).unlink()
    kept = _snapshot(run_dir, wf.STAGES[:3])
    loads = []
    original = real.load_source
    monkeypatch.setattr(real, "load_source", lambda *a, **k: loads.append(a) or original(*a, **k))

    outcome = wf.Workflow("deterministic").run_case(run_dir, _detect(world))
    assert outcome["stages_run"] == [wf.STAGE_REPORT] and loads == []
    assert _snapshot(run_dir, wf.STAGES[:3]) == kept
    rebuilt = wf.read_stage(run_dir, wf.STAGE_REPORT)["summary"]["rebuilt_from_rerun"]
    assert rebuilt and "run_id" in rebuilt["state_matched_except"]
    record = json.loads((run_dir / wf.RUN).read_text(encoding="utf-8"))
    assert record["stages"][wf.STAGE_REPORT] == wf.read_stage(run_dir, wf.STAGE_REPORT)["stage_sha256"]


def test_rebuild_is_refused_when_the_rerun_does_not_reproduce_the_sealed_state(world, tmp_path, monkeypatch):
    """A report is only rebuilt for the investigation that was sealed; if the re-run
    differs in anything but run id, timestamps and elapsed time, 04 is refused."""
    run_dir = tmp_path / "run"
    wf.Workflow("deterministic").run_case(run_dir, _detect(world))
    shutil.rmtree(run_dir / wf.STAGE_REPORT)
    (run_dir / wf.RUN).unlink()
    original = pilot.evaluate_case

    def drifted(*args, **kwargs):
        row, report = original(*args, **kwargs)
        row["state"]["plan_log"].append("a code change altered the investigation")
        return row, report
    monkeypatch.setattr(pilot, "evaluate_case", drifted)
    with pytest.raises(wf.WorkflowRefused, match="no longer reproduces"):
        wf.Workflow("deterministic").run_case(run_dir, _detect(world))
    assert not (run_dir / wf.STAGE_REPORT).exists()


def test_d1_report_is_never_rebuilt_from_a_fresh_model_run(world, tmp_path):
    """A model investigation cannot be replayed; a new one would be a different
    investigation, so a d1 case missing only its report is refused."""
    run_dir = tmp_path / "run"
    flow = wf.Workflow("d1", session=wf.ScriptedSession(Abstains()))
    assert flow.run_case(run_dir, _seeded(world))["status"] == wf.COMPLETE
    shutil.rmtree(run_dir / wf.STAGE_REPORT)
    (run_dir / wf.RUN).unlink()
    with pytest.raises(wf.WorkflowRefused, match="cannot be replayed"):
        wf.Workflow("d1", session=wf.ScriptedSession(Abstains())).run_case(run_dir, _seeded(world))


def test_a_completed_run_missing_a_stage_is_refused(world, tmp_path):
    """run.json names the stages it was built from; deleting one of a completed run is an
    alteration, not a crash, and is never partly rebuilt."""
    run_dir = tmp_path / "run"
    wf.Workflow("deterministic").run_case(run_dir, _detect(world))
    shutil.rmtree(run_dir / wf.STAGE_REPORT)
    with pytest.raises(wf.WorkflowRefused, match="completed run"):
        wf.Workflow("deterministic").run_case(run_dir, _detect(world))


@pytest.mark.parametrize("target, edit", [
    (f"{wf.STAGE_TELEMETRY}/slice/process_events.csv", lambda t: t.replace("cmd.exe", "cmd2.exe")),
    (f"{wf.STAGE_SEED}/seed.json", lambda t: t.replace('"investigable"', '"undetected"', 1)),
    (f"{wf.STAGE_INVESTIGATION}/state.json", lambda t: t.replace('"malicious"', '"benign"')),
    (f"{wf.STAGE_REPORT}/report.md", lambda t: t + "\nedited\n"),
    (f"{wf.STAGE_SEED}/{wf.SEAL}", lambda t: t.replace('"sealed_at": "', '"sealed_at": "1', 1)),
])
def test_a_tampered_stage_is_refused_and_left_as_found(world, tmp_path, target, edit):
    """An altered artifact or seal is refused, never trusted and never recomputed over:
    the edited file is still on disk afterwards, exactly as the editor left it."""
    run_dir = tmp_path / "run"
    wf.Workflow("deterministic").run_case(run_dir, _detect(world))
    path = run_dir / target
    path.write_text(edit(path.read_text(encoding="utf-8")), encoding="utf-8")
    tampered = path.read_bytes()
    with pytest.raises(wf.WorkflowRefused, match="altered|differ"):
        wf.Workflow("deterministic").run_case(run_dir, _detect(world))
    assert path.read_bytes() == tampered


@pytest.mark.parametrize("change, stage", [
    (lambda w: (wf.Workflow("deterministic", "operational-v6"), _detect(w)), wf.STAGE_INVESTIGATION),
    (lambda w: (wf.Workflow("deterministic"), _detect(w, window={
        "start": "2026-08-01T08:00:00Z", "end": "2026-08-01T09:00:00Z"})), wf.STAGE_TELEMETRY),
])
def test_changed_inputs_are_refused_not_silently_recomputed(world, tmp_path, change, stage):
    """Pointing a sealed run directory at different inputs names the first stage whose
    inputs differ and changes nothing; the user must choose a new run directory."""
    run_dir = tmp_path / "run"
    wf.Workflow("deterministic").run_case(run_dir, _detect(world))
    before = _snapshot(run_dir)
    flow, inputs = change(world)
    with pytest.raises(wf.WorkflowRefused, match=f"{stage}: .*different inputs"):
        flow.run_case(run_dir, inputs)
    assert _snapshot(run_dir) == before


def test_a_killed_partial_stage_is_discarded_not_trusted(world, tmp_path):
    """A stage directory exists only once sealed; a ``.partial`` leftover from a killed
    run is rebuilt from scratch rather than read."""
    run_dir = tmp_path / "run"
    (run_dir / f"{wf.STAGE_TELEMETRY}.partial" / "slice").mkdir(parents=True)
    (run_dir / f"{wf.STAGE_TELEMETRY}.partial" / "slice" / "process_events.csv").write_text("junk")
    assert wf.Workflow("deterministic").run_case(run_dir, _detect(world))["status"] == wf.COMPLETE
    assert not list(run_dir.glob("*.partial"))


# -- batch and model sessions ---------------------------------------------------------


def _spec(world, tmp_path, seed_mode=real.ANALYST):
    malicious, benign = world["malicious"], world["benign"]

    def case(key, source, decision, anchor):
        return {"key": key, "source": {"kind": "canonical", "path": source}, "expected_decision": decision,
                "provenance": "synthetic", "label_source": "generator (test fixture)",
                "anchor_refs": [_ref(anchor)]}
    spec = {"spec_version": real.SPEC_VERSION, "name": "workflow-fixture", "seed_mode": seed_mode, "cases": [
        case("mal-01", world["mal_src"], "malicious", malicious.link.event_id),
        case("ben-01", world["ben_src"], "benign", benign.link.event_id),
        case("routine-01", world["mal_src"], "benign", world["notepad"]),
    ]}
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path


def test_d1_batch_warms_up_once_and_uses_one_client_for_every_case(world, tmp_path, monkeypatch):
    """One model load per batch: the first investigation triggers the single warm-up and
    every case is investigated by the very same client object, labelled scripted."""
    seen = []
    original = pilot.evaluate_case

    def recording(case, arm, client=None, **kwargs):
        seen.append(client)
        return original(case, arm, client, **kwargs)
    monkeypatch.setattr(pilot, "evaluate_case", recording)
    client = Abstains()
    session = wf.ScriptedSession(client)
    index = wf.Workflow("d1", session=session).run_batch(_spec(world, tmp_path), tmp_path / "out")

    assert index["counts"] == {wf.COMPLETE: 3}
    assert session.loads == 1 and index["model_loads_this_invocation"] == 1
    assert len(seen) == 3 and all(c is client for c in seen)
    assert len(client.calls) >= 3  # the one client answered every case
    assert index["scripted"] is True
    for key in ("mal-01", "ben-01", "routine-01"):
        record = json.loads((tmp_path / "out" / "cases" / key / wf.RUN).read_text(encoding="utf-8"))
        assert record["scripted"] is True and record["model"]["provider"] == "scripted"
        assert record["load_seconds"] == 0.0 and record["scoring"]["scoring_only"] is True


def test_batch_labels_never_reach_the_investigation(world, tmp_path):
    """The workflow reads a spec's labels (the reason it may import the label module),
    but only for scoring after the fact: no label text appears in any model prompt or in
    any stage the investigation reads."""
    spec_path = _spec(world, tmp_path)
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    for case in spec["cases"]:
        case["note"], case["label_source"] = "LABEL-NOTE-SENTINEL", "LABEL-SOURCE-SENTINEL"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    client = Abstains()
    wf.Workflow("d1", session=wf.ScriptedSession(client)).run_batch(spec_path, tmp_path / "out")
    prompts = " ".join(system + prompt for system, prompt, *_ in client.calls)
    assert real.SEED_TITLE in prompts
    for key in ("mal-01", "ben-01", "routine-01"):
        stages = _snapshot(tmp_path / "out" / "cases" / key, wf.STAGES[:3])
        text = prompts + "".join(data.decode("utf-8", "replace") for data, _ in stages.values())
        assert "LABEL-NOTE-SENTINEL" not in text and "LABEL-SOURCE-SENTINEL" not in text


def test_batch_records_a_blocked_case_and_completes_it_on_resume(world, tmp_path):
    """A RAM-guard block is on record -- INDEX.json, index.html and an attempt file with the
    guard's figures -- never a silently missing case; a later run completes it, reuses
    the others untouched, and the attempt stays on disk."""
    spec, out = _spec(world, tmp_path), tmp_path / "out"
    verdicts = iter([check_ram(8 * GIB, 16 * GIB).to_dict(), check_ram(8 * GIB, 1 * GIB).to_dict(),
                     check_ram(8 * GIB, 16 * GIB).to_dict()])
    session = wf.ScriptedSession(Abstains(), guard=lambda: next(verdicts))
    index = wf.Workflow("d1", session=session).run_batch(spec, out)

    assert index["counts"] == {wf.COMPLETE: 2, wf.BLOCKED: 1}
    blocked = next(c for c in index["cases"] if c["status"] == wf.BLOCKED)
    assert blocked["key"] == "ben-01" and blocked["attempt"]["ram_guard"]["ok"] is False
    attempt = out / "cases" / "ben-01" / blocked["attempt"]["path"]
    assert json.loads(attempt.read_text(encoding="utf-8"))["reason"] == "RAM guard"
    assert not (out / "cases" / "ben-01" / wf.STAGE_INVESTIGATION).exists()
    on_disk = json.loads((out / wf.INDEX).read_text(encoding="utf-8"))
    assert on_disk["counts"] == index["counts"]
    assert "Blocked" in (out / "index.html").read_text(encoding="utf-8")
    assert session.loads == 1

    done = _snapshot(out / "cases" / "mal-01")
    resumed = wf.Workflow("d1", session=wf.ScriptedSession(Abstains())).run_batch(spec, out)
    assert resumed["counts"] == {wf.COMPLETE: 3}
    stages_run = {c["key"]: c["stages_run"] for c in resumed["cases"]}
    assert stages_run == {"mal-01": [], "ben-01": [wf.STAGE_INVESTIGATION, wf.STAGE_REPORT], "routine-01": []}
    assert _snapshot(out / "cases" / "mal-01") == done and attempt.exists()


def test_deterministic_batch_indexes_expected_labels_for_scoring_only(world, tmp_path):
    """The index shows expected labels beside verdicts, for scoring; run.json says what
    the workflow does not score, so it is not mistaken for the evaluator."""
    out = tmp_path / "out"
    index = wf.Workflow("deterministic").run_batch(_spec(world, tmp_path, real.DETECTION), out)
    statuses = {c["key"]: c["status"] for c in index["cases"]}
    assert statuses == {"mal-01": wf.COMPLETE, "ben-01": wf.COMPLETE, "routine-01": real.UNDETECTED}
    page = (out / "index.html").read_text(encoding="utf-8")
    assert "Expected (scoring only)" in page and "cases/mal-01/04-report/report.html" in page
    record = json.loads((out / "cases" / "mal-01" / wf.RUN).read_text(encoding="utf-8"))
    assert "not scored" in record["limits"] and record["inputs"]["labels"]["expected_decision"] == "malicious"


class FakeOllama:
    """Just the surface OllamaSession touches; no daemon."""

    model, num_ctx, base_url = "qwen3.5:9b", 10240, "http://127.0.0.1:11434"

    def __init__(self, resident=True):
        self.resident = resident

    def describe(self):
        return {"provider": "ollama", "model": self.model, "digest": "d", "daemon_version": "v",
                "parameter_size": "9.7B"}

    def configuration(self):
        return {"model": self.model}

    def residency(self):
        return {"size": 6 * GIB, "size_vram": 0} if self.resident else {"size": None, "size_vram": None}

    def resident_bytes(self):
        return self.residency()["size"] or 0


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, *args):
        return json.dumps(self.body).encode()


def test_ollama_warm_up_is_one_empty_prompt_with_keep_alive_forever():
    """The load step matches the notebook's: one /api/generate call with no prompt and
    keep_alive -1, residency checked once, and load_seconds recorded; loading again is a
    no-op, so N cases cost one load."""
    requests = []

    def opener(request, timeout):
        requests.append((request.full_url, json.loads(request.data)))
        return FakeResponse({"done": True})
    session = wf.OllamaSession("qwen3.5:9b", None, client=FakeOllama(), opener=opener)
    first = session.ensure_loaded()
    assert session.ensure_loaded() is first and session.loads == 1 and len(requests) == 1
    url, body = requests[0]
    assert url.endswith("/api/generate") and body["keep_alive"] == -1
    assert "prompt" not in body and "messages" not in body
    assert first["task_prompt_sent"] is False and first["load_seconds"] >= 0
    assert first["residency"]["size"] == 6 * GIB
    assert session.guard()["resident_bytes"] == 6 * GIB  # the guard credits the loaded weights


def test_ollama_session_refuses_a_model_that_is_not_resident_after_warm_up():
    """A warm-up that did not leave the model loaded is an error, not a slow first case."""
    session = wf.OllamaSession("qwen3.5:9b", None, client=FakeOllama(resident=False),
                               opener=lambda request, timeout: FakeResponse({"done": True}))
    with pytest.raises(wf.ModelNotResident):
        session.ensure_loaded()


def test_a_live_session_blocks_when_the_guard_cannot_decide_but_a_scripted_one_does_not():
    """Same rule as the evaluator's run_rows for a live model (undecidable blocks); a
    scripted client loads no weights, so only an explicit failing guard blocks it."""
    live = wf.OllamaSession("m", None, client=FakeOllama())
    assert live.blocks({"ok": None}) and live.blocks({"ok": False}) and not live.blocks({"ok": True})
    scripted = wf.ScriptedSession(Abstains())
    assert not scripted.blocks(scripted.guard()) and scripted.blocks({"ok": False})
    with pytest.raises(TypeError):
        wf.ScriptedSession(object())


# -- CLI ------------------------------------------------------------------------------


def _cli(argv):
    args = cli.build_parser().parse_args(argv)
    return args.func(args, SimpleNamespace())


def test_cli_workflow_run_single_case_resume_and_exit_codes(world, tmp_path, capsys):
    """One command runs a case; the same command resumes it; a case with nothing to
    investigate exits 4, never 0; malformed seed choices are refused."""
    out = tmp_path / "run"
    argv = ["workflow", "run", "--telemetry", world["mal_src"], "--kind", "canonical", "--detect",
            "--out", str(out)]
    assert _cli(argv) == 0
    assert (out / wf.STAGE_REPORT / "report.html").exists()
    before = _snapshot(out)
    assert _cli(argv) == 0
    assert _snapshot(out) == before
    assert _cli(["workflow", "run", "--telemetry", world["mal_src"], "--kind", "canonical", "--detect",
                 "--device", "OFFICE-01", "--out", str(tmp_path / "none")]) == 4
    assert _cli(["workflow", "run", "--telemetry", world["mal_src"], "--kind", "canonical", "--detect",
                 "--seed-ref", "generated:x", "--out", str(tmp_path / "x")]) == 2
    assert _cli(["workflow", "run", "--telemetry", world["mal_src"], "--kind", "canonical",
                 "--out", str(tmp_path / "x")]) == 2
    assert _cli(["workflow", "run", "--telemetry", world["mal_src"], "--kind", "canonical", "--detect",
                 "--profile", "operational-v6", "--out", str(out)]) == 2  # sealed for v5: refused
    assert "Refused" in capsys.readouterr().out


def test_cli_workflow_batch_writes_the_index(world, tmp_path):
    """--batch takes its cases from the spec alone; mixing in single-case options is a
    caller error, not a silently ignored flag."""
    out = tmp_path / "batch"
    assert _cli(["workflow", "run", "--batch", str(_spec(world, tmp_path)), "--out", str(out)]) == 0
    index = json.loads((out / wf.INDEX).read_text(encoding="utf-8"))
    assert index["counts"] == {wf.COMPLETE: 3} and (out / "index.html").exists()
    assert _cli(["workflow", "run", "--batch", str(_spec(world, tmp_path)), "--detect", "--out", str(out)]) == 2
