"""Real-case evaluator: build, seal, freeze, run and summarise from native label refs.

Fixtures push generated telemetry through the ``canonical`` source path, the same
write-reload-resolve route a real export takes; no test here is a model score.
"""

import json
import re
import shutil

import pytest

from ath.agent.llm import ScriptedLLM
from ath.agent.operational import StableContextProfile
from ath.evaluation import auth_execution as pilot
from ath.evaluation import real_cases as real
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
    root = tmp_path_factory.mktemp("real")
    malicious, benign, _ = pilot.scenarios("dev")
    _write_source(malicious, root / "src-mal")
    _write_source(benign, root / "src-ben")
    routine = malicious.telemetry.processes
    notepad = routine[routine["device"] == "OFFICE-01"]["event_id"].iloc[0]
    target = malicious.telemetry.processes[malicious.telemetry.processes["process_name"] == "cmd.exe"]["device"].iloc[0]

    def case(key, source, decision, anchors, **extra):
        return {"key": key, "source": {"kind": "canonical", "path": source}, "expected_decision": decision,
                "provenance": "synthetic", "label_source": "generator (test fixture)",
                "anchor_refs": anchors, **extra}

    spec = {"spec_version": real.SPEC_VERSION, "name": "fixture", "cases": [
        case("mal-01", "src-mal", "malicious", [_ref(malicious.link.event_id)],
             useful_refs=[_ref(malicious.link.other_event_id)],
             link={"kind": "parent_child", "refs": [_ref(malicious.link.event_id), _ref(malicious.link.other_event_id)]}),
        case("ben-01", "src-ben", "benign", [_ref(benign.link.event_id)],
             useful_refs=[_ref(benign.link.other_event_id)]),
        case("routine-01", "src-mal", "benign", [_ref(notepad)]),
        case("unlabelled-01", "src-mal", "malicious", ["generated:no-such-event"]),
        case("sliced-01", "src-mal", "malicious", [_ref(malicious.link.event_id)], devices=["OFFICE-01"]),
        case("windowed-01", "src-mal", "malicious", [_ref(malicious.link.event_id)],
             window={"start": "2026-08-01T08:00:00Z", "end": "2026-08-01T09:00:00Z"}),
    ]}
    spec_path = root / "spec.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    bundle_dir = root / "bundle"
    bundle = real.build_bundle(spec_path, bundle_dir)
    return {"root": root, "spec": spec_path, "bundle_dir": bundle_dir, "bundle": bundle,
            "malicious": malicious, "benign": benign, "target": target}


def _entry(world, key):
    return next(e for e in world["bundle"]["cases"] if e["key"] == key)


def test_build_selects_the_anchor_incident_and_resolves_follow_up_evidence(world):
    mal = _entry(world, "mal-01")
    assert mal["status"] == real.INVESTIGABLE and "ATH-007" in mal["rule_ids"]
    assert world["malicious"].link.event_id in mal["case_ids"]
    assert mal["useful_ids"] == [world["malicious"].link.other_event_id]
    assert mal["useful_preflagged"] == []  # the follow-up is unflagged: a discovery case
    assert mal["link"] == world["malicious"].link.to_dict()
    assert all(r["status"] == "resolved" for r in mal["refs"].values())
    assert _entry(world, "ben-01")["status"] == real.INVESTIGABLE
    assert _entry(world, "windowed-01")["status"] == real.INVESTIGABLE


def test_uninvestigable_cases_are_classified_not_dropped(world):
    assert _entry(world, "routine-01")["status"] == real.UNDETECTED
    unlabelled = _entry(world, "unlabelled-01")
    assert unlabelled["status"] == real.UNRESOLVED_LABELS
    assert unlabelled["refs"]["generated:no-such-event"]["status"] == "unresolved"
    sliced = _entry(world, "sliced-01")
    assert sliced["status"] == real.UNRESOLVED_LABELS and sliced["events"] > 0
    freeze = real.make_freeze(world["bundle_dir"], {"digest": "fake"}, {}, 1)
    assert {i["key"]: i["status"] for i in freeze["not_investigable"]} == {
        "routine-01": real.UNDETECTED, "unlabelled-01": real.UNRESOLVED_LABELS,
        "sliced-01": real.UNRESOLVED_LABELS}
    assert [m["key"] for m in freeze["manifest"]] == ["mal-01", "ben-01", "windowed-01"]


def test_window_and_device_slicing(world):
    telemetry = world["malicious"].telemetry
    only_office = real.slice_telemetry(telemetry, devices=["OFFICE-01"])
    assert set(only_office.processes["device"]) == {"OFFICE-01"}
    empty = real.slice_telemetry(telemetry, {"start": "2030-01-01T00:00:00Z", "end": "2030-01-02T00:00:00Z"})
    assert empty.event_count == 0


def test_bundle_is_sealed_and_never_overwritten(world):
    bundle = real.read_bundle(world["bundle_dir"])
    assert bundle["bundle_sha256"] == world["bundle"]["bundle_sha256"]
    assert (world["bundle_dir"] / "SPEC.json").read_bytes() == world["spec"].read_bytes()
    with pytest.raises(FileExistsError):
        real.build_bundle(world["spec"], world["bundle_dir"])


def test_tampering_with_telemetry_bundle_or_spec_is_refused(world, tmp_path):
    copy = tmp_path / "bundle"
    shutil.copytree(world["bundle_dir"], copy)
    freeze = real.make_freeze(copy, {"digest": "fake"}, {}, 1)
    csv = copy / "cases" / "mal-01" / "process_events.csv"
    csv.write_text(csv.read_text(encoding="utf-8").replace("cmd.exe", "cmd2.exe"), encoding="utf-8")
    with pytest.raises(ValueError, match="telemetry differs"):
        real.real_cases(copy)
    shutil.rmtree(copy)
    shutil.copytree(world["bundle_dir"], copy)
    (copy / "SPEC.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="spec was altered"):
        real.read_bundle(copy)
    shutil.rmtree(copy)
    shutil.copytree(world["bundle_dir"], copy)
    data = json.loads((copy / "BUNDLE.json").read_text(encoding="utf-8"))
    data["cases"][0]["expected_decision"] = "benign"
    (copy / "BUNDLE.json").write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="altered"):
        real.validate_freeze(freeze, copy)


@pytest.mark.parametrize("mutate, message", [
    (lambda c: c.pop("label_source"), "label_source"),
    (lambda c: c.update(expected_decision="suspicious"), "expected_decision"),
    (lambda c: c.update(anchor_refs=[]), "anchor_refs"),
    (lambda c: c.update(window={"start": "2026-01-01T00:00:00", "end": "2026-01-02T00:00:00"}), "window"),
    (lambda c: c.update(link={"kind": "parent_child", "refs": ["a"]}), "link"),
    (lambda c: c.update(provenance="vibes"), "provenance"),
    (lambda c: c["source"].update(kind="splunk"), "source"),
])
def test_spec_validation_fails_loudly(tmp_path, mutate, message):
    case = {"key": "c1", "source": {"kind": "canonical", "path": "x"}, "expected_decision": "benign",
            "provenance": "real", "label_source": "me", "anchor_refs": ["a=b"]}
    mutate(case)
    path = tmp_path / "spec.json"
    path.write_text(json.dumps({"spec_version": real.SPEC_VERSION, "cases": [case]}), encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        real.load_spec(path)


def test_duplicate_case_keys_are_refused(tmp_path):
    case = {"key": "c1", "source": {"kind": "canonical", "path": "x"}, "expected_decision": "benign",
            "provenance": "real", "label_source": "me", "anchor_refs": ["a=b"]}
    path = tmp_path / "spec.json"
    path.write_text(json.dumps({"spec_version": real.SPEC_VERSION, "cases": [case, case]}), encoding="utf-8")
    with pytest.raises(ValueError, match="unique"):
        real.load_spec(path)


class ProcessTreeScript(ScriptedLLM):
    """Probe once, then cite the first catalogued relationship; never a live-model score."""

    def complete(self, system, prompt, max_tokens=1024, timeout_seconds=None):
        catalog = prompt.split("CHECKED OBSERVATIONS", 1)[1]
        links = re.findall(r"^(R\d+): Process event", catalog, re.M)
        probe = "P1" if not self.calls else "none"
        self.responses.append(json.dumps({
            "explanations": [{"label": "insufficient", "statement": "Scripted.", "evidence": links[:1]}],
            "evidence_gap": "intent", "next_probe": probe, "probe_reason": "Scripted.", "disposition": "abstain"}))
        return super().complete(system, prompt, max_tokens, timeout_seconds)


def test_real_cases_score_through_the_pilot_scorer(world):
    cases = {c.key: c for c in real.real_cases(world["bundle_dir"])}
    row, _ = real.evaluate_case(cases["mal-01"], "deterministic")
    assert row["scores"]["complete"] and row["scores"]["expected_decision"] == "malicious"
    row, report = real.evaluate_case(cases["mal-01"], "d1", ProcessTreeScript(), scripted=True,
                                     profile=StableContextProfile())
    assert row["scripted"] and row["scores"]["complete"]
    assert row["scores"]["useful_cited"] == 1 and row["scores"]["link_recovered"]


def test_cli_build_freeze_run_and_resume_without_model_calls(world, tmp_path, monkeypatch, capsys):
    class MetadataOnly:
        def describe(self):
            return {"digest": "fake", "daemon_version": "test"}

        def configuration(self):
            return {"model": "test"}

    monkeypatch.setattr(pilot, "_client", lambda model, profile=None: MetadataOnly())
    bundle = tmp_path / "bundle"
    assert real.main(["build", "--spec", str(world["spec"]), "--bundle", str(bundle)]) == 0
    out = tmp_path / "results"
    assert real.main(["freeze", "--bundle", str(bundle), "--out", str(out)]) == 0
    freeze = json.loads((out / "FREEZE.json").read_text(encoding="utf-8"))
    assert freeze["profile"]["version"] == "operational-v5"
    assert freeze["protocol"]["decision_rule_version"] == pilot.EVIDENCE_CEILING_RULE
    assert real.main(["run", "--bundle", str(bundle), "--out", str(out), "--arm", "deterministic"]) == 0
    saved = {p.name: p.read_bytes() for p in (out / "rows").glob("*.json")}
    assert len(saved) == 3
    assert real.main(["run", "--bundle", str(bundle), "--out", str(out), "--arm", "deterministic"]) == 0
    assert saved == {p.name: p.read_bytes() for p in (out / "rows").glob("*.json")}
    summary = json.loads((out / "SUMMARY.json").read_text(encoding="utf-8"))
    assert summary["investigable_cases"] == 3
    assert summary["not_investigable_counts"] == {real.UNDETECTED: 1, real.UNRESOLVED_LABELS: 2}
    assert not summary["complete_comparison"] and len(summary["missing_rows"]) == 3
    assert summary["arms"]["deterministic"]["complete"] == 3


def test_build_needs_a_spec_and_results_need_an_out(world, tmp_path):
    with pytest.raises(SystemExit):
        real.main(["build", "--bundle", str(tmp_path / "b")])
    with pytest.raises(SystemExit):
        real.main(["summarise", "--bundle", str(world["bundle_dir"])])


# -- analyst-seeded investigation (not end-to-end ATH) -----------------------------------


@pytest.fixture(scope="module")
def seeded(world):
    spec = json.loads(world["spec"].read_text(encoding="utf-8"))
    spec["seed_mode"] = real.ANALYST
    spec["cases"] = [c for c in spec["cases"] if c["key"] in ("mal-01", "ben-01", "routine-01", "unlabelled-01")]
    for case in spec["cases"]:
        case["note"] = "LABEL-NOTE-SENTINEL"
        case["label_source"] = "LABEL-SOURCE-SENTINEL"
    path = world["root"] / "seeded-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    bundle_dir = world["root"] / "seeded-bundle"
    return {"spec": path, "bundle_dir": bundle_dir, "bundle": real.build_bundle(path, bundle_dir)}


def _seeded(seeded, key):
    return next(e for e in seeded["bundle"]["cases"] if e["key"] == key)


def test_analyst_seed_makes_undetected_cases_investigable_and_keeps_detection_status(seeded):
    assert seeded["bundle"]["seed_mode"] == real.ANALYST
    routine = _seeded(seeded, "routine-01")
    assert routine["status"] == real.INVESTIGABLE and routine["detection_status"] == real.UNDETECTED
    assert routine["case_ids"] == routine["anchor_ids"] and routine["rule_ids"] == [real.SEED_RULE_ID]
    assert _seeded(seeded, "mal-01")["detection_status"] == real.INVESTIGABLE
    unlabelled = _seeded(seeded, "unlabelled-01")
    assert unlabelled["status"] == real.UNRESOLVED_LABELS  # nothing to seed from


def test_seed_wording_is_identical_and_carries_no_label(seeded):
    cases = {c.key: c for c in real.real_cases(seeded["bundle_dir"])}
    seeds = {key: real.prepare(case)[1].findings[0] for key, case in cases.items()}
    assert {(s.rule_id, s.title, s.reason, s.severity) for s in seeds.values()} == {
        (real.SEED_RULE_ID, real.SEED_TITLE, real.SEED_REASON, real.Severity.MEDIUM)}
    text = json.dumps([[s.title, s.reason, [e.summary for e in s.evidence], s.metadata] for s in seeds.values()])
    for leak in ("LABEL-NOTE-SENTINEL", "LABEL-SOURCE-SENTINEL", "malicious", "benign", "abstain"):
        assert leak not in text
    assert all(re.fullmatch(r"Analyst-selected \w+ event on \S+", e.summary)
               for s in seeds.values() for e in s.evidence)


class RecordPrompts(ScriptedLLM):
    def complete(self, system, prompt, max_tokens=1024, timeout_seconds=None):
        self.responses.append(json.dumps({
            "explanations": [{"label": "insufficient", "statement": "Scripted.", "evidence": []}],
            "evidence_gap": "intent", "next_probe": "none", "probe_reason": "Scripted.", "disposition": "abstain"}))
        return super().complete(system, prompt, max_tokens, timeout_seconds)


def test_seeded_cases_run_both_arms_without_label_text_in_prompts(seeded):
    for case in real.real_cases(seeded["bundle_dir"]):
        row, _ = real.evaluate_case(case, "deterministic", profile=StableContextProfile())
        assert row["scores"]["complete"]
        client = RecordPrompts([])
        row, _ = real.evaluate_case(case, "d1", client, scripted=True, profile=StableContextProfile())
        assert row["scores"]["complete"]
        prompts = " ".join(system + prompt for system, prompt, *_ in client.calls)
        assert "LABEL-NOTE-SENTINEL" not in prompts and "LABEL-SOURCE-SENTINEL" not in prompts
        assert real.SEED_TITLE in prompts


def test_seeded_freeze_and_summary_say_analyst_seeded_not_end_to_end(seeded, tmp_path, monkeypatch):
    class MetadataOnly:
        def describe(self):
            return {"digest": "fake", "daemon_version": "test"}

        def configuration(self):
            return {"model": "test"}

    monkeypatch.setattr(pilot, "_client", lambda model, profile=None: MetadataOnly())
    out = tmp_path / "results"
    bundle = str(seeded["bundle_dir"])
    assert real.main(["freeze", "--bundle", bundle, "--out", str(out)]) == 0
    freeze = json.loads((out / "FREEZE.json").read_text(encoding="utf-8"))
    assert freeze["seed_mode"] == real.ANALYST
    assert freeze["protocol"]["evaluation"] == "Analyst-seeded investigation, not end-to-end ATH."
    assert "seeded by an analyst" in freeze["protocol"]["question"]
    assert real.main(["run", "--bundle", bundle, "--out", str(out), "--arm", "deterministic"]) == 0
    summary = json.loads((out / "SUMMARY.json").read_text(encoding="utf-8"))
    assert summary["evaluation"] == "Analyst-seeded investigation, not end-to-end ATH."
    assert summary["seed_mode"] == real.ANALYST and summary["investigable_cases"] == 3
    assert summary["detected_by_ath"] == "2/4"
    assert "say nothing about whether ATH would have raised" in summary["limitations"]


def test_detection_bundles_are_labelled_end_to_end(world):
    freeze = real.make_freeze(world["bundle_dir"], {"digest": "fake"}, {}, 1)
    assert freeze["seed_mode"] == real.DETECTION
    assert freeze["protocol"]["evaluation"] == "End-to-end ATH: detection selects the case."


def test_a_seed_is_exactly_one_initial_record(world):
    malicious = world["malicious"]
    processes = malicious.telemetry.processes
    office = processes[processes["device"] == "OFFICE-01"]["event_id"].iloc[0]
    with pytest.raises(ValueError, match="exactly one initial record"):
        real.analyst_incident(malicious.telemetry, [malicious.link.event_id, office])
    seed = real.analyst_incident(malicious.telemetry, [malicious.link.event_id])
    assert len(seed.findings[0].evidence) == 1 and seed.findings[0].channels


def _analyst_spec(tmp_path, world, **case_changes):
    spec = json.loads(world["spec"].read_text(encoding="utf-8"))
    spec["seed_mode"] = real.ANALYST
    spec["cases"] = [dict(spec["cases"][0], **case_changes)]
    for case in spec["cases"]:
        case["source"] = {**case["source"], "path": str(world["root"] / case["source"]["path"])}
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path


def test_analyst_spec_refuses_several_anchors_or_seed_as_follow_up(world, tmp_path):
    malicious = world["malicious"]
    two = [_ref(malicious.link.event_id), _ref(malicious.link.other_event_id)]
    with pytest.raises(ValueError, match="exactly one initial record"):
        real.load_spec(_analyst_spec(tmp_path, world, anchor_refs=two))
    with pytest.raises(ValueError, match="cannot also be follow-up"):
        real.load_spec(_analyst_spec(tmp_path, world, useful_refs=[_ref(malicious.link.event_id)]))


def test_seeded_bundle_records_the_policy_and_scores_follow_up_discovery(seeded):
    assert seeded["bundle"]["seed_policy"] == real.SEED_POLICY
    mal = _seeded(seeded, "mal-01")
    assert len(mal["anchor_ids"]) == 1 and mal["useful_ids"] and not set(mal["useful_ids"]) & set(mal["anchor_ids"])
    freeze = real.make_freeze(seeded["bundle_dir"], {"digest": "fake"}, {}, 1)
    assert freeze["seed_policy"] == real.SEED_POLICY
    assert "exactly one initial suspicious record" in freeze["protocol"]["cases"]


def test_unknown_seed_mode_is_refused(world, tmp_path):
    spec = json.loads(world["spec"].read_text(encoding="utf-8"))
    spec["seed_mode"] = "oracle"
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    with pytest.raises(ValueError, match="seed_mode"):
        real.load_spec(path)


def test_row_writes_are_atomic_and_never_replace(tmp_path):
    target = tmp_path / "rows" / "case_d1_1.json"
    (tmp_path / "rows").mkdir()
    (tmp_path / "rows" / "case_d1_1.json.partial").write_text("{truncated", encoding="utf-8")
    pilot.write_new(target, {"x": 1})  # a leftover from a killed session is overwritten
    assert json.loads(target.read_text(encoding="utf-8")) == {"x": 1}
    assert not (tmp_path / "rows" / "case_d1_1.json.partial").exists()
    assert sorted(p.name for p in (tmp_path / "rows").glob("*.json")) == ["case_d1_1.json"]
    with pytest.raises(FileExistsError):
        pilot.write_new(target, {"x": 2})
    assert json.loads(target.read_text(encoding="utf-8")) == {"x": 1}


# -- holdout-v1 ------------------------------------------------------------------------------


def _verdict_rows(cases, decide):
    """One scored row per (case, arm); ``decide(case, arm)`` returns the decision."""
    rows = []
    for case in cases:
        for arm in ("deterministic", "d1"):
            decision, expected = decide(case, arm), case["expected_decision"]
            rows.append({"sample": case["key"], "arm": arm, "scores": {
                "correct": decision == expected,
                "false_benign": expected == "malicious" and decision == "benign",
                "false_malicious": expected == "benign" and decision == "malicious"}})
    return rows


def _holdout_cases(windows=(11, 1), k8s=(1, 11)):
    """24 cases whose label is correlated with platform: (malicious, benign) per platform."""
    cases = []
    for platform_name, (malicious, benign) in (("windows", windows), ("k8s", k8s)):
        for label, count in (("malicious", malicious), ("benign", benign)):
            cases += [{"key": f"{platform_name}-{label}-{i}", "platform": platform_name, "expected_decision": label}
                      for i in range(count)]
    return cases


def test_constant_answer_per_platform_fails_discrimination_despite_high_accuracy():
    """The reason holdout-v1 exists. When labels are correlated with platform (here 11 of
    12 Windows cases malicious, 11 of 12 Kubernetes cases benign), a predictor that never
    looks at the evidence -- "Windows means malicious, Kubernetes means benign" -- scores
    22/24 (92%), beats a baseline that abstains by 22, and makes only one unsafe clear and
    one false accusation. Criteria 1-3 all pass. It has discriminated nothing: on each
    platform it recalls one class fully and the other not at all, balanced accuracy 0.5.
    Criterion 4 is what refuses to call that investigative value."""
    cases = _holdout_cases()
    constant = _verdict_rows(cases, lambda c, arm: "abstain" if arm == "deterministic"
                             else "malicious" if c["platform"] == "windows" else "benign")
    verdict = real.holdout_verdict(real.HOLDOUT_RULES, cases, constant)
    assert verdict["tallies"]["d1"]["correct"] == 22 and verdict["result"] == "complete"
    passed = {c["criterion"]: c["passed"] for c in verdict["criteria"]}
    assert passed["1-correct-gain"] and passed["2-unsafe-clears"] and passed["3-false-accusations"]
    assert verdict["failing_criteria"] == ["4-discrimination:k8s", "4-discrimination:windows"]
    assert verdict["tallies"]["d1"]["by_platform"]["windows"]["balanced_accuracy"] == 0.5
    assert verdict["conclusion"] == "investigative value not demonstrated"

    # The same case set is passable: one correct minority case per platform flips it.
    minority = {"windows-benign-0", "k8s-malicious-0"}
    looking = _verdict_rows(cases, lambda c, arm: "abstain" if arm == "deterministic"
                            else c["expected_decision"] if c["key"] in minority
                            else "malicious" if c["platform"] == "windows" else "benign")
    verdict = real.holdout_verdict(real.HOLDOUT_RULES, cases, looking)
    assert verdict["failing_criteria"] == [] and verdict["conclusion"] == "investigative value demonstrated"
    assert verdict["notes"] == []


def test_holdout_names_every_failing_criterion_and_counts_absent_rows_as_incorrect():
    """A verdict that says only "not demonstrated" hides which safety bound broke. And a
    row that never ran must not shrink the denominator, or blocking the hard cases would
    raise the score."""
    cases = _holdout_cases(windows=(6, 6), k8s=(6, 6))
    rows = _verdict_rows(cases, lambda c, arm: c["expected_decision"] if arm == "d1" else "abstain")
    full = real.holdout_verdict(real.HOLDOUT_RULES, cases, rows)
    assert full["conclusion"] == "investigative value demonstrated"
    dropped = [r for r in rows if not (r["arm"] == "d1" and r["sample"] == "k8s-benign-0")]
    verdict = real.holdout_verdict(real.HOLDOUT_RULES, cases, dropped)
    assert verdict["result"] == "incomplete" and verdict["missing"] == [("k8s-benign-0", "d1")]
    assert verdict["failing_criteria"] == ["complete"]
    assert verdict["tallies"]["d1"]["by_platform"]["k8s"]["benign"] == {"cases": 6, "correct": 5, "recall": 5 / 6}
    unsafe = _verdict_rows(cases, lambda c, arm: "abstain" if arm == "deterministic"
                           else "benign" if c["key"] in ("windows-malicious-0", "windows-malicious-1")
                           else "malicious" if c["key"] in ("k8s-benign-0", "k8s-benign-1")
                           else c["expected_decision"])
    verdict = real.holdout_verdict(real.HOLDOUT_RULES, cases, unsafe, scripted=True)
    assert verdict["failing_criteria"] == ["live-model", "2-unsafe-clears", "3-false-accusations"]
    small = real.holdout_verdict(real.HOLDOUT_RULES, cases[:4], _verdict_rows(cases[:4], lambda c, a: "abstain"))
    assert "declared for 24 cases" in small["notes"][0]


def _holdout_spec(world, tmp_path, name="holdout-spec.json", **changes):
    spec = json.loads(world["spec"].read_text(encoding="utf-8"))
    spec["protocol"] = real.HOLDOUT
    spec["cases"] = [c for c in spec["cases"] if c["key"] in ("mal-01", "ben-01", "routine-01")]
    for case in spec["cases"]:
        case["source"] = {**case["source"], "path": str(world["root"] / case["source"]["path"])}
        case.update(platform="windows", provenance_class="injected",
                    quadrant=f"windows-{case['expected_decision']}")
        case.update(changes.get(case["key"], {}))
    path = tmp_path / name
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path


@pytest.mark.parametrize("changes, message", [
    ({"mal-01": {"quadrant": "windows-benign"}}, "must be 'windows-malicious'"),
    ({"ben-01": {"platform": None}}, "needs platform"),
    ({"ben-01": {"platform": "macos"}}, "platform must be one of"),
    ({"routine-01": {"provenance_class": "guessed"}}, "provenance_class must be one of"),
])
def test_holdout_spec_refuses_missing_or_inconsistent_case_metadata(world, tmp_path, changes, message):
    """The quadrant is the grouping the verdict balances over; one that disagrees with its
    own platform and label would put a case in the wrong cell without anyone noticing."""
    with pytest.raises(ValueError, match=message):
        real.load_spec(_holdout_spec(world, tmp_path, **changes))


def test_case_metadata_is_optional_and_unchecked_for_consistency_outside_holdout(world, tmp_path):
    spec = json.loads(_holdout_spec(world, tmp_path).read_text(encoding="utf-8"))
    del spec["protocol"]
    spec["cases"][0]["quadrant"] = "anything"
    del spec["cases"][1]["platform"]
    path = tmp_path / "plain.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    assert real.load_spec(path)["cases"][0]["quadrant"] == "anything"
    spec["protocol"] = "holdout-v0"
    path.write_text(json.dumps(spec), encoding="utf-8")
    with pytest.raises(ValueError, match="protocol must be one of"):
        real.load_spec(path)


def test_holdout_rules_are_sealed_in_the_freeze_and_applied_from_it(world, tmp_path, monkeypatch):
    """Rules written after the results are seen are not a holdout. The freeze carries the
    rules and the per-case platform before any row exists; rows carry the case metadata;
    the summary applies the sealed rules and says the run is incomplete while d1 rows are
    missing."""
    class MetadataOnly:
        def describe(self):
            return {"digest": "fake", "daemon_version": "test"}

        def configuration(self):
            return {"model": "test"}

    monkeypatch.setattr(pilot, "_client", lambda model, profile=None: MetadataOnly())
    bundle_dir = tmp_path / "bundle"
    bundle = real.build_bundle(_holdout_spec(world, tmp_path), bundle_dir)
    assert bundle["protocol"] == real.HOLDOUT
    assert {e["quadrant"] for e in bundle["cases"]} == {"windows-malicious", "windows-benign"}
    with pytest.raises(ValueError, match="exactly 1 repeat"):
        real.make_freeze(bundle_dir, {"digest": "fake"}, {}, repeats=2)
    out = tmp_path / "results"
    assert real.main(["freeze", "--bundle", str(bundle_dir), "--out", str(out)]) == 0
    freeze = json.loads((out / "FREEZE.json").read_text(encoding="utf-8"))
    assert freeze["protocol"]["holdout_rules"] == real.HOLDOUT_RULES
    assert freeze["protocol"]["decision_rule_version"] == real.HOLDOUT
    assert all(e["platform"] == "windows" for e in [*freeze["manifest"], *freeze["not_investigable"]])
    assert real.main(["run", "--bundle", str(bundle_dir), "--out", str(out), "--arm", "deterministic"]) == 0
    row = json.loads(next((out / "rows").glob("*.json")).read_text(encoding="utf-8"))
    assert row["case_metadata"]["platform"] == "windows" and row["case_metadata"]["provenance_class"] == "injected"
    summary = json.loads((out / "SUMMARY.json").read_text(encoding="utf-8"))
    assert summary["holdout"]["result"] == "incomplete" and "complete" in summary["holdout"]["failing_criteria"]
    assert summary["conclusion"] == "investigative value not demonstrated"
    assert "windows" in summary["arms"]["deterministic"]["by_platform"]
    # Loosening the rule afterwards is caught as tampering with the freeze.
    freeze["protocol"]["holdout_rules"]["min_correct_gain"] = 0
    with pytest.raises(ValueError, match="altered"):
        real.validate_freeze(freeze, bundle_dir)


def test_non_holdout_freeze_and_summary_keep_their_shape(world):
    """Existing v5/v6 real-case freezes must not change under this milestone: no holdout
    rules, no extra manifest keys when cases carry no metadata, and the pilot's rule still
    decides the conclusion."""
    freeze = real.make_freeze(world["bundle_dir"], {"digest": "fake"}, {}, 1)
    assert freeze["protocol"] == real.DETECTION_PROTOCOL and "protocol" not in world["bundle"]
    assert all(set(e) == {"key", "telemetry_sha256", "expected_decision", "useful_ids", "link", "case_ids",
                          "seed_mode"} for e in freeze["manifest"])
    summary = real.summarise(freeze, [])
    assert "holdout" not in summary and summary["conclusion"] == "investigative value not demonstrated"
    assert summary["blocked_rows"] == summary["errored_rows"] == []


# -- holdout-v1-windows ----------------------------------------------------------------------


def _windows_spec(world, tmp_path, name="windows-spec.json", **changes):
    """mal-01 and ben-01 are the primary Windows cases; routine-01 is the benign secondary
    check, labelled Kubernetes as the real secondary cases are."""
    spec = json.loads(_holdout_spec(world, tmp_path, name=name).read_text(encoding="utf-8"))
    spec["protocol"] = real.HOLDOUT_WINDOWS
    for case in spec["cases"]:
        if case["key"] == "routine-01":
            case.update(platform="k8s", quadrant="k8s-benign", holdout_role="secondary")
        else:
            case["holdout_role"] = "primary"
        if case["key"] == "mal-01":
            case["seed_type"] = "non-implant"
        case.update(changes.get(case["key"], {}))
    path = tmp_path / name
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path


def _roled(cases, role):
    return [{**c, "holdout_role": role} for c in cases]


def test_secondary_cases_never_move_the_windows_verdict():
    """The Kubernetes cases are benign only, so they can show false accusation but never
    discrimination. If they entered the verdict, a model that calls every Kubernetes event
    benign would buy correct answers -- and a Kubernetes discrimination claim -- for free.
    Here D1 is perfect on Windows and accuses every secondary case: the conclusion is
    unchanged, and the accusations are reported, not hidden."""
    primary = _holdout_cases(windows=(6, 6), k8s=(0, 0))
    secondary = [{"key": f"k8s-benign-{i}", "platform": "k8s", "expected_decision": "benign"} for i in range(6)]
    rows = _verdict_rows(primary, lambda c, arm: c["expected_decision"] if arm == "d1" else "abstain")
    rows += _verdict_rows(secondary, lambda c, arm: "malicious" if arm == "d1" else "abstain")
    for row in rows:
        row["scores"].update(complete=True, decision=(
            row["scores"]["correct"] and next(c for c in primary + secondary if c["key"] == row["sample"])["expected_decision"])
            or ("malicious" if row["arm"] == "d1" and row["sample"].startswith("k8s") else "abstain"))
    rules = real.HOLDOUT_WINDOWS_RULES
    verdict = real.holdout_verdict(rules, primary, rows)
    assert verdict["conclusion"] == "investigative value demonstrated" and verdict["notes"] == []
    assert set(verdict["tallies"]["d1"]["by_platform"]) == {"windows"}
    check = real.secondary_check(secondary, rows)
    assert check["counts_toward_conclusion"] is False
    assert check["d1"]["false_accusations"] == 6 and check["deterministic"]["abstained"] == 6


def test_windows_gain_threshold_is_three_of_twelve():
    """Re-declared for 12 cases before any result: a gain of 2 fails, 3 passes. The
    baseline is right on 5 cases here so that D1 can clear criterion 4 (balanced accuracy
    above 0.5 needs more than 6 of 12 correct) while the gain alone decides."""
    cases = _holdout_cases(windows=(6, 6), k8s=(0, 0))
    malicious, benign = [c["key"] for c in cases[:6]], [c["key"] for c in cases[6:]]
    baseline = set(malicious[:3] + benign[:2])

    def decide(d1_right):
        return lambda c, arm: c["expected_decision"] if c["key"] in (d1_right if arm == "d1" else baseline) else "abstain"

    verdict = real.holdout_verdict(real.HOLDOUT_WINDOWS_RULES, cases, _verdict_rows(cases, decide(set(malicious[:4] + benign[:4]))))
    assert verdict["failing_criteria"] == [] and verdict["tallies"]["d1"]["correct"] - verdict["tallies"]["deterministic"]["correct"] == 3
    verdict = real.holdout_verdict(real.HOLDOUT_WINDOWS_RULES, cases, _verdict_rows(cases, decide(set(malicious[:4] + benign[:3]))))
    assert verdict["failing_criteria"] == ["1-correct-gain"]


@pytest.mark.parametrize("changes, message", [
    ({"ben-01": {"holdout_role": None}}, "needs holdout_role"),
    ({"ben-01": {"holdout_role": "tertiary"}}, "holdout_role must be one of"),
    ({"ben-01": {"platform": "k8s", "quadrant": "k8s-benign"}}, "primary cases are Windows"),
    ({"routine-01": {"expected_decision": "malicious", "quadrant": "k8s-malicious"}}, "benign false-accusation check only"),
    ({"ben-01": {"holdout_role": "secondary", "platform": "k8s", "quadrant": "k8s-benign"}}, "both labels"),
])
def test_windows_spec_refuses_roles_that_would_widen_the_claim(world, tmp_path, changes, message):
    """Each refusal blocks a way to claim more than the design supports: an unroled case,
    a non-Windows primary, a malicious secondary (a Kubernetes discrimination claim by the
    back door), or a primary set that cannot discriminate at all."""
    with pytest.raises(ValueError, match=message):
        real.load_spec(_windows_spec(world, tmp_path, **changes))


def test_windows_rules_and_k8s_statement_are_sealed_before_any_row(world, tmp_path, monkeypatch):
    """The Windows-only rule, and the statement that Kubernetes malicious discrimination
    was not evaluated, are in the freeze before any row exists; the summary carries both,
    and applies the verdict to the primary cases only."""
    class MetadataOnly:
        def describe(self):
            return {"digest": "fake", "daemon_version": "test"}

        def configuration(self):
            return {"model": "test"}

    monkeypatch.setattr(pilot, "_client", lambda model, profile=None: MetadataOnly())
    bundle_dir = tmp_path / "bundle"
    bundle = real.build_bundle(_windows_spec(world, tmp_path), bundle_dir)
    assert bundle["protocol"] == real.HOLDOUT_WINDOWS
    out = tmp_path / "results"
    assert real.main(["freeze", "--bundle", str(bundle_dir), "--out", str(out)]) == 0
    freeze = json.loads((out / "FREEZE.json").read_text(encoding="utf-8"))
    assert freeze["protocol"]["holdout_rules"] == real.HOLDOUT_WINDOWS_RULES
    assert freeze["protocol"]["not_evaluated"] == real.K8S_NOT_EVALUATED
    # routine-01 is undetected in this detection-mode fixture: listed, role intact, still missing.
    roles = {e["key"]: e["holdout_role"] for e in [*freeze["manifest"], *freeze["not_investigable"]]}
    assert roles == {"mal-01": "primary", "ben-01": "primary", "routine-01": "secondary"}
    assert real.main(["run", "--bundle", str(bundle_dir), "--out", str(out), "--arm", "deterministic"]) == 0
    summary = json.loads((out / "SUMMARY.json").read_text(encoding="utf-8"))
    assert summary["not_evaluated"] == real.K8S_NOT_EVALUATED
    assert summary["secondary_check"]["cases"] == 1
    assert summary["secondary_check"]["deterministic"]["missing"] == ["routine-01"]
    assert {k for k, _ in summary["holdout"]["missing"]} == {"mal-01", "ben-01"}
    assert set(summary["holdout"]["tallies"]["d1"]["by_platform"]) == {"windows"}
    assert "primary" in summary["arms"]["deterministic"]["by_role"]
    # Seed type travels with the case so malicious recall can be split by it: a model that
    # only recognises the implant would show recall on "implant" seeds alone.
    assert "non-implant" in summary["arms"]["deterministic"]["by_seed_type"]
