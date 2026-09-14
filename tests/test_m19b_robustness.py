"""The M19b robustness harness: the freeze gate, the selection, the rule, and the refusal.

Why this file exists
---------------------
``scripts/m19b_robustness.py`` re-runs ten M19 cases and reports the spread beside M19's
single value. Four things must hold for that to mean anything, and each is tested here
because each has a silent failure mode:

*The freeze.* If the repeats run under a prompt, a budget, a model id or a scoring rule
that is not M19's, they are not repeats of M19 -- they are a second experiment reported
in M19's column. The assertion must **fail on a mutated hash** and **pass on the real
files**; a gate that only ever passes is a gate nobody has seen refuse.

*The selection.* The ten cases were fixed before any repeat ran. A selection recomputed
at score time from the results it is scoring is not a selection, it is a conclusion, so
the list is asserted against the literal ten and against the M19 manifest.

*The rule.* "The M19 decision rule" must mean, byte for byte, what it meant in
``GRADING.json``. The scorer is new code answering an old question, so it is run on
M19's own committed rows and required to reproduce the frozen answer -- and required to
be capable of a different answer, so the reproduction is not vacuous.

*The refusal.* ``reports/m19/`` is frozen. Every write this harness performs is checked
by path, and a real command is run under an audit of every file opened for writing.
"""

from __future__ import annotations

import builtins
import json
import pathlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import m19_ablation as m19  # noqa: E402
import m19b_robustness as m19b  # noqa: E402

M19_DIR = ROOT / "reports" / "m19" / "ablation"

EXPECTED_SELECTION = (
    ("synthetic:INC-004", "CASE-001", "B_unique"),
    ("flaws_cloud", "CASE-018", "B_unique"),
    ("flaws_cloud", "CASE-050", "B_unique"),
    ("flaws_cloud", "CASE-065", "B_unique"),
    ("comiset", "CASE-001", "B_degraded"),
    ("comiset", "CASE-002", "B_degraded"),
    ("synthetic:INC-001", "CASE-001", "C_planner_choice"),
    ("attack_data_aws", "CASE-002", "agreed_easy"),
    ("synthetic:INC-002", "CASE-001", "agreed_easy"),
    ("flaws_cloud", "CASE-005", "agreed_easy"),
)
"""The ten cases, written out a second time. Deliberately a duplicate: the point of the
test is that the list in the script is *this* list, and a test that imported the value
it is checking would pass whatever the script said."""


@pytest.fixture(scope="module")
def m19_environment() -> dict:
    return m19b.read_m19_environment()


@pytest.fixture(scope="module")
def live_environment(m19_environment) -> dict:
    return m19b.capture_environment(
        ROOT,
        manifest_hash=str(m19_environment["manifest_hash"]),
        manifest_head=str(m19_environment.get("manifest_head", "")),
    )


# --------------------------------------------------------------------------------------
# The freeze assertion
# --------------------------------------------------------------------------------------


def test_the_freeze_assertion_passes_on_the_real_files(
    m19_environment, live_environment
) -> None:
    assert m19b.environment_differences(m19_environment, live_environment) == []


def test_a_mutated_prompt_hash_fails_the_freeze_assertion(
    m19_environment, live_environment
) -> None:
    mutated = json.loads(json.dumps(m19_environment))
    mutated["prompts"]["planner_system"] = "0" * 64
    differences = m19b.environment_differences(mutated, live_environment)
    assert differences, "a changed planner prompt must refuse the freeze"
    assert any("prompts.planner_system" in d for d in differences), differences


@pytest.mark.parametrize(
    ("field_name", "mutate"),
    [
        ("prompts", lambda p: p["prompts"].__setitem__("synthesis_system", "0" * 64)),
        ("manifest_hash", lambda p: p.__setitem__("manifest_hash", "0" * 64)),
        ("arms", lambda p: p["arms"]["B_single_llm"].__setitem__("model", "other")),
        ("arms", lambda p: p["arms"]["C_crew_llm"].__setitem__("tool_call_cap", 999)),
        ("arms", lambda p: p["arms"]["B_single_llm"].__setitem__("max_steps", 3)),
        ("arms", lambda p: p["arms"]["B_single_llm"]["tool_surface"].pop()),
        ("shared_tool_surface", lambda p: p["shared_tool_surface"].pop()),
        ("request", lambda p: p["request"]["max_tokens"].__setitem__("planner", 1024)),
        ("request", lambda p: p["request"].__setitem__("thinking", {"type": "off"})),
        ("retry", lambda p: p["retry"].__setitem__("max_attempts", 9)),
        ("retry", lambda p: p["retry"]["retryable_statuses"].append(413)),
    ],
)
def test_every_asserted_field_refuses_when_it_moves(
    m19_environment, live_environment, field_name, mutate
) -> None:
    mutated = json.loads(json.dumps(m19_environment))
    mutate(mutated)
    differences = m19b.environment_differences(mutated, live_environment)
    assert differences, f"{field_name} moved and the assertion said nothing"
    assert any(d.startswith(field_name) for d in differences), differences


def test_the_scoring_hash_is_no_longer_gated_and_the_numbers_are(
    m19_environment, live_environment,
) -> None:
    """T6 added the necessity metrics, so the hash cannot match and does not gate.

    What gates instead is stronger and is asserted in the same freeze: the M19 metrics,
    recomputed by the new code over M19's committed rows, reproduce ``GRADING.json``.
    This test fails if ``scoring`` is quietly put back into the byte-equal set -- which
    would refuse every M19b run -- or if the reproduction stops being checked at all.
    """
    assert "scoring" not in m19b.ASSERTED_FIELDS
    mutated = json.loads(json.dumps(m19_environment))
    mutated["scoring"]["scoring.py"] = "0" * 64
    assert m19b.environment_differences(mutated, live_environment) == []

    reproduces, differences = m19b.reproduces_grading()
    assert differences == []
    assert reproduces


def test_the_freeze_refuses_a_scoring_change_that_moves_an_m19_number(
    monkeypatch,
) -> None:
    """The other half: the replacement gate must be capable of refusing."""
    monkeypatch.setattr(
        m19b, "reproduces_grading",
        lambda *args, **kwargs: (False, ["arms.A_deterministic: facts 335 -> 336"]),
    )
    payload, _entries, digest = m19._read_manifest(M19_DIR)
    with pytest.raises(SystemExit) as excinfo:
        m19b.build_m19b_environment(digest, str(payload.get("head", "")))
    assert "does not reproduce" in str(excinfo.value)
    assert "facts 335 -> 336" in str(excinfo.value)


def test_the_commit_is_recorded_but_not_gated(m19_environment, monkeypatch, tmp_path) -> None:
    """M19b is a later commit by construction; both commits are recorded instead."""
    assert "commit" not in m19b.ASSERTED_FIELDS
    payload, _entries, digest = m19._read_manifest(M19_DIR)
    environment = m19b.build_m19b_environment(digest, str(payload.get("head", "")))
    equality = environment["m19_equality"]
    assert equality["byte_equal"] is True
    assert equality["m19_commit"] == m19_environment["git"]["commit"]
    assert equality["m19b_commit"]
    assert list(equality["asserted_fields"]) == list(m19b.ASSERTED_FIELDS)
    assert equality["scoring"]["reproduces_grading"] is True
    assert set(equality["scoring"]["hashes"]) == {
        "scoring.py", "arms.py", "incidents.py"
    }


def test_the_freeze_refuses_when_m19s_environment_differs(monkeypatch) -> None:
    mutated = json.loads(json.dumps(m19b.read_m19_environment()))
    mutated["prompts"]["planner_user_template"] = "0" * 64
    monkeypatch.setattr(m19b, "read_m19_environment", lambda: mutated)
    payload, _entries, digest = m19._read_manifest(M19_DIR)
    with pytest.raises(SystemExit) as excinfo:
        m19b.build_m19b_environment(digest, str(payload.get("head", "")))
    assert "prompts.planner_user_template" in str(excinfo.value)


def test_a_model_arm_refuses_without_a_frozen_environment(tmp_path) -> None:
    with pytest.raises(SystemExit) as excinfo:
        m19b.guard_environment(tmp_path, "any-digest")
    assert "does not exist" in str(excinfo.value)


def test_a_freeze_that_drifted_from_m19_refuses_the_run(tmp_path) -> None:
    drifted = json.loads(json.dumps(m19b.read_m19_environment()))
    drifted["arms"]["B_single_llm"]["model"] = "some-other-model"
    (tmp_path / "ENVIRONMENT.json").write_text(json.dumps(drifted), encoding="utf-8")
    with pytest.raises(SystemExit) as excinfo:
        m19b.guard_environment(tmp_path, str(drifted["manifest_hash"]))
    assert "arm_models" in str(excinfo.value) or "arms.B_single_llm" in str(excinfo.value)


def test_the_credential_value_is_never_recorded(monkeypatch, tmp_path) -> None:
    secret = "sk-ant-this-value-must-not-appear-anywhere"
    monkeypatch.setenv(m19b.CREDENTIAL_VARIABLE, secret)
    assert m19b.cmd_freeze(SimpleNamespace(out_dir=tmp_path)) == 0
    for path in tmp_path.iterdir():
        assert secret not in path.read_text(encoding="utf-8"), path
    recorded = json.loads((tmp_path / "ENVIRONMENT.json").read_text(encoding="utf-8"))
    assert recorded["credential"]["present"] is True


# --------------------------------------------------------------------------------------
# The selection
# --------------------------------------------------------------------------------------


def test_the_selection_is_exactly_the_ten_pre_defined_cases() -> None:
    assert tuple(m19b.SELECTION) == EXPECTED_SELECTION
    assert len(m19b.SELECTION) == 10
    assert len(set(m19b.SELECTED_KEYS)) == 10


def test_the_strata_have_the_pre_defined_sizes() -> None:
    counts: dict[str, int] = {}
    for _corpus, _case, stratum in m19b.SELECTION:
        counts[stratum] = counts.get(stratum, 0) + 1
    assert counts == {
        "B_unique": 4, "B_degraded": 2, "C_planner_choice": 1, "agreed_easy": 3,
    }


def test_the_selected_entries_come_from_the_m19_manifest_in_order() -> None:
    _payload, entries, _digest = m19._read_manifest(M19_DIR)
    selected = m19b.select_entries(entries)
    assert [(e.corpus, e.case_id) for e in selected] == list(m19b.SELECTED_KEYS)


def test_a_missing_case_refuses_rather_than_running_a_subset() -> None:
    _payload, entries, _digest = m19._read_manifest(M19_DIR)
    thinned = [e for e in entries if (e.corpus, e.case_id) != m19b.SELECTED_KEYS[0]]
    with pytest.raises(SystemExit) as excinfo:
        m19b.select_entries(thinned)
    assert "not in the M19 manifest" in str(excinfo.value)


def test_the_b_unique_cases_are_the_lowest_ids_b_actually_won() -> None:
    """The stratum's definition, checked against GRADING.json rather than trusted."""
    grading = json.loads((M19_DIR / "GRADING.json").read_text(encoding="utf-8"))
    threshold = grading["vii_decision_rule"]["thresholds"]["A_mean_inferences_per_case"]
    won = [
        entry["case"]
        for entry in grading["vii_decision_rule"]["B"]["per_case"]
        if entry["unsupported"] <= threshold
        and entry["hyp_cites_evidence_A_claims_did_not"]
    ]
    assert len(won) == 13
    lowest_per_corpus: dict[str, list[str]] = {}
    for case in won:
        corpus, case_id = case.split("/", 1)
        lowest_per_corpus.setdefault(corpus, []).append(case_id)
    expected = set()
    for corpus, case_ids in lowest_per_corpus.items():
        for case_id in sorted(case_ids)[: 3 if corpus == "flaws_cloud" else 1]:
            expected.add((corpus, case_id))
    chosen = {
        (corpus, case_id)
        for corpus, case_id, stratum in m19b.SELECTION if stratum == "B_unique"
    }
    assert chosen == expected


def test_the_degraded_cases_are_the_two_m19_recorded() -> None:
    grading = json.loads((M19_DIR / "GRADING.json").read_text(encoding="utf-8"))
    degraded = {entry["case"] for entry in grading["degraded"]["B"]}
    chosen = {
        f"{corpus}/{case_id}"
        for corpus, case_id, stratum in m19b.SELECTION if stratum == "B_degraded"
    }
    assert chosen == degraded


def test_the_planner_choice_case_is_the_one_m19_found() -> None:
    grading = json.loads((M19_DIR / "GRADING.json").read_text(encoding="utf-8"))
    with_choice = {
        key for key, value in grading["planner"]["C"]["per_case"].items()
        if value["offered"]
    }
    chosen = {
        f"{corpus}/{case_id}"
        for corpus, case_id, stratum in m19b.SELECTION
        if stratum == "C_planner_choice"
    }
    assert chosen == with_choice


# --------------------------------------------------------------------------------------
# The decision rule
# --------------------------------------------------------------------------------------


def test_the_threshold_is_m19s_and_is_rederived_not_copied() -> None:
    grading = json.loads((M19_DIR / "GRADING.json").read_text(encoding="utf-8"))
    recorded = grading["vii_decision_rule"]["thresholds"]["A_mean_inferences_per_case"]
    assert round(m19b.m19_threshold(), 4) == recorded


@pytest.mark.parametrize("letter", ["B", "C"])
def test_the_scorer_reproduces_grading_json_on_m19s_own_rows(letter) -> None:
    """Feed the scorer ``arm_B.json`` / ``arm_C.json`` and require GRADING.json back."""
    grading = json.loads((M19_DIR / "GRADING.json").read_text(encoding="utf-8"))
    threshold = m19b.m19_threshold()
    arm_a = m19b.m19_rows("A")
    rows = m19b.m19_rows(letter)
    recorded = {
        entry["case"]: entry
        for entry in grading["vii_decision_rule"][letter]["per_case"]
    }
    for key in m19b.SELECTED_KEYS:
        computed = m19b.decision_rule(rows[key], arm_a[key], threshold)
        expected = recorded[f"{key[0]}/{key[1]}"]
        for field_name in (
            "hypotheses", "unsupported", "hyp_cites_evidence_A_claims_did_not",
            "hyp_cites_evidence_A_never_touched", "degraded",
        ):
            assert computed[field_name] == expected[field_name], (
                letter, key, field_name, computed, expected
            )
        assert computed["meets_rule"] == (
            expected["unsupported"] <= threshold
            and expected["hyp_cites_evidence_A_claims_did_not"]
        )


def test_the_reproduction_check_is_wired_into_scoring() -> None:
    verification = m19b.verify_against_grading(m19b.m19_threshold())
    assert verification["reproduced"] is True
    assert verification["rows_checked"] == 2 * len(m19b.SELECTED_KEYS)


def test_the_rule_is_capable_of_saying_no() -> None:
    """Otherwise the reproduction above proves only that both sides always say yes."""
    threshold = m19b.m19_threshold()
    arm_a = m19b.m19_rows("A")
    rows = m19b.m19_rows("B")
    key = ("flaws_cloud", "CASE-018")
    assert m19b.decision_rule(rows[key], arm_a[key], threshold)["meets_rule"] is True

    without_hypotheses = json.loads(json.dumps(rows[key]))
    without_hypotheses["state"]["claims"] = [
        c for c in without_hypotheses["state"]["claims"] if c["type"] != "HYPOTHESIS"
    ]
    assert m19b.decision_rule(
        without_hypotheses, arm_a[key], threshold
    )["meets_rule"] is False

    too_many_unsupported = json.loads(json.dumps(rows[key]))
    too_many_unsupported["scores"]["unsupported_claims"] = 99
    assert m19b.decision_rule(
        too_many_unsupported, arm_a[key], threshold
    )["meets_rule"] is False


def test_a_hypothesis_citing_only_what_A_cited_is_not_new_evidence() -> None:
    threshold = m19b.m19_threshold()
    arm_a = m19b.m19_rows("A")
    key = ("flaws_cloud", "CASE-018")
    recycled = json.loads(json.dumps(m19b.m19_rows("B")[key]))
    a_ids = sorted(m19b.claim_evidence_ids(arm_a[key]))
    for claim in recycled["state"]["claims"]:
        if claim["type"] == "HYPOTHESIS":
            claim["evidence_ids"] = a_ids[:1]
    computed = m19b.decision_rule(recycled, arm_a[key], threshold)
    assert computed["hyp_cites_evidence_A_claims_did_not"] is False
    assert computed["meets_rule"] is False


def test_the_threshold_refuses_a_rule_that_is_not_m19s(monkeypatch) -> None:
    monkeypatch.setattr(
        m19b, "m19_rows",
        lambda letter: {
            ("c", "1"): {"scores": {"completeness": {"inferences": 99}}},
        },
    )
    with pytest.raises(SystemExit) as excinfo:
        m19b.m19_threshold()
    assert "GRADING.json records" in str(excinfo.value)


# --------------------------------------------------------------------------------------
# reports/m19/ is never written
# --------------------------------------------------------------------------------------


def test_every_output_path_lives_outside_reports_m19() -> None:
    paths = [
        m19b.OUT_DIR / "ENVIRONMENT.json",
        m19b.OUT_DIR / "ENVIRONMENT.md",
        m19b.OUT_DIR / "SCORES.json",
        m19b.OUT_DIR / "REPORT.md",
        m19b.repeat_path(m19b.OUT_DIR, "A", 1),
        m19b.repeat_path(m19b.OUT_DIR, "B", 3),
        m19b.combined_path(m19b.OUT_DIR, "C"),
    ]
    frozen = M19_DIR.resolve()
    for path in paths:
        assert frozen not in path.resolve().parents, path
        assert "m19b" in str(path).replace("\\", "/")


@pytest.mark.parametrize(
    "path",
    [
        M19_DIR / "arm_B.json",
        M19_DIR / "GRADING.json",
        M19_DIR / "scripted" / "arm_B.json",
        Path(ROOT / "reports" / "m19" / "anything.txt"),
        Path(ROOT / "reports" / "m19b" / ".." / "m19" / "sneaky.json"),
    ],
)
def test_a_write_under_reports_m19_is_refused_by_path(path) -> None:
    with pytest.raises(SystemExit) as excinfo:
        m19b._refuse_m19_path(path)
    assert "reports/m19/" in str(excinfo.value)


def test_the_refusal_leaves_the_frozen_artifact_untouched() -> None:
    target = M19_DIR / "GRADING.json"
    before = target.read_bytes()
    with pytest.raises(SystemExit):
        m19b.write_artifact(target, {"clobbered": True})
    with pytest.raises(SystemExit):
        m19b.write_text(target, "clobbered")
    assert target.read_bytes() == before


def test_a_path_outside_reports_m19_is_allowed(tmp_path) -> None:
    m19b.write_artifact(tmp_path / "fine.json", {"ok": True})
    m19b.write_text(tmp_path / "fine.md", "ok")
    assert json.loads((tmp_path / "fine.json").read_text(encoding="utf-8")) == {"ok": True}


class _WriteAudit:
    """Every path this process opens for writing, while the audit is installed."""

    WRITE_MODES = set("wxa+")

    def __init__(self) -> None:
        self.paths: list[str] = []

    def install(self, monkeypatch) -> None:
        real_open = builtins.open
        real_write_text = pathlib.Path.write_text
        real_write_bytes = pathlib.Path.write_bytes
        real_path_open = pathlib.Path.open

        def record(path) -> None:
            self.paths.append(str(Path(path).resolve()))

        def open_(file, mode="r", *args, **kwargs):
            if self.WRITE_MODES & set(mode):
                record(file)
            return real_open(file, mode, *args, **kwargs)

        def path_open(self_path, mode="r", *args, **kwargs):
            if self.WRITE_MODES & set(mode):
                record(self_path)
            return real_path_open(self_path, mode, *args, **kwargs)

        def write_text(self_path, *args, **kwargs):
            record(self_path)
            return real_write_text(self_path, *args, **kwargs)

        def write_bytes(self_path, *args, **kwargs):
            record(self_path)
            return real_write_bytes(self_path, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", open_)
        monkeypatch.setattr(pathlib.Path, "open", path_open)
        monkeypatch.setattr(pathlib.Path, "write_text", write_text)
        monkeypatch.setattr(pathlib.Path, "write_bytes", write_bytes)

    def under_m19(self) -> list[str]:
        frozen = str(M19_DIR.resolve().parent)
        return [p for p in self.paths if p.startswith(frozen)]


def test_freeze_opens_nothing_under_reports_m19_for_writing(monkeypatch, tmp_path) -> None:
    audit = _WriteAudit()
    audit.install(monkeypatch)
    assert m19b.cmd_freeze(SimpleNamespace(out_dir=tmp_path)) == 0
    assert audit.under_m19() == []
    assert any(str(tmp_path) in p for p in audit.paths), audit.paths


@pytest.mark.skipif(
    not (m19b.OUT_DIR / "arm_C_rep3.json").exists(),
    reason="the arm runs have not been performed in this tree yet",
)
def test_score_opens_nothing_under_reports_m19_for_writing(monkeypatch, tmp_path) -> None:
    for name in ("arm_A_rep1.json", "arm_A_repeats.json"):
        (tmp_path / name).write_bytes((m19b.OUT_DIR / name).read_bytes())
    for letter in ("B", "C"):
        for index in (1, 2, 3):
            name = f"arm_{letter}_rep{index}.json"
            (tmp_path / name).write_bytes((m19b.OUT_DIR / name).read_bytes())
    audit = _WriteAudit()
    audit.install(monkeypatch)
    assert m19b.cmd_score(SimpleNamespace(out_dir=tmp_path, repeat=3)) == 0
    assert audit.under_m19() == []
    assert (tmp_path / "SCORES.json").exists()
    assert (tmp_path / "REPORT.md").exists()


# --------------------------------------------------------------------------------------
# The arm-A identity comparison
# --------------------------------------------------------------------------------------


def test_the_comparable_payload_drops_only_the_time_fields() -> None:
    row = m19b.m19_rows("A")[("attack_data_aws", "CASE-002")]
    payload = m19b.comparable_payload(row)
    assert "started_at" not in payload["state"]
    assert "wall_seconds" not in payload["scores"]["completeness"]
    for result in payload["state"]["results"]:
        for call in result.get("tool_calls", []):
            assert "called_at" not in call
    assert payload["scores"]["completeness"]["facts"] == \
        row["scores"]["completeness"]["facts"]
    assert payload["state"]["claims"] == row["state"]["claims"]


def test_the_comparable_payload_matches_the_live_case_result_view() -> None:
    """It is the dict twin of ``CaseResult.comparable``; the two must not drift."""
    row = m19b.m19_rows("A")[("attack_data_aws", "CASE-002")]
    assert set(m19b.comparable_payload(row)) == {
        "arm", "corpus", "case_id", "manifest_hash", "telemetry_hash", "configuration",
        "llm_degraded", "budgets", "scores", "state", "label_scores",
    }


def test_a_moved_claim_is_not_hidden_by_the_time_stripping() -> None:
    row = m19b.m19_rows("A")[("attack_data_aws", "CASE-002")]
    moved = json.loads(json.dumps(row))
    moved["state"]["claims"][0]["statement"] = "something else"
    assert m19b.comparable_payload(moved) != m19b.comparable_payload(row)


def test_a_different_wall_time_is_hidden_by_the_time_stripping() -> None:
    row = m19b.m19_rows("A")[("attack_data_aws", "CASE-002")]
    later = json.loads(json.dumps(row))
    later["state"]["started_at"] = "2099-01-01T00:00:00+00:00"
    later["scores"]["completeness"]["wall_seconds"] = 999.0
    assert m19b.comparable_payload(later) == m19b.comparable_payload(row)


# --------------------------------------------------------------------------------------
# The spread
# --------------------------------------------------------------------------------------


def test_a_metric_nobody_reported_is_not_reported_as_zero() -> None:
    assert m19b.spread([None, None, None])["n"] == 0
    assert m19b.spread([None, None, None])["median"] is None


def test_the_spread_is_min_median_max() -> None:
    entry = m19b.spread([3, 1, 2])
    assert (entry["min"], entry["median"], entry["max"]) == (1, 2, 3)
    assert entry["values"] == [3, 1, 2], "the raw repeats stay visible"


def test_the_two_degradation_kinds_are_told_apart() -> None:
    """A 413 is a property of the request; a 400 here was an exhausted credit balance.

    Folding them into one "degradation_frequency" would let an accounting failure read
    as an architectural one, which is precisely what question (b) is trying to measure.
    """
    assert m19b.degradation_kind(
        "DEGRADED -- model requested but 1 call(s) failed (HTTP 413); ran "
        "deterministically"
    ) == "http_413_request_too_large"
    assert m19b.degradation_kind(
        "DEGRADED -- model requested but 1 call(s) failed (HTTP 400 (the request was "
        "rejected as malformed)); ran deterministically"
    ) == "http_400_request_rejected"
    assert m19b.degradation_kind("model available and used for planning") == ""
    assert m19b.degradation_kind("DEGRADED -- something new") == "other"


@pytest.mark.skipif(
    not (m19b.OUT_DIR / "arm_C_rep3.json").exists(),
    reason="the arm runs have not been performed in this tree yet",
)
def test_the_undegraded_subset_never_hides_a_failure() -> None:
    """Both denominators are published: the full count, and the count with a model."""
    scores = json.loads(
        (m19b.OUT_DIR / "SCORES.json").read_text(encoding="utf-8")
    )
    for case in scores["per_case"]:
        for letter in ("B", "C"):
            arm = case["arms"][letter]
            degraded = arm["degradation_frequency"]
            live = arm["undegraded"]
            assert live["of"] == degraded["of"]
            assert live["repeats"] == degraded["of"] - degraded["degraded"]
            assert (
                live["decision_rule_passed"]
                <= arm["decision_rule_pass_frequency"]["passed"]
            ), "the undegraded subset cannot pass more often than the whole"
            assert (
                live["new_evidence_found"] <= arm["new_evidence_frequency"]["found"]
            )
            assert sum(degraded["by_kind"].values()) == degraded["degraded"]


def test_a_deterministic_arm_repeated_is_not_run(tmp_path) -> None:
    with pytest.raises(SystemExit) as excinfo:
        m19b.cmd_run(SimpleNamespace(
            arm="A", repeat=3, out_dir=tmp_path, check_planner=False,
        ))
    assert "deterministic" in str(excinfo.value)
