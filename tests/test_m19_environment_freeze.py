"""The frozen environment, and the two gates that make it worth freezing.

Why this file exists
---------------------
An ablation's claim is that two arms differed in one thing. The prompts, the model id,
the request parameters, the tool surface, the budgets, the scoring code and the library
versions are all outside the rows and all of them can move between the day arm B runs
and the day arm C does. ``freeze`` records them; these tests are about the part that
matters afterwards -- that a run under different ones is *refused* rather than reported.

How each fails
---------------
*Round trip.* The record must survive JSON and still render. Fails if a value that
cannot be serialised creeps in, which would make the freeze unwritable at the moment it
is needed.

*The gates.* A changed prompt hash, a changed scoring hash, a changed commit with code
in the diff, a changed model id, or an uncommitted edit outside ``reports/`` must each
produce a refusal naming what moved. Each fails if that check is dropped -- and a gate
nobody tested is a gate that records an intention.

*The carve-out.* Committing the freeze moves HEAD, so a commit difference whose diff
touches only ``reports/`` must be accepted. Fails if the gate is so strict that the
frozen file can never be committed, which in practice means it is never used.

*The credential.* The key's value must appear in no artifact. Fails if presence
recording ever becomes value recording -- truncated, hashed or otherwise.

*The planner detector.* ``--check-planner`` must fail a model-arm row that had a real
choice and made none of it, and must not fail a row that had no choice to make. This is
the detector for the whole N1 failure: an arm whose planner answers were all discarded
ran deterministically under a model arm's label.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from ath.evaluation.ablation import arm_b, arm_c
from ath.evaluation.ablation import environment as env

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from m19_ablation import guard_environment, planner_report  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def frozen() -> dict:
    return env.capture_environment(
        ROOT, manifest_hash="manifest-hash", manifest_head="abc1234",
    )


def _live(frozen: dict, **overrides) -> dict:
    live = {
        "commit": frozen["git"]["commit"],
        "dirty_paths": [],
        "changed_since_frozen": [],
        "prompts": dict(frozen["prompts"]),
        "scoring": dict(frozen["scoring"]),
        "manifest_hash": frozen["manifest_hash"],
        "arm_models": {
            name: arm["model"] for name, arm in frozen["arms"].items()
        },
    }
    live.update(overrides)
    return live


# --------------------------------------------------------------------------------------
# The record
# --------------------------------------------------------------------------------------


def test_the_environment_round_trips_through_json(frozen) -> None:
    restored = json.loads(json.dumps(frozen))
    assert restored == frozen
    assert env.render_markdown(restored).startswith("# M19 Phase 1")


def test_the_record_carries_what_the_run_depends_on(frozen) -> None:
    assert frozen["arms"]["B_single_llm"]["model"] == "claude-opus-5"
    assert frozen["arms"]["C_crew_llm"]["model"] == "claude-opus-5"
    assert frozen["arms"]["A_deterministic"]["model"] is None
    assert frozen["request"]["thinking"] == {"type": "adaptive"}
    assert frozen["request"]["max_tokens"] == {"planner": 8192, "synthesis": 8192}
    assert "temperature" in frozen["request"]["sampling_parameters"]
    assert frozen["request"]["body_fields"] == [
        "model", "max_tokens", "system", "messages", "thinking"
    ]
    assert frozen["retry"]["timeout_seconds_per_attempt"] == 60
    assert frozen["retry"]["max_attempts"] == 3
    assert set(frozen["prompts"]) == {
        "planner_system", "synthesis_system",
        "planner_user_template", "synthesis_user_template",
    }
    assert set(frozen["scoring"]) == {"scoring.py", "arms.py", "incidents.py"}
    assert frozen["runtime"]["packages"]["pandas"] != "absent"
    assert frozen["manifest_hash"] == "manifest-hash"


def test_the_model_arms_share_one_tool_surface(frozen) -> None:
    assert (
        frozen["arms"]["B_single_llm"]["tool_surface"]
        == frozen["arms"]["C_crew_llm"]["tool_surface"]
        == frozen["shared_tool_surface"]
    )
    assert any("lookup_technique" in tool for tool in frozen["shared_tool_surface"])
    assert not any("calls_by" in tool for tool in frozen["shared_tool_surface"]), (
        "calls_by is bookkeeping, not a tool: it serves no evidence"
    )


def test_a_divergent_tool_surface_refuses_the_freeze(monkeypatch) -> None:
    """The one sentence the experiment rests on is not written down unverified."""
    surfaces = iter([["get_case(...)"], ["get_case(...)", "extra(...)"]])

    def _alternating() -> list:
        return list(next(surfaces))

    monkeypatch.setattr(env, "tool_surface", _alternating)
    with pytest.raises(ValueError, match="do not share a tool surface"):
        env.capture_environment(
            ROOT, manifest_hash="x", arm_configs=[arm_b(), arm_c()],
        )


# --------------------------------------------------------------------------------------
# The gate
# --------------------------------------------------------------------------------------


def test_an_unchanged_environment_has_no_differences(frozen) -> None:
    assert env.check_environment(frozen, _live(frozen)) == []


def test_a_changed_prompt_refuses(frozen) -> None:
    live = _live(frozen)
    live["prompts"]["planner_system"] = "0" * 64
    differences = env.check_environment(frozen, live)
    assert differences and "prompts.planner_system" in differences[0]


def test_a_changed_scoring_hash_refuses(frozen) -> None:
    live = _live(frozen)
    live["scoring"]["scoring.py"] = "0" * 64
    differences = env.check_environment(frozen, live)
    assert differences and "scoring.scoring.py" in differences[0]


def test_a_changed_manifest_refuses(frozen) -> None:
    differences = env.check_environment(frozen, _live(frozen, manifest_hash="other"))
    assert differences and "manifest_hash" in differences[0]


def test_a_changed_model_id_refuses(frozen) -> None:
    live = _live(frozen)
    live["arm_models"]["B_single_llm"] = "claude-sonnet-5"
    differences = env.check_environment(frozen, live)
    assert differences and "arm_models.B_single_llm" in differences[0]


def test_a_commit_that_changed_code_refuses(frozen) -> None:
    live = _live(
        frozen, commit="f" * 40,
        changed_since_frozen=["src/ath/agent/orchestrator.py", "reports/m19/x.json"],
    )
    differences = env.check_environment(frozen, live)
    assert differences
    assert "src/ath/agent/orchestrator.py" in differences[0]


def test_a_commit_that_only_committed_the_results_is_allowed(frozen) -> None:
    """Committing the freeze moves HEAD; that must not lock the experiment out."""
    live = _live(
        frozen, commit="f" * 40,
        changed_since_frozen=[
            "reports/m19/ablation/ENVIRONMENT.json",
            "reports/m19/ablation/ENVIRONMENT.md",
        ],
    )
    assert env.check_environment(frozen, live) == []


def test_a_commit_whose_diff_git_cannot_read_refuses(frozen) -> None:
    live = _live(frozen, commit="f" * 40, changed_since_frozen=None)
    differences = env.check_environment(frozen, live)
    assert differences and "could not say what changed" in differences[0]


def test_an_uncommitted_code_change_refuses(frozen) -> None:
    live = _live(frozen, dirty_paths=["src/ath/agent/llm.py"])
    differences = env.check_environment(frozen, live)
    assert differences and "uncommitted" in differences[0]


def test_uncommitted_results_and_raw_data_do_not_refuse(frozen) -> None:
    live = _live(
        frozen, dirty_paths=["reports/m19/ablation/arm_A.json", "data/raw/x.csv"],
    )
    assert env.check_environment(frozen, live) == []


def test_a_model_arm_refuses_to_run_without_a_frozen_environment(tmp_path) -> None:
    with pytest.raises(SystemExit, match="does not exist"):
        guard_environment(tmp_path, "manifest-hash")


def test_a_model_arm_refuses_to_run_against_a_stale_freeze(
    tmp_path, frozen, monkeypatch
) -> None:
    stale = json.loads(json.dumps(frozen))
    stale["prompts"]["synthesis_system"] = "0" * 64
    (tmp_path / env.ENVIRONMENT_JSON).write_text(
        json.dumps(stale), encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="synthesis_system"):
        guard_environment(tmp_path, frozen["manifest_hash"])


# --------------------------------------------------------------------------------------
# The credential
# --------------------------------------------------------------------------------------


FAKE_KEY = "sk-ant-fake-key-for-the-freeze-test-do-not-use"


def test_the_key_value_appears_in_no_artifact(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv(env.CREDENTIAL_VARIABLE, FAKE_KEY)
    payload = env.capture_environment(
        ROOT, manifest_hash="x", credential_present=bool(FAKE_KEY),
    )
    (tmp_path / env.ENVIRONMENT_JSON).write_text(
        json.dumps(payload, indent=2), encoding="utf-8",
    )
    (tmp_path / env.ENVIRONMENT_MD).write_text(
        env.render_markdown(payload), encoding="utf-8",
    )

    assert payload["credential"] == {
        "variable": "ATH_LLM_API_KEY",
        "present": True,
        "note": "presence only; the value is never recorded anywhere",
    }
    searched = 0
    for directory in (tmp_path, ROOT / "reports" / "m19"):
        for path in directory.rglob("*"):
            if not path.is_file():
                continue
            searched += 1
            text = path.read_text(encoding="utf-8", errors="ignore")
            assert FAKE_KEY not in text, f"the key value reached {path}"
            assert "sk-ant-fake" not in text, f"a truncated key reached {path}"
    assert searched >= 2, "the grep is vacuous if it read nothing"


# --------------------------------------------------------------------------------------
# The N1 detector
# --------------------------------------------------------------------------------------


def _row(multi: int, chosen: int, *, degraded: bool = False, unparseable: int = 0):
    return SimpleNamespace(
        corpus="synthetic:INC-001", case_id="CASE-001", llm_degraded=degraded,
        state={
            "llm": {
                "unparseable_responses": unparseable,
                "planner": {
                    "multi_candidate_steps": multi,
                    "chosen_by_model": chosen,
                    "fallbacks": {"model-unparseable": unparseable} if unparseable else {},
                },
            }
        },
    )


def test_the_detector_fails_a_model_arm_row_that_chose_nothing() -> None:
    lines, failures = planner_report([_row(3, 0, unparseable=3)], requires_model=True)
    assert len(lines) == 1
    assert failures and "chose none of them" in failures[0]


def test_the_detector_passes_a_row_the_model_actually_steered() -> None:
    _lines, failures = planner_report([_row(3, 2)], requires_model=True)
    assert failures == []


def test_a_case_with_no_choice_to_make_is_not_a_failure() -> None:
    """No multi-candidate step means the planner was never asked. Not evidence."""
    _lines, failures = planner_report([_row(0, 0)], requires_model=True)
    assert failures == []


def test_the_detector_says_nothing_about_the_deterministic_arm() -> None:
    _lines, failures = planner_report([_row(5, 0)], requires_model=False)
    assert failures == []


def test_the_report_line_carries_the_numbers_a_reader_needs() -> None:
    lines, _failures = planner_report(
        [_row(4, 1, degraded=True, unparseable=2)], requires_model=True,
    )
    assert "planner chose 1 of 4" in lines[0]
    assert "unparseable 2" in lines[0]
    assert "degraded True" in lines[0]
