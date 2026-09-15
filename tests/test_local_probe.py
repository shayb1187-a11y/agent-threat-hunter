"""The local probe: it times the arm's prompts, not a toy, and writes where it may.

Why these tests exist
----------------------
Every V1 compute budget is a multiple of the probe's numbers. Three things would make
those numbers wrong without anyone noticing:

*A drifted prompt.* If the probe's shapes stop being built from the orchestrator's own
strings, it times something the arm never sends. Fails if the system strings are not the
frozen ones, or if the synthesis shape stops carrying the M19b bound (no elision marker).

*A misplaced report.* Fails if a probe can be written under a frozen experiment.

*A wrong aggregate.* Fails if the cold call is averaged into the warm ones, if a prose
reply counts as parsed, or if a median is invented from nothing. Driven with a scripted
client, so it runs without a daemon.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import local_probe as probe  # noqa: E402

from ath.agent.llm import ScriptedLLM  # noqa: E402
from ath.agent.orchestrator import (  # noqa: E402
    ELISION,
    PLANNER_SYSTEM,
    SYNTHESIS_SYSTEM,
)
from ath.evaluation.ablation.environment import prompt_hashes, sha256_text  # noqa: E402
from ath.evaluation.ablation.local import FrozenPathRefused  # noqa: E402


# --------------------------------------------------------------------------------------
# Prompt linkage
# --------------------------------------------------------------------------------------


def test_the_planner_shape_is_the_frozen_planner_prompt_with_a_seven_facet_menu() -> None:
    system, user = probe.planner_prompt()
    assert system is PLANNER_SYSTEM
    assert sha256_text(system) == prompt_hashes()["planner_system"]
    assert user.startswith("Case: PROBE-001-0")
    assert "Candidates:" in user
    assert user.count("generalist:") >= 7


def test_the_synthesis_shape_is_the_frozen_synthesis_prompt_at_the_m19b_bound() -> None:
    system, user = probe.synthesis_prompt()
    assert system is SYNTHESIS_SYSTEM
    assert sha256_text(system) == prompt_hashes()["synthesis_system"]
    assert user.startswith("Case PROBE-001-0. Verified claims:")
    marker = ELISION.split("{")[0]
    assert marker in user, "the bound must bite, or the probe times an unbounded prompt"
    assert user.count("- [") == probe.SYNTHESIS_CLAIMS


def test_template_linkage_reports_identity_with_the_freeze() -> None:
    linkage = probe.template_linkage()
    assert linkage["identical"] is True
    assert linkage["used"] == linkage["frozen"] == prompt_hashes()


def test_synthesis_claims_are_deterministic() -> None:
    a, b = probe.synthesis_claims(12), probe.synthesis_claims(12)
    assert [c.to_dict() for c in a] == [c.to_dict() for c in b]


# --------------------------------------------------------------------------------------
# Aggregation, with a scripted client
# --------------------------------------------------------------------------------------


def _scripted(planner: list[str], synthesis: list[str]) -> ScriptedLLM:
    # The probe runs the planner shape first, then synthesis; responses are consumed in order.
    return ScriptedLLM(responses=planner + synthesis, name="scripted-probe")


def test_the_cold_call_is_reported_apart_and_prose_does_not_count_as_parsed() -> None:
    planner = ['{"next_agent": "generalist:auth"}'] * 3 + ["prose, not JSON"] + ['{"next_agent": "none"}']
    synthesis = ['{"claims": []}'] * 5
    readings = iter([8_000_000_000 + i * 1000 for i in range(40)])
    payload = probe.run_probe(_scripted(planner, synthesis), calls=5, ram_reader=lambda: next(readings))

    planner_shape = payload["shapes"]["planner"]
    agg = planner_shape["aggregate"]
    assert agg["calls"] == 5 and agg["warm_calls"] == 4
    assert agg["parse_rate"] == 0.8
    assert agg["ok_rate"] == 1.0, "prose is ok-but-unparseable, as the pre-registration fixed"
    assert planner_shape["cold_call"] is planner_shape["calls"][0]
    assert payload["shapes"]["synthesis"]["aggregate"]["parse_rate"] == 1.0

    call = planner_shape["calls"][0]
    for key in ("wall_seconds", "load_seconds", "prompt_eval_seconds", "eval_seconds",
                "prompt_tokens_per_second", "eval_tokens_per_second", "prompt_eval_count",
                "estimated_prompt_tokens", "parsed", "ram_before_bytes", "ram_after_bytes"):
        assert key in call, key
    assert call["prompt_eval_count"] == 100, "the scripted client's fake usage reaches the row"
    assert call["ram_before_bytes"] == 8_000_000_000
    assert call["ram_after_bytes"] == 8_000_001_000
    assert agg["min_ram_bytes"] == 8_000_000_000
    # Durations a client cannot report stay None and produce no median.
    assert call["load_seconds"] is None
    assert agg["median_eval_tokens_per_second_warm"] is None
    assert agg["median_wall_seconds_warm"] is not None


def test_medians_are_never_invented() -> None:
    assert probe._median([]) is None
    assert probe._median([None, None]) is None
    assert probe._median([None, 3.0, 1.0]) == 2.0


def test_a_single_call_shape_has_no_warm_median() -> None:
    payload = probe.run_probe(
        _scripted(['{"next_agent": "none"}'], ['{"claims": []}']), calls=1, ram_reader=lambda: None,
    )
    agg = payload["shapes"]["planner"]["aggregate"]
    assert agg["warm_calls"] == 0
    assert agg["median_wall_seconds_warm"] is None
    assert agg["min_ram_bytes"] is None


def test_zero_calls_is_refused() -> None:
    with pytest.raises(ValueError):
        probe.probe_shape(_scripted([], []), "planner", probe.planner_prompt, 10, 0)


def test_every_call_of_a_shape_is_a_different_prompt_of_the_same_size() -> None:
    """A repeated prompt is served from the daemon's KV cache: prefill in 0.3 s at
    15,000 tok/s on the first run of this probe, against 168 s cold. The arm never repeats
    a prompt, so a probe that did would report a speed the arm cannot have."""
    users = [probe.synthesis_prompt(v)[1] for v in range(5)]
    assert len(set(users)) == 5
    assert len({len(u) for u in users}) == 1, "same size, different content"
    planners = [probe.planner_prompt(v)[1] for v in range(5)]
    assert len(set(planners)) == 5


def test_a_builder_that_repeats_a_prompt_is_refused() -> None:
    with pytest.raises(ValueError, match="repeated a prompt"):
        probe.probe_shape(_scripted(["{}"] * 3, []), "planner", lambda _v: ("s", "same"), 10, 3)


# --------------------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------------------


def _payload() -> dict:
    payload = probe.run_probe(
        _scripted(['{"next_agent": "none"}'] * 2, ['{"claims": []}'] * 2), calls=2,
        ram_reader=lambda: 7 * probe.GIB,
    )
    payload.update({
        "generated_at": "2026-09-15T00:00:00+00:00", "head": "abc1234",
        "slug": probe.slug("qwen3.5:4b", False),
        "model": {"provider": "ollama", "model": "qwen3.5:4b", "quantization": "Q4_K_M",
                  "parameter_size": "4.7B", "digest": "d" * 64},
        "daemon_version": "0.33.3",
        "configuration": {"sampling": {"temperature": 0.0, "seed": 0}, "think": False,
                          "format": "json", "num_ctx": 10240, "num_predict_cap": 2048},
        "ram_preflight": {"ok": True, "available_bytes": 7 * probe.GIB,
                          "floor_bytes": 4 * probe.GIB, "message": "fine", "overridden": False},
    })
    return payload


@pytest.mark.parametrize("relative", ["reports/m19/ablation", "reports/m19b/probe", "reports/m19b"])
def test_a_probe_report_is_refused_under_a_frozen_experiment(tmp_path, relative) -> None:
    with pytest.raises(FrozenPathRefused):
        probe.write_reports(tmp_path / relative, _payload(), root=tmp_path)
    assert not (tmp_path / relative).exists()


def test_a_probe_report_is_written_as_json_and_markdown_beside_the_frozen_ones(tmp_path) -> None:
    json_path, md_path = probe.write_reports(tmp_path / "reports" / "local" / "probe", _payload(), root=tmp_path)
    assert json_path.name == "PROBE_qwen3.5-4b.json" and md_path.name == "PROBE_qwen3.5-4b.md"
    written = json.loads(json_path.read_text(encoding="utf-8"))
    assert written["shapes"]["planner"]["aggregate"]["parse_rate"] == 1.0
    text = md_path.read_text(encoding="utf-8")
    assert "## Shape: planner" in text and "## Shape: synthesis" in text
    assert "| cold |" in text and "| warm 1 |" in text
    assert "## Prompt linkage" in text
    assert "d" * 12 in text


def test_the_think_flag_changes_the_report_name_so_the_two_never_overwrite() -> None:
    assert probe.slug("qwen3.5:4b", True) == "qwen3.5-4b_think"
    assert probe.slug("qwen3.5:4b", False) == "qwen3.5-4b"
