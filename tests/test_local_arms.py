"""Arm D1: arm B's architecture on a local model, and nothing else about it changed.

Why these tests exist
----------------------
The whole V1 comparison rests on D1 differing from the hosted arm B in the model and in
the model alone. If D1 quietly picked up a different step budget, tool cap, planner
setting or synthesis bound, a gap between the two would be a gap between two
experiments. These tests pin the differences to exactly three fields.

How each fails
---------------
*Equality.* Fails if ``arm_d1`` stops being built from ``arm_b`` or adds a fourth
difference.

*The bound.* Fails if the local tier's synthesis budget drifts from the M19b constant --
two copies of one pre-registered number that no longer agree.

*Labelling.* Fails if a scripted D1 row can be aggregated into the real arm, or if the
factory stops receiving the arm's pinned tag (in which case the header would name a model
the client never ran).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from ath.agent.llm import NullLLM, ScriptedLLM
from ath.agent.ollama_llm import D1_SAMPLING, OllamaLLM, Sampling
from ath.evaluation.ablation import ARM_B, ArmUnavailable, arm_b, build_client
from ath.evaluation.ablation.local import (
    ARM_D1,
    LOCAL_ARM_BUILDERS,
    LOCAL_TOOL_OUTPUT_BUDGET,
    ModelSpec,
    arm_d1,
    ollama_factory,
    run_local_arm,
)

# The harness fixtures the existing arm tests use, imported rather than copied.
from test_ablation_harness import corpus, manifest, pipeline  # noqa: F401


def test_d1_keeps_arm_bs_budgets_and_is_its_own_architecture() -> None:
    """D1 v2 is the bounded investigator, not the facet generalist. What it must share
    with arm B is the budgets -- the same step budget and tool cap -- so a cost or
    coverage difference is a difference in what investigates, not in what it was
    allowed to spend. Fails if a budget drifts, if D1 is quietly rebuilt on the
    generalist, or if the arm stops requiring a model."""
    b, d1 = arm_b(), arm_d1("qwen3.5:4b")
    assert d1.name == ARM_D1 and b.name == ARM_B
    assert d1.model == "qwen3.5:4b"
    assert d1.requires_model is True and d1.implemented is True
    assert d1.tool_call_cap == b.tool_call_cap == 40
    assert d1.config.max_steps == b.config.max_steps == 8
    assert d1.generalist is False, "D1 v2 is the investigator loop, not the facet walk"
    assert "investigator" in d1.design_note
    assert d1.config.tool_output_budget == LOCAL_TOOL_OUTPUT_BUDGET
    assert b.config.tool_output_budget is None


def test_the_synthesis_bound_is_the_m19b_constant() -> None:
    import m19b_ablation  # noqa: PLC0415 -- the script, for the pre-registered value

    assert LOCAL_TOOL_OUTPUT_BUDGET == m19b_ablation.TOOL_OUTPUT_BUDGET == 4096


def test_the_factory_receives_the_arms_pinned_tag() -> None:
    client = build_client(arm_d1("qwen3.5:9b", sampling=Sampling(0.7, 3)))
    assert isinstance(client, OllamaLLM)
    assert client.model == "qwen3.5:9b"
    assert client.sampling == Sampling(0.7, 3)


def test_the_default_factory_uses_the_d1_sampling_policy() -> None:
    client = ollama_factory()("qwen3.5:4b")
    assert client.sampling == D1_SAMPLING == Sampling(temperature=0.0, seed=0)


def test_d1_is_registered_in_its_own_builder_table_not_the_frozen_one() -> None:
    from ath.evaluation.ablation import ARM_BUILDERS  # noqa: PLC0415

    assert LOCAL_ARM_BUILDERS[ARM_D1] is arm_d1
    assert ARM_D1 not in ARM_BUILDERS


def test_d1_refuses_an_empty_tag() -> None:
    with pytest.raises(ValueError):
        arm_d1("")


def test_a_scripted_d1_row_is_labelled_d1_scripted_and_runs_the_investigator(
    manifest, corpus, pipeline,
) -> None:
    findings, cases, environment = pipeline
    abstain = (
        '{"explanations": [{"label": "insufficient", "statement": "not enough", "evidence": []}], '
        '"evidence_gap": "none", "next_probe": "none", "probe_reason": "", "disposition": "abstain"}'
    )
    scripted = ScriptedLLM(responses=[abstain] * 64, name="scripted-model")
    results = run_local_arm(
        arm_d1("qwen3.5:4b"), manifest, corpus, cases, findings=findings,
        environment=environment, llm=scripted, scripted=True,
    )
    assert results
    for result in results:
        assert result.arm == ARM_D1
        assert result.labelled_arm == f"{ARM_D1}_SCRIPTED"
        assert result.budgets["tool_call_cap"] == 40
        assert result.budgets["max_steps"] == 8
        assert result.state["agents_run"][0] == "investigator:seed", "D1 must run the investigator"
        assert result.state["investigation"]["final_disposition"] == "abstain"


def test_run_local_arm_refuses_without_a_model_exactly_as_run_arm_does(manifest, corpus, pipeline) -> None:
    findings, cases, environment = pipeline
    with pytest.raises(ArmUnavailable):
        run_local_arm(arm_d1("qwen3.5:4b", llm_factory=NullLLM), manifest, corpus, cases, findings=findings)
    with pytest.raises(ArmUnavailable):
        run_local_arm(arm_d1("qwen3.5:4b"), manifest, corpus, cases, findings=findings, llm=NullLLM(), scripted=True)


def test_model_spec_reads_the_daemons_description() -> None:
    spec = ModelSpec.from_description({
        "provider": "ollama", "model": "qwen3.5:4b", "quantization_level": "Q4_K_M",
        "parameter_size": "4.7B", "digest": "abc",
    })
    assert spec == ModelSpec("ollama", "qwen3.5:4b", "Q4_K_M", "4.7B", "abc")
    assert spec.quant_label == "Q4_K_M"
    assert ModelSpec("ollama", "x").quant_label == "unknown-quant"
