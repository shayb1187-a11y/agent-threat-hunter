"""The LLM arm is the same pipeline with a model in the loop -- and says so.

Three properties pinned here, because each is a way the arm comparison could lie:

1. With no model the run is byte-for-byte the deterministic one (the default did not
   move when the parameter was added).
2. A row produced under an LLM arm is labelled with the model's name, so it can never
   be mistaken for a deterministic row in the evaluation table.
3. An LLM arm whose model failed and fell back to deterministic planning is labelled
   ``llm_degraded`` -- the silent-degradation failure this codebase has been bitten by
   before (see ``AnthropicLLM``'s permanent/retryable split) must be visible here too.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ath.agent.llm import ScriptedLLM
from ath.agent.orchestrator import InvestigationConfig
from ath.evaluation.incidents import run_benchmark, run_incident
from ath.evaluation.suite import windows_intrusion
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory) -> Path:
    directory = tmp_path_factory.mktemp("llm-arm")
    tables, ground_truth = generate_telemetry(GeneratorConfig(seed=7))
    write_telemetry(tables, ground_truth, directory)
    return directory


@pytest.fixture(scope="module")
def deterministic(data_dir):
    return run_incident(windows_intrusion(data_dir))


def test_default_arm_is_deterministic_and_says_so(deterministic) -> None:
    assert deterministic.configuration == "deterministic"
    assert deterministic.llm_degraded is False
    assert deterministic.to_dict()["configuration"] == "deterministic"


def test_explicit_null_llm_matches_the_default_exactly(data_dir, deterministic) -> None:
    """Adding the parameter must not have moved any deterministic number."""
    from ath.agent.llm import NullLLM

    again = run_incident(windows_intrusion(data_dir), llm=NullLLM())
    lhs, rhs = deterministic.to_dict(), again.to_dict()
    lhs["cost"].pop("runtime_seconds")
    rhs["cost"].pop("runtime_seconds")
    assert lhs == rhs


def test_llm_arm_rows_carry_the_model_name(data_dir) -> None:
    llm = ScriptedLLM(responses=[], name="scripted-model")
    outcome = run_incident(windows_intrusion(data_dir), llm=llm)
    assert outcome.configuration == "scripted-model"
    # Detection, triage and correlation are the same code either way; only the
    # investigation stage differs, so these must match the deterministic arm.
    baseline = run_incident(windows_intrusion(data_dir))
    assert outcome.findings == baseline.findings
    assert outcome.cases == baseline.cases
    assert outcome.findings_after_triage == baseline.findings_after_triage


def test_a_model_that_fails_is_reported_as_degraded_not_as_an_llm_result(data_dir) -> None:
    """Zero scripted responses: every call errors, the orchestrator falls back."""
    llm = ScriptedLLM(responses=[], name="scripted-model")
    outcome = run_incident(windows_intrusion(data_dir), llm=llm)
    assert outcome.llm_degraded is True
    assert outcome.llm_status
    assert outcome.to_dict()["llm_degraded"] is True


def test_investigation_config_can_be_pinned_per_arm(data_dir) -> None:
    """A planner-only arm is a legitimate configuration and must be honoured."""
    llm = ScriptedLLM(responses=[], name="scripted-model")
    config = InvestigationConfig(use_llm_planner=True, use_llm_synthesis=False)
    outcome = run_incident(windows_intrusion(data_dir), llm=llm, investigation_config=config)
    assert outcome.configuration == "scripted-model"
    # Synthesis was off, so the only model calls were planning ones and every one
    # failed: the run degraded to deterministic planning and says so.
    assert outcome.llm_degraded is True


def test_benchmark_threads_the_arm_through_every_incident(data_dir) -> None:
    llm = ScriptedLLM(responses=[], name="scripted-model")
    result = run_benchmark([windows_intrusion(data_dir)], llm=llm)
    assert [o.configuration for o in result.outcomes] == ["scripted-model"]
