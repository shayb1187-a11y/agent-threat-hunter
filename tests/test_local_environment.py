"""The RAM guard and the local freeze.

Why these tests exist
----------------------
*RAM.* Paging is the one failure on a 16 GB laptop that produces no error anywhere: the
call just takes fifteen minutes. The guard is the only defence, so its three answers --
refuse, proceed, cannot-tell -- must each be the right one and must each say why.

*Freeze.* A scored local run must be able to say afterwards which weights, which daemon,
which sampling, which prompts and which scoring produced it. The check must flag every
one of those moving and must *not* flag the two things that legitimately move between
runs: the commit (the dev loop commits) and available RAM.
"""

from __future__ import annotations

from pathlib import Path

from ath.evaluation.ablation.local import (
    GIB,
    LOCAL_GATED_FIELDS,
    RAM_FLOORS_BYTES,
    arm_d1,
    available_ram_bytes,
    check_local_environment,
    check_ram,
    local_environment,
    ram_floor_for,
)

ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------------------
# RAM
# --------------------------------------------------------------------------------------


def test_floors_follow_the_daemons_reported_size() -> None:
    assert ram_floor_for("4.7B") == RAM_FLOORS_BYTES["4B"]
    assert ram_floor_for("3.1B") == RAM_FLOORS_BYTES["4B"]
    assert ram_floor_for("9.1B") == RAM_FLOORS_BYTES["9B"]
    assert ram_floor_for("8B") == RAM_FLOORS_BYTES["9B"]
    assert ram_floor_for("27B") is None, "no class -> unguarded, and the row says so"
    assert ram_floor_for(None) is None
    assert ram_floor_for("large") is None


def test_below_the_floor_is_refused_with_both_numbers_in_the_message() -> None:
    verdict = check_ram(RAM_FLOORS_BYTES["9B"], int(6 * GIB))
    assert verdict.ok is False
    assert "6.00 GiB" in verdict.message and "9.5 GiB" in verdict.message
    assert verdict.to_dict()["floor_bytes"] == RAM_FLOORS_BYTES["9B"]


def test_at_or_above_the_floor_proceeds() -> None:
    assert check_ram(RAM_FLOORS_BYTES["4B"], RAM_FLOORS_BYTES["4B"]).ok is True
    assert check_ram(RAM_FLOORS_BYTES["4B"], int(12 * GIB)).ok is True


def test_an_unknown_measurement_or_floor_proceeds_but_says_it_is_unguarded() -> None:
    no_floor = check_ram(None, int(12 * GIB))
    assert no_floor.ok is None and "unguarded" in no_floor.message
    no_reading = check_ram(RAM_FLOORS_BYTES["4B"], None)
    assert no_reading.ok is None and "could not be measured" in no_reading.message


def test_available_ram_is_a_positive_integer_or_none_on_this_platform() -> None:
    reading = available_ram_bytes()
    assert reading is None or (isinstance(reading, int) and reading > 0)


# --------------------------------------------------------------------------------------
# Freeze
# --------------------------------------------------------------------------------------


def _described(**overrides) -> dict:
    base = {
        "provider": "ollama", "base_url": "http://127.0.0.1:11434", "daemon_version": "0.33.3",
        "model": "qwen3.5:4b", "digest": "d" * 64, "size_bytes": 3_389_983_735,
        "modified_at": "2026-09-14T20:37:31Z", "family": "qwen35", "parameter_size": "4.7B",
        "quantization_level": "Q4_K_M", "format": "gguf",
        "capabilities": ["completion", "tools", "thinking"], "model_context_length": 262144,
        "configuration": {
            "provider": "ollama", "model": "qwen3.5:4b", "base_url": "http://127.0.0.1:11434",
            "sampling": {"temperature": 0.0, "seed": 0}, "num_ctx": 10240,
            "num_predict_cap": 2048, "think": False, "format": "json", "keep_alive": -1,
            "timeout_seconds_per_attempt": 900, "max_attempts": 3, "backoff_seconds": 1.0,
        },
    }
    base.update(overrides)
    return base


def _frozen(**overrides) -> dict:
    return local_environment(
        ROOT, manifest_hash="a" * 64, arm=arm_d1("qwen3.5:4b"),
        described=_described(**overrides), available_ram=int(7 * GIB),
    )


def test_the_freeze_carries_the_m19b_sections_and_a_local_one() -> None:
    frozen = _frozen()
    for section in ("git", "arms", "prompts", "scoring", "manifest_hash", "request", "retry"):
        assert section in frozen, section
    assert frozen["arms"]["D1_local_single"]["model"] == "qwen3.5:4b"
    local = frozen["local"]
    assert local["model"]["digest"] == "d" * 64
    assert local["daemon"]["version"] == "0.33.3"
    assert local["client_configuration"]["think"] is False
    assert local["machine"]["available_ram_bytes"] == 7 * GIB
    assert frozen["credential"]["present"] is False
    # The hosted credential's *name* is recorded (presence only, as M19b does); no value
    # of any kind may be, and the local tier has none to leak.
    assert frozen["credential"]["variable"] == "ATH_LLM_API_KEY"
    assert "sk-" not in str(frozen)


def test_a_clean_world_has_no_differences() -> None:
    assert check_local_environment(_frozen(), manifest_hash="a" * 64, described=_described()) == []


def test_every_gated_field_is_flagged_when_it_moves() -> None:
    frozen = _frozen()
    flagged = []

    flagged += check_local_environment(frozen, manifest_hash="b" * 64, described=_described())
    flagged += check_local_environment(frozen, manifest_hash="a" * 64, described=_described(digest="e" * 64))
    flagged += check_local_environment(frozen, manifest_hash="a" * 64, described=_described(daemon_version="0.34.0"))
    moved_sampling = _described()
    moved_sampling["configuration"] = {**moved_sampling["configuration"], "sampling": {"temperature": 0.7, "seed": 0}}
    flagged += check_local_environment(frozen, manifest_hash="a" * 64, described=moved_sampling)
    moved_think = _described()
    moved_think["configuration"] = {**moved_think["configuration"], "think": True}
    flagged += check_local_environment(frozen, manifest_hash="a" * 64, described=moved_think)

    joined = "\n".join(flagged)
    for field_name in ("manifest_hash", "model_digest", "daemon_version",
                       "client_configuration.sampling", "client_configuration.think"):
        assert field_name in joined, field_name
    assert len(flagged) == 5


def test_where_the_daemon_lives_and_how_patient_the_client_is_are_not_gated() -> None:
    frozen = _frozen()
    moved = _described(base_url="http://gpu-box:11434")
    moved["configuration"] = {
        **moved["configuration"], "base_url": "http://gpu-box:11434",
        "timeout_seconds_per_attempt": 1200, "max_attempts": 5,
    }
    assert check_local_environment(frozen, manifest_hash="a" * 64, described=moved) == []


def test_available_ram_and_the_commit_are_recorded_but_never_gated() -> None:
    frozen = _frozen()
    frozen["git"]["commit"] = "0" * 40
    frozen["local"]["machine"]["available_ram_bytes"] = 1
    assert check_local_environment(frozen, manifest_hash="a" * 64, described=_described()) == []
    assert "commit" not in LOCAL_GATED_FIELDS


def test_a_prompt_or_scoring_drift_is_flagged_by_name() -> None:
    frozen = _frozen()
    frozen["prompts"]["planner_system"] = "0" * 64
    frozen["scoring"]["arms.py"] = "0" * 64
    flagged = check_local_environment(frozen, manifest_hash="a" * 64, described=_described())
    assert any(f.startswith("prompts.planner_system") for f in flagged)
    assert any(f.startswith("scoring.arms.py") for f in flagged)
    assert len(flagged) == 2


def test_the_investigators_prompts_and_bounds_are_frozen_and_gated() -> None:
    """A D1 run under different investigator prompts, schema or bounds is a different
    experiment. Fails if the freeze stops recording them or the gate stops reading them."""
    frozen = _frozen()
    investigator = frozen["local"]["investigator"]
    for name in ("investigator_version", "investigator_system", "investigator_user_template",
                 "investigator_schema", "investigator_bounds", "max_probes", "max_tokens"):
        assert name in investigator, name
    assert "investigator" in LOCAL_GATED_FIELDS
    frozen["local"]["investigator"]["investigator_system"] = "0" * 64
    frozen["local"]["investigator"]["max_probes"] = 99
    flagged = check_local_environment(frozen, manifest_hash="a" * 64, described=_described())
    assert any(f.startswith("investigator.investigator_system") for f in flagged)
    assert any(f.startswith("investigator.max_probes") for f in flagged)
    assert len(flagged) == 2


def test_a_model_already_resident_is_credited_against_the_floor() -> None:
    """A daemon that kept the weights loaded is not refused for the memory they use."""
    floor = RAM_FLOORS_BYTES["4B"]
    refused = check_ram(floor, int(1.7 * GIB))
    assert refused.ok is False
    credited = check_ram(floor, int(1.7 * GIB), resident_bytes=int(3.2 * GIB))
    assert credited.ok is True
    assert "already resident" in credited.message
    assert credited.to_dict()["resident_bytes"] == int(3.2 * GIB)
    assert credited.effective_bytes == int(1.7 * GIB) + int(3.2 * GIB)
    still_short = check_ram(floor, int(0.5 * GIB), resident_bytes=int(3.2 * GIB))
    assert still_short.ok is False and "already resident" in still_short.message
