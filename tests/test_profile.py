"""The label-free profile reports the same numbers the layers it wraps would give.

It is a measurement, not a model: every figure must be derivable by calling hunt,
triage and correlation directly, and the per-day rates must follow from the window.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ath.correlation import correlate
from ath.environment import build_environment_model
from ath.evaluation.profile import profile_telemetry
from ath.hunting import run_hunt
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import Telemetry, load_telemetry
from ath.triage import Disposition, assess_findings


@pytest.fixture(scope="module")
def telemetry(tmp_path_factory) -> Telemetry:
    directory: Path = tmp_path_factory.mktemp("profile")
    tables, ground_truth = generate_telemetry(GeneratorConfig(seed=11))
    write_telemetry(tables, ground_truth, directory)
    return load_telemetry(directory)


@pytest.fixture(scope="module")
def profile(telemetry):
    return profile_telemetry(telemetry)


def test_counts_match_the_layers_called_directly(telemetry, profile) -> None:
    hunt = run_hunt(telemetry)
    assert profile.findings == len(hunt.findings)
    assert sum(profile.findings_by_rule.values()) == profile.findings
    assert sum(profile.findings_by_severity.values()) == profile.findings

    environment = build_environment_model(telemetry)
    assert profile.hosts == len(environment.hosts)
    assert profile.identities == len(environment.identities)

    assessments = assess_findings(hunt.findings, environment)
    benign = sum(
        1 for a in assessments.values() if a.disposition is Disposition.LIKELY_BENIGN
    )
    assert profile.findings_after_triage == profile.findings - benign

    cases = correlate(hunt.findings, telemetry)
    assert profile.cases == len(cases)
    assert profile.singleton_cases == sum(1 for c in cases if len(c.findings) == 1)


def test_rates_follow_from_the_window(profile) -> None:
    assert profile.window_hours > 0
    assert profile.findings_per_day == pytest.approx(profile.findings / profile.window_days)
    assert profile.findings_per_host_day == pytest.approx(
        profile.findings / (profile.window_days * profile.hosts)
    )


def test_stage_timings_are_recorded_separately(profile) -> None:
    """E8 needs the pairwise correlator told apart from the linear stages."""
    d = profile.to_dict()["cost_seconds"]
    assert set(d) == {"hunt", "environment", "triage", "correlate"}
    assert all(v >= 0 for v in d.values())


def test_empty_telemetry_profiles_to_zero_not_an_error() -> None:
    from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS
    from ath.telemetry.cloudtrail_source import _empty

    empty = Telemetry(
        processes=_empty(EVENT_PROCESS), network=_empty(EVENT_NETWORK),
        logons=_empty(EVENT_LOGON), controls=_empty(EVENT_CONTROL),
    )
    profile = profile_telemetry(empty)
    assert profile.events == 0
    assert profile.findings == 0
    assert profile.findings_per_day == 0.0
