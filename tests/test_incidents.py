"""Tests for the end-to-end incident benchmark.

These pin *measurements*, not a green tick. All three incidents currently meet their
success condition, which is precisely when a benchmark is most at risk of becoming
decorative -- so the numbers underneath stay asserted individually: noise cases, case
precision, residual triage load, cost. Two of these incidents failed when the suite was
written, and each fix had to change an assertion here before it counted.

"All incidents pass" is not the same claim as "the system is quiet". The Windows
scenario still raises a false-positive case, and `test_known_false_positive_is_counted
_as_noise` keeps that visible rather than letting a green suite imply otherwise.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ath.evaluation.incidents import run_benchmark, run_incident
from ath.evaluation.suite import (
    MALICIOUS_SCENARIOS,
    cloud_credential_stuffing,
    kubernetes_privilege_escalation,
    malicious_event_ids,
    quiet_day,
    scenario_event_ids,
    standard_suite,
    windows_intrusion,
)
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry

CLOUDTRAIL = Path(__file__).parent / "fixtures" / "cloudtrail"
K8S_AUDIT = Path(__file__).parent / "fixtures" / "k8s_audit"


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory):
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("bench_data")
    write_telemetry(tables, gt, out)
    return out


@pytest.fixture(scope="module")
def windows(data_dir):
    return run_incident(windows_intrusion(data_dir))


@pytest.fixture(scope="module")
def cloud():
    return run_incident(cloud_credential_stuffing(CLOUDTRAIL))


@pytest.fixture(scope="module")
def kubernetes():
    return run_incident(kubernetes_privilege_escalation(K8S_AUDIT))


@pytest.fixture(scope="module")
def quiet(data_dir):
    return run_incident(quiet_day(data_dir))


def _all_event_ids(telemetry) -> set:
    return (
        set(telemetry.processes["event_id"])
        | set(telemetry.network["event_id"])
        | set(telemetry.logons["event_id"])
    )


# ======================================================================================
# What counts as malicious
# ======================================================================================


def test_benign_lookalike_is_not_counted_as_malicious(data_dir) -> None:
    """The measurement bug this suite was first written with.

    `benign_lookalike` is labelled in ground truth *because* it is benign -- the IT
    administrator's encoded PowerShell, present so false-positive analysis is real.
    Treating every labelled scenario as an attack inflated the recall denominator and,
    worse, made the known false-positive case count as a true positive, so the harness
    reported zero noise while a real false alarm sat in the output.
    """
    assert "benign_lookalike" not in MALICIOUS_SCENARIOS

    malicious = malicious_event_ids(data_dir)
    lookalike = scenario_event_ids(data_dir, frozenset({"benign_lookalike"}))
    assert lookalike, "fixture no longer contains a benign look-alike"
    assert not (malicious & lookalike)


# ======================================================================================
# INC-001: the Windows intrusion
# ======================================================================================


def test_windows_intrusion_is_fully_detected(windows) -> None:
    assert windows.detected
    assert windows.event_recall == 1.0, (
        f"only {windows.malicious_events_surfaced}/{windows.malicious_events_total} "
        "intrusion events were surfaced"
    )


def test_windows_intrusion_lands_in_one_clean_case(windows) -> None:
    """Fragmentation and contamination are the two failure modes of correlation.

    Perfect recall with poor purity means the intrusion was merged with unrelated
    activity; perfect purity with poor recall means it was split across cases. Both
    are invisible to rule-level scoring.
    """
    assert windows.primary_case_recall == 1.0
    assert windows.primary_case_purity == 1.0


def test_windows_intrusion_reaches_its_conclusions(windows) -> None:
    assert not windows.conclusions_missed
    assert not windows.techniques_missing


def test_windows_intrusion_output_is_trustworthy(windows) -> None:
    assert windows.hallucinated_citations == 0
    assert windows.calibration_warnings == 0
    assert not windows.overclaimed_as_fact


def test_exfiltration_is_never_asserted_as_fact(windows) -> None:
    """The telemetry shows an archive made and, separately, a connection out.

    It never shows the bytes leaving. This is the specific overclaim the calibration
    layer exists to prevent, so it is measured rather than assumed.
    """
    assert "exfiltrat" not in windows.overclaimed_as_fact


def test_windows_intrusion_passes(windows) -> None:
    assert windows.passed


# ======================================================================================
# Analyst load -- the numbers that say whether any of this is useful
# ======================================================================================


def test_correlation_measurably_reduces_triage_load(windows) -> None:
    """13 findings become 2 cases. Without this, correlation is unjustified."""
    assert windows.findings > windows.cases
    assert windows.triage_reduction > 0.7


def test_known_false_positive_no_longer_costs_a_case(windows) -> None:
    """The benign look-alike is still detected and still counted; it no longer forms a
    case (M15-4). Until then half the cases on this dataset were false alarms: the
    administrator's two findings were explained by triage and raised as a case anyway,
    so case precision was pinned at 0.5. Both findings remain in the output, both carry
    a cited benign verdict, and the correlator is told not to raise a case for a group
    that is entirely explained.
    """
    assert windows.benign_findings_total == 2
    assert windows.benign_findings_identified == 2
    assert windows.noise_cases == 0
    assert windows.case_precision == 1.0


# ======================================================================================
# INC-002: cloud -- detection transfers, investigation does not
# ======================================================================================


def test_cloud_incident_is_detected(cloud) -> None:
    """ATH-005 transfers to CloudTrail with no modification."""
    assert cloud.detected
    assert cloud.event_recall > 0.9
    assert not cloud.techniques_missing


def test_cloud_incident_is_investigated_despite_a_single_finding(cloud) -> None:
    """The gap this benchmark found, and the fix for it.

    Correlation requires two structurally linked findings, and cloud telemetry here
    yields exactly one -- so no case formed, and the investigation layer never ran:
    0 facts, 0 tool calls. Detection metrics alone reported this as a success. A lone
    finding at or above HIGH is now raised as a single-finding case, so severity, not
    corroboration, decides whether something gets investigated.
    """
    assert cloud.findings == 1
    assert cloud.cases == 1
    assert cloud.facts > 0
    assert cloud.tool_calls > 0


def test_cloud_incident_reaches_its_conclusions(cloud) -> None:
    """Including the source address, which needed a second fix.

    `IdentityAgent` reported only resolved source *hostnames*, which cloud telemetry
    never carries -- so the sole piece of origin evidence available was dropped, and
    the incident still failed on `203.0.113.42` after the case-formation fix.
    """
    assert cloud.passed
    assert not cloud.conclusions_missed


# ======================================================================================
# INC-005: Kubernetes -- detection and correlation transfer, investigation does not
# ======================================================================================


def test_kubernetes_incident_is_detected_and_correlated(kubernetes) -> None:
    """K8S-001 and K8S-002 both fire and correlate into one case via shared_evidence."""
    assert kubernetes.detected
    assert kubernetes.event_recall == 1.0
    assert kubernetes.findings == 2
    assert kubernetes.cases == 1
    assert kubernetes.primary_case_recall == 1.0
    assert kubernetes.primary_case_purity == 1.0
    assert not kubernetes.techniques_missing


def test_kubernetes_incident_reaches_its_conclusions(kubernetes) -> None:
    """Phase B closes the gap Phase A measured and left open on purpose.

    `run_incident` builds an `EnvironmentModel` and passes it to the orchestrator,
    which -- since M13 Phase B -- assembles its specialist roster from that
    environment via `ath.capabilities.crew.assemble_crew` rather than always using
    the fixed `default_specialists()`. `CONTAINER_AUDIT` is observable for this
    telemetry, so `ControlPlaneAgent` now stands up automatically and this incident
    is actually investigated: this is the same measured incident that used to be
    pinned at 0 facts (see the M13 Phase A commit) before this orchestrator wiring
    existed.
    """
    assert kubernetes.facts > 0
    assert kubernetes.tool_calls > 0
    assert kubernetes.passed
    assert not kubernetes.conclusions_missed


def test_kubernetes_incident_never_asserts_exfiltration_or_ransom(kubernetes) -> None:
    assert not kubernetes.overclaimed_as_fact


# ======================================================================================
# INC-003: the quiet day
# ======================================================================================


def test_quiet_day_keeps_the_benign_lookalike(data_dir) -> None:
    """Removing every labelled event would delete the decoy and measure nothing."""
    incident = quiet_day(data_dir)
    lookalike = scenario_event_ids(data_dir, frozenset({"benign_lookalike"}))
    present = _all_event_ids(incident.telemetry)
    assert lookalike & present, "the benign look-alike was stripped along with the attack"


def test_quiet_day_contains_no_intrusion_events(data_dir) -> None:
    incident = quiet_day(data_dir)
    assert not (malicious_event_ids(data_dir) & _all_event_ids(incident.telemetry))


def test_quiet_day_still_raises_findings(quiet) -> None:
    """The detection layer is unchanged: a quiet day still trips two rules.

    Worth pinning separately from the triage result. The benign-evidence layer does not
    make the false positives stop happening -- it explains them -- and conflating the
    two would hide a real regression if the rules themselves got noisier. What changed
    in M15-4 is the case: two explained findings no longer raise one.
    """
    assert quiet.incident.is_benign
    assert quiet.findings == 2
    assert quiet.cases == 0
    assert quiet.noise_cases == 0


def test_quiet_day_false_alarms_are_all_explained(quiet) -> None:
    """The measured residual load on a day with no attack: zero.

    Both findings carry an explicit, cited benign verdict, so nothing is left for an
    analyst to investigate. This is the number that moved when the triage layer was
    added -- before it, the same two findings arrived with nothing but a severity.
    """
    assert quiet.benign_findings_total == 2
    assert quiet.benign_findings_identified == 2
    assert quiet.findings_after_triage == 0
    assert quiet.triage_load_reduction == 1.0
    assert quiet.passed


def test_quiet_day_output_is_still_well_formed(quiet) -> None:
    """Wrong is not the same as untrustworthy -- the false alarm is still calibrated."""
    assert quiet.trustworthy
    assert quiet.hallucinated_citations == 0


# ======================================================================================
# The suite
# ======================================================================================


def test_standard_suite_covers_attack_and_quiet_scenarios(data_dir) -> None:
    incidents = standard_suite(data_dir, CLOUDTRAIL)
    assert len(incidents) == 4
    assert any(i.is_benign for i in incidents), (
        "a suite with no quiet day rewards trigger-happy detection"
    )
    assert any(not i.is_benign for i in incidents)


def test_standard_suite_includes_kubernetes_when_a_fixture_dir_is_given(data_dir) -> None:
    """Opt-in, like CloudTrail: omitting the directory keeps the suite unchanged."""
    incidents = standard_suite(data_dir, CLOUDTRAIL, K8S_AUDIT)
    assert len(incidents) == 5
    assert any(i.incident_id == "INC-005" for i in incidents)


def test_benchmark_reports_current_state_honestly(data_dir) -> None:
    """Pins the headline: 4 of 4, and where the false positives went.

    Until M15-4 three noise cases were raised across the suite (the administrator's
    look-alike in INC-001, INC-004 and the quiet day), kept visible so a metric could
    not hide them. They are now zero, and the pressure that number applied has to be
    kept somewhere else: the look-alike findings are still raised by the rules and
    still counted here, every one of them explained, so a rule getting noisier or a
    benign verdict going missing shows up as a finding count, not as silence.
    """
    result = run_benchmark(standard_suite(data_dir, CLOUDTRAIL))
    assert result.total == 4
    assert result.passed == 4
    assert result.total_noise_cases == 0
    benign_total = sum(o.benign_findings_total for o in result.outcomes)
    benign_identified = sum(o.benign_findings_identified for o in result.outcomes)
    assert benign_total == 6  # the look-alike's two findings, in INC-001, INC-004 and INC-003
    assert benign_identified == benign_total


def test_no_incident_clears_a_true_positive(data_dir) -> None:
    """The suite-wide guarantee, checked across every scenario at once."""
    result = run_benchmark(standard_suite(data_dir, CLOUDTRAIL))
    for outcome in result.outcomes:
        assert outcome.malicious_findings_called_benign == 0, (
            f"{outcome.incident.incident_id} cleared a true positive as benign"
        )


def test_benchmark_serialises(data_dir) -> None:
    import json

    result = run_benchmark(standard_suite(data_dir, CLOUDTRAIL))
    payload = json.loads(json.dumps(result.to_dict()))
    assert len(payload["incidents"]) == 4
    assert payload["passed"] == 4
    assert "benign_discrimination" in payload["incidents"][0]
