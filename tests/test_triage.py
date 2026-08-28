"""Tests for benign-evidence assessment.

The asymmetry these tests enforce: failing to explain a false positive is a missed
opportunity, but calling a true positive benign is a correctness failure. Every test
that could only fail in the second direction is written to fail loudly.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ath.environment import build_environment_model
from ath.hunting import run_hunt
from ath.hunting.finding import Evidence, Finding, Severity
from ath.triage import (
    BENIGN_THRESHOLD,
    Disposition,
    assess_finding,
    assess_findings,
    triage_summary,
)
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import load_telemetry


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory):
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("triage_data")
    write_telemetry(tables, gt, out)
    return out


@pytest.fixture(scope="module")
def telemetry(data_dir):
    return load_telemetry(data_dir)


@pytest.fixture(scope="module")
def environment(telemetry):
    return build_environment_model(telemetry)


@pytest.fixture(scope="module")
def findings(telemetry):
    return run_hunt(telemetry).findings


@pytest.fixture(scope="module")
def malicious(data_dir):
    from ath.evaluation.suite import malicious_event_ids

    return malicious_event_ids(data_dir)


@pytest.fixture(scope="module")
def assessments(findings, environment):
    return assess_findings(findings, environment)


def _finding(rule_id: str, severity: Severity, metadata: dict) -> Finding:
    return Finding(
        rule_id=rule_id, title="t", severity=severity, device="PC02", user="mrossi",
        evidence=(Evidence("evt-000001", datetime.now(timezone.utc), "s"),),
        reason="r", metadata=metadata,
    )


# ======================================================================================
# The asymmetric guarantee
# ======================================================================================


def test_no_true_positive_is_ever_called_benign(findings, assessments, malicious) -> None:
    """The one failure mode that is not acceptable at any rate.

    Telling an analyst to disregard a real detection is categorically worse than
    failing to reassure them about a false one, which is why benign evidence can be
    out-voted by a single veto but can never out-weigh one.
    """
    wrongly_cleared = [
        f.rule_id for f in findings
        if (set(f.event_ids) & malicious)
        and assessments[f.finding_id].disposition is Disposition.LIKELY_BENIGN
    ]
    assert not wrongly_cleared, f"attack findings marked benign: {wrongly_cleared}"


def test_both_known_false_positives_are_explained(findings, assessments, malicious) -> None:
    """The administrator's look-alike is the whole reason this layer exists."""
    cleared = [
        f.rule_id for f in findings
        if not (set(f.event_ids) & malicious)
        and assessments[f.finding_id].disposition is Disposition.LIKELY_BENIGN
    ]
    assert sorted(cleared) == ["ATH-002", "ATH-003"]


def test_triage_never_removes_a_finding(findings, assessments) -> None:
    """Assessment annotates; it must never suppress.

    A pipeline that silently dropped alerts it believed benign would be unauditable,
    and the first time it was wrong nobody would ever find out.
    """
    assert len(assessments) == len(findings)
    assert set(assessments) == {f.finding_id for f in findings}


def test_disposition_counts_are_reported(assessments) -> None:
    summary = triage_summary(assessments)
    assert summary["likely_benign"] == 2
    # ATH-011 and ATH-012 both grade CRITICAL, which the severity veto refuses to
    # clear -- so the malicious count grew by exactly the two new rules.
    assert summary["likely_malicious"] == 10
    assert summary["needs_review"] == 3


# ======================================================================================
# Why each verdict was reached
# ======================================================================================


def test_benign_verdicts_cite_their_reasons(findings, assessments, malicious) -> None:
    """A verdict without a stated basis cannot be checked, so it must not exist."""
    for finding in findings:
        assessment = assessments[finding.finding_id]
        if assessment.disposition is Disposition.LIKELY_BENIGN:
            assert assessment.benign_signals
            assert all(s.reason for s in assessment.benign_signals)
            assert assessment.score >= BENIGN_THRESHOLD


def test_environment_knowledge_drives_the_admin_verdict(findings, assessments) -> None:
    """The decisive fact was already known and previously unused.

    The environment model identifies `CcmExec.exe` as Configuration Manager. Nothing
    consumed that until this layer existed.
    """
    ath002 = [f for f in findings if f.rule_id == "ATH-002" and f.device == "PC07"]
    assert ath002, "the benign look-alike is missing from this generation"
    names = {s.name for s in assessments[ath002[0].finding_id].benign_signals}
    assert "known_management_tool" in names


def test_prevalence_drives_the_destination_verdict(findings, assessments) -> None:
    ath003 = [f for f in findings if f.rule_id == "ATH-003" and f.device == "PC07"]
    assert ath003
    names = {s.name for s in assessments[ath003[0].finding_id].benign_signals}
    assert "ubiquitous_destination" in names


def test_malicious_verdicts_cite_a_veto(findings, assessments) -> None:
    for finding in findings:
        assessment = assessments[finding.finding_id]
        if assessment.disposition is Disposition.LIKELY_MALICIOUS:
            assert assessment.vetoes
            assert all(v.reason for v in assessment.vetoes)


def test_needs_review_is_the_honest_default(findings, assessments) -> None:
    """Most alerts have nothing decisive either way, and should say so."""
    undecided = [
        a for a in assessments.values() if a.disposition is Disposition.NEEDS_REVIEW
    ]
    assert undecided
    for assessment in undecided:
        assert not assessment.vetoes
        assert assessment.score < BENIGN_THRESHOLD


# ======================================================================================
# Adversarial: can benign evidence be manufactured?
# ======================================================================================


def test_beacon_through_trusted_infrastructure_is_not_cleared(environment) -> None:
    """The hole prevalence opens, and the veto that closes it.

    An implant beaconing through a popular cloud service inherits that service's reach,
    so `ubiquitous_destination` fires on it. Before the sustained-contact veto existed,
    that alone was enough to mark a 48-connection beacon `likely_benign` -- telling an
    analyst to ignore live C2, the worst output this system could produce.
    """
    ubiquitous = max(
        environment.destinations.values(), key=lambda p: len(p.processes)
    ).remote_ip
    beacon = _finding("ATH-003", Severity.MEDIUM, {
        "remote_ip": ubiquitous, "ports": [443],
        "connection_count": 48, "cleartext_http": False,
    })
    assessment = assess_finding(beacon, environment)
    assert assessment.disposition is not Disposition.LIKELY_BENIGN
    assert any(v.name == "sustained_interpreter_contact" for v in assessment.vetoes)


def test_low_volume_contact_to_the_same_destination_is_still_clearable(
    environment,
) -> None:
    """The veto must discriminate on volume, not disable the signal entirely.

    An inventory script checking in once is the case this layer was built to explain;
    if the beacon veto also caught that, it would have closed the hole by removing the
    capability.
    """
    ubiquitous = max(
        environment.destinations.values(), key=lambda p: len(p.processes)
    ).remote_ip
    one_off = _finding("ATH-003", Severity.MEDIUM, {
        "remote_ip": ubiquitous, "ports": [443],
        "connection_count": 1, "cleartext_http": False,
    })
    assert assess_finding(one_off, environment).disposition is Disposition.LIKELY_BENIGN


def test_high_severity_findings_can_never_be_cleared(environment) -> None:
    """A rule that graded itself HIGH did so on evidence this layer does not revisit."""
    loaded = {
        "parent_process": "CcmExec.exe", "evasion_flags": [], "download_indicators": [],
    }
    benign = assess_finding(_finding("ATH-002", Severity.LOW, loaded), environment)
    assert benign.disposition is Disposition.LIKELY_BENIGN

    severe = assess_finding(_finding("ATH-002", Severity.HIGH, loaded), environment)
    assert severe.disposition is Disposition.LIKELY_MALICIOUS
    assert any(v.name == "graded_high_by_detection" for v in severe.vetoes)


def test_trusted_parent_does_not_excuse_evasion(environment) -> None:
    """Signals accumulate, vetoes dominate -- even a management-tool parent."""
    assessment = assess_finding(_finding("ATH-002", Severity.MEDIUM, {
        "parent_process": "CcmExec.exe",
        "evasion_flags": ["hidden window", "no profile"],
        "download_indicators": ["iex", "downloadstring"],
    }), environment)
    assert assessment.disposition is Disposition.LIKELY_MALICIOUS
    assert assessment.benign_signals, "the trusted-parent signal should still be recorded"


def test_missing_metadata_is_not_read_as_absence(environment) -> None:
    """A rule that never inspected a field has not checked and found nothing.

    Treating an absent key as "no evasion flags present" would manufacture benign
    evidence out of a rule's silence.
    """
    assessment = assess_finding(_finding("ATH-007", Severity.MEDIUM, {}), environment)
    names = {s.name for s in assessment.benign_signals}
    assert "no_evasion_indicators" not in names
    assert "no_download_indicators" not in names
    assert assessment.disposition is Disposition.NEEDS_REVIEW


def test_assessment_serialises(findings, assessments) -> None:
    import json

    payload = json.loads(json.dumps([a.to_dict() for a in assessments.values()]))
    assert len(payload) == len(findings)
    assert all("explanation" in entry for entry in payload)


# ======================================================================================
# Affirmative evidence is required, not merely the absence of bad news
# ======================================================================================


def test_absence_of_indicators_alone_never_clears_a_finding(environment) -> None:
    """The hole adversarial testing found.

    `no_evasion_indicators` (2) + `no_download_indicators` (2) reached the threshold on
    their own, so a finding naming a parent this environment has never seen -- with an
    empty command line -- was cleared as benign. Nothing about it was known to be
    legitimate; it had simply avoided tripping anything, which is the easy half of
    evasion and exactly the inference this project refuses everywhere else.
    """
    assessment = assess_finding(_finding("ATH-002", Severity.LOW, {
        "parent_process": "NeverSeenBefore.exe",
        "evasion_flags": [], "download_indicators": [],
    }), environment)

    assert assessment.score >= BENIGN_THRESHOLD, "test is vacuous below the threshold"
    assert not any(s.affirmative for s in assessment.benign_signals)
    assert assessment.disposition is Disposition.NEEDS_REVIEW


def test_that_verdict_explains_what_is_missing(environment) -> None:
    """An analyst must be able to tell "nothing found" from "nothing to find"."""
    assessment = assess_finding(_finding("ATH-002", Severity.LOW, {
        "parent_process": "NeverSeenBefore.exe",
        "evasion_flags": [], "download_indicators": [],
    }), environment)
    assert "nothing positively identifies" in assessment.explanation


def test_supporting_signals_still_corroborate_an_affirmative_one(environment) -> None:
    """The fix must not discard the supporting signals, only stop them standing alone."""
    assessment = assess_finding(_finding("ATH-002", Severity.LOW, {
        "parent_process": "CcmExec.exe",
        "evasion_flags": [], "download_indicators": [],
    }), environment)
    names = {s.name for s in assessment.benign_signals}
    assert "known_management_tool" in names
    assert {"no_evasion_indicators", "no_download_indicators"} <= names
    assert assessment.disposition is Disposition.LIKELY_BENIGN


def test_every_signal_declares_whether_it_is_affirmative() -> None:
    """Guards the classification itself: a new signal must make the choice explicitly."""
    from ath.triage.benign import BENIGN_SIGNALS

    affirmative = [name for name, _, is_affirmative, _ in BENIGN_SIGNALS if is_affirmative]
    supporting = [name for name, _, is_affirmative, _ in BENIGN_SIGNALS if not is_affirmative]
    assert affirmative, "no affirmative signal exists, so nothing could ever be cleared"
    assert supporting, "the distinction is meaningless if every signal is affirmative"
