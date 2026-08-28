"""Adversarial tests: can an attacker manufacture a benign verdict?

The triage layer is the one component whose *success* is telling an analyst to stop
looking. That makes it the most valuable thing in this system to subvert, and the only
component where an exploited weakness actively helps an intruder rather than merely
failing to help the defender.

Each test below is written as an attack with a stated goal, not as a coverage exercise.
Where an attack succeeds, the test asserts the current -- inadequate -- behaviour and
says so plainly, so a limitation cannot hide behind a green suite.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd
import pytest

from ath.environment import build_environment_model
from ath.hunting.finding import Evidence, Finding, Severity
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.identity import derive_identity
from ath.telemetry.loader import Telemetry, load_telemetry
from ath.triage import Disposition, assess_finding


@pytest.fixture(scope="module")
def telemetry(tmp_path_factory):
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("adversarial")
    write_telemetry(tables, gt, out)
    return load_telemetry(out)


@pytest.fixture(scope="module")
def environment(telemetry):
    return build_environment_model(telemetry)


def _finding(rule_id="ATH-002", severity=Severity.MEDIUM, **metadata) -> Finding:
    return Finding(
        rule_id=rule_id, title="t", severity=severity, device="PC02", user="mrossi",
        evidence=(Evidence("evt-000001", datetime.now(timezone.utc), "s"),),
        reason="r", metadata=metadata,
    )


def _most_trusted_destination(environment) -> str:
    return max(
        environment.destinations.values(), key=lambda p: len(p.processes)
    ).remote_ip


# ======================================================================================
# Attack 1: impersonate a trusted product
# ======================================================================================


def test_attack_rename_payload_after_a_security_product(telemetry) -> None:
    """Goal: inherit Microsoft Defender's reputation for the price of a rename.

    Worked before process identity was carried: `is_known_security_tool` matched on
    image name, so a file called `MsMpEng.exe` contributed the single largest benign
    signal available.
    """
    path = r"C:\Users\jdoe\AppData\Local\Temp\MsMpEng.exe"
    sha, signer, status = derive_identity("MsMpEng.exe", path)
    row = telemetry.processes.iloc[0].copy()
    row["event_id"], row["process_name"], row["file_path"] = "evt-EVIL", "MsMpEng.exe", path
    row["sha256"], row["signer"], row["signature_status"] = sha, signer, status
    poisoned = Telemetry(
        processes=pd.concat([telemetry.processes, pd.DataFrame([row])], ignore_index=True),
        network=telemetry.network, logons=telemetry.logons,
    )
    environment = build_environment_model(poisoned)

    assessment = assess_finding(_finding(
        parent_process="MsMpEng.exe", evasion_flags=[], download_indicators=[],
    ), environment)
    assert assessment.disposition is not Disposition.LIKELY_BENIGN
    assert any(v.name == "process_identity_conflict" for v in assessment.vetoes)


# ======================================================================================
# Attack 2: hide behind trusted infrastructure
# ======================================================================================


def test_attack_beacon_through_a_popular_destination(environment) -> None:
    """Goal: inherit a cloud service's prevalence for C2."""
    assessment = assess_finding(_finding(
        rule_id="ATH-003", remote_ip=_most_trusted_destination(environment),
        ports=[443], connection_count=48, cleartext_http=False,
    ), environment)
    assert assessment.disposition is Disposition.LIKELY_MALICIOUS


def test_attack_low_and_slow_through_a_popular_destination(environment) -> None:
    """Goal: stay under the sustained-contact threshold.

    **This attack currently succeeds**, and the test asserts that rather than hiding
    it. Four contacts to a widely-used destination over TLS is indistinguishable, on
    the evidence available here, from an application checking in -- defeating it needs
    inter-arrival regularity, which lives in the investigation layer's `analyse_beacon`
    tool and is not available at triage time.

    Recorded with an explicit assertion so that closing the gap breaks this test and
    forces the README's stated limitations to be updated with it.
    """
    assessment = assess_finding(_finding(
        rule_id="ATH-003", remote_ip=_most_trusted_destination(environment),
        ports=[443], connection_count=4, cleartext_http=False,
    ), environment)
    assert assessment.disposition is Disposition.LIKELY_BENIGN, (
        "if this now fails, the low-and-slow gap has been closed -- update the "
        "README's stated limitations"
    )


# ======================================================================================
# Attack 3: forge the metadata the signals read
# ======================================================================================


def test_attack_claim_a_trusted_parent_that_does_not_exist(environment) -> None:
    """Goal: name a parent process the environment has never seen.

    An unknown name earns nothing: signals are gated on what the environment model
    actually observed, not on what a finding asserts about itself.
    """
    assessment = assess_finding(_finding(
        parent_process="TotallyLegitEDR.exe", evasion_flags=[], download_indicators=[],
    ), environment)
    assert assessment.disposition is not Disposition.LIKELY_BENIGN


def test_attack_empty_metadata_to_dodge_every_veto(environment) -> None:
    """Goal: emit a finding with nothing incriminating in it.

    Dodging the vetoes must not amount to earning a benign verdict. Benign requires
    affirmative evidence, so the absence of everything lands on `needs_review`.
    """
    assessment = assess_finding(_finding(), environment)
    assert assessment.disposition is Disposition.NEEDS_REVIEW
    assert not assessment.benign_signals


def test_attack_flood_metadata_with_irrelevant_keys(environment) -> None:
    """Goal: dilute or confuse scoring with unrecognised fields."""
    assessment = assess_finding(_finding(**{
        f"junk_{n}": "x" * 50 for n in range(200)
    }), environment)
    assert assessment.disposition is Disposition.NEEDS_REVIEW
    assert assessment.score == 0


# ======================================================================================
# Attack 4: exploit the accumulation rule
# ======================================================================================


def test_attack_stack_weak_signals_past_the_threshold(environment) -> None:
    """Goal: reach the benign threshold on cheap signals while doing something bad.

    Accumulation must never outrun a veto. Here several benign signals fire *and* a
    download indicator is present; the veto has to win regardless of score.
    """
    assessment = assess_finding(_finding(
        rule_id="ATH-003",
        parent_process="CcmExec.exe",
        evasion_flags=[],
        download_indicators=["iex"],
        remote_ip=_most_trusted_destination(environment),
        ports=[443], connection_count=1, cleartext_http=False,
    ), environment)
    assert assessment.score >= 4, "test is vacuous unless benign evidence accumulated"
    assert assessment.disposition is Disposition.LIKELY_MALICIOUS


def test_attack_downgrade_severity_to_become_eligible(environment) -> None:
    """Goal: present severe activity at a severity the benign layer may clear.

    Severity is set by the rule, not by finding metadata, so this is only reachable via
    a compromised rule -- but even then the incriminating indicators still dominate.
    """
    assessment = assess_finding(_finding(
        severity=Severity.LOW, parent_process="CcmExec.exe",
        evasion_flags=["hidden window"], download_indicators=[],
    ), environment)
    assert assessment.disposition is Disposition.LIKELY_MALICIOUS


# ======================================================================================
# Attack 5: poison the baseline itself
# ======================================================================================


def test_attack_poison_prevalence_with_a_burst_of_hosts(telemetry) -> None:
    """Goal: make adversary infrastructure look ubiquitous by contacting it widely.

    Reach alone no longer clears anything: the destination must also have been present
    across the observation window. Something that appears everywhere at once is the
    shape of something spreading, not of something established.
    """
    c2 = "185.220.101.47"
    latest = telemetry.network["timestamp"].max()
    injected = []
    for host in ("PC01", "PC02", "PC03", "PC05", "PC07"):
        row = telemetry.network.iloc[0].copy()
        row["event_id"] = f"evt-POISON-{host}"
        row["device"], row["remote_ip"] = host, c2
        row["process_name"], row["timestamp"] = "chrome.exe", latest
        injected.append(row)
    poisoned = Telemetry(
        processes=telemetry.processes,
        network=pd.concat(
            [telemetry.network, pd.DataFrame(injected)], ignore_index=True
        ),
        logons=telemetry.logons,
    )
    environment = build_environment_model(poisoned)

    assert environment.destination_reach(c2) >= 0.5, "poisoning did not take effect"
    assessment = assess_finding(_finding(
        rule_id="ATH-003", remote_ip=c2, ports=[443],
        connection_count=1, cleartext_http=False,
    ), environment)
    assert assessment.disposition is not Disposition.LIKELY_BENIGN


def test_a_genuinely_established_destination_is_still_clearable(environment) -> None:
    """The counterweight: the emerging-destination guard must not disable the signal.

    Closing a hole by removing the capability would be no fix at all.
    """
    assessment = assess_finding(_finding(
        rule_id="ATH-003", remote_ip=_most_trusted_destination(environment),
        ports=[443], connection_count=1, cleartext_http=False,
    ), environment)
    assert assessment.disposition is Disposition.LIKELY_BENIGN


# ======================================================================================
# Invariants that must hold under every attack above
# ======================================================================================


def test_every_benign_verdict_carries_citable_reasons(environment) -> None:
    """No verdict may rest on an unstated basis, however it was reached."""
    assessment = assess_finding(_finding(
        parent_process="CcmExec.exe", evasion_flags=[], download_indicators=[],
    ), environment)
    assert assessment.disposition is Disposition.LIKELY_BENIGN
    assert assessment.benign_signals
    assert all(signal.reason.strip() for signal in assessment.benign_signals)


def test_assessment_never_mutates_the_finding(environment) -> None:
    """Triage annotates. A layer that edited findings would be unauditable."""
    finding = _finding(parent_process="CcmExec.exe", evasion_flags=[])
    before = finding.to_dict()
    assess_finding(finding, environment)
    assert finding.to_dict() == before
