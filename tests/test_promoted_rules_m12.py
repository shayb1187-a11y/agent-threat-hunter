"""Tests for ATH-011 and ATH-012, the first behavior-backed detections.

Both key on what was *done*, never on which binary did it. That is the property most
worth attacking, so most of these tests are attempts to evade or to provoke a false
alarm rather than confirmations that the happy path works.
"""

from __future__ import annotations

import pandas as pd
import pytest

from ath.hunting import Severity, run_hunt
from ath.hunting.base import get_detector
from ath.mitre.mapper import map_finding
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import Telemetry, load_ground_truth, load_telemetry


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory):
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("m12_rules")
    write_telemetry(tables, gt, out)
    return out


@pytest.fixture(scope="module")
def telemetry(data_dir):
    return load_telemetry(data_dir)


@pytest.fixture(scope="module")
def findings(telemetry):
    return run_hunt(telemetry).findings


def _one_process(telemetry, command_line: str, process_name: str, device="PC02"):
    """Telemetry containing exactly one process event with the given command line."""
    row = telemetry.processes.iloc[0].copy()
    row["event_id"] = "evt-SYNTH"
    row["device"], row["user"] = device, "mrossi"
    row["process_name"], row["command_line"] = process_name, command_line
    return Telemetry(
        processes=pd.DataFrame([row]),
        network=telemetry.network.iloc[0:0],
        logons=telemetry.logons.iloc[0:0],
    )


# ======================================================================================
# ATH-011 -- recovery inhibition
# ======================================================================================


def test_recovery_inhibition_fires_on_the_labelled_scenario(findings, data_dir) -> None:
    ath011 = [f for f in findings if f.rule_id == "ATH-011"]
    assert len(ath011) == 1

    gt = load_ground_truth(data_dir)
    labelled = set(gt["scenarios"]["ransomware_prep"]["event_ids"])
    assert set(ath011[0].event_ids) <= labelled


def test_multiple_controls_escalate_to_critical(findings) -> None:
    """Two independent recovery paths destroyed is a sequence, not an admin action."""
    ath011 = next(f for f in findings if f.rule_id == "ATH-011")
    assert ath011.metadata["distinct_controls_affected"] >= 2
    assert ath011.severity is Severity.CRITICAL


def test_a_single_control_stays_high(telemetry) -> None:
    detector = get_detector("ATH-011")
    produced = detector.run(_one_process(
        telemetry, "vssadmin.exe delete shadows /all /quiet", "vssadmin.exe",
    ))
    assert len(produced) == 1
    assert produced[0].severity is Severity.HIGH


def test_enumeration_produces_no_finding(telemetry) -> None:
    """`vssadmin list shadows` is a backup administrator checking their backups.

    The dataset contains this deliberately, on a different host from the attack. A rule
    keying on the binary name would fire on it.
    """
    detector = get_detector("ATH-011")
    assert not detector.run(_one_process(
        telemetry, "vssadmin.exe list shadows", "vssadmin.exe",
    ))
    assert not detector.run(_one_process(
        telemetry, "wbadmin.exe get versions", "wbadmin.exe",
    ))


def test_renamed_binary_still_fires(telemetry) -> None:
    """The image name is the one part an attacker changes for free.

    `svc-helper.exe delete shadows /all` destroys exactly as much as the real thing,
    because the arguments are what the operating system acts on.
    """
    detector = get_detector("ATH-011")
    produced = detector.run(_one_process(
        telemetry, "svc-helper.exe delete shadows /all /quiet", "svc-helper.exe",
    ))
    assert len(produced) == 1


def test_the_benign_admin_is_not_flagged(findings) -> None:
    """The whole dataset, not a synthetic fixture: klarsen must not appear."""
    flagged_users = {f.user for f in findings if f.rule_id == "ATH-011"}
    assert "klarsen" not in flagged_users


def test_recovery_inhibition_maps_to_t1490(findings) -> None:
    ath011 = next(f for f in findings if f.rule_id == "ATH-011")
    assert {m.technique_id for m in map_finding(ath011)} == {"T1490"}


# ======================================================================================
# ATH-012 -- security tool tampering
# ======================================================================================


def test_security_tampering_fires_on_the_labelled_scenario(findings, data_dir) -> None:
    ath012 = [f for f in findings if f.rule_id == "ATH-012"]
    assert len(ath012) == 1

    gt = load_ground_truth(data_dir)
    labelled = set(gt["scenarios"]["ransomware_prep"]["event_ids"])
    assert set(ath012[0].event_ids) <= labelled


def test_three_controls_escalate_to_critical(findings) -> None:
    ath012 = next(f for f in findings if f.rule_id == "ATH-012")
    assert ath012.metadata["distinct_controls_affected"] >= 3
    assert ath012.severity is Severity.CRITICAL


def test_a_single_change_stays_high(telemetry) -> None:
    """One exclusion is genuinely ambiguous -- administrators add them daily."""
    detector = get_detector("ATH-012")
    produced = detector.run(_one_process(
        telemetry, r"powershell.exe Add-MpPreference -ExclusionPath C:\App",
        "powershell.exe",
    ))
    assert len(produced) == 1
    assert produced[0].severity is Severity.HIGH


def test_renamed_taskkill_still_fires(telemetry) -> None:
    """The target is the signal, not the utility used to reach it."""
    detector = get_detector("ATH-012")
    produced = detector.run(_one_process(
        telemetry, "kill-helper.exe /F /IM MsMpEng.exe", "kill-helper.exe",
    ))
    assert len(produced) == 1


def test_killing_an_ordinary_process_is_not_flagged(telemetry) -> None:
    """`taskkill` against a hung application is routine support work."""
    detector = get_detector("ATH-012")
    assert not detector.run(_one_process(
        telemetry, "taskkill.exe /F /IM EXCEL.EXE", "taskkill.exe",
    ))


def test_security_tampering_maps_to_t1685_at_parent_level(findings) -> None:
    """T1685's sub-techniques are all log-specific; this evidence is not about logs."""
    ath012 = next(f for f in findings if f.rule_id == "ATH-012")
    techniques = {m.technique_id for m in map_finding(ath012)}
    assert techniques == {"T1685"}
    assert not any(t.startswith("T1685.") for t in techniques)


def test_neither_rule_maps_to_the_retired_technique(findings) -> None:
    for finding in findings:
        for mapping in map_finding(finding):
            assert not mapping.technique_id.startswith("T1562")


# ======================================================================================
# Rule hygiene
# ======================================================================================


@pytest.mark.parametrize("rule_id", ["ATH-011", "ATH-012"])
def test_new_rules_declare_their_caveats(rule_id: str) -> None:
    """Undeclared false positives would let the caveat vanish before the report."""
    detector = get_detector(rule_id)
    assert detector.fields_used
    assert len(detector.false_positives) >= 3
    assert detector.description


@pytest.mark.parametrize("rule_id", ["ATH-011", "ATH-012"])
def test_new_rules_are_quiet_on_the_quiet_day(rule_id: str, data_dir) -> None:
    """Neither may fire once the attack is removed from the same background."""
    from ath.evaluation.suite import quiet_day

    detector = get_detector(rule_id)
    assert not detector.run(quiet_day(data_dir).telemetry)
