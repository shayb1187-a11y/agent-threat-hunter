"""Tests for ATH-009 and ATH-010: the two rules promoted from the detection-engineering
loop (Milestone 6).

Structured identically to the rest of ``tests/test_hunting.py`` -- a true-positive test
and a false-positive test per rule -- because these are now permanent, registered
detections and must meet the same bar as the original eight. What is different about
this pair specifically is that their false-positive tests assert against the *exact*
row counts the engineering harness measured for the rejected v1 candidates, so a
silent regression toward v1's behaviour (e.g. someone "simplifying" the rule by
dropping the extension check) is caught immediately.
"""

from __future__ import annotations

import pandas as pd
import pytest

from ath.hunting import Severity, get_detector, run_hunt
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import load_ground_truth, load_telemetry


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory):
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("promoted_data")
    write_telemetry(tables, gt, out)
    return out


@pytest.fixture(scope="module")
def telemetry(data_dir):
    return load_telemetry(data_dir)


@pytest.fixture(scope="module")
def ground_truth(data_dir):
    return load_ground_truth(data_dir)


@pytest.fixture(scope="module")
def hunt(telemetry):
    return run_hunt(telemetry)


def stage_ids(ground_truth: dict, stage: str) -> set[str]:
    return set(ground_truth["scenarios"]["intrusion"]["stages"][stage]["event_ids"])


# ======================================================================================
# ATH-009 -- Macro-enabled document opened via email client
# ======================================================================================


def test_ath009_detects_the_macro_attachment(hunt, ground_truth) -> None:
    findings = hunt.by_rule("ATH-009")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.device == "PC01"
    assert set(finding.event_ids) == stage_ids(ground_truth, "1-initial-access")
    assert ".docm" in finding.metadata["command_line"].lower()


def test_ath009_ignores_ordinary_docx_attachments(telemetry) -> None:
    """The exact false positive the v1 candidate produced -- Notes.docx via Outlook --
    must NOT fire on the promoted rule. This is the regression this test exists to
    catch: v1 had 0.03 precision precisely because it lacked this check."""
    procs = telemetry.processes
    ordinary_opens = procs[
        (procs["parent_process_name"].str.lower() == "outlook.exe")
        & (procs["process_name"] == "WINWORD.EXE")
        & procs["command_line"].str.contains(".docx", case=False, na=False)
    ]
    assert len(ordinary_opens) > 5, "benign dataset should contain several Notes.docx opens"

    findings = get_detector("ATH-009").run(telemetry)
    assert len(findings) == 1
    flagged_ids = {eid for f in findings for eid in f.event_ids}
    assert not flagged_ids & set(ordinary_opens["event_id"])


def test_ath009_requires_macro_capable_extension(telemetry) -> None:
    """A synthetic .docx open with an otherwise identical parent/child shape must not
    fire, proving the gate is the extension, not merely 'Outlook opened Word'."""
    from ath.hunting.rules.initial_access_rules import OfficeMacroAttachmentOpened

    procs = telemetry.processes.copy()
    fake = procs[
        (procs["parent_process_name"].str.lower() == "outlook.exe")
        & (procs["process_name"] == "WINWORD.EXE")
    ].iloc[[0]].copy()
    fake["event_id"] = "evt-999901"
    fake["command_line"] = r'"...\WINWORD.EXE" /n "C:\Users\test\Documents\report.docx"'
    augmented = type(telemetry)(
        processes=pd.concat([procs, fake], ignore_index=True),
        network=telemetry.network, logons=telemetry.logons,
    )
    findings = OfficeMacroAttachmentOpened().run(augmented)
    assert "evt-999901" not in {eid for f in findings for eid in f.event_ids}


def test_ath009_severity_and_declared_metadata() -> None:
    detector = get_detector("ATH-009")
    assert detector.severity is Severity.MEDIUM
    assert detector.false_positives
    assert "command_line" in detector.fields_used


# ======================================================================================
# ATH-010 -- Sequence of discovery commands from one parent process
# ======================================================================================


def test_ath010_detects_the_discovery_sequence(hunt, ground_truth) -> None:
    findings = hunt.by_rule("ATH-010")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.device == "PC01"
    assert set(finding.event_ids) == stage_ids(ground_truth, "5-discovery")
    assert set(finding.metadata["matched_binaries"]) == {"whoami.exe", "net.exe", "nltest.exe"}


def test_ath010_maps_to_all_three_expected_techniques(hunt) -> None:
    finding = hunt.by_rule("ATH-010")[0]
    assert set(finding.metadata["candidate_techniques"]) == {"T1033", "T1069.002", "T1482"}


def test_ath010_ignores_single_ipconfig_calls(telemetry) -> None:
    """The exact false positive the v1 candidate produced -- lone ipconfig calls --
    must NOT fire on the promoted rule (a single binary can never reach the
    >=2-distinct-binaries threshold)."""
    procs = telemetry.processes
    ipconfig_calls = procs[procs["command_line"].str.contains("ipconfig", case=False, na=False)]
    assert len(ipconfig_calls) > 3, "benign dataset should contain several ipconfig calls"

    findings = get_detector("ATH-010").run(telemetry)
    flagged_ids = {eid for f in findings for eid in f.event_ids}
    assert not flagged_ids & set(ipconfig_calls["event_id"])


def test_ath010_ignores_single_whoami_from_a_different_parent(telemetry) -> None:
    """A lone whoami.exe run by cmd.exe elsewhere must not fire -- only a SEQUENCE of
    distinct binaries sharing a parent qualifies."""
    from ath.hunting.rules.discovery_rules import DiscoveryCommandSequence

    procs = telemetry.processes.copy()
    fake = procs.iloc[[0]].copy()
    fake["event_id"] = "evt-999902"
    fake["device"] = "PC02"
    fake["process_name"] = "whoami.exe"
    fake["parent_process_name"] = "cmd.exe"
    fake["parent_process_id"] = 88888
    fake["command_line"] = "whoami.exe /all"
    augmented = type(telemetry)(
        processes=pd.concat([procs, fake], ignore_index=True),
        network=telemetry.network, logons=telemetry.logons,
    )
    findings = DiscoveryCommandSequence().run(augmented)
    assert "evt-999902" not in {eid for f in findings for eid in f.event_ids}


def test_ath010_requires_binaries_within_the_time_window(telemetry) -> None:
    """Two distinct binaries from the same parent but far apart in time must not
    correlate into one finding -- the window bounds what counts as 'a sequence'."""
    from datetime import timedelta

    from ath.hunting.rules.discovery_rules import DiscoveryCommandSequence

    procs = telemetry.processes.copy()
    base = procs[procs["process_name"] == "whoami.exe"].iloc[0]
    far_apart = pd.DataFrame([
        {**base.to_dict(), "event_id": "evt-999903", "process_name": "whoami.exe",
         "parent_process_id": 77777, "timestamp": base["timestamp"]},
        {**base.to_dict(), "event_id": "evt-999904", "process_name": "net.exe",
         "parent_process_id": 77777,
         "timestamp": base["timestamp"] + timedelta(hours=2)},
    ])
    augmented = type(telemetry)(
        processes=pd.concat([procs, far_apart], ignore_index=True),
        network=telemetry.network, logons=telemetry.logons,
    )
    findings = DiscoveryCommandSequence().run(augmented)
    flagged = {eid for f in findings for eid in f.event_ids}
    assert not ({"evt-999903", "evt-999904"} <= flagged)


def test_ath010_severity_and_declared_metadata() -> None:
    detector = get_detector("ATH-010")
    assert detector.severity is Severity.MEDIUM
    assert detector.false_positives
    assert "parent_process_id" in detector.fields_used


# ======================================================================================
# Both rules integrate cleanly with the rest of the pipeline
# ======================================================================================


def test_both_promoted_rules_have_kql_files() -> None:
    from pathlib import Path

    queries = Path(__file__).resolve().parents[1] / "queries"
    assert list(queries.glob("ATH-009-*.kql"))
    assert list(queries.glob("ATH-010-*.kql"))


def test_both_promoted_rules_declare_evaluation_coverage() -> None:
    from ath.evaluation import RULE_COVERAGE

    assert RULE_COVERAGE["ATH-009"] == frozenset({"1-initial-access"})
    assert RULE_COVERAGE["ATH-010"] == frozenset({"5-discovery"})
