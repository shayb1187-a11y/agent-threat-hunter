"""Tests for the deterministic correlation layer.

The tests come in matched pairs: for every "related things group" test there is an
"unrelated things stay apart" test. A correlator that only passes the first half is
indistinguishable from one that puts everything in a single case.
"""

from __future__ import annotations

from datetime import timedelta

import pandas as pd
import pytest

from ath.correlation import CorrelationConfig, InvestigationCase, correlate
from ath.correlation.correlator import _ProcessIndex, score_pair
from ath.hunting import Evidence, Finding, Severity, run_hunt
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import load_ground_truth, load_telemetry


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory):
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("corr_data")
    write_telemetry(tables, gt, out)
    return out


@pytest.fixture(scope="module")
def telemetry(data_dir):
    return load_telemetry(data_dir)


@pytest.fixture(scope="module")
def findings(telemetry):
    return run_hunt(telemetry).findings


@pytest.fixture(scope="module")
def cases(findings, telemetry):
    return correlate(findings, telemetry)


@pytest.fixture(scope="module")
def intrusion_case(cases) -> InvestigationCase:
    return max(cases, key=lambda c: len(c.findings))


def _mk(
    rule_id: str, device: str, user: str, minute: int, event_id: str, **metadata
) -> Finding:
    ts = pd.Timestamp("2026-08-17 09:00", tz="UTC") + timedelta(minutes=minute)
    return Finding(
        rule_id=rule_id, title="t", severity=Severity.HIGH, device=device, user=user,
        evidence=(Evidence(event_id, ts, "s"),), reason="r", metadata=metadata,
    )


# ======================================================================================
# Related findings correlate
# ======================================================================================


def test_the_intrusion_forms_a_single_case(intrusion_case, data_dir) -> None:
    """11 findings: the original 9 plus ATH-009/ATH-010, promoted by the Milestone 6
    detection-engineering loop, which correlate into the SAME case because their
    evidence shares process lineage/host with the rest of the chain."""
    gt = load_ground_truth(data_dir)
    attack_ids = set(gt["scenarios"]["intrusion"]["event_ids"])
    assert len(intrusion_case.findings) == 11
    assert set(intrusion_case.event_ids) <= attack_ids


def test_case_spans_both_hosts_of_the_intrusion(intrusion_case) -> None:
    assert intrusion_case.devices == ("FS02", "PC01")
    assert intrusion_case.is_multi_host
    assert set(intrusion_case.users) == {"jdoe", "svc_backup"}


def test_case_contains_the_expected_rule_sequence(intrusion_case) -> None:
    assert intrusion_case.rule_ids == (
        "ATH-001", "ATH-002", "ATH-003", "ATH-004", "ATH-005",
        "ATH-006", "ATH-007", "ATH-008", "ATH-009", "ATH-010",
    )


# ======================================================================================
# Unrelated findings do NOT correlate
# ======================================================================================


def test_benign_lookalike_forms_its_own_case(cases, data_dir) -> None:
    """The two admin false positives must not be absorbed into the intrusion."""
    gt = load_ground_truth(data_dir)
    benign_ids = set(gt["scenarios"]["benign_lookalike"]["event_ids"])
    attack_ids = set(gt["scenarios"]["intrusion"]["event_ids"])

    benign_cases = [c for c in cases if set(c.event_ids) & benign_ids]
    assert len(benign_cases) == 1
    case = benign_cases[0]
    assert case.devices == ("PC07",)
    assert set(case.event_ids) & attack_ids == set(), "benign activity leaked into the attack"


def test_no_case_mixes_the_two_scenarios(cases, data_dir) -> None:
    gt = load_ground_truth(data_dir)
    attack_ids = set(gt["scenarios"]["intrusion"]["event_ids"])
    benign_ids = set(gt["scenarios"]["benign_lookalike"]["event_ids"])
    for case in cases:
        events = set(case.event_ids)
        assert not (events & attack_ids and events & benign_ids), case.case_id


def test_circumstantial_signals_alone_do_not_link(telemetry) -> None:
    """Same host + same user + close in time = 6 points, and must still be REFUSED.

    This is the naive-correlation guard. On one workstation those three facts are true
    of nearly every pair of alerts.
    """
    index = _ProcessIndex(telemetry)
    config = CorrelationConfig()
    a = _mk("ATH-001", "PC01", "jdoe", 0, "evt-A")
    b = _mk("ATH-008", "PC01", "jdoe", 2, "evt-B")

    score, signals, structural = score_pair(a, b, index, config)
    assert score >= config.min_score, "should clear the score bar"
    assert not structural, "but must have no structural signal"

    # They must not be MERGED. Each is severe enough to be raised on its own now, so
    # the claim under test is separation, not silence -- asserting emptiness here would
    # pass for the wrong reason once singletons became investigable.
    cases = correlate([a, b], telemetry, config)
    assert len(cases) == 2
    assert all(case.is_singleton for case in cases)


def test_disabling_the_structural_requirement_reproduces_naive_grouping(telemetry) -> None:
    """Demonstrates exactly what the guard prevents."""
    a = _mk("ATH-001", "PC01", "jdoe", 0, "evt-A")
    b = _mk("ATH-008", "PC01", "jdoe", 2, "evt-B")
    naive = CorrelationConfig(require_structural=False)
    assert len(correlate([a, b], telemetry, naive)) == 1


def test_findings_beyond_max_gap_never_link(telemetry) -> None:
    """Strong circumstantial overlap must not survive a 10-hour gap."""
    a = _mk("ATH-004", "PC01", "jdoe", 0, "evt-A")
    b = _mk("ATH-007", "PC01", "jdoe", 600, "evt-B")
    cases = correlate([a, b], telemetry, CorrelationConfig())
    assert len(cases) == 2, "a 10-hour gap must not produce one merged case"
    assert all(case.is_singleton for case in cases)


def test_duplicate_finding_ids_raise(telemetry) -> None:
    """A key collision would merge findings with no link recorded -- fail loudly."""
    a = _mk("ATH-002", "PC01", "jdoe", 0, "evt-DUP")
    b = _mk("ATH-002", "FS02", "svc_backup", 5, "evt-DUP")
    with pytest.raises(ValueError, match="Duplicate finding_id"):
        correlate([a, b], telemetry, CorrelationConfig())


def test_lone_severe_finding_is_raised_for_investigation(telemetry) -> None:
    """A single CRITICAL detection must still reach the investigation layer.

    Isolated findings used to be dropped, on the reasoning that "one alert is an alert,
    not a chain". True about naming, wrong about consequences: investigation only ever
    runs on cases, so a lone severe detection produced no investigation at all. That was
    measured as INC-002 in the incident benchmark -- a cloud credential-stuffing attack
    detected, then zero facts and zero tool calls.
    """
    lone = _mk("ATH-004", "PC99", "nobody", 0, "evt-Z")
    cases = correlate([lone], telemetry, CorrelationConfig())
    assert len(cases) == 1
    assert cases[0].is_singleton


def test_lone_severe_case_does_not_claim_corroboration(telemetry) -> None:
    """A singleton must not borrow the credibility of a chain.

    Nothing was corroborated, so grouping confidence is `low` regardless of how many
    tactics the finding's own ATT&CK mappings span -- otherwise one rule's mappings
    would masquerade as independent agreement.
    """
    lone = _mk("ATH-004", "PC99", "nobody", 0, "evt-Z")
    case = correlate([lone], telemetry, CorrelationConfig())[0]
    assert case.confidence == "low"
    assert "correlated with no other activity" in case.explain()
    assert "nothing here corroborates it" in case.explain()


def test_lone_low_severity_finding_stays_an_alert(telemetry) -> None:
    """The guard against reopening "every finding is a case".

    Below the singleton threshold an isolated finding is not promoted, so the
    triage-reduction metric keeps meaning something.
    """
    quiet = Finding(
        rule_id="ATH-002", title="t", severity=Severity.LOW, device="PC99",
        user="nobody",
        evidence=(Evidence("evt-Y", pd.Timestamp("2026-08-17 09:00", tz="UTC"), "s"),),
        reason="r",
    )
    assert correlate([quiet], telemetry, CorrelationConfig()) == []


def test_no_findings_yields_no_cases(telemetry) -> None:
    assert correlate([], telemetry) == []


# ======================================================================================
# Individual signals
# ======================================================================================


def test_shared_evidence_is_structural(telemetry) -> None:
    index = _ProcessIndex(telemetry)
    a = _mk("ATH-001", "PC01", "jdoe", 0, "evt-SAME")
    b = _mk("ATH-002", "PC01", "jdoe", 0, "evt-SAME")
    _, signals, structural = score_pair(a, b, index, CorrelationConfig())
    assert structural
    assert any(s.startswith("shared_evidence") for s in signals)


def test_host_movement_signal_requires_an_auth_relationship(telemetry) -> None:
    index = _ProcessIndex(telemetry)
    on_pc01 = _mk("ATH-004", "PC01", "jdoe", 0, "evt-A")
    moved = _mk("ATH-006", "FS02", "svc_backup", 5, "evt-B", source_device="PC01")
    _, signals, structural = score_pair(on_pc01, moved, index, CorrelationConfig())
    assert structural
    assert any(s.startswith("host_movement") for s in signals)

    # Two hosts with no authentication relationship must NOT produce the signal.
    unrelated = _mk("ATH-004", "PC02", "mrossi", 5, "evt-C")
    _, signals2, structural2 = score_pair(on_pc01, unrelated, index, CorrelationConfig())
    assert not any(s.startswith("host_movement") for s in signals2)
    assert not structural2


def test_auth_then_exec_links_logon_to_remote_execution(telemetry) -> None:
    index = _ProcessIndex(telemetry)
    auth = _mk("ATH-006", "FS02", "svc_backup", 0, "evt-A")
    execution = _mk("ATH-007", "FS02", "svc_backup", 1, "evt-B")
    _, signals, structural = score_pair(auth, execution, index, CorrelationConfig())
    assert structural
    assert any(s.startswith("auth_then_exec") for s in signals)


def test_auth_then_exec_respects_its_window(telemetry) -> None:
    index = _ProcessIndex(telemetry)
    auth = _mk("ATH-006", "FS02", "svc_backup", 0, "evt-A")
    much_later = _mk("ATH-007", "FS02", "svc_backup", 45, "evt-B")
    _, signals, _ = score_pair(auth, much_later, index, CorrelationConfig())
    assert not any(s.startswith("auth_then_exec") for s in signals)


def test_same_process_signal_links_execution_to_its_own_traffic(findings, telemetry) -> None:
    """ATH-002 (PowerShell PID 6612) and ATH-003 (traffic from PID 6612)."""
    index = _ProcessIndex(telemetry)
    ps = [f for f in findings if f.rule_id == "ATH-002" and f.device == "PC01"][0]
    net = [f for f in findings if f.rule_id == "ATH-003" and f.device == "PC01"][0]
    _, signals, structural = score_pair(ps, net, index, CorrelationConfig())
    assert structural
    assert any(s.startswith("same_process") for s in signals)


def test_process_lineage_signal(findings, telemetry) -> None:
    """ATH-004's rundll32 has ATH-002's PowerShell as its parent."""
    index = _ProcessIndex(telemetry)
    ps = [f for f in findings if f.rule_id == "ATH-002" and f.device == "PC01"][0]
    dump = [f for f in findings if f.rule_id == "ATH-004"][0]
    _, signals, _ = score_pair(ps, dump, index, CorrelationConfig())
    assert any(s.startswith("process_lineage") for s in signals)


# ======================================================================================
# Structural guarantees of the case object
# ======================================================================================


def test_timeline_is_chronological(cases) -> None:
    for case in cases:
        stamps = [e.timestamp for e in case.timeline()]
        assert stamps == sorted(stamps), case.case_id


def test_cases_are_ordered_and_numbered_by_start_time(cases) -> None:
    assert [c.case_id for c in cases] == [f"CASE-{i:03d}" for i in range(1, len(cases) + 1)]
    starts = [c.start_time for c in cases]
    assert starts == sorted(starts)


def test_event_ids_survive_correlation(cases, findings) -> None:
    """No evidence may be lost or invented on the way into a case."""
    for case in cases:
        expected = {eid for f in case.findings for eid in f.event_ids}
        assert set(case.event_ids) == expected


def test_no_finding_is_fabricated(cases, findings) -> None:
    """Every finding in a case must be one the hunt actually produced."""
    real = {f.finding_id for f in findings}
    for case in cases:
        assert {f.finding_id for f in case.findings} <= real


def test_every_finding_is_either_cased_or_isolated(cases, findings) -> None:
    """No finding may appear in two cases -- components are disjoint."""
    seen: list[str] = []
    for case in cases:
        seen.extend(f.finding_id for f in case.findings)
    assert len(seen) == len(set(seen))
    assert set(seen) <= {f.finding_id for f in findings}


def test_all_links_are_within_the_case(cases) -> None:
    for case in cases:
        member_ids = {f.finding_id for f in case.findings}
        for link in case.links:
            assert link.left_id in member_ids and link.right_id in member_ids


def test_cross_device_movement_is_represented(intrusion_case) -> None:
    movements = [e.movement for e in intrusion_case.timeline() if e.movement]
    assert "PC01 -> FS02" in movements


def test_case_severity_inherits_the_worst_finding(intrusion_case) -> None:
    assert intrusion_case.severity is Severity.CRITICAL


def test_case_confidence_reflects_tactic_breadth(cases, intrusion_case) -> None:
    assert intrusion_case.confidence == "high"
    benign = [c for c in cases if c is not intrusion_case][0]
    assert benign.confidence in ("low", "medium")


def test_case_carries_attack_mappings(intrusion_case) -> None:
    assert "T1003.001" in intrusion_case.techniques
    assert "Credential Access" in intrusion_case.tactics
    assert "Lateral Movement" in intrusion_case.tactics


def test_explanation_is_hedged_not_conclusive(intrusion_case) -> None:
    """Deterministic output must not assert that an intrusion occurred."""
    text = intrusion_case.explain().lower()
    assert "requires analyst confirmation" in text
    assert "consistent with" in text
    for overclaim in ("attacker", "malicious", "compromised", "breach"):
        assert overclaim not in text


def test_case_serialises_to_json(cases) -> None:
    import json

    for case in cases:
        payload = json.loads(json.dumps(case.to_dict()))
        assert payload["case_id"] and payload["timeline"]
        assert payload["event_ids"]


def test_correlation_is_deterministic(findings, telemetry) -> None:
    a = correlate(findings, telemetry)
    b = correlate(findings, telemetry)
    assert [c.to_dict() for c in a] == [c.to_dict() for c in b]
