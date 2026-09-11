"""Tests for ``sibling_lineage`` -- linking findings that share a parent process.

The gap this closes
-------------------
``process_lineage`` asserts that a process in one finding *is* the parent of a process
in the other. That covers a chain but not a fan: two findings whose processes were both
started by a third process which is itself no finding at all. INC-004 is exactly that
shape -- recovery inhibition and security-tool tampering are siblings under one
``cmd.exe`` -- and it measured a chain recall of 50%, with the two halves of one
operator's session sitting in two separate cases.

Why most of this file is negative tests
---------------------------------------
"Same parent process" is a dangerous relation to add naively, because on a workstation
``explorer.exe`` is the parent of everything the user runs all day. A correlator that
linked on shared parentage alone would merge a morning of unrelated alerts and present
it as an attack chain -- which is worse than the fragmentation it set out to fix, since
it manufactures a story rather than merely failing to tell one.

So the relation is gated by two properties measured off the telemetry -- a parent's
fan-out and the span over which it started its children -- and the tests below spend
most of their effort proving that gate holds rather than proving the link works.

No test here names a rule id as a reason to correlate, and neither does the
implementation: :func:`test_the_relation_is_indifferent_to_rule_identity` runs the same
telemetry under invented rule ids and requires the same outcome.
"""

from __future__ import annotations

from datetime import timedelta

import pandas as pd
import pytest

from ath.correlation import CorrelationConfig, correlate
from ath.correlation.correlator import _ProcessIndex, score_pair
from ath.evaluation.incidents import run_incident
from ath.evaluation.suite import quiet_day, ransomware_preparation, windows_intrusion
from ath.hunting import Evidence, Finding, Severity, run_hunt
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import Telemetry, load_ground_truth, load_telemetry

# Disables the sibling relation without touching any other behaviour: every observed
# parent has at least one child, so a bound of zero admits none of them. Used to measure
# what the relation changed, rather than asserting it changed nothing.
NO_SIBLINGS = CorrelationConfig(max_session_fan_out=0)

BASE = pd.Timestamp("2026-08-17 09:00", tz="UTC")


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory):
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("sibling_data")
    write_telemetry(tables, gt, out)
    return out


@pytest.fixture(scope="module")
def telemetry(data_dir):
    return load_telemetry(data_dir)


# ======================================================================================
# Synthetic scaffolding
#
# Built by hand rather than generated, because these tests are about process-tree shapes
# the generator does not produce -- a parent with twenty children, a parent whose
# children span three hours -- and the shape is the thing under test.
# ======================================================================================


def _telemetry(rows, empty_like: Telemetry) -> Telemetry:
    """``rows`` are ``(event_id, second_offset, pid, ppid, device)`` tuples."""
    frame = pd.DataFrame(
        [
            {
                "event_id": event_id,
                "timestamp": BASE + timedelta(seconds=offset),
                "event_type": "process",
                "device": device,
                "user": "operator",
                "process_name": f"p{pid}.exe",
                "process_id": pid,
                "parent_process_id": ppid,
                "parent_process_name": "shell.exe",
                "command_line": f"p{pid}.exe",
            }
            for event_id, offset, pid, ppid, device in rows
        ]
    )
    return Telemetry(
        processes=frame,
        network=empty_like.network.iloc[0:0],
        logons=empty_like.logons.iloc[0:0],
    )


def _finding(rule_id: str, event_id: str, offset: int, device="PC09", user="operator"):
    ts = BASE + timedelta(seconds=offset)
    return Finding(
        rule_id=rule_id,
        title="t",
        severity=Severity.MEDIUM,
        device=device,
        user=user,
        evidence=(Evidence(event_id, ts, "s"),),
        reason="r",
    )


def _signals(a, b, telemetry, config=None) -> list[str]:
    """Bare signal names for a pair, e.g. ``["sibling_lineage", "same_device"]``."""
    config = config or CorrelationConfig()
    _, signals, _ = score_pair(a, b, _ProcessIndex(telemetry), config)
    return [s.split("(")[0] for s in signals]


def _linked(a, b, telemetry, config=None) -> bool:
    config = config or CorrelationConfig()
    return len(correlate([a, b], telemetry, config)) == 1


# ======================================================================================
# The regression: the exact INC-004 failure
# ======================================================================================


def test_inc_004_recovery_and_tampering_reach_one_case(data_dir) -> None:
    """The measured failure, pinned at the level it was measured.

    Both findings are children of one ``cmd.exe`` that is itself no finding, so no
    parent/child relationship exists *between the findings* and the chain broke in half.
    """
    incident = ransomware_preparation(data_dir)
    findings = run_hunt(incident.telemetry).findings
    cases = correlate(findings, incident.telemetry)

    holding = [case for case in cases if {"ATH-011", "ATH-012"} <= set(case.rule_ids)]
    assert len(holding) == 1, "recovery inhibition and tampering are still in two cases"

    link = next(
        link
        for link in holding[0].links
        if any(s.startswith("sibling_lineage") for s in link.signals)
    )
    assert not any(s.startswith("process_lineage") for s in link.signals), (
        "if process_lineage now fires, this test is no longer exercising the fan case"
    )


def test_inc_004_chain_recall_is_complete(data_dir) -> None:
    """50% before this relation existed.

    Purity is asserted alongside deliberately: a recall of 1.0 is trivially reachable
    by merging everything into one case, and would be a worse system, not a better one.
    """
    outcome = run_incident(ransomware_preparation(data_dir))
    assert outcome.primary_case_recall == 1.0
    assert outcome.primary_case_purity == 1.0


def test_inc_004_was_genuinely_broken_before(data_dir) -> None:
    """Guards the guard: without the relation the failure must still reproduce.

    If this stops failing, something else began linking the two findings, and the test
    above would keep passing for a reason that has nothing to do with siblings.
    """
    incident = ransomware_preparation(data_dir)
    findings = run_hunt(incident.telemetry).findings
    cases = correlate(findings, incident.telemetry, NO_SIBLINGS)
    assert not [c for c in cases if {"ATH-011", "ATH-012"} <= set(c.rule_ids)]


# ======================================================================================
# Generalisation -- the relation is about shape, not about these two rules
# ======================================================================================


@pytest.mark.parametrize(
    "left_rule,right_rule",
    [
        ("ATH-011", "ATH-012"),  # the pair that motivated the work
        ("ATH-002", "ATH-008"),  # two unrelated existing rules
        ("ZZZ-999", "QQQ-001"),  # rule ids this codebase has never heard of
    ],
)
def test_the_relation_is_indifferent_to_rule_identity(
    left_rule, right_rule, telemetry
) -> None:
    """Identical telemetry, different rule ids, identical outcome.

    This is the property that separates a correlation rule from a special case. A
    hardcoded ``if ATH-011 and ATH-012`` would pass the first row and fail the third.
    """
    data = _telemetry(
        [
            ("e1", 0, 100, 4242, "PC09"),
            ("e2", 60, 101, 4242, "PC09"),
            ("e3", 90, 102, 4242, "PC09"),
        ],
        telemetry,
    )
    a = _finding(left_rule, "e1", 0)
    b = _finding(right_rule, "e2", 60)
    assert "sibling_lineage" in _signals(a, b, data)
    assert _linked(a, b, data)


def test_siblings_link_across_different_binaries(telemetry) -> None:
    """The children are ``p100.exe`` and ``p101.exe`` -- names carrying no meaning.

    Nothing in the relation inspects what was run, only who started it and when.
    """
    data = _telemetry(
        [("e1", 0, 100, 4242, "PC09"), ("e2", 30, 101, 4242, "PC09")], telemetry
    )
    assert "sibling_lineage" in _signals(
        _finding("R-1", "e1", 0), _finding("R-2", "e2", 30), data
    )


# ======================================================================================
# The gate: parents that are launchers, not sessions
# ======================================================================================


def test_a_parent_that_spawns_all_morning_is_not_a_session(telemetry) -> None:
    """The desktop-shell shape, and the one the generated dataset actually contains.

    ``PC05/631`` starts OUTLOOK, WINWORD, chrome and powershell across two and three
    quarter hours. Its fan-out is only 4, so a fan-out bound alone would have admitted
    it; the span is what rules it out. Two findings *two minutes apart* under such a
    parent must not be called siblings -- their own proximity says nothing about the
    parent being a single session.
    """
    data = _telemetry(
        [
            ("e1", 0, 100, 4242, "PC09"),
            ("e2", 120, 101, 4242, "PC09"),
            ("e3", 3 * 3600, 102, 4242, "PC09"),  # same parent, three hours later
        ],
        telemetry,
    )
    a, b = _finding("R-1", "e1", 0), _finding("R-2", "e2", 120)
    assert "sibling_lineage" not in _signals(a, b, data)
    assert not _linked(a, b, data)


def test_a_parent_with_a_large_fan_out_is_not_a_session(telemetry) -> None:
    """An installer or service host: many children, all within a minute.

    The span bound cannot catch this one, which is why the fan-out bound exists. Marked
    honestly: the generated dataset's largest fan-out is 6, so that bound is never the
    binding constraint there, and this synthetic case is the only thing exercising it.
    """
    rows = [("e1", 0, 100, 4242, "PC09"), ("e2", 30, 101, 4242, "PC09")]
    rows += [(f"x{n}", n, 200 + n, 4242, "PC09") for n in range(20)]
    data = _telemetry(rows, telemetry)
    a, b = _finding("R-1", "e1", 0), _finding("R-2", "e2", 30)

    fan_out = _ProcessIndex(data).fan_out(("PC09", 4242))
    assert fan_out > CorrelationConfig().max_session_fan_out
    assert "sibling_lineage" not in _signals(a, b, data)
    assert not _linked(a, b, data)


# ======================================================================================
# The gate: things that are not siblings at all
# ======================================================================================


def test_different_parents_are_not_siblings(telemetry) -> None:
    data = _telemetry(
        [("e1", 0, 100, 4242, "PC09"), ("e2", 30, 101, 5353, "PC09")], telemetry
    )
    a, b = _finding("R-1", "e1", 0), _finding("R-2", "e2", 30)
    assert "sibling_lineage" not in _signals(a, b, data)
    assert not _linked(a, b, data)


def test_the_same_parent_pid_on_two_hosts_is_a_coincidence(telemetry) -> None:
    """PID 4242 on PC09 and PID 4242 on PC10 are unrelated processes.

    The relation keys on ``(device, pid)``. Keying on the bare number would correlate
    across an entire estate every time two machines happened to reuse a pid.
    """
    data = _telemetry(
        [("e1", 0, 100, 4242, "PC09"), ("e2", 30, 101, 4242, "PC10")], telemetry
    )
    a = _finding("R-1", "e1", 0, device="PC09")
    b = _finding("R-2", "e2", 30, device="PC10")
    assert "sibling_lineage" not in _signals(a, b, data)
    assert not _linked(a, b, data)


def test_siblings_too_far_apart_are_not_linked(telemetry) -> None:
    """One qualifying session, but these two commands are half an hour apart.

    The parent still passes the session test -- its children span under the bound -- so
    this isolates the finding-to-finding window from the parent-shape tests above.
    """
    data = _telemetry(
        [("e1", 0, 100, 4242, "PC09"), ("e2", 1800, 101, 4242, "PC09")], telemetry
    )
    a, b = _finding("R-1", "e1", 0), _finding("R-2", "e2", 1800)
    assert "sibling_lineage" not in _signals(a, b, data)
    assert not _linked(a, b, data)


def test_a_refused_sibling_is_not_rescued_by_circumstance(telemetry) -> None:
    """The negative results above must not be accidents of the score falling short.

    Same host, same user, ninety seconds apart: the circumstantial signals alone reach
    6, comfortably over ``min_score`` of 5. The pair is still refused, because the
    structural requirement is what holds -- not the arithmetic. Without this assertion a
    future weight change could silently turn every test above green for the wrong
    reason.
    """
    data = _telemetry(
        [
            ("e1", 0, 100, 4242, "PC09"),
            ("e2", 90, 101, 4242, "PC09"),
            ("e3", 3 * 3600, 102, 4242, "PC09"),  # makes the parent a launcher
        ],
        telemetry,
    )
    a, b = _finding("R-1", "e1", 0), _finding("R-2", "e2", 90)
    names = _signals(a, b, data)
    score, _, structural = score_pair(a, b, _ProcessIndex(data), CorrelationConfig())

    assert set(names) == {"same_device", "same_user", "temporal_close"}
    assert score >= CorrelationConfig().min_score
    assert not structural
    assert not _linked(a, b, data)


# ======================================================================================
# Over-merging: what the relation cost on real telemetry
# ======================================================================================


def test_the_relation_never_joins_two_scenarios(data_dir, telemetry) -> None:
    """Measured over every pair of findings on the full dataset.

    This is the number that decides whether the relation was worth adding. It fires on
    three pairs, and all three join findings from the *same* ground-truth scenario -- so
    it bought INC-004's chain recall without merging anything that does not belong
    together. Were a fourth pair to appear spanning two scenarios, the relation would be
    manufacturing a chain, and this test is where that shows up.
    """
    truth = load_ground_truth(data_dir)
    label = {
        event_id: name
        for name, scenario in truth.get("scenarios", {}).items()
        for stage in scenario.get("stages", {}).values()
        for event_id in stage.get("event_ids", [])
    }

    def scenarios_of(finding):
        return {label.get(e, "benign") for e in finding.event_ids}

    findings = run_hunt(telemetry).findings
    index, config = _ProcessIndex(telemetry), CorrelationConfig()

    fired = 0
    for i, left in enumerate(findings):
        for right in findings[i + 1 :]:
            _, signals, _ = score_pair(left, right, index, config)
            if not any(s.startswith("sibling_lineage") for s in signals):
                continue
            fired += 1
            assert scenarios_of(left) == scenarios_of(right), (
                f"sibling_lineage joined {left.rule_id} and {right.rule_id} across "
                f"{scenarios_of(left)} and {scenarios_of(right)}"
            )
    assert fired == 3


def test_the_relation_merges_exactly_two_pairs(telemetry) -> None:
    """Case shapes with and without, on the whole dataset: four cases become three.

    Of the three pairs it fires on, one was already linked by shared evidence and the
    same process, so it changes nothing there. The other two each join a genuine pair. A
    relation that collapsed the dataset into one case would be caught here.
    """
    findings = run_hunt(telemetry).findings
    before = correlate(findings, telemetry, NO_SIBLINGS)
    after = correlate(findings, telemetry)

    assert sorted(len(c.findings) for c in before) == [1, 1, 2, 11]
    assert sorted(len(c.findings) for c in after) == [2, 2, 11]


def test_inc_001_is_untouched(data_dir) -> None:
    """The regression baseline. Its case structure must be identical either way."""
    incident = windows_intrusion(data_dir)
    findings = run_hunt(incident.telemetry).findings

    def shape(config):
        return sorted(
            tuple(sorted(case.rule_ids))
            for case in correlate(findings, incident.telemetry, config)
        )

    assert shape(CorrelationConfig()) == shape(NO_SIBLINGS)


def test_the_quiet_day_gains_no_residual_load(data_dir) -> None:
    """A day with no attack must not start producing analyst work.

    The two false positives it raises are on one host, minutes apart -- precisely the
    circumstances under which a careless sibling relation would join them into a larger
    and more alarming-looking case.

    The bar here tightened from one case to zero while this test was being written:
    M15-6 stopped findings that triage has already explained from raising a case at all.
    That makes the assertion stricter rather than weaker, and it is the direction the
    sibling relation could most easily undo -- linking two explained findings into a
    case is exactly the regression this guards.
    """
    outcome = run_incident(quiet_day(data_dir))
    assert outcome.cases == 0
    assert outcome.findings_after_triage == 0
    assert outcome.malicious_findings_called_benign == 0
