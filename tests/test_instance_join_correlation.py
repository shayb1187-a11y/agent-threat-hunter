"""Correlation joins on process-instance identity, and labels every fallback.

The invariant under test
------------------------
**When both sides of a process join carry an instance identity of the same scheme, the
join is by identity and nothing else. When either side lacks one, or the schemes differ,
the join falls back to ``(device, pid)`` and the result is labelled "inferred from
pid".**

Why each half matters
---------------------
The first half is the correctness half. ``(device, pid)`` names a slot the operating
system reissues, so a lineage link keyed on it can join two genuinely different runs --
and the output cannot tell you that it did. M18b-1 measured the size of this on real
telemetry: 94.8% of the ``(device, pid)`` keys COMISET's network rows used were
ambiguous, the worst covering 27 process instances.

The second half is the honesty half. Refusing every join a source cannot identify would
be *safer* and useless: this project's own generated corpus names a parent instance on 7
of 462 process rows, so a strict rule would delete almost all of its lineage. The link is
still made; what changes is that it says what it rests on.

Every test below asserts one of those two halves, and the ones marked FAILS ON HEAD fail
against the pre-M18b-2 correlator, which keyed on ``(device, pid)`` alone.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from _builders import at, net, proc, telemetry as build_telemetry
from ath.correlation import CorrelationConfig, correlate_with_stats, score_pair
from ath.correlation.correlator import _ProcessIndex
from ath.hunting import Evidence, Finding, Severity
from ath.instance_identity import INFERRED_FROM_PID, start_identity

DEVICE = "PC09"
REUSED_PID = 4444


def finding(rule_id: str, event_id: str, when, *, device: str = DEVICE,
            user: str = "operator") -> Finding:
    return Finding(
        rule_id=rule_id, title="t", severity=Severity.MEDIUM, device=device, user=user,
        evidence=(Evidence(event_id, when, "s"),), reason="r",
    )


def signals(
    a: Finding, b: Finding, data, config: CorrelationConfig | None = None,
) -> list[str]:
    """The raw signal strings for a pair, label included."""
    _, produced, _ = score_pair(a, b, _ProcessIndex(data), config or CorrelationConfig())
    return produced


def names(
    a: Finding, b: Finding, data, config: CorrelationConfig | None = None,
) -> list[str]:
    return [s.split("(")[0] for s in signals(a, b, data, config)]


def labelled(produced: list[str], name: str) -> bool:
    """Whether the named signal is present *and* declares its pid fallback."""
    return any(s.startswith(f"{name}(") and INFERRED_FROM_PID in s for s in produced)


# ======================================================================================
# False lineage: one PID, two processes
# ======================================================================================


@pytest.fixture()
def two_instances():
    """One host, one PID, two runs of it -- and a child that names its real parent.

    ``first`` is the earlier run of PID 4444. ``child`` was started by the *second* run,
    an hour later, and its ``parent_process_guid`` says so. Keyed on ``(device, pid)``
    the two are indistinguishable, which is the whole problem.
    """
    started_first = at(0)
    started_second = at(20)
    first_identity = start_identity(DEVICE, REUSED_PID, started_first)
    second_identity = start_identity(DEVICE, REUSED_PID, started_second)

    first = proc("cmd.exe", "cmd.exe /c one", "explorer.exe", device=DEVICE,
                 user="operator", when=started_first, pid=REUSED_PID, ppid=1000,
                 guid=first_identity)
    second = proc("cmd.exe", "cmd.exe /c two", "explorer.exe", device=DEVICE,
                  user="operator", when=started_second, pid=REUSED_PID, ppid=1000,
                  guid=second_identity)
    child = proc("whoami.exe", "whoami", "cmd.exe", device=DEVICE, user="operator",
                 when=at(21), pid=7777, ppid=REUSED_PID,
                 guid=start_identity(DEVICE, 7777, at(21)), parent_guid=second_identity)
    return first, second, child


def test_two_runs_of_one_pid_are_not_parent_and_child(two_instances) -> None:
    """FAILS ON HEAD: the pid join calls the first run the child's parent.

    The child was started by the *second* run and says so. Nothing links it to the
    first, and a lineage claim about the first is a claim about a different process.
    """
    first, _second, child = two_instances
    data = build_telemetry(procs=[first, _second, child])

    a = finding("R-1", first["event_id"], at(0))
    b = finding("R-2", child["event_id"], at(21))

    assert "process_lineage" not in names(a, b, data)


def test_the_real_parent_still_links_and_is_not_labelled(two_instances) -> None:
    """The other half: identity does not only refuse, it also confirms."""
    _first, second, child = two_instances
    data = build_telemetry(procs=[_first, second, child])

    a = finding("R-1", second["event_id"], at(20))
    b = finding("R-2", child["event_id"], at(21))

    produced = signals(a, b, data)
    assert "process_lineage" in [s.split("(")[0] for s in produced]
    assert not labelled(produced, "process_lineage"), (
        "both rows named the instance, so nothing here was inferred from a pid"
    )


def test_without_identities_the_same_shape_links_and_says_so(two_instances) -> None:
    """Identities stripped: the link is made, and labelled ``inferred from pid``.

    This is the corpus shape the fallback exists for -- a source that records no
    instance identifier. Refusing the join would be safe and would delete the evidence;
    making it silently is what M18b-2 removed.
    """
    first, second, child = two_instances
    blank = []
    for row in (first, second, child):
        row = dict(row)
        row["process_guid"] = ""
        row["parent_process_guid"] = ""
        blank.append(row)
    data = build_telemetry(procs=blank)

    a = finding("R-1", blank[0]["event_id"], at(0))
    b = finding("R-2", blank[2]["event_id"], at(21))

    produced = signals(a, b, data)
    assert "process_lineage" in [s.split("(")[0] for s in produced]
    assert labelled(produced, "process_lineage"), produced


def test_two_authorities_cannot_confirm_each_other(two_instances) -> None:
    """A Sysmon GUID and a creation-time key with identical id text do not join.

    They are answers from different authorities to the same question, and neither can
    check the other. So the identity comparison is refused, the join falls back to the
    pid -- and because these two rows *do* share a slot, the link is made and labelled.
    """
    shared_text = "0f0f0f0f-1111-2222-3333-444444444444"
    parent = proc("cmd.exe", "cmd.exe", "explorer.exe", device=DEVICE, user="operator",
                  when=at(0), pid=REUSED_PID, ppid=1000, guid=f"sysmon:{shared_text}")
    child = proc("whoami.exe", "whoami", "cmd.exe", device=DEVICE, user="operator",
                 when=at(1), pid=7777, ppid=REUSED_PID,
                 guid=start_identity(DEVICE, 7777, at(1)),
                 parent_guid=f"start:{shared_text}")
    data = build_telemetry(procs=[parent, child])

    a = finding("R-1", parent["event_id"], at(0))
    b = finding("R-2", child["event_id"], at(1))

    produced = signals(a, b, data)
    assert "process_lineage" in [s.split("(")[0] for s in produced]
    assert labelled(produced, "process_lineage"), (
        "a cross-authority comparison is a pid comparison and must say so"
    )


def test_two_authorities_on_different_slots_do_not_link() -> None:
    """The same cross-authority pair with nothing else in common links to nothing.

    Proves the previous test's link came from the pid fallback and not from some
    accidental agreement between two id strings.
    """
    shared_text = "0f0f0f0f-1111-2222-3333-444444444444"
    parent = proc("cmd.exe", "cmd.exe", "explorer.exe", device=DEVICE, user="operator",
                  when=at(0), pid=1234, ppid=1000, guid=f"sysmon:{shared_text}")
    child = proc("whoami.exe", "whoami", "cmd.exe", device=DEVICE, user="operator",
                 when=at(1), pid=7777, ppid=9999,
                 guid=start_identity(DEVICE, 7777, at(1)),
                 parent_guid=f"start:{shared_text}")
    data = build_telemetry(procs=[parent, child])

    a = finding("R-1", parent["event_id"], at(0))
    b = finding("R-2", child["event_id"], at(1))

    assert "process_lineage" not in names(a, b, data)


# ======================================================================================
# Siblings
# ======================================================================================


def _sibling_children(parent_identities: tuple[str, str]) -> list[dict]:
    """Two children of PID 5000, each naming the parent instance it was given."""
    return [
        proc("whoami.exe", "whoami", "cmd.exe", device=DEVICE, user="operator",
             when=at(0), pid=6001, ppid=5000,
             guid=start_identity(DEVICE, 6001, at(0)), parent_guid=parent_identities[0]),
        proc("net.exe", "net view", "cmd.exe", device=DEVICE, user="operator",
             when=at(1), pid=6002, ppid=5000,
             guid=start_identity(DEVICE, 6002, at(1)), parent_guid=parent_identities[1]),
    ]


def test_two_children_of_one_parent_instance_are_siblings() -> None:
    parent_identity = start_identity(DEVICE, 5000, at(-5))
    rows = _sibling_children((parent_identity, parent_identity))
    data = build_telemetry(procs=rows)

    a = finding("R-1", rows[0]["event_id"], at(0))
    b = finding("R-2", rows[1]["event_id"], at(1))

    produced = signals(a, b, data)
    assert "sibling_lineage" in [s.split("(")[0] for s in produced]
    assert not labelled(produced, "sibling_lineage")


def test_two_children_of_different_runs_of_one_parent_pid_are_not_siblings() -> None:
    """FAILS ON HEAD: keyed on ``(device, parent_pid)`` these two look like siblings.

    Two shells that held PID 5000 at different times are two sessions, and the sibling
    relation exists precisely to express "one session".
    """
    rows = _sibling_children(
        (start_identity(DEVICE, 5000, at(-30)), start_identity(DEVICE, 5000, at(-5)))
    )
    data = build_telemetry(procs=rows)

    a = finding("R-1", rows[0]["event_id"], at(0))
    b = finding("R-2", rows[1]["event_id"], at(1))

    assert "sibling_lineage" not in names(a, b, data)


def test_children_that_name_no_parent_instance_are_siblings_and_say_so() -> None:
    """The generated corpus's shape: a parent PID and no parent identity anywhere."""
    rows = _sibling_children(("", ""))
    data = build_telemetry(procs=rows)

    a = finding("R-1", rows[0]["event_id"], at(0))
    b = finding("R-2", rows[1]["event_id"], at(1))

    produced = signals(a, b, data)
    assert "sibling_lineage" in [s.split("(")[0] for s in produced]
    assert labelled(produced, "sibling_lineage"), produced


# ======================================================================================
# Cross-channel attribution: a connection is opened by an instance, not by a slot
# ======================================================================================


def test_a_connection_is_not_attributed_across_two_runs_of_one_pid(two_instances) -> None:
    """FAILS ON HEAD: the connection belongs to the second run, the finding to the first."""
    first, second, _child = two_instances
    connection = net("cmd.exe", "185.220.101.47", device=DEVICE, user="operator",
                     when=at(25), pid=REUSED_PID,
                     guid=start_identity(DEVICE, REUSED_PID, at(20)))
    data = build_telemetry(procs=[first, second], nets=[connection])

    a = finding("R-1", first["event_id"], at(0))
    b = finding("R-2", connection["event_id"], at(25))

    assert "same_process" not in names(a, b, data)

    opener = finding("R-3", second["event_id"], at(20))
    produced = signals(opener, b, data)
    assert "same_process" in [s.split("(")[0] for s in produced]
    assert not labelled(produced, "same_process")


def test_a_connection_with_no_identity_is_attributed_by_pid_and_labelled(
    two_instances,
) -> None:
    """Sysmon 3 without a ProcessGuid: the attribution stands, and declares itself."""
    first, _second, _child = two_instances
    connection = net("cmd.exe", "185.220.101.47", device=DEVICE, user="operator",
                     when=at(2), pid=REUSED_PID, guid="")
    data = build_telemetry(procs=[first], nets=[connection])

    a = finding("R-1", first["event_id"], at(0))
    b = finding("R-2", connection["event_id"], at(2))

    produced = signals(a, b, data)
    assert "same_process" in [s.split("(")[0] for s in produced]
    assert labelled(produced, "same_process"), produced


# ======================================================================================
# What the run reports about itself
# ======================================================================================


def test_the_run_counts_the_links_that_rested_on_a_pid(two_instances) -> None:
    """A counter, not only prose: how much of this run was slot-keyed.

    Reported for the run rather than per case, because a link inside a component that
    never became a case is invisible from the cases alone.
    """
    first, second, child = two_instances
    data = build_telemetry(procs=[first, second, child])

    identified = correlate_with_stats(
        [finding("R-1", second["event_id"], at(20)),
         finding("R-2", child["event_id"], at(21))],
        data,
    )[1]
    assert identified.links == 1
    assert identified.inferred_links == 0
    assert identified.links_by_signal["process_lineage"] == 1
    assert "process_lineage" not in identified.inferred_links_by_signal

    blank = [dict(row, process_guid="", parent_process_guid="")
             for row in (first, second, child)]
    unidentified = correlate_with_stats(
        [finding("R-1", blank[1]["event_id"], at(20)),
         finding("R-2", blank[2]["event_id"], at(21))],
        build_telemetry(procs=blank),
    )[1]
    assert unidentified.links == 1
    assert unidentified.inferred_links == 1
    assert unidentified.inferred_links_by_signal["process_lineage"] == 1


def test_stats_cover_links_inside_components_that_never_became_cases() -> None:
    """``min_case_size`` discards a component; the link it rested on is still counted."""
    parent_identity = start_identity(DEVICE, 5000, at(-5))
    rows = _sibling_children((parent_identity, parent_identity))
    data = build_telemetry(procs=rows)
    findings = [finding("R-1", rows[0]["event_id"], at(0)),
                finding("R-2", rows[1]["event_id"], at(1))]

    cases, stats = correlate_with_stats(
        findings, data, CorrelationConfig(min_case_size=3)
    )
    assert cases == []
    assert stats.links == 1
    assert stats.cases == 0


def test_a_run_with_no_findings_reports_an_empty_run() -> None:
    cases, stats = correlate_with_stats([], build_telemetry())
    assert cases == []
    assert (stats.findings, stats.cases, stats.links) == (0, 0, 0)


# ======================================================================================
# The session bounds are measured per instance
# ======================================================================================


def test_fan_out_is_counted_per_parent_instance() -> None:
    """Two runs of one parent PID, six children each: neither is a twelve-child launcher.

    Counted per slot the pooled fan-out is 12 and both still pass, so this asserts the
    split rather than the bound. What it protects is the *sibling* answer underneath:
    the two halves must not be read as one session.
    """
    older = start_identity(DEVICE, 5000, at(-30))
    newer = start_identity(DEVICE, 5000, at(-5))
    rows = []
    for n in range(6):
        rows.append(proc("a.exe", "a", "cmd.exe", device=DEVICE, when=at(0, n), pid=6100 + n,
                         ppid=5000, guid=start_identity(DEVICE, 6100 + n, at(0, n)),
                         parent_guid=older))
        rows.append(proc("b.exe", "b", "cmd.exe", device=DEVICE, when=at(1, n), pid=6200 + n,
                         ppid=5000, guid=start_identity(DEVICE, 6200 + n, at(1, n)),
                         parent_guid=newer))
    data = build_telemetry(procs=rows)
    index = _ProcessIndex(data)

    from ath.instance_identity import instance_key

    assert index.fan_out(instance_key(older, DEVICE, 5000)) == 6
    assert index.fan_out(instance_key(newer, DEVICE, 5000)) == 6

    a = finding("R-1", rows[0]["event_id"], at(0))
    b = finding("R-2", rows[1]["event_id"], at(1))
    assert "sibling_lineage" not in names(a, b, data)


def test_spawn_span_is_measured_per_parent_instance() -> None:
    """Two runs of one parent PID an hour apart: the pooled span would be an hour.

    Per instance each span is seconds, so each run reads as a session -- and the two
    runs' children still do not read as each other's siblings.
    """
    older = start_identity(DEVICE, 5000, at(-90))
    newer = start_identity(DEVICE, 5000, at(-5))
    rows = [
        proc("a.exe", "a", "cmd.exe", device=DEVICE, when=at(-90), pid=6100, ppid=5000,
             guid=start_identity(DEVICE, 6100, at(-90)), parent_guid=older),
        proc("a2.exe", "a2", "cmd.exe", device=DEVICE, when=at(-89), pid=6101, ppid=5000,
             guid=start_identity(DEVICE, 6101, at(-89)), parent_guid=older),
        proc("b.exe", "b", "cmd.exe", device=DEVICE, when=at(0), pid=6200, ppid=5000,
             guid=start_identity(DEVICE, 6200, at(0)), parent_guid=newer),
        proc("b2.exe", "b2", "cmd.exe", device=DEVICE, when=at(1), pid=6201, ppid=5000,
             guid=start_identity(DEVICE, 6201, at(1)), parent_guid=newer),
    ]
    data = build_telemetry(procs=rows)
    index = _ProcessIndex(data)

    from ath.instance_identity import instance_key

    assert index.spawn_span(instance_key(newer, DEVICE, 5000)) == timedelta(minutes=1)
    assert index.spawn_span(instance_key(older, DEVICE, 5000)) == timedelta(minutes=1)

    a = finding("R-1", rows[2]["event_id"], at(0))
    b = finding("R-2", rows[3]["event_id"], at(1))
    assert "sibling_lineage" in names(a, b, data)
