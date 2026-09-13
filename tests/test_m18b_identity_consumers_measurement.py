"""The M18b-2 measurement script, on a corpus whose answers are known by hand.

Why a measurement script needs tests at all
--------------------------------------------
This script's output is the milestone's claim, and the claim is a *difference*: what the
old ``(device, pid)`` key attributed that an instance identity refuses, and what it
could not see. Both halves of that difference are computed here, and both can fail
silently:

* **The transcription drifts.** :class:`_LegacyProcessIndex` and
  :func:`legacy_process_tree` stand in for the consumers at 7e68840. If either ever
  behaved like the current code, every "before" number would equal its "after" and the
  script would report "nothing changed" on every corpus, forever, without erroring.
  That is the worst outcome available: a measurement that is always reassuring.
* **The diff counts the wrong thing.** ``lost_process_links`` is the false-lineage
  count. Counting links rather than *signals* would miss a pair that kept its link and
  lost its lineage, which is the ordinary shape of this change.

The fixture below is four process rows on one host, so each expected number can be read
straight off it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from m18b_identity_consumers import (  # noqa: E402
    _LegacyProcessIndex,
    compare,
    legacy_correlator,
    legacy_process_tree,
    reused_keys,
    run,
)

from _builders import at, proc, telemetry as build_telemetry  # noqa: E402
from ath.correlation import correlator as correlator_module  # noqa: E402
from ath.hunting import Evidence, Finding, Severity  # noqa: E402
from ath.instance_identity import start_identity  # noqa: E402

DEVICE = "PC09"
REUSED_PID = 4444

FIRST = start_identity(DEVICE, REUSED_PID, at(0))
SECOND = start_identity(DEVICE, REUSED_PID, at(20))


@pytest.fixture()
def two_runs():
    """PID 4444 twice, and a child that names the second run as its creator.

    The old key cannot tell the two apart; the child says which one started it.
    """
    return build_telemetry(procs=[
        proc("cmd.exe", "cmd /c one", "explorer.exe", device=DEVICE, user="operator",
             when=at(0), pid=REUSED_PID, ppid=1000, guid=FIRST),
        proc("cmd.exe", "cmd /c two", "explorer.exe", device=DEVICE, user="operator",
             when=at(20), pid=REUSED_PID, ppid=1000, guid=SECOND),
        proc("whoami.exe", "whoami", "cmd.exe", device=DEVICE, user="operator",
             when=at(21), pid=7777, ppid=REUSED_PID,
             guid=start_identity(DEVICE, 7777, at(21)), parent_guid=SECOND),
    ])


def _finding(rule_id: str, event_id: str, when) -> Finding:
    return Finding(
        rule_id=rule_id, title="t", severity=Severity.MEDIUM, device=DEVICE,
        user="operator", evidence=(Evidence(event_id, when, "s"),), reason="r",
    )


def _findings(data) -> list[Finding]:
    rows = data.processes.sort_values("timestamp").to_dict("records")
    return [
        _finding("R-1", rows[0]["event_id"], at(0)),
        _finding("R-2", rows[2]["event_id"], at(21)),
    ]


# ======================================================================================
# The transcription is the old behaviour, and demonstrably not the new one
# ======================================================================================


def test_the_legacy_index_still_makes_the_attribution_the_identity_refuses(two_runs) -> None:
    """The measurement's whole value: the two keys must disagree on this corpus.

    Fails if the transcription is ever quietly replaced by the current index -- at which
    point the script would report "no change" on every corpus and look like good news.
    """
    findings = _findings(two_runs)

    before = run(two_runs, findings, set(), legacy=True)
    after = run(two_runs, findings, set(), legacy=False)

    assert before["links_by_signal"].get("process_lineage") == 1, (
        "the old key attributed the child to the first run of pid 4444"
    )
    assert "process_lineage" not in after["links_by_signal"], (
        "the child names the second run, so the first is not its parent"
    )


def test_the_diff_counts_the_lost_attribution(two_runs) -> None:
    findings = _findings(two_runs)
    before = run(two_runs, findings, set(), legacy=True)
    after = run(two_runs, findings, set(), legacy=False)

    movement = compare(before, after, {"findings": 2, "by_rule": {"R-1": 1, "R-2": 1}})

    assert movement["lost_process_link_count"] == 1
    assert movement["lost_process_links"][0]["signal"] == "process_lineage"
    assert movement["gained_process_link_count"] == 0
    assert movement["findings_unchanged"] is True


def test_a_lost_signal_is_counted_even_when_the_link_survives(two_runs) -> None:
    """Two findings can stay linked on circumstance and still lose their lineage.

    Counting links rather than signals would report zero here, which is the ordinary
    shape of this change on a corpus where same-host and same-time hold everywhere.
    """
    rows = two_runs.processes.sort_values("timestamp").to_dict("records")
    # The second finding cites the child *and* the first run, so the pair keeps a
    # structural signal (shared evidence) after the lineage claim is withdrawn.
    second = Finding(
        rule_id="R-2", title="t", severity=Severity.MEDIUM, device=DEVICE,
        user="operator", reason="r",
        evidence=(
            Evidence(rows[2]["event_id"], at(21), "s"),
            Evidence(rows[0]["event_id"], at(0), "s"),
        ),
    )
    findings = [_finding("R-1", rows[0]["event_id"], at(0)), second]

    before = run(two_runs, findings, set(), legacy=True)
    after = run(two_runs, findings, set(), legacy=False)
    pair = next(iter(before["_links"]))

    assert "process_lineage" in before["_links"][pair]["signals"]
    assert pair in after["_links"], "the pair is still linked, on weaker signals"
    assert "process_lineage" not in after["_links"][pair]["signals"]
    assert compare(before, after, {})["lost_process_link_count"] == 1


def test_the_legacy_context_manager_puts_the_real_index_back(two_runs) -> None:
    """A measurement that left the correlator patched would poison everything after it."""
    original = correlator_module._ProcessIndex
    with legacy_correlator():
        assert correlator_module._ProcessIndex is _LegacyProcessIndex
    assert correlator_module._ProcessIndex is original


# ======================================================================================
# The lineage tool, before and after
# ======================================================================================


def test_the_legacy_tree_picks_one_instance_and_says_nothing_about_the_others(
    two_runs,
) -> None:
    """``iloc[0]``, reproduced: one answer of two, and the count of what it discarded."""
    tree = legacy_process_tree(two_runs, DEVICE, REUSED_PID)

    assert [a["process_name"] for a in tree["ancestry"]] == ["cmd.exe"]
    assert tree["candidates_ignored"] == 1
    assert tree["children"] == 1


def test_reused_keys_reports_the_slots_more_than_one_process_passed_through(
    two_runs,
) -> None:
    ambiguity = reused_keys(two_runs)

    assert ambiguity["process_keys"] == 2  # pid 4444 and pid 7777
    assert ambiguity["reused"] == 1
    assert ambiguity["worst"] == {"key": f"{DEVICE}|{REUSED_PID}", "instances": 2}


def test_an_empty_corpus_reports_no_ambiguity_rather_than_failing() -> None:
    """k8s and CloudTrail corpora have no process table at all; they must still measure."""
    assert reused_keys(build_telemetry())["reused"] == 0
