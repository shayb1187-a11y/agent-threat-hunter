"""M18-7: the sliding-window statistics a cloud discovery rule would be built on.

These tests measure the *measurement*. No threshold is chosen anywhere in this milestone,
so what has to be right is the arithmetic: the maximum over every window of a given
length, per actor, computed by two pointers over that actor's own event times rather than
by fixed buckets -- because a burst that straddles a bucket boundary is exactly the burst
a bucketed count halves, and a scanner's burst has no reason to respect the clock.

The table below is hand-built and its answers are known by construction: one actor who
touches twelve services in four minutes, one who touches the same twelve over three
hours, and one who is refused eight times and rejected six.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from m18_cloud_behaviour_stats import (  # noqa: E402
    CANDIDATE_THRESHOLDS,
    STATISTICS,
    measure_actor,
    measure_table,
    threshold_table,
    window_maxima,
)

from tests import _builders as build  # noqa: E402

MINUTE_NS = 60 * 1_000_000_000
START = datetime(2026, 3, 4, 9, 58, tzinfo=timezone.utc)

# Twelve invented services, disjoint from every corpus: the same vocabulary
# tests/test_cloudtrail_representation.py asserts absent from attack_data_aws and the
# flaws.cloud top-100, extended by numbering rather than by borrowing real service names.
SERVICES = tuple(f"quokka{index}" for index in range(12))


def _read(actor: str, service: str, minute: float, decision: str = "allowed") -> dict:
    return build.ctrl(
        actor, "describe", f"{service}:ledger-fleet", f"ledger-{service}",
        decision=decision, device="aws:519204773311/ap-southeast-2",
        source_ip="198.51.100.203", source="cloudtrail_mgmt",
        when=START + timedelta(minutes=minute),
    )


def _identity_change(actor: str, verb: str, minute: float, decision: str) -> dict:
    return build.ctrl(
        actor, verb, "iam:quokka-policy", f"quokka-policy-{minute}",
        decision=decision, device="aws:519204773311/ap-southeast-2",
        source_ip="198.51.100.203", source="cloudtrail_mgmt",
        when=START + timedelta(minutes=minute),
    )


@pytest.fixture(scope="module")
def table() -> pd.DataFrame:
    """Three actors, each one known shape.

    ``burst`` reads twelve distinct services between 09:58 and 10:02 -- four minutes
    across a clock-hour boundary. ``spread`` reads the same twelve, twenty minutes apart,
    over three hours and forty minutes. ``refused`` is denied eight times inside four
    minutes, has six identity-authority writes rejected for other reasons, and removes
    three authorities twenty minutes apart.
    """
    rows: list[dict] = []
    rows += [
        _read("burst", service, index * (4 / 11)) for index, service in enumerate(SERVICES)
    ]
    rows += [
        _read("spread", service, index * 20) for index, service in enumerate(SERVICES)
    ]
    rows += [
        _read("refused", SERVICES[index], 100 + index * 0.5, decision="denied")
        for index in range(8)
    ]
    rows += [
        _identity_change("refused", "attach", 200 + index * 0.5, "failed")
        for index in range(6)
    ]
    rows += [
        _identity_change("refused", verb, 300 + index * 20, "allowed")
        for index, verb in enumerate(("detach", "remove", "delete"))
    ]
    return build.telemetry(ctrls=rows).controls


# ======================================================================================
# The two-pointer itself
# ======================================================================================


def test_a_window_is_inclusive_at_both_ends() -> None:
    """Two events exactly one window apart are one window; one nanosecond more are two.

    Fails if the comparison is written with the wrong strictness, which moves every
    measured maximum by one at exactly the boundary a threshold would be chosen on.
    """
    exact = [0, 10 * MINUTE_NS]
    beyond = [0, 10 * MINUTE_NS + 1]
    assert window_maxima(exact, [None, None], 10 * MINUTE_NS)[0] == 2
    assert window_maxima(beyond, [None, None], 10 * MINUTE_NS)[0] == 1


def test_distinct_values_are_counted_once_while_they_are_in_the_window() -> None:
    """A repeated value inside the window is one distinct value, and leaving restores it.

    Fails if the accumulator counts occurrences rather than distinct values (a caller
    polling one service looks like a caller enumerating many), or if a value that leaves
    the window is not retired (every window from the first event onward, which is not a
    window at all).
    """
    times = [0, MINUTE_NS, 2 * MINUTE_NS, 30 * MINUTE_NS]
    best, per_event = window_maxima(times, ["a", "a", "b", "a"], 10 * MINUTE_NS)
    assert best == 2
    assert per_event == [1, 1, 2, 1]


def test_an_empty_series_measures_zero_rather_than_failing() -> None:
    """An actor with no qualifying row is a measured zero. Fails if it raises instead."""
    assert window_maxima([], [], 10 * MINUTE_NS) == (0, [])


# ======================================================================================
# The statistics over the hand-built table
# ======================================================================================


@pytest.mark.parametrize("window,expected", [("10", 12), ("60", 12)])
def test_a_burst_of_twelve_services_in_four_minutes_measures_twelve(
    table, window, expected
) -> None:
    """The shape the T1526 capture has: everything, at once, from one caller.

    Fails if the window is applied across all of an actor's rows rather than the rows the
    statistic is computed over, and fails if the maximum is taken over anything but every
    window -- twelve is only visible in the windows that contain the whole burst.
    """
    actors = measure_table(table)
    assert actors["burst"]["windows"][window]["read_services"] == expected
    assert actors["burst"]["windows"][window]["read_resource_types"] == expected


def test_the_same_twelve_services_spread_over_three_hours_do_not(table) -> None:
    """The same twelve services, twenty minutes apart: 1 in ten minutes, 4 in sixty.

    This is the pair that makes the statistic mean anything. Both actors touch twelve
    services and only one of them did it at machine speed; a total, or a per-day count,
    cannot tell them apart at all.
    """
    actors = measure_table(table)
    assert actors["spread"]["windows"]["10"]["read_services"] == 1
    assert actors["spread"]["windows"]["60"]["read_services"] == 4
    assert actors["spread"]["totals"]["read_services"] == 12


def test_fixed_buckets_would_have_halved_the_burst(table) -> None:
    """The burst straddles 10:00, so no ten-minute clock bucket holds more than half of it.

    Asserted against the alternative implementation rather than described in prose: fails
    the moment the sliding window is replaced by a ``resample``/``floor`` grouping, which
    is the cheap way to write this and reports six where the answer is twelve.
    """
    burst = table[table["actor"] == "burst"]
    bucketed = burst.groupby(burst["timestamp"].dt.floor("10min"))["resource_type"].apply(
        lambda column: column.map(lambda value: value.split(":")[0]).nunique()
    )
    assert int(bucketed.max()) == 6

    actors = measure_table(table)
    assert actors["burst"]["windows"]["10"]["read_services"] == 12


def test_denied_and_failed_are_counted_apart(table) -> None:
    """Eight refusals and six rejections by the same actor are two different statistics.

    The whole of M18-7 in one assertion: before the tri-state both populations were
    "denied", and a rule counting denials would have counted fourteen. Fails if either
    statistic reads ``decision != allowed``.
    """
    refused = measure_table(table)["refused"]
    assert refused["windows"]["10"]["denied_calls"] == 8
    assert refused["windows"]["10"]["failed_identity_authority_changes"] == 6
    assert refused["decisions"] == {"allowed": 3, "denied": 8, "failed": 6}


def test_removals_are_counted_whatever_the_platform_said(table) -> None:
    """Detach, remove and delete on the identity service: three, in one hour.

    No decision filter, deliberately -- an attempted removal is as much the behaviour as a
    successful one. Fails if the statistic is restricted to allowed rows, or if the
    delete/revoke classes are narrowed to one of the two.
    """
    refused = measure_table(table)["refused"]
    assert refused["windows"]["60"]["identity_delete_revoke_changes"] == 3
    assert refused["windows"]["10"]["identity_delete_revoke_changes"] == 1


def test_an_actor_who_did_none_of_it_measures_zero_everywhere(table) -> None:
    """The reads-only actors must be zero on every denial statistic.

    Fails if a statistic's row predicate leaks -- e.g. if "denied" ever falls back to
    "not allowed", which would give both reading actors a full denial count.
    """
    actors = measure_table(table)
    for actor in ("burst", "spread"):
        for name in ("denied_calls", "denied_resource_types",
                     "failed_identity_authority_changes",
                     "identity_delete_revoke_changes"):
            assert actors[actor]["windows"]["10"][name] == 0, (actor, name)
            assert actors[actor]["totals"][name] == 0, (actor, name)


def test_span_and_totals_describe_the_actor_not_the_window(table) -> None:
    """Totals are over everything the actor did; the span is first to last.

    Fails if a total is quietly computed over a window, which would make "this actor
    touched twelve services" and "this actor touched twelve services at once" the same
    number again.
    """
    actors = measure_table(table)
    assert actors["burst"]["rows"] == 12
    assert actors["burst"]["span_hours"] == pytest.approx(4 / 60, abs=1e-3)
    assert actors["spread"]["span_hours"] == pytest.approx(220 / 60, abs=1e-3)
    assert actors["refused"]["totals"]["denied_calls"] == 8


# ======================================================================================
# The candidate grid: reported, never chosen
# ======================================================================================


def test_the_candidate_grid_counts_actors_and_actor_days(table) -> None:
    """At ``read_services >= 10`` one of the three actors reaches it, on one day.

    Actor-days rather than actors alone because that is the unit an alert queue is
    measured in. Fails if a threshold is applied with the wrong comparison (``>`` for
    ``>=`` moves every count) or if actor-days collapse to actors.
    """
    grid = threshold_table(measure_table(table))
    ten_minutes = grid["10"]["read_services"]
    # `refused` reaches 5 too: its eight denied reads are reads, and a caller enumerating
    # an account it has no rights in is the shape the statistic is for.
    assert ten_minutes["5"]["actors"] == 2
    assert ten_minutes["10"]["actors"] == 1
    assert ten_minutes["20"]["actors"] == 0
    assert ten_minutes["10"]["actor_days"] == 1
    assert ten_minutes["10"]["actors_named"] == ["burst"]
    assert grid["10"]["identity_delete_revoke_changes"]["1"]["actors"] == 1
    assert grid["10"]["identity_delete_revoke_changes"]["3"]["actors"] == 0
    assert grid["60"]["identity_delete_revoke_changes"]["3"]["actors"] == 1


def test_the_script_chooses_no_threshold_of_its_own() -> None:
    """The only numbers in the grid are the ones the architect pre-registered.

    Fails if a value is added, removed or tuned -- which is how a measurement quietly
    becomes a detection fitted to the corpus it was measured on.
    """
    assert CANDIDATE_THRESHOLDS == {
        "read_services": (5, 10, 20),
        "denied_calls": (10, 25, 50, 100),
        "failed_identity_authority_changes": (3, 5, 10),
        "identity_delete_revoke_changes": (1, 3, 5),
    }
    assert set(CANDIDATE_THRESHOLDS) <= set(STATISTICS)


def test_every_statistic_is_measured_at_every_window(table) -> None:
    """No statistic may be silently absent from an artifact a threshold is read out of."""
    actor = measure_actor(table[table["actor"] == "refused"])
    for window in ("10", "60"):
        assert set(actor["windows"][window]) == set(STATISTICS)
