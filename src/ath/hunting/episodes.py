"""Grouping one actor's events into non-overlapping episodes inside a sliding window.

One function, shared by every rule that has to answer "did enough of this happen close
enough together". It was written for ATH-005 and lived as ``_find_bursts`` inside
:mod:`ath.hunting.rules.logon_rules`; M18-8 added four control-plane rules with exactly
the same question to ask, and a second implementation of a sliding window is a second
answer to it. The body below is the ATH-005 body, unchanged -- ``logon_rules`` imports it
under its old private name, so ATH-005's own code is byte-identical to what it was and
its two dedicated tests still exercise the same function.

Why a sliding window rather than fixed buckets
-----------------------------------------------
Bucketing by clock hours splits a burst that straddles a boundary: fourteen attempts
spanning 09:58--10:02 become two sub-threshold buckets and are missed entirely. The same
artefact eats a cloud scanner's breadth -- twelve services touched across a ten-minute
boundary measure twelve in a sliding window and six in the best fixed bucket -- which is
why :mod:`scripts.m18_cloud_behaviour_stats` measured the background distribution with a
sliding window too. A threshold read off one shape and applied with the other is a
threshold for a different rule.

Why episodes are non-overlapping
---------------------------------
A thousand-call scan should be one alert, not a thousand. Once a cluster is reported the
sweep resumes *after* it, so the same events are never re-reported under a shifted
window -- the difference between an analyst seeing one episode and an analyst seeing a
queue of near-duplicates that all describe it.
"""

from __future__ import annotations

from datetime import timedelta

import pandas as pd


def find_episodes(
    timestamps: list[pd.Timestamp], min_events: int, window: timedelta
) -> list[tuple[int, int]]:
    """Find non-overlapping clusters of >= ``min_events`` inside ``window``.

    A two-pointer sweep over sorted timestamps. Returns inclusive ``(start, end)``
    index pairs.

    Why a sliding window rather than "count failures per hour": bucketing by fixed
    clock hours splits a burst that straddles a boundary, so a 14-attempt attack
    spanning 09:58-10:02 becomes two sub-threshold buckets and is missed entirely.
    Boundary artefacts like this are a classic source of silent false negatives.
    """
    bursts: list[tuple[int, int]] = []
    n = len(timestamps)
    i = 0
    while i < n:
        j = i
        while j + 1 < n and timestamps[j + 1] - timestamps[i] <= window:
            j += 1
        if j - i + 1 >= min_events:
            bursts.append((i, j))
            i = j + 1  # non-overlapping: do not re-report the same failures
        else:
            i += 1
    return bursts
