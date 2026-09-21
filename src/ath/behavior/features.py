"""Shared temporal features, computed once and read by every layer.

``ConnectionPattern`` is the reason this package exists. The median/MAD computation
below previously lived inside ``ath.agent.tools.analyse_beacon`` -- in the investigation
layer, which only runs after a case has formed. Triage, which decides whether to tell an
analyst to stop looking, could not see it, and returned four regular TLS connections to a
popular destination as ``likely_benign``.

The statistics were moved here rather than copied. There is exactly one implementation.

Statistical honesty
-------------------
Four connections give **three** intervals. That is thin, and the object says so rather
than hiding it behind a confident-looking ratio:

* ``interarrival_count`` is exposed so every consumer can see how much support exists.
* ``robust_cv`` is ``None`` when it cannot be computed -- never ``0.0`` (which reads as
  "perfectly regular") and never ``inf`` (which the old implementation returned for a
  zero median, and which compares as larger than every threshold).
* There is deliberately **no** ``is_beacon: bool``. Whether a pattern warrants suspicion
  is a judgement, and judgements belong to consumers holding context this module does
  not have.

Why median/MAD rather than mean/standard deviation
---------------------------------------------------
The naive coefficient of variation, ``stdev(gaps) / mean(gaps)``, is defeated by exactly
the pattern real C2 produces: the first contact fetches a payload at a different tempo
than the heartbeat that follows. One short gap among several identical ones drags the
mean down and inflates the standard deviation, so a genuinely regular beacon scores as
irregular.

Median and median absolute deviation are far less sensitive to a single outlier: five
identical 300s gaps and one 27s gap give a median of exactly 300s and a MAD of 0. That
is why the statistic is ``MAD / median`` -- the standard robust alternative, chosen
because security telemetry is full of this specific shape.

The honest limit: implants add *jitter* precisely to defeat this. A high ``robust_cv``
is weak evidence of absence, and no consumer may read it as exoneration.
"""

from __future__ import annotations

import statistics
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

# How far a relationship's inter-arrival times may vary and still count as regular.
# Applied to MAD/median, so it is a proportion of the typical gap rather than an
# absolute tolerance.
REGULARITY_THRESHOLD: float = 0.15

# Gaps shorter than this are not evidence of automation -- bursty user activity produces
# sub-second regularity all the time.
MIN_MEANINGFUL_INTERVAL_SECONDS: float = 5.0

# Below this many intervals, regularity is not a meaningful measurement at all.
# Two connections give one interval, which is regular by definition and means nothing.
MIN_INTERVALS_FOR_REGULARITY: int = 3

# Baseline relation lifecycle. A relationship earns standing over time; it never starts
# trusted. Ordered weakest to strongest.
RELATION_NEW = "new"
RELATION_EMERGING = "emerging"
RELATION_ESTABLISHING = "establishing"
RELATION_ESTABLISHED = "established"
RELATION_STALE = "stale"
RELATION_UNKNOWN = "unknown"


@dataclass(frozen=True)
class ConnectionPattern:
    """The measured timing of one process-to-destination relationship.

    Attributes:
        source_process: Image that opened the connections.
        destination: Remote address contacted.
        connection_count: Number of connection events observed.
        observation_span: First to last connection.
        interarrival_count: Number of gaps -- always ``connection_count - 1``. Exposed
            because it is how a consumer judges whether the statistics mean anything.
        median_interval / interval_mad: Robust centre and dispersion, ``None`` when
            there are too few intervals to compute them.
        robust_cv: ``MAD / median``. ``None`` when undefined.
        min_interval / max_interval: Bounds, for consumers that want the raw shape.
        first_seen / last_seen: Window bounds.
        baseline_relation_status: Where this relationship sits in its lifecycle.
        evidence_ids: The connection events measured.
    """

    source_process: str
    destination: str
    connection_count: int
    observation_span: timedelta
    interarrival_count: int
    median_interval: timedelta | None
    interval_mad: timedelta | None
    robust_cv: float | None
    min_interval: timedelta | None
    max_interval: timedelta | None
    first_seen: datetime
    last_seen: datetime
    baseline_relation_status: str = RELATION_UNKNOWN
    evidence_ids: tuple[str, ...] = ()

    @property
    def has_measurable_regularity(self) -> bool:
        """Whether enough intervals exist for ``robust_cv`` to carry any weight."""
        return (
            self.robust_cv is not None
            and self.interarrival_count >= MIN_INTERVALS_FOR_REGULARITY
        )

    @property
    def is_regular(self) -> bool:
        """Whether the observed gaps are tightly clustered.

        A *measurement*, not a verdict. Regular polling by an update client satisfies
        this exactly as a beacon does; distinguishing them needs context this object
        does not hold.
        """
        if not self.has_measurable_regularity or self.median_interval is None:
            return False
        return (
            self.robust_cv < REGULARITY_THRESHOLD
            and self.median_interval.total_seconds() > MIN_MEANINGFUL_INTERVAL_SECONDS
        )

    @property
    def support_note(self) -> str:
        """One line stating how much the timing figures can bear."""
        if self.interarrival_count == 0:
            return "a single connection provides no interval to measure"
        if self.interarrival_count < MIN_INTERVALS_FOR_REGULARITY:
            return (
                f"{self.connection_count} connections give only "
                f"{self.interarrival_count} interval(s), too few to characterise timing"
            )
        return (
            f"{self.connection_count} connections give {self.interarrival_count} "
            "intervals"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_process": self.source_process,
            "destination": self.destination,
            "connection_count": self.connection_count,
            "observation_span_seconds": self.observation_span.total_seconds(),
            "interarrival_count": self.interarrival_count,
            "median_interval_seconds": _seconds(self.median_interval),
            "interval_mad_seconds": _seconds(self.interval_mad),
            "robust_cv": (
                round(self.robust_cv, 4) if self.robust_cv is not None else None
            ),
            "min_interval_seconds": _seconds(self.min_interval),
            "max_interval_seconds": _seconds(self.max_interval),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "baseline_relation_status": self.baseline_relation_status,
            "is_regular": self.is_regular,
            "has_measurable_regularity": self.has_measurable_regularity,
            "support_note": self.support_note,
            "evidence_ids": list(self.evidence_ids),
        }


def _seconds(value: timedelta | None) -> float | None:
    return None if value is None else value.total_seconds()


def compute_connection_pattern(
    source_process: str,
    destination: str,
    timestamps: Sequence[datetime],
    evidence_ids: Sequence[str] = (),
    baseline_relation_status: str = RELATION_UNKNOWN,
) -> ConnectionPattern:
    """Measure the timing of one relationship. The only implementation in the codebase.

    Args:
        source_process: Image that opened the connections.
        destination: Remote address.
        timestamps: Connection times. Sorted internally; order need not be guaranteed.
        evidence_ids: The events measured.
        baseline_relation_status: Lifecycle standing, when the caller knows it.

    Raises:
        ValueError: if no timestamps are given -- there is nothing to measure, and
            returning a zero-valued pattern would be a fabricated observation.
    """
    if not timestamps:
        raise ValueError(
            f"cannot compute a connection pattern for {source_process} -> "
            f"{destination} with no timestamps"
        )

    ordered = sorted(timestamps)
    gaps = [
        (ordered[i + 1] - ordered[i]).total_seconds() for i in range(len(ordered) - 1)
    ]

    median_interval = interval_mad = robust_cv = None
    if len(gaps) >= MIN_INTERVALS_FOR_REGULARITY:
        median_gap = statistics.median(gaps)
        mad = statistics.median([abs(gap - median_gap) for gap in gaps])
        median_interval = timedelta(seconds=median_gap)
        interval_mad = timedelta(seconds=mad)
        # None, not inf: a zero median means the gaps are degenerate, and a sentinel
        # that compares larger than every threshold would silently read as "irregular"
        # rather than as "not measurable".
        robust_cv = (mad / median_gap) if median_gap > 0 else None

    return ConnectionPattern(
        source_process=source_process,
        destination=destination,
        connection_count=len(ordered),
        observation_span=ordered[-1] - ordered[0],
        interarrival_count=len(gaps),
        median_interval=median_interval,
        interval_mad=interval_mad,
        robust_cv=robust_cv,
        min_interval=timedelta(seconds=min(gaps)) if gaps else None,
        max_interval=timedelta(seconds=max(gaps)) if gaps else None,
        first_seen=ordered[0],
        last_seen=ordered[-1],
        baseline_relation_status=baseline_relation_status,
        evidence_ids=tuple(evidence_ids),
    )
