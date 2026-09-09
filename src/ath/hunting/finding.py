"""The structured output of a detection.

Design principle: **a finding cannot exist without evidence.**

It would be easy to let detectors return DataFrames. It would also be a mistake. A
DataFrame has no rule id, no severity, no stated reasoning, and no record of which
telemetry fields were consulted -- so by the time it reaches a report or an LLM, the
chain back to the raw event is gone.

:class:`Finding` makes that chain structural rather than optional:

* ``evidence`` is validated as non-empty at construction time
* ``event_ids`` is *derived* from evidence, so it can never disagree with it
* ``false_positives`` travels with the finding, so the caveat cannot get lost

Everything downstream (MITRE mapping, the agent's tools, the final report) consumes
this type, which is what will let us say "every sentence in the report cites an event
id that exists in the dataset" and actually mean it.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

import pandas as pd

from ath.channels import TelemetryChannel


class Severity(str, Enum):
    """Analyst-facing severity.

    This is a *triage* signal, not a statement of confirmed impact. ``CRITICAL`` means
    "stop what you are doing and look at this", not "an attacker is definitely present".
    """

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting and threshold filtering."""
        return _SEVERITY_RANK[self]

    def __str__(self) -> str:  # keeps f-strings readable
        return self.value


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class Evidence:
    """A single telemetry event that supports a finding.

    Attributes:
        event_id: The id of the supporting event. Must exist in the telemetry.
        timestamp: When the event occurred (UTC).
        summary: One line describing what the event shows, in analyst language.
    """

    event_id: str
    timestamp: datetime
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": _iso(self.timestamp),
            "summary": self.summary,
        }


@dataclass(frozen=True)
class Finding:
    """A deterministic detection result.

    Attributes:
        rule_id: Stable identifier, e.g. ``"ATH-001"``. Never reused or renumbered.
        title: Short human-readable name of the behaviour observed.
        severity: Triage priority.
        device: Host the behaviour was observed on.
        user: Account context the behaviour ran under.
        evidence: Supporting events. Must be non-empty.
        reason: Why this specific data tripped the rule -- the analyst's "so what".
        fields_used: Telemetry fields the rule depends on. Documents the rule's blind
            spots: a rule that only reads ``command_line`` cannot see handle-based
            behaviour, and saying so out loud is part of doing this honestly.
        false_positives: Known benign causes of this pattern.
        metadata: Rule-specific extras (decoded commands, counts, source IPs).
        channels: The rule's explicitly declared telemetry channels, carried on the
            finding itself rather than looked up later by rule id. Empty for the common
            case, where a channel can be inferred from ``fields_used`` column names;
            set when a rule declared ``Detector.channels`` explicitly because that
            inference would be ambiguous. See ``ath.hunting.base.Detector.channels``.
    """

    rule_id: str
    title: str
    severity: Severity
    device: str
    user: str
    evidence: tuple[Evidence, ...]
    reason: str
    fields_used: tuple[str, ...] = ()
    false_positives: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)
    channels: frozenset[TelemetryChannel] = frozenset()

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError(
                f"{self.rule_id}: a Finding must cite at least one event. "
                "Unevidenced findings are assertions, not detections."
            )
        # Keep evidence chronological so timelines read correctly everywhere.
        object.__setattr__(
            self, "evidence", tuple(sorted(self.evidence, key=lambda e: e.timestamp))
        )

    # -- derived properties: cannot drift out of sync with the evidence ---------

    @property
    def event_ids(self) -> tuple[str, ...]:
        """Ids of every event supporting this finding, in chronological order."""
        return tuple(e.event_id for e in self.evidence)

    @property
    def finding_id(self) -> str:
        """A stable, deterministic handle for this finding.

        Derived rather than stored, so it cannot disagree with the evidence. The rule
        id plus the earliest supporting event uniquely identifies a finding, because no
        rule emits two findings whose earliest evidence is the same event. Correlation
        needs a key to build a graph on; deriving it keeps that key traceable.
        """
        return f"{self.rule_id}:{self.evidence[0].event_id}"

    @property
    def first_seen(self) -> datetime:
        """Timestamp of the earliest supporting event."""
        return self.evidence[0].timestamp

    @property
    def last_seen(self) -> datetime:
        """Timestamp of the latest supporting event."""
        return self.evidence[-1].timestamp

    @property
    def time_window(self) -> tuple[datetime, datetime]:
        """The (first_seen, last_seen) window this finding spans."""
        return self.first_seen, self.last_seen

    @property
    def event_count(self) -> int:
        return len(self.evidence)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to plain JSON-safe types.

        Used by the CLI's ``--json`` output and, later, as the payload the agent's
        tools return. Keeping serialisation here means the agent can never receive a
        finding shape that differs from what the report renders.
        """
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "device": self.device,
            "user": self.user,
            "first_seen": _iso(self.first_seen),
            "last_seen": _iso(self.last_seen),
            "event_ids": list(self.event_ids),
            "reason": self.reason,
            "evidence": [e.to_dict() for e in self.evidence],
            "fields_used": list(self.fields_used),
            "false_positives": list(self.false_positives),
            "metadata": _jsonable(self.metadata),
            "channels": sorted(c.value for c in self.channels),
        }

    def __str__(self) -> str:
        return (
            f"[{self.severity}] {self.rule_id} {self.title} "
            f"({self.device}/{self.user}, {self.event_count} events)"
        )


def _iso(value: Any) -> str:
    """Render a timestamp as an unambiguous ISO-8601 string."""
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _jsonable(value: Any) -> Any:
    """Recursively convert pandas/NumPy scalars into plain Python types."""
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (pd.Timestamp, datetime)):
        return _iso(value)
    if hasattr(value, "item") and not isinstance(value, (str, bytes)):
        try:
            return value.item()
        except (AttributeError, ValueError):
            return str(value)
    return value


def findings_to_frame(findings: list[Finding]) -> pd.DataFrame:
    """Flatten findings into a DataFrame for display and ad-hoc analysis."""
    if not findings:
        return pd.DataFrame(
            columns=["rule_id", "severity", "title", "device", "user",
                     "first_seen", "last_seen", "events", "event_ids"]
        )
    return pd.DataFrame(
        [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "title": f.title,
                "device": f.device,
                "user": f.user,
                "first_seen": f.first_seen,
                "last_seen": f.last_seen,
                "events": f.event_count,
                "event_ids": ", ".join(f.event_ids[:4])
                + ("..." if f.event_count > 4 else ""),
            }
            for f in findings
        ]
    )


__all__ = ["Evidence", "Finding", "Severity", "findings_to_frame"]
