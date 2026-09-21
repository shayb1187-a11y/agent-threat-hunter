"""The Behavior: a deterministic description of observed activity, without judgement.

Why a behavior is not a finding
-------------------------------
A :class:`~ath.hunting.finding.Finding` answers *"why is this suspicious?"*. A
:class:`Behavior` answers only *"what happened?"*, and the separation is load-bearing
rather than tidy-minded.

``remote_interactive_logon`` is usually an administrator doing their job.
``local_account_created`` is usually onboarding. ``recovery_mechanism_disabled`` is
occasionally a genuine restore operation. A layer that only emitted the alarming ones
would be a rule engine wearing a new name -- and, more importantly, it could never
support *benign* explanation, which is half of what hypothesis reasoning needs. You
cannot argue that an intrusion has an innocent reading if the only vocabulary available
describes intrusions.

So a Behavior carries **no severity and no ``is_suspicious`` flag**, and a test asserts
that no such attribute is ever added. Suspicion is a judgement made by consumers, against
context the behavior layer deliberately does not have.

Computed once, consumed everywhere
-----------------------------------
The reason this package exists at all is a measured failure. Inter-arrival regularity
was computed inside ``analyse_beacon``, in the investigation layer, which only runs
*after* a case is formed -- so triage, which decides whether to reassure an analyst,
could not see it. Four regular TLS connections to a popular destination were returned as
``likely_benign``. One deterministic computation existed in exactly one place, and the
layer that most needed it was not that place.

Behaviors and their features are therefore computed once, deterministically, from
telemetry alone, and read by detection, triage, correlation, the agent and the report.

Dependency direction
--------------------
``telemetry -> behavior -> {detection, triage, correlation, agent}``, one way only.
This package must stay importable and computable without the hunting, triage or agent
layers; :func:`tests.test_behavior.test_import_direction` enforces it. That is why the
:class:`~ath.channels.TelemetryChannel` vocabulary lives at the top level rather than
inside :mod:`ath.environment`, which cannot be imported without pulling in hunting.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ath.channels import TelemetryChannel

# Behavior type names, declared as constants so a typo is an ImportError rather than a
# behavior nobody ever matches on. Named for what was observed, never for what it might
# mean: `recovery_mechanism_disabled`, not `ransomware_preparation`.
INTERPRETER_EXTERNAL_CONTACT = "interpreter_external_contact"
PERIODIC_OUTBOUND_RELATIONSHIP = "periodic_outbound_relationship"
FIRST_SEEN_PROCESS_DESTINATION = "first_seen_process_destination_relationship"
RECOVERY_MECHANISM_DISABLED = "recovery_mechanism_disabled"
SECURITY_TOOL_CONFIGURATION_MODIFIED = "security_tool_configuration_modified"
TELEMETRY_HEALTH_CHANGE = "telemetry_health_change"

BEHAVIOR_TYPES: tuple[str, ...] = (
    INTERPRETER_EXTERNAL_CONTACT,
    PERIODIC_OUTBOUND_RELATIONSHIP,
    FIRST_SEEN_PROCESS_DESTINATION,
    RECOVERY_MECHANISM_DISABLED,
    SECURITY_TOOL_CONFIGURATION_MODIFIED,
    TELEMETRY_HEALTH_CHANGE,
)


class BehaviorError(ValueError):
    """Raised when a behavior would be constructed without real evidence."""


@dataclass(frozen=True)
class Behavior:
    """One deterministic, evidence-backed description of observed activity.

    Attributes:
        behavior_id: Stable identifier, derived from type and earliest evidence so it
            cannot disagree with what it describes.
        behavior_type: One of :data:`BEHAVIOR_TYPES`.
        start_time / end_time: Window the behavior spans.
        entities: The things involved -- ``{"host": ..., "user": ..., "process": ...}``.
            A mapping rather than fixed fields because a cloud behavior has a principal
            and no host, and forcing one shape onto both is how the schema became
            Windows-shaped in the first place.
        evidence_ids: Real telemetry event ids. Validated non-empty at construction,
            exactly as ``Finding`` does -- there is no code path to an unevidenced
            behavior.
        fields_used: Telemetry fields this behavior was derived from. Same contract as
            ``Finding.fields_used``, so capability-based eligibility works identically
            over behaviors.
        required_channels: Channels this behavior cannot be observed without.
        observations: Deterministic measurements only. Numbers and facts, never
            conclusions.
        baseline_context: What the environment already knew, when known.
    """

    behavior_id: str
    behavior_type: str
    start_time: datetime
    end_time: datetime
    entities: Mapping[str, str] = field(default_factory=dict)
    evidence_ids: tuple[str, ...] = ()
    fields_used: tuple[str, ...] = ()
    required_channels: frozenset[TelemetryChannel] = frozenset()
    observations: Mapping[str, Any] = field(default_factory=dict)
    baseline_context: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if not self.evidence_ids:
            raise BehaviorError(
                f"{self.behavior_type}: a Behavior must cite at least one event. "
                "An unevidenced behavior is an assertion, not an observation."
            )
        if self.behavior_type not in BEHAVIOR_TYPES:
            raise BehaviorError(
                f"Unknown behavior_type {self.behavior_type!r}; "
                f"expected one of {BEHAVIOR_TYPES}"
            )
        if self.end_time < self.start_time:
            raise BehaviorError(
                f"{self.behavior_type}: end_time precedes start_time"
            )

    @property
    def duration_seconds(self) -> float:
        return (self.end_time - self.start_time).total_seconds()

    @property
    def event_count(self) -> int:
        return len(self.evidence_ids)

    def entity(self, kind: str) -> str:
        """Return one entity, or an empty string when this behavior has no such role."""
        return self.entities.get(kind, "")

    def to_dict(self) -> dict[str, Any]:
        return {
            "behavior_id": self.behavior_id,
            "behavior_type": self.behavior_type,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "entities": dict(self.entities),
            "evidence_ids": list(self.evidence_ids),
            "fields_used": list(self.fields_used),
            "required_channels": sorted(c.value for c in self.required_channels),
            "observations": _jsonable(self.observations),
            "baseline_context": (
                _jsonable(self.baseline_context)
                if self.baseline_context is not None else None
            ),
        }

    def __str__(self) -> str:
        who = ", ".join(f"{k}={v}" for k, v in sorted(self.entities.items()))
        return f"{self.behavior_type}({who}) [{self.event_count} events]"


def make_behavior_id(behavior_type: str, evidence_ids: tuple[str, ...]) -> str:
    """Derive a stable id from what the behavior actually rests on.

    Derived rather than stored, for the same reason ``Finding.finding_id`` is: an id
    that is assigned independently can drift from the evidence it names.
    """
    if not evidence_ids:
        raise BehaviorError("cannot derive a behavior id with no evidence")
    return f"{behavior_type}:{min(evidence_ids)}"


def _jsonable(value: Any) -> Any:
    """Recursively convert measurements into plain JSON-safe types."""
    from datetime import timedelta

    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if isinstance(value, timedelta):
        return value.total_seconds()
    if isinstance(value, datetime):
        return value.isoformat()
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if hasattr(value, "item") and not isinstance(value, (str, bytes)):
        try:
            return value.item()
        except (AttributeError, ValueError):
            return str(value)
    return value
