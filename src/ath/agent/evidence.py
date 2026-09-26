"""Small, deterministic predicates over cited telemetry, never free-text entailment."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

import pandas as pd

from ath.instance_identity import scheme_of
from ath.telemetry.loader import Telemetry


class AssertionKind(str, Enum):
    AUTH_OUTCOME = "auth_outcome"
    PROCESS_IDENTITY = "process_identity"
    SAME_PROCESS = "same_process"
    PARENT_CHILD = "parent_child"
    BEFORE = "before"
    # Operational-v6: a recorded control-plane action. Never offered to the v2 schema,
    # whose kind list is pinned to the five kinds above (see structured.V2_ASSERTION_KINDS).
    CONTROL_ACTION = "control_action"


@dataclass(frozen=True)
class EvidenceAssertion:
    """Unary observation or directed relationship; event_id is the parent/earlier side."""

    kind: AssertionKind
    event_id: str
    other_event_id: str = ""
    expected: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.kind, AssertionKind):
            raise ValueError("kind must be an AssertionKind")
        if any(not isinstance(v, str) for v in (self.event_id, self.other_event_id, self.expected)):
            raise ValueError("assertion identifiers and expected value must be strings")
        if not self.event_id.strip() or len(self.event_id) > 512:
            raise ValueError("event_id must be nonempty and at most 512 characters")
        if len(self.other_event_id) > 512 or len(self.expected) > 512:
            raise ValueError("assertion values must be at most 512 characters")
        unary = self.kind in (AssertionKind.AUTH_OUTCOME, AssertionKind.PROCESS_IDENTITY,
                              AssertionKind.CONTROL_ACTION)
        if unary and (self.other_event_id or not self.expected):
            raise ValueError("unary assertions require expected and no other_event_id")
        if not unary and (not self.other_event_id.strip() or self.expected):
            raise ValueError("relationship assertions require other_event_id and no expected")
        if self.kind is AssertionKind.AUTH_OUTCOME and self.expected not in ("success", "failure"):
            raise ValueError("auth_outcome expected must be success or failure")
        if self.kind is AssertionKind.PROCESS_IDENTITY and not _identity(self.expected):
            raise ValueError("process_identity requires a recognized source-qualified identity")
        if self.kind is AssertionKind.CONTROL_ACTION and len(self.expected.split()) != 2:
            raise ValueError("control_action expected must be '<verb> <resource type>'")

    @property
    def event_ids(self) -> tuple[str, ...]:
        return (self.event_id, self.other_event_id) if self.other_event_id else (self.event_id,)

    def to_dict(self) -> dict:
        return {"kind": self.kind.value, "event_id": self.event_id,
                **({"other_event_id": self.other_event_id} if self.other_event_id else {}),
                **({"expected": self.expected} if self.expected else {})}

    @classmethod
    def from_dict(cls, payload: object) -> EvidenceAssertion:
        if not isinstance(payload, dict) or set(payload) - {"kind", "event_id", "other_event_id", "expected"}:
            raise ValueError("invalid assertion object or unknown assertion field")
        try:
            return cls(kind=AssertionKind(payload["kind"]), event_id=payload["event_id"],
                       other_event_id=payload.get("other_event_id", ""), expected=payload.get("expected", ""))
        except (KeyError, TypeError) as exc:
            raise ValueError("assertion requires kind and event_id") from exc

    def render(self) -> str:
        if self.kind is AssertionKind.AUTH_OUTCOME:
            return f"Authentication event {self.event_id} records outcome {self.expected}."
        if self.kind is AssertionKind.PROCESS_IDENTITY:
            return f"Event {self.event_id} records process identity {self.expected}."
        if self.kind is AssertionKind.CONTROL_ACTION:
            verb, resource = self.expected.split()
            return f"Control event {self.event_id} records the action {verb} on {resource}."
        if self.kind is AssertionKind.SAME_PROCESS:
            return f"Events {self.event_id} and {self.other_event_id} identify the same process instance."
        if self.kind is AssertionKind.PARENT_CHILD:
            return f"Process event {self.other_event_id} identifies the instance in {self.event_id} as its parent."
        return f"Event {self.event_id} precedes {self.other_event_id} by recorded timestamp; this does not establish causation."


class EvidenceStatus(str, Enum):
    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    UNVERIFIABLE = "unverifiable"


@dataclass(frozen=True)
class EvidenceCheck:
    assertion: EvidenceAssertion
    status: EvidenceStatus
    reason: str

    def to_dict(self) -> dict:
        return {"assertion": self.assertion.to_dict(), "status": self.status.value, "reason": self.reason}


def _text(value: object) -> str:
    return "" if value is None or pd.isna(value) else str(value).strip()


def _identity(value: object) -> str:
    text = _text(value)
    return text if scheme_of(text) and text.partition(":")[2] else ""


def _stamp(value: object) -> pd.Timestamp | None:
    try:
        stamp = pd.Timestamp(value)
    except (TypeError, ValueError):
        return None
    return None if pd.isna(stamp) or stamp.tzinfo is None else stamp


class EvidenceVerifier:
    """Resolve IDs without choosing an arbitrary duplicate, then evaluate predicates.

    Input telemetry must remain unchanged during the investigation. Indexes contain
    IDs only; payload rows are read on demand, not copied into another whole corpus.
    """

    def __init__(self, telemetry: Telemetry):
        self.tables = tuple((frame, pd.Index(frame["event_id"])) for frame in (
            telemetry.processes, telemetry.network, telemetry.logons, telemetry.controls,
        ))

    def row(self, event_id: str) -> tuple[dict | None, str]:
        matches = []
        for frame, index in self.tables:
            positions = index.get_indexer_for([event_id])
            matches.extend(frame.iloc[int(pos)].to_dict() for pos in positions if pos >= 0)
        if len(matches) != 1:
            return None, "event ID is missing" if not matches else "event ID is ambiguous (duplicate records)"
        return matches[0], ""

    def check(self, assertion: EvidenceAssertion) -> EvidenceCheck:
        def result(status: EvidenceStatus, reason: str) -> EvidenceCheck:
            return EvidenceCheck(assertion, status, reason)

        yes, no, unknown = EvidenceStatus.SUPPORTED, EvidenceStatus.CONTRADICTED, EvidenceStatus.UNVERIFIABLE
        rows = []
        for event_id in assertion.event_ids:
            row, reason = self.row(event_id)
            if row is None:
                return result(unknown, f"{event_id}: {reason}")
            rows.append(row)
        left = rows[0]
        kind = assertion.kind
        if kind is AssertionKind.AUTH_OUTCOME:
            if left["event_type"] != "logon":
                return result(no, "cited event is not an authentication event")
            actual = _text(left.get("action"))
            if actual not in ("success", "failure"):
                return result(unknown, "authentication outcome is missing or not normalized")
            return result(yes if actual == assertion.expected else no, f"recorded authentication outcome: {actual}")
        if kind is AssertionKind.CONTROL_ACTION:
            if left["event_type"] != "control":
                return result(no, "cited event is not a control-plane event")
            verb, resource = _text(left.get("verb")), _text(left.get("resource_type"))
            if not verb or not resource:
                return result(unknown, "control-plane action is missing its verb or resource type")
            actual = f"{verb} {resource}"
            return result(yes if actual == assertion.expected else no, f"recorded control-plane action: {actual}")
        if kind is AssertionKind.PROCESS_IDENTITY:
            if left["event_type"] not in ("process", "network"):
                return result(no, "event does not describe a process instance")
            actual = _identity(left.get("process_guid"))
            if not actual or scheme_of(actual) != scheme_of(assertion.expected):
                return result(unknown, "process identity is missing or from a different authority")
            return result(yes if actual == assertion.expected else no, f"recorded process identity: {actual}")
        right = rows[1]
        if assertion.event_id == assertion.other_event_id and kind is not AssertionKind.SAME_PROCESS:
            return result(no, "a directed relationship requires distinct events")
        if kind is AssertionKind.BEFORE:
            first, second = _stamp(left.get("timestamp")), _stamp(right.get("timestamp"))
            if first is None or second is None:
                return result(unknown, "ordering requires two timezone-aware timestamps")
            return result(yes if first < second else no,
                          f"recorded times: {first.isoformat()} and {second.isoformat()}; no causal claim")
        allowed = ("process",) if kind is AssertionKind.PARENT_CHILD else ("process", "network")
        if left["event_type"] not in allowed or right["event_type"] not in allowed:
            return result(no, "event types do not support this process relationship")
        host_left, host_right = _text(left.get("device")), _text(right.get("device"))
        if not host_left or not host_right:
            return result(unknown, "process relationship requires both host identities")
        if host_left != host_right:
            return result(no, "process instances belong to different hosts")
        right_field = "parent_process_guid" if kind is AssertionKind.PARENT_CHILD else "process_guid"
        first, second = _identity(left.get("process_guid")), _identity(right.get(right_field))
        if not first or not second or scheme_of(first) != scheme_of(second):
            return result(unknown, "source-qualified identities are absent or incomparable; PID equality is insufficient")
        if first != second:
            return result(no, "source-qualified process identities disagree")
        right_pid = "parent_process_id" if kind is AssertionKind.PARENT_CHILD else "process_id"
        pid_left, pid_right = left.get("process_id"), right.get(right_pid)
        if pd.notna(pid_left) and pd.notna(pid_right) and pid_left != pid_right:
            return result(no, "process identity matches but recorded PIDs conflict")
        if kind is AssertionKind.PARENT_CHILD:
            if first == _identity(right.get("process_guid")):
                return result(no, "a process instance cannot be its own parent")
            first_time, second_time = _stamp(left.get("timestamp")), _stamp(right.get("timestamp"))
            if first_time is None or second_time is None:
                return result(unknown, "parent-child ordering requires recorded timestamps")
            if first_time > second_time:
                return result(no, "parent process event occurs after the child")
        return result(yes, "matching source-qualified identity on the same host")
