"""Durable records for operational investigations.

What is recorded, and what deliberately is not
-----------------------------------------------
A :class:`TelemetryReference` names a corpus by its location and a content digest; the
rows stay where the loader reads them. An :class:`Incident` pins one correlated case to
one telemetry reference by the canonical hash of the case the correlator produced, so a
later worker can prove it re-derived the same case before investigating it. An
:class:`InvestigationJob` is the durable request; each :class:`JobAttempt` is one
worker's execution of it, with the serialised investigation state as its audit record;
a :class:`ReportRevision` is one rendered report, numbered per job and never
overwritten.

Every record serialises to JSON-safe dictionaries so the in-memory and PostgreSQL
backends carry exactly the same shape and the tests can assert on either.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return uuid4().hex


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def canonical_sha256(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def to_utc(value: datetime | str | None) -> datetime | None:
    """A timezone-aware UTC datetime from a datetime or an ISO string; naive is refused."""
    if value is None:
        return None
    stamp = datetime.fromisoformat(value) if isinstance(value, str) else value
    if stamp.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return stamp.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    """The investigation completed under its operational profile."""
    INCOMPLETE = "incomplete"
    """The investigation ran and ended without a reliable conclusion; a result, not a fault."""
    FAILED = "failed"
    """No attempt could execute the investigation and the retry allowance is spent."""
    CANCELLED = "cancelled"

    @property
    def terminal(self) -> bool:
        return self in (JobStatus.COMPLETE, JobStatus.INCOMPLETE, JobStatus.FAILED, JobStatus.CANCELLED)


class AttemptOutcome(str, Enum):
    RUNNING = "running"
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    FAILED = "failed"
    """The attempt raised or could not reproduce its inputs."""
    EXPIRED = "expired"
    """The worker stopped heartbeating; its lease lapsed and the job was requeued."""
    CANCELLED = "cancelled"

    @property
    def terminal(self) -> bool:
        return self is not AttemptOutcome.RUNNING


@dataclass(frozen=True)
class TelemetryReference:
    """Where a corpus lives and what its content hashed to when it was registered."""

    telemetry_id: str
    location: str
    digest: str
    digest_version: int
    row_counts: dict[str, int]
    registered_at: datetime

    def __post_init__(self) -> None:
        if not self.digest or not self.location:
            raise ValueError("a telemetry reference needs a location and a digest")
        object.__setattr__(self, "registered_at", to_utc(self.registered_at))

    @classmethod
    def create(cls, location: str, digest: str, digest_version: int, row_counts: dict[str, int],
               now: datetime | None = None) -> TelemetryReference:
        return cls(new_id(), location, digest, digest_version, dict(row_counts), now or utcnow())

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "registered_at": _iso(self.registered_at)}

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> TelemetryReference:
        return cls(**payload)


@dataclass(frozen=True)
class Incident:
    """One correlated case, pinned to the telemetry it was derived from."""

    incident_id: str
    telemetry_id: str
    case_id: str
    case_sha256: str
    case: dict[str, Any]
    created_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "created_at", to_utc(self.created_at))

    @classmethod
    def create(cls, telemetry_id: str, case_payload: dict[str, Any], now: datetime | None = None) -> Incident:
        return cls(new_id(), telemetry_id, case_payload["case_id"], canonical_sha256(case_payload),
                   case_payload, now or utcnow())

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "created_at": _iso(self.created_at)}

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Incident:
        return cls(**payload)


@dataclass(frozen=True)
class InvestigationJob:
    """A durable request to investigate one incident under one operational profile."""

    job_id: str
    incident_id: str
    profile: dict[str, Any]
    profile_sha256: str
    model_requested: bool
    status: JobStatus
    max_attempts: int
    retry_incomplete: bool
    attempts_made: int
    created_at: datetime
    updated_at: datetime
    lease_owner: str | None = None
    lease_expires_at: datetime | None = None
    last_error: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.max_attempts, bool) or not isinstance(self.max_attempts, int) or self.max_attempts < 1:
            raise ValueError("max_attempts must be a positive integer")
        object.__setattr__(self, "status", JobStatus(self.status))
        for name in ("created_at", "updated_at", "lease_expires_at"):
            object.__setattr__(self, name, to_utc(getattr(self, name)))

    @classmethod
    def create(cls, incident_id: str, profile: dict[str, Any], profile_sha256: str, *,
               model_requested: bool, max_attempts: int = 3, retry_incomplete: bool = False,
               now: datetime | None = None) -> InvestigationJob:
        stamp = now or utcnow()
        return cls(new_id(), incident_id, dict(profile), profile_sha256, bool(model_requested),
                   JobStatus.QUEUED, max_attempts, bool(retry_incomplete), 0, stamp, stamp)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["status"] = self.status.value
        for name in ("created_at", "updated_at", "lease_expires_at"):
            payload[name] = _iso(getattr(self, name))
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> InvestigationJob:
        return cls(**payload)


@dataclass(frozen=True)
class JobAttempt:
    """One worker's execution of a job; ``state`` is the investigation's audit record."""

    attempt_id: str
    job_id: str
    number: int
    worker_id: str
    outcome: AttemptOutcome
    started_at: datetime
    heartbeat_at: datetime
    finished_at: datetime | None = None
    run_id: str | None = None
    state: dict[str, Any] | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "outcome", AttemptOutcome(self.outcome))
        for name in ("started_at", "heartbeat_at", "finished_at"):
            object.__setattr__(self, name, to_utc(getattr(self, name)))

    @classmethod
    def start(cls, job_id: str, number: int, worker_id: str, now: datetime) -> JobAttempt:
        return cls(new_id(), job_id, number, worker_id, AttemptOutcome.RUNNING, now, now)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["outcome"] = self.outcome.value
        for name in ("started_at", "heartbeat_at", "finished_at"):
            payload[name] = _iso(getattr(self, name))
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> JobAttempt:
        return cls(**payload)


@dataclass(frozen=True)
class ReportRevision:
    """One rendered report for a job. Revisions are appended, never rewritten."""

    revision_id: str
    job_id: str
    attempt_id: str
    revision: int
    report: dict[str, Any]
    markdown: str
    sha256: str
    created_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "created_at", to_utc(self.created_at))

    @classmethod
    def create(cls, job_id: str, attempt_id: str, revision: int, report: dict[str, Any],
               markdown: str, now: datetime) -> ReportRevision:
        digest = canonical_sha256({"report": report, "markdown": markdown})
        return cls(new_id(), job_id, attempt_id, revision, report, markdown, digest, now)

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "created_at": _iso(self.created_at)}

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> ReportRevision:
        return cls(**payload)


__all__ = [
    "AttemptOutcome", "Incident", "InvestigationJob", "JobAttempt", "JobStatus",
    "ReportRevision", "TelemetryReference", "canonical_json", "canonical_sha256",
    "new_id", "to_utc", "utcnow",
]
