"""The storage contract, and the job-lifecycle rules both backends apply verbatim.

Why the rules live here
-----------------------
A lease, a retry allowance and a terminal status are easy to implement slightly
differently twice. :func:`claim_transition`, :func:`finish_transition` and
:func:`cancel_transition` are pure functions over the records; the in-memory store
applies them under a lock and the PostgreSQL store applies them inside a transaction
on rows it has locked. The behaviour a test observes on one backend is the behaviour
the other has by construction.

What a store guarantees
-----------------------
* A queued job is claimed by at most one worker at a time. The claim carries a lease;
  a worker that stops heartbeating loses it, and :meth:`InvestigationStore.expire_leases`
  requeues the job while recording the lapsed attempt.
* Only the lease owner can heartbeat or finish an attempt. A late worker whose lease
  was reassigned gets :class:`LeaseLost`, never a silent overwrite.
* Faults retry up to ``max_attempts``; an *incomplete* investigation is a recorded
  result and retries only when the job opted in.
* A report revision is written in the same transaction as the attempt that produced
  it, so a job cannot show a finished attempt without its report or a report without
  its attempt.

What it does not guarantee: preemption of a running attempt (a hung worker holds the
lease until it lapses), exactly-once execution (a worker that finishes after its lease
lapsed has done the work twice; the second result is refused), or that a stored state
can be resumed mid-investigation. Attempts restart from the beginning.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any

from ath.persistence.models import (
    AttemptOutcome,
    Incident,
    InvestigationJob,
    JobAttempt,
    JobStatus,
    ReportRevision,
    TelemetryReference,
    utcnow,
)


class StoreError(Exception):
    """Base class for storage failures the caller can act on."""


class NotFound(StoreError):
    pass


class LeaseLost(StoreError):
    """The attempt is no longer owned by this worker (lease lapsed, reassigned or cancelled)."""


class InvalidTransition(StoreError):
    pass


# -- pure lifecycle rules ---------------------------------------------------------------


def claim_transition(job: InvestigationJob, worker_id: str, lease_seconds: float,
                     now: datetime) -> tuple[InvestigationJob, JobAttempt]:
    if job.status is not JobStatus.QUEUED:
        raise InvalidTransition(f"job {job.job_id} is {job.status.value}, not queued")
    if not worker_id or lease_seconds <= 0:
        raise ValueError("a claim needs a worker id and a positive lease")
    number = job.attempts_made + 1
    claimed = replace(
        job, status=JobStatus.RUNNING, attempts_made=number, lease_owner=worker_id,
        lease_expires_at=now + timedelta(seconds=lease_seconds), updated_at=now,
    )
    return claimed, JobAttempt.start(job.job_id, number, worker_id, now)


def finish_transition(
    job: InvestigationJob, attempt: JobAttempt, outcome: AttemptOutcome, now: datetime, *,
    retryable: bool = True, state: dict[str, Any] | None = None, run_id: str | None = None,
    error: str | None = None,
) -> tuple[InvestigationJob, JobAttempt]:
    """The job and attempt after ``attempt`` ends with ``outcome``.

    ``retryable`` applies to :attr:`AttemptOutcome.FAILED` only: an attempt that could
    not reproduce its inputs (telemetry content moved, case no longer derivable) has no
    reason to expect a different result and marks the job failed at once.
    """
    if attempt.outcome is not AttemptOutcome.RUNNING:
        raise InvalidTransition(f"attempt {attempt.attempt_id} already ended ({attempt.outcome.value})")
    if outcome is AttemptOutcome.RUNNING:
        raise InvalidTransition("an attempt cannot finish as running")
    remaining = job.attempts_made < job.max_attempts
    if outcome is AttemptOutcome.COMPLETE:
        status = JobStatus.COMPLETE
    elif outcome is AttemptOutcome.INCOMPLETE:
        status = JobStatus.QUEUED if job.retry_incomplete and remaining else JobStatus.INCOMPLETE
    elif outcome is AttemptOutcome.CANCELLED:
        status = JobStatus.CANCELLED
    else:  # FAILED or EXPIRED
        retry = remaining and (retryable or outcome is AttemptOutcome.EXPIRED)
        status = JobStatus.QUEUED if retry else JobStatus.FAILED
    ended = replace(
        attempt, outcome=outcome, finished_at=now, heartbeat_at=now, state=state,
        run_id=run_id, error=error,
    )
    updated = replace(
        job, status=status, lease_owner=None, lease_expires_at=None, updated_at=now,
        last_error=error if error is not None else job.last_error,
    )
    return updated, ended


def cancel_transition(job: InvestigationJob, attempt: JobAttempt | None,
                      now: datetime) -> tuple[InvestigationJob, JobAttempt | None]:
    if job.status.terminal:
        raise InvalidTransition(f"job {job.job_id} is already {job.status.value}")
    if job.status is JobStatus.RUNNING:
        if attempt is None:
            raise InvalidTransition(f"running job {job.job_id} has no running attempt")
        return finish_transition(job, attempt, AttemptOutcome.CANCELLED, now)
    return replace(job, status=JobStatus.CANCELLED, updated_at=now), None


def lease_is_valid(job: InvestigationJob, attempt: JobAttempt, worker_id: str, now: datetime) -> bool:
    return (
        job.status is JobStatus.RUNNING
        and attempt.outcome is AttemptOutcome.RUNNING
        and job.lease_owner == worker_id
        and attempt.worker_id == worker_id
        and job.lease_expires_at is not None
        and job.lease_expires_at > now
    )


# -- the contract -------------------------------------------------------------------------


class InvestigationStore(ABC):
    """Durable state for operational investigations. Methods are atomic per call."""

    # telemetry references

    @abstractmethod
    def register_telemetry(self, reference: TelemetryReference) -> TelemetryReference:
        """Record a corpus. Registering the same digest again returns the first record."""

    @abstractmethod
    def get_telemetry(self, telemetry_id: str) -> TelemetryReference: ...

    @abstractmethod
    def find_telemetry(self, digest: str) -> TelemetryReference | None: ...

    # incidents

    @abstractmethod
    def register_incident(self, incident: Incident) -> Incident:
        """Record a case. The same case hash on the same telemetry returns the first record."""

    @abstractmethod
    def get_incident(self, incident_id: str) -> Incident: ...

    @abstractmethod
    def list_incidents(self, telemetry_id: str | None = None) -> list[Incident]: ...

    # jobs and attempts

    @abstractmethod
    def enqueue_job(self, job: InvestigationJob) -> InvestigationJob: ...

    @abstractmethod
    def get_job(self, job_id: str) -> InvestigationJob: ...

    @abstractmethod
    def list_jobs(self, status: JobStatus | None = None,
                  incident_id: str | None = None) -> list[InvestigationJob]: ...

    @abstractmethod
    def claim_job(self, worker_id: str, lease_seconds: float,
                  now: datetime | None = None) -> tuple[InvestigationJob, JobAttempt] | None:
        """Lease the oldest queued job to ``worker_id``, or ``None`` when nothing waits."""

    @abstractmethod
    def heartbeat(self, attempt_id: str, worker_id: str, lease_seconds: float,
                  now: datetime | None = None) -> bool:
        """Extend the lease. ``False`` means the lease is gone and the result will be refused."""

    @abstractmethod
    def finish_attempt(
        self, attempt_id: str, worker_id: str, outcome: AttemptOutcome, *,
        retryable: bool = True, state: dict[str, Any] | None = None, run_id: str | None = None,
        error: str | None = None, report: dict[str, Any] | None = None, markdown: str | None = None,
        now: datetime | None = None,
    ) -> InvestigationJob:
        """End the attempt, and store its report revision in the same transaction.

        Raises :class:`LeaseLost` when ``worker_id`` no longer owns the attempt.
        """

    @abstractmethod
    def expire_leases(self, now: datetime | None = None) -> list[JobAttempt]:
        """Requeue running jobs whose lease lapsed; the lapsed attempts are returned."""

    @abstractmethod
    def cancel_job(self, job_id: str, now: datetime | None = None) -> InvestigationJob: ...

    @abstractmethod
    def get_attempt(self, attempt_id: str) -> JobAttempt: ...

    @abstractmethod
    def list_attempts(self, job_id: str) -> list[JobAttempt]: ...

    # report revisions

    @abstractmethod
    def add_report_revision(self, job_id: str, attempt_id: str, report: dict[str, Any],
                            markdown: str, now: datetime | None = None) -> ReportRevision: ...

    @abstractmethod
    def list_report_revisions(self, job_id: str) -> list[ReportRevision]: ...

    def latest_report(self, job_id: str) -> ReportRevision | None:
        revisions = self.list_report_revisions(job_id)
        return revisions[-1] if revisions else None

    # helpers shared by backends

    @staticmethod
    def _now(now: datetime | None) -> datetime:
        return now or utcnow()


__all__ = [
    "InvalidTransition", "InvestigationStore", "LeaseLost", "NotFound", "StoreError",
    "cancel_transition", "claim_transition", "finish_transition", "lease_is_valid",
]
