"""The in-memory store: the same contract with no process outside this one.

This is what batch evaluation and the tests use. The experiment runner and the
incident benchmark keep their existing in-process toolboxes; this store lets a
single-process run (``ath jobs run``) exercise the exact job, attempt and revision
lifecycle that PostgreSQL provides, without a database. Nothing survives the process.
"""

from __future__ import annotations

import threading
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
)
from ath.persistence.store import (
    InvalidTransition,
    InvestigationStore,
    LeaseLost,
    NotFound,
    cancel_transition,
    claim_transition,
    finish_transition,
    lease_is_valid,
)


class InMemoryStore(InvestigationStore):
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._telemetry: dict[str, TelemetryReference] = {}
        self._incidents: dict[str, Incident] = {}
        self._jobs: dict[str, InvestigationJob] = {}
        self._attempts: dict[str, JobAttempt] = {}
        self._revisions: dict[str, list[ReportRevision]] = {}

    # -- telemetry ------------------------------------------------------------------

    def register_telemetry(self, reference: TelemetryReference) -> TelemetryReference:
        with self._lock:
            existing = self.find_telemetry(reference.digest)
            if existing is not None:
                return existing
            self._telemetry[reference.telemetry_id] = reference
            return reference

    def get_telemetry(self, telemetry_id: str) -> TelemetryReference:
        with self._lock:
            return self._require(self._telemetry, telemetry_id, "telemetry reference")

    def find_telemetry(self, digest: str) -> TelemetryReference | None:
        with self._lock:
            return next((r for r in self._telemetry.values() if r.digest == digest), None)

    # -- incidents ------------------------------------------------------------------

    def register_incident(self, incident: Incident) -> Incident:
        with self._lock:
            self.get_telemetry(incident.telemetry_id)
            for existing in self._incidents.values():
                if (existing.telemetry_id, existing.case_id, existing.case_sha256) == (
                    incident.telemetry_id, incident.case_id, incident.case_sha256,
                ):
                    return existing
            self._incidents[incident.incident_id] = incident
            return incident

    def get_incident(self, incident_id: str) -> Incident:
        with self._lock:
            return self._require(self._incidents, incident_id, "incident")

    def list_incidents(self, telemetry_id: str | None = None) -> list[Incident]:
        with self._lock:
            found = [i for i in self._incidents.values() if telemetry_id in (None, i.telemetry_id)]
            return sorted(found, key=lambda i: (i.created_at, i.incident_id))

    # -- jobs -----------------------------------------------------------------------

    def enqueue_job(self, job: InvestigationJob) -> InvestigationJob:
        with self._lock:
            self.get_incident(job.incident_id)
            if job.job_id in self._jobs:
                raise InvalidTransition(f"job {job.job_id} already exists")
            if job.status is not JobStatus.QUEUED or job.attempts_made:
                raise InvalidTransition("only a fresh queued job can be enqueued")
            self._jobs[job.job_id] = job
            return job

    def get_job(self, job_id: str) -> InvestigationJob:
        with self._lock:
            return self._require(self._jobs, job_id, "job")

    def list_jobs(self, status: JobStatus | None = None,
                  incident_id: str | None = None) -> list[InvestigationJob]:
        with self._lock:
            found = [
                j for j in self._jobs.values()
                if status in (None, j.status) and incident_id in (None, j.incident_id)
            ]
            # A stable sort over insertion order: jobs enqueued in one instant keep
            # the order they arrived in, exactly as the PostgreSQL sequence does.
            return sorted(found, key=lambda j: j.created_at)

    def claim_job(self, worker_id: str, lease_seconds: float,
                  now: datetime | None = None) -> tuple[InvestigationJob, JobAttempt] | None:
        now = self._now(now)
        with self._lock:
            self.expire_leases(now)
            queued = self.list_jobs(JobStatus.QUEUED)
            if not queued:
                return None
            job, attempt = claim_transition(queued[0], worker_id, lease_seconds, now)
            self._jobs[job.job_id] = job
            self._attempts[attempt.attempt_id] = attempt
            return job, attempt

    def heartbeat(self, attempt_id: str, worker_id: str, lease_seconds: float,
                  now: datetime | None = None) -> bool:
        now = self._now(now)
        with self._lock:
            attempt = self._attempts.get(attempt_id)
            if attempt is None:
                return False
            job = self._jobs[attempt.job_id]
            if not lease_is_valid(job, attempt, worker_id, now):
                return False
            self._jobs[job.job_id] = replace(
                job, lease_expires_at=now + timedelta(seconds=lease_seconds), updated_at=now,
            )
            self._attempts[attempt_id] = replace(attempt, heartbeat_at=now)
            return True

    def finish_attempt(
        self, attempt_id: str, worker_id: str, outcome: AttemptOutcome, *,
        retryable: bool = True, state: dict[str, Any] | None = None, run_id: str | None = None,
        error: str | None = None, report: dict[str, Any] | None = None, markdown: str | None = None,
        now: datetime | None = None,
    ) -> InvestigationJob:
        with self._lock:
            now = self._now(now)
            attempt = self._require(self._attempts, attempt_id, "attempt")
            job = self._jobs[attempt.job_id]
            if not lease_is_valid(job, attempt, worker_id, now):
                raise LeaseLost(f"attempt {attempt_id} is not owned by {worker_id!r}")
            job, attempt = finish_transition(
                job, attempt, outcome, now, retryable=retryable, state=state, run_id=run_id, error=error,
            )
            revision = None
            if report is not None:
                revision = ReportRevision.create(
                    job.job_id, attempt_id, len(self._revisions.get(job.job_id, ())) + 1,
                    report, markdown or "", now,
                )
            self._jobs[job.job_id] = job
            self._attempts[attempt_id] = attempt
            if revision is not None:
                self._revisions.setdefault(job.job_id, []).append(revision)
            return job

    def expire_leases(self, now: datetime | None = None) -> list[JobAttempt]:
        now = self._now(now)
        lapsed: list[JobAttempt] = []
        with self._lock:
            for job in self.list_jobs(JobStatus.RUNNING):
                if job.lease_expires_at is None or job.lease_expires_at > now:
                    continue
                attempt = self._running_attempt(job.job_id)
                job, attempt = finish_transition(
                    job, attempt, AttemptOutcome.EXPIRED, now, error="lease expired",
                )
                self._jobs[job.job_id] = job
                self._attempts[attempt.attempt_id] = attempt
                lapsed.append(attempt)
        return lapsed

    def cancel_job(self, job_id: str, now: datetime | None = None) -> InvestigationJob:
        now = self._now(now)
        with self._lock:
            job = self.get_job(job_id)
            attempt = self._running_attempt(job_id) if job.status is JobStatus.RUNNING else None
            job, attempt = cancel_transition(job, attempt, now)
            self._jobs[job_id] = job
            if attempt is not None:
                self._attempts[attempt.attempt_id] = attempt
            return job

    def get_attempt(self, attempt_id: str) -> JobAttempt:
        with self._lock:
            return self._require(self._attempts, attempt_id, "attempt")

    def list_attempts(self, job_id: str) -> list[JobAttempt]:
        with self._lock:
            return sorted((a for a in self._attempts.values() if a.job_id == job_id),
                          key=lambda a: a.number)

    # -- reports --------------------------------------------------------------------

    def add_report_revision(self, job_id: str, attempt_id: str, report: dict[str, Any],
                            markdown: str, now: datetime | None = None) -> ReportRevision:
        with self._lock:
            self.get_job(job_id)
            attempt = self.get_attempt(attempt_id)
            if attempt.job_id != job_id:
                raise InvalidTransition("attempt belongs to a different job")
            return self._append_revision(job_id, attempt_id, report, markdown, self._now(now))

    def list_report_revisions(self, job_id: str) -> list[ReportRevision]:
        with self._lock:
            return list(self._revisions.get(job_id, ()))

    # -- internals ------------------------------------------------------------------

    def _append_revision(self, job_id: str, attempt_id: str, report: dict[str, Any],
                         markdown: str, now: datetime) -> ReportRevision:
        revisions = self._revisions.setdefault(job_id, [])
        revision = ReportRevision.create(job_id, attempt_id, len(revisions) + 1, report, markdown, now)
        revisions.append(revision)
        return revision

    def _running_attempt(self, job_id: str) -> JobAttempt:
        for attempt in self._attempts.values():
            if attempt.job_id == job_id and attempt.outcome is AttemptOutcome.RUNNING:
                return attempt
        raise InvalidTransition(f"running job {job_id} has no running attempt")

    @staticmethod
    def _require(table: dict[str, Any], key: str, kind: str) -> Any:
        try:
            return table[key]
        except KeyError:
            raise NotFound(f"{kind} {key!r} not found") from None


__all__ = ["InMemoryStore"]
