"""The PostgreSQL store.

One connection, one transaction per call, every row a worker will change locked with
``FOR UPDATE`` first; the claim uses ``SKIP LOCKED`` so several workers polling one
queue never wait on each other or double-claim. The lifecycle rules are the pure
functions in :mod:`ath.persistence.store`; this module only reads rows, applies them,
and writes rows back.

The driver (``psycopg`` 3) is imported when a store is constructed, not when this
module is, so the package stays importable and testable without it. Install with
``pip install "agentic-threat-hunter[postgres]"``. The DSN comes from the caller
(``ATH_DATABASE_URL`` via :func:`ath.config.load_settings`); it is never logged.
"""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
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
    StoreError,
    cancel_transition,
    claim_transition,
    finish_transition,
    lease_is_valid,
)

SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS ath_schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ath_telemetry_references (
    telemetry_id   TEXT PRIMARY KEY,
    location       TEXT NOT NULL,
    digest         TEXT NOT NULL UNIQUE,
    digest_version INTEGER NOT NULL,
    row_counts     JSONB NOT NULL,
    registered_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS ath_incidents (
    incident_id  TEXT PRIMARY KEY,
    telemetry_id TEXT NOT NULL REFERENCES ath_telemetry_references(telemetry_id),
    case_id      TEXT NOT NULL,
    case_sha256  TEXT NOT NULL,
    case_payload JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL,
    UNIQUE (telemetry_id, case_id, case_sha256)
);

CREATE TABLE IF NOT EXISTS ath_investigation_jobs (
    job_id           TEXT PRIMARY KEY,
    seq              BIGSERIAL NOT NULL,
    incident_id      TEXT NOT NULL REFERENCES ath_incidents(incident_id),
    profile          JSONB NOT NULL,
    profile_sha256   TEXT NOT NULL,
    model_requested  BOOLEAN NOT NULL,
    status           TEXT NOT NULL,
    max_attempts     INTEGER NOT NULL CHECK (max_attempts >= 1),
    retry_incomplete BOOLEAN NOT NULL,
    attempts_made    INTEGER NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL,
    lease_owner      TEXT,
    lease_expires_at TIMESTAMPTZ,
    last_error       TEXT
);
CREATE INDEX IF NOT EXISTS ath_jobs_status_created ON ath_investigation_jobs (status, created_at, seq);

CREATE TABLE IF NOT EXISTS ath_job_attempts (
    attempt_id   TEXT PRIMARY KEY,
    job_id       TEXT NOT NULL REFERENCES ath_investigation_jobs(job_id),
    number       INTEGER NOT NULL,
    worker_id    TEXT NOT NULL,
    outcome      TEXT NOT NULL,
    started_at   TIMESTAMPTZ NOT NULL,
    heartbeat_at TIMESTAMPTZ NOT NULL,
    finished_at  TIMESTAMPTZ,
    run_id       TEXT,
    state        JSONB,
    error        TEXT,
    UNIQUE (job_id, number)
);

CREATE TABLE IF NOT EXISTS ath_report_revisions (
    revision_id TEXT PRIMARY KEY,
    job_id      TEXT NOT NULL REFERENCES ath_investigation_jobs(job_id),
    attempt_id  TEXT NOT NULL REFERENCES ath_job_attempts(attempt_id),
    revision    INTEGER NOT NULL,
    report      JSONB NOT NULL,
    markdown    TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    UNIQUE (job_id, revision)
);

INSERT INTO ath_schema_version (version) VALUES (1) ON CONFLICT DO NOTHING;
"""

TABLES = (
    "ath_report_revisions", "ath_job_attempts", "ath_investigation_jobs",
    "ath_incidents", "ath_telemetry_references", "ath_schema_version",
)
"""Every table this store owns, dependents first."""

_JOB_COLUMNS = (
    "job_id", "incident_id", "profile", "profile_sha256", "model_requested", "status",
    "max_attempts", "retry_incomplete", "attempts_made", "created_at", "updated_at",
    "lease_owner", "lease_expires_at", "last_error",
)
_ATTEMPT_COLUMNS = (
    "attempt_id", "job_id", "number", "worker_id", "outcome", "started_at", "heartbeat_at",
    "finished_at", "run_id", "state", "error",
)
_JSON_COLUMNS = frozenset({"row_counts", "case_payload", "profile", "state", "report"})


def _dumps(value: Any) -> str:
    return json.dumps(value, allow_nan=False, default=str)


def _driver() -> Any:
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise StoreError(
            "PostgreSQL support needs the psycopg driver: "
            "pip install \"agentic-threat-hunter[postgres]\""
        ) from exc
    return psycopg


class PostgresStore(InvestigationStore):
    def __init__(self, dsn: str, *, connect_timeout: float = 10.0) -> None:
        if not dsn:
            raise ValueError("a PostgreSQL DSN is required")
        self._psycopg = _driver()
        self._dsn = dsn
        self._connect_timeout = connect_timeout
        self._lock = threading.RLock()
        self._conn: Any = None

    # -- connection -----------------------------------------------------------------

    def _connection(self) -> Any:
        if self._conn is None or self._conn.closed or self._conn.broken:
            from psycopg.rows import dict_row

            self._conn = self._psycopg.connect(
                self._dsn, row_factory=dict_row, connect_timeout=max(1, int(self._connect_timeout)),
                autocommit=False,
            )
        return self._conn

    @contextmanager
    def _tx(self):
        with self._lock:
            conn = self._connection()
            with conn.transaction(), conn.cursor() as cur:
                yield cur

    def close(self) -> None:
        with self._lock:
            if self._conn is not None and not self._conn.closed:
                self._conn.close()
            self._conn = None

    def migrate(self) -> int:
        """Create the tables this store needs; safe to run repeatedly."""
        with self._tx() as cur:
            cur.execute(SCHEMA_SQL)
            cur.execute("SELECT max(version) AS version FROM ath_schema_version")
            return int(cur.fetchone()["version"])

    def _jsonb(self, value: Any) -> Any:
        from psycopg.types.json import Jsonb

        # jsonb rejects NaN/Infinity tokens; refuse them here, loudly, rather than let
        # the database report a syntax error deep inside a transaction.
        return None if value is None else Jsonb(value, dumps=_dumps)

    def _params(self, record: dict[str, Any]) -> dict[str, Any]:
        return {k: (self._jsonb(v) if k in _JSON_COLUMNS else v) for k, v in record.items()}

    # -- telemetry ------------------------------------------------------------------

    def register_telemetry(self, reference: TelemetryReference) -> TelemetryReference:
        with self._tx() as cur:
            cur.execute(
                "INSERT INTO ath_telemetry_references"
                " (telemetry_id, location, digest, digest_version, row_counts, registered_at)"
                " VALUES (%(telemetry_id)s, %(location)s, %(digest)s, %(digest_version)s,"
                " %(row_counts)s, %(registered_at)s) ON CONFLICT (digest) DO NOTHING",
                self._params({**reference.to_dict(), "registered_at": reference.registered_at}),
            )
            cur.execute("SELECT * FROM ath_telemetry_references WHERE digest = %s", (reference.digest,))
            return TelemetryReference.from_dict(cur.fetchone())

    def get_telemetry(self, telemetry_id: str) -> TelemetryReference:
        with self._tx() as cur:
            cur.execute("SELECT * FROM ath_telemetry_references WHERE telemetry_id = %s", (telemetry_id,))
            return TelemetryReference.from_dict(self._one(cur, "telemetry reference", telemetry_id))

    def find_telemetry(self, digest: str) -> TelemetryReference | None:
        with self._tx() as cur:
            cur.execute("SELECT * FROM ath_telemetry_references WHERE digest = %s", (digest,))
            row = cur.fetchone()
            return None if row is None else TelemetryReference.from_dict(row)

    # -- incidents ------------------------------------------------------------------

    def register_incident(self, incident: Incident) -> Incident:
        with self._tx() as cur:
            cur.execute("SELECT 1 FROM ath_telemetry_references WHERE telemetry_id = %s", (incident.telemetry_id,))
            self._one(cur, "telemetry reference", incident.telemetry_id)
            cur.execute(
                "INSERT INTO ath_incidents"
                " (incident_id, telemetry_id, case_id, case_sha256, case_payload, created_at)"
                " VALUES (%(incident_id)s, %(telemetry_id)s, %(case_id)s, %(case_sha256)s,"
                " %(case_payload)s, %(created_at)s)"
                " ON CONFLICT (telemetry_id, case_id, case_sha256) DO NOTHING",
                self._params({
                    "incident_id": incident.incident_id, "telemetry_id": incident.telemetry_id,
                    "case_id": incident.case_id, "case_sha256": incident.case_sha256,
                    "case_payload": incident.case, "created_at": incident.created_at,
                }),
            )
            cur.execute(
                "SELECT * FROM ath_incidents WHERE telemetry_id = %s AND case_id = %s AND case_sha256 = %s",
                (incident.telemetry_id, incident.case_id, incident.case_sha256),
            )
            return self._incident(cur.fetchone())

    def get_incident(self, incident_id: str) -> Incident:
        with self._tx() as cur:
            cur.execute("SELECT * FROM ath_incidents WHERE incident_id = %s", (incident_id,))
            return self._incident(self._one(cur, "incident", incident_id))

    def list_incidents(self, telemetry_id: str | None = None) -> list[Incident]:
        with self._tx() as cur:
            cur.execute(
                "SELECT * FROM ath_incidents WHERE %(t)s::text IS NULL OR telemetry_id = %(t)s"
                " ORDER BY created_at, incident_id",
                {"t": telemetry_id},
            )
            return [self._incident(row) for row in cur.fetchall()]

    # -- jobs -----------------------------------------------------------------------

    def enqueue_job(self, job: InvestigationJob) -> InvestigationJob:
        if job.status is not JobStatus.QUEUED or job.attempts_made:
            raise InvalidTransition("only a fresh queued job can be enqueued")
        with self._tx() as cur:
            cur.execute("SELECT 1 FROM ath_incidents WHERE incident_id = %s", (job.incident_id,))
            self._one(cur, "incident", job.incident_id)
            cur.execute("SELECT 1 FROM ath_investigation_jobs WHERE job_id = %s", (job.job_id,))
            if cur.fetchone() is not None:
                raise InvalidTransition(f"job {job.job_id} already exists")
            columns = ", ".join(_JOB_COLUMNS)
            values = ", ".join(f"%({c})s" for c in _JOB_COLUMNS)
            cur.execute(
                f"INSERT INTO ath_investigation_jobs ({columns}) VALUES ({values})",
                self._params(self._job_row(job)),
            )
            return job

    def get_job(self, job_id: str) -> InvestigationJob:
        with self._tx() as cur:
            cur.execute("SELECT * FROM ath_investigation_jobs WHERE job_id = %s", (job_id,))
            return self._job(self._one(cur, "job", job_id))

    def list_jobs(self, status: JobStatus | None = None,
                  incident_id: str | None = None) -> list[InvestigationJob]:
        with self._tx() as cur:
            cur.execute(
                "SELECT * FROM ath_investigation_jobs"
                " WHERE (%(s)s::text IS NULL OR status = %(s)s)"
                " AND (%(i)s::text IS NULL OR incident_id = %(i)s)"
                " ORDER BY created_at, seq",
                {"s": None if status is None else status.value, "i": incident_id},
            )
            return [self._job(row) for row in cur.fetchall()]

    def claim_job(self, worker_id: str, lease_seconds: float,
                  now: datetime | None = None) -> tuple[InvestigationJob, JobAttempt] | None:
        now = self._now(now)
        with self._tx() as cur:
            self._expire(cur, now)
            cur.execute(
                "SELECT * FROM ath_investigation_jobs WHERE status = %s"
                " ORDER BY created_at, seq LIMIT 1 FOR UPDATE SKIP LOCKED",
                (JobStatus.QUEUED.value,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            job, attempt = claim_transition(self._job(row), worker_id, lease_seconds, now)
            self._write_job(cur, job)
            columns = ", ".join(_ATTEMPT_COLUMNS)
            values = ", ".join(f"%({c})s" for c in _ATTEMPT_COLUMNS)
            cur.execute(
                f"INSERT INTO ath_job_attempts ({columns}) VALUES ({values})",
                self._params(self._attempt_row(attempt)),
            )
            return job, attempt

    def heartbeat(self, attempt_id: str, worker_id: str, lease_seconds: float,
                  now: datetime | None = None) -> bool:
        now = self._now(now)
        with self._tx() as cur:
            pair = self._locked_pair(cur, attempt_id)
            if pair is None:
                return False
            job, attempt = pair
            if not lease_is_valid(job, attempt, worker_id, now):
                return False
            cur.execute(
                "UPDATE ath_investigation_jobs SET lease_expires_at = %s, updated_at = %s WHERE job_id = %s",
                (now + timedelta(seconds=lease_seconds), now, job.job_id),
            )
            cur.execute("UPDATE ath_job_attempts SET heartbeat_at = %s WHERE attempt_id = %s", (now, attempt_id))
            return True

    def finish_attempt(
        self, attempt_id: str, worker_id: str, outcome: AttemptOutcome, *,
        retryable: bool = True, state: dict[str, Any] | None = None, run_id: str | None = None,
        error: str | None = None, report: dict[str, Any] | None = None, markdown: str | None = None,
        now: datetime | None = None,
    ) -> InvestigationJob:
        with self._tx() as cur:
            pair = self._locked_pair(cur, attempt_id)
            if pair is None:
                raise NotFound(f"attempt {attempt_id!r} not found")
            job, attempt = pair
            # A row lock can wait past expiry; check the clock after acquiring it.
            now = self._now(now)
            if not lease_is_valid(job, attempt, worker_id, now):
                raise LeaseLost(f"attempt {attempt_id} is not owned by {worker_id!r}")
            job, attempt = finish_transition(
                job, attempt, outcome, now, retryable=retryable, state=state, run_id=run_id, error=error,
            )
            self._write_job(cur, job)
            self._write_attempt(cur, attempt)
            if report is not None:
                self._append_revision(cur, job.job_id, attempt_id, report, markdown or "", now)
            return job

    def expire_leases(self, now: datetime | None = None) -> list[JobAttempt]:
        with self._tx() as cur:
            return self._expire(cur, self._now(now))

    def cancel_job(self, job_id: str, now: datetime | None = None) -> InvestigationJob:
        now = self._now(now)
        with self._tx() as cur:
            cur.execute("SELECT * FROM ath_investigation_jobs WHERE job_id = %s FOR UPDATE", (job_id,))
            job = self._job(self._one(cur, "job", job_id))
            attempt = self._running_attempt(cur, job_id) if job.status is JobStatus.RUNNING else None
            job, attempt = cancel_transition(job, attempt, now)
            self._write_job(cur, job)
            if attempt is not None:
                self._write_attempt(cur, attempt)
            return job

    def get_attempt(self, attempt_id: str) -> JobAttempt:
        with self._tx() as cur:
            cur.execute("SELECT * FROM ath_job_attempts WHERE attempt_id = %s", (attempt_id,))
            return JobAttempt.from_dict(self._one(cur, "attempt", attempt_id))

    def list_attempts(self, job_id: str) -> list[JobAttempt]:
        with self._tx() as cur:
            cur.execute("SELECT * FROM ath_job_attempts WHERE job_id = %s ORDER BY number", (job_id,))
            return [JobAttempt.from_dict(row) for row in cur.fetchall()]

    # -- reports --------------------------------------------------------------------

    def add_report_revision(self, job_id: str, attempt_id: str, report: dict[str, Any],
                            markdown: str, now: datetime | None = None) -> ReportRevision:
        with self._tx() as cur:
            cur.execute("SELECT 1 FROM ath_investigation_jobs WHERE job_id = %s FOR UPDATE", (job_id,))
            self._one(cur, "job", job_id)
            cur.execute("SELECT job_id FROM ath_job_attempts WHERE attempt_id = %s", (attempt_id,))
            if self._one(cur, "attempt", attempt_id)["job_id"] != job_id:
                raise InvalidTransition("attempt belongs to a different job")
            return self._append_revision(cur, job_id, attempt_id, report, markdown, self._now(now))

    def list_report_revisions(self, job_id: str) -> list[ReportRevision]:
        with self._tx() as cur:
            cur.execute("SELECT * FROM ath_report_revisions WHERE job_id = %s ORDER BY revision", (job_id,))
            return [ReportRevision.from_dict(row) for row in cur.fetchall()]

    # -- internals ------------------------------------------------------------------

    def _expire(self, cur: Any, now: datetime) -> list[JobAttempt]:
        cur.execute(
            "SELECT * FROM ath_investigation_jobs WHERE status = %s AND lease_expires_at <= %s"
            " ORDER BY created_at, seq FOR UPDATE SKIP LOCKED",
            (JobStatus.RUNNING.value, now),
        )
        lapsed: list[JobAttempt] = []
        for row in cur.fetchall():
            job = self._job(row)
            attempt = self._running_attempt(cur, job.job_id)
            job, attempt = finish_transition(job, attempt, AttemptOutcome.EXPIRED, now, error="lease expired")
            self._write_job(cur, job)
            self._write_attempt(cur, attempt)
            lapsed.append(attempt)
        return lapsed

    def _locked_pair(self, cur: Any, attempt_id: str) -> tuple[InvestigationJob, JobAttempt] | None:
        """Lock the job before its attempt: the order every other path uses, so two
        transactions touching one job wait on each other instead of deadlocking."""
        cur.execute("SELECT job_id FROM ath_job_attempts WHERE attempt_id = %s", (attempt_id,))
        row = cur.fetchone()
        if row is None:
            return None
        cur.execute("SELECT * FROM ath_investigation_jobs WHERE job_id = %s FOR UPDATE", (row["job_id"],))
        job = self._job(cur.fetchone())
        cur.execute("SELECT * FROM ath_job_attempts WHERE attempt_id = %s FOR UPDATE", (attempt_id,))
        return job, JobAttempt.from_dict(cur.fetchone())

    def _running_attempt(self, cur: Any, job_id: str) -> JobAttempt:
        cur.execute(
            "SELECT * FROM ath_job_attempts WHERE job_id = %s AND outcome = %s FOR UPDATE",
            (job_id, AttemptOutcome.RUNNING.value),
        )
        row = cur.fetchone()
        if row is None:
            raise InvalidTransition(f"running job {job_id} has no running attempt")
        return JobAttempt.from_dict(row)

    def _write_job(self, cur: Any, job: InvestigationJob) -> None:
        assignments = ", ".join(f"{c} = %({c})s" for c in _JOB_COLUMNS if c != "job_id")
        cur.execute(
            f"UPDATE ath_investigation_jobs SET {assignments} WHERE job_id = %(job_id)s",
            self._params(self._job_row(job)),
        )

    def _write_attempt(self, cur: Any, attempt: JobAttempt) -> None:
        assignments = ", ".join(f"{c} = %({c})s" for c in _ATTEMPT_COLUMNS if c != "attempt_id")
        cur.execute(
            f"UPDATE ath_job_attempts SET {assignments} WHERE attempt_id = %(attempt_id)s",
            self._params(self._attempt_row(attempt)),
        )

    def _append_revision(self, cur: Any, job_id: str, attempt_id: str, report: dict[str, Any],
                         markdown: str, now: datetime) -> ReportRevision:
        cur.execute(
            "SELECT coalesce(max(revision), 0) AS latest FROM ath_report_revisions WHERE job_id = %s",
            (job_id,),
        )
        revision = ReportRevision.create(job_id, attempt_id, int(cur.fetchone()["latest"]) + 1, report, markdown, now)
        cur.execute(
            "INSERT INTO ath_report_revisions"
            " (revision_id, job_id, attempt_id, revision, report, markdown, sha256, created_at)"
            " VALUES (%(revision_id)s, %(job_id)s, %(attempt_id)s, %(revision)s, %(report)s,"
            " %(markdown)s, %(sha256)s, %(created_at)s)",
            self._params({**revision.to_dict(), "created_at": revision.created_at}),
        )
        return revision

    @staticmethod
    def _job_row(job: InvestigationJob) -> dict[str, Any]:
        return {
            **{c: getattr(job, c) for c in _JOB_COLUMNS},
            "status": job.status.value,
        }

    @staticmethod
    def _attempt_row(attempt: JobAttempt) -> dict[str, Any]:
        return {
            **{c: getattr(attempt, c) for c in _ATTEMPT_COLUMNS},
            "outcome": attempt.outcome.value,
        }

    @staticmethod
    def _job(row: dict[str, Any]) -> InvestigationJob:
        return InvestigationJob.from_dict({k: v for k, v in row.items() if k != "seq"})

    @staticmethod
    def _incident(row: dict[str, Any]) -> Incident:
        payload = dict(row)
        payload["case"] = payload.pop("case_payload")
        return Incident.from_dict(payload)

    @staticmethod
    def _one(cur: Any, kind: str, key: str) -> dict[str, Any]:
        row = cur.fetchone()
        if row is None:
            raise NotFound(f"{kind} {key!r} not found")
        return row


__all__ = ["PostgresStore", "SCHEMA_SQL", "SCHEMA_VERSION", "TABLES"]
