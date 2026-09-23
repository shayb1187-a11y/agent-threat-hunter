"""Persistence and background execution for operational investigations.

The store records telemetry references, incidents, investigation jobs, their
attempts and report revisions. Two implementations share one contract and one set
of lifecycle rules: :class:`InMemoryStore` for single-process and batch use, and
:class:`~ath.persistence.postgres.PostgresStore` for durable queues shared by
background workers. The PostgreSQL backend is imported from its own module so that
this package never needs the driver installed.

The toolbox, verifier, investigators and report builder are unchanged: the store
supplies their inputs and keeps what they produce.
"""

from ath.persistence.memory import InMemoryStore
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
)
from ath.persistence.worker import (
    Executor,
    Worker,
    derive_footing,
    describe_telemetry,
    submit_investigations,
)

__all__ = [
    "AttemptOutcome", "Executor", "InMemoryStore", "Incident", "InvalidTransition",
    "InvestigationJob", "InvestigationStore", "JobAttempt", "JobStatus", "LeaseLost",
    "NotFound", "ReportRevision", "StoreError", "TelemetryReference", "Worker",
    "derive_footing", "describe_telemetry", "submit_investigations",
]
