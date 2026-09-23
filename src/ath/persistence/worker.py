"""Submitting investigation jobs and executing them in the background.

The executor re-derives its inputs instead of trusting stored copies: it loads the
telemetry the reference names, checks its content digest, re-runs the deterministic
hunt and correlation, and refuses to investigate unless the case it derives hashes to
the case the incident recorded. The existing :class:`~ath.agent.tools.ToolBox` is then
built exactly as the CLI builds it -- the store sits beside the toolbox, feeding it and
keeping its ledger, so the frozen tool surface is untouched.

Reliability comes from the store's lease protocol, not from this process surviving: a
worker heartbeats while it runs, a crashed worker's lease lapses and the job is
requeued with the lapsed attempt on record, and a worker that outlived its lease has
its result refused rather than written over a newer attempt's. There is still no
preemption: a CPU-bound attempt that ignores the profile's cooperative time budget
holds its lease until the heartbeat stops.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from ath.agent.llm import LLMClient, NullLLM
from ath.agent.operational import EvidenceProfile, OperationalProfile, investigate_operational
from ath.agent.state import InvestigationState, InvestigationStatus
from ath.correlation import correlate
from ath.correlation.chain import InvestigationCase
from ath.environment import build_environment_model
from ath.environment.model import EnvironmentModel
from ath.evaluation.ablation.manifest import telemetry_digest, telemetry_rows
from ath.hunting import HuntConfig, run_hunt
from ath.hunting.finding import Finding
from ath.persistence.models import (
    AttemptOutcome,
    Incident,
    InvestigationJob,
    JobAttempt,
    TelemetryReference,
    canonical_sha256,
    utcnow,
)
from ath.persistence.store import InvestigationStore, LeaseLost
from ath.reporting import build_report, render_markdown
from ath.telemetry.loader import Telemetry, load_telemetry
from ath.triage import assess_findings, set_aside_ids

logger = logging.getLogger(__name__)

DIGEST_VERSION = 2
"""Telemetry references use the runtime-stable v2 corpus digest."""


class ReproductionError(RuntimeError):
    """The attempt's inputs cannot be re-derived; retrying would not change that."""


# -- deriving the inputs ------------------------------------------------------------------


@dataclass(frozen=True)
class CaseFooting:
    """Everything the CLI computes before it investigates, derived once per corpus."""

    telemetry: Telemetry
    findings: list[Finding]
    cases: dict[str, InvestigationCase]
    environment: EnvironmentModel


def derive_footing(telemetry: Telemetry) -> CaseFooting:
    """The same hunt, triage set-aside and correlation ``ath investigate`` performs."""
    result = run_hunt(telemetry, config=HuntConfig())
    environment = build_environment_model(telemetry)
    assessments = assess_findings(result.findings, environment)
    cases = correlate(result.findings, telemetry, set_aside=set_aside_ids(assessments))
    return CaseFooting(telemetry, list(result.findings), {c.case_id: c for c in cases}, environment)


def describe_telemetry(telemetry: Telemetry, location: str | Path,
                       now: datetime | None = None) -> TelemetryReference:
    return TelemetryReference.create(
        str(location), telemetry_digest(telemetry, DIGEST_VERSION), DIGEST_VERSION,
        telemetry_rows(telemetry), now,
    )


def load_referenced_telemetry(reference: TelemetryReference) -> Telemetry:
    """Load the corpus a reference names and refuse it if its content moved."""
    telemetry = load_telemetry(Path(reference.location))
    digest = telemetry_digest(telemetry, reference.digest_version)
    if digest != reference.digest:
        raise ReproductionError("telemetry content no longer matches its registered digest")
    return telemetry


def submit_investigations(
    store: InvestigationStore, telemetry: Telemetry, location: str | Path, *,
    case_ids: Iterable[str] | None = None, profile: OperationalProfile | None = None,
    model_requested: bool = False, max_attempts: int = 3, retry_incomplete: bool = False,
    footing: CaseFooting | None = None, now: datetime | None = None,
) -> list[InvestigationJob]:
    """Register the corpus and its cases, and enqueue one job per selected case."""
    profile = profile or EvidenceProfile()
    footing = footing or derive_footing(telemetry)
    reference = store.register_telemetry(describe_telemetry(telemetry, location, now))
    wanted = None if case_ids is None else {c.upper() for c in case_ids}
    missing = set() if wanted is None else wanted - {c.upper() for c in footing.cases}
    if missing:
        raise KeyError(f"no such case(s): {', '.join(sorted(missing))}")
    jobs = []
    for case_id, case in footing.cases.items():
        if wanted is not None and case_id.upper() not in wanted:
            continue
        incident = store.register_incident(Incident.create(reference.telemetry_id, case.to_dict(), now))
        jobs.append(store.enqueue_job(InvestigationJob.create(
            incident.incident_id, profile.to_dict(), profile.sha256(),
            model_requested=model_requested, max_attempts=max_attempts,
            retry_incomplete=retry_incomplete, now=now,
        )))
    return jobs


def profile_from_job(job: InvestigationJob) -> OperationalProfile:
    """The profile the job recorded, refused if its hash no longer matches the values."""
    values = {k: v for k, v in job.profile.items()
              if k not in ("version", "reject_unretrieved", "prompt_contract", "ledger")}
    profile_type = {OperationalProfile.version: OperationalProfile, EvidenceProfile.version: EvidenceProfile}.get(
        job.profile.get("version")
    )
    if profile_type is None:
        raise ReproductionError("unsupported job profile version")
    try:
        profile = profile_type(**values)
    except (TypeError, ValueError) as exc:
        raise ReproductionError("invalid job profile configuration") from exc
    if profile.sha256() != job.profile_sha256 or job.profile != profile.to_dict():
        raise ReproductionError("job profile does not hash to its recorded configuration")
    return profile


# -- executing one attempt ----------------------------------------------------------------


@dataclass(frozen=True)
class AttemptResult:
    outcome: AttemptOutcome
    retryable: bool = True
    state: InvestigationState | None = None
    report: dict[str, Any] | None = None
    markdown: str | None = None
    error: str | None = None


class Executor:
    """Turns a claimed job into an :class:`AttemptResult`, never raising past itself.

    ``llm_factory`` is called once per model attempt; a job that requested a model
    cannot run without one and fails (retryably, since configuration can be fixed).
    Errors are recorded by exception type only -- transport exceptions can carry
    credentials or prompt text, and the store is not a place for either.
    """

    def __init__(
        self, store: InvestigationStore, *, llm_factory: Callable[[], LLMClient] | None = None,
        loader: Callable[[TelemetryReference], Telemetry] = load_referenced_telemetry,
    ) -> None:
        self.store = store
        self.llm_factory = llm_factory
        self.loader = loader
        self._footings: dict[str, CaseFooting] = {}

    def remember(self, telemetry_id: str, footing: CaseFooting) -> None:
        """Seed the cache, so a submit-and-run process derives its footing once."""
        self._footings[telemetry_id] = footing

    def footing(self, telemetry_id: str) -> CaseFooting:
        if telemetry_id not in self._footings:
            reference = self.store.get_telemetry(telemetry_id)
            self._footings[telemetry_id] = derive_footing(self.loader(reference))
        return self._footings[telemetry_id]

    def execute(self, job: InvestigationJob, attempt: JobAttempt) -> AttemptResult:
        try:
            return self._execute(job)
        except ReproductionError as exc:
            logger.error("attempt %s cannot reproduce its inputs: %s", attempt.attempt_id, exc)
            return AttemptResult(AttemptOutcome.FAILED, retryable=False, error=str(exc))
        except Exception as exc:  # noqa: BLE001 -- recorded as an outcome, never propagated
            logger.exception("attempt %s raised", attempt.attempt_id)
            return AttemptResult(AttemptOutcome.FAILED, error=f"attempt raised {type(exc).__name__}")

    def _execute(self, job: InvestigationJob) -> AttemptResult:
        profile = profile_from_job(job)
        incident = self.store.get_incident(job.incident_id)
        footing = self.footing(incident.telemetry_id)
        case = footing.cases.get(incident.case_id)
        if case is None or canonical_sha256(case.to_dict()) != incident.case_sha256:
            raise ReproductionError("the recorded case is no longer derived from its telemetry")
        llm = None
        if job.model_requested:
            if self.llm_factory is None:
                return AttemptResult(AttemptOutcome.FAILED, error="job requested a model but none is configured")
            llm = self.llm_factory()
            if isinstance(llm, NullLLM):
                return AttemptResult(AttemptOutcome.FAILED, error="job requested a model but none is configured")
        state = investigate_operational(
            case, footing.telemetry, footing.findings, llm=llm, profile=profile,
            environment=footing.environment,
        )
        report = build_report(state, footing.telemetry)
        outcome = (AttemptOutcome.INCOMPLETE if state.status is InvestigationStatus.INCOMPLETE
                   else AttemptOutcome.COMPLETE)
        return AttemptResult(outcome, state=state, report=report.to_dict(), markdown=render_markdown(report))


# -- the worker loop ----------------------------------------------------------------------


class Worker:
    """Claim, heartbeat, execute, record; one job at a time."""

    def __init__(
        self, store: InvestigationStore, executor: Executor, *, worker_id: str | None = None,
        lease_seconds: float = 60.0, heartbeat_seconds: float | None = None,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        self.store = store
        self.executor = executor
        self.worker_id = worker_id or f"worker-{uuid4().hex[:12]}"
        self.lease_seconds = lease_seconds
        self.heartbeat_seconds = heartbeat_seconds if heartbeat_seconds is not None else lease_seconds / 3
        if not 0 < self.heartbeat_seconds < lease_seconds:
            raise ValueError("heartbeat_seconds must be positive and shorter than the lease")
        self.clock = clock

    def run_once(self) -> JobAttempt | None:
        """Process one job. ``None`` when the queue is empty."""
        self.store.expire_leases(self.clock())
        claimed = self.store.claim_job(self.worker_id, self.lease_seconds, self.clock())
        if claimed is None:
            return None
        job, attempt = claimed
        stop, lost = threading.Event(), threading.Event()
        beat = threading.Thread(
            target=self._heartbeat, args=(attempt.attempt_id, stop, lost),
            name=f"{self.worker_id}-heartbeat", daemon=True,
        )
        beat.start()
        try:
            result = self.executor.execute(job, attempt)
        finally:
            stop.set()
            beat.join()
        if lost.is_set():
            logger.warning("attempt %s lost its lease before finishing; result discarded", attempt.attempt_id)
            return self.store.get_attempt(attempt.attempt_id)
        try:
            self.store.finish_attempt(
                attempt.attempt_id, self.worker_id, result.outcome, retryable=result.retryable,
                state=None if result.state is None else result.state.to_dict(),
                run_id=None if result.state is None else result.state.run_id or None,
                error=result.error, report=result.report, markdown=result.markdown,
                now=None if self.clock is utcnow else self.clock(),
            )
        except LeaseLost:
            logger.warning("attempt %s was reassigned before its result was recorded", attempt.attempt_id)
        return self.store.get_attempt(attempt.attempt_id)

    def run(self, *, max_jobs: int | None = None, idle_seconds: float = 1.0,
            stop: threading.Event | None = None, drain: bool = False) -> int:
        """Process jobs until ``stop`` is set or ``max_jobs`` is reached.

        With ``drain`` the loop also returns as soon as the queue is empty, which is
        what a submit-and-run process wants; a background worker keeps polling.
        """
        stop = stop or threading.Event()
        processed = 0
        while not stop.is_set() and (max_jobs is None or processed < max_jobs):
            if self.run_once() is None:
                if drain or stop.wait(idle_seconds):
                    break
                continue
            processed += 1
        return processed

    def _heartbeat(self, attempt_id: str, stop: threading.Event, lost: threading.Event) -> None:
        while not stop.wait(self.heartbeat_seconds):
            try:
                alive = self.store.heartbeat(attempt_id, self.worker_id, self.lease_seconds, self.clock())
            except Exception:  # noqa: BLE001 -- a transient store fault is not a lost lease
                logger.exception("heartbeat for attempt %s failed", attempt_id)
                continue
            if not alive:
                lost.set()
                return


__all__ = [
    "AttemptResult", "CaseFooting", "DIGEST_VERSION", "Executor", "ReproductionError",
    "Worker", "derive_footing", "describe_telemetry", "load_referenced_telemetry",
    "profile_from_job", "submit_investigations",
]
