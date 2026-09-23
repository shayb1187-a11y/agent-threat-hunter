"""The store contract on every backend, and the worker over real investigations.

The in-memory store always runs. The PostgreSQL store runs when
``ATH_TEST_DATABASE_URL`` names a database this test may truncate; otherwise its
parametrisation is skipped, and the skip is visible in the run.
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import timedelta
from types import SimpleNamespace

import pytest

from ath import cli
from ath.agent.llm import ScriptedLLM
from ath.agent.operational import EvidenceProfile, OperationalProfile
from ath.persistence import (
    AttemptOutcome,
    Executor,
    Incident,
    InMemoryStore,
    InvalidTransition,
    InvestigationJob,
    JobStatus,
    LeaseLost,
    NotFound,
    Worker,
    derive_footing,
    describe_telemetry,
    submit_investigations,
)
from ath.persistence.models import JobAttempt, ReportRevision, TelemetryReference, utcnow
from ath.persistence.worker import AttemptResult, profile_from_job
from test_d1_investigator import _answer, world  # noqa: F401

POSTGRES_URL = os.getenv("ATH_TEST_DATABASE_URL")
LOCATION = "memory://world"


@pytest.fixture(params=[
    "memory",
    pytest.param("postgres", marks=pytest.mark.skipif(
        not POSTGRES_URL, reason="ATH_TEST_DATABASE_URL not set; PostgreSQL contract not exercised",
    )),
])
def store(request):
    if request.param == "memory":
        yield InMemoryStore()
        return
    from ath.persistence.postgres import TABLES, PostgresStore

    pg = PostgresStore(POSTGRES_URL)
    pg.migrate()
    with pg._tx() as cur:
        cur.execute("TRUNCATE " + ", ".join(TABLES) + " CASCADE")
    pg.migrate()
    yield pg
    pg.close()


@pytest.fixture(scope="module")
def footing(world):
    derived = derive_footing(world["telemetry"])
    assert derived.cases, "the shared world must correlate into at least one case"
    return derived


def seed(store, world, *, case=None):
    reference = store.register_telemetry(describe_telemetry(world["telemetry"], LOCATION))
    incident = store.register_incident(Incident.create(reference.telemetry_id, (case or world["case"]).to_dict()))
    return reference, incident


def enqueue(store, incident, **overrides):
    profile = OperationalProfile()
    fields = {"model_requested": False, "max_attempts": 3, "retry_incomplete": False, **overrides}
    return store.enqueue_job(InvestigationJob.create(incident.incident_id, profile.to_dict(), profile.sha256(), **fields))


# -- the contract -------------------------------------------------------------------------


def test_telemetry_and_incident_registration_are_idempotent(store, world):
    first, incident = seed(store, world)
    again, same_incident = seed(store, world)
    assert again == first and same_incident == incident
    assert store.find_telemetry(first.digest) == first
    assert store.get_telemetry(first.telemetry_id).row_counts == first.row_counts
    assert store.list_incidents(first.telemetry_id) == [incident]
    with pytest.raises(NotFound):
        store.register_incident(Incident.create("missing", world["case"].to_dict()))
    with pytest.raises(NotFound):
        store.get_job("missing")


def test_claims_are_exclusive_and_oldest_first(store, world):
    _, incident = seed(store, world)
    now = utcnow()
    first = enqueue(store, incident)
    second = store.enqueue_job(InvestigationJob.create(
        incident.incident_id, first.profile, first.profile_sha256, model_requested=False,
        now=now + timedelta(seconds=1),
    ))
    job, attempt = store.claim_job("w1", 30, now)
    assert job.job_id == first.job_id and attempt.number == 1 and attempt.worker_id == "w1"
    assert job.status is JobStatus.RUNNING and job.lease_owner == "w1"
    assert job.lease_expires_at == now + timedelta(seconds=30)
    other, _ = store.claim_job("w2", 30, now)
    assert other.job_id == second.job_id
    assert store.claim_job("w3", 30, now) is None
    assert [j.status for j in store.list_jobs()] == [JobStatus.RUNNING, JobStatus.RUNNING]
    assert store.list_jobs(JobStatus.QUEUED) == []
    assert store.get_attempt(attempt.attempt_id) == attempt


def test_only_the_lease_owner_can_heartbeat_or_finish(store, world):
    _, incident = seed(store, world)
    enqueue(store, incident)
    now = utcnow()
    job, attempt = store.claim_job("w1", 30, now)
    assert not store.heartbeat(attempt.attempt_id, "w2", 30, now)
    assert store.heartbeat(attempt.attempt_id, "w1", 30, now + timedelta(seconds=10))
    assert store.get_job(job.job_id).lease_expires_at == now + timedelta(seconds=40)
    assert not store.heartbeat("missing", "w1", 30, now)
    with pytest.raises(LeaseLost):
        store.finish_attempt(attempt.attempt_id, "w2", AttemptOutcome.COMPLETE)
    done = store.finish_attempt(attempt.attempt_id, "w1", AttemptOutcome.COMPLETE, state={"ok": True},
                                run_id="run-1", now=now + timedelta(seconds=20))
    assert done.status is JobStatus.COMPLETE and done.lease_owner is None
    ended = store.get_attempt(attempt.attempt_id)
    assert ended.outcome is AttemptOutcome.COMPLETE and ended.state == {"ok": True} and ended.run_id == "run-1"
    with pytest.raises(LeaseLost):
        store.finish_attempt(attempt.attempt_id, "w1", AttemptOutcome.COMPLETE)
    assert not store.heartbeat(attempt.attempt_id, "w1", 30, now)


def test_an_expired_lease_requeues_until_the_allowance_is_spent(store, world):
    _, incident = seed(store, world)
    job = enqueue(store, incident, max_attempts=2)
    now = utcnow()
    _, first = store.claim_job("w1", 10, now)
    assert store.expire_leases(now + timedelta(seconds=9)) == []
    lapsed = store.expire_leases(now + timedelta(seconds=10))  # the lease lapses at its expiry instant
    assert [a.attempt_id for a in lapsed] == [first.attempt_id]
    assert lapsed[0].outcome is AttemptOutcome.EXPIRED and lapsed[0].error == "lease expired"
    requeued = store.get_job(job.job_id)
    assert requeued.status is JobStatus.QUEUED and requeued.attempts_made == 1
    with pytest.raises(LeaseLost):
        store.finish_attempt(first.attempt_id, "w1", AttemptOutcome.COMPLETE)
    _, second = store.claim_job("w2", 10, now + timedelta(seconds=12))
    assert second.number == 2
    # A claim expires stale leases on its own before it looks for work.
    assert store.claim_job("w3", 10, now + timedelta(seconds=30)) is None
    final = store.get_job(job.job_id)
    assert final.status is JobStatus.FAILED and final.attempts_made == 2
    assert [a.outcome for a in store.list_attempts(job.job_id)] == [AttemptOutcome.EXPIRED] * 2


def test_a_fault_retries_only_while_retryable_and_within_the_allowance(store, world):
    _, incident = seed(store, world)
    job = enqueue(store, incident, max_attempts=3)
    _, attempt = store.claim_job("w1", 30)
    after = store.finish_attempt(attempt.attempt_id, "w1", AttemptOutcome.FAILED, error="attempt raised X")
    assert after.status is JobStatus.QUEUED and after.last_error == "attempt raised X"
    _, attempt = store.claim_job("w1", 30)
    after = store.finish_attempt(attempt.attempt_id, "w1", AttemptOutcome.FAILED, retryable=False,
                                 error="the recorded case is no longer derived from its telemetry")
    assert after.status is JobStatus.FAILED and after.attempts_made == 2
    assert store.claim_job("w1", 30) is None
    assert len(store.list_attempts(job.job_id)) == 2


def test_incomplete_is_a_terminal_result_unless_the_job_opted_in(store, world):
    _, incident = seed(store, world)
    plain = enqueue(store, incident)
    opted = enqueue(store, incident, retry_incomplete=True, max_attempts=2)
    for expected in (JobStatus.INCOMPLETE, JobStatus.QUEUED):
        _, attempt = store.claim_job("w1", 30)
        assert store.finish_attempt(attempt.attempt_id, "w1", AttemptOutcome.INCOMPLETE).status is expected
    assert store.get_job(plain.job_id).status is JobStatus.INCOMPLETE
    _, attempt = store.claim_job("w1", 30)
    assert attempt.job_id == opted.job_id and attempt.number == 2
    assert store.finish_attempt(attempt.attempt_id, "w1", AttemptOutcome.INCOMPLETE).status is JobStatus.INCOMPLETE


def test_a_report_revision_is_recorded_with_the_attempt_and_numbered_per_job(store, world):
    _, incident = seed(store, world)
    job = enqueue(store, incident)
    _, attempt = store.claim_job("w1", 30)
    assert store.latest_report(job.job_id) is None
    store.finish_attempt(attempt.attempt_id, "w1", AttemptOutcome.COMPLETE,
                         report={"case_id": "X", "facts": []}, markdown="# X\n")
    first = store.latest_report(job.job_id)
    assert first.revision == 1 and first.attempt_id == attempt.attempt_id and first.markdown == "# X\n"
    second = store.add_report_revision(job.job_id, attempt.attempt_id, {"case_id": "X", "facts": []}, "# X v2\n")
    assert second.revision == 2 and second.sha256 != first.sha256
    assert [r.revision for r in store.list_report_revisions(job.job_id)] == [1, 2]
    assert store.latest_report(job.job_id) == second
    other = enqueue(store, incident)
    with pytest.raises(InvalidTransition):
        store.add_report_revision(other.job_id, attempt.attempt_id, {}, "")
    with pytest.raises(NotFound):
        store.add_report_revision("missing", attempt.attempt_id, {}, "")


def test_cancel_refuses_a_late_result_and_terminal_jobs(store, world):
    _, incident = seed(store, world)
    queued = enqueue(store, incident)
    assert store.cancel_job(queued.job_id).status is JobStatus.CANCELLED
    running = enqueue(store, incident)
    _, attempt = store.claim_job("w1", 30)
    assert attempt.job_id == running.job_id
    cancelled = store.cancel_job(running.job_id)
    assert cancelled.status is JobStatus.CANCELLED and cancelled.lease_owner is None
    assert store.get_attempt(attempt.attempt_id).outcome is AttemptOutcome.CANCELLED
    with pytest.raises(LeaseLost):
        store.finish_attempt(attempt.attempt_id, "w1", AttemptOutcome.COMPLETE)
    with pytest.raises(InvalidTransition):
        store.cancel_job(queued.job_id)
    with pytest.raises(NotFound):
        store.cancel_job("missing")


def test_enqueue_accepts_only_fresh_jobs_for_known_incidents(store, world):
    _, incident = seed(store, world)
    job = enqueue(store, incident)
    with pytest.raises(InvalidTransition):
        store.enqueue_job(job)
    with pytest.raises(NotFound):
        store.enqueue_job(InvestigationJob.create("missing", job.profile, job.profile_sha256, model_requested=False))
    with pytest.raises(ValueError):
        InvestigationJob.create(incident.incident_id, job.profile, job.profile_sha256,
                                model_requested=False, max_attempts=0)


def test_records_round_trip_through_json_safe_dictionaries(world):
    reference = describe_telemetry(world["telemetry"], LOCATION)
    incident = Incident.create(reference.telemetry_id, world["case"].to_dict())
    job = InvestigationJob.create(incident.incident_id, OperationalProfile().to_dict(),
                                  OperationalProfile().sha256(), model_requested=True)
    attempt = JobAttempt.start(job.job_id, 1, "w", utcnow())
    revision = ReportRevision.create(job.job_id, attempt.attempt_id, 1, {"a": 1}, "# a", utcnow())
    for record in (reference, incident, job, attempt, revision):
        payload = json.loads(json.dumps(record.to_dict()))
        assert type(record).from_dict(payload) == record
    assert reference.digest_version == 2 and reference.row_counts["logon"] == len(world["telemetry"].logons)
    with pytest.raises(ValueError):
        TelemetryReference.from_dict({**reference.to_dict(), "registered_at": "2026-01-01T00:00:00"})


@pytest.mark.parametrize("profile_type", [OperationalProfile, EvidenceProfile])
def test_profile_from_job_refuses_a_profile_that_does_not_hash_to_its_record(world, profile_type):
    incident = Incident.create("t", world["case"].to_dict())
    profile = profile_type(max_probes=1)
    job = InvestigationJob.create(incident.incident_id, profile.to_dict(), profile.sha256(), model_requested=False)
    assert profile_from_job(job) == profile
    tampered = InvestigationJob.create(incident.incident_id, {**profile.to_dict(), "max_probes": 2},
                                       profile.sha256(), model_requested=False)
    with pytest.raises(Exception, match="does not hash"):
        profile_from_job(tampered)


# -- the worker ---------------------------------------------------------------------------


def submit(store, world, footing, **overrides):
    case_id = next(iter(footing.cases))
    jobs = submit_investigations(store, world["telemetry"], LOCATION, case_ids=[case_id], footing=footing, **overrides)
    assert len(jobs) == 1
    return jobs[0]


def make_executor(store, footing, job, **kwargs):
    executor = Executor(store, **kwargs)
    executor.remember(store.get_incident(job.incident_id).telemetry_id, footing)
    return executor


def test_worker_executes_a_deterministic_job_and_records_state_and_report(store, world, footing):
    """On every backend: a real investigation state and report go through the store intact."""
    job = submit(store, world, footing)
    worker = Worker(store, make_executor(store, footing, job), worker_id="w1")
    attempt = worker.run_once()
    assert attempt.outcome is AttemptOutcome.COMPLETE and attempt.worker_id == "w1"
    finished = store.get_job(job.job_id)
    assert finished.status is JobStatus.COMPLETE and finished.attempts_made == 1
    audit = attempt.state["investigation"]["operational"]
    assert audit["outcome"] == "complete" and audit["engine"] == "deterministic"
    assert audit["profile_sha256"] == job.profile_sha256
    assert audit["profile"]["version"] == EvidenceProfile.version
    assert attempt.state["investigation"]["evidence_verification"]["observations_verified"] > 0
    assert attempt.run_id == attempt.state["run_id"]
    revision = store.latest_report(job.job_id)
    assert revision.revision == 1 and revision.report["case_id"] == store.get_incident(job.incident_id).case_id
    assert revision.report["case_id"] in revision.markdown
    assert worker.run_once() is None
    assert worker.run(drain=True) == 0


def test_submit_registers_every_case_once_and_rejects_unknown_ones(world, footing):
    store = InMemoryStore()
    jobs = submit_investigations(store, world["telemetry"], LOCATION, footing=footing)
    assert {store.get_incident(j.incident_id).case_id for j in jobs} == set(footing.cases)
    again = submit_investigations(store, world["telemetry"], LOCATION, footing=footing)
    assert {j.incident_id for j in again} == {j.incident_id for j in jobs}
    assert len(store.list_incidents()) == len(footing.cases)
    assert len(store.list_jobs()) == 2 * len(footing.cases)
    with pytest.raises(KeyError):
        submit_investigations(store, world["telemetry"], LOCATION, case_ids=["NOPE"], footing=footing)


def test_an_incomplete_model_investigation_is_recorded_without_retry(world, footing):
    store = InMemoryStore()
    job = submit(store, world, footing, model_requested=True)
    executor = make_executor(store, footing, job, llm_factory=lambda: ScriptedLLM(responses=[]))
    attempt = Worker(store, executor).run_once()
    assert attempt.outcome is AttemptOutcome.INCOMPLETE
    assert store.get_job(job.job_id).status is JobStatus.INCOMPLETE
    assert attempt.state["investigation"]["operational"]["engine"] == "d1"
    assert attempt.state["investigation"]["final_disposition"] == "abstain"
    assert any("incomplete" in note.lower() for note in store.latest_report(job.job_id).report["limitations"])


def test_a_model_job_without_a_client_fails_instead_of_running_deterministically(world, footing):
    store = InMemoryStore()
    job = submit(store, world, footing, model_requested=True, max_attempts=1)
    attempt = Worker(store, make_executor(store, footing, job)).run_once()
    assert attempt.outcome is AttemptOutcome.FAILED and "none is configured" in attempt.error
    assert store.get_job(job.job_id).status is JobStatus.FAILED
    assert store.latest_report(job.job_id) is None


def test_a_raising_executor_is_retried_and_its_exception_text_is_not_stored(world, footing):
    class Broken(Executor):
        def _execute(self, job):
            raise RuntimeError("api key sk-secret in a transport error")

    store = InMemoryStore()
    job = submit(store, world, footing, max_attempts=2)
    worker = Worker(store, Broken(store))
    first = worker.run_once()
    assert first.outcome is AttemptOutcome.FAILED and first.error == "attempt raised RuntimeError"
    assert store.get_job(job.job_id).status is JobStatus.QUEUED
    second = worker.run_once()
    assert second.number == 2 and store.get_job(job.job_id).status is JobStatus.FAILED
    assert "secret" not in json.dumps([a.to_dict() for a in store.list_attempts(job.job_id)])


def test_a_case_that_no_longer_derives_from_its_telemetry_fails_without_retry(world, footing):
    store = InMemoryStore()
    reference = store.register_telemetry(describe_telemetry(world["telemetry"], LOCATION))
    case = next(iter(footing.cases.values()))
    incident = store.register_incident(Incident.create(
        reference.telemetry_id, {**case.to_dict(), "explanation": "edited after the fact"},
    ))
    job = enqueue(store, incident, max_attempts=3)
    executor = Executor(store)
    executor.remember(reference.telemetry_id, footing)
    attempt = Worker(store, executor).run_once()
    assert attempt.outcome is AttemptOutcome.FAILED and "no longer derived" in attempt.error
    assert store.get_job(job.job_id).status is JobStatus.FAILED and len(store.list_attempts(job.job_id)) == 1


def test_a_worker_that_outlives_its_lease_has_its_result_discarded(world, footing):
    store = InMemoryStore()
    job = submit(store, world, footing)
    now = [utcnow()]

    class Slow(Executor):
        def execute(self, job, attempt):
            now[0] += timedelta(seconds=120)
            thief, _ = store.claim_job("thief", 60, now[0])  # expires the lease, takes the job
            assert thief.job_id == job.job_id
            return AttemptResult(AttemptOutcome.COMPLETE, report={"case_id": "late"}, markdown="late")

    worker = Worker(store, Slow(store), worker_id="slow", lease_seconds=60, clock=lambda: now[0])
    attempt = worker.run_once()
    assert attempt.outcome is AttemptOutcome.EXPIRED
    current = store.get_job(job.job_id)
    assert current.status is JobStatus.RUNNING and current.lease_owner == "thief"
    assert store.latest_report(job.job_id) is None


def test_the_heartbeat_keeps_a_short_lease_alive_through_a_long_attempt(world, footing):
    store = InMemoryStore()
    job = submit(store, world, footing)

    class Sleeping(Executor):
        def execute(self, job, attempt):
            time.sleep(0.5)
            return AttemptResult(AttemptOutcome.COMPLETE, report={"case_id": "slept"}, markdown="slept")

    worker = Worker(store, Sleeping(store), lease_seconds=0.2, heartbeat_seconds=0.05)
    attempt = worker.run_once()
    assert attempt.outcome is AttemptOutcome.COMPLETE
    assert attempt.heartbeat_at > attempt.started_at + timedelta(seconds=0.3)
    assert store.get_job(job.job_id).status is JobStatus.COMPLETE


def test_run_stops_on_the_stop_event_and_honours_max_jobs(world, footing):
    store = InMemoryStore()
    submit_investigations(store, world["telemetry"], LOCATION, footing=footing)
    submit_investigations(store, world["telemetry"], LOCATION, footing=footing)
    executor = Executor(store)
    executor.remember(store.list_incidents()[0].telemetry_id, footing)
    worker = Worker(store, executor)
    assert worker.run(max_jobs=1) == 1
    stop = threading.Event()
    stop.set()
    assert worker.run(stop=stop) == 0
    remaining = len(store.list_jobs(JobStatus.QUEUED))
    assert remaining >= 1 and worker.run(drain=True) == remaining
    assert store.list_jobs(JobStatus.QUEUED) == []
    with pytest.raises(ValueError):
        Worker(store, executor, lease_seconds=1, heartbeat_seconds=2)


# -- the CLI ------------------------------------------------------------------------------


def settings(tmp_path, url=None):
    return SimpleNamespace(raw_data_dir=tmp_path, database_url=url, log_level="WARNING")


def test_cli_jobs_run_uses_the_in_memory_store_without_a_database(world, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "load_telemetry", lambda path: world["telemetry"])
    output = tmp_path / "jobs.json"
    args = cli.build_parser().parse_args(["jobs", "run", "--no-llm", "--json", str(output)])
    assert cli.cmd_jobs(args, settings(tmp_path)) == 0
    payload = json.loads(output.read_text())
    assert payload and all(entry["job"]["status"] == "complete" for entry in payload)
    assert all(entry["report_revisions"] == 1 and entry["latest_report"]["case_id"] for entry in payload)
    assert all(a["outcome"] == "complete" for entry in payload for a in entry["attempts"])
    assert all(entry["job"]["profile"]["version"] == EvidenceProfile.version for entry in payload)
    assert "in-memory store" in capsys.readouterr().out


def test_cli_jobs_run_reports_incomplete_with_exit_code_3(world, monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "load_telemetry", lambda path: world["telemetry"])
    monkeypatch.setattr(cli, "build_llm", lambda: ScriptedLLM(responses=[]))
    args = cli.build_parser().parse_args(["jobs", "run"])
    assert cli.cmd_jobs(args, settings(tmp_path)) == 3


def test_cli_jobs_run_rejects_an_unknown_case(world, monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "load_telemetry", lambda path: world["telemetry"])
    monkeypatch.setattr(cli, "load_settings", lambda: settings(tmp_path))
    assert cli.main(["jobs", "run", "--no-llm", "--case", "NOPE"]) == 2


@pytest.mark.parametrize("argv", [
    ["jobs", "migrate"], ["jobs", "submit"], ["jobs", "work", "--once"], ["jobs", "status"],
    ["jobs", "cancel", "x"], ["jobs", "report", "x"],
])
def test_cli_durable_commands_explain_the_missing_database(argv, tmp_path, capsys):
    args = cli.build_parser().parse_args(argv)
    assert cli.cmd_jobs(args, settings(tmp_path)) == 2
    assert "ATH_DATABASE_URL" in capsys.readouterr().out


def test_cli_durable_commands_against_a_store(world, footing, monkeypatch, tmp_path, capsys):
    """The submit/work/status/report/cancel handlers over one shared in-memory store."""
    shared = InMemoryStore()
    monkeypatch.setattr(cli, "_open_store", lambda settings, allow_memory=False: shared)
    monkeypatch.setattr(cli, "load_telemetry", lambda path: world["telemetry"])
    monkeypatch.setattr(cli, "derive_footing", lambda telemetry: footing)
    # `jobs work` is a separate process in practice: it re-loads the corpus the
    # reference names and checks its digest before deriving the case again.
    monkeypatch.setattr("ath.persistence.worker.load_telemetry", lambda path: world["telemetry"])
    conf = settings(tmp_path, "postgresql://stubbed")
    parse = cli.build_parser().parse_args
    assert cli.cmd_jobs(parse(["jobs", "submit", "--no-llm", "--max-attempts", "1"]), conf) == 0
    assert cli.cmd_jobs(parse(["jobs", "submit", "--no-llm", "--max-attempts", "1"]), conf) == 0
    jobs = shared.list_jobs()
    assert len(jobs) >= 2 and all(j.status is JobStatus.QUEUED for j in jobs)
    assert cli.cmd_jobs(parse(["jobs", "cancel", jobs[-1].job_id]), conf) == 0
    assert cli.cmd_jobs(parse(["jobs", "work", "--drain", "--worker-id", "cli-w"]), conf) == 0
    assert shared.get_job(jobs[0].job_id).status is JobStatus.COMPLETE
    assert shared.get_job(jobs[-1].job_id).status is JobStatus.CANCELLED
    assert cli.cmd_jobs(parse(["jobs", "status", jobs[0].job_id]), conf) == 0
    out = capsys.readouterr().out
    assert "attempt 1  complete   worker cli-w" in out and "report revision 1" in out
    assert cli.cmd_jobs(parse(["jobs", "status", "--status", "cancelled"]), conf) == 0
    assert cli.cmd_jobs(parse(["jobs", "status", "missing"]), conf) == 2
    report = tmp_path / "report.md"
    assert cli.cmd_jobs(parse(["jobs", "report", jobs[0].job_id, "--out", str(report)]), conf) == 0
    assert shared.get_incident(jobs[0].incident_id).case_id in report.read_text(encoding="utf-8")
    assert cli.cmd_jobs(parse(["jobs", "report", jobs[-1].job_id]), conf) == 2
    listing = tmp_path / "status.json"
    assert cli.cmd_jobs(parse(["jobs", "status", "--json", str(listing)]), conf) == 0
    assert len(json.loads(listing.read_text())) == len(jobs)


def test_cli_jobs_submit_can_target_one_case_and_reports_an_unknown_one(world, footing, monkeypatch, tmp_path):
    shared = InMemoryStore()
    monkeypatch.setattr(cli, "_open_store", lambda settings, allow_memory=False: shared)
    monkeypatch.setattr(cli, "load_telemetry", lambda path: world["telemetry"])
    monkeypatch.setattr(cli, "derive_footing", lambda telemetry: footing)
    monkeypatch.setattr(cli, "load_settings", lambda: settings(tmp_path, "postgresql://stubbed"))
    case_id = next(iter(footing.cases))
    assert cli.main(["jobs", "submit", "--no-llm", "--case", case_id.lower()]) == 0
    assert len(shared.list_jobs()) == 1
    assert cli.main(["jobs", "submit", "--no-llm", "--case", "NOPE"]) == 2
    assert cli.main(["jobs", "submit", "--no-llm", "--max-steps", "1"]) == 2


def test_the_postgres_backend_is_optional_at_import_time():
    import ath.persistence.postgres as module

    assert "psycopg" not in module.__dict__
    assert "FOR UPDATE SKIP LOCKED" not in module.SCHEMA_SQL and "ath_job_attempts" in module.SCHEMA_SQL
    with pytest.raises(ValueError):
        module.PostgresStore("")


def test_scripted_answers_still_drive_a_complete_model_job(world, footing):
    """A model job that concludes cleanly is complete, with the model's claim on record."""
    store = InMemoryStore()
    job = submit(store, world, footing, model_requested=True, profile=OperationalProfile())
    case = footing.cases[store.get_incident(job.incident_id).case_id]
    reply = _answer([{"label": "benign", "statement": "administration is a possible explanation",
                      "evidence": [case.findings[0].evidence[0].event_id]}], disposition="benign")
    executor = make_executor(store, footing, job, llm_factory=lambda: ScriptedLLM(responses=[reply]))
    attempt = Worker(store, executor).run_once()
    audit = attempt.state["investigation"]["operational"]
    assert audit["engine"] == "d1"
    assert store.get_job(job.job_id).status in (JobStatus.COMPLETE, JobStatus.INCOMPLETE)
    assert store.latest_report(job.job_id).revision == 1


@pytest.mark.parametrize("delay", [10, 11])
def test_expired_owner_cannot_finish_before_cleanup(store, world, delay):
    _, incident = seed(store, world)
    job = enqueue(store, incident)
    now = utcnow()
    _, attempt = store.claim_job("owner", 10, now)
    with pytest.raises(LeaseLost):
        store.finish_attempt(attempt.attempt_id, "owner", AttemptOutcome.COMPLETE,
                             report={"late": True}, now=now + timedelta(seconds=delay))
    assert store.get_attempt(attempt.attempt_id).outcome is AttemptOutcome.RUNNING
    assert store.latest_report(job.job_id) is None
    _, replacement = store.claim_job("replacement", 30, now + timedelta(seconds=delay))
    assert replacement.number == 2
    assert store.get_attempt(attempt.attempt_id).outcome is AttemptOutcome.EXPIRED


def test_jobs_cli_can_explicitly_submit_legacy_profile(world, footing, monkeypatch, tmp_path):
    shared = InMemoryStore()
    monkeypatch.setattr(cli, "_open_store", lambda settings, allow_memory=False: shared)
    monkeypatch.setattr(cli, "load_telemetry", lambda path: world["telemetry"])
    monkeypatch.setattr(cli, "derive_footing", lambda telemetry: footing)
    args = cli.build_parser().parse_args(["jobs", "submit", "--no-llm", "--profile", "operational-v1"])
    assert cli.cmd_jobs(args, settings(tmp_path)) == 0
    assert all(type(profile_from_job(j)) is OperationalProfile for j in shared.list_jobs())


def test_unknown_job_profile_is_a_terminal_configuration_error(world):
    from ath.persistence.worker import ReproductionError
    profile = EvidenceProfile()
    job = InvestigationJob.create("incident", {**profile.to_dict(), "version": "future"},
                                  profile.sha256(), model_requested=False)
    with pytest.raises(ReproductionError, match="unsupported"):
        profile_from_job(job)



def test_report_serialization_failure_does_not_finish_attempt(store, world):
    _, incident = seed(store, world)
    job = enqueue(store, incident)
    _, attempt = store.claim_job("owner", 30)
    circular = {}
    circular["self"] = circular
    with pytest.raises(ValueError):
        store.finish_attempt(attempt.attempt_id, "owner", AttemptOutcome.COMPLETE, report=circular)
    assert store.get_job(job.job_id).status is JobStatus.RUNNING
    assert store.get_attempt(attempt.attempt_id).outcome is AttemptOutcome.RUNNING
    assert store.latest_report(job.job_id) is None
