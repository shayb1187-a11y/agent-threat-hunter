"""Real PostgreSQL concurrency and transactional failure tests; isolated test DB only."""

import multiprocessing
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest

from ath.persistence import AttemptOutcome, JobStatus, LeaseLost
from ath.persistence.models import utcnow
from ath.persistence.postgres import TABLES, PostgresStore
from test_d1_investigator import world  # noqa: F401
from test_persistence import enqueue, seed

URL = os.getenv("ATH_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not URL, reason="ATH_TEST_DATABASE_URL not set; real PostgreSQL required")


@pytest.fixture
def database():
    store = PostgresStore(URL)
    store.migrate()
    with store._tx() as cur:
        cur.execute("TRUNCATE " + ", ".join(TABLES) + " CASCADE")
    store.migrate()
    yield store
    store.close()


def _competing_worker(url, barrier, worker_id):
    store = PostgresStore(url)
    try:
        barrier.wait(timeout=30)
        while pair := store.claim_job(worker_id, 60):
            job, attempt = pair
            store.finish_attempt(attempt.attempt_id, worker_id, AttemptOutcome.COMPLETE,
                                 report={"job": job.job_id, "worker": worker_id})
    finally:
        store.close()


def _crashing_worker(url, pipe):
    store = PostgresStore(url)
    _, attempt = store.claim_job("crashed", 30)
    pipe.send(attempt.attempt_id)
    pipe.close()
    os._exit(17)  # Simulate abrupt process loss, without cleanup or lease release.


def test_independent_processes_claim_and_finish_each_job_once(database, world):
    _, incident = seed(database, world)
    jobs = [enqueue(database, incident) for _ in range(16)]
    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(4)
    processes = [ctx.Process(target=_competing_worker, args=(URL, barrier, f"worker-{i}")) for i in range(4)]
    try:
        for process in processes:
            process.start()
        for process in processes:
            process.join(45)
            assert process.exitcode == 0
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(10)
    for job in jobs:
        assert database.get_job(job.job_id).status is JobStatus.COMPLETE
        attempts = database.list_attempts(job.job_id)
        assert len(attempts) == 1 and attempts[0].outcome is AttemptOutcome.COMPLETE
        revisions = database.list_report_revisions(job.job_id)
        assert len(revisions) == 1 and revisions[0].attempt_id == attempts[0].attempt_id


def test_process_crash_reclaims_lease_and_rejects_stale_report(database, world):
    _, incident = seed(database, world)
    job = enqueue(database, incident)
    ctx = multiprocessing.get_context("spawn")
    reader, writer = ctx.Pipe(duplex=False)
    process = ctx.Process(target=_crashing_worker, args=(URL, writer))
    process.start()
    writer.close()
    try:
        assert reader.poll(30), "crashed worker did not acquire a job"
        stale_id = reader.recv()
        process.join(10)
        assert process.exitcode == 17
    finally:
        reader.close()
        if process.is_alive():
            process.terminate()
            process.join(10)
    expiry = database.get_job(job.job_id).lease_expires_at
    replacement = PostgresStore(URL)
    try:
        _, attempt = replacement.claim_job("replacement", 30, now=expiry + timedelta(seconds=1))
        assert attempt.number == 2
        with pytest.raises(LeaseLost):
            database.finish_attempt(stale_id, "crashed", AttemptOutcome.COMPLETE,
                                    report={"stale": True}, now=expiry + timedelta(seconds=2))
        replacement.finish_attempt(attempt.attempt_id, "replacement", AttemptOutcome.COMPLETE,
                                   report={"replacement": True}, now=expiry + timedelta(seconds=2))
    finally:
        replacement.close()
    assert [a.outcome for a in database.list_attempts(job.job_id)] == [
        AttemptOutcome.EXPIRED, AttemptOutcome.COMPLETE,
    ]
    assert [r.report for r in database.list_report_revisions(job.job_id)] == [{"replacement": True}]


@pytest.mark.parametrize("rollback", [False, True])
def test_attempt_and_report_become_visible_atomically(database, world, monkeypatch, rollback):
    import threading

    _, incident = seed(database, world)
    job = enqueue(database, incident)
    _, attempt = database.claim_job("writer", 60)
    writer = PostgresStore(URL)
    inserted, release = threading.Event(), threading.Event()
    append = writer._append_revision

    def pause_after_insert(*args, **kwargs):
        result = append(*args, **kwargs)
        inserted.set()
        assert release.wait(15)
        if rollback:
            raise RuntimeError("injected failure after report INSERT")
        return result

    monkeypatch.setattr(writer, "_append_revision", pause_after_insert)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(writer.finish_attempt, attempt.attempt_id, "writer", AttemptOutcome.COMPLETE,
                                 report={"complete": True})
            try:
                assert inserted.wait(15)
                assert database.get_job(job.job_id).status is JobStatus.RUNNING
                assert database.get_attempt(attempt.attempt_id).outcome is AttemptOutcome.RUNNING
                assert database.latest_report(job.job_id) is None
            finally:
                release.set()
            if rollback:
                with pytest.raises(RuntimeError, match="injected"):
                    future.result(timeout=15)
            else:
                future.result(timeout=15)
        assert database.get_job(job.job_id).status is (JobStatus.RUNNING if rollback else JobStatus.COMPLETE)
        assert database.get_attempt(attempt.attempt_id).outcome is (
            AttemptOutcome.RUNNING if rollback else AttemptOutcome.COMPLETE
        )
        assert len(database.list_report_revisions(job.job_id)) == (0 if rollback else 1)
    finally:
        writer.close()


def test_locked_oldest_job_does_not_block_other_claimants(database, world):
    _, incident = seed(database, world)
    first, second = enqueue(database, incident), enqueue(database, incident)
    other = PostgresStore(URL)
    try:
        with database._tx() as cur:
            cur.execute("SELECT job_id FROM ath_investigation_jobs WHERE job_id = %s FOR UPDATE", (first.job_id,))
            with other._tx() as cursor:
                cursor.execute("SET statement_timeout = '3s'")
            claimed, _ = other.claim_job("other", 30, utcnow())
            assert claimed.job_id == second.job_id
    finally:
        other.close()



def test_finish_rechecks_expiry_after_waiting_for_row_lock(database, world, monkeypatch):
    import threading
    import time

    _, incident = seed(database, world)
    job = enqueue(database, incident)
    claimed, attempt = database.claim_job("owner", 0.5)
    writer = PostgresStore(URL)
    waiting = threading.Event()
    locked_pair = writer._locked_pair

    def signal_then_lock(*args):
        waiting.set()
        return locked_pair(*args)

    monkeypatch.setattr(writer, "_locked_pair", signal_then_lock)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with database._tx() as cur:
                cur.execute("SELECT job_id FROM ath_investigation_jobs WHERE job_id = %s FOR UPDATE", (job.job_id,))
                future = pool.submit(writer.finish_attempt, attempt.attempt_id, "owner", AttemptOutcome.COMPLETE,
                                     report={"late": True})
                assert waiting.wait(10)
                time.sleep(max(0, (claimed.lease_expires_at - utcnow()).total_seconds()) + 0.1)
            with pytest.raises(LeaseLost):
                future.result(timeout=10)
        assert database.latest_report(job.job_id) is None
    finally:
        writer.close()
