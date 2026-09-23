# Operational step 4: persistence and reliable background execution

This is step 4 of the operational delivery sequence, separate from historical
research milestone M4. See the [roadmap](../README.md#roadmap).

## What was added, and what was left alone

| Component | Existing implementation | Operational step 4 action |
| --- | --- | --- |
| Toolbox, verifier, investigators, report builder | In-process objects built per case by the CLI | Unchanged. The store sits beside the toolbox: it supplies the toolbox's inputs (a telemetry reference and a pinned case) and keeps what the toolbox produced (the ledger inside the serialised state). The frozen tool surface is untouched. |
| Operational profile | `investigate_operational` with per-case limits | Reused as the only execution path for a job; the profile values and their hash travel with the job. |
| Batch evaluation | `ath-experiment`, the incident benchmark, the ablation harness | Unchanged; they keep their in-process toolboxes. The in-memory store is the default for any single-process run. |
| Run records | JSON files per experiment invocation (`ath.experiments.runs`) | Unchanged. Investigation jobs are a separate, operational record with a lifecycle, not a replacement for experiment provenance. |

New package: `src/ath/persistence/`.

| Module | Holds |
| --- | --- |
| `models.py` | `TelemetryReference`, `Incident`, `InvestigationJob`, `JobAttempt`, `ReportRevision`; JSON-safe round trips. |
| `store.py` | The `InvestigationStore` contract and the pure lifecycle rules (`claim_transition`, `finish_transition`, `cancel_transition`) both backends apply. |
| `memory.py` | `InMemoryStore`: lock-protected dictionaries, nothing survives the process. |
| `postgres.py` | `PostgresStore`: one transaction per call, `FOR UPDATE` on every row a worker changes, `SKIP LOCKED` claims, the DDL in `SCHEMA_SQL`. |
| `worker.py` | `submit_investigations`, `Executor`, `Worker`. |

## Records

- **Telemetry reference**: a corpus location plus the v2 content digest and per-table
  row counts. Registering the same digest twice returns the first record. Rows are not
  copied into the database.
- **Incident**: one correlated case pinned to one telemetry reference by the SHA-256 of
  the case's canonical serialisation. The same case on the same telemetry registers once.
- **Investigation job**: the durable request. It carries the operational profile values
  and their hash, whether a model was requested, a retry allowance (`max_attempts`),
  whether an *incomplete* result may be retried, and the current lease.
- **Job attempt**: one worker's execution, numbered per job. Its `state` is the full
  serialised `InvestigationState`, including the tool ledger with argument and result
  hashes, so an attempt is auditable on its own.
- **Report revision**: one rendered report (structured JSON and Markdown) with its
  hash, numbered per job. Revisions are appended, never rewritten, and the revision an
  attempt produces is written in the same transaction as the attempt's completion.

## Lifecycle

```
queued --claim--> running --finish--> complete | incomplete | failed | cancelled
   ^                 |
   +---- requeue ----+   (lease lapsed, or a retryable fault with attempts remaining)
```

- A claim takes the oldest queued job and leases it to one worker. Expired leases are
  requeued before every claim and by `expire_leases`; the lapsed attempt is recorded as
  `expired`.
- Only the lease owner can heartbeat or finish. A worker that finishes at or after its lease expiry, even before cleanup or
  reassignment, receives `LeaseLost`; its result is discarded, never written over the
  newer attempt's.
- A fault (`failed`) retries while attempts remain. Faults that cannot change on retry,
  such as telemetry whose content no longer matches its digest or a case that no longer
  derives from its telemetry, mark the job failed at once.
- An `incomplete` investigation is a recorded result, not a fault. It retries only when
  the job was submitted with `--retry-incomplete`.
- Cancelling a running job ends its attempt as `cancelled` and refuses the worker's
  later result.

## Execution

New jobs default to `operational-v2`, including typed evidence checks and verified
observations in stored reports. `jobs submit` and `jobs run` accept
`--profile operational-v1` for explicit compatibility. The executor reconstructs
the recorded version and verifies the complete profile and hash; existing v1 jobs
remain v1, and unknown versions fail without retry. No database migration is needed
for this change because the version is already stored in the profile JSON.

The executor re-derives its inputs rather than trusting stored copies: it loads the
telemetry the reference names, checks the digest, re-runs the hunt, triage set-aside and
correlation exactly as `ath investigate` does, and refuses to proceed unless the derived
case hashes to the incident's recorded case. It then calls `investigate_operational`
with the job's profile and a fresh toolbox, builds and renders the report, and records
attempt and revision together.

Errors are stored by exception type only. Transport exceptions can carry credentials or
prompt text, and neither belongs in the database.

A worker heartbeats on a daemon thread at a third of the lease by default. A crashed
worker stops heartbeating, its lease lapses, and another worker takes the job with the
lapsed attempt on record.

## Usage

Single process, no database (in-memory store; the same lifecycle end to end):

```powershell
.\.venv\Scripts\python.exe main.py jobs run --no-llm --json reports/local/jobs.json
```

Durable queue:

```powershell
$env:ATH_DATABASE_URL = "postgresql://ath:secret@localhost:5432/ath"
.\.venv\Scripts\python.exe -m pip install -e ".[postgres]"
.\.venv\Scripts\python.exe main.py jobs migrate
.\.venv\Scripts\python.exe main.py jobs submit --no-llm            # every correlated case
.\.venv\Scripts\python.exe main.py jobs work --worker-id host-a    # keeps polling; Ctrl-C to stop
.\.venv\Scripts\python.exe main.py jobs status
.\.venv\Scripts\python.exe main.py jobs status <job-id>            # attempts and revisions
.\.venv\Scripts\python.exe main.py jobs report <job-id> --out reports/local/<job-id>.md
.\.venv\Scripts\python.exe main.py jobs cancel <job-id>
```

`jobs run` exits 3 when any job did not complete, matching `investigate --profile
operational-v2`. `jobs work` exits 130 on Ctrl-C; a running attempt's lease lapses on
its own. Commands that need a database explain the missing `ATH_DATABASE_URL` and exit 2.

Python:

```python
from ath.persistence import Executor, InMemoryStore, Worker, submit_investigations
from ath.persistence.postgres import PostgresStore

store = PostgresStore(dsn)          # or InMemoryStore()
store.migrate()
jobs = submit_investigations(store, telemetry, data_dir, case_ids=["CASE-001"])
Worker(store, Executor(store, llm_factory=build_llm)).run(drain=True)
revision = store.latest_report(jobs[0].job_id)
```

## Boundaries

- **No preemption.** A CPU-bound attempt that ignores the profile's cooperative time
  budget holds its lease while its heartbeat runs. Cancellable worker isolation
  (a child process with a hard deadline) is still future work.
- **At-least-once, not exactly-once.** Two workers can execute the same job when a
  lease lapses under a live worker; the second result is refused, the work was still
  done twice.
- **Attempts restart from the beginning.** The stored state is an audit record, not a
  checkpoint; a mid-investigation resume is not provided.
- **The store does not hold telemetry.** A reference is a location and a digest; if the
  files move or change, the job fails without retry rather than investigating something
  else.
- **The PostgreSQL contract is verified only where a database is available.** The
  contract tests run against both backends; the PostgreSQL parametrisation skips, and
  says so, unless `ATH_TEST_DATABASE_URL` names a database the tests may truncate.
  Local validation uses an isolated PostgreSQL 16.2 server supplied by `pgserver`.
  CI now runs a dedicated PostgreSQL 16 service with the contract and concurrency
  tests. Four independent processes compete for 16 jobs; additional tests exercise
  abrupt process death, reassignment, stale-result rejection, lock waits across
  expiry, and report/attempt visibility and rollback through separate connections.
  These bounded integration tests are not a throughput or production load test.
- **Job records are operational, not experimental provenance.** The experiment runner's
  run records, manifests and frozen pins are unchanged and remain authoritative for
  measured results.

## Acceptance checks

`tests/test_persistence.py` covers idempotent registration, exclusive oldest-first
claims, lease ownership on heartbeat and finish, expiry and retry up to the allowance,
retryable versus terminal faults, incomplete-as-result, revision numbering and
atomicity with the attempt, cancellation, record round trips, the worker end to end
over the shared fixture world (deterministic complete, model incomplete, raising
executor without leaking exception text, non-reproducible case, lost lease, heartbeat
through a short lease), and every `jobs` subcommand. It also covers both profile versions, expiry before cleanup,
unknown profiles and report-serialization rollback.

`tests/test_postgres_workers.py` exercises independent PostgreSQL connections and
processes, including a deliberate crash and an injected failure after a report
INSERT but before commit. Test only against a disposable database: these tests
truncate all ATH tables. Run sequentially, without pytest-xdist workers sharing
the same database.

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests scripts
$env:ATH_TEST_DATABASE_URL = "postgresql://..."; .\.venv\Scripts\python.exe -m pytest -q tests/test_persistence.py tests/test_postgres_workers.py
```

Validation on 2026-09-23: the full suite passed with the isolated PostgreSQL 16.2
server enabled: **2,386 passed, 5 skipped**. PostgreSQL contract and concurrency
tests ran; the five skips belong to other optional checks. Ruff passed. The local
server was stopped after validation. CI is configured to repeat the database tests.
