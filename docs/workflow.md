# Investigation workflow (`ath workflow run`)

A checkpointed run of one case, or a batch of cases, from a telemetry export to a
report: **telemetry → seed or detection → investigation (tool calls, evidence) →
verdict → report**. It reuses the evaluator's code paths rather than re-implementing them
(`ath.evaluation.real_cases` for loading, slicing, seeding and incident re-derivation;
`auth_execution.evaluate_case` for the investigation and the decision rule;
`ath.reporting` for the reports). Module: `src/ath/workflow.py`.

It is **not** an evaluator. In a batch, a case's `expected_decision` appears beside the
verdict for scoring only, after the investigation. `useful_refs` and `link` are not
scored here, and `run.json` says so. For those metrics, use
[real-case evaluation](real-case-evaluation.md).

## Usage

```bash
# One case, detection mode: the (sliced) telemetry must correlate to exactly one incident
python main.py workflow run --telemetry data/external/x --kind winlogbeat --detect \
    --window-start 2020-05-01T02:00:00Z --window-end 2020-05-01T03:00:00Z --device HOST-A \
    --engine deterministic --profile operational-v5 --out runs/host-a

# One case, analyst seed: one native ref naming exactly one record
python main.py workflow run --telemetry data/external/x --kind winlogbeat \
    --seed-ref "host.name=HOST-A;winlog.record_id=123" --engine d1 --model qwen3.5:9b --out runs/seed-123

# A batch: a real-cases-v1 spec (see real-case-evaluation.md), one run dir per case
python main.py workflow run --batch specs/my-set.json --engine d1 --profile operational-v6 --out runs/my-set
```

Kinds are `winlogbeat`, `elastic-winevent`, `k8s` (with `--cluster`), `cloudtrail`,
`defender` and `canonical`. A batch takes its seed mode (`analyst` or `detection`) from
the spec. The exit codes are:

- 0: complete, or a batch that ran with no blocks
- 2: refused (bad arguments, altered run dir, changed inputs, or Ollama unavailable)
- 3: a case was blocked by the RAM guard
- 4: a single case had nothing to investigate (`undetected`, `ambiguous` or
  `labels_unresolved`, which is recorded in `02-seed/seed.json`)

`ath investigate --profile` also accepts `operational-v3` to `operational-v6`.

## Run directory

Here is a deterministic run on the dev fixture (the malicious development scenario of
`auth_execution.scenarios("dev")`, written as canonical CSV):

```
runs/dev-malicious/
├── 01-telemetry/   STAGE.json  telemetry.json  slice/{control,logon,network,process}_events.csv
├── 02-seed/        STAGE.json  seed.json
├── 03-investigation/ STAGE.json  state.json
├── 04-report/      STAGE.json  report.md  report.html  report.json
└── run.json
```

- `01-telemetry` holds the slice, written as canonical CSV and **reloaded**. Every later
  stage reads the reloaded slice, and its digest is re-checked on every resume.
- `02-seed/seed.json` holds the seed mode and status, the resolution of each ref, the
  anchor ids, and the incident's case id, event ids and rule ids. It also holds the seed
  findings and every detection finding and correlated incident. When no single incident
  exists, it records why.
- `03-investigation/state.json` holds `state.to_dict()`, the operational audit and the
  verdict inputs: `decision`, `triage_disposition`, `model_disposition`, and the rule
  that produced them. It also holds the model session record (`load_seconds`, residency)
  and the RAM-guard verdict.
- `04-report` holds the report as Markdown, HTML and JSON.
- `run.json` is written last. It holds the inputs, profile, model identity, whether the
  run was scripted, `load_seconds`, one `stage_sha256` per stage, and the verdict. When it
  exists, the case is done.
- `attempts/attempt-N.json` holds a RAM-guard block, with its figures and host memory.
  Attempts are never overwritten, and a later success does not erase them.

A batch writes `cases/<key>/` per case, plus `INDEX.json` and `index.html`. These two are
derived from the case directories and are rewritten on every batch invocation. They are
the only files the workflow replaces. Blocked and uninvestigated cases appear in both,
with a link to the attempt record or the seed record.

## Sealing and resume semantics

Each stage is built in `<stage>.partial/`. It is sealed by `STAGE.json`, which records
the sha256 of every artifact file, the stage's input hash, and a hash of the seal itself.
JSON artifacts are written through `auth_execution.write_new`. The stage is then renamed
into place with one `os.replace`. A stage directory therefore only exists once it is
complete. A leftover `.partial` directory comes from a killed run: it is discarded and
rebuilt, and never read.

Each stage's input hash chains the previous stage's seal with that stage's own
parameters. Stage 01 includes the absolute telemetry path, kind, window, devices, cluster,
seed mode and refs. It also includes a source fingerprint and the hash of ATH's source
code (`auth_execution.source_hash`). The fingerprint covers file names, sizes and mtimes,
not the content, because a multi-gigabyte export is not hashed on every resume. Stage 03
adds the engine, profile and model identity (the digest and configuration for Ollama).

When a run is resumed:

| On disk | What happens |
|---|---|
| The stage exists and its seal, artifacts and input hash all validate | It is reused. Nothing is rewritten, byte or mtime. |
| The stage was altered (seal or artifact edited, file added or removed) | **Refused**, and the files are left as found. |
| The stage's inputs differ from this invocation | **Refused**, naming the stage. Choose a new `--out`. |
| `run.json` exists but a stage it names is missing | **Refused**. A completed run is never partly rebuilt. |
| The stage is missing | It is computed. |

Nothing sealed is ever recomputed or overwritten. The fix is always a new run directory.

**Stages 03 and 04 run as one step.** The investigation cannot be reloaded as live
objects from `state.json`, and the report needs those objects. So both stages are built
from the same live state and sealed back to back. The only way to end up with 03 and no
04 is a crash between the two renames, which leaves no `run.json` either. In that case:

- With the **deterministic** engine, the investigation is re-run. The re-run must
  reproduce the sealed `state.json` exactly, apart from `run_id`, `started_at`,
  `called_at` and `elapsed_seconds`. Only then is 04 built from the re-run, and its seal
  records `rebuilt_from_rerun`. The report's timestamp and elapsed time come from the
  re-run. If the re-run differs in anything else (for example, after a code change), the
  rebuild is refused.
- With **d1**, the rebuild is always refused. A model investigation is not reproducible,
  so a report from a fresh run would describe a different investigation than the sealed
  one.

## Model loading

The model sits behind `ModelSession`. A batch uses **one client** for every case.

- `OllamaSession` calls `describe()` once to get the model's identity (digest, parameter
  size). The first case that needs an investigation triggers **one warm-up request**:
  `POST /api/generate` with no prompt, `keep_alive: -1` and the client's `num_ctx`, as
  the Colab notebook does. The session then checks residency once and records
  `load_seconds`. If the model is not resident after the warm-up, the run fails with
  `ModelNotResident`. It does not fall back to a slow first case. The model is not
  loaded when every case is already complete.
- The RAM guard (`check_ram(ram_floor_for(parameter_size), available_ram_bytes(),
  resident_bytes)`) runs before each case that needs an investigation. A live model is
  blocked unless the guard says `ok`. An undecidable guard blocks too, as in
  `auth_execution.run_rows`. A blocked case is recorded in `attempts/` and `INDEX.json`,
  and the batch continues. On the next invocation, that case is retried and the
  completed ones are reused.
- `ScriptedSession` wraps a `ScriptedLLM` for tests. It is labelled `scripted` in
  `state.json`, `run.json` and `INDEX.json`. Because it loads no weights, its default
  guard answers `ok: null` with that reason and does not block. A test can inject a
  failing guard.
- The deterministic engine has no session. `run.json` records `model: null` and
  `load_seconds: null`, which means not loaded, not zero seconds.

## Limits

- The source fingerprint does not detect a same-size edit that keeps the mtime.
- Moving the telemetry directory changes its absolute path, so the run is refused.
- A change to ATH's source code refuses every existing run directory. This is
  deliberate: the stages were computed by different code.
- Detection mode without a seed investigates only a slice with exactly one incident. If
  there are several incidents, narrow the slice with `--window-*` or `--device`, or use a
  batch spec with anchor refs.
