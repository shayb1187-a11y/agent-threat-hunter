# Authentication-to-execution evaluation (operational step 3)

**For the corrected Colab GPU run, use the
[self-contained operational-v5 notebook](../notebooks/ath_auth_execution_gpu_v5.ipynb)
and [its runbook](observation-reference-investigation.md).** It fixes the model-facing
evidence contract and includes the corrected source, GPU preload checks and development
gate. The operational-v2 protocol and historical results below retain their scope.

To score the same arms on real, externally labelled telemetry, see
[real-case evaluation](real-case-evaluation.md).

`python -m ath.evaluation.auth_execution` provides a separate, frozen comparison of
deterministic specialists and bounded D1, both using operational-v2. It does not
modify or reuse the existing frozen D1/M19 held-out experiment results.

For a new Colab run, use
[`notebooks/ath_auth_execution_colab.ipynb`](../notebooks/ath_auth_execution_colab.ipynb)
in Google Colab with a T4 GPU. The notebook now defaults to a separate Qwen3.5 9B
follow-up after the reviewed 4B run failed. It freezes both splits before investigation,
runs paired Colab baselines, resumes validated rows, and exports the result bundle.
The older Colab notebooks answer different D1-v3 questions and do not complete this
operational-v2 evaluation.

[Open the operational-v2 notebook directly in Google Colab](https://colab.research.google.com/github/shayb1187-a11y/agent-threat-hunter/blob/m14-real-data-validation/notebooks/ath_auth_execution_colab.ipynb).

## Scope and predeclared protocol

The generated Windows-shaped scenarios contain an authentication failure burst,
a subsequent success, and a remote command shell. The distinguishing child process
is outside the initially flagged evidence. There are three development cases and
six held-out cases: credential export, routine administration, and missing follow-up
telemetry. Held-out cases use different commands and independent seeds, but share
the mechanism family. This is a synthetic pilot, not external-corpus validation.

The deterministic case disposition adapter is declared in the freeze: malicious
when any existing triage assessment is likely malicious; benign only when all are
likely benign; otherwise abstain. D1 uses its explicit disposition. Neither arm
receives expected labels through its tools or prompts. Incomplete execution forces
abstention and is never counted as a correct missing-data decision.

The comparison records:

- Accuracy, benign false accusations, malicious false clearances, and missing-data abstention.
- Useful follow-up evidence retrieved/cited, and verified parent-child link recovery.
- Rejected claims, accepted invalid typed predicates, and unverified model prose.
- Elapsed time, reported tokens, and zero local Ollama API charges; hardware/energy costs remain unknown.

A promising pilot requires improved accuracy **and** more useful evidence cited,
zero malicious cases cleared as benign, no additional benign false accusations,
zero accepted invalid typed predicates, and every planned row complete. This strict
criterion is frozen before live calls. The development baseline already retrieves
all available useful evidence: this pilot can expose classification differences,
but cannot establish better evidence recovery if that ceiling persists. Do not
change the criterion after inspecting held-out results to manufacture a win.

Free-text semantic correctness and analyst time savings require human review and
are left unmeasured. Repeated runs are not independent incidents, and even a passing
pilot would not establish statistical significance or production readiness.

## Run and resume

Use a clean checkout: the freeze hashes every Python source under `src/ath`, generated
telemetry, protocol, profile, model digest/configuration, and runtime versions. Code,
data, model, daemon version, or configuration changes require a new freeze/directory.
Raw rows and freezes use exclusive creation; row hashes detect accidental edits.
Hashes are not signatures or a tamper-proof storage system. Only derived summaries
are overwritten. Scripted-client tests are labelled and cannot demonstrate AI value.

With a local Ollama model installed:

```powershell
.\.venv\Scripts\python.exe -m ath.evaluation.auth_execution freeze --out reports/auth-execution-dev --split dev --repeats 1
.\.venv\Scripts\python.exe -m ath.evaluation.auth_execution run --out reports/auth-execution-dev

# Freeze held-out settings before any held-out model calls; do not tune on results.
.\.venv\Scripts\python.exe -m ath.evaluation.auth_execution freeze --out reports/auth-execution-heldout --split heldout --repeats 2
.\.venv\Scripts\python.exe -m ath.evaluation.auth_execution run --out reports/auth-execution-heldout
.\.venv\Scripts\python.exe -m ath.evaluation.auth_execution summarise --out reports/auth-execution-heldout
```

`--arm deterministic` runs the baseline without model calls. `--arm d1` runs only
the model arm. Reissuing `run` validates and skips saved rows. Failures remain in
the denominator; existing failed rows are not silently retried. `SUMMARY.json`
lists missing rows, so an interrupted comparison cannot appear complete.

Each model case checks the repository's RAM floor, crediting already resident model
memory. A refusal returns exit code 3 before inference; free memory and resume later.
The profile's 120-second deadline is cooperative, not process preemption. A timeout
counts as an incomplete investigation. Baseline runs need no GPU or model loading.

Tests: `tests/test_auth_execution.py` covers discovery beyond detections, scored
abstention versus runtime failure, labelled scripted runs, changed freezes/rows,
duplicate results, missing result denominators, and append-only raw artifacts.

## Recorded baseline, 2026-09-22

The checked-in [development summary](../reports/auth-execution-dev/SUMMARY.json) and
[held-out summary](../reports/auth-execution-heldout/SUMMARY.json) contain baseline
results only. Every raw row includes its investigation, report and integrity hash.

| Held-out baseline metric | Result |
| --- | --- |
| Distinct scenarios / repeats | 6 / 2 |
| Complete executions | 12 / 12 |
| Correct decisions | 4 / 12 (33.3%) |
| Benign cases accused, including repeats | 4 / 4 |
| Correct missing-data abstentions, including repeats | 0 / 4 |
| Useful follow-up events retrieved and cited | 8 / 8 |
| Verified target parent-child links recovered | 8 / 8 |
| Accepted invalid typed predicates | 0 |
| Median / maximum latency | 0.046 / 0.057 seconds |

The baseline labels every incident malicious. It finds the extra evidence but the
declared triage adapter does not distinguish routine administration or missing
follow-up telemetry. These are descriptive synthetic results, not estimates of
production false-positive rates.

No live D1 investigation completed or started inference: the local model's RAM
guard refused at about 4.16 GiB available against a 4.5 GiB floor, including a retry
after the tests finished. The model arm has 12 missing held-out rows and three
missing development rows. Consequently the paired comparison is unfinished and
AI investigative value has not been demonstrated. After freeing memory, resume
development with the commands above, then the frozen held-out run without tuning
against its results. Use the clean publication checkout; unrelated source changes
in a shared working tree intentionally invalidate these freezes.

The dedicated Colab notebook creates new Colab-specific freezes outside the checkout.
Do not copy its rows over these checked-in Windows rows: keep the paired Colab baseline
and D1 rows together under their own result directory.

## Qwen3.5 9B follow-up

The [4B Colab review](auth-execution-colab-review.md) found zero completed model
investigations: invalid structured identities were the dominant failure. The current
notebook prepares `qwen3.5:9b` as a larger candidate on the same T4 setup. The
[Ollama model listing](https://ollama.com/library/qwen3.5:9b) reports approximately
6.6 GB for its Q4_K_M weights; the notebook checks GPU residency before cases run.
Better behavior on this task remains to be measured.

1. Upload the updated local `ath_auth_execution_colab.ipynb` to Google Colab using
   **File → Upload notebook**. The GitHub launch link uses the published version,
   which will not include local changes until they are pushed.
2. Select **Runtime → Change runtime type → T4 GPU** and use a fresh session.
3. Keep `MODEL = "qwen3.5:9b"` and `RUN_ID = "qwen35-9b-followup"`; run cells in order.
4. Save `ath_auth_execution_qwen35-9b-followup_dev_checkpoint.zip`. If any development
   investigation fails, the next stage stops and the checkpoint contains its reasons.
5. If development passes, the remaining cases run. Save
   `ath_auth_execution_qwen35-9b-followup_results.zip`, including any failed or missing rows.

Outputs live in `/content/ath-auth-execution-qwen35-9b-followup`. Do not restore 4B
archives into this run. The notebook verifies the evaluator's source digest against
the reviewed implementation and preserves the original prompts, data, sampling,
120-second investigation deadline, two-probe limit and 1,536-token output cap.
It preloads the model without a task prompt, records that separately, and excludes
loading time from case latency. That startup difference must be considered when
comparing time with the earlier run.

All three development investigations must successfully complete before further
model calls are made on the evaluation split. Row presence alone is insufficient.
Saved failures are not deleted or retried in place.

This is an exploratory follow-up on already inspected cases. The historical split
name `heldout` remains in the evaluator, but it is no longer unseen validation for
this model-selection exercise. `RUN_CONTEXT.json` records this distinction. The
unchanged success criterion still has its evidence-recovery ceiling; examine the
individual metrics. A larger model does not repair that evaluation-design limit.
