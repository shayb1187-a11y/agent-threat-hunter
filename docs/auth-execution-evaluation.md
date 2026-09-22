# Authentication-to-execution evaluation (milestone 3)

`python -m ath.evaluation.auth_execution` provides a separate, frozen comparison of
deterministic specialists and bounded D1, both using operational-v2. It does not
modify or reuse the existing frozen D1/M19 held-out experiment results.

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
