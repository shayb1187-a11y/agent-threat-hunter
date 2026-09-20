# D1 model comparison: preparation record (2026-09-20)

What was audited, what was found, what was changed, and what the next Colab session
does. Everything here is read from the code and the recorded rows; nothing is a guess
about a model. The experiment this prepares is `notebooks/ath_d1_model_comparison_colab.ipynb`.

## The question, and the rule

Does a stronger local model improve D1's investigation when the architecture, evidence,
prompts, schema, budgets and cases stay fixed? The investigator is `d1-investigator-v3`
on both sides and is not changed. Model choice is the one variable. Prompt tuning
(`d1-investigator-v4`) and architecture changes (D2+) are separate experiments and are
not in this change. Rows from different prompt versions, manifests or client budgets
cannot be compared: `scripts/local_compare.py` refuses them.

## Phase 1: audit

### 1A. Why the 4B run stopped after nine rows

**Confirmed implementation defect, general, fixed.** The RAM guard credits a model the
daemon already holds against the floor (`RamVerdict.effective_bytes = available +
resident`). `OllamaLLM.resident_bytes` credited only the part *not* in VRAM ("VRAM is
not the memory the OS would page"). On a GPU host the whole model sits in VRAM, so the
credit was zero and the guard compared the host's free system memory (4.38 GiB, the
summary's `min available RAM seen`) against a floor meant for a CPU load (4.5 GiB for the
4B class). The refusal was written to `GUARD_EVENTS.jsonl` and the run stopped by design.

The floor is the system memory the weights take if they have to be loaded into it.
Weights already resident anywhere have spent that memory. The fix credits every loaded
byte (`size`), records where they live on each row (`header.model_residency = {size,
size_vram}`), and keeps the guard: with nothing loaded the full floor applies, an
unreadable `/api/ps` still credits nothing, and `--ignore-ram-floor` is neither used nor
recommended. The notebook loads each model (`keep_alive`) before its first row so the
credit applies from the first case.

Ruled out: memory accumulation in the runner. MEASURED on the laptop, loading six
injected bundles in sequence: process RSS 0.08 GiB throughout, each bundle 2.3k to 3k
rows. The row files are written atomically (`.partial` then `os.replace`) before the next
case starts. Ruled out: a wrong `MemAvailable` reading; `/proc/meminfo` is what Colab has.
Not measurable here: why the Colab box had only 4.38 GiB available at that moment (the
daemon, the CUDA context and the notebook kernel share a 12.7 GB VM). The readiness cell
now prints the figure and the guard's arithmetic before each run.

Tests: `tests/test_ollama_client.py` (partly offloaded, fully in VRAM, fully in system
memory, unreadable daemon) and the unchanged guard tests in
`tests/test_local_environment.py` and `tests/test_local_ablation.py`.

**Effect on existing rows: none.** The guard runs before a row and records its verdict
on the header; nothing the model sees or does changes. The nine 4B rows remain this
experiment's rows.

### 1B. The 5,346 "new evidence ids" on the flaws.cloud case

**Not a defect; a metric that named the wrong thing.** `user_auth_history` returns every
logon row for the account (`ToolBox.user_auth_history`: all activity, by design, no time
window) and the investigator counts `new_evidence_ids_returned` as those ids minus the
case's own. The observation the model reads renders a bounded head and tail
(`MAX_ROWS_SHOWN = 8`, six then two), so the model was shown eight ids of the 5,346, and
the FACT claim for the probe cites all 5,346 (which is what the claim asserts: the
account's history). Row size stays far under `MAX_ROW_BYTES`; the retrieval is one pandas
filter.

Change: the diagnostics now record `new_evidence_ids_shown` beside `returned` and `used`,
per round and per row, and the summary prints all three. Nothing the model reads changes;
`prompt_hashes()` is untouched, so v3 rows before and after summarise together (rows
without the field show as unrecorded, never as zero).

Not changed, recommended for a separate evaluation: bounding the account history to the
case window plus a margin would cut the FACT's citation list and the tool's cost on cloud
corpora. It would also change the evidence, so it is a new experiment version, not a fix.

### 1C. Evidence integrity, and three measurements that are not one

Model output cannot modify canonical evidence: tools read the telemetry tables and return
copies (`to_dict("records")`), the investigator never writes to them, and
`ClaimVerifier` is built from the telemetry independently of any client. It checks every
cited id exists, and an id the model was not shown but which exists is dropped from the
claim and counted as out of scope (`_conclude`).

The three measurements, as the rows record them:

1. **Rejected model claims**: `scores.rejected_claims` and `rejection_reasons`. In the
   nine 4B rows every rejection is an observation label (`O5`, `O6`, `O1`) cited as an
   id. This is a model failure against a rendering that puts `O<n>` and `[id]` on the
   same line; it is not fixed here, because fixing it means changing what the model sees.
2. **Evidence correctness**: `cited_event_ids_existing / cited_event_ids` over accepted
   *and* rejected claims (`score_case`). It is below 0.99 on seven of nine rows for the
   same reason as (1). Accepted claims alone are 1.0 by construction.
3. **Whether accepted claims are supported by what they cite**: not a number any script
   computes. It is the blind review (`scripts/m19b_review_build.py`), unchanged. A
   recovered citation pair (LINK-2) is a citation fact, not a correctness fact, and the
   comparison says so.

`ClaimVerifier` is unchanged.

### Model-behaviour findings (recorded, not acted on)

From the nine rows, in the raw replies now recorded per round: process_tree never chosen
in four of six LINK-2 misses (the network probe chosen on a PsExec-style output
redirect, then repeated on the other host); observation labels cited as ids in seven
rows; abstain as the final disposition on eight of nine rows. These are what the model
comparison is for.

## Phase 2: the nine 4B rows

They can be reused. They were written at `c4ccb24` under `d1-investigator-v3` with the
Colab manifest, and nothing in this change alters the investigator hashes, the schema,
the bounds, scoring or the manifest builder. The notebook restores them from the uploaded `dev_results.zip` (Google Drive is not used: its authorisation failed on the user's account, so results travel as downloaded and re-uploaded zips) into the session's rows directory without
overwriting, and the new `validate-rows` subcommand checks each row's manifest hash,
telemetry hash, model digest, daemon version, gated client configuration, prompt
version and investigator hashes against the live freeze and manifest. A row that fails is
moved to `<rows_dir>.quarantine/`, never deleted, and its case is rerun. `run` skips only
parseable rows under the exact manifest-and-version directory; `.partial` files never
count. Degraded rows are recorded failures and are kept, by the row store's design.

The rows will fail validation if the Colab runtime's telemetry digest differs from the
one they carry (a different numpy or pandas build). Then the notebook reruns the cases: a
clean baseline, reported as such. Expected, if the runtime matches: 11 cases run, 9
skipped.

## Phase 3: the challenger

`qwen3.5:9b` (Ollama library tag, 6.6 GB; Qwen3.5 dense 9B, Apache-2.0 on Hugging Face;
the family's default quantisation on Ollama is Q4_K_M; 256K native context). Same family
as the baseline, next dense size up, so parameters change and the tokenizer, chat
template and thinking control (`think: false`, which the 4B run already used) do not.
Verified against the Ollama library tag list on 2026-09-20; the daemon's own description
(`/api/show`) is printed and frozen before any row.

Settings identical to the baseline, by construction: the client is built by the same
`arm_d1` with the same `Sampling(0.0, 0)`, `num_ctx 10240`, `num_predict` cap 2048 and
768 per call, `format` = the response schema, `think` False. `local_compare.py` refuses
rows whose gated client configuration differs in anything but `model`. VRAM: 6.6 GB of
weights plus a 10K KV cache fits a 16 GB T4 with room; the readiness cell errors when the
model is not resident and warns when any of it is off the GPU. RAM guard: the 9B class
floor is 9.5 GiB; with the model loaded first, the credit is its full size.

Not changed for the challenger: no token budget, no thinking mode, no prompt. If the
9B cannot produce schema-valid JSON under the same settings, checkpoint 2 fails and the
notebook says to record a compatibility failure rather than retry with a different
budget.

## Phase 4: the comparison

`scripts/local_compare.py --models qwen3.5:4b qwen3.5:9b` pairs rows by case and applies
stated orderings per dimension (decision correctness against the label, LINK-2, new ids
used, productive probes, rejected claims, invalid references, tokens, wall). It reports
aggregates per model, contribution per 100k tokens, a B-vs-A tally, and a per-case table,
and refuses to compare when anything but the model differs. No significance test.

## Files

- `src/ath/agent/ollama_llm.py`: `resident_bytes` credits every loaded byte; `residency()`.
- `src/ath/agent/investigator.py`: `new_evidence_ids_shown` per round and per row.
- `src/ath/evaluation/ablation/local.py`: `gpu_summary()` recorded in the freeze; floor docstring.
- `scripts/local_ablation.py`: `model_residency` on every row header; `validate-rows` subcommand; shown ids in the summary.
- `scripts/local_compare.py` (new), `tests/test_local_compare.py` (new).
- `tests/test_local_validate_rows.py` (new); `tests/test_ollama_client.py`, `tests/test_d1_investigator.py` extended.
- `notebooks/ath_d1_model_comparison_colab.ipynb` (new); the earlier notebook is unchanged.
