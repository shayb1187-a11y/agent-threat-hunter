# Qwen3.5 9B development checkpoint review

Reviewed 2026-09-23. Inputs are the supplied checkpoint and notebook; neither was
modified or executed against a model during this review.

**Verdict: the checkpoint is internally consistent, but increasing model size did
not resolve the development failures. All three D1 investigations remain incomplete.
Do not interpret this checkpoint as a successful 9B evaluation or proceed to the
longer split on the strength of `complete_comparison: true`.**

## Artifact integrity and scope

| Input | SHA-256 |
| --- | --- |
| `ath_auth_execution_colab_9b_dev_checkpoint.zip` | `ac169590f2c4d35492ed151056ab62db0c311ae9aa8927c29f086a17d406a1c5` |
| `ath_auth_execution_colab_9b_only.ipynb` | `899a99a5d889425c94821af80802224a0f79c3102e1fb39cbb475c8b049a65c1` |

Archive paths below are relative to `ath-auth-execution-colab-9b/`.

- Both freeze hashes and all 18 saved row hashes validate. The two summaries
  recompute exactly, accounting for JSON's tuple-to-array serialization of missing
  row identities.
- Six development rows are present: three deterministic and three D1. The other
  12 rows are held-out deterministic baselines. **All 12 held-out D1 rows are missing**;
  their absence is recorded correctly, not treated as successful abstention.
- The freeze identifies `qwen3.5:9b`, Q4_K_M, digest
  `6488c96fa5faab64bb65cbd30d4289e20e6130ef535a93ef9a49f42eda893ea7`.
  Compared with the earlier 4B freezes, only model metadata, model configuration,
  and resulting freeze hashes differ. Protocol, manifests, source digest, profile,
  Python/pandas/platform values, and repeat counts match.
- Regenerated manifests match. Current source bytes reproduce the frozen source
  digest using Colab's POSIX path separators, as in the earlier review.
- Completion, correctness, and useful-citation scores agree with saved states.
  All 496 accepted claims carrying typed assertions were independently checked
  against regenerated telemetry; none failed verification.
- The notebook's Python cells parse, but all execution counts are null and it has
  no saved cell outputs. It does not establish the actual GPU allocation or residency.

These are consistency checks, not independent authentication of the execution.
The original archives and frozen rows remain unchanged.

## Development comparison

These are three synthetic development cases, not a statistically meaningful model
ranking. Comparison uses the earlier 4B **development** split, not its 12 held-out rows.

| Metric | Earlier 4B | New 9B |
| --- | --- | --- |
| Complete investigations | 0/3 | 0/3 |
| Correct decisions under the frozen rule | 0/3 | 0/3 |
| Useful follow-up events retrieved/cited | 0/2 | 0/2 |
| Target parent-child links recovered | 0/2 | 0/2 |
| Rejected claims | 1 | 4 |
| Accepted invalid typed predicates | 0 | 0 |
| Median case latency | 60.42 seconds | 102.79 seconds |
| Maximum case latency | 120.15 seconds | 120.17 seconds |
| Known reported tokens | 21,749 | 18,784 |
| Rows with unknown token usage | 1 | 1 |

The known token totals exclude a timed-out row in each model and cannot establish
lower total token consumption. All model decisions are forced abstentions after
incomplete execution; zero false accusations therefore does not show improved
classification. The 9B run is slower by the observed median, but this small,
failure-dominated sample does not establish general model speed or capability.

The paired 9B deterministic development baseline completes 3/3, gets 1/3 decisions
correct, and retrieves/cites 2/2 useful events. Its tendency to label everything
malicious remains a separate baseline weakness.

## Per-case findings

| Development row | Observed failure | Implication |
| --- | --- | --- |
| `sample-01_d1_1.json` (malicious) | First model call times out at 120.17 seconds; no reply or token count | Cannot evaluate this case's model reasoning |
| `sample-02_d1_1.json` (benign) | Retrieves user authentication history, then supplies `process_identity.expected = "services.exe"`; two claims rejected for assertion IDs outside their citations | The same typed-identity contract problem remains |
| `sample-03_d1_1.json` (missing evidence) | Selects `process_tree`, then network activity; final reply again uses `services.exe` as an identity; two earlier claims rejected | A relevant probe choice does not yield a valid completed investigation |

`services.exe` is a filename, not a source-qualified process-instance identity.
The visible invalid assertions reproduce the parser's specific error:
`process_identity requires a recognized source-qualified identity`.

In sample 03, one rejected claim also connects a process event to an authentication
event with `parent_child`. The verifier correctly rejects the relationship because
the event types do not support it. Another rejection concerns missing claim citations.
These are substantive evidence-contract errors, not merely malformed JSON.

The 9B model selects different probes from the earlier 4B development run, including
a process tree in the missing-evidence case. That is a behavioral difference, but it
does not establish improved task performance. No useful target follow-up is recovered.
None of these three 9B rows records output-token truncation; increasing the output
cap is not supported as the immediate fix for the failures in this checkpoint.

## Supplied notebook findings

1. **Development failures do not block the longer run.** Section 7 checks only
   `summary["complete_comparison"]`, which is true for this checkpoint despite
   `arms.d1.complete == 0`. Section 9 starts model calls without checking successful
   development completion. Require all three D1 investigations to complete, both
   when reporting development status and immediately before the next split. Keep
   checkpoint export available even when development fails.

2. **No model preload or GPU-residency check precedes timed investigations.**
   The first row records `resident_bytes: 0`; subsequent rows report approximately
   5.40 GiB already resident. Cold loading may have contributed to the first timeout,
   but the checkpoint contains no load-duration or GPU-placement evidence to prove
   that cause. `nvidia-smi` availability and a passing system-RAM check do not prove
   full GPU residency. Preload without a task prompt, record placement and loading
   time separately, and retain the investigation deadline for a new run.

3. **Checkpoint restoration can overwrite existing files.** Section 4 checks that
   archive paths stay in the 9B output directory, then uses `extractall('/content')`.
   Existing freezes and raw rows can be replaced before the evaluator validates
   them, contrary to the adjacent instruction. Compare existing bytes and reject
   conflicts, or restore into an empty matching directory. There is no evidence
   that such an overwrite occurred in the submitted checkpoint.

This is a different variant from the prepared
`ath_auth_execution_9b_colab.ipynb`, which includes preload, residency checks,
successful-development gating, and conflict detection during checkpoint restore.
Those safeguards cannot be assumed to have run here. Its additional
`RUN_CONTEXT.json` and preload records are also absent from this archive.

## Recommended next experiment

Fix the model-facing assertion representation before spending time on more cases:
constrain predicate-specific fields and present real identity values or deterministic
assertion references that the model can select. Preserve the strict verifier.
Use development-only tests for identity syntax, citation membership, and event-type
compatibility. Retain full bounded replies and specific validation errors for diagnosis.

Use the notebook's startup and development gates, then create a new freeze and output
directory for any changed implementation or run conditions. Preserve this 9B checkpoint
as a failed experiment; existing failures must not be silently replaced.

The original six held-out scenarios were inspected during the 4B review. A subsequent
run on them is exploratory. The original evidence-recovery success criterion also
remains unattainable where the baseline already retrieves all available useful events.
A claim of generalization or investigative improvement requires a separately declared
evaluation with appropriate headroom and fresh unseen cases.

Related: [4B review](auth-execution-colab-review.md),
[evaluation runbook](auth-execution-evaluation.md),
[assertion schema](../src/ath/agent/structured.py),
[predicate validation](../src/ath/agent/evidence.py).
