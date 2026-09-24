# Colab authentication-to-execution review

Reviewed 2026-09-23. This reviews supplied artifacts; it does not change the
protocol, implementation, freezes, or recorded results.

**Verdict: the experiment bundle is complete and internally consistent, but the
model arm failed to complete any investigation. Investigative value was not
demonstrated.** This is a useful failure analysis and a limited demonstration of
evidence rejection, not evidence of a successful AI investigator.

## Artifacts and validation

| Archive | SHA-256 |
| --- | --- |
| `ath_auth_execution_colab_complete.zip` | `d4f3cbfcd5fa6d95ce382a943cef1fbff642dfc0b85aa9dd2700080a4f82c770` |
| `ath_auth_execution_dev_checkpoint.zip` | `f460602e09c2a7c64c01bf82a095c3051c0ba92fcb76fbadf4af3bf8beba07b1` |

Paths below are relative to `ath-auth-execution-colab/` inside the archives.

- The complete archive contains six development rows and 24 held-out rows, each
  with a JSON record and Markdown report, plus the two freezes and summaries.
- Both freeze hashes and all 30 row hashes validate. Both complete summaries
  recompute exactly using the repository's summary function.
- The complete archive preserves all checkpoint files byte for byte except the
  derived `heldout/SUMMARY.json`. Its 24 added files are the 12 held-out D1 rows
  and their Markdown reports. The checkpoint is not a second independent experiment.
- Regenerated development and held-out manifests match the frozen manifests.
  Application source bytes match the frozen source digest when paths use Colab's
  POSIX separators. Native Windows hashing produces a different digest because
  `source_hash()` uses platform-specific path strings. This does not indicate a
  source-content change. Local runtime versions also differ from the Colab freeze;
  this review is not a live rerun or a claim of native freeze-validation success.
- Completion, correctness, useful citations, recovered links, rejected-claim counts,
  and retained model-prose counts agree with the saved investigation states.
- All 662 accepted claims carrying typed assertions were independently rechecked
  against regenerated telemetry; none failed the claim verifier.

These checks establish internal consistency. Self-contained hashes are not
signatures and do not independently attest execution provenance or the absence of
unrecorded tuning. No model calls were made during this review.

## Held-out results

Six distinct synthetic scenarios were each run twice per arm. Repeats are not
independent incidents. The model was `qwen3.5:4b`, Q4_K_M, with temperature 0 and
seed 0. Each held-out pair has identical recorded response excerpts, probe choices,
and errors; timing differs.

| Metric | Deterministic | D1 model |
| --- | --- | --- |
| Recorded executions | 12 | 12 |
| Successfully completed | 12/12 | 0/12 |
| Correct decisions under the frozen scoring rule | 4/12 (33.3%) | 0/12 (0%) |
| Benign executions labelled malicious | 4/4 | 0/4 |
| Correct missing-data abstentions | 0/4 | 0/4 |
| Useful events retrieved and cited | 8/8 | 2/8 |
| Target parent-child links recovered | 8/8 | 2/8 |
| Rejected claims | 0 | 8 |
| Accepted invalid typed predicates | 0 | 0 |
| Median latency | 0.128 seconds | 34.409 seconds |
| Maximum latency | 0.193 seconds | 85.925 seconds |
| Reported tokens | 0 | 85,256 |

Source: `heldout/SUMMARY.json`, checked against the individual rows.

The baseline labels every execution malicious. D1's zero false accusations and
zero false clearances result from all executions being incomplete and forced to
abstain; they do not establish better discrimination. Its 0% accuracy is the
declared end-to-end score, not an estimate of accuracy conditional on successful
execution. No successful model executions exist for that estimate.

Development also had zero completed D1 investigations out of three: one timeout,
one probe-budget exhaustion with a rejected claim, and one invalid-assertion failure.

## Findings

1. **The model-to-verifier contract is the dominant execution failure.** Ten of
   twelve held-out rows end with `invalid structured evidence assertions`. Every
   one contains a visible `process_identity` assertion using a command or process
   description as its expected value. For example, `heldout/rows/sample-01_d1_1.json`
   supplies a `cmd.exe /Q /c ...` command instead of a source-qualified identity.
   `EvidenceAssertion.from_dict()` rejects this with
   `process_identity requires a recognized source-qualified identity`.
   The generated JSON schema permits an arbitrary string for `expected`, while
   runtime validation imposes predicate-specific requirements. Valid JSON therefore
   does not imply a valid assertion. Preserve the strict verifier; a future version
   should constrain predicate shapes and expose only usable identity values or
   deterministic assertion references. Validate this on development cases first.

2. **Output capacity and probe selection also fail.** Both `sample-05` repeats
   terminate at `num_predict=1536`. Their two probes inspect network activity and
   never retrieve the distinguishing child process. Only `sample-02` selects
   `process_tree`, recovering the useful child and relationship in both repeats;
   it still fails later. Four held-out rows additionally have rejected claims,
   including assertion IDs absent from their claim citations and an observation
   label `O4` cited as though it were a telemetry event ID. Increasing the output
   allowance alone would not resolve these observed contract and evidence errors.

3. **The success criterion has no evidence-recovery headroom on this dataset.**
   The frozen rule requires D1 to cite strictly more useful evidence than the
   baseline. The baseline already cites 8/8 available useful events, so a passing
   result is unattainable on this frozen dataset even if decision quality improves.
   This ceiling was disclosed in the existing runbook. Keep this run's conclusion;
   design any subsequent protocol and dataset around the question it can actually
   answer. These held-out cases have now been inspected and cannot serve as fresh
   unseen evidence after tuning.

4. **Several labels and diagnostics need clearer interpretation.**
   `complete_comparison: true` means every expected result row exists, including
   failures; it does not mean investigations completed successfully. The generic
   model-status text says the run “ran deterministically” and the planner was never
   asked, even where D1 chose probes. The operational outcome and round records
   describe what happened more accurately. A future report should distinguish row
   coverage, execution completion, D1 probe selection, and deterministic enrichment.

5. **Response logging limits replay and diagnosis.** The implementation clips raw
   reply logs at 2,000 characters; 23 of the 29 model-round records end with that
   clipping marker. This is distinct from actual model output-token truncation.
   Assertion failures also collapse the specific parser exception into one generic
   message. A future artifact format should preserve the full bounded model reply
   and a precise validation error. The visible invalid identities substantiate the
   dominant failure here, but the bundle does not permit complete reply replay for
   every failed round.

Relevant implementation: [assertion schema and adapter](../src/ath/agent/structured.py),
[predicate validation](../src/ath/agent/evidence.py),
[D1 response logging](../src/ath/agent/investigator.py),
[summary and source hashing](../src/ath/evaluation/auth_execution.py), and
[generic model-status text](../src/ath/agent/state.py).

## Publication interpretation

A defensible project statement is:

> Evaluated a bounded local-model investigator on six synthetic held-out scenarios,
> with two repeats per arm. All model attempts ended incomplete, mainly due to
> invalid structured assertions. The verifier rejected invalid claims, but the
> model did not improve investigation quality over the deterministic baseline.

The observed rejection behavior supports the controls' operation in these cases;
it does not establish broad semantic correctness, production safety, or analyst
time savings. The baseline's classification weaknesses remain material as well.

The existing [evaluation runbook](auth-execution-evaluation.md) records the earlier
Windows baseline and local RAM refusal. These Colab results are a separate completed
experiment bundle and should be published alongside that history, not overwrite it.
Statements that the live comparison is still pending should be revised when the
Colab artifacts are incorporated into the project. This review leaves the original
archives, checked-in baseline rows, and implementation unchanged.
