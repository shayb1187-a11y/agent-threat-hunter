# M19-1 results: arm A over the frozen manifest

**Manifest `1764be3cea5a5afd532038a40c934fc1d79baf88d91016a29ab3bfba6911aa15`** --
22 cases, 8 corpora, built at HEAD `ffc31d5`.
Artifacts: `MANIFEST.json`, `arm_A.json` (full per-case table), `scores_A.json`.
Predictions: `PREREGISTERED.md`, unedited.

```
python scripts/m19_ablation.py build
python scripts/m19_ablation.py run --arm A --repeat 2
python scripts/m19_ablation.py score --arm A
```

## Reproducibility -- invariant B

Arm A ran twice over the whole manifest inside one invocation, and the two runs are
**identical**: every claim, every rejected claim, every tool call and its event ids,
every plan-log line, every agent order and every score. Only wall seconds and wall-clock
timestamps are excluded from the comparison, and the exclusion list is itself asserted in
`tests/test_ablation_harness.py`. The manifest was also built in one process and run in
another, so the telemetry hashes were re-derived from a fresh load of every corpus and
matched -- loading is reproducible too, not merely investigating.

```
reproducibility: IDENTICAL
```

## Inputs, checked against the M18 / M18b artifacts

| corpus | rows (proc/net/logon/ctrl) | findings | cases | pinned | matches |
|---|---|---|---|---|---|
| `attack_data_aws` | 0 / 0 / 2 / 2347 | 33 | 2 | 2 | M18b `attack_data_aws.json` |
| `comiset` | 15095 / 589476 / 6063 / 0 | 5 | 2 | 2 | M18b `comiset.json` |
| `flaws_cloud` | 0 / 0 / 79424 / 1857154 | 1476 | 281 | 14 | M18b `flaws_cloud.json` |
| `synthetic:INC-001` | 456 / 389 / 267 / 0 | 13 | 1 | 1 | per-incident slice |
| `synthetic:INC-002` | 0 / 0 / 15 / 0 | 1 | 1 | 1 | per-incident slice |
| `synthetic:INC-003` | 448 / 381 / 252 / 0 | 2 | 0 | 0 | quiet day: no case, nothing to pin |
| `synthetic:INC-004` | 454 / 381 / 252 / 0 | 4 | 1 | 1 | per-incident slice |
| `synthetic:INC-005` | 0 / 0 / 0 / 4 | 2 | 1 | 1 | per-incident slice |

Rows, findings and case counts for the three real corpora are identical to M18b's, so
"identical inputs" is checkable rather than asserted. The synthetic corpora are the
per-incident slices `run_incident` builds and have no M18b counterpart (M18b measured the
whole `data/raw` set: 15 findings, 2 cases); their pipeline is instead pinned by the
benchmark, which is 5/5 with 0 noise cases at this HEAD.

## Arm A scores

`ec` = evidence_correctness, `cov` = evidence_coverage, `jac` = technique Jaccard,
`comp` = specialists run / eligible, `unsup` = unsupported claims. All means per case.

| corpus | cases | ec | cov | jac | comp | unsup | facts | inf | hyp | tools | steps | wall (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `attack_data_aws` | 2 | 1.000 | 1.000 | 1.000 | 1.00 | 0.00 | 22.5 | 3.0 | 0.0 | 3.5 | 2.0 | 0.005 |
| `comiset` | 2 | 1.000 | 1.000 | 1.000 | 1.00 | 0.00 | 4.0 | 3.5 | 0.0 | 5.5 | 2.0 | 0.053 |
| `flaws_cloud` | 14 | 1.000 | 1.000 | 0.976 | 1.00 | 0.00 | 18.2 | 3.1 | 0.0 | 3.4 | 2.0 | 0.094 |
| `synthetic:INC-001` | 1 | 1.000 | 1.000 | 0.941 | 1.00 | 2.00 | 20.0 | 28.0 | 2.0 | 43.0 | 4.0 | 0.072 |
| `synthetic:INC-002` | 1 | 1.000 | 1.000 | 0.667 | 1.00 | 0.00 | 2.0 | 4.0 | 0.0 | 3.0 | 2.0 | 0.002 |
| `synthetic:INC-004` | 1 | 1.000 | 1.000 | 1.000 | 1.00 | 0.00 | 2.0 | 3.0 | 0.0 | 6.0 | 2.0 | 0.013 |
| `synthetic:INC-005` | 1 | 1.000 | 1.000 | 1.000 | 1.00 | 0.00 | 3.0 | 5.0 | 0.0 | 5.0 | 2.0 | 0.005 |
| **all 22** | 22 | **1.000** | **1.000** | **0.967** | **1.00** | **0.091** | 15.2 | 4.4 | 0.09 | 5.6 | 2.1 | 0.068 |

Totals across the manifest: 335 facts, 97 inferences, 2 hypotheses, **0 rejected claims**,
**0 facts without evidence**, 4885 cited event ids of which 4885 exist, 361 case evidence
ids of which 361 were touched by a tool call, 123 tool calls, 46 steps, 22/22 runs ending
`complete`, 0 degraded runs, tokens `null`.

Identity hygiene (M18b-2): 3 facts carry "inferred from pid" (1 on INC-001, 2 on INC-004,
matching M18b's 3 for the synthetic corpus); 0 inferences name an ambiguous pid anywhere.

### Wall time per corpus (seconds)

| corpus | load | hunt + triage + correlate | arm A, both repeats |
|---|---|---|---|
| `flaws_cloud` | 58.5 | 38.8 | 42.3 |
| `comiset` | 0.5 | 13.2 | 12.2 |
| `attack_data_aws` | 0.1 | 0.1 | 0.1 |
| the four synthetic incidents | 0.0 | 0.4 | 1.2 |

Investigation is not the expensive part of this pipeline on any corpus: 22 cases twice
cost 56s in total, of which 42s is flaws.cloud's fourteen. Getting to the cases costs
about twice that.

## Grading the two predictions that are about arm A

> **(i) `evidence_correctness`.** Arm A is 1.0 by construction.

**Held.** 1.000 on every case, 0 rejected claims, 0 facts without evidence, 4885/4885
cited ids real.

> **(ii) `unsupported_claims`.** A = 0.

**Missed, on one case of 22.** Arm A produced two claims citing no evidence, both on
`synthetic:INC-001`, and both are deterministic HYPOTHESES the specialists are *designed*
to emit:

* `identity`: "The credentials for 'svc_backup' may have been obtained from memory on
  PC01. This is unverified: no telemetry links the credential-access activity to ..."
* `attack`: "Data staged on disk may have been transferred to the external destination
  observed in this case. This is unverified: ..."

A HYPOTHESIS is the one claim type permitted to stand without evidence -- that is what
makes it a hypothesis -- so this is not a defect, it is the prediction having been made
about a corpus (flaws.cloud, where M18-9 measured zero) and generalised to one where the
Windows chain reaches the two hedged conclusions the suite explicitly asks for. The
metric is unchanged. What it means for the decision rule in (vii) is that arm A's
baseline is **0.09 unsupported claims per case, not 0**, and a threshold derived from
"arm A's inference count" now has a non-zero floor to be read against.

> **(v) Hypotheses.** A = 0.

**Missed in the same place and for the same reason**: 2 hypotheses across 22 cases, both
on INC-001, 0 on all 14 flaws.cloud cases -- which is exactly what M18-9 measured, so the
prediction was right about the corpus it was drawn from and wrong as a general claim.

## What arm A leaves for the model arms to beat

* **`evidence_coverage` is already 1.000 on every case.** Prediction (iii) said C >= A;
  A is at the ceiling, so C can only tie or lose. If C ever scores below 1.0, planning
  skipped a specialist that had work -- which is precisely the finding (iii) anticipates,
  and the metric will now say so unambiguously rather than by a margin.
* **`specialists run / eligible` is 1.00 on every case**, and all 22 runs ended
  `complete` rather than at the step budget. Arm A never leaves eligible work undone, so
  any C run that does is visible immediately.
* **Technique agreement is 0.967, and every point of disagreement is in one direction.**
  `asserted_not_mapped` is `T1110.003` on three cases; `mapped_not_asserted` is empty
  everywhere. The `T1110.003` is an artefact of reading technique ids out of claim text:
  the ATT&CK mapper's own reason for `T1110.001` ends "(a spray against many accounts
  would be `T1110.003`)", so a technique named as a *contrast* counts as asserted. It is
  not corrected by a prose heuristic -- see the scoring module's docstring for why -- and
  every arm is read the same way.
* **Claims cite far more evidence than the case contains**: 4885 cited ids against 361
  case evidence ids. The specialists publish what the tools found (ancestry, children,
  peers), not only what the detections cited. An arm that cites fewer ids is not
  necessarily worse and an arm that cites more is not necessarily better; the column that
  matters is that all 4885 exist.

## Labels, where they exist

* `attack_data_aws/CASE-002` is labelled `T1580` by its capture file name; the mapper
  asserted it and the investigation named it (`labelled_technique_mapped: true`,
  `labelled_technique_asserted: true`). `CASE-001` spans two captures
  (`T1526__aws_security_scanner`, `T1580__aws_iam_accessdenied_discovery_events`) and is
  therefore left unlabelled rather than given one of the two arbitrarily.
* The four synthetic cases carry `run_incident`'s own fields, reused rather than
  re-implemented: all four passed, event recall 1.0 / 0.93 / 1.0 / 1.0, all trustworthy,
  0 fabricated citations.
* `flaws_cloud` and `comiset` carry no labels and are scored label-free only. That is the
  point of the label-free metrics existing.

## Known gaps

* **Arm B is declared, not implemented** (`NotImplementedError` with its design note).
* **Tokens are `null` for every arm.** No LLM client in this codebase reports usage;
  `run_arm` reads `tokens_used` off the client if it is ever there. Prediction (vi)'s cost
  column cannot be filled until a client reports it.
* **`AWS-005` is unrepresented in the flaws.cloud sample** because it appears in no case:
  17 findings, all MEDIUM, none of which linked to anything, and `singleton_min_severity`
  is HIGH. Recorded in `PREREGISTERED.md` next to the expectation it missed.
* **The synthetic corpora have no M18b counterpart** to check against, because M18b
  measured the whole `data/raw` set rather than the per-incident slices.
