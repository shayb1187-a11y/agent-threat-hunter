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
  every arm is read the same way. **¹ Superseded on 2026-09-13 -- the metric is now
  structural and this figure is 1.000. See "M19-2: the technique metric is structural
  now" below; this paragraph is left as written, because it is what the number meant when
  it was published.**
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
* The four synthetic cases carry the label-based fields `ath.evaluation.incidents.
  score_labels` computes **from the row's own investigation state** -- one definition,
  shared with the benchmark: all four passed, event recall 1.0 / 0.93 / 1.0 / 1.0, all
  trustworthy, 0 fabricated citations. Until M19 Phase 1 these were lifted from a
  *second* `run_incident` call made after the arm had already investigated the case;
  for arm A that second call is the same deterministic run, so every figure above is
  unchanged, and for a model arm it would not have been. See the Phase 1 addendum in
  PREREGISTERED.md.
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


---

# M19-2 (2026-09-13): the technique metric is structural now

## What changed, and why

`technique_agreement`'s asserted set was a regular expression over claim text. The
paragraph above named the resulting artefact honestly and kept it, which was the right
call for M19-1 -- the metric was pre-registered and an arm had already run against it.
M19-2 replaces the measurement rather than patching the sentence it tripped on:

**Asserted techniques are now the technique ids the investigation passed to the
`lookup_technique` tool**, read from the recorded `ToolCall` arguments. An investigation
asserts a technique by going and getting it. That is an action, it is already recorded,
and there is no wording to interpret. A call the tool budget refused is excluded: the
investigation asked, was not answered, and published nothing.

`Claim` carries no structured technique field. That was checked, and none was added:
inventing a field for one metric would let the metric shape the claim layer.

The old text-derived set is kept as a **diagnostic**, `techniques_in_prose`, with
`in_prose_not_asserted` beside it, so the difference between what an investigation
retrieved and what it wrote down stays visible instead of being scored.

## Arm A, re-scored

Same rows, same manifest `1764be3c…`, same 22 cases; only the scores move.

```
python scripts/m19_ablation.py run --arm A --repeat 2
```

| corpus | cases | Jaccard (M19-1, prose) | Jaccard (M19-2, structural) |
|---|---:|---:|---:|
| `attack_data_aws` | 2 | 1.000 | 1.000 |
| `comiset` | 2 | 1.000 | 1.000 |
| `flaws_cloud` | 14 | 0.976 | **1.000** |
| `synthetic:INC-001` | 1 | 0.941 | **1.000** |
| `synthetic:INC-002` | 1 | 0.667 | **1.000** |
| `synthetic:INC-004` | 1 | 1.000 | 1.000 |
| `synthetic:INC-005` | 1 | 1.000 | 1.000 |
| **all 22** | 22 | **0.967** | **1.000** |

The `T1110.003` artefact is gone, from exactly the three cases that carried it
(`synthetic:INC-001`, `synthetic:INC-002`, `flaws_cloud/CASE-005`). `T1110.003` now
appears in each of those rows under `in_prose_not_asserted`, which is precisely where a
technique nobody retrieved belongs. **Every other arm A number is unchanged**: the two
runs of this re-run were identical to each other, and each row is byte-identical to the
one M19-1 published apart from its scores, its wall-clock fields, and the new `budgets`
and `scripted` keys that every row now carries.

## What this costs -- stated, not buried

Only a specialist can call a tool. A model plans and synthesises; neither touches the
toolbox. So **a model arm cannot add to the asserted set at all**, and on any arm whose
crew reaches the ATT&CK step the asserted set simply *is* the mapper's set. The metric
has therefore become a coverage question -- *did this investigation retrieve the
techniques its own detection layer produced?* -- and arm A now answers it 1.000
everywhere, which means prediction (iv) can no longer be graded on this number alone.

That is a real loss and it is worth being explicit about: the question (iv) asks -- did
a model name a technique nothing supports -- is now answered by the
`in_prose_not_asserted` diagnostic, per case, and it must be read there. It is not folded
into the Jaccard, where a model's invention would have been indistinguishable from a
mapper disagreement.

Two cases where the structural metric will still move, and they are the ones that matter:

* a run that hits its **tool budget** before the ATT&CK step retrieves fewer techniques
  than the mapper produced, and scores below 1.0 with `mapped_not_asserted` naming
  exactly what it missed;
* a run whose **planner** skips the ATT&CK specialist retrieves none of them.

## The other change visible in these rows

Every row now carries a `budgets` block (`max_steps`, `tool_call_cap`,
`tool_calls_served`, `tool_calls_refused`, `tool_budget_hit`, `step_budget_hit`) and a
`scripted` flag. Arm A's `tool_call_cap` is `null` by the architect's ruling -- the cap
was invented for the generalist, and capping the baseline to match would change the thing
every other arm is read against. See the dated addendum in `PREREGISTERED.md`.

`specialists_run` now counts distinct specialists rather than steps. Arm A never runs a
specialist twice, so no arm A number moves; arm B's generalist runs on several steps and
would otherwise have reported a completeness above 1.0.

---

# M19-3: arm B's planner is consulted

**Everything below is a scripted run.** The responses were written by this repository,
not by a model; the rows live under `scripted/` and are labelled `*_SCRIPTED`. They prove
that the arm's planner and synthesis path executes end to end. **They say nothing
whatever about model quality**, and the fact counts below are a property of a canned
planner that always names the last eligible candidate.

```
python scripts/m19_ablation.py run --arm B --scripted
python scripts/m19_ablation.py run --arm C --scripted
```

## What changed, and why it had to

M19-2 built arm B as a crew of one. `InvestigationOrchestrator.plan` consults the model
only when more than one specialist is eligible, so arm B's planner was never asked
anything: **0 planner-chosen steps**. The arm measured synthesis over a fixed walk.

Arm B is still one generalist, and its tool surface is now seven facets of that surface
(`generalist:case`, `generalist:finding`, `generalist:process`, `generalist:timeline`,
`generalist:account`, `generalist:host`, `generalist:technique`) sharing one walk, one
toolbox and one budget. See the dated addendum in `PREREGISTERED.md`.

## How each step was chosen

`planner` = the model named an eligible candidate and the run followed it.
`only eligible` = one candidate, so the model was never asked. `fallback` = the
deterministic priority order, or the first eligible candidate in crew order.

| run | cases | steps | planner | only eligible | fallback |
|---|---:|---:|---:|---:|---:|
| B scripted, M19-2 | 22 | 49 | **0** | 49 | 0 |
| B scripted, M19-3 | 22 | 134 | **113** | 21 | 0 |
| C scripted, M19-3 | 22 | 46 | 3 | 43 | 0 |

Arm C is byte-identical to its M19-2 rows (re-run and diffed; only `generated_at`, `head`
and wall-clock fields differ). Arm A was re-run twice, reported `IDENTICAL`, and matched
its committed rows field for field, so its published file is left untouched.

## Arm B, before and after

| corpus | n | steps (before → after) | tool calls | facts | inf | hyp | step budget hit |
|---|---:|---:|---:|---:|---:|---:|---:|
| `attack_data_aws` | 2 | 4 → 12 | 14 → 14 | 10 → 10 | 2 → 2 | 2 → 2 | 0 → 0 |
| `comiset` | 2 | 4 → 12 | 14 → 14 | 14 → 14 | 2 → 2 | 2 → 2 | 0 → 0 |
| `flaws_cloud` | 14 | 28 → 84 | 99 → 99 | 84 → 84 | 14 → 14 | 14 → 14 | 0 → 0 |
| `synthetic:INC-001` | 1 | 7 → 8 | 35 → **23** | 35 → **23** | 1 → 1 | 1 → 1 | 0 → **1** |
| `synthetic:INC-002` | 1 | 2 → 6 | 7 → 7 | 6 → 6 | 1 → 1 | 1 → 1 | 0 → 0 |
| `synthetic:INC-004` | 1 | 2 → 6 | 8 → 8 | 8 → 8 | 1 → 1 | 1 → 1 | 0 → 0 |
| `synthetic:INC-005` | 1 | 2 → 6 | 8 → 8 | 6 → 6 | 1 → 1 | 1 → 1 | 0 → 0 |
| **all 22** | 22 | **49 → 134** | **185 → 173** | **163 → 151** | 22 | 22 | **0 → 1** |

Tool calls and facts are **unchanged on 21 of the 22 cases**. Every difference in the
totals comes from one case.

## The one case that lost work, and what it shows

`synthetic:INC-001` is the largest case in the manifest (13 findings, 35 planned
entities). It now ends at the 8-step budget with `generalist:case` and
`generalist:finding` still eligible and never run -- so it reaches 23 of its 35 entities
where the fixed walk reached all 35.

Two independent reasons, and they should not be conflated:

* **A step is narrower.** A facet walks up to `ITEMS_PER_STEP` entities *of its own
  kind*; the M19-2 agent walked five entities across kinds. A kind with one entity
  (`case`, `timeline`) therefore costs a whole step. This is the mechanical price of
  giving the planner a menu, and it is why step counts roughly tripled everywhere while
  tool calls did not move.
* **The canned planner chose badly, on purpose.** `ScriptedArmLLM` always names the
  *last* eligible candidate -- chosen so the plan log can be distinguished from the
  fallback, not because it is a good strategy. On INC-001 that spends the budget on
  techniques, hosts, accounts and processes and never reaches the findings. A run where
  the planner steers into worse coverage than the deterministic order is exactly the
  behaviour the ablation exists to be able to see, and here it is visible in the
  `budgets` block and in `eligible_never_ran` rather than hidden in a lower score.

Neither is evidence about a model. The first is a design property of the arm; the second
is a property of text written in `scripts/m19_ablation.py`.

## A harness defect this run found

The scripted planner parsed a candidate line by splitting on the first colon, so
`generalist:process` was read as `generalist` -- not an eligible name. The orchestrator
discarded every answer and every step fell back to the deterministic order: the first
M19-3 run recorded 0 planner steps and 113 fallback steps, which looks exactly like the
defect it was meant to fix. The parser now splits on colon-space, and
`tests/test_m19_scripted_harness.py` asserts it on a facet name. A harness proof that
silently proves the fallback works is worse than no proof.

## Completeness, and what it now means for arm B

`specialists_run` counts the agent *family*, so arm B reports **1 of 1** specialists run
on every case and its completeness is 1.0 throughout. That is correct -- arm B is one
agent -- and it means completeness can no longer say anything about arm B's coverage.
What arm B left undone is in `eligible_never_ran` (facet names) and in the `budgets`
block, per case, and it must be read there.

## Artifact size guard

M19-2 wrote and then replaced a 372 MB `scripted/arm_B.json`. `write_artifact` now
refuses any single artifact above 50 MB, prints the largest fields, and exits non-zero;
`tests/test_artifact_size_guard.py` fails if any file under `reports/` reaches 60 MB
outside the two named COMISET parquet freezes (53.2 MB each). The current
`scripted/arm_B.json` is 16.3 MB.
