# M19: the agentic ablation, measured

Run 2026-09-13/14 on the frozen checkout at `5b8c3f2` (freeze `0dcfdf4`, reports only).
Manifest `1764be3c…` (22 cases, 8 corpora). Predictions: `reports/m19/ablation/PREREGISTERED.md`,
unedited. Artifacts: `arm_{A,B,C}.json`, `scores_{A,B,C}.json`, `run_{A,B,C}.log`,
`GRADING.json` (produced by `scripts/m19_grade.py`, which post-dates the runs and only
joins the artifacts), `HYPOTHESES.md`. Nothing was changed after any result was observed.

Every number below is MEASURED from those artifacts unless marked otherwise.

## 1. What ran

```
python scripts/m19_ablation.py freeze                     # 0dcfdf4, credential present
python scripts/m19_ablation.py run --arm A --repeat 2     # reproducibility: IDENTICAL
python scripts/m19_ablation.py score --arm A
python scripts/m19_ablation.py run --arm B --check-planner
python scripts/m19_ablation.py score --arm B
python scripts/m19_ablation.py run --arm C --check-planner
python scripts/m19_ablation.py score --arm C
```

Arm A re-ran at this freeze and reproduced the Phase 1 result field for field; the only
differing fields are timestamps, wall seconds and the recorded head commit. Model arms
B and C ran once each against `claude-opus-5`, thinking adaptive, `max_tokens` 8192,
under the frozen prompts, budgets (8 steps, 40 tool calls) and tool surface.

## 2. The three arms

| arm | rows | evidence correctness | coverage | technique Jaccard | unsupported / case | hypotheses / case | tool calls / case | steps / case | wall s / case | tokens / case | facts / inferences / hypotheses | rejected |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| A deterministic | 22 | 1.000 | 1.000 | 1.000 | 0.09 | 0.09 | 5.6 | 2.1 | 0.2 | 0 | 335 / 97 / 2 | 0 |
| B single LLM | 20 | 1.000 | 1.000 | 0.950 | 0.00 | 2.05 | 7.8 | 6.1 | 47.6 | 55,917 mean, 71,280 median | 133 / 79 / 41 | 0 |
| B DEGRADED | 2 | 1.000 | 1.000 | 1.000 | 0.00 | 0.00 | 7.0 | 6.0 | 31.6 | 3,191 mean | 14 / 0 / 0 | 0 |
| C crew LLM | 22 | 1.000 | 1.000 | 0.997 | 0.09 | 2.68 | 5.6 | 2.1 | 27.8 | 9,767 mean, 3,677 median | 335 / 161 / 59 | 0 |

Totals: B 1,230,172 tokens and 1,016 s; C 214,862 tokens and 611 s; A 4.6 s.

## 3. Degradations and the planner, preserved as measured

* **Arm B degraded on 2 of 22 rows**, both COMISET cases: one model call each returned
  HTTP 413 (request entity too large), which the frozen client treats as permanent, so the
  row finished deterministically and is aggregated under `B_single_llm_DEGRADED`. On both
  rows the planner had already decided 5 of 5 multi-candidate steps; what was lost was
  synthesis: 0 inferences, 0 hypotheses. HYPOTHESIS, not measured: the oversized request
  was the synthesis call, whose user message carries every facet's tool output for the
  largest corpus (589,476 network rows).
* **Arm C degraded on no row.** One reply on `attack_data_aws/CASE-001` was complete but
  unparseable and was counted, not retried, as the freeze specifies.
* **Arm B's planner was asked on every case:** 113 multi-candidate steps offered, 113
  chosen by the model, 0 fallbacks.
* **Arm C's planner was asked on one case.** The specialist crew offered more than one
  eligible candidate only on `synthetic:INC-001` (3 steps, all chosen). On the other 21
  cases exactly one specialist was eligible at every step, so the orchestrator never
  consulted the model. **On 21 of 22 cases arm C differs from arm A in synthesis alone.**
  This is a property of the crew's eligibility gating on these corpora, not of the model,
  and it is the single most important thing the experiment measured about arm C.
* Budgets: C hit the 40-call cap on `synthetic:INC-001` (40 served, 3 refused) and still
  reached coverage 1.000, so the M19-2 addendum's expected 0.968 did not materialise: the
  refused calls would have re-touched evidence already covered. B hit the 8-step budget on
  the same case (19 tool calls served) with coverage 1.000, but never reached its
  `technique` facet.

## 4. The seven predictions, graded

| # | Prediction | Grade | Measured |
| - | ---------- | ----- | -------- |
| (i) | evidence_correctness: A = 1.0; B and C must stay 1.0 or be disqualified | **MATCH** | A, B, C all 1.000 on every row; 0 rejected claims, 0 facts without evidence, 0 fabricated citations in 22 + 22 + 22 rows |
| (ii) | unsupported_claims: A = 0; B and C > 0 expected, the primary cost | **MISS, in the direction of the model arms** | A 2 (its two deterministic INC-001 hypotheses, known since M19-1); **B 0**; C 2 (the same two). Every model-authored hypothesis, all 100 of them, carried evidence ids that exist |
| (iii) | coverage: C >= A, else planning skipped a specialist | **MATCH** | C = A on every one of 22 cases (mean 1.000 both); B also 1.000 |
| (iv) | technique_agreement: C's asserted set differs from the mapper's; report both directions | **MATCH in form, differently than predicted** | asserted-but-unmapped: **0** for every arm (no model named a technique the mapper had not). mapped-but-unasserted: C misses one (`T1074.001` on INC-001); **B misses all 16 mapped techniques on INC-001** because its step budget ran out before the `technique` facet; B Jaccard 0.950, C 0.997 |
| (v) | hypotheses: A = 0; B and C will produce some; actionable vs restating by manual reading | **PARTIAL** | A 2 (M19-1 already recorded the miss on "A = 0"); B 41 on 19 cases; C 59 on 21 cases. Actionable-vs-restating: **UNAVAILABLE** here by design; every hypothesis is in `HYPOTHESES.md` for a human |
| (vi) | cost, reported never credited | reported | B 55.9k tokens and 46 s per case; C 9.8k tokens and 28 s per case; A 0.2 s. C's median (3.7k) is far below its mean: the one case with a real planner (INC-001, 122.7k tokens) dominates |
| (vii) | decision rule: unsupported under a threshold set from A's inference count **and** ≥ 1 hypothesis per case citing evidence A did not cite | **B: 13 of 22 cases. C: 0 of 22.** | Threshold set here as A's mean inferences per case (4.41); at 1.0 the counts are identical. Condition 1 holds on all 22 cases for B and on 22 (21 at the strict threshold) for C. Condition 2: B produced a hypothesis citing evidence A's claims never cited on 13 cases (the same 13 when "never touched by A's tools" is used instead); **C on none**: every C hypothesis cites only evidence the deterministic specialists had already cited |

## 5. Labels

| case | A | B | C |
| --- | --- | --- | --- |
| attack_data_aws/CASE-002 (label T1580) | asserted | asserted | asserted |
| attack_data_aws/CASE-001 | spans two captures, no single label | same | same |
| synthetic INC-001 | passed, trustworthy | **failed: `overclaimed_as_fact: exfiltrat`** | passed |
| synthetic INC-002 / 004 / 005 | passed | passed | passed |

The B failure on INC-001 is a tool-authored FACT: the generalist's `finding` facet
republishes each finding's detector reason verbatim as a FACT (`source: detector`), and
ATH-008's reason reads "consistent with staging data prior to exfiltration, but …". The
model wrote nothing in that sentence; the never-as-fact substring check flags the
detector's own hedged phrasing once it is carried under the FACT type. Arm C's one mention
of exfiltration on that case is a HYPOTHESIS, and arm A's specialists never republish
reason text. VERIFIED FROM the row's claim `source`/`agent` fields. Recorded as measured;
whether the metric or the facet is wrong is a question for after this milestone.

## 6. What the experiment established

1. **The verifier boundary held under a real model.** 44 model-arm rows, 100 model-authored
   hypotheses, 240 model-authored inferences: zero fabricated citations, zero rejected
   claims, zero facts without evidence. Prediction (ii)'s "primary cost" did not appear.
   Either reading is available: the model was disciplined, or the claim schema (a FACT or
   INFERENCE cannot be constructed without evidence; a HYPOTHESIS must cite ids that exist
   to be counted as supported) leaves the model nowhere to put an unsupported claim except
   a hypothesis, and it then cited existing ids. The metric cannot tell these apart; the
   manual reading in `HYPOTHESES.md` can.
2. **Arm C is not an LLM-planned crew on real data.** With one eligible specialist per step
   on 21 of 22 cases, the "crew with an LLM planner" collapses to the deterministic crew
   plus synthesis. Its extra inferences (161 vs 97) and hypotheses (59 vs 2) are synthesis
   over identical evidence; its coverage, tool calls and facts are A's to the row. Any
   claim that specialist selection benefits from a model is untestable on this manifest.
3. **Arm B earns its place on 13 of 22 cases by the pre-registered rule, and on 0 by the
   "every case" reading of that rule.** It is also the arm that degraded (2 rows, 413),
   exhausted its step budget before asserting any technique on the richest case, failed a
   label check through a facet design choice, and cost 5.7× arm C's tokens and 270× arm
   A's wall time. Where it did earn its place, it was by hypotheses citing evidence the
   deterministic arm had not cited: that is the one measured capability neither A nor C has.
4. **Nothing in the label-scored synthetic cases improved under a model.** Recall,
   conclusions and techniques are identical across arms except for the B facet failure.

## 7. Limits of this experiment

* One run per model arm; the model arms' variance is unmeasured (prediction (vi) was
  written for a single run).
* 22 cases, 14 of them unlabelled flaws.cloud cases; the decision rule's second condition
  is measurable there, its meaning is not.
* Prediction (v)'s manual reading has not been done; it is UNAVAILABLE, not skipped.
* The 413 threshold was never characterised; the frozen client has no request-size guard,
  and the two degraded rows are the only measurement of it.
* Arm C's planner inertness means the experiment measured LLM *synthesis* on the crew,
  not LLM *planning*; a manifest with multi-specialist cases would be needed to measure
  the latter, and building one after seeing this result would be fitting the case set.

## 8. Nothing was changed

No prompt, model setting, manifest, scoring, tool, budget, rule or correlation setting was
modified after the first arm B row was observed. The parallel branch
`parallel-dev-2026-09-13` was not merged. `.env` is untracked.
