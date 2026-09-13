# M19b: Cross-Specialist Necessity and Agentic Robustness

Architect's design, written 2026-09-14 before any M19b model run. The M19 primary result
(`reports/m19/ablation/`, commits `0dcfdf4`..`523cf92`) is immutable: nothing in this
milestone reruns, re-scores, reinterprets or averages into it. Everything M19b produces
lives under `reports/m19b/` and `docs/m19b-*.md`.

## The question

M19 measured "does the current crew improve these 22 investigations" and the answer was
no: arm C's planner was consulted on 1 case of 22 because on 21 cases exactly one domain
specialist was eligible at every step, with the ATT&CK mapper eligible only afterwards
(`orchestrator.plan`: "only eligible specialist"). M19b asks the question M19 could not:

> Is the specialist crew measurably better than a bounded single-LLM investigator on
> realistic investigations where at least two security domains genuinely matter?

Admissible outcomes, none preferred: KEEP CREW / SIMPLIFY CREW / HYBRID / SINGLE LLM
DEFAULT / DETERMINISTIC DEFAULT. A result that deletes complexity is a success.

## Hard rules

1. M19 artifacts are never modified. New runs write under `reports/m19b/`.
2. Model, prompts, tool surface, budgets, retry policy and scoring for every M19b model
   run are the M19 freeze's values; each M19b run directory carries its own
   `ENVIRONMENT.json` whose prompt, scoring, budget and model hashes are asserted equal to
   `reports/m19/ablation/ENVIRONMENT.json` (commit may differ; the assertion is the point).
   The one permitted difference is the Phase 2 mitigation, and only in a run whose
   directory says so, after the unmitigated baseline is recorded.
3. Cases are constructed or selected before any B/C run and never adjusted after one.
   Where a case is new, its generation logic is committed and hashed first, and at least
   one case is held untouched until final evaluation.
4. Nothing is rerun to make it pass. Retries are the frozen API policy only.
5. No task grades model output with a model as the primary assessment.
6. Claims carry a label: MEASURED / VERIFIED / PROJECTED / HYPOTHESIS / INCONCLUSIVE /
   UNAVAILABLE, and a worker may not promote one to another.

## Phases and tasks

| Phase | Task | Output | Depends on |
| --- | --- | --- | --- |
| 1 | T1 blinded hypothesis-review package | `reports/m19b/review/` worksheet with 100 hypotheses, arm/model/cost stripped, shuffled with a sealed key; answer template; a scorer that reads the human's answers back | nothing |
| 2 | T2 413 characterisation | `reports/m19b/http413/` measurement of request bytes, input tokens, tool-output vs history contribution, largest tool result, per call; synthetic reproduction; a designed (not merged) mitigation with before/after on the reproduction | nothing |
| 3 | T3 robustness harness and runs | `reports/m19b/robustness/` selected-case repeat runs, 3-5 per arm×case, own freeze asserting equality with M19's, reported beside and never averaged into M19 | nothing (uses the unmitigated M19 configuration) |
| 4-6 | T4 cross-domain corpus audit | `reports/m19b/necessity/AUDIT.md`: every existing corpus and case, domains with materially relevant evidence, redundancy, whether synthesis could change verdict/priority/next action; candidate list ranked by provenance | nothing |
| 5-6 | T5 benchmark construction | frozen manifest of qualifying cases (existing first; new cases only where necessary, generation hashed, one held out) with a per-case necessity audit | T4 |
| 7, 9, 10 | T6 necessity metrics and fair-comparison instrumentation | scoring additions: Cross-Domain Evidence Recovery, Unique Cross-Domain Contribution, planner activation, specialists selected, duplicate tool calls, cross-specialist evidence combinations, context size; equal-footing assertions for the three arms | T5 |
| 8 | T7 pre-registration | `reports/m19b/PREREGISTERED.md` with H1-H7, thresholds, the selection rule, freeze | T5, T6 |
| 11 | T8 frozen A → B → C → score | `reports/m19b/arm_*.json`, `scores_*.json`, `GRADING.json` | T7 |
| 12 | T9 architectural report and decision | `docs/m19b-report.md` with the recommendation | T1, T3, T8 |

T1, T2, T3 and T4 are independent and run in parallel, each in its own git worktree on
its own branch (`m19b/<task>`), merged into `m14-real-data-validation` only after
independent verification. No two tasks edit the same file.

## Cross-specialist necessity, defined before any case is chosen

A case qualifies for the M19b benchmark only if all three hold, and the audit says why:

1. **Two or more domain specialists** (endpoint, identity, network, control_plane; the
   ATT&CK mapper does not count) have **materially relevant evidence**: rows in their
   channel that belong to the labelled attack chain or, for unlabelled real data, to the
   same actor/host/time story the case's findings tell.
2. **The evidence is not redundant**: removing either domain's rows would remove a stage
   of the story, not a second copy of the same stage.
3. **Cross-domain synthesis could change the verdict, the priority, or the analyst's next
   action**: stated concretely per case, e.g. "the logon burst is credential guessing only
   if the process evidence shows no interactive session that could have typed it".

"Two specialists eligible" is not sufficient. Every M19 case except INC-001 had two
eligible (a domain specialist and the mapper) and no choice.

## The necessity metrics, defined before any run

* **Cross-Domain Evidence Recovery (CDER)**: per case, the set of pre-registered
  cross-domain *links* (pairs of evidence ids from two different domains that the ground
  truth says belong to one stage transition). A link is recovered when one accepted claim
  (FACT or INFERENCE, verified) cites evidence on both sides. CDER = recovered / defined.
  Arm A is scored too: a deterministic crew that already recovers every link leaves the
  model arms nothing to add.
* **Unique Cross-Domain Contribution (UCC)**: a recovered link, or an accepted claim
  citing evidence from two domains, that C produced, that is verified, that neither A
  nor B produced on the same case, and that maps to a pre-registered "matters" item
  (a stage, the verdict, or a next action named in the case's rubric). Counted per
  case; also defined symmetrically for B (UCC-B), because the question is comparative.
* **Planner activation**: steps with more than one eligible candidate / steps; and
  domain-specialist selections, in order.
* **Duplicate tool calls**: identical (tool, arguments) pairs within one case.
* **Context size**: bytes and tokens of the largest request per case, and the sum.

These are computed from the artifacts by code committed before the runs. A metric that
needs a constant states it in the pre-registration.

## Cost and reliability, reported never credited

Tokens (input / output / thinking where reported), latency, tool calls, model calls, HTTP
failures, truncations, parse failures, degraded rows, budget exhaustion. A longer answer is
not a better one; a cheaper arm that misses a stage is not a better one either.

## What M19b will not do

It will not touch M20's sealed holdout, will not add RAG or a vector store, will not
change detection rules, and will not adjust a case after seeing a model's behaviour on
it. If genuinely cross-domain real data does not exist in the corpora, the benchmark says
so and uses the smallest number of clearly-labelled constructed cases, never calling them
real.
