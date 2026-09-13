# M19-1 pre-registration: the agentic ablation

**Written 2026-09-13, at HEAD `ffc31d5` (branch `m14-real-data-validation`).**
**Manifest hash: `1764be3cea5a5afd532038a40c934fc1d79baf88d91016a29ab3bfba6911aa15`** (`reports/m19/ablation/MANIFEST.json`).

This file is written *before* any arm other than the deterministic one runs, and before
any key exists in this environment. Nothing in it moves once an arm has run. If a
prediction misses, the miss is recorded next to the prediction; the metric behind it
does not change inside this milestone.

---

## 1. The arms

Detection, correlation, triage, the tool surface, the claim verifier and the case set are
identical in all three. The only thing that varies is what plans the investigation and
what synthesises on top of the verified claims.

| Arm | Planner | Synthesis | Crew | Needs a key |
|---|---|---|---|---|
| `A_deterministic` | deterministic priority order | off | the assembled specialist crew | no |
| `B_single_llm` | model | model | one generalist agent with every tool | yes |
| `C_crew_llm` | model | model | the assembled specialist crew | yes |

**Arm B is declared, not implemented.** It requires a generalist `Specialist` subclass,
which this milestone excludes; the design, and the two budget questions that must be
settled before it is written, are in `ath.evaluation.ablation.arms.__doc__`. Running it
raises `NotImplementedError` carrying that note, so the gap is visible in the experiment
rather than absent from it. **B and C refuse to run without a configured model**, and a
run whose model failed mid-way is labelled `*_DEGRADED` and aggregated separately: a
deterministic fallback reported under an LLM arm's name is a false row, not a weak one.

## 2. The case set

Frozen in `MANIFEST.json` with, per case: corpus, case id, leading rule, member finding
ids, every evidence event id, and the content hash of the canonical tables the case is
investigated against. `run_arm` refuses to investigate when the re-loaded corpus hashes
differently or when the pinned case is made of different findings.

* **`attack_data_aws`** -- every case (2, from 33 findings). Each carries the capture's
  ATT&CK technique as a label, because that label is in the capture file name.
* **`comiset`** -- every case (2, from 5 findings), read from the M18b canonical freeze.
* **`synthetic:INC-00n`** -- the case `run_incident` investigates for each incident of
  the standard suite, built the way it builds it. Each incident is its own corpus
  because each carries its own telemetry and therefore its own hash.
* **`flaws_cloud`** -- a seeded stratified sample of the corpus's 281 cases: up to 5 per
  *leading rule* (the rule of the case's highest-severity, earliest finding), drawn with
  one `random.Random(19)` consumed in ascending rule order over each stratum's case ids
  sorted ascending; then up to 5 per rule that fires on the corpus but leads no case;
  plus every case containing a finding from a rule that predates M18-8. Seed, rule and
  the full stratum census are recorded in the manifest.

  The pre-registration expected five strata (ATH-005, AWS-002..005). There are four:
  **AWS-005 leads no case and appears in no case at all.** It fires 17 times, it is a
  MEDIUM rule, and `singleton_min_severity` is HIGH, so an AWS-005 finding that links to
  nothing never becomes a case -- and none of the seventeen linked to anything. The
  second stratum kind above exists for the "fires but never leads" shape and is empty
  here for the same reason. The expectation is recorded as missed rather than edited.

## 3. The metrics

All computed from the claim verifier and the telemetry. **Nothing is scored by another
model**, and nothing is scored by reading prose for quality. The scoring module defines
no numeric constant, so no metric carries its own cutoff.

* **`evidence_correctness`** -- cited event ids that exist / cited event ids, over
  accepted *and* rejected claims. Every rejected claim is counted and its reason listed.
* **`unsupported_claims`** -- claims carrying no evidence at all. `Claim.__post_init__`
  refuses to construct a FACT or an INFERENCE without evidence, so in practice this
  counts evidence-free HYPOTHESES; a FACT with no evidence is checked for anyway and
  *raises* rather than scoring badly.
* **`evidence_coverage`** -- the case's finding evidence ids touched by at least one tool
  call / all of them.
* **`technique_agreement`** -- Jaccard between the techniques the investigation asserted
  (read literally out of its own claim text) and the deterministic ATT&CK mapper's
  techniques for the case, reported with both directions of disagreement separately.
  Label-based where labels exist: the attack_data_aws capture technique, and
  `run_incident`'s own event recall and trust fields for the synthetic cases.
* **`completeness`** -- specialists run / eligible, steps, tool calls, distinct tools,
  facts / inferences / hypotheses, wall seconds, tokens (`null` for A).
* **`identity_hygiene`** -- facts carrying "inferred from pid", and inferences naming an
  ambiguous pid (M18b-2), so an LLM arm's handling of ambiguity can be compared.

---

## 4. The architect's predictions, to be graded when a key exists

> **(i) `evidence_correctness`.** Arm A is 1.0 by construction -- every FACT it publishes
> is authored by a tool from a row it just read. B and C must remain 1.0 or the arm is
> disqualified. Every rejected claim is counted and listed; a model arm that fabricates a
> citation has not scored poorly, it has failed.
>
> **(ii) `unsupported_claims`.** A = 0. B and C > 0 is expected -- this is the primary
> cost metric. A model asked to synthesise will produce statements that rest on nothing,
> and the count of them is what the crew's constraints are buying against.
>
> **(iii) `evidence_coverage`.** C >= A: the crew runs the same deterministic tools plus
> planning, so it cannot see less. If C < A, planning skipped a specialist, and that is a
> finding about LLM planning rather than a measurement artefact.
>
> **(iv) `technique_agreement`.** C's asserted set will differ from the mapper's. Report
> both directions -- asserted-but-unmapped is the model naming techniques nothing
> supports; mapped-but-unasserted is the investigation failing to mention what the
> deterministic layer already established. They are different failures and must not be
> averaged into one number.
>
> **(v) Hypotheses.** A = 0 (M18-9 measured 0 hypotheses on 10 flaws.cloud cases). B and
> C will produce some. Record how many are actionable-looking versus merely restating the
> findings -- by manual reading later, not by a model.
>
> **(vi) Cost.** Tokens and wall time per case, for B and C. Reported, never credited: a
> longer answer is not a better one.
>
> **(vii) The decision rule.** An LLM arm "earns its place" only if `unsupported_claims`
> per case stays under a threshold to be set from arm A's inference count, **and** it
> produces at least one hypothesis per case that names evidence the deterministic arm did
> not cite. Both conditions, not either.

---

## 5. Grading arm A now (the only arm that can run without a key)

Arm A's results are in `arm_A.json` and `scores_A.json`, run twice over the whole
manifest with identical output. Two of the predictions above are about arm A and can
therefore be graded immediately; they are graded in `RESULTS.md`, next to the prediction,
and the predictions themselves are not edited.

---

## Addendum, 2026-09-13 (M19-2): the architect's budget ruling

Nothing above is edited. This addendum records the ruling that settled the two budget
questions `arms.py` left open in M19-1, and under which arm B was then built. It is
quoted verbatim:

> both LLM arms get the same step budget as arm A's orchestrator (max_steps = 8); both
> get a per-case tool-call cap of 40, enforced by the ToolBox (a call beyond the cap
> returns a structured refusal recorded as a tool call with `refused=True` and never
> raises); the caps are the same for every case and recorded per case in the results; an
> arm that hits a cap is not disqualified, but the hit is counted.

Consequences, none of which change a metric defined in §3:

* **Arm B is now implemented** as `ath.agent.generalist.GeneralistAgent`, a crew of one.
  §1's "Arm B is declared, not implemented" stands as written for the record; it is no
  longer true as of this addendum.
* **Arm A keeps no tool cap** (`tool_call_cap: null`). The cap was invented for the
  generalist, and capping the baseline to match would change the thing every other arm is
  read against. Arm A's own budget -- `max_steps = 8` -- is unchanged and is now recorded
  on its rows.
* **Every row carries a `budgets` block**: `max_steps`, `tool_call_cap`,
  `tool_calls_served`, `tool_calls_refused`, `tool_budget_hit`, `step_budget_hit`. A
  tool-call count cannot be read without the cap beside it, because a small number means
  either "cheap" or "cut off" and the row must say which.
* **The cap of 40 already binds on one case of the 22.** `synthetic:INC-001` takes 43
  tool calls in arm A; a crew arm run under the cap serves 40 and refuses 3, ending with
  `evidence_coverage` 0.968 rather than 1.000. That is the cap doing its job, recorded
  rather than hidden, and it is a prediction-relevant fact for §4 (iii): **arm C can now
  score below arm A on coverage for a reason that is a budget rather than a planning
  failure**, and the `budgets` block is what distinguishes the two.

---

## Addendum, 2026-09-13 (M19-3): arm B's planner must have a choice to make

Nothing above is edited. This addendum supersedes one sentence of the M19-2 addendum and
records the design that replaces it.

### What was wrong

The M19-2 addendum recorded arm B as implemented "as `ath.agent.generalist.GeneralistAgent`,
a crew of one". That is accurate about the code and wrong about the experiment. The
orchestrator consults the model **only when more than one specialist is eligible**; with a
single candidate `plan()` returns `"only eligible specialist"` and never calls it. So arm
B's planner was inert: the M19-2 scripted run recorded **0** planner-chosen steps for B
against 3 for C. What arm B measured was model *synthesis* laid over a fixed walk, and §1
of this document describes it as "one strong general LLM investigator... the model
deciding what to look at next".

**The M19-2 statement that arm B is a crew of one is superseded as of this addendum.** The
budget ruling it recorded is not: both budgets are unchanged.

### The facet design

Arm B is still **one** generalist. Its tool surface is now presented to the planner as
seven `GeneralistFacet` instances -- one per walk-item kind, in the fixed order
`case, finding, process, timeline, account, host, technique` -- which

* **share one walk.** The plan is built once per case; an entity is marked walked the
  moment a facet takes it, so no entity is walked twice and none is dropped between
  facets.
* **share one `ToolBox`, and therefore one budget.** The 40-call cap and the 8-step
  budget are per case, not per facet. Splitting the surface changed what arm B may
  *choose*; it did not change what arm B may *spend*.
* **are eligible per kind.** A facet declines with `"every <kind> entity has been walked"`
  once its own kind is exhausted, so on any case naming more than one kind of entity the
  planner has a real menu.
* **count as one agent.** `specialists_run` counts the agent *family* (`agent_family`
  splits `generalist:process` at the colon), so arm B reports one specialist run out of
  one eligible and its completeness stays at most 1.0. `eligible_never_ran` keeps the
  facet names: which part of the tool surface went unvisited is information. Arms A and C
  carry no facet suffix and no number in either arm moves.
* **fall back to the fixed order.** With no model, or when the model's answer is
  rejected, the orchestrator takes the first eligible candidate in crew order -- which is
  the order above. A keyless arm B is therefore still deterministic and walks exactly the
  queue M19-2 walked.

**The invariant:** the tool surface, the budgets, the claim rules and the evidence
discipline are identical to arm C. The difference between B and C is what the planner
chooses among -- tool-surface facets versus domain specialists -- and nothing else. The
orchestrator is unchanged; no metric defined in §3 is redefined.

### Consequences for the predictions in §4

* **(iii) Coverage.** A step now covers one facet rather than a slice across the whole
  surface, so arm B spends more steps per case for the same work and can reach the
  8-step budget where it previously did not. That is the cost of giving the planner a
  choice, it is recorded in the `budgets` block per case, and it is a property of the
  arm rather than of any model.
* **(vii) The decision rule** is unchanged.

### The artifact size guard

M19-2 wrote, committed and then replaced a **372 MB** `scripted/arm_B.json`; the blob
remains in this repository's history. `scripts/m19_ablation.py` now refuses to write any
single artifact above **50 MB**, prints where the bytes were, and exits non-zero, and
`tests/test_artifact_size_guard.py` fails if any file under `reports/` reaches 60 MB
outside the two named COMISET parquet freezes. Neither is a change to any arm or any
metric.

## Addendum, 2026-09-13 (M19 Phase 1): the frozen experiment environment

**Nothing in the predictions changes.** §4's seven predictions, §3's metrics and §5's
decision rule stand exactly as written. This addendum records the architect's rulings on
everything *outside* the reasoning architecture, so that the sentence "the arms differed
in one thing" can be checked rather than asserted.

### The architect's rulings, verbatim

> the ablation pins its own model id, claude-opus-5, on ArmConfig for arms B and C (the
> brief calls arm B "one strong general LLM investigator"; the project's DEFAULT_MODEL in
> src/ath/config.py is left unchanged and out of scope). Requests send thinking
> {"type": "adaptive"} explicitly and leave output_config.effort at the provider default
> (high), recorded as such. max_tokens becomes 8192 for both planner and synthesis calls
> -- the outputs are short JSON and the model stops at end_turn; the cap exists only to
> bound cost. No sampling parameters are sent. Timeout 60 s per attempt and the existing
> retry policy stay. Raw urllib stays (project choice; do not introduce the SDK).

### What the freeze records, and where

`python scripts/m19_ablation.py freeze` writes `ENVIRONMENT.md` and `ENVIRONMENT.json`
beside this file: the commit, branch and dirty flag; the model id per arm; the request
configuration (thinking, effort, `max_tokens` per call kind, the absence of sampling
parameters, the `anthropic-version` header, the endpoint); the timeout and retry policy;
the sha256 of both system prompts and of both user-message templates; the tool surface
for arms B and C, asserted identical; the budgets; the manifest hash and the manifest's
head; the sha256 of `scoring.py` and `arms.py`; the Python and library versions; and the
name of the credential variable with **presence only** -- the key's value is recorded
nowhere, not truncated and not hashed.

Every value is read from the code that will run rather than transcribed here. A frozen
value typed in by hand would record what somebody believed.

### The freeze is a gate

A real run of a model arm refuses to start unless the commit, the prompt hashes, the
scoring hashes, the manifest hash and the per-arm model ids still match `ENVIRONMENT.json`,
and unless the working tree is clean outside `reports/` and `data/`. Committing the freeze
moves HEAD, so a differing commit is accepted only when every path changed since lives
under `reports/`; one changed line of code, test or script refuses the run. A `--scripted`
run is exempt: it contains no model output, is written under `scripted/` and is labelled
`*_SCRIPTED`, so there is no comparison for it to drift out of.

### The two defects Phase 0.5 corrected first

Both would have made a model arm's rows false rather than weak, and neither was visible
in any output.

1. **A reply cut off at `max_tokens` was read as a reply.** Thinking tokens count against
   the cap; the planner asked for 256 of them. A response that reaches the cap returns
   `stop_reason: "max_tokens"` and may contain no text block at all, which parses to
   `None` -- indistinguishable, to the orchestrator, from a model answering in prose, and
   the answer to prose is to plan deterministically and continue. `state.llm_errors` stayed
   empty, so `llm_degraded` stayed False, so the row was labelled as a model arm. Both LLM
   arms could have collapsed to arm A on every case while reporting themselves as model
   arms. The client now reads `stop_reason` and the presence of a text block on every call
   and returns an error naming the cause; both budgets are 8192.

2. **The synthetic rows' label scores came from a second, separate investigation.**
   `cmd_run` called `run_incident` again -- its own uncapped `ToolBox`, the
   environment-assembled crew -- and wrote that verdict onto the row. For arm B that was
   arm C's architecture wearing arm B's label. The label scores are now computed by
   `ath.evaluation.incidents.score_labels` from the row's own state, one definition shared
   with the benchmark. Arm A's published figures are unchanged field for field; scripted
   arm B's `synthetic:INC-001` row moved from `passed: true` to `passed: false`
   (`conclusions_missed: ["guessed"]`), because arm B's own investigation exhausted its
   8-step budget without reaching that conclusion and the crew's separate run had been
   supplying it.

### The detector

`run --arm B|C --check-planner` prints, per row, how many steps offered the planner more
than one eligible candidate and how many of them the model decided, together with the
fallbacks by reason, the count of complete-but-unparseable replies, and the degraded flag.
It exits non-zero if any model-arm row had a multi-candidate step and the model chose none
of them -- a row that planned deterministically under a model arm's label. A case with no
multi-candidate step is neither a pass nor a failure: the planner was never asked, and the
row says nothing either way.
