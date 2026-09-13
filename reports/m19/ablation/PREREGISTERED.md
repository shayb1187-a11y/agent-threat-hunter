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
