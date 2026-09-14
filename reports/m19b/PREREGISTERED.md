# M19b pre-registration: cross-specialist necessity

**Written 2026-09-14 by the architect at integration HEAD `4452b19`, before any M19b model
run.** Manifest `reports/m19b/MANIFEST.json` (hash `0ced14fb…`, nine cases; H1 sealed and
excluded). Nothing in sections 1-6 changes once a model arm has run; a missed prediction
is recorded beside the prediction.

## 1. The arms and their footing

`A_deterministic`, `B_single_llm` (seven-facet generalist), `C_crew_llm` (specialist crew,
model planner and synthesis), exactly as frozen for M19: same model (`claude-opus-5`),
prompts, request configuration, retry policy, tool surface, budgets (8 steps, 40 tool
calls for B and C, A uncapped), scoring definitions for every M19 metric. Asserted by
`scripts/m19b_env.py check` = EQUAL AND REPRODUCING at the freeze commit.

**One pre-registered difference from M19, applied to both model arms identically:**
`InvestigationConfig.tool_output_budget = 4096` bytes of evidence ids per claim in the
synthesis prompt (the T2 mitigation; `reports/m19b/http413/REPORT.md`). Reason: without
it arm B degrades on any case whose tool results are large (both COMISET cases, 6/6 in
T3), and `flaws_cloud/CASE-256` here carries 108 deterministic facts from 17 tool calls.
The bound changes only how already-verified claim evidence is rendered for synthesis; arm A
never synthesises and is unaffected; B and C receive the same bound. Recorded in the
M19b `ENVIRONMENT.json` as the single divergence.

Two agent-layer defects were fixed before the freeze and verified to leave arm A's claims
unchanged on all 22 M19 cases (`NetworkAgent` `robust_cv` at exactly three connections;
`AnthropicLLM` now records the API error type and message).

## 2. The cases (frozen, `MANIFEST.json`)

| case | provenance | domains | planner choice steps (arm A) | links | verdict |
| --- | --- | --- | ---: | ---: | --- |
| synthetic:INC-001 | synthetic (the M19 case; unchanged by the correlator change) | endpoint, identity, network | 3 | 15 | malicious |
| dedale_injected:M1..M4 | real benign DEDALE hours + injected labelled attack rows | endpoint, identity | 2 | 2 each | malicious |
| dedale_injected:L1, L2 | same background, injected **benign look-alike** (lockout + PsExec support; stale backup password + service script) | endpoint, identity | 2 | 2, 1 | benign |
| flaws_cloud CASE-182 (`backup`), CASE-256 (`Level6`) | real, unlabelled CloudTrail | identity, control_plane | 2 | UNAVAILABLE | unknown |

Every case offers the planner at least two multi-candidate steps (MEASURED, arm A). Six of
nine are the same shape (endpoint × identity via `auth_then_exec`); this benchmark measures
one kind of cross-domain investigation and says so. `HELDOUT_H1` is not run until the
final evaluation and its labels stay sealed.

## 3. Metrics, with the constants fixed here

All from `ath.evaluation.ablation.scoring` (T6) plus the rules below, computed by code
committed before the runs.

* **Evidence correctness**, **unsupported claims**, **rejected claims**, **evidence
  coverage**, **technique agreement (both directions)**, **completeness counts**: as in
  M19.
* **CDER-specific.** A pre-registered link is recovered when one accepted FACT or
  INFERENCE cites both of its ids **and is specific**: the claim cites **fewer than 50% of
  the case's evidence ids and at most 25 ids**. Rationale (MEASURED on arm A, T5c): the
  only claim recovering any link today is the ATT&CK mapper's blanket inference citing
  100% of the case's evidence, which asserts nothing cross-domain. Blanket recoveries are
  reported separately as **CDER-blanket** and never credited.
* **Stage recovery.** A rubric stage is recovered when a specific accepted claim (same
  rule) cites at least one evidence id labelled to that stage. Completeness for H1 =
  (CDER-specific recovered + stages recovered) / (links defined + stages defined), per
  case, labelled cases only.
* **Conclusion substrings** (M19's `must_conclude` / `never_as_fact` mechanism), written
  per case by T7 from the rubric text before any run: for malicious cases the stage
  notes' distinguishing facts; for L1/L2 the benign explanation ("lock" / "unlock" or
  "scheduled" / "backup" / "stale"), and `never_as_fact` = the malicious reading. A
  benign case is **discriminated** by an arm when its claims contain the benign
  explanation and no FACT asserts the malicious reading.
* **UCC** (T6 definition): a verified cross-domain link or specific cross-domain claim
  that one arm produced and no other arm produced on that case (identity by cited-id set
  and domain pair, never prose), mapped to a rubric item. Blanket claims excluded by the
  same specificity rule. Reported for A, B and C symmetrically.
* **New evidence**: hypotheses citing evidence arm A's claims did not cite (M19's rule).
* **Planner activation**, **specialists selected and handoffs**, **duplicate tool calls**,
  **context size** (largest and total request bytes and input tokens), **cost** (tokens,
  wall seconds, model calls), **reliability** (HTTP errors by type and message, truncations,
  parse failures, degraded rows, budget hits).

## 4. The hypotheses and the architect's predictions

| # | Hypothesis | Prediction | Grading rule |
| - | ---------- | ---------- | ------------ |
| H1 | C outperforms B on investigation completeness where ≥2 domains carry non-redundant evidence | **Predicted FALSE.** C's synthesis sees the same tool results B's facets see; M19 and T3 showed C's claims cite only what the deterministic specialists already cited. Expect C ≈ A + synthesis, B ≥ C on specific CDER because B pulls ids outside the case | C's per-case completeness (§3) > B's on ≥ 5 of 7 labelled cases |
| H2 | C combines cross-domain evidence more often than B | **Predicted FALSE.** Expect specific cross-domain claim counts within ±1 per case, or B higher | count of specific cross-domain claims, C > B on ≥ 5 of 9 cases |
| H3 | C needs fewer tokens than B | **Predicted TRUE** (M19: 9.8k vs 55.9k per case) | median tokens per case C < 0.5 × B |
| H4 | C incurs coordination overhead in latency and duplicated tool calls | **Predicted TRUE for duplication** (crew duplicated 17/123 calls in M19, B 0/169), **FALSE for latency** (C was faster in M19) | duplicate calls per case C > B; wall seconds per case C > B |
| H5 | B remains better at opportunistically discovering evidence outside predefined scopes | **Predicted TRUE** (T1: B new-evidence hypotheses 26/41, C 0/59; T3: 12/12 reproducible) | cases with ≥1 new-evidence hypothesis: B > C |
| H6 | All factual claims stay evidence-grounded in every arm | **Predicted TRUE** (0 rejected in 66 + 60 rows so far) | evidence correctness 1.0 and 0 rejected claims on every row; any fabricated citation disqualifies the arm |
| H7 | If C cannot outperform B even here, the crew is not justified as the default | conditional; see §5 | see §5 |

Secondary predictions: arm A's CDER-specific is 0 on every labelled case (only blanket
recoveries today). L1/L2 discrimination: predicted **no arm** discriminates both (the
benign explanation needs the lockout code, which the adapter records as `0x0`, and the
real interactive-session history, which the tools expose only through
`user_auth_history`); if any arm does, record which and how. flaws_cloud/CASE-256 is the
context-size stress case: with the bound on, predicted no 413 in either model arm.

## 5. The decision rule, fixed now

Read only after H1-H6 are graded.

* **KEEP CREW AS DEFAULT** only if H1 holds **and** C's UCC ≥ B's UCC on ≥ 5 of 9 cases
  **and** H6 holds.
* **HYBRID (deterministic → single LLM → crew on multi-domain trigger)** only if C's UCC
  > B's on ≥ 3 cases *and* those cases share a detectable trigger (≥2 domain specialists
  eligible) that B fails on. Since every case here carries that trigger, HYBRID requires C
  to beat B on this set; it cannot be reached by C matching B.
* **SINGLE LLM DEFAULT** if H5 holds, B's new-evidence and UCC advantage persists, H6
  holds, and B's reliability with the bound on is ≥ C's (degraded rows).
* **DETERMINISTIC DEFAULT + OPTIONAL LLM** if neither model arm adds specific CDER, UCC
  or a discriminated look-alike over arm A on a majority of cases, whatever the hypothesis
  counts.
* **SIMPLIFY / REMOVE CREW** is added to any outcome in which C's specialists contribute no
  claim, link or discrimination that A alone did not, on every case; the duplicate-call
  and planner-inertness measurements decide whether the mapper and the eligibility gating
  are simplified regardless.

## 6. Runs

Primary: `freeze` → `run --arm A` (twice, identical) → `run --arm B --check-planner` →
`run --arm C --check-planner` → `score`, one run per model arm. Secondary, only if credit
allows and reported separately: one repeat of B and C. No row is rerun; retries follow the
frozen client policy; every failure is preserved. Runs are blocked until the account has
credit (400 "credit balance is too low", MEASURED 2026-09-14).
