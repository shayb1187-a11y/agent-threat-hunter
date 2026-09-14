# M19b: Cross-Specialist Necessity and Agentic Robustness

Status: **in progress.** Phases 1-7 are complete and verified; Phase 8 (the frozen A → B
→ C runs on the nine-case benchmark) is **blocked on API credit** (400 "credit balance is
too low", MEASURED 2026-09-14, twice). Sections 6-7 are therefore UNAVAILABLE and the
architectural decision is not yet made. The M19 primary result
(`reports/m19/ablation/`) is untouched throughout.

Plan: `docs/m19b-plan.md`. Pre-registration: `reports/m19b/PREREGISTERED.md` (committed
`fafd7f7` before any M19b model run). Every number below is MEASURED from a committed
artifact unless labelled otherwise.

## 1. Are B's M19 advantages reproducible? (Phase 3, T3)

Yes, on the cases where M19 found them. Ten pre-defined M19 cases, three repeats each of
arms B and C under a freeze byte-equal to M19's (`reports/m19b/robustness/`):

* Arm B met the M19 decision rule in **12 of 12** repeats on the four cases it won in M19,
  and failed it in **18 of 18** repeats on the six it lost; per-case verdicts agree with
  M19 on 10 of 10 cases in all 30 repeats.
* Arm B's HTTP 413 on both COMISET cases reproduced **6 of 6** times.
* Tokens per full B repeat: 506,185 / 506,614 / 505,800 (stable within 814); B cost about
  45× C on the two flaws.cloud cases where it met the rule.
* Arm C: 13 of 30 repeats ran with a live model and matched arm A on coverage, accepted
  facts and (except INC-001) tool calls; its planner was offered a choice on INC-001 only,
  3 of 3 steps, in all three repeats; it produced a new-evidence hypothesis in **0 of 30**
  repeats. The other 17 rows degraded on HTTP 400 in strict time order: the account's
  credit ran out mid-run (confirmed by an independent probe). Arm C's variance is
  **INCONCLUSIVE** at this repeat count for that external reason.

## 2. Are B's extra hypotheses genuinely useful? (Phase 1, T1)

**UNAVAILABLE pending the human review.** The blinded package is at
`reports/m19b/review/` (102 entries: 41 B, 59 C, 2 A; arm, model, facet and cost
stripped; sealed key; scorer). What is already MEASURED without judging usefulness:

* B hypotheses citing evidence arm A's claims never cited: **26 of 41**; C: **0 of 59**.
  Arms A and C have identical tool-call profiles because C runs the same specialists; B
  called `user_auth_history` and `host_network_activity` far more often.
* 2 of C's 59 hypotheses are arm A's own deterministic hypotheses, carried unchanged.

## 3. What caused the 413 failures? (Phase 2, T2)

**Pathological tool output, not context accumulation and not a token limit.** Arm B's
synthesis request on `comiset/CASE-001` was **36,827,172 bytes**, 99.24% of it one claim's
`evidence_ids`: the verbatim return of `host_network_activity`, 589,476 event ids.
Conversation history contributed 0 bytes; planner requests shrank over the case
(1,663 → 1,161 bytes). The endpoint's limits, bisected with `max_tokens=1`: **32 MiB body
(413 at 33,554,433 bytes)**, inside it 32,000,000 text bytes and 1,000,000 tokens (both
400). Arm C did not hit it because its network specialist's gate never passed on a
process-led COMISET case, not because C bounds anything.

Mitigation, flag-gated and off by default (`InvestigationConfig.tool_output_budget`):
with 4,096 bytes of ids per claim the two requests fall to 11,512 and 10,739 bytes, both
rows un-degrade, 12 synthesis claims are accepted with 0 rejected and evidence
correctness 1.0. The pre-registration turns the flag on for both model arms in M19b as
the single divergence from M19.

## 4. Why M19 could not test the crew, and what the benchmark does about it (Phases 4-6)

* **Structural, not data scarcity.** Of 294 cases across 23 corpora, exactly one
  (`synthetic:INC-001`) had two domain specialists eligible at the same step (T4). The
  rule catalogue produces single-domain findings, and the correlator's only cross-domain
  link was a hard-coded allowlist `{ATH-005, ATH-006} × {ATH-007}`; identity × control
  plane could never form on flaws.cloud despite 79,424 auth rows and 1,857,154 control
  rows by overlapping principals.
* **Correlator change (T5a, applied to every arm, upstream of investigation).** A
  declared cross-channel link (`shared_principal` within 15 minutes, plus the old
  `auth_then_exec` relation without its allowlist) replaced the allowlist. Benchmark 5/5
  before and after; INC-001..005 chain quality unchanged; two real flaws.cloud identity ×
  control-plane cases now form (`backup`, 2 findings; `Level6`, 7 findings, a 3.5× merge
  flagged as a contamination candidate on unlabelled data).
* **Injected cases (T5b).** Six labelled endpoint × identity cases (M1-M4 malicious; L1,
  L2 benign look-alikes that fire the identical rule fingerprint as M1) on real DEDALE
  benign hours whose background yields 0 findings at HEAD, plus H1 sealed. Every case
  forms one case via `auth_then_exec`; every label ref resolves; generation is seeded and
  byte-reproducible.
* **The benchmark (T5c).** Nine cases; every one offers arm A's planner 2-3
  multi-candidate steps (M19: 1 case of 22). Provenance is stated per case; six of nine
  share one shape, and the benchmark measures one kind of cross-domain investigation.
* **A metric that would have lied.** Arm A "recovers" every pre-registered link only
  through the ATT&CK mapper's blanket inference citing 100% of case evidence. The
  pre-registration adds a specificity rule (a recovering claim cites < 50% of the case's
  ids and ≤ 25 ids); blanket recoveries are reported and never credited.
* **Two crew facts already measured on M19 rows (T6):** the crew (A and C) duplicates 17
  of 123 tool calls per manifest run (`lookup_technique` once per mapping rather than per
  id), B 0 of 169; on INC-001 the duplicates consumed the cap and displaced one technique
  lookup. Two agent-layer defects were fixed before the freeze with arm A's claims
  unchanged on all 22 M19 cases.

## 5. What it will cost (Phase 9)

Known from M19 and T3: B ≈ 56k tokens and 47 s per case, C ≈ 10k and 28 s, A 0 and 0.2 s.
M19b figures: UNAVAILABLE until Phase 8.

## 6. Does C provide unique value on genuinely cross-domain cases? (Phase 8)

**UNAVAILABLE.** Blocked on API credit. The harness (`scripts/m19b_ablation.py`), the
freeze and arm A's baseline are prepared; the pre-registered predictions are that H1 and
H2 are false, H3 true, H4 true for duplication and false for latency, H5 true, H6 true.

## 7. Architectural decision (Phase 12)

**Not yet made.** The decision rule in `PREREGISTERED.md` §5 is mechanical and will be
applied to the Phase 8 numbers as they come out. What the evidence so far supports, stated
as HYPOTHESIS and not as the decision: arm C has not yet produced any claim, link or
discrimination that arm A alone did not; its measurable additions on M19 were synthesis
over identical evidence; arm B's unique capability is reproducible and expensive.
