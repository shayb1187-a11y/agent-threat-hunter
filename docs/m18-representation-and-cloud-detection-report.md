# M18: can ATH represent cloud control-plane telemetry, and detect on it without memorising the corpus?

**Verdict up front: representation is now genuinely good and the detection work was done
honestly, but almost nothing about detection *quality* on cloud telemetry has been
established, and the layers above detection are worse off than before.** CloudTrail
management activity went from 0.09% of an attack corpus represented to 100%, and the
per-field measurement that says so is now trustworthy in both directions -- it stopped
reporting blindness that did not exist as well as blindness that did. Four generic rules
were pre-registered before the held-out corpus was opened, graded whether or not they
were right, and caught 4 of 5 labelled captures. Against that: those rules put 1,437 new
unlabelled findings and 277 new cases on a 3.6-year background trail, triage dispositioned
**zero** of 1,476 as benign, and the investigation layer's first contact with real cloud
cases produced 203 facts and 0 hypotheses on ten of them. The binding constraint moved
from ingestion to triage and to cross-channel identity; it did not disappear.

Three classes of statement appear below and are labelled where it matters:

* **MEASURED** -- a number this milestone produced from a corpus, written to a named
  artifact. Every number in this report is one of these unless marked otherwise.
* **VERIFIED FROM CODE** -- a property asserted by a test or read off the source, not
  counted from data.
* **PROJECTED** -- an inference beyond what was measured. There are three of them and each
  is marked.

Frozen baselines this report compares against and does not modify:
[`reports/m16/attack_data_aws.json`](../reports/m16/attack_data_aws.json),
[`reports/m17/H4_FROZEN.json`](../reports/m17/H4_FROZEN.json),
[`reports/m17/D18_FROZEN.json`](../reports/m17/D18_FROZEN.json).

---

## 1. What changed

| # | Commit | Change | Invariant it establishes |
| - | ------ | ------ | ------------------------ |
| M18-1 | `202712e`, `dba8501` | `Detector.tables` / `optional_fields`; per-field population replaces one nominated column per channel | A rule is usable only if the fields it filters on carry values |
| M17-fix | `0ccf565` | ATH-007's eligible count corrected 21,158 → 15,095 (a rule-to-table map outside the rules) | A table map maintained outside the rules drifts from them silently |
| M18-2A | `04e041e` | `ath.telemetry.admission`: a file is read only if it parses in a shape the source recognises | Nothing enters a canonical table from a file the source has not recognised |
| M18-2B | `1f1e9d8` | Timestamp quarantine: NaT, < 2000-01-01, > load+1d leave the table as an issue; nothing is repaired | Nothing enters a canonical table unless its timestamp could be an event time |
| M18-3 | `a663381`, `1186900` | CloudTrail management records become control rows by parsing the event name into verb + resource family + service; no API allowlist | Management activity is represented by service + verb + resource family |
| M18-4A | `9b51253` | `parse_event_time` fast path with a proven-equivalent fallback (58,647 real strings, 0 mismatches) | Making ingestion faster may not change a single canonical value |
| M18-4B | `f43726e` | `FIELD_APPLICABILITY`: a column is graded over the rows it could carry a value on | A field is measured over the rows it could have carried a value on |
| M18-5A | `27489b8` | `changes_authority` in a leaf vocabulary; `target_actor`/`role_ref` filled only on authority changes | `target_actor` is the identity whose authority the action changed |
| M18-5B | `1df2bd9` | Optional fields report `sparse_optional_fields` and no longer move a rule's verdict | A rule's verdict moves only on fields that can change what it finds |
| M18-6A | `0f02f13` | `is_identity_grant` narrows the applicability denominator; `SourceLoadResult.field_gaps` counts the rest | A field is measured where the source model guarantees its value |
| M18-6B | `532bd76` | `resource_name` derived by one four-tier convention over request parameters, never per API | Every control row names the subject it acted on |
| M18-7A | `f329643` | `decision` becomes three-valued: allowed / denied / failed, split by a closed authorization-token vocabulary | "denied" means the platform refused authorization |
| M18-7B | `eb7d395` | `scripts/m18_cloud_behaviour_stats.py`: per-actor sliding-window distributions on the background trail, choosing nothing | The distribution comes before the threshold |
| M18-8A | `b8953f2` | `PREREGISTERED.md`: 4 rules, 5 thresholds, 16 predictions, committed before the rule code existed | The threshold is fixed before the corpus is opened |
| M18-8B | `d8b3da2` | AWS-003..006, containing no service, API or actor name (asserted against both corpora's vocabulary) | A detection describes behaviour, and names nothing |
| M18-8C | `7565d21` | All 16 predictions graded: 12 MATCH, 3 PARTIAL, 1 MISS, one paragraph per miss | A prediction is graded whether or not it was right |
| M18-8D | `58b513d` | Coverage test asserts the full flip: DETECTABLE on cloud rows, UNOBSERVABLE on Windows rows | A coverage gap is closed only where the telemetry is present |
| M18-9 | `3ed26aa` | `channels_of_row` / `channel_of_control_row` / `findings_respect_declared_channels`; AWS-005/006 scoped to the identity service | Every evidence row a finding cites belongs to a channel the rule declares |

Test suite across the milestone: **1342 passed / 2 skipped** at `58b513d` → **1357 passed
/ 2 skipped** at `3ed26aa` (`python -m pytest -q`, run in this task). Benchmark
**5/5, 0 noise cases** at both (`python main.py benchmark`, run in this task).

## 2. What was deliberately not changed

- **The pre-registered thresholds.** `cloud_discovery_min_services = 10`,
  `cloud_denial_min_count = 25`, `cloud_identity_failed_min_count = 5`, both windows.
  One prediction missed and three were partial; nothing moved. A test parses
  `PREREGISTERED.md` and fails the suite if any `HuntConfig` default differs from what is
  declared there (VERIFIED FROM CODE).
- **`changes_authority` itself.** M18-9 conjoined two rules with an extra clause rather
  than narrowing the shared predicate, because the predicate is correct for the column it
  was written for -- `target_actor`, which both adapters fill.
- **AWS-004's platform scope.** Known exposure, recorded not fixed -- see §10.
- **The M18-8 result narrative.** `PREREGISTERED.md` records the P13 miss, the P2/P8/P9
  partials and the reasoning behind each, and the POST-REGISTRATION CHANGE section is
  appended below the results rather than edited into them.
- **The triage layer.** It dispositioned 0 of 1,476 flaws.cloud findings as benign, before
  and after. That is the M15-4 signal gap and no cloud-specific benign signal was added to
  hide it.
- **Anything under `reports/m16` or `reports/m17`.**

## 3. Per-stage loss ledger -- attack_data_aws

Five captures, one ATT&CK technique each, the only cloud ground truth this project has.

| Stage | Before (M16) | After (M18) | Source |
| ----- | -----------: | ----------: | ------ |
| Raw records in the directory | 2,349 | 2,349 | `reports/m18/cloud_representation/attack_data_aws.json` ¹ |
| Files listed → admitted | not measured | 5 → **5**, 0 rejected | `reports/m18/input_boundary/attack_data_aws.json` |
| Records in admitted files | not measured | 2,349 | ¹ `after.ledger` |
| Recognised (auth / management / neither) | not measured | 2 / **2,347** / 0 | ¹ |
| Canonical rows kept | **2** (logon 2, control 0) | **2,349** (logon 2, control 2,347) | ¹ |
| Quarantined on timestamp | not measured | **0** | `reports/m18/input_boundary/attack_data_aws.json` |
| Normalisation issues | 2,347 (unmapped eventName) | **0** | ¹ |
| Field gaps on kept rows | n/a | 146 (`target_actor` not guaranteed) | ¹ |
| Rules usable / unusable / not eligible | 4 supported, 12 unsupported ² | **3 / 3 / 10** ² | `reports/m18/field_usability/attack_data_aws.json` |
| Behaviour represented | 0 control rows | 2,347 rows, 6 verbs, 109 resource types, `verb`/`resource_type`/`actor`/`decision` at **100%** | ¹ `after.control_table` |
| Detector covers the technique | T1098/T1526/T1580 not covered | **DETECTABLE** on a cloud-control environment (VERIFIED FROM CODE, `58b513d`) | `tests/test_environment.py::test_watchlist_techniques_flip_to_detectable_on_a_cloud_environment` |
| Findings | **0** | **36** (AWS-005 27, AWS-006 4, AWS-004 3, AWS-003 2) | `reports/m18/cloud_detection/attack_data_aws.json` |
| Capture-level recall | 0/5 | **4/5** `caught_any`; **3/5** with the labelled technique | same |
| Cases | 0 | not measured (the per-capture measurement does not correlate) | -- |
| Investigation | 0 | not measured on this corpus | -- |

¹ `reports/m18/cloud_representation/attack_data_aws.json` -- the `before` half of that file
quotes `reports/m16/attack_data_aws.json`, which is frozen and unmodified.
² Over the 16 rules registered at `dba8501`; AWS-003..006 did not exist when this artifact
was written. The four-rule increase is not reflected in the usability counts.

## 4. Per-stage loss ledger -- flaws.cloud

1,939,207 CloudTrail records, 55 identities, 3.6 years, deliberately vulnerable account,
**no labels**. Every finding here is an alert whose cost is known and whose truth is not.

| Stage | Before (M16) | After (M18) | Source |
| ----- | -----------: | ----------: | ------ |
| Raw records | 1,939,207 | 1,939,207 | ³ |
| Files listed → admitted | not measured | 20 → **20**, 0 rejected | `reports/m18/input_boundary/flaws_cloud.json` |
| Recognised (auth / management / neither) | not measured | 79,720 / **1,859,487** / 0 | ³ |
| Canonical rows kept | **79,520** (logon 79,424, control 96) | **1,936,578** (logon 79,424, control **1,857,154**) | ³ |
| Rows dropped, with a reason | 1,859,687 (unmapped eventName) | **2,629** (`no_principal`) | ³ |
| Quarantined on timestamp | not measured | **0** | `reports/m18/input_boundary/flaws_cloud.json` |
| Field gaps on kept rows | n/a | 3,098 (3,030 `target_actor` not guaranteed; 34+34 denied requests carrying no parameters) | ³ |
| Rules usable / unusable / not eligible | 4 supported, 12 unsupported ² | **3 / 3 / 10** ² | `reports/m18/field_usability/flaws_cloud.json` |
| Behaviour represented | 96 control rows | 1,857,154 rows, 51 verbs, 1,158 resource types; `resource_name` 0.08% → **8.09%** | ³, `532bd76` |
| Detector covers | AWS-001/002 only | AWS-001..006 | `reports/m18/cloud_detection/flaws_cloud.json` |
| Findings | **39** (ATH-005 36, AWS-002 3) | **1,476** (ATH-005 36, AWS-002 3, AWS-004 1,142, AWS-003 278, AWS-005 17, AWS-006 0) | ⁴ |
| Severity mix | 4 CRITICAL / 35 MEDIUM | 4 CRITICAL / **351 HIGH** / 1,121 MEDIUM | ⁴ |
| Triage dispositions | 4 likely_malicious / 35 needs_review / **0 likely_benign** | 355 / 1,121 / **0 likely_benign** | ⁴ |
| Cases | 4 (4 singletons) | **281** (97 singletons) | ⁴ |
| Investigation (first 10 cases) | never run | 20 steps, 172 tool calls, 203 FACT, 34 INFERENCE, 0 HYPOTHESIS, 0 rejected | ⁴ |
| Alert rate | 0.029/day | AWS-003 0.21/day, AWS-004 0.86/day, AWS-005 0.013/day over 1,333 days | ⁴ |

³ `reports/m18/cloud_representation/flaws_cloud.json`.
⁴ `reports/m18/cloud_detection/flaws_cloud.json`.

## 5. Field-level usability, before and after

Verdict counts over the 16 rules registered at `dba8501`. "Before" is the M17
channel-granularity verdict; "after" is the M18-1 per-field verdict.

| Corpus | Before (supported / degraded / unsupported) | After (usable / degraded / unusable / not eligible) | Source |
| ------ | ------------------------------------------ | --------------------------------------------------- | ------ |
| synthetic | 11 / 1 / 4 | 11 / 1 / 0 / 4 | `reports/m18/field_usability/synthetic.json` |
| COMISET | 9 / 2 / 5 | 9 / 2 / 1 / 4 | `reports/m18/field_usability/comiset.json` |
| attack_data_aws | 4 / 0 / 12 | 3 / 0 / 3 / 10 | `reports/m18/field_usability/attack_data_aws.json` |
| flaws.cloud | 4 / 0 / 12 | 3 / 0 / 3 / 10 | `reports/m18/field_usability/flaws_cloud.json` |
| k8s_ci | 2 / 0 / 14 | 2 / 0 / 2 / 12 | `reports/m18/field_usability/k8s_ci.json` |

The point is the split of the old "unsupported" bucket into **not eligible** (the rule's
declared table is empty here -- 10 of 16 rules on both AWS corpora) and **unusable** (the
table has rows and a required field does not carry values). Those have different remedies
and the old verdict named neither.

Two corrections inside the measurement itself, both making it report *less* blindness:

* M18-4B (`f43726e`): `target_actor` read as populated on 0.61% of 1,857,154 rows and
  AWS-001 came back UNUSABLE on a trail whose grant rows *do* carry it. Applicability
  denominators fixed it. "Reporting blindness that does not exist spends exactly the trust
  that hiding blindness spends."
* M18-5B (`1df2bd9`): AWS-002 was DEGRADED on flaws.cloud solely for a sparse
  `resource_name`, and ATH-005 solely for a `logon_type` CloudTrail does not have. Both
  found every finding they were ever going to find. Optional fields now report
  `sparse_optional_fields` and move no verdict.

## 6. Admission, quarantine, and the outlier rule that was rejected

**Admission** (MEASURED, `reports/m18/input_boundary/*.json`): attack_data_aws 5/5 files
admitted, flaws.cloud 20/20, k8s_ci 1/1, COMISET **1 of 2** -- `comiset_seen.json`, the
slice directory's own statistics sidecar, rejected because it parses in no shape the source
accepts. Its **513 lines** had previously been counted in `rows_read` and then rejected one
by one, so every "we used X% of the corpus" number was a fraction of bytes the corpus never
claimed were events.

**Quarantine** (MEASURED): total quarantined is **0** on attack_data_aws, flaws.cloud,
k8s_ci and synthetic, and **1** on COMISET -- a network row timestamped 1990-12-18, which
in `H4_FROZEN.json` was the lower bound of that corpus' observed network window and had
stretched the corpus by 35 years. Nothing is repaired: a clamped timestamp is a time this
project invented.

**The relative-outlier rule, measured and rejected.** The absolute bounds are a floor and a
ceiling. A *relative* test -- "quarantine rows more than 30 days from their table's own
median" -- was measured report-only before being considered:

| Corpus / table | Rows | Beyond 30d from the median | Fraction |
| -------------- | ---: | -------------------------: | -------: |
| flaws.cloud logon | 79,424 | 76,472 | **96.3%** |
| flaws.cloud control | 96 ⁵ | 88 | 91.7% |
| k8s_ci control | 7,951 | 0 | 0.0% |
| synthetic (all) | 1,093 | 0 | 0.0% |

⁵ measured at the M18-2 HEAD, before M18-3 made every management record a control row.

A rule that would quarantine 96% of a legitimate 3.6-year trail is not a data-quality rule,
it is a rule that mistakes a long observation window for corruption. It was measured, it is
reported, and it was not adopted. Source: `reports/m18/input_boundary/flaws_cloud.json`
`far_from_median`.

## 7. Decision, three-valued

| Corpus | Before: allowed / denied | After: allowed / denied / failed | Source |
| ------ | -----------------------: | -------------------------------: | ------ |
| flaws.cloud | 368,084 / 1,489,070 | 368,084 / **455,794** / **1,033,276** | `reports/m18/cloud_behaviour/flaws_cloud.json` |
| attack_data_aws | 170 / 2,177 | 170 / 2,132 / 45 | `reports/m18/cloud_behaviour/attack_data_aws.json` |
| k8s_ci | 7,928 / 23 | 7,928 / **0** / 23 | `reports/m18/cloud_behaviour/k8s_ci.json` |

**69% of what flaws.cloud called a "denial" was not about authority at all** -- 779,330
throttled `RunInstances` retries, 101,226 unsupported operations, 59,323 insufficient
capacity, and so on (`f329643`). A count of denials per identity, the one question the
column exists to answer, was a count of retries. On k8s_ci the split moves *every* refusal
out of `denied`: the 23 non-2xx responses there are 409 conflicts and 404s, none of them an
authorization answer.

This is the measurement that made AWS-004 and AWS-006 expressible at all: under a
two-valued column, "the platform refused you" and "your request was malformed" were the
same value.

## 8. The pre-registered detection result

`reports/m18/cloud_detection/PREREGISTERED.md` was committed at `eb7d395`, before the rule
code existed and before anything ran against the held-out captures. **12 MATCH, 3 PARTIAL,
1 MISS.**

| # | Subject | Grade | Measured |
| - | ------- | ----- | -------- |
| P1 | T1526 security_scanner | MATCH | AWS-003 ×1 HIGH (19 services, 1,071 calls, 91.4% denied), AWS-004 ×1 HIGH (979 denials / 49 resource types) |
| P2 | T1580 accessdenied_discovery | **PARTIAL** | cloudsploit as predicted; **cloudmapper also fired** -- AWS-004 ×1 HIGH, 37 denials across 5 resource types in 4m44s |
| P3 | T1580 brute force | MATCH | AWS-006 exactly 2, `bhavin_cli` and `mhart_cli`, 5 rejected writes each |
| P4 | T1098 delete_policy | MATCH | 27 AWS-005 episodes over all 5 actors, covering all 78 allowed removals; plus 2 unpredicted AWS-006 |
| P5 | T1078.004 login_sfa | MATCH | 0 control rows, 0 findings |
| P6 | Capture recall | MATCH | **4/5 (0.80)**, missing exactly T1078.004 |
| P7 | Existing findings unchanged | MATCH | exactly 39 (ATH-005 36, AWS-002 3), severity mix unchanged |
| P8 | AWS-003 ≤ 7 actors / ≤ 179 episodes | **PARTIAL** | 7 actors (exact), **278 episodes** |
| P9 | AWS-004 ≤ 3 actors / ≤ 203 episodes | **PARTIAL** | 3 actors (exact), **1,142 episodes** |
| P10 | AWS-005 ≤ 6 actors / ≤ 25 episodes | MATCH | 3 actors, 17 episodes |
| P11 | AWS-006 = 0 on flaws | MATCH | 0. Report-only denied-inclusive variant: 32 episodes / 3 actors, largest 940 in 32 minutes |
| P12 | Cases rise | MATCH | 4 → 281 (97 singletons); 39 → 1,476 findings; **0 likely_benign at both ends** |
| P13 | k8s_ci 0 new findings | **MISS** | **1** -- AWS-006, `system:addon-manager`, 21 rejected ClusterRoleBinding creates in 37 minutes |
| P14 | synthetic 0 new | MATCH | 0 new; 15 before and after |
| P15 | COMISET 0 new | MATCH | 0 new; 5 before and after |
| P16 | Benchmark 5/5, 0 noise | MATCH | 5/5, 0 noise |

**The second recall number, not predicted.** `caught_with_labelled_technique` is **3/5
(0.60)**. The extra miss is the T1580 brute-force capture: AWS-006 fires correctly and
asserts T1098 Account Manipulation, not T1580. Both readings are defensible and the label
says T1580. Recorded, not reconciled -- adding a T1580 mapping after seeing this number
would be fitting the ATT&CK layer to five files.

**P2 (PARTIAL)** was a mis-read of an artifact already in the repository: cloudmapper's 37
denials span 4m44s, not "two hours"; the two hours are the gap between two bursts. Nothing
about the rule is implicated.

**P8/P9 (PARTIAL)** used the wrong unit. The ceiling was the M18-7 grid's *actor-days*,
which is a lower bound on episodes, not an upper one: an identity tripping the threshold at
09:00, 11:00 and 16:00 is one actor-day and three non-overlapping episodes. Both actor
ceilings held exactly. The population was predicted exactly; the volume was under-predicted
by 1.6× and 5.6×.

### 8.1 P13 and the M18-9 post-registration change

AWS-006's predicate was `changes_authority`, whose second clause is Kubernetes RBAC
bindings, while the rule declared `channels = {CLOUD_MANAGEMENT_ACTIVITY}` -- a channel the
catalogue defines as `source == "cloudtrail_mgmt"`. So the coverage model told the operator
the rule was UNUSABLE on k8s_ci while the rule produced a finding there. The finding was
true; the declaration was false; and the coverage model is only worth printing if it cannot
be contradicted.

M18-8 deliberately refused to narrow the predicate after seeing the result. M18-9 made the
change as a *declaration repair* -- the declared channel was already
`CLOUD_MANAGEMENT_ACTIVITY`, and the predicate was wider than the declaration -- and
validated it on a corpus these rules have never run on.

| # | Predicted (before the corpus was opened) | Measured | Grade |
| - | ---------------------------------------- | -------- | ----- |
| P17 | K8NTEXT: 0 findings from AWS-003..006 | 18,448 records read, **31 kept**, **0 findings**, 0 cases | MATCH |
| P18 | K8NTEXT: 0 declared-channel violations | **0** | MATCH |
| P19 | k8s_ci: 0 findings (was 1), 0 violations (was 20 cited rows) | **0 / 0** | MATCH |
| P20 | attack_data_aws and flaws.cloud unchanged | identical in every field but the new `channel_violations` block | MATCH |

Declared-channel violations, all corpora, at `3ed26aa`:

| Corpus | Rows | Findings | Violations before | Violations after |
| ------ | ---: | -------: | ----------------: | ---------------: |
| k8s_ci | 7,951 control | 1 → **0** | **20** (AWS-006) | **0** |
| K8NTEXT | 31 control | 0 | 0 | **0** |
| attack_data_aws | 2,349 | 36 | 0 | **0** |
| flaws.cloud | 1,936,578 | 1,476 | 0 | **0** |
| synthetic | 1,093 | 15 | 0 | **0** |
| COMISET | 610,635 | 5 | 0 | **0** |

Sources: `reports/m18/cloud_detection/{k8s_ci,k8ntext,k8ntext_profile,attack_data_aws,flaws_cloud,synthetic,comiset}.json`,
field `channel_violations`. The pre-change k8s_ci count of 20 was measured in this task by
running the new checker against the rule file at `58b513d`; the same experiment on the
test fixture produces 7 violations (6 AWS-006, 1 AWS-005).

## 9. The agent layer's first contact with real cloud cases

Deterministic (NullLLM) investigation over the first ten flaws.cloud cases. Nothing tuned,
no model called. Source: `reports/m18/cloud_detection/flaws_cloud.json`
`agent_deterministic`.

* 10 cases, **20** specialist steps, ~~**172** tool calls~~ **39** tool calls ¹
* **203 FACT**, **34 INFERENCE**, **0 HYPOTHESIS**
* **0 claims rejected by the verifier** -- the construction-time guarantee, not a lucky run
* Specialists dispatched: `control_plane` 9, `attack` 10, `identity` 1

¹ **Corrected after publication, 2026-09-13 (M19-2).** This row originally read **172**,
which was *cumulative across cases rather than per case*. `scripts/m18_cloud_detection.py`
built one `ToolBox` and reused it for all ten investigations; `ToolBox.calls_by` returns
every call made since the toolbox was constructed and `Specialist._result` attaches
exactly that, so case *n* recorded cases 1..n-1's calls as its own and the total is the
accumulation. The same ten cases, re-run with **one toolbox per case**, make **39** tool
calls. Everything else in this section is unchanged: facts, inferences, hypotheses,
rejections and steps are read from the investigation state, which was always per case, and
they re-measure identically (203 / 34 / 0 / 0 / 20). The fix is structural rather than
arithmetical -- a fresh toolbox per case, which `ath.evaluation.ablation.arms.run_arm`
already did and documented -- because subtracting the previous case's count would have
produced the same numbers today and re-broken the moment anything else read `calls_by`.
The old cumulative figure is kept beside the corrected one in
`reports/m18/cloud_detection/flaws_cloud.json` under
`agent_deterministic.cumulative_pre_correction`, with the per-case table under
`agent_deterministic.per_case`. Reproduce with
`python scripts/m18_cloud_detection.py flaws_cloud --investigate`; pinned by
`tests/test_m18_cloud_detection_per_case.py`, which fails against the pre-correction
script.

Per case, corrected:

| case | rules | findings | tool calls | FACT | INFERENCE | steps | specialists |
|---|---|---:|---:|---:|---:|---:|---|
| CASE-001 | AWS-004 | 1 | 2 | 8 | 2 | 2 | control_plane, attack |
| CASE-002 | AWS-004 | 1 | 2 | 11 | 2 | 2 | control_plane, attack |
| CASE-003 | AWS-004 | 1 | 2 | 11 | 2 | 2 | control_plane, attack |
| CASE-004 | AWS-003, AWS-004 | 2 | 5 | 33 | 4 | 2 | control_plane, attack |
| CASE-005 | ATH-005 | 1 | 3 | 2 | 4 | 2 | identity, attack |
| CASE-006 | AWS-003, AWS-004 | 2 | 5 | 26 | 4 | 2 | control_plane, attack |
| CASE-007 | AWS-003, AWS-004 | 2 | 5 | 28 | 4 | 2 | control_plane, attack |
| CASE-008 | AWS-003, AWS-004 | 2 | 5 | 28 | 4 | 2 | control_plane, attack |
| CASE-009 | AWS-003, AWS-004 | 2 | 5 | 28 | 4 | 2 | control_plane, attack |
| CASE-010 | AWS-003, AWS-004 | 2 | 5 | 28 | 4 | 2 | control_plane, attack |
| **total** | | **16** | **39** | **203** | **34** | **20** | |

The correction makes the section's own conclusion sharper rather than softer: **3.9 tool
calls per case**, not 17.2. The layer was doing even less asking than the published
number suggested.

For scale: `H4_FROZEN.json` records that across *every* real external corpus before this
milestone, the investigation layer had produced 3 facts, 2 inferences and 4 tool calls in
total. This is the first time it has done real work on real data. What it did was restate
rows of the trail with their event ids and assert two techniques -- correct, verifiable,
and shallow. **0 hypotheses over 10 cases** is the number to watch: the layer is
summarising, not investigating.

## 10. Defects found this milestone

**Fixed** (each with the commit that fixed it):

| Defect | Measured impact | Fixed in |
| ------ | --------------- | -------- |
| Management-call allowlist: 5 named APIs, everything else refused | 2 of 2,349 attack records ingested (0.09%), 0 findings -- the rules were never given the attack | `a663381` |
| Files admitted by filename extension | COMISET's statistics sidecar counted 513 lines into `rows_read`; same pattern in all 4 JSON adapters + Defender | `04e041e` |
| Implausible timestamps pass unflagged | one 1990 network row stretched COMISET's observed window by 35 years | `1f1e9d8` |
| `decision` two-valued: "denied" meant any error | 1,033,276 of 1,489,070 flaws "denials" (69%) were retries, capacity and not-found | `f329643` |
| `target_actor` filled on identity-service *reads* | 11,388 flaws rows filed under the user being enumerated rather than the caller; 11,210 were reads | `27489b8` |
| Applicability denominator wider than the source guarantee | all 146 attack_data_aws authority-change rows name no principal; AWS-001 reported UNUSABLE on a corpus with no grants | `0f02f13` |
| `resource_name` asked an identity question on every service | answered on 1,461 of 1,857,154 rows (0.08%) → 150,281 (8.09%) | `532bd76` |
| Optional fields moved rule verdicts | AWS-002 and ATH-005 DEGRADED on flaws while finding everything they ever would | `1df2bd9` |
| Rule→table map outside the rules | ATH-007 credited 21,158 eligible events; the true number is 15,095 | `0ccf565` |
| Fast timestamp path could diverge from its fallback | flaws load 159s → 2,288s after M18-3; now 162.6s, 58,647 real strings, 0 mismatches | `9b51253` |
| Rule predicate wider than its channel declaration (P13) | AWS-006: 1 finding / 20 cited rows on a corpus the coverage model called UNUSABLE | `3ed26aa` |

**Recorded and not fixed:**

* **AWS-004 has the same exposure AWS-006 had.** Its predicate is `decision == "denied"`
  with no platform scope, and the Kubernetes adapter emits `denied` on 401/403
  (VERIFIED FROM CODE, `ath.telemetry.k8s_audit_source._decision` →
  `ath.control_vocab.classify_error`). A Kubernetes authorization-denial burst would make
  it cite `container_audit` rows while declaring `cloud_management_activity`. **No corpus
  in this repository contains one** -- k8s_ci measures 0 denied rows of 7,951 -- so this is
  PROJECTED, not measured. It is written into `tests/test_declared_channels.py` and into
  `PREREGISTERED.md` rather than smuggled past the invariant test by silence. M18-9's remit
  was the two rules whose declaration was *measurably* false.
* **AWS-006 asserts T1098 on a capture labelled T1580.** §8.
* **Triage disposes of no cloud finding as benign.** 0 of 1,476. M15-4's known gap.
* **`'?'` in agent FACT text** where the adapter could not recover a `resource_name`.
  Cosmetic, pre-existing, recorded in `PREREGISTERED.md`.

## 11. Negative results preserved

* The relative-outlier quarantine rule: measured at 96.3% of a legitimate trail, rejected
  (§6).
* The denied-inclusive AWS-006 variant: **report-only**, never a `Finding`, measured at 32
  episodes / 3 actors on flaws.cloud with the largest at 940 rejections-or-refusals in 32
  minutes. A test fails if it ever starts returning findings.
* P13, P2, P8 and P9 stand in the pre-registration as written, with the reasoning that got
  them wrong.
* The 4/5 vs 3/5 recall gap is reported both ways rather than as the flattering one.
* K8NTEXT finding 0 is reported as a test of the *repair*, not as evidence the rules
  discriminate anything.

## 12. Five highest-priority risks

1. **Alert volume has no benign story.** 39 → 1,476 findings and 4 → 281 cases on one
   account, with **0** dispositioned likely_benign at either end. The rules are honest
   about their false positives in prose and the triage layer cannot act on any of it. This
   is now the binding constraint, ahead of representation.
2. **No ground truth on any cloud corpus but five labelled captures.** Precision is
   unmeasurable on flaws.cloud by construction. Recall is measured on a denominator of 5,
   each file collected to demonstrate the technique it is named for.
3. **Cross-channel identity is still ambiguous.** `H4_FROZEN.json`: 99.98% join rate,
   **86.5%** of `(device, pid)` keys ambiguous, worst key covering 27 process instances,
   because `process_guid` is discarded at ingestion. Untouched by M18.
4. **The investigation layer summarises rather than investigates.** 203 facts, 34
   inferences, **0 hypotheses** over 10 real cases.
5. **Declaration truth is enforced, not guaranteed.** The invariant holds on six corpora
   and one mixed fixture. AWS-004's exposure (§10) shows the class is not closed, and
   nothing prevents a new rule from borrowing a cross-platform predicate again except a
   test that must be given the right shape to see it.

## 13. Recommended next milestone

**M18b: process-instance identity, then an agentic ablation, then the triage gap.**
The architect's direction, in the order the evidence supports.

1. **`process_guid` / process-instance identity.** Driven by the 86.5% join ambiguity in
   `H4_FROZEN.json` and by nothing else. Every cross-channel claim an investigation makes
   -- "this process made this connection" -- is currently unsubstantiable two times in
   three, and no amount of rule or agent work changes that.
2. **An agentic ablation on identical inputs.** Arm A NullLLM, arm B one LLM, arm C the
   crew, over the *same* flaws.cloud cases. flaws.cloud has no verdict labels, so the score
   cannot be precision: score **evidence correctness** (does every cited event id exist and
   say what the claim says) and **unsupported claims** (assertions with no evidence behind
   them). Those are measurable without labels, and they are the two things an LLM arm can
   plausibly make worse.
3. **The triage gap.** 0 of 1,476. Until a cloud finding can be dispositioned benign on
   evidence, every rule added to this surface is a rule that adds queue.

The question M18b should answer: **does the crew produce claims a NullLLM cannot, without
producing claims the telemetry cannot support?**

## 14. What this milestone does not establish

* **That the thresholds are right.** They are *fixed*, and now *priced*: 0.21, 0.86 and
  0.013 episodes per day on a 3.6-year trail, and (before M18-9) one alert per month of CI
  audit log. Whether that is affordable is an architect call.
* **That the 1,437 new flaws.cloud findings are false positives.** The corpus is unlabelled
  and the account was deliberately vulnerable. Volume is what was measured.
* **Detection quality on cloud telemetry.** Five captures, one technique each.
* **Anything about corpora not run here.** DEDALE and the Kubernetes ingress corpus were
  not part of M18's measurement; no number in this report is about them.
* **Cases or investigation on attack_data_aws.** Not measured: the per-capture harness
  stops at findings, deliberately, so two captures sharing an actor cannot merge.
* **That representation is finished.** 0.17% of K8NTEXT and 2.97% of k8s_ci records become
  canonical rows, because the Kubernetes adapter maps RBAC binding writes and pod exec and
  nothing else. That is a stated scope, not a measurement of blindness -- but it is also
  why "0 findings on K8NTEXT" costs so little to achieve.
