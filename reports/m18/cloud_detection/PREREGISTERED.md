# M18-8 pre-registration: four generic control-plane detections

**Written** 2026-09-13.
**HEAD at the time of writing** `eb7d395e7bda2cae21d36b8a3cd79691b3b3a6fb`
(`M18-7 Part B: the distribution comes before the threshold`).

**Nothing in this document was derived from the held-out corpus.** Every threshold below
comes from the background distribution measured in
`reports/m18/cloud_behaviour/flaws_cloud.json` (flaws.cloud, 1,857,154 control rows, 55
actors, ~3.6 years) and from the candidate grid that M18-7 evaluated *before* any rule
existed. This file is committed before a single line of rule code is written, and before
any detection is run against `data/external/attack_data_aws/raw`. The predictions in the
second half are the architect's, recorded verbatim; the RESULTS section appended after
measurement grades every one of them, whether or not it matched.

Why the order matters: a threshold chosen after seeing the attack corpus is not a
detection, it is a memory of that corpus. The only way to make "the rule caught it" a
statement about the rule rather than about the tuning is to fix the number first, in
public, and then look.

What the background corpus is and is not: flaws.cloud is a deliberately vulnerable CTF
account. Its rows carry no per-event labels, so a finding there is **unlabelled**, never
"a known false positive". The numbers below are alert *volume*, which is a real cost, and
nothing more.

---

## The rules

All four read `telemetry.controls` only, and describe behaviour through verb classes,
`decision`, the identity-service predicate, distinct-service / distinct-resource breadth,
counts and windows. No API name, service name or actor name appears in any rule body.
None is CRITICAL: every one of these behaviours has a common benign reading.

### AWS-003 -- Cloud service discovery burst

One actor performs read-class calls (`verb_class == read`) touching
**>= `cloud_discovery_min_services` = 10 distinct services** within
**`cloud_discovery_window` = 10 minutes**.

* One finding per burst episode per actor, non-overlapping clusters, the ATH-005
  `_find_bursts` pattern.
* Severity **MEDIUM**; **HIGH** when the majority of the burst's calls were
  `decision == denied` -- breadth with no permission is probing, not administration.
* Evidence: up to 20 representative rows (first occurrence per distinct service), with
  the true count in metadata.
* Metadata: `distinct_services`, `distinct_resource_types`, `call_count`,
  `denied_fraction`, window bounds.

Threshold provenance: `read_services` in the M18-7 grid, 10-minute window. The background
distribution over 55 actors is p50 = 1, p90 = 11.8, p99 = 125.6, max = 145. The candidate
grid's consequences at that window: `>= 5` catches 9 actors on 335 actor-days, `>= 10`
catches 7 actors on 179 actor-days, `>= 20` catches 4 actors on 89 actor-days. 10 is
chosen as the value just above p90 -- the knee -- and because `>= 20` would miss the
T1526 capture's 19 services, which is the failure mode a breadth rule exists to avoid.

### AWS-004 -- Authorization-denial burst

One actor accumulates **>= `cloud_denial_min_count` = 25 `decision == denied` calls**
within **`cloud_denial_window` = 10 minutes**.

* One finding per episode per actor.
* Severity **MEDIUM**; **HIGH** when the denied calls span **>= 5 distinct
  `resource_type`s**.
* Evidence: up to 20 rows (first per distinct `resource_type`), true count in metadata.

Threshold provenance: `denied_calls` in the M18-7 grid, 10-minute window. Background
distribution p50 = 0, p90 = 1.6, p99 = 2,417, max = 2,639 -- a trail where almost every
actor is never refused and three are refused constantly. Grid consequences at 10 minutes:
`>= 10` catches 4 actors on 306 actor-days, `>= 25` catches 3 on 203, `>= 50` catches 3 on
162, `>= 100` catches 3 on 134. 25 buys most of the volume reduction available without
moving off the same three tail actors; beyond it the cost stops falling because the tail
is the tail. `denied` here means the platform refused for authorization reasons and never
"an error occurred" -- which is only a usable column since M18-7 Part A.

### AWS-005 -- Identity authority removed

Delete- or revoke-class authority changes on the identity service
(`changes_authority(verb, resource_type)` and `verb_class in {delete, revoke}`) by one
actor, aggregated into **one finding per actor per
`cloud_identity_change_window` = 60 minutes** episode.

* Severity **MEDIUM** regardless of count.
* Evidence: every row up to 20, true count in metadata.
* **Only `decision == allowed` rows count as removals.** Denied and failed attempts
  belong to AWS-006 / AWS-004; a removal that did not happen is not a removal.

Threshold provenance: `identity_delete_revoke_changes` in the M18-7 grid. The effective
threshold is 1 -- an authority actually removed is the event, not a rate -- and the grid
prices that: at `>= 1` it reaches 6 actors on 25 actor-days over 3.6 years, which is
roughly one alert every 53 days. That is affordable; `>= 3` (2 actors, 8 actor-days at 10
minutes) would be cheaper and would miss single deliberate removals, which are the ones
worth seeing.

### AWS-006 -- Repeated rejected identity authority changes

**>= `cloud_identity_failed_min_count` = 5** authority changes on the identity service
with **`decision == failed`** by one actor within **60 minutes**
(`cloud_identity_change_window`).

* Severity **MEDIUM**.
* Report-only, producing **no finding**: the same computation with
  `decision in {failed, denied}`, so the architect can see the background cost of the
  wider variant before anyone proposes adopting it.

Threshold provenance: `failed_identity_authority_changes` in the M18-7 grid. Background
distribution p50 = 0, p90 = 0, p99 = 2.92, max = 4 -- at both window lengths. Grid
consequences: `>= 3` catches 1 actor on 1 actor-day, `>= 5` catches **0 actors**, `>= 10`
catches 0. 5 is chosen as the smallest value the background corpus never reaches, which is
exactly one above its observed maximum of 4.

---

## Predictions

Recorded before any rule ran. Each is graded MATCH / MISS / PARTIAL in RESULTS below.

### attack_data_aws, per capture (held out; capture-level labels are the only cloud
ground truth ATH has)

| # | Capture (technique) | Prediction |
|---|---------------------|------------|
| P1 | T1526 `security_scanner` | AWS-003 >= 1 finding (actor `cloudsploit`, 19 services, **HIGH** via denied majority) **and** AWS-004 >= 1 finding |
| P2 | T1580 `accessdenied_discovery_events` | AWS-003 >= 1 and AWS-004 >= 1 for `cloudsploit`; **nothing** for `cloudmapper` (3 services, 37 denials over 2 hours) |
| P3 | T1580 `assume_role_policy_brute_force` | AWS-006 **exactly 2** findings (`bhavin_cli`, `mhart_cli`, 5 failed CreatePolicy each) **IF** each actor's 5 fall within 60 minutes -- else 0, and the prediction was wrong |
| P4 | T1098 `iam_delete_policy` | AWS-005 >= 1 finding for each of the 5 actors' allowed deletes (78 allowed of 116 rows); multiple episodes for `bhavin_cli` |
| P5 | T1078.004 `login_sfa` | **0 findings from any rule** -- no control rows exist; the distinguishing factor (MFA) is unobservable |
| P6 | Capture-level recall | **4 of 5**, with T1078.004 the known miss |

### flaws_cloud (background)

| # | Prediction |
|---|------------|
| P7 | Existing 39 findings unchanged (ATH-005 36, AWS-002 3) |
| P8 | AWS-003: **<= 7 actors** and **<= 179 episodes** (upper bound = 10-minute actor-days from the grid) |
| P9 | AWS-004: **<= 3 actors** and **<= 203 episodes** |
| P10 | AWS-005: **<= 6 actors** and **<= 25 episodes** |
| P11 | AWS-006: **0 findings**. The grid says no actor reaches 5 failed identity changes. The report-only denied-inclusive variant: **unknown** |
| P12 | Cases will rise; the count is **unknown** |

### Everything else

| # | Prediction |
|---|------------|
| P13 | k8s_ci: **0 new findings** (no read-class or identity-service rows; the Kubernetes adapter maps only binding writes and exec) |
| P14 | synthetic `data/raw`: **0 new findings** |
| P15 | COMISET canonical: **0 new findings** |
| P16 | `python main.py benchmark`: unchanged **5/5**, **0 noise cases** |

---

## What this pre-registration does not claim

* That the thresholds are right. They are *fixed*, which is a different and weaker
  property. A miss below does not license changing them inside M18-8.
* That flaws.cloud findings are false positives. It is an unlabelled, deliberately
  vulnerable account; a finding there is an alert whose cost is known and whose truth is
  not.
* That capture-level recall is detection quality. Five captures, one technique each,
  each collected to demonstrate that technique: the denominator is tiny and the positives
  are unusually clean. It is the only cloud ground truth available, and it is reported as
  such.

<!-- RESULTS APPENDED BELOW AFTER MEASUREMENT -- do not edit anything above this line. -->

---

# RESULTS (appended 2026-09-13, after measurement)

Measured at HEAD `d8b3da2` (`M18-8 Part B`), with `scripts/m18_cloud_detection.py`, which
writes the artifacts this section quotes:
`reports/m18/cloud_detection/{attack_data_aws,flaws_cloud,k8s_ci,synthetic,comiset}.json`.
No threshold moved between the pre-registration above and this measurement, and none moves
because of it; an anti-overfitting test parses this file and fails the suite if any
`HuntConfig` default differs from what is declared above.

Twelve of the sixteen predictions matched, three were partial and one missed outright.

## attack_data_aws -- per capture

| # | Capture | Predicted | Measured | Grade |
|---|---------|-----------|----------|-------|
| P1 | T1526 `security_scanner` | AWS-003 >= 1 (cloudsploit, 19 services, HIGH) and AWS-004 >= 1 | AWS-003 x1 HIGH, `cloudsploit`, 19 services / 1,071 calls / 91.4% denied, 11:32:52-11:35:44; AWS-004 x1 HIGH, 979 denials across 49 resource types | **MATCH** |
| P2 | T1580 `accessdenied_discovery_events` | AWS-003 >= 1 and AWS-004 >= 1 for cloudsploit; **nothing** for cloudmapper | cloudsploit: AWS-003 x1 HIGH (45 services, 1,093 calls, 100% denied), AWS-004 x1 HIGH (1,113 denials, 78 resource types). cloudmapper: **AWS-004 x1 HIGH** -- 37 denials across 5 resource types in 4m44s | **PARTIAL** |
| P3 | T1580 `assume_role_policy_brute_force` | AWS-006 **exactly 2** (bhavin_cli, mhart_cli, 5 each) if each actor's 5 fall inside 60 minutes | Exactly 2, MEDIUM, `bhavin_cli` and `mhart_cli`, 5 rejected writes each, both bursts inside a single second | **MATCH** |
| P4 | T1098 `iam_delete_policy` | AWS-005 >= 1 for each of the 5 actors; multiple episodes for bhavin_cli | 27 AWS-005 episodes over all 5 actors -- bhavin_cli 19, patrick_cli 4, bpatel@contoso.local 2, jose_cli 1, mhart_cli 1 -- covering all 78 allowed removals. Plus 2 unpredicted AWS-006 episodes (bhavin_cli, 11 rejected writes) | **MATCH** |
| P5 | T1078.004 `login_sfa` | **0 findings from any rule** | 0 control rows, 2 logon rows, 0 findings | **MATCH** |
| P6 | Capture-level recall | **4 of 5**, T1078.004 the known miss | `caught_any` = **4/5 (0.80)**, missing exactly T1078.004 | **MATCH** |

### The second recall number, which was not predicted

`caught_with_labelled_technique` -- did the ATT&CK mapper assert the technique the capture
is *labelled* with -- is **3 of 5 (0.60)**. The extra miss is the T1580 brute-force
capture: AWS-006 fires on it, correctly and for the right reason, and asserts **T1098
Account Manipulation**, not T1580. Both readings are defensible (the capture is a
permission brute force against a role trust policy, which is discovery of what the
platform will accept *and* an attempt to manipulate an account), and the label says T1580.
Recorded rather than reconciled: adding a T1580 mapping to AWS-006 after seeing this
number would be fitting the ATT&CK layer to five files.

## flaws_cloud -- background volume

| # | Predicted | Measured | Grade |
|---|-----------|----------|-------|
| P7 | Existing 39 findings unchanged (ATH-005 36, AWS-002 3) | Exactly 39: ATH-005 36, AWS-002 3. Severity mix unchanged (4 CRITICAL, 35 MEDIUM) | **MATCH** |
| P8 | AWS-003 <= 7 actors, <= 179 episodes | **7 actors**, **278 episodes** (0.21/day over 1,333 days; 108 HIGH, 170 MEDIUM) | **PARTIAL** |
| P9 | AWS-004 <= 3 actors, <= 203 episodes | **3 actors**, **1,142 episodes** (0.86/day; 243 HIGH, 899 MEDIUM) | **PARTIAL** |
| P10 | AWS-005 <= 6 actors, <= 25 episodes | **3 actors**, **17 episodes** (0.013/day; all MEDIUM) | **MATCH** |
| P11 | AWS-006 = 0 findings; denied-inclusive variant unknown | **0 findings.** The report-only denied-inclusive variant: **32 episodes across 3 actors**, the largest 940 rejections-or-refusals in 32 minutes | **MATCH** |
| P12 | Cases rise; count unknown | 4 -> **281** cases (97 singletons). Triage: 39 findings (4 likely_malicious / 35 needs_review) -> 1,476 findings (355 / 1,121); nothing was dispositioned likely_benign either before or after | **MATCH** |

Top actors per rule, with the identity type recovered from the raw records:

| Rule | Actor | Episodes | Identity type (rows) |
|------|-------|----------|----------------------|
| AWS-003 | Level6 | 164 | IAMUser 899,736 / AssumedRole 4,192 |
| AWS-003 | backup | 84 | IAMUser 904,084 |
| AWS-003 | i-aa2d3b42e5c6e801a | 17 | AssumedRole 19,769 |
| AWS-003 | secmonkey | 10 | AssumedRole 12,354 |
| AWS-003 | cloudsploit_scan | 1 | AssumedRole 568 |
| AWS-004 | backup | 601 | IAMUser 904,084 |
| AWS-004 | Level6 | 507 | IAMUser 899,736 / AssumedRole 4,192 |
| AWS-004 | i-aa2d3b42e5c6e801a | 34 | AssumedRole 19,769 |
| AWS-005 | arn:aws:iam::811596193553:root | 11 | Root 7,530 |
| AWS-005 | flaws | 5 | Root 3,346 |
| AWS-005 | piper | 1 | IAMUser 142 |

## The other corpora

| # | Predicted | Measured | Grade |
|---|-----------|----------|-------|
| P13 | k8s_ci: **0 new findings** | **1 new finding** -- AWS-006, MEDIUM, `system:addon-manager`, 21 rejected `create` calls on the `system:coredns` ClusterRoleBinding in 37 minutes | **MISS** |
| P14 | synthetic `data/raw`: 0 new findings | 0 new. 15 findings before and after; the control table is empty | **MATCH** |
| P15 | COMISET canonical: 0 new findings | 0 new. 5 findings before and after; the control table is empty | **MATCH** |
| P16 | Benchmark 5/5, 0 noise cases | **5/5**, 0 noise cases across the suite, every incident on the deterministic arm | **MATCH** |

## Interpretation, one paragraph per miss

**P2, cloudmapper (PARTIAL).** The prediction read cloudmapper 37 denials as spread "over
2 hours" and concluded they would not reach 25 inside a ten-minute window. They are not:
`reports/m18/cloud_behaviour/attack_data_aws.json` records cloudmapper span as 0.079
hours, and the measured episode runs 13:30:36 to 13:35:20 -- 37 refusals in four minutes
and forty-four seconds, across five distinct resource types, which is over the count
threshold and exactly at the HIGH grading condition. The two hours in the prediction are
the gap between the cloudsploit burst and the cloudmapper one, not the duration of either.
This is a mis-read of an artifact that was already in the repository, not a surprise about
the rule: the rule did what it says on a caller refused 37 times in five minutes. Whether
it *should* fire there is a separate question from whether it was predicted to, and the
threshold stays where it was registered.

**P8 and P9, episode ceilings (PARTIAL).** Both actor ceilings held exactly; both episode
ceilings were wrong, and wrong the same way, by factors of 1.6 and 5.6. The ceiling was
taken from the M18-7 grid *actor-days* -- the number of (actor, day) pairs on which a
qualifying window ended -- and an actor-day is not an upper bound on episodes. It is a
lower one. An identity that trips the threshold at 09:00, again at 11:00 and again at
16:00 contributes **one** actor-day and **three** non-overlapping episodes, and on a trail
whose three tail identities carry ~900,000 rows each over three and a half years that
multiplier is the whole gap. The unit the pre-registration should have used is the one the
rule emits, and M18-7 measured a different one; nothing about the rules or the thresholds
is implicated, and the correct reading of P8/P9 is that the *population* was predicted
exactly while the *volume* was under-predicted. What the measurement does establish, and
the prediction did not ask, is the real operator cost: 0.21 and 0.86 episodes per day,
concentrated on three identities, on an account that is deliberately vulnerable and
unlabelled.

**P13, k8s_ci (MISS).** The prediction reasoned that the Kubernetes adapter maps only
binding writes and exec, so no read-class or identity-service rows exist there -- true for
AWS-003, AWS-004 and AWS-005, all three of which are silent. It missed that the AWS-006
predicate is `changes_authority`, and that function is deliberately cross-platform: its
second clause is *Kubernetes RBAC bindings*, which is exactly what the adapter does map.
So the rule ran on Kubernetes rows and found `system:addon-manager` re-creating the
`system:coredns` ClusterRoleBinding twenty-one times in thirty-seven minutes, every
attempt rejected for a reason that is not an authorization refusal. That is, word for
word, the second false positive AWS-006 itself declares -- "automation racing itself: two
runs creating the same identity object, where the loser is rejected for a name conflict"
-- so the rule is behaving exactly as documented, on exactly the benign shape it
documented. Three things are worth recording rather than fixing: the finding is a true
instance of a declared false positive, not a defect; the `AWS-` prefix in the rule id and
the `CLOUD_MANAGEMENT_ACTIVITY` channel declaration both now under-describe where this
rule fires, which is a naming and declaration question for the architect; and narrowing
the predicate to exclude Kubernetes *after seeing this result* would be precisely the
tuning this pre-registration exists to prevent. One alert across thirty days of CI audit
log is not a cost that forces the question.

## The agent layer meets real cloud cases

First run of the deterministic (NullLLM) investigation over cases these rules produced, on
the first ten flaws.cloud cases. Nothing was tuned and no model was called. The CLI
`investigate --no-llm` reads only the configured synthetic data directory, so the external
corpus was driven through the same library objects the command builds.

* 10 cases, 20 specialist steps, **172 tool calls**
* **203 FACT** claims, **34 INFERENCE** claims, **0 HYPOTHESIS** claims
* **0 claims rejected by the verifier** -- every FACT cited an event id that exists in the
  telemetry, which is the construction-time guarantee rather than a lucky run
* Specialists dispatched: `control_plane` on 9 cases, `attack` on 10, `identity` on 1

Example, CASE-001 (one AWS-004 finding, actor `backup`): the planner ran `control_plane`
because the case evidence rests on cloud management telemetry, then `attack` because the
case carries ATT&CK mappings, then stopped because no specialist had further useful work.
Two tool calls -- `get_events` over the eight cited event ids (8/8 found) and
`lookup_technique(T1580)`. Eight FACTs, each one row of the trail restated with its event
id (`'backup' performed get on iam:user`, `... get on s3:bucket-acl ...`), and two
INFERENCEs: that the behaviour is consistent with T1580 Cloud Infrastructure Discovery,
and that the case spans one ATT&CK tactic. One imprecision worth noting, cosmetic and
pre-existing: a fact built from a row whose `resource_name` the adapter could not recover
renders the name as `'?'`.

## What this measurement does not establish

* **That these thresholds are right.** They are *fixed*, and now *priced*: 0.21, 0.86 and
  0.013 episodes per day on a three-and-a-half-year trail, and one alert per month of CI
  audit log. Whether that is affordable is the architect call, and a different one from
  the call this milestone made.
* **That the 1,437 new flaws.cloud findings are false positives.** The corpus is
  unlabelled and the account was deliberately vulnerable. What is measured is volume.
* **Detection quality.** Five captures, one technique each, each collected to demonstrate
  that technique. The denominator is tiny and the positives are unusually clean.
* **Anything about the triage benign layer on cloud evidence.** It dispositioned 0 of
  1,476 findings as likely_benign, before and after, which is the known signal gap M15-4
  recorded and not something these rules changed.
