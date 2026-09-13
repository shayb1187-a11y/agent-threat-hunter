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
