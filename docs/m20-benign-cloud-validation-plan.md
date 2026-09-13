# M20: a predeclared benign cloud corpus

Written before any account exists and before any log is collected. flaws.cloud cannot
serve as a benign baseline -- its long-lived identities are the attackers, so its
"background" is the attack. This plan builds a baseline whose benignity is known by
construction: a disposable AWS account, workflows declared in this file before they run,
real CloudTrail, and a sealed holdout.

The workflows below are **ordinary operations**. None is shaped to make a rule fire or
not fire. Where a rule is expected to fire, it is because the operation genuinely has
that shape and the rule says so itself -- every such expectation quotes the rule's own
`false_positives` declaration.

## 1. The rules under test

Read from the source at `4fd11a0`. Thresholds from `src/ath/hunting/base.py`.

| rule | file:line | severity | threshold |
| ---- | --------- | -------- | --------- |
| ATH-005 failed-logon burst then success | `hunting/rules/logon_rules.py:61` | HIGH | 10 failures / 10 min, success within 15 min (`base.py:39,43,46`) |
| AWS-001 policy grant then access-key creation | `hunting/rules/aws_rules.py:77` | HIGH | same identity within 30 min (`base.py:65`) |
| AWS-002 trail stopped or deleted | `hunting/rules/aws_rules.py:189` | CRITICAL | any single event |
| AWS-003 service-discovery burst | `hunting/rules/cloud_behaviour_rules.py:217` | MEDIUM (HIGH if >50% denied) | 10 distinct services / 10 min (`base.py:82,93`; `_DENIED_MAJORITY = 0.5`) |
| AWS-004 authorization-denial burst | `cloud_behaviour_rules.py:360` | MEDIUM (HIGH at >=5 resource types) | 25 denials / 10 min (`base.py:98,108`; `_DENIAL_BREADTH_RESOURCE_TYPES = 5`) |
| AWS-005 identity authority removed | `cloud_behaviour_rules.py:512` | MEDIUM | per-identity episode, 60 min (`base.py:111`) |
| AWS-006 repeated rejected authority changes | `cloud_behaviour_rules.py:665` | MEDIUM | 5 failed writes (`base.py:119`) |

## 2. Workflow catalogue (predeclared)

Identity types: `IAMUser` (named human), `AssumedRole` (human via role, or CI),
`AWSService` (Lambda/SSM/CloudFormation service principals), `Root` (used once, day 1,
for account setup only).

| id | workflow | actor | calls / cadence | services, verb class | rules that could fire |
| -- | -------- | ----- | --------------- | -------------------- | --------------------- |
| W01 | Console login **with** MFA | `IAMUser` alice, bob | 1-3/day each, business hours | `signin` ConsoleLogin, write | none expected |
| W02 | Console login **without** MFA, incl. 2-4 mistyped passwords | `IAMUser` carol | 1/day, ~3 days of the 14 | `signin`, write | ATH-005 only if a burst reaches 10 failures in 10 min; the declared cadence stays under it. A deliberate day-6 lockout episode (12 failures then success) is included -- see below |
| W03 | Role assumption chain: user -> `DeveloperRole` -> `DeployRole` | `IAMUser` -> `AssumedRole` | 5-15/day | `sts` AssumeRole, write | none; feeds the actor identity of most other workflows |
| W04 | IAM administration: create user/role/group, attach/detach policies, rotate access keys | `AssumedRole` AdminRole | ~30 calls, 3 sessions over 14 days | `iam`, write + delete | **AWS-001** ("Routine onboarding: an administrator grants a new identity permissions, and that identity (or a provisioning script) creates its first access key shortly after as part of normal setup."), **AWS-005** ("Routine deprovisioning... Least-privilege cleanup campaigns") |
| W05 | Benign policy modification: widen then narrow a role's policy as its job changes | `AssumedRole` AdminRole | ~12 calls, 2 sessions | `iam`, write | **AWS-005** ("Policy churn during development, where a role's permissions are attached and detached repeatedly while someone works out what it needs.") |
| W06 | EC2 lifecycle: run 2 t3.micro, tag, stop, start, terminate | `AssumedRole` DeveloperRole | ~25 calls, 4 sessions | `ec2`, write + delete + read | none expected; AWS-003 only if bundled with W09 |
| W07 | S3 operations: create bucket, put/get/list objects, lifecycle policy, delete bucket | `AssumedRole` DeveloperRole | ~40 calls, 5 sessions | `s3`, all classes | none expected (object-level events are **not** enabled -- see 3) |
| W08 | IaC: CloudFormation `create-stack` / `delete-stack` of a small VPC + SG + instance stack, run 4 times | `AssumedRole` DeployRole + `AWSService` cloudformation | ~60 calls/run, 4 runs | `cloudformation`, `ec2`, `iam`, all classes | **AWS-001** ("Infrastructure-as-code pipelines that both attach policies and rotate access keys as part of a single automated run."), **AWS-005** ("Infrastructure-as-code runs that delete and recreate identity objects on every apply, so that a no-op change produces a removal."), **AWS-003** ("Infrastructure-as-code planning runs, which read the current state of every resource they manage before deciding what to change.") |
| W09 | **Inventory scan** -- `describe-everything` across every enabled service, read-only | `AssumedRole` AuditRole | ~250 read calls in <10 min, daily at 02:00 UTC | 15-25 services, read | **AWS-003 expected to fire, MEDIUM**: "Cloud security posture and compliance scanners (the whole point of which is to read every service in the account, on a schedule, forever)" and "Inventory, asset-management, cost-explorer and backup tooling enumerating resources across services as designed." Also **AWS-004** if the role lacks some reads |
| W10 | **Least-privilege role probing its own permissions** -- a newly scoped-down `ReportingRole` runs its normal daily job; calls outside its policy are denied | `AssumedRole` ReportingRole | ~40 calls/day of which ~28 denied, in <10 min | `ce`, `cloudwatch`, `s3`, `ec2`, mixed | **AWS-004 expected to fire, HIGH** (>=5 resource types): "A pipeline or application whose role is missing a permission, retrying the call it cannot make -- by far the most common cause of denial runs" and "A newly created or newly scoped-down role exercising paths its old policy allowed, until the code catches up with the policy." |
| W11 | Routine service automation: scheduled Lambda (hourly) + one SSM `RunCommand` per day | `AWSService` lambda/ssm | 24+1 /day | `lambda`, `ssm`, `logs`, read + write | none expected; establishes the AWSService background rate |
| W12 | Malformed-policy iteration: an engineer hand-edits a trust policy, platform rejects it 6 times before accepting | `IAMUser` bob | 7 calls, one session, day 8 | `iam`, write, decision=failed | **AWS-006 expected** ("An engineer iterating on a trust policy or a permission boundary by hand until the platform accepts it.") |
| W13 | Lockout episode: carol mistypes 12 times in 6 minutes, then resets and logs in | `IAMUser` carol | 13 events, day 6 | `signin` | **ATH-005 expected, HIGH** ("A user whose phone or mapped drive holds an old password after a reset"; "Account lockout thresholds causing repeated failures after a single mistake.") |

W09, W10, W12 and W13 exist precisely because a benign corpus that cannot trip any rule
measures nothing. They are ordinary operations that any real account produces, not
rule-shaped constructions. **AWS-002 is deliberately never exercised**: stopping the trail
would delete the corpus. Its expected count is zero and that is a prediction, not an
omission.

## 3. Collection protocol

**Isolation.** A brand-new AWS account created for this purpose, in its own Organization
or standalone, with no other workload, no shared credentials, and nothing of the
operator's real identity in it. Deleted after the corpus is archived.

```bash
aws cloudtrail create-trail --name ath-m20-baseline \
  --s3-bucket-name ath-m20-trail-<accountid> \
  --is-multi-region-trail --include-global-service-events
aws cloudtrail put-event-selectors --trail-name ath-m20-baseline \
  --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":true,
                       "DataResources":[]}]'
aws cloudtrail start-logging --name ath-m20-baseline
```

Management events only, read **and** write, all regions, global service events included,
delivered to S3. No data events: object-level S3 logging would swamp the corpus with
volume ATH's control-plane rules do not read, and `data/external/MANIFEST.json` records
flaws.cloud as "AWS CloudTrail management events" -- the same shape keeps the two
comparable.

**Schedule -- 14 calendar days.** Written before collection begins.

| day | what runs |
| --- | --------- |
| 1 | account + trail setup (Root, once); W01, W03, W11 begin and run daily from here |
| 2 | W04 session 1 (onboard a user), W06 session 1, W09 |
| 3 | W07 sessions 1-2, W02, W09 |
| 4 | W08 run 1, W06 session 2, W09 |
| 5 | W05 session 1, W07 session 3, W09 |
| 6 | **W13 lockout episode**, W02, W09 |
| 7 | quiet day: W01, W11, W09 only -- the weekend baseline |
| 8 | **W12 policy iteration**, W04 session 2, W09 |
| 9 | W08 run 2, W10 begins and runs daily from here, W09 |
| 10 | W06 session 3, W07 session 4, W09, W10 |
| 11 | W05 session 2, W08 run 3, W09, W10 |
| 12 | W04 session 3 (offboard a user -- AWS-005), W09, W10 |
| 13 | quiet day: W01, W11, W09, W10 |
| 14 | W08 run 4 + full teardown, W06 terminate, W07 delete bucket, W09, W10 |

**Session labelling, written BEFORE execution.** A `sessions.csv` committed to the repo
before day 1 with one row per planned session:
`session_id, workflow_id, actor_arn, actor_type, planned_start_utc, planned_end_utc, day`.
After each session, an `actual_start_utc`, `actual_end_utc` and a free-text `notes` column
is filled in -- appended, never overwriting the plan. A session that did not happen is
marked `skipped` and kept.

**Provenance recorded:** account id (redacted to last 4), region list, trail ARN, the
`sessions.csv` with both planned and actual times, the exact scripts/Terraform used, the
IAM policies attached to each role at each point in time, sha256 of every delivered
CloudTrail `.json.gz`, and the operator's own attestation that no adversarial action was
taken.

**Cost.** Trail #1 management events are free; S3 storage for 14 days of a low-volume
account is well under 1 GB (~USD 0.03/month). Two t3.micro instances run intermittently
and a small Lambda stay inside or near free tier. Estimate **USD 5-15 total**, dominated
by EC2 hours and NAT-free VPC usage if the IaC stack is kept minimal.

**Human time.** ~4 h setup (account, trail, roles, scripts, `sessions.csv`), then
~20-30 min/day of hands-on operation over 14 days, plus ~4 h to archive and manifest.
Roughly **12-15 hours**.

## 4. Sealing

**Split rule, chosen now, by calendar:** days 1-9 are the **development split**;
days 10-14 are the **sealed holdout**. The boundary is a wall-clock date fixed before
collection starts, not a property of the data, so it cannot be moved once the findings
are inconvenient. Days 10-14 deliberately contain the offboarding (W12 on day 12) and the
final teardown, so the holdout is not merely "more of the same".

The holdout is written to a separate prefix on delivery and moved, unopened, to
`data/external/m20_benign_cloud/holdout/` with its own sha256 list. **No ATH code is run
against the holdout** -- not the adapter, not a probe, not a row count beyond the file
sizes and hashes -- until section 5's prediction is committed.

## 5. Pre-registration template

Committed to `reports/m20/PREREGISTERED.md` **before** the holdout is opened. Every number
is derived from the development split and stated as a rate, so the holdout's different
length does not excuse a miss.

```
Development-split observation (days 1-9, N events = ____):
  findings/day by rule:  ATH-005 __  AWS-001 __  AWS-002 __
                         AWS-003 __  AWS-004 __  AWS-005 __  AWS-006 __

Predictions for the sealed holdout (days 10-14):
  1. findings/day per rule, +/- band: as above, +/- 50%
  2. triage benign disposition fraction: >= __ % of findings are dispositioned
     benign by ATH's triage
  3. CRITICAL findings: exactly 0. Named exception: none -- AWS-002 is never
     exercised (section 2), so any CRITICAL is a defect.
  4. HIGH findings: exactly 0, with two named exceptions --
     AWS-004 at HIGH from W10 (>=5 resource types denied), expected __ /day;
     ATH-005 at HIGH only if a further lockout occurs, expected 0.
  5. persistent high-severity noise: no single rule contributes > __ % of all
     findings across the holdout.
```

**Decision rule for "operationally acceptable"**, fixed before opening:

* every per-rule rate falls inside its predicted band, **and**
* zero CRITICAL, and HIGH only from the two named exceptions, **and**
* the benign disposition fraction meets or exceeds the predicted floor, **and**
* total findings across days 10-14 are fewer than **one per analyst-hour** at the
  8 h/day staffing the corpus assumes -- i.e. < 40 findings over 5 days.

A miss on any clause is recorded as a miss. The predictions are not adjusted afterwards.

## 6. What this corpus cannot establish

* **No attack recall.** Nothing adversarial is in it, so it says nothing about whether
  ATH detects anything. Precision-shaped evidence only, and only on the seven rules above.
* **One account's habits.** Fourteen days of one small, freshly built account. Its service
  mix, its IAM shape and its automation cadence are not a population.
* **Synthetic actors.** Four named identities operated by one person imitating a team.
  Cadence, mistake rate and the diurnal pattern are all performed, not observed.
* **No scale.** Per-rule rates measured at ~10^3-10^4 events/day do not extrapolate to an
  enterprise account at 10^7.
* **The rules never exercised** (AWS-002) get a zero that is a property of the plan, not a
  measurement.

## 7. Manifest entry

`data/external/MANIFEST.json` is `{_about, datasets, _attack_generation}`; each dataset
carries `name, publisher, url, source_page, license, provenance, telemetry, files[]
{path, bytes, sha256}, fetched_on, fetch_command, subset_kept, labels`, plus dated probe
and evaluation keys added as work proceeds. Proposed entry:

```json
"m20_benign_cloud": {
  "name": "ATH M20 benign cloud baseline (disposable AWS account, 14 days)",
  "publisher": "this project (own data)",
  "url": null,
  "source_page": "docs/m20-benign-cloud-validation-plan.md",
  "license": "Own data. Generated by this project in a disposable account created
              for the purpose. Redistributable once account identifiers are redacted.",
  "provenance": "real -- real AWS CloudTrail from real API calls; benign by
                 construction, every session predeclared in sessions.csv before it ran",
  "telemetry": "AWS CloudTrail management events (read+write, all regions, global
                service events), {Records:[...]} JSON, gzipped, S3 delivery layout",
  "files": [
    {"path": "m20_benign_cloud/dev/...", "bytes": 0, "sha256": ""},
    {"path": "m20_benign_cloud/holdout/...", "bytes": 0, "sha256": ""},
    {"path": "m20_benign_cloud/sessions.csv", "bytes": 0, "sha256": ""}
  ],
  "fetched_on": "TBD",
  "fetch_command": "aws s3 sync s3://ath-m20-trail-<acct>/AWSLogs/ data/external/m20_benign_cloud/",
  "subset_kept": "whole trail; split by calendar date -- days 1-9 dev, days 10-14 sealed",
  "labels": "every event is benign by construction; sessions.csv gives actor,
             workflow id and start/end for each session, written before execution"
}
```

The `license` and `provenance` values differ in kind from every existing entry: the four
current datasets are all `"license": "UNVERIFIED ..."` third-party fetches. This is the
first entry the project owns, and the first whose benignity is asserted by the collector
rather than inferred.

## 8. Corrections found while building the tooling (2026-09-13)

Building `scripts/m20/` against sections 2-5 surfaced these; the tooling encodes the
resolution stated here, and the earlier sections are left as written so the change is
visible.

1. **W12's day.** Section 4 says "the offboarding (W12 on day 12)"; section 2 has W12 as
   policy iteration on day 8 and the day-12 row as W04 session 3 (offboard). Sections 2
   and 3 govern.
2. **Day-14 teardown must not stop the trail.** `stop-logging` *is* AWS-002 and would put
   one CRITICAL into the holdout, falsifying prediction 3 by the plan's own hand. The
   runbook (`docs/m20-aws-setup.md`) tears down by deleting resources and then the
   account; the trail is never stopped, and `scripts/m20/workflows/_common.sh` refuses
   `stop-logging`, `delete-trail`, `update-trail`, `put-event-selectors`.
3. **W01, W02, W13 are operator-assisted.** `ConsoleLogin` is produced by a browser
   sign-in, not by any CLI call; the scripts pace the episode and do the bookkeeping.
4. **Session coverage is checked on logon and control rows.** The four authentication
   event names land in the logon table, so W01/W02/W03/W13 produce no control rows;
   `validate_dev.py` reports which table covered each session.
5. **Quiet days** (7, 13) run W01, W11, W09 (and W10 from day 9) literally; W03's "daily
   from day 1" is read as excluding them. Either reading is defensible; this is the one
   encoded.
6. **W02 is two sessions** (days 3 and 6), the table's count, not "~3".
7. **Day-1 Root setup is session `SETUP`**, so day-1 Root activity is explained.
8. **Account id cannot be redacted from delivered file names** (CloudTrail keys carry it);
   the provenance entry records that fact instead of pretending otherwise.
9. **Key-timestamp splitting has a bounded edge**: a delivery straddling midnight is
   assigned by delivery window. Accepted under the sealing invariant; no session is
   scheduled within an hour of the day-10 boundary.
