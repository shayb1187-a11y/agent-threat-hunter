# M20 operator guide: building, running and sealing the benign cloud corpus

This is the runbook for `docs/m20-benign-cloud-validation-plan.md`. The plan is the
specification and does not change; this document says how to execute it, and where a step
exists only to protect a claim the plan makes, it says which claim.

Nothing here has been run: no AWS account existed when it was written. Every command is
written to be read before it is typed.

**Two rules that outrank convenience**

1. **The trail is never stopped, deleted or narrowed.** The plan predicts zero AWS-002
   findings *because the action is never taken* (section 2). `scripts/m20/workflows/_common.sh`
   refuses `stop-logging`, `delete-trail`, `update-trail` and `put-event-selectors`
   outright, so the only way to break this is to run `aws` by hand. Do not.
2. **Days 10-14 are not looked at.** Not a row count, not `zcat | head`, not "just
   checking the files arrived" with anything that decompresses them. `scripts/m20/split.py`
   records size and sha256 and nothing else; that is the complete list of facts you are
   allowed to know about the holdout before `reports/m20/PREREGISTERED.md` is committed.

---

## 0. Before day 1

```bash
# The schedule, written before anything runs (INV-2). Do this first; it is dated.
python scripts/m20/sessions.py plan --start-date 2026-10-01 --account-id 012345678901
git add reports/m20/sessions.csv && git commit -m "M20: predeclared session schedule"
```

`sessions.py plan` refuses to overwrite an existing `sessions.csv`. That refusal is the
predeclaration: after day 1 the file is only ever appended to, via
`python scripts/m20/sessions.py record`.

The command prints 110 planned sessions. Read them. If a planned window does not suit
your calendar, change it **now** and regenerate — not on day 6.

---

## 1. Account creation

A brand-new account, nothing else in it, deleted when the corpus is archived
(plan section 3, "Isolation").

1. Create a standalone account with an email alias you control
   (`you+ath-m20@example.com`) and a fresh, unique root password in your password
   manager.
2. **Enable MFA on the root user immediately.** Root is used once, on day 1, for setup
   (plan section 2, identity types) and never again.
3. Set the account alias so console sign-in URLs are stable:
   ```bash
   aws iam create-account-alias --account-alias ath-m20
   ```
4. Note the 12-digit account id. Everything below writes it as `<accountid>`; only the
   last four digits are ever recorded (`scripts/m20/provenance.py` refuses to emit a
   record that contains the full id).
5. Create the operator profile you will use for everything else:
   ```bash
   aws configure --profile ath-m20   # an IAM admin user, not root
   ```

Region choice: pick one home region (`us-east-1` in the examples) and stay in it. The
trail is multi-region, so a stray call in another region is still recorded — it is just
harder to explain in `sessions.csv`.

---

## 2. The trail

Quoted from the plan, section 3, unchanged except the bucket name:

```bash
aws cloudtrail create-trail --name ath-m20-baseline \
  --s3-bucket-name ath-m20-trail-<accountid> \
  --is-multi-region-trail --include-global-service-events
aws cloudtrail put-event-selectors --trail-name ath-m20-baseline \
  --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":true,
                       "DataResources":[]}]'
aws cloudtrail start-logging --name ath-m20-baseline
```

The bucket must exist first and must allow CloudTrail to write to it:

```bash
aws s3api create-bucket --bucket ath-m20-trail-<accountid> --region us-east-1
aws s3api put-public-access-block --bucket ath-m20-trail-<accountid> \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
aws s3api put-bucket-policy --bucket ath-m20-trail-<accountid> --policy file://trail-bucket-policy.json
```

`trail-bucket-policy.json` — the standard CloudTrail delivery policy, with the two
condition keys that stop another account writing into your corpus:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::ath-m20-trail-<accountid>",
      "Condition": {"StringEquals": {"aws:SourceArn": "arn:aws:cloudtrail:us-east-1:<accountid>:trail/ath-m20-baseline"}}
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::ath-m20-trail-<accountid>/AWSLogs/<accountid>/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control",
          "aws:SourceArn": "arn:aws:cloudtrail:us-east-1:<accountid>:trail/ath-m20-baseline"
        }
      }
    }
  ]
}
```

Verify before doing anything else — an hour of collection with logging off is an hour
that silently is not in the corpus:

```bash
aws cloudtrail get-trail-status --name ath-m20-baseline    # IsLogging: true
aws cloudtrail describe-trails --trail-name-list ath-m20-baseline
```

Record the trail ARN; `provenance.py --trail-arn` needs it.

**Delivery latency.** CloudTrail delivers management events within about 15 minutes and
names each file for its delivery window, not for the events inside it. The split
(`split.py`) reads that name. So a session that runs at 23:55 UTC on day 9 may be
delivered in a day-10 file and end up sealed. Avoid scheduling sessions within 30 minutes
of the day-9/day-10 boundary; the schedule generated in step 0 already does.

---

## 3. Identities

Four named identities plus five roles, one per job. Each role's policy is the *smallest*
one that lets its workflows run — which is also what makes W10's denials real rather than
manufactured.

### Users

```bash
aws iam create-user --user-name alice    # W01, W03
aws iam create-user --user-name bob      # W01, W12
aws iam create-user --user-name carol    # W02, W13
aws iam create-login-profile --user-name alice --password-reset-required
# ... same for bob and carol
```

* **alice** and **bob** get MFA devices attached (W01 is "console login *with* MFA").
* **carol** deliberately does not (W02 is "console login *without* MFA"). This is a
  declared property of the corpus, not an oversight; it is in the plan's catalogue.

Each user needs only the ability to assume the roles they use:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AssumeTheirOwnRoles",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": [
        "arn:aws:iam::<accountid>:role/DeveloperRole",
        "arn:aws:iam::<accountid>:role/DeployRole"
      ]
    },
    {
      "Sid": "SeeTheirOwnIdentity",
      "Effect": "Allow",
      "Action": ["iam:GetUser", "iam:ListMFADevices", "sts:GetCallerIdentity"],
      "Resource": "*"
    }
  ]
}
```

bob additionally needs the one call W12 makes, and nothing else:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "W12TrustPolicyIteration",
      "Effect": "Allow",
      "Action": ["iam:UpdateAssumeRolePolicy", "iam:GetRole"],
      "Resource": "arn:aws:iam::<accountid>:role/ReportingRole"
    }
  ]
}
```

### Roles

Every role's trust policy is the same shape — only the account's own users may assume it:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::<accountid>:root"},
      "Action": "sts:AssumeRole"
    }
  ]
}
```

```bash
for role in AdminRole DeveloperRole DeployRole AuditRole ReportingRole; do
  aws iam create-role --role-name "$role" --assume-role-policy-document file://trust.json
done
```

**AdminRole** (W04, W05). IAM administration, scoped to the objects these workflows
touch:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "W04IdentityLifecycle",
      "Effect": "Allow",
      "Action": [
        "iam:CreateUser", "iam:DeleteUser", "iam:GetUser", "iam:ListUsers",
        "iam:CreateGroup", "iam:DeleteGroup", "iam:AddUserToGroup", "iam:RemoveUserFromGroup",
        "iam:AttachUserPolicy", "iam:DetachUserPolicy", "iam:ListAttachedUserPolicies",
        "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
        "iam:CreateAccessKey", "iam:DeleteAccessKey", "iam:UpdateAccessKey", "iam:ListAccessKeys"
      ],
      "Resource": [
        "arn:aws:iam::<accountid>:user/*",
        "arn:aws:iam::<accountid>:group/ath-m20-*"
      ]
    },
    {
      "Sid": "W05PolicyChurn",
      "Effect": "Allow",
      "Action": ["iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:GetRolePolicy",
                 "iam:ListRolePolicies", "iam:GetRole"],
      "Resource": "arn:aws:iam::<accountid>:role/ReportingRole"
    }
  ]
}
```

**DeveloperRole** (W06, W07). EC2 lifecycle and bucket-level S3:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "W06Ec2",
      "Effect": "Allow",
      "Action": ["ec2:RunInstances", "ec2:StartInstances", "ec2:StopInstances",
                 "ec2:TerminateInstances", "ec2:CreateTags", "ec2:Describe*"],
      "Resource": "*"
    },
    {
      "Sid": "W07S3",
      "Effect": "Allow",
      "Action": ["s3:CreateBucket", "s3:DeleteBucket", "s3:ListBucket", "s3:ListAllMyBuckets",
                 "s3:GetBucketLocation", "s3:PutBucketTagging", "s3:GetBucketTagging",
                 "s3:PutLifecycleConfiguration", "s3:GetLifecycleConfiguration",
                 "s3:PutBucketPublicAccessBlock",
                 "s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
      "Resource": ["arn:aws:s3:::ath-m20-work-*", "arn:aws:s3:::ath-m20-work-*/*"]
    },
    {
      "Sid": "NeverTheTrailBucket",
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::ath-m20-trail-*", "arn:aws:s3:::ath-m20-trail-*/*"]
    }
  ]
}
```

That explicit `Deny` is the second line of defence behind `_common.sh`'s refusal: the
corpus lives in that bucket.

**DeployRole** (W08). CloudFormation plus the resources the stack creates:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "W08CloudFormation",
      "Effect": "Allow",
      "Action": ["cloudformation:CreateStack", "cloudformation:DeleteStack",
                 "cloudformation:DescribeStack*", "cloudformation:ListStacks",
                 "cloudformation:ValidateTemplate", "cloudformation:GetTemplate"],
      "Resource": "*"
    },
    {
      "Sid": "W08StackResources",
      "Effect": "Allow",
      "Action": ["ec2:*Vpc*", "ec2:*Subnet*", "ec2:*SecurityGroup*", "ec2:*RouteTable*",
                 "ec2:*Tags", "ec2:RunInstances", "ec2:TerminateInstances", "ec2:Describe*",
                 "iam:CreateRole", "iam:DeleteRole", "iam:GetRole", "iam:ListRoles",
                 "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:GetRolePolicy",
                 "iam:CreateInstanceProfile", "iam:DeleteInstanceProfile",
                 "iam:AddRoleToInstanceProfile", "iam:RemoveRoleFromInstanceProfile",
                 "iam:PassRole", "ssm:GetParameters"],
      "Resource": "*"
    }
  ]
}
```

**AuditRole** (W09). Read-only, and deliberately *not* complete — the plan says AWS-004
may fire "if the role lacks some reads", so `ReadOnlyAccess` is not used:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "W09Inventory",
      "Effect": "Allow",
      "Action": ["ec2:Describe*", "s3:ListAllMyBuckets", "iam:List*", "iam:GetAccountSummary",
                 "cloudtrail:DescribeTrails", "cloudtrail:ListTrails",
                 "cloudwatch:Describe*", "cloudwatch:List*", "logs:Describe*",
                 "lambda:List*", "ssm:Describe*", "cloudformation:Describe*",
                 "cloudformation:List*", "kms:List*", "sns:List*", "sqs:List*",
                 "sts:GetCallerIdentity"],
      "Resource": "*"
    }
  ]
}
```

The scan's remaining calls (`rds`, `dynamodb`, `route53`, `config`, `events`, `budgets`,
`autoscaling`, `elbv2`, `iam:GetAccountPasswordPolicy`) are therefore refused. That is
the declared condition, not a misconfiguration.

**ReportingRole** (W10). The narrowed policy, which is the whole workflow:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TheJobItStillHas",
      "Effect": "Allow",
      "Action": ["ce:GetCostAndUsage", "cloudwatch:GetMetricStatistics",
                 "sts:GetCallerIdentity"],
      "Resource": "*"
    }
  ]
}
```

Everything W10 tries beyond those three is denied by default — 14 distinct resource
types, retried twice a day, which is what the plan predicts will take AWS-004 to HIGH.

### Snapshot every policy, every time it changes

Section 3 requires "the IAM policies attached to each role at each point in time".

```bash
mkdir -p reports/m20/iam_snapshots
stamp=$(date -u +%Y%m%dT%H%M%SZ)
for role in AdminRole DeveloperRole DeployRole AuditRole ReportingRole; do
  aws iam list-role-policies --role-name "$role" \
    > "reports/m20/iam_snapshots/${stamp}_${role}_inline_list.json"
  for p in $(aws iam list-role-policies --role-name "$role" --query 'PolicyNames[]' --output text); do
    aws iam get-role-policy --role-name "$role" --policy-name "$p" \
      > "reports/m20/iam_snapshots/${stamp}_${role}_${p}.json"
  done
  aws iam list-attached-role-policies --role-name "$role" \
    > "reports/m20/iam_snapshots/${stamp}_${role}_attached.json"
done
```

Run it on day 1, again after every W05 session (days 5 and 11), and again on day 14.
`provenance.py --iam-policies-dir` hashes the directory.

---

## 4. Service automation (W11)

The hourly half of W11 must run without an operator, or it is not a background rate.

```bash
# A function that does nothing but log, so the trail records the service principal.
cat > heartbeat.py <<'EOF'
def handler(event, context):
    return {"ok": True}
EOF
zip heartbeat.zip heartbeat.py
aws iam create-role --role-name ath-m20-lambda --assume-role-policy-document file://lambda-trust.json
aws iam attach-role-policy --role-name ath-m20-lambda \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
aws lambda create-function --function-name ath-m20-heartbeat \
  --runtime python3.12 --handler heartbeat.handler --zip-file fileb://heartbeat.zip \
  --role arn:aws:iam::<accountid>:role/ath-m20-lambda

aws events put-rule --name ath-m20-hourly --schedule-expression "rate(1 hour)"
aws events put-targets --rule ath-m20-hourly \
  --targets "Id=1,Arn=arn:aws:lambda:us-east-1:<accountid>:function:ath-m20-heartbeat"
aws lambda add-permission --function-name ath-m20-heartbeat --statement-id events \
  --action lambda:InvokeFunction --principal events.amazonaws.com \
  --source-arn arn:aws:events:us-east-1:<accountid>:rule/ath-m20-hourly
```

Also enable SSM on the W06 instances (the `ath-m20-w08-instance` role in the W08 template
shows the four `ssmmessages` actions needed) so the daily `RunCommand` has a target.

---

## 5. Cost guard

The plan estimates USD 5-15. A budget alarm is what makes that estimate falsifiable
before the bill arrives.

```bash
cat > budget.json <<'EOF'
{
  "BudgetName": "ath-m20-total",
  "BudgetLimit": {"Amount": "25", "Unit": "USD"},
  "TimeUnit": "MONTHLY",
  "BudgetType": "COST"
}
EOF
cat > notifications.json <<'EOF'
[
  {
    "Notification": {
      "NotificationType": "ACTUAL", "ComparisonOperator": "GREATER_THAN",
      "Threshold": 40, "ThresholdType": "PERCENTAGE"
    },
    "Subscribers": [{"SubscriptionType": "EMAIL", "Address": "you@example.com"}]
  },
  {
    "Notification": {
      "NotificationType": "FORECASTED", "ComparisonOperator": "GREATER_THAN",
      "Threshold": 100, "ThresholdType": "PERCENTAGE"
    },
    "Subscribers": [{"SubscriptionType": "EMAIL", "Address": "you@example.com"}]
  }
]
EOF
aws budgets create-budget --account-id <accountid> \
  --budget file://budget.json --notifications-with-subscribers file://notifications.json
```

Two thresholds on purpose: 40% of USD 25 is USD 10, the top of the plan's estimate, so
the first mail means "the estimate was wrong" rather than "you are about to overspend".

If an alarm fires: the likely causes are EC2 instances left running (W06's `cycle` mode
stops them; `terminate` is day 14) and anything with a NAT gateway, which the W08 stack
deliberately does not create.

---

## 6. The daily checklist

Twenty to thirty minutes a day (plan section 3, "Human time"). Each step exists because
something it protects is otherwise only noticed at the end.

1. **Trail still logging.**
   ```bash
   aws cloudtrail get-trail-status --name ath-m20-baseline --query 'IsLogging'
   ```
   `false` is an emergency: everything since the last `true` is missing. Start it again,
   record the gap in the notes of every session that overlapped it.
2. **Yesterday delivered.**
   ```bash
   aws s3 ls s3://ath-m20-trail-<accountid>/AWSLogs/<accountid>/CloudTrail/us-east-1/ --recursive \
     | tail -5
   ```
   Names only. Do not download day-10-or-later files to look at them.
3. **Run today's sessions**, in the order `sessions.csv` gives, each through its workflow
   script with the session id from the file, e.g.
   ```bash
   scripts/m20/workflows/W04_iam_administration.sh --session-id D02-W04-1 --mode onboard \
     --user dave --role-arn arn:aws:iam::<accountid>:role/AdminRole --profile ath-m20
   ```
   The script records start and end itself.
4. **W01/W02/W13 are done by hand** — a console login comes from a browser, and no CLI
   call produces one. The scripts pace the episode and record the session; you do the
   signing in.
5. **Anything unplanned gets a note.** If you log into the console to look at something,
   that activity is in the trail and belongs to no session. Record it against the nearest
   session with `--notes`, or `validate_dev.py` will report it as unexplained activity —
   which is correct, and is a worse outcome than a note.
6. **`git commit reports/m20/sessions.csv`** at the end of the day. The commit timestamps
   are part of the evidence that the annotations followed the sessions.

### A session that was missed

Do not run it late in silence and do not delete the row. Both destroy the thing
`sessions.csv` is for.

* **Not run at all:**
  ```bash
  python scripts/m20/sessions.py record --session-id D07-W09-1 --status skipped \
    --notes "operator travelling; inventory scan not run"
  ```
  The plan's rule: "A session that did not happen is marked `skipped` and kept."
* **Run, but outside its planned window:** run it, and let the script record the real
  times. The planned and actual columns disagreeing is the record working, not a problem
  to hide. Add a note saying why.
* **Run, but you forgot to use the script:** record the actual times from the console or
  from `aws cloudtrail lookup-events`, and note that the times were reconstructed.
* **Noticed after day 10:** annotate the row anyway. Annotating a row is not reading the
  holdout.

---

## 7. Day 10: sealing

Do this **once**, at the start of day 10, before day 10's sessions run — the split is by
delivery time, so anything delivered from day 10 00:00 UTC onwards is holdout whether it
has been pulled yet or not.

```bash
# 1. Pull everything delivered so far into a staging prefix, without opening anything.
aws s3 sync s3://ath-m20-trail-<accountid>/AWSLogs/ \
  data/external/m20_benign_cloud/delivered/

# 2. See what the split would do, before it moves anything.
python scripts/m20/split.py --source data/external/m20_benign_cloud/delivered \
  --out data/external/m20_benign_cloud --start-date 2026-10-01 --dry-run

# 3. Do it.
python scripts/m20/split.py --source data/external/m20_benign_cloud/delivered \
  --out data/external/m20_benign_cloud --start-date 2026-10-01
```

What this does and does not do:

* assigns each file by the timestamp in its **name** — never by `eventTime` inside it,
  because reading `eventTime` means opening the file;
* moves the files, writes `dev/SHA256SUMS`, `holdout/SHA256SUMS`, `holdout/SIZES` and
  `SPLIT.json`;
* refuses to run twice, refuses a file whose name is not a CloudTrail delivery name, and
  refuses before moving anything if any name is unparseable.

Verify — hashes only:

```bash
cd data/external/m20_benign_cloud/holdout && sha256sum -c SHA256SUMS && cd -
```

Then the same sync-and-split at the end of day 14 for the remaining holdout deliveries,
into a second staging prefix (`split.py` refuses to re-split an output directory, so run
the second one with `--out data/external/m20_benign_cloud/final` and merge the holdout
directories by hand, keeping both `SHA256SUMS` files).

**What you may run against the development split** from day 10 onwards:

```bash
python scripts/m20/validate_dev.py --dev-dir data/external/m20_benign_cloud/dev \
  --sessions reports/m20/sessions.csv
python scripts/m20/measure_dev.py --telemetry-dir data/external/m20_benign_cloud/dev
```

`measure_dev.py` prints section 5's template with the development numbers filled in and
every holdout prediction left as `__`. Fill the blanks, commit it as
`reports/m20/PREREGISTERED.md`, **then** the holdout may be opened — and not before, which
is what `measure_dev.py` enforces: a holdout path is refused unless that file exists with
no blanks left in it.

---

## 8. Day 14: teardown

In this order. The trail goes last, because everything before it is activity that belongs
in the corpus.

```bash
# 1. The last sessions: W08 run 4 + teardown, W06 terminate, W07 delete bucket, W09, W10.
scripts/m20/workflows/W08_iac_stack.sh --session-id D14-W08-1 --mode cycle ...
scripts/m20/workflows/W06_ec2_lifecycle.sh --session-id D14-W06-1 --mode terminate ...
scripts/m20/workflows/W07_s3_operations.sh --session-id D14-W07-1 --mode delete --bucket ath-m20-work-0001 ...

# 2. Final IAM policy snapshot (section 3, "at each point in time").
#    Same loop as section 3 of this document.

# 3. Stop the automation, so day 15 adds nothing.
aws events remove-targets --rule ath-m20-hourly --ids 1
aws events delete-rule --name ath-m20-hourly
aws lambda delete-function --function-name ath-m20-heartbeat

# 4. Wait 30 minutes for the last deliveries, then sync and split the remainder (section 7).

# 5. Only now, the trail.
aws cloudtrail stop-logging --name ath-m20-baseline
```

That `stop-logging` is the single moment AWS-002's action is taken, and it is taken
*after* the corpus is complete and synced. It will appear in the very last delivery. Two
consequences, both of which belong in the report rather than in a quiet edit:

* the holdout may contain one AWS-002 event and therefore one CRITICAL finding, which
  would falsify section 5's prediction 3 on a technicality;
* so either stop logging **after** the final sync and exclude the final file by its name
  (recording the exclusion in `SPLIT.json` and the report), or leave the trail running and
  delete the whole account, which produces no `StopLogging` call at all.

The second is cleaner and is what this runbook recommends: **do not stop the trail; delete
the account.** The plan's "AWS-002 is deliberately never exercised" is then true without
an asterisk.

```bash
# 6. Provenance, then archive.
python scripts/m20/provenance.py \
  --split-dir data/external/m20_benign_cloud \
  --sessions reports/m20/sessions.csv \
  --account-id <accountid> --regions us-east-1 \
  --trail-arn arn:aws:cloudtrail:us-east-1:<accountid>:trail/ath-m20-baseline \
  --iam-policies-dir reports/m20/iam_snapshots \
  --attestation-file reports/m20/ATTESTATION.txt \
  --fetched-on 2026-10-15 --write

# 7. Close the account (Organizations, or the account settings page for a standalone
#    account). The plan: "Deleted after the corpus is archived."
```

`reports/m20/ATTESTATION.txt` is the operator's own words, required by section 3. It
should say who ran the corpus, that every session in `sessions.csv` was ordinary
operation, that nothing adversarial was performed, and name anything unusual that
happened — an outage, a mistyped command, a session run from the wrong identity.
`provenance.py` refuses an empty one.

---

## 9. What the tooling refuses, and where

| refusal | enforced in |
| ------- | ----------- |
| overwrite `sessions.csv` | `scripts/m20/sessions.py` `write_plan` |
| edit a planned column, or an unknown session id | `scripts/m20/sessions.py` `record_session` |
| stop/delete/narrow the trail from a workflow | `scripts/m20/workflows/_common.sh` `ath_refuse_forbidden` |
| split by `eventTime` instead of the object key | `scripts/m20/split.py` `classify` (reads the name only) |
| split twice, or split an unparseable name | `scripts/m20/split.py` `split`, `key_timestamp` |
| validate or probe the holdout | `scripts/m20/common.py` `refuse_holdout` |
| measure the holdout before the prediction is committed | `scripts/m20/common.py` `holdout_gate` |
| emit the full account id in the manifest | `scripts/m20/provenance.py` `refuse_account_id_leak` |
