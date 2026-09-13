# AWS-006 vs. the T1580 label: what the rule detects, what the capture contains, and what ATT&CK says

**Scope.** Research only. No rule, mapping, threshold, test or report was changed by this
investigation. Everything under `reports/` was read, never re-run. The frozen checkout
`agentic-threat-hunter/` was read-only (`data/external/`).

**Question.** M18 §8 row P3 recorded a technique-label MISS: AWS-006 fired on a Splunk
`attack_data` capture labelled T1580 and asserted T1098. The report wrote "Both readings
are defensible and the label says T1580. Recorded, not reconciled." This document asks
whether that is true.

**Verdict (stated here, argued below): `dataset label questionable`.** A second, separate
defect was found on the way: the capture contains **two** distinct CloudTrail events, each
recorded **five times**, and AWS-006's threshold of 5 was met entirely by those duplicates.

---

## 1. What AWS-006 actually detects

### 1.1 The predicate (VERIFIED FROM CODE, `src/ath/hunting/rules/cloud_behaviour_rules.py:617-737`)

```python
rejected = frame[
    frame["_changes_authority"]
    & frame["_identity_service"]
    & (frame["_decision"] == DECISION_FAILED)
]
```

grouped by `actor`, requiring `cloud_identity_failed_min_count` inside
`cloud_identity_change_window`. MEASURED from
`reports/m18/cloud_detection/attack_data_aws.json` -> `thresholds`: those constants were
`5` and `60.0` minutes for this run.

The rule's own docstring states its claim precisely:

> "A caller who *is* authorized to change identity authority, but does not know how to
> write what it is trying to write, produces a run of rejections that are not
> authorization refusals: malformed policy documents, references to principals that do
> not exist, conflicting names. That is the signature of someone searching for a policy
> the platform will accept -- a permission brute force -- and it is a different statement
> from being told "you may not", which is AWS-004's subject."

`fields_used = ("actor", "verb", "resource_type", "resource_name", "decision", "timestamp")`
(VERIFIED FROM CODE). **The rule never reads the event name, the error code, the error
message or the request parameters.** That is load-bearing for §4: the rule is structurally
incapable of distinguishing "malformed policy document" from "principal does not exist",
which is exactly the distinction the T1580 reading would require.

### 1.2 What counts as an authority change (VERIFIED FROM CODE, `src/ath/control_vocab.py:199-242`)

```python
def changes_authority(verb: str, resource_type: str) -> bool:
    if verb_class(verb) not in AUTHORITY_CHANGING_CLASSES:
        return False
    return (
        service_of(resource_type) in IDENTITY_SERVICES
        or resource_type.strip().lower() in RBAC_BINDING_RESOURCES
    )
```

with `IDENTITY_SERVICES = frozenset({"iam"})` and
`AUTHORITY_CHANGING_CLASSES = frozenset({GRANT, REVOKE, CREATE, DELETE, MODIFY})`
(`control_vocab.py:177-184`). READ is the exclusion the class set exists for. AWS-006
conjoins this with the identity-service clause a second time (`_identity_service`), the
M18-9 fix that stopped it citing Kubernetes RBAC rows.

MEASURED (executed against this worktree's own code):

```
verb_class("create")                             -> "create"
service_of("iam:policy")                         -> "iam"
changes_authority("create", "iam:policy")        -> True
parse_event_name("CreatePolicy")                 -> verb="create", family="policy", parsed=True
```

So a `CreatePolicy` call is an authority change by this vocabulary. **No read call can
satisfy the predicate.**

### 1.3 "failed" vs "denied" (VERIFIED FROM CODE, `src/ath/control_vocab.py:350-489`)

```
allowed  the platform performed the action
denied   the platform refused it for authorization or authentication reasons
failed   the platform rejected it for any other reason -- validation, conflict,
         not-found, throttling, capacity, an unsupported parameter
```

`classify_error` tests an authorization-token substring first, then 401/403, then "any
other error code ... is `failed`". The comment block names what is deliberately excluded
from `denied`: "validation (MalformedPolicyDocument, ValidationException,
InvalidParameterValue), absence (NoSuchBucket, NoSuchEntity), conflict (DeleteConflict,
EntityAlreadyExists)... Not one of them is a statement about what the caller may do."

MEASURED: `classify_error("MalformedPolicyDocumentException", None) -> "failed"`.

**VERIFIED FROM CODE -- what AWS-006 keys on, stated without interpretation:** at least 5
rows in 60 minutes from one actor, each a create/delete/modify/grant/revoke on an `iam:*`
resource that the platform rejected for a non-authorization reason. Nothing about *which*
call, *which* error, or *what* the caller was trying to write.

---

## 2. What the capture actually contains

### 2.1 Provenance

The file is
`data/external/attack_data_aws/raw/T1580__aws_iam_assume_role_policy_brute_force__aws_iam_assume_role_policy_brute_force.json`
in the frozen checkout (15,615 bytes, NDJSON, 10 records).

MEASURED: `data/external/MANIFEST.json` has entries only for `flaws_cloud`, `k8s_ci`,
`k8ntext`, `dedale`. **There is no `attack_data_aws` manifest entry, and no README, YAML
or label file ships in `data/external/attack_data_aws/`.** The only ground truth is the
file name, which is what `scripts/m18_cloud_detection.py` says in its own docstring:

> "The five attack_data_aws captures are one ATT&CK technique each, and the technique is
> in the file name -- which is the only cloud ground truth this project has ever had."

VERIFIED FROM SOURCE (WebFetch, `github.com/splunk/attack_data`): the upstream path is
`datasets/attack_techniques/T1580/aws_iam_assume_role_policy_brute_force/`. So **the label
"T1580" is a directory name in the Splunk `attack_data` repository**, and §3.4 shows where
that directory name comes from.

### 2.2 Every row, in full (MEASURED)

10 records. Sorted by actor and time:

| # | eventTime | actor | eventName | eventSource | errorCode | errorMessage |
|---|-----------|-------|-----------|-------------|-----------|--------------|
| 1-5 | 2021-02-24T21:07:35Z | `bhavin_cli` | `CreatePolicy` | `iam.amazonaws.com` | `MalformedPolicyDocumentException` | "Statement IDs (SID) must be alpha-numeric. Check that your input satisfies the regular expression [0-9A-Za-z]*" |
| 6-10 | 2021-03-13T02:49:24Z | `mhart_cli` | `CreatePolicy` | `iam.amazonaws.com` | `MalformedPolicyDocumentException` | "Resource 174313347505.dkr.ecr.us-west-2.amazonaws.com/mhart-experimental must be in ARN format or \"\*\"." |

MEASURED, and this is the central fact:

```
eventIDs:   {'2db16856-f94d-4e5f-aebf-b46bb9342ebc': 5,
             '2bcfb87f-f450-49ce-815b-817f34503ea7': 5}
requestIDs: {'ebac341d-8d32-430c-9a56-bd25ea2a6335': 5,
             '16184c0a-6b18-47f8-a80a-57701913ffde': 5}
distinct full rows (sha256 of the canonicalised record): 2
```

**The capture is two CloudTrail records, each duplicated five times.** Not five attempts
per actor -- one attempt per actor, written to the file five times.

Corroborated independently by the frozen report
(`reports/m18/cloud_detection/attack_data_aws.json`, MEASURED): both AWS-006 findings have
`window_start == window_end` (`2021-02-24 21:07:35+00:00` and `2021-03-13 02:49:24+00:00`)
and `rejected_count: 5`. Five events in a zero-second window is the duplication, visible in
the frozen artefact all along.

MEASURED -- the duplication is specific to this capture, not a corpus-wide property:

| capture | rows | distinct eventIDs | max duplication |
|---|---|---|---|
| `T1580__..._assume_role_policy_brute_force` | 10 | **2** | **5x** |
| `T1098__aws_iam_delete_policy` | 116 | 110 | 3x |
| `T1526__aws_security_scanner` | 1,071 | 1,071 | 1x |
| `T1580__aws_iam_accessdenied_discovery_events` | 1,150 | 1,150 | 1x |
| `T1078.004__aws_login_sfa` | 2 | 1 | 2x |

VERIFIED FROM CODE: `src/ath/telemetry/cloudtrail_source.py` carries `eventID` into
`source_ref` (`f"eventID={event_id};File={file_name}"`, lines 732 and 866) but **never
deduplicates on it**, so five copies of one record become five canonical rows.

MEASURED, for contrast: the *other* AWS-006 findings in this corpus (capture P4,
`T1098__aws_iam_delete_policy`) are built from 38 rows with 38 distinct eventIDs --
`DeletePolicy` x `NoSuchEntityException` 29, `DeleteConflictException` 6, `AccessDenied` 3,
spread over real minutes. Those findings are not affected by this defect.

### 2.3 What the two callers were actually doing (MEASURED, from request parameters)

**`bhavin_cli`** -- userAgent `aws-cli/2.0.62 ... command/iam.create-policy`, source IP
`71.23.14.129`, `policyName: "Atomic_Red_Team"`, policy document:

```json
{"Version": "2012-10-17",
 "Statement": [{"Sid": "Atomic_Red_Team",
                "Effect": "Allow",
                "Action": "iam:CreatePolicyVersion",
                "Resource": "arn:aws:iam::*:policy/*"}]}
```

The call was rejected because the SID contains underscores. The *intent* is unambiguous
from the document itself: create a policy granting `iam:CreatePolicyVersion` on every
policy in the account -- the canonical AWS privilege-escalation primitive. The policy name
identifies the tooling as an Atomic Red Team test.

**`mhart_cli`** -- userAgent
`aws-sdk-go/1.37.24 ... HashiCorp/1.0 Terraform/0.14.6 ... terraform-provider-aws/dev`,
source IP `14.120.112.134`, `policyName: "dc_builder_policy"`, description "Policy to
attach to ML tuning instances", document granting `s3:ListBucket` + `s3:*Object` on
`mhart-smle` and `ecr:*` on an ECR **registry URI** rather than an ARN -- which is
precisely why AWS rejected it.

MEASURED absences, all of them material:

* **Zero `AssumeRole` events.** Zero `UpdateAssumeRolePolicy` events. Zero `sts.*` events.
* **Zero `Describe*`, `List*`, `Get*` or any other read call.** Every row is `CreatePolicy`.
* **Zero distinct targets.** Each actor submitted one policy name, once.
* **Zero authorization errors.** Both errors are document-validation errors about the
  caller's own syntax.

---

## 3. What ATT&CK says

### 3.1 T1580 Cloud Infrastructure Discovery (VERIFIED FROM ATT&CK, https://attack.mitre.org/techniques/T1580/)

> "An adversary may attempt to discover infrastructure and resources that are available
> within an infrastructure-as-a-service (IaaS) environment. This includes compute service
> resources such as instances, virtual machines, and snapshots as well as resources of
> other services including the storage and database services."

> "Cloud providers offer methods such as APIs and commands issued through CLIs to serve
> information about infrastructure. For example, AWS provides a `DescribeInstances` API
> within the Amazon EC2 API that can return information about one or more instances within
> an account, the `ListBuckets` API that returns a list of all buckets owned by the
> authenticated sender of the request, the `HeadBucket` API to determine a bucket's
> existence along with access permissions of the request sender, or the
> `GetPublicAccessBlock` API to retrieve access block configuration for a bucket."

> "An adversary may enumerate resources using a compromised user's access keys to determine
> which are available to that user."

Tactic: Discovery (TA0007). Every API named is a read.

### 3.2 T1098 Account Manipulation (VERIFIED FROM ATT&CK, https://attack.mitre.org/techniques/T1098/)

> "Adversaries may manipulate accounts to maintain and/or elevate access to victim systems.
> Account manipulation may consist of any action that preserves or modifies adversary
> access to a compromised account, such as modifying credentials or permission groups."

> "In order to create or manipulate accounts, the adversary must already have sufficient
> permissions on systems or the domain."

> "account manipulation may also lead to privilege escalation where modifications grant
> access to additional roles, permissions, or higher-privileged Valid Accounts."

Tactics: Persistence, Privilege Escalation.

### 3.3 The adjacent techniques, checked rather than assumed

* **T1098.003 Additional Cloud Roles** (VERIFIED FROM ATT&CK,
  https://attack.mitre.org/techniques/T1098/003/):
  > "An adversary may add additional roles or permissions to an adversary-controlled cloud
  > account to maintain persistent access to a tenant."

  and, quoted verbatim from that page:
  > "For example, in AWS environments, an adversary with appropriate permissions may be
  > able to use the `CreatePolicyVersion` API to define a new version of an IAM policy or
  > the `AttachUserPolicy` API to attach an IAM policy with additional or distinct
  > permissions to a compromised user account."

  This is the technique `bhavin_cli`'s policy document was *building toward* -- it grants
  exactly `iam:CreatePolicyVersion`. Tactics: Persistence, Privilege Escalation.

* **T1098.001 Additional Cloud Credentials** (VERIFIED FROM ATT&CK): names `CreateKeyPair`,
  `ImportKeyPair`, `CreateAccessKey`, `CreateLoginProfile`, `sts:GetFederationToken`. Does
  not name policy creation. Not applicable.

* **T1110 Brute Force** (VERIFIED FROM ATT&CK, https://attack.mitre.org/techniques/T1110/):
  > "Adversaries may use brute force techniques to gain access to accounts when passwords
  > are unknown or when password hashes are obtained."

  Tactic: Credential Access. Sub-techniques: Password Guessing, Password Cracking, Password
  Spraying, Credential Stuffing. All four are about secrets. Not applicable to a rejected
  policy document.

* **T1087.004 Cloud Account discovery** (VERIFIED FROM ATT&CK,
  https://attack.mitre.org/techniques/T1087/004/):
  > "Adversaries may attempt to get a listing of cloud accounts."

  Tactic: Discovery. Names `aws iam list-roles`. It is about *listing*; no row in this
  capture lists anything. Not applicable to this capture, but see §6.2.

### 3.4 Where the label came from (VERIFIED FROM SOURCE, research.splunk.com + splunk/security_content)

The Splunk detection the dataset was built for is
`detections/cloud/aws_iam_assume_role_policy_brute_force.yml`
(https://research.splunk.com/cloud/f19e09b0-9308-11eb-b7ec-acde48001122/). Its SPL:

```
`cloudtrail` (errorCode=MalformedPolicyDocumentException) status=failure (userAgent!=*.amazonaws.com)
| rename user_name as user
| stats count min(_time) as firstTime max(_time) as lastTime values(requestParameters.policyName) as policy_name BY src, user, vendor_account vendor_region, vendor_product, signature, dest, errorCode
| where count >= 2
```

Its description: *"The following analytic detects multiple failed attempts to assume an AWS
IAM role, indicating a potential brute force attack."* Its ATT&CK annotation: **T1110 and
T1580**. Its known false positives: *"This detection will require tuning to provide high
fidelity detection capabilties. Tune based on src addresses (corporate offices, VPN
terminations) or by groups of users."*

Two observations follow, and they are the crux of this document.

**(a) AWS-006 and the Splunk detection observe the same signal.** Both count
non-authorization rejections of IAM writes per principal over a window; Splunk's threshold
is 2, ATH's is 5. Splunk's SPL does not filter on event name either. They are the same
detector with different constants.

**(b) The Splunk detection's *narrative* does not match the events its own dataset ships.**
The detection is named for, and describes, assume-role-policy brute force -- repeatedly
rewriting a role's trust policy with different principal ARNs, where AWS's rejection of a
non-existent principal is the enumeration oracle. That behaviour would appear as
`UpdateAssumeRolePolicy` with an invalid-principal message. The dataset contains
`CreatePolicy` with a SID-syntax complaint and an ARN-format complaint. The technique
annotation T1580 was attached to the *detection*; the directory
`datasets/attack_techniques/T1580/` inherited it; the capture inherited the directory; and
`scripts/m18_cloud_detection.py` read it off the file name. At no point did anyone assert
that these two records are cloud infrastructure discovery.

---

## 4. Reasoning

### 4.1 Which technique describes the behaviour the *rule* keys on

The rule keys on: one principal, 5 or more create/delete/modify writes to `iam:*` in 60
minutes, each rejected for a non-authorization reason.

* Against **T1580**: T1580 is defined by *discovering infrastructure and resources*, and
  every API it names (`DescribeInstances`, `ListBuckets`, `HeadBucket`,
  `GetPublicAccessBlock`) is a read. VERIFIED FROM CODE, `changes_authority` returns False
  for every read verb -- `verb_class(verb) not in AUTHORITY_CHANGING_CLASSES -> return
  False`. **The rule cannot, by construction, cite a single row of the kind T1580 is
  defined by.** The T1580 reading requires an extra inference -- "these writes were being
  used as an oracle" -- which the rule neither observes nor can observe, because it does
  not read the error message that would carry the oracle's answer (§1.1).
* For **T1098**: the rows *are* attempts to modify permission groups and credentials on an
  account, which is the subject of T1098's first sentence. The rule's weakness is the word
  "attempted": T1098's defining element is an account that was manipulated, and none was.
* Against **T1110**: T1110 is about passwords and hashes. No secret is guessed here.
* Against **T1098.003 / T1098.001**: both describe authority being *added*. Nothing was
  added -- asserting a sub-technique would report an outcome that did not occur. The mapper
  already reasons this way for AWS-005, whose comment reads: "Claiming .003 for a detach
  would be reporting the opposite of what happened."

**Conclusion (a):** T1098 at LOW is the best available description of what AWS-006
observes, and the existing rationale text states the limitation exactly -- *"LOW because
the technique's defining element -- an account that was actually manipulated -- was not
observed: every call in this evidence failed."*

### 4.2 Which technique describes what the capture's actors did

Judged from the API calls and error codes and not from the label:

* `bhavin_cli` submitted **one** `CreatePolicy` call whose document grants
  `iam:CreatePolicyVersion` on `arn:aws:iam::*:policy/*`. That is an attempt at exactly the
  behaviour T1098.003 names verbatim. It is an account-manipulation / privilege-escalation
  act that failed on a SID syntax rule. It is not discovery: nothing was enumerated, no
  response carried information about the account, and the caller learned only that
  underscores are not alphanumeric.
* `mhart_cli` submitted **one** `CreatePolicy` call from Terraform whose document had a
  non-ARN ECR resource. HYPOTHESIS, and a strong one given the userAgent, the policy
  description ("Policy to attach to ML tuning instances") and the error: this is benign
  infrastructure-as-code, not an attack at all. It matches AWS-006's own declared false
  positive verbatim -- *"A deployment or policy-generation script emitting a malformed
  policy document and retrying it -- the single most common cause of this shape."*

**Conclusion (b):** T1580 describes neither actor. If anything is being modelled here it is
T1098 (parent) for `bhavin_cli`, and nothing at all for `mhart_cli`.

### 4.3 Are the two readings "different abstraction levels"?

This was the hypothesis the M18 report left open, and it is the one the evidence rejects.
The abstraction-level story would run: *the actors were enumerating by trial (discovery),
and the rule observes the identity writes that enumeration produced.* For that story to
hold, the capture would have to show trial -- several different values submitted against
the same target, each rejection carrying information back.

MEASURED, it shows the opposite: one policy name per actor, one submission per actor, five
copies of each in the file, and rejections that report a syntax error in the caller's own
text rather than a fact about the account. There is no trial, so there is no enumeration,
so there is no lower level for T1580 to sit at. The two readings are not at different
altitudes; one of them is simply not supported by the rows.

### 4.4 Is the ATH mapping wrong?

No, and the evidence is §4.1: T1098 is the only technique in the catalogue whose definition
covers "an attempt to modify an account's permissions", and LOW is the correct confidence
for an attempt that failed. The mapper's stated design -- *"each candidate mapping carries
a gate ... Blanket mapping inflates your ATT&CK heat map with techniques you never actually
observed"* (`src/ath/mitre/mapper.py:1-27`) -- is being honoured, not violated, by the
absence of a T1580 mapping.

---

## 5. Classification

### **`dataset label questionable`**

**Evidence for:**

1. MEASURED -- the capture contains zero `AssumeRole` and zero `UpdateAssumeRolePolicy`
   events, so it does not contain the behaviour its own file name describes.
2. MEASURED -- the capture contains zero read calls of any kind, so it contains nothing
   that matches T1580's definition (§3.1), all of whose named APIs are reads.
3. MEASURED -- the capture contains two distinct events, duplicated five times each.
   Neither actor made repeated attempts at anything; "brute force" is not merely
   mislabelled, it is arithmetically absent.
4. VERIFIED FROM SOURCE -- the T1580 annotation belongs to the Splunk *detection*
   `aws_iam_assume_role_policy_brute_force` (tagged T1110 + T1580), and the label reached
   ATH by directory inheritance: detection tag -> `attack_techniques/T1580/` directory ->
   capture file name -> `scripts/m18_cloud_detection.py` reading the file name. Nobody
   asserted that these two records are Discovery.
5. MEASURED -- the two records' request parameters describe a privilege-escalation policy
   (`iam:CreatePolicyVersion` on all policies) and a Terraform ECR/S3 policy. Read without
   the label, the first is T1098-shaped and the second is benign.

**Evidence against `ATH mapping wrong`:** T1098's definition covers modification of an
account's permission groups (§3.2); T1580's covers discovery of infrastructure by reading
it (§3.1); AWS-006's predicate is structurally incapable of citing a read row (§1.2,
VERIFIED FROM CODE). Asserting T1580 from AWS-006 would assert a technique whose defining
observation the rule has never made. The existing LOW confidence and its rationale already
name the mapping's one weakness accurately.

**Evidence against `both defensible at different abstraction levels`:** §4.3. The
abstraction-level reading requires trial-and-error against a target; the capture has one
submission per actor and error messages that report the caller's own syntax rather than a
property of the account. There is no discovery event at any level of description.

**Evidence against `insufficient evidence`:** every claim above is either a quotation from
code in this worktree, a count computed from the raw capture bytes in the frozen checkout,
a field of the frozen report, or a quotation from a fetched attack.mitre.org page. The one
HYPOTHESIS label in this document (`mhart_cli` is benign Terraform) is not load-bearing for
the classification.

**Scope of the verdict.** "Dataset label questionable" is a statement about *this capture*,
not about `splunk/attack_data` generally and not about the T1580 technique. The other four
captures in this corpus are unaffected; P1 and P2 both produced correctly-labelled
T1580/T1526 matches against genuine `Describe*`/`List*` reconnaissance volume.

---

## 6. Prepared change: **none**

### 6.1 Why no mapping change is prepared

The instruction was to prepare a change **if and only if** it is justified by ATT&CK's
definitions and the observed behaviour, and not by agreement with the label. Neither
condition is met:

* ATT&CK's T1580 definition (§3.1) is not satisfied by any row AWS-006 can cite (§1.2).
* The observed behaviour in the capture (§2.3) is two failed policy-creation attempts, one
  of them almost certainly benign IaC. Adding T1580 would move ATH's
  `labelled_technique_recall` from 0.60 to 0.80 by asserting a Discovery technique on
  evidence that contains no discovery. That is precisely the failure M18 §8 named in
  advance: *"adding a T1580 mapping after seeing this number would be fitting the ATT&CK
  layer to five files."*

This investigation's result is that M18's refusal was not merely cautious -- it was
**correct**, and the reason is now on the record rather than deferred. Recommended edit to
the M18 report's own wording, at the project's discretion and not made here: the sentence
"Both readings are defensible and the label says T1580" is the claim this document
falsifies; a cross-reference to this file would close it.

### 6.2 The falsifier, recorded so this is not unfalsifiable

A T1580 (or T1087.004) mapping on AWS-006 would become justified if the rule could observe
the enumeration oracle rather than infer it. Concretely: rejected identity writes whose
error is *absence or invalidity of a named principal* (`Invalid principal in policy`,
`NoSuchEntity` naming a principal) across **distinct target names**, which is genuine
trial-based enumeration and is what the Splunk detection's prose actually describes. ATH
cannot express that today -- AWS-006's `fields_used` contains no error-code or
error-message field (§1.1), and the canonical schema's `decision` column collapses every
non-authorization rejection to `failed` by design (§1.3). That is a **rule** question (a
future `AWS-0xx` keyed on rejection *reason* and target diversity), not a mapping question,
and it should be priced against a background trail before it is proposed.

### 6.3 Separate defect found, not fixed here (outside the mapping question)

MEASURED, §2.2: five-fold duplication of single CloudTrail records in capture P3 met
AWS-006's threshold of 5 on its own. `cloudtrail_source.py` reads `eventID` into
`source_ref` but never deduplicates on it. Consequences, in order of importance:

1. **The P3 MATCH in M18 §8 is weaker than it reads.** "AWS-006 exactly 2, `bhavin_cli` and
   `mhart_cli`, 5 rejected writes each" is, at the event level, *one* rejected write each.
   The threshold provenance argument ("the background trail's maximum is 4 in a window; 5
   is the smallest value it never reaches") is unaffected -- that was measured on
   flaws.cloud -- but the P3 evidence does not demonstrate the threshold discriminating
   anything.
2. **`window_start == window_end` is a detectable signature of it**, already present in the
   frozen report, and no check looks for it.
3. This does **not** affect the P4 AWS-006 findings (38 failed rows, 38 distinct eventIDs,
   MEASURED), nor P1/P2 (zero duplication, MEASURED).

INCONCLUSIVE: whether the duplication is upstream in `splunk/attack_data` or was introduced
when the capture was fetched into `data/external/`. There is no `attack_data_aws` entry in
`data/external/MANIFEST.json` recording a fetch command or a sha256 to check against, which
is itself worth noting -- the other four datasets have one.

Recommended follow-up (a rule/ingestion question, deliberately not prepared as a change
here, since the task's `PREPARE` clause is scoped to mapping changes): decide whether
`CloudTrailSource` should drop records whose `eventID` it has already seen within a file,
and add an `attack_data_aws` MANIFEST entry. Both are behaviour changes to frozen ingestion
and belong in a milestone with a pre-registration, not in a research pass.
