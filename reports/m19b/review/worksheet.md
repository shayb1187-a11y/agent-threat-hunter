# M19 hypothesis review worksheet

102 hypotheses, one per entry, in a shuffled order. Read `README.md` first, and do not open `KEY.sealed.json`.

Each entry is self-contained: a case's deterministic findings are repeated under every hypothesis drawn from that case, because the entries are shuffled and nothing may be inferred from what sits next to what.

"Already cited" is computed, not judged. It says whether the deterministic pass on this same case had itself already cited that event id; it is a fact about two sets of ids and says nothing about whether the hypothesis is any good.

Record your answers in `answers_template.csv`.

---

## R001

**Case:** `flaws_cloud` / `CASE-018` (10 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | HIGH | 'backup' made 35 read calls across 10 distinct services in 53s, 21 of them refused for want of authority (60%). Breadth with no permission behind it is enumeration rather than administration. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 10: `cloudtrail-control-110341`, `cloudtrail-control-110344`, `cloudtrail-control-110347`, `cloudtrail-control-110350`, `cloudtrail-control-110351`, `cloudtrail-control-110352`, `cloudtrail-control-110353`, `cloudtrail-control-110355`, `cloudtrail-control-110356`, `cloudtrail-control-110357` |

**Hypothesis (verbatim):**

> iam:account-summary being the earliest event in the band suggests the session opened by establishing the account's identity posture and quota/limit context before fanning out to service inventory. That ordering — capability check first, resource sweep second — is the characteristic opening move of automated AWS enumeration frameworks (e.g. Pacu, ScoutSuite, CloudFox) as well as of legitimate CSPM baseline scans.

**Evidence it cites (3):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-110341` | 2018-08-02 07:04:50+00:00 | aws:811596193553/us-east-1 / backup | backup get iam:account-summary [denied] | yes |
| `cloudtrail-control-110344` | 2018-08-02 07:04:52+00:00 | aws:811596193553/us-east-1 / backup | backup describe ec2:image [allowed] | yes |
| `cloudtrail-control-110347` | 2018-08-02 07:04:56+00:00 | aws:811596193553/us-east-1 / backup | backup describe rds:db-instance [denied] | yes |

**Computed:** 0 of 3 cited ids were not cited on this case by the deterministic pass.

---

## R002

**Case:** `flaws_cloud` / `CASE-065` (29 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | MEDIUM | 'Level6' made 1808 read calls across 20 distinct services in 316s, 282 of them refused (16%). Breadth on this scale is consistent with account enumeration, and is also exactly what inventory and compliance tooling does. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 20: `cloudtrail-control-224294`, `cloudtrail-control-224300`, `cloudtrail-control-224346`, `cloudtrail-control-224351`, `cloudtrail-control-224356`, `cloudtrail-control-224384`, `cloudtrail-control-224412`, `cloudtrail-control-224446`, `cloudtrail-control-224468`, `cloudtrail-control-224532`, `cloudtrail-control-224570`, `cloudtrail-control-224571` ... (+8 more; all of them are in worksheet.csv) |
| `AWS-004` | HIGH | 'Level6' was refused authorization 282 times in 307s, across 13 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 13: `cloudtrail-control-224294`, `cloudtrail-control-224468`, `cloudtrail-control-224469`, `cloudtrail-control-224696`, `cloudtrail-control-225208`, `cloudtrail-control-225228`, `cloudtrail-control-225510`, `cloudtrail-control-225648`, `cloudtrail-control-225649`, `cloudtrail-control-225650`, `cloudtrail-control-225651`, `cloudtrail-control-225652` ... (+1 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> An alternative benign reading is that 'Level6' is a shared training/lab or CTF-style account: the naming convention, the very high authentication failure ratio, and a short broad read-only sweep with many denials are equally consistent with repeated enumeration exercises against a deliberately restricted credential. Account ownership and purpose should be established before escalating.

**Evidence it cites (3):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-000144` | 2017-02-28 07:58:45+00:00 | aws:811596193553/us-east-1 / Level6 | success logon [Unknown] from 137.53.124.9 | NO |
| `cloudtrail-control-224294` | 2019-06-06 11:26:57+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get apigateway:rest-apis [denied] | yes |
| `cloudtrail-control-225366` | 2019-06-06 11:31:48+00:00 | aws:811596193553/ap-northeast-1 / Level6 | Level6 list elasticmapreduce:cluster [allowed] | yes |

**Computed:** 1 of 3 cited ids were not cited on this case by the deterministic pass.

---

## R003

**Case:** `flaws_cloud` / `CASE-256` (32 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | MEDIUM | 'Level6' made 671 read calls across 21 distinct services in 550s, 196 of them refused (29%). Breadth on this scale is consistent with account enumeration, and is also exactly what inventory and compliance tooling does. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 20: `cloudtrail-control-1817072`, `cloudtrail-control-1817082`, `cloudtrail-control-1817085`, `cloudtrail-control-1817088`, `cloudtrail-control-1817159`, `cloudtrail-control-1817175`, `cloudtrail-control-1817217`, `cloudtrail-control-1817317`, `cloudtrail-control-1817318`, `cloudtrail-control-1817321`, `cloudtrail-control-1817323`, `cloudtrail-control-1817324` ... (+8 more; all of them are in worksheet.csv) |
| `AWS-004` | HIGH | 'Level6' was refused authorization 196 times in 241s, across 17 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 17: `cloudtrail-control-1817217`, `cloudtrail-control-1817246`, `cloudtrail-control-1817318`, `cloudtrail-control-1817322`, `cloudtrail-control-1817358`, `cloudtrail-control-1817365`, `cloudtrail-control-1817368`, `cloudtrail-control-1817369`, `cloudtrail-control-1817371`, `cloudtrail-control-1817372`, `cloudtrail-control-1817373`, `cloudtrail-control-1817374` ... (+5 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The benign 'inventory/compliance tooling' explanation offered for AWS-003 is weakened by the identity's authentication profile: account 'Level6' shows 5285 failed versus 61 successful authentications (~98.9% failure), which is atypical for sanctioned tooling operating with provisioned credentials and more consistent with credential guessing or a misconfigured/unauthorized client.

**Evidence it cites (5):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-000144` | 2017-02-28 07:58:45+00:00 | aws:811596193553/us-east-1 / Level6 | success logon [Unknown] from 137.53.124.9 | NO |
| `cloudtrail-logon-018192` | 2018-02-24 12:49:58+00:00 | aws:811596193553/us-east-1 / Level6 | failure logon [Unknown] from 245.181.7.4 reason=User: arn:aws:iam::811596193553:user/Level6 is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/service-role/Level6 | NO |
| `cloudtrail-logon-046949` | 2019-03-07 20:35:36+00:00 | aws:811596193553/us-east-1 / Level6 | failure logon [Unknown] from 2.231.90.242 reason=Not authorized to perform sts:AssumeRole | NO |
| `cloudtrail-control-1817072` | 2020-09-21 03:54:58+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 list iam:user [allowed] | yes |
| `cloudtrail-control-1817217` | 2020-09-21 04:00:07+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 get s3:account-public-access-block [denied] | yes |

**Computed:** 3 of 5 cited ids were not cited on this case by the deterministic pass.

---

## R004

**Case:** `synthetic:INC-005` / `CASE-001` (2 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `K8S-001` | HIGH | 'system:serviceaccount:ci:ci-deployer' created clusterrolebindings 'ci-runner-escalation', granting the maximally-privileged role 'cluster-admin' to 'system:serviceaccount:ci:ci-runner'. Very few legitimate workloads need this level of access, and the grantor is not a superuser, so this grant confers standing the grantor did not itself hold; it is worth review even when the grantor is an ordinary ... (full text in worksheet.csv) | 1: `k8s-control-000003` |
| `K8S-002` | CRITICAL | 'system:serviceaccount:ci:ci-runner' was granted the 'cluster-admin' role 149s before exec'ing into pod 'web-1' (namespace 'prod'). A freshly-escalated identity acting on that escalation shortly after receiving it is consistent with the grant being used for exploration or post-exploitation access rather than left dormant. | 2: `k8s-control-000003`, `k8s-control-000004` |

**Hypothesis (verbatim):**

> The 149-second grant-to-use interval and the clean two-step sequence are more consistent with scripted or pipeline-driven execution than with interactive human operation; conversely, the same pattern would be produced by a legitimate but over-permissioned CI deployment job, so automation alone does not distinguish malicious from benign.

**Evidence it cites (2):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `k8s-control-000003` | 2026-08-17 09:20:00.040000+00:00 | k8s:test-cluster / system:serviceaccount:ci:ci-runner | system:serviceaccount:ci:ci-deployer create clusterrolebindings (ci-runner-escalation) -> system:serviceaccount:ci:ci-runner [allowed] | yes |
| `k8s-control-000004` | 2026-08-17 09:22:30.015000+00:00 | k8s:test-cluster / system:serviceaccount:ci:ci-runner | system:serviceaccount:ci:ci-runner exec pods/exec (web-1) [allowed] | yes |

**Computed:** 0 of 2 cited ids were not cited on this case by the deterministic pass.

---

## R005

**Case:** `flaws_cloud` / `CASE-005` (54 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-005` | CRITICAL | 53 failed logons for 'SecurityMokey' on aws:811596193553/us-east-1 from 255.253.125.115 within 247s. A successful logon followed at 22:26:48, -148s after the last failure. This may indicate the credential was successfully guessed and the account is now compromised. | 54: `cloudtrail-logon-002652`, `cloudtrail-logon-002653`, `cloudtrail-logon-002654`, `cloudtrail-logon-002655`, `cloudtrail-logon-002656`, `cloudtrail-logon-002657`, `cloudtrail-logon-002658`, `cloudtrail-logon-002659`, `cloudtrail-logon-002660`, `cloudtrail-logon-002661`, `cloudtrail-logon-002665`, `cloudtrail-logon-002664` ... (+42 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> Only 53 failures preceding success suggests the guessing was targeted (short curated wordlist or credential-stuffing from a prior leak) rather than exhaustive brute force; an exhaustive attack against a non-trivial password would be expected to generate orders of magnitude more failures.

**Evidence it cites (5):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-002652` | 2017-05-26 22:25:09+00:00 | aws:811596193553/us-east-1 / SecurityMokey | failure logon [Unknown] from 255.253.125.115 reason=User: arn:aws:iam::811596193553:user/SecurityMokey is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/SecurityMonkey | yes |
| `cloudtrail-logon-002676` | 2017-05-26 22:26:48+00:00 | aws:811596193553/us-east-1 / SecurityMokey | failure logon [Unknown] from 255.253.125.115 reason=User: arn:aws:iam::811596193553:user/SecurityMokey is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/SecurityMonkey | yes |
| `cloudtrail-logon-002754` | 2017-05-26 22:27:52+00:00 | aws:811596193553/us-east-1 / SecurityMokey | failure logon [Unknown] from 255.253.125.115 reason=User: arn:aws:iam::811596193553:user/SecurityMokey is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/SecurityMonkey | yes |
| `cloudtrail-logon-002791` | 2017-05-26 22:28:27+00:00 | aws:811596193553/us-east-1 / SecurityMokey | failure logon [Unknown] from 255.253.125.115 reason=User: arn:aws:iam::811596193553:user/SecurityMokey is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/SecurityMonkey | yes |
| `cloudtrail-logon-002822` | 2017-05-26 22:29:16+00:00 | aws:811596193553/us-east-1 / SecurityMokey | failure logon [Unknown] from 255.253.125.115 reason=User: arn:aws:iam::811596193553:user/SecurityMokey is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/SecurityMonkey | yes |

**Computed:** 0 of 5 cited ids were not cited on this case by the deterministic pass.

---

## R006

**Case:** `synthetic:INC-004` / `CASE-001` (6 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-012` | CRITICAL | 3 distinct security-control change(s) on PC03 by 'achen': Defender real-time monitoring disabled; a Defender scanning exclusion was added; a security product process was terminated. A single change is often administrative; several in one window is the shape of an attacker clearing the way for what comes next. | 3: `evt-000901`, `evt-000905`, `evt-000909` |
| `ATH-011` | CRITICAL | 3 distinct recovery control(s) were destroyed on PC03 by 'achen': Windows backup catalog deleted; boot-time recovery disabled; volume shadow copies deleted. Destroying recovery paths removes the ability to roll back and commonly immediately precedes encryption. | 3: `evt-000922`, `evt-000925`, `evt-000927` |

**Hypothesis (verbatim):**

> Because 'achen' successfully authenticated from PC03 to APP01 and FS02, the same credentials could be reused to stage the identical defense-disable plus recovery-destruction sequence on those hosts; APP01 and FS02 should be triaged for the same three Defender changes and the same three recovery deletions.

**Evidence it cites (9):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `evt-000027` | 2026-08-17 08:00:26+00:00 | FS02 / achen | success logon [Network (SMB / share access)] from 10.10.20.17 | NO |
| `evt-000085` | 2026-08-17 08:14:29+00:00 | APP01 / achen | success logon [Network (SMB / share access)] from 10.10.20.17 | NO |
| `evt-000090` | 2026-08-17 08:14:58+00:00 | APP01 / achen | success logon [Network (SMB / share access)] from 10.10.20.17 | NO |
| `evt-000901` | 2026-08-17 11:12:00+00:00 | PC03 / achen | cmd.exe -> powershell.exe \| powershell.exe -nop -w hidden Set-MpPreference -DisableRealtimeMonitoring $true | yes |
| `evt-000905` | 2026-08-17 11:12:35+00:00 | PC03 / achen | cmd.exe -> powershell.exe \| powershell.exe Add-MpPreference -ExclusionPath C:\ProgramData\svc | yes |
| `evt-000909` | 2026-08-17 11:13:10+00:00 | PC03 / achen | cmd.exe -> taskkill.exe \| taskkill.exe /F /IM MsMpEng.exe | yes |
| `evt-000922` | 2026-08-17 11:14:30+00:00 | PC03 / achen | cmd.exe -> vssadmin.exe \| vssadmin.exe delete shadows /all /quiet | yes |
| `evt-000925` | 2026-08-17 11:15:05+00:00 | PC03 / achen | cmd.exe -> wbadmin.exe \| wbadmin.exe delete catalog -quiet | yes |
| `evt-000927` | 2026-08-17 11:15:40+00:00 | PC03 / achen | cmd.exe -> bcdedit.exe \| bcdedit.exe /set {default} recoveryenabled no | yes |

**Computed:** 3 of 9 cited ids were not cited on this case by the deterministic pass.

---

## R007

**Case:** `flaws_cloud` / `CASE-065` (29 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | MEDIUM | 'Level6' made 1808 read calls across 20 distinct services in 316s, 282 of them refused (16%). Breadth on this scale is consistent with account enumeration, and is also exactly what inventory and compliance tooling does. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 20: `cloudtrail-control-224294`, `cloudtrail-control-224300`, `cloudtrail-control-224346`, `cloudtrail-control-224351`, `cloudtrail-control-224356`, `cloudtrail-control-224384`, `cloudtrail-control-224412`, `cloudtrail-control-224446`, `cloudtrail-control-224468`, `cloudtrail-control-224532`, `cloudtrail-control-224570`, `cloudtrail-control-224571` ... (+8 more; all of them are in worksheet.csv) |
| `AWS-004` | HIGH | 'Level6' was refused authorization 282 times in 307s, across 13 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 13: `cloudtrail-control-224294`, `cloudtrail-control-224468`, `cloudtrail-control-224469`, `cloudtrail-control-224696`, `cloudtrail-control-225208`, `cloudtrail-control-225228`, `cloudtrail-control-225510`, `cloudtrail-control-225648`, `cloudtrail-control-225649`, `cloudtrail-control-225650`, `cloudtrail-control-225651`, `cloudtrail-control-225652` ... (+1 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The full pattern — an sts:GetCallerIdentity call to establish credential context, followed by breadth-first list/describe sweeps across ~20 unrelated services, then a fixed per-bucket S3 configuration checklist — matches the execution profile of an off-the-shelf multi-service auditing tool (e.g. ScoutSuite, Prowler, CloudMapper) rather than hand-typed reconnaissance. This would explain both the service breadth in AWS-003 and the authorization refusals in AWS-004 as the tool probing checks the credential is not entitled to.

**Evidence it cites (8):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-224300` | 2019-06-06 11:30:41+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 get sts:caller-identity [allowed] | yes |
| `cloudtrail-control-224346` | 2019-06-06 11:31:05+00:00 | aws:811596193553/ap-northeast-1 / Level6 | Level6 list cloudformation:stack [allowed] | yes |
| `cloudtrail-control-224412` | 2019-06-06 11:31:08+00:00 | aws:811596193553/ap-northeast-1 / Level6 | Level6 describe cloudtrail:trail [allowed] | yes |
| `cloudtrail-control-224468` | 2019-06-06 11:31:11+00:00 | aws:811596193553/ap-northeast-1 / Level6 | Level6 describe config:configuration-recorder [denied] | yes |
| `cloudtrail-control-224469` | 2019-06-06 11:31:11+00:00 | aws:811596193553/ap-northeast-1 / Level6 | Level6 describe config:config-rule [denied] | yes |
| `cloudtrail-control-225510` | 2019-06-06 11:31:53+00:00 | aws:811596193553/ap-northeast-1 / Level6 | Level6 describe config:configuration-recorder-status [denied] | yes |
| `cloudtrail-control-225648` | 2019-06-06 11:31:59+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-acl (b5677c799b465420d8e7b0a6689a0bb0c4afbc9e.flaws.cloud) [denied] | yes |
| `cloudtrail-control-225652` | 2019-06-06 11:31:59+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-logging (b5677c799b465420d8e7b0a6689a0bb0c4afbc9e.flaws.cloud) [denied] | yes |

**Computed:** 0 of 8 cited ids were not cited on this case by the deterministic pass.

---

## R008

**Case:** `flaws_cloud` / `CASE-050` (34 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | HIGH | 'backup' made 720 read calls across 87 distinct services in 596s, 498 of them refused for want of authority (69%). Breadth with no permission behind it is enumeration rather than administration. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 20: `cloudtrail-control-189268`, `cloudtrail-control-189271`, `cloudtrail-control-189274`, `cloudtrail-control-189276`, `cloudtrail-control-189278`, `cloudtrail-control-189290`, `cloudtrail-control-189293`, `cloudtrail-control-189312`, `cloudtrail-control-189320`, `cloudtrail-control-189322`, `cloudtrail-control-189323`, `cloudtrail-control-189330` ... (+8 more; all of them are in worksheet.csv) |
| `AWS-004` | HIGH | 'backup' was refused authorization 506 times in 161s, across 245 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 20: `cloudtrail-control-189271`, `cloudtrail-control-189274`, `cloudtrail-control-189276`, `cloudtrail-control-189278`, `cloudtrail-control-189279`, `cloudtrail-control-189280`, `cloudtrail-control-189281`, `cloudtrail-control-189286`, `cloudtrail-control-189287`, `cloudtrail-control-189290`, `cloudtrail-control-189291`, `cloudtrail-control-189292` ... (+8 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The combination of high denial volume (AWS-004) with broad enumeration (AWS-003) argues against the benign compliance-scanner explanation that the existing claims correctly flag as an alternative. Sanctioned scanners (Prowler, Scout Suite, Security Hub) are normally granted SecurityAudit or ReadOnlyAccess and therefore succeed on most read calls; a sweep that is refused repeatedly across many service families suggests the caller did not know what the credential was entitled to and was probing blindly. This is a discriminator, not proof — a scanner deployed with a broken or partially-attached policy produces the same pattern.

**Evidence it cites (10):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-189279` | 2019-04-05 09:22:15+00:00 | aws:811596193553/us-east-1 / backup | backup get apigateway:rest-apis [denied] | yes |
| `cloudtrail-control-189280` | 2019-04-05 09:22:15+00:00 | aws:811596193553/us-east-1 / backup | backup get apigateway:client-certificate [denied] | yes |
| `cloudtrail-control-189281` | 2019-04-05 09:22:15+00:00 | aws:811596193553/us-east-1 / backup | backup get apigateway:api-key [denied] | yes |
| `cloudtrail-control-189286` | 2019-04-05 09:22:16+00:00 | aws:811596193553/us-east-1 / backup | backup get apigateway:sdk-type [denied] | yes |
| `cloudtrail-control-189287` | 2019-04-05 09:22:16+00:00 | aws:811596193553/us-east-1 / backup | backup get apigateway:usage-plan [denied] | yes |
| `cloudtrail-control-189291` | 2019-04-05 09:22:19+00:00 | aws:811596193553/us-east-1 / backup | backup describe autoscaling:adjustment-type [denied] | yes |
| `cloudtrail-control-189292` | 2019-04-05 09:22:19+00:00 | aws:811596193553/us-east-1 / backup | backup describe autoscaling:account-limit [denied] | yes |
| `cloudtrail-control-189294` | 2019-04-05 09:22:19+00:00 | aws:811596193553/us-east-1 / backup | backup list athena:query-execution [denied] | yes |
| `cloudtrail-control-189300` | 2019-04-05 09:22:20+00:00 | aws:811596193553/us-east-1 / backup | backup describe autoscaling:termination-policy-type [denied] | yes |
| `cloudtrail-control-189301` | 2019-04-05 09:22:20+00:00 | aws:811596193553/us-east-1 / backup | backup describe autoscaling:tag [denied] | yes |

**Computed:** 0 of 10 cited ids were not cited on this case by the deterministic pass.

---

## R009

**Case:** `flaws_cloud` / `CASE-018` (10 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | HIGH | 'backup' made 35 read calls across 10 distinct services in 53s, 21 of them refused for want of authority (60%). Breadth with no permission behind it is enumeration rather than administration. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 10: `cloudtrail-control-110341`, `cloudtrail-control-110344`, `cloudtrail-control-110347`, `cloudtrail-control-110350`, `cloudtrail-control-110351`, `cloudtrail-control-110352`, `cloudtrail-control-110353`, `cloudtrail-control-110355`, `cloudtrail-control-110356`, `cloudtrail-control-110357` |

**Hypothesis (verbatim):**

> The ambiguity between T1526 and T1580 is resolvable from data the rule discarded: if the 21 denials cluster on compute/network/storage inventory APIs (EC2/RDS/VPC describes) the behaviour is Cloud Infrastructure Discovery (T1580), whereas denials spread evenly as single probes per service favour Cloud Service Discovery (T1526). A per-service breakdown of the 10 services should be retrieved before assigning a technique.

**Evidence it cites (5):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-110341` | 2018-08-02 07:04:50+00:00 | aws:811596193553/us-east-1 / backup | backup get iam:account-summary [denied] | yes |
| `cloudtrail-control-110344` | 2018-08-02 07:04:52+00:00 | aws:811596193553/us-east-1 / backup | backup describe ec2:image [allowed] | yes |
| `cloudtrail-control-110350` | 2018-08-02 07:05:24+00:00 | aws:811596193553/ap-northeast-1 / backup | backup list dynamodb:table [denied] | yes |
| `cloudtrail-control-110355` | 2018-08-02 07:05:25+00:00 | aws:811596193553/ap-northeast-1 / backup | backup list s3:bucket [allowed] | yes |
| `cloudtrail-control-110356` | 2018-08-02 07:05:25+00:00 | aws:811596193553/ap-northeast-1 / backup | backup describe cloudformation:stack [denied] | yes |

**Computed:** 0 of 5 cited ids were not cited on this case by the deterministic pass.

---

## R010

**Case:** `attack_data_aws` / `CASE-002` (5 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-004` | HIGH | 'cloudmapper' was refused authorization 37 times in 284s, across 5 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 5: `cloudtrail-control-001224`, `cloudtrail-control-001222`, `cloudtrail-control-001220`, `cloudtrail-control-001219`, `cloudtrail-control-001204` |

**Hypothesis (verbatim):**

> If the enumeration is adversarial, the abrupt end of activity at 13:35:10 with no observed successful action suggests the credential's permission boundary held and the operator either abandoned the principal or pivoted to a different identity; a search for other principals in account 731544447609 showing similar burst patterns shortly after 13:35 would test this.

**Evidence it cites (2):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-001204` | 2021-04-13 13:35:10+00:00 | aws:731544447609/eu-north-1 / cloudmapper | cloudmapper get glue:trigger [denied] | yes |
| `cloudtrail-control-001224` | 2021-04-13 13:30:36+00:00 | aws:731544447609/us-east-1 / cloudmapper | cloudmapper list kms:key-policy [denied] | yes |

**Computed:** 0 of 2 cited ids were not cited on this case by the deterministic pass.

---

## R011

**Case:** `flaws_cloud` / `CASE-122` (13 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-004` | HIGH | 'Level6' was refused authorization 84 times in 92s, across 13 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 13: `cloudtrail-control-1649380`, `cloudtrail-control-1649381`, `cloudtrail-control-1649382`, `cloudtrail-control-1649383`, `cloudtrail-control-1649386`, `cloudtrail-control-1649387`, `cloudtrail-control-1649388`, `cloudtrail-control-1649390`, `cloudtrail-control-1649391`, `cloudtrail-control-1649392`, `cloudtrail-control-1649393`, `cloudtrail-control-1649394` ... (+1 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The subset of calls targeting bucket-policy, bucket-policy-status, bucket-acl, and bucket-website is the portion of the sweep that would reveal public-exposure and permission-boundary information. If the caller is adversarial, this cluster is the likely objective of the enumeration and a precursor to attempted object access or a public-exposure abuse path; its presence raises the priority of checking whether GetObject/ListObjects calls followed against the same bucket.

**Evidence it cites (4):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1649382` | 2019-08-28 21:53:05+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-acl (dev-eztax) [denied] | yes |
| `cloudtrail-control-1649387` | 2019-08-28 21:53:07+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-policy-status (dev-eztax) [denied] | yes |
| `cloudtrail-control-1649391` | 2019-08-28 21:53:07+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-policy (dev-eztax) [denied] | yes |
| `cloudtrail-control-1649393` | 2019-08-28 21:53:08+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-website (dev-eztax) [denied] | yes |

**Computed:** 0 of 4 cited ids were not cited on this case by the deterministic pass.

---

## R012

**Case:** `flaws_cloud` / `CASE-018` (10 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | HIGH | 'backup' made 35 read calls across 10 distinct services in 53s, 21 of them refused for want of authority (60%). Breadth with no permission behind it is enumeration rather than administration. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 10: `cloudtrail-control-110341`, `cloudtrail-control-110344`, `cloudtrail-control-110347`, `cloudtrail-control-110350`, `cloudtrail-control-110351`, `cloudtrail-control-110352`, `cloudtrail-control-110353`, `cloudtrail-control-110355`, `cloudtrail-control-110356`, `cloudtrail-control-110357` |

**Hypothesis (verbatim):**

> The sustained high-volume authentication failure history against 'backup' is consistent with a credential-stuffing or brute-force campaign targeting this identity, which would make the 07:04:50Z discovery burst a post-compromise reconnaissance stage rather than an isolated anomaly; correlating failure timestamps against the 125 successes would confirm or refute a guess-then-succeed pattern.

**Evidence it cites (3):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-025755` | 2018-09-06 10:47:31+00:00 | aws:811596193553/us-east-1 / backup | failure logon [Unknown] from 1.5.5.223 reason=Not authorized to perform sts:AssumeRole | NO |
| `cloudtrail-logon-000120` | 2017-02-27 16:58:36+00:00 | aws:811596193553/us-east-1 / backup | success logon [Unknown] from 0.229.250.9 | NO |
| `cloudtrail-control-110341` | 2018-08-02 07:04:50+00:00 | aws:811596193553/us-east-1 / backup | backup get iam:account-summary [denied] | yes |

**Computed:** 2 of 3 cited ids were not cited on this case by the deterministic pass.

---

## R013

**Case:** `comiset` / `CASE-002` (1 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-012` | HIGH | 1 distinct security-control change(s) on desktop-4pvps6e by 'system': a security service was stopped. A single change is often administrative; several in one window is the shape of an attacker clearing the way for what comes next. | 1: `comiset_slice.jsonl:4bdb0f0e83e0a62d3ca40b33ef0d892801fd4d3b` |

**Hypothesis (verbatim):**

> remotemouse.exe is being abused as attacker remote-access tooling (a legitimate remote-control application used in lieu of a custom RAT), making it the hands-on-keyboard entry point for this host rather than a user-initiated convenience tool.

**Evidence it cites (1):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `comiset_slice.jsonl:2123df97130430b012740761f3c88c0bbe4bc345` | 2022-11-19 19:00:59.545000+00:00 | desktop-4pvps6e / system | remotemouse.exe -> cmd.exe \| "c:\windows\system32\cmd.exe" | yes |

**Computed:** 0 of 1 cited ids were not cited on this case by the deterministic pass.

---

## R014

**Case:** `flaws_cloud` / `CASE-065` (29 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | MEDIUM | 'Level6' made 1808 read calls across 20 distinct services in 316s, 282 of them refused (16%). Breadth on this scale is consistent with account enumeration, and is also exactly what inventory and compliance tooling does. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 20: `cloudtrail-control-224294`, `cloudtrail-control-224300`, `cloudtrail-control-224346`, `cloudtrail-control-224351`, `cloudtrail-control-224356`, `cloudtrail-control-224384`, `cloudtrail-control-224412`, `cloudtrail-control-224446`, `cloudtrail-control-224468`, `cloudtrail-control-224532`, `cloudtrail-control-224570`, `cloudtrail-control-224571` ... (+8 more; all of them are in worksheet.csv) |
| `AWS-004` | HIGH | 'Level6' was refused authorization 282 times in 307s, across 13 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 13: `cloudtrail-control-224294`, `cloudtrail-control-224468`, `cloudtrail-control-224469`, `cloudtrail-control-224696`, `cloudtrail-control-225208`, `cloudtrail-control-225228`, `cloudtrail-control-225510`, `cloudtrail-control-225648`, `cloudtrail-control-225649`, `cloudtrail-control-225650`, `cloudtrail-control-225651`, `cloudtrail-control-225652` ... (+1 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The 'Level6' principal's authentication history (5285 failures against only 61 successes, ~99% failure rate, across two regions with no source resolved) is anomalous for a healthy service identity and raises the possibility that the credential used for the discovery burst was not under its legitimate owner's exclusive control. Confirming this requires correlating the timestamps and source identity of the 61 successful authentications against the 11:26-11:32 control-plane window.

**Evidence it cites (6):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-000144` | 2017-02-28 07:58:45+00:00 | aws:811596193553/us-east-1 / Level6 | success logon [Unknown] from 137.53.124.9 | NO |
| `cloudtrail-logon-000145` | 2017-02-28 08:01:21+00:00 | aws:811596193553/us-east-1 / Level6 | failure logon [Unknown] from 137.53.124.9 reason=User: arn:aws:iam::811596193553:user/Level6 is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/service-role/Level6 | NO |
| `cloudtrail-logon-000146` | 2017-02-28 08:01:50+00:00 | aws:811596193553/us-east-1 / Level6 | failure logon [Unknown] from 137.53.124.9 reason=User: arn:aws:iam::811596193553:user/Level6 is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/service-role/Level6 | NO |
| `cloudtrail-logon-002347` | 2017-05-16 23:04:44+00:00 | aws:811596193553/us-east-1 / Level6 | failure logon [Unknown] from 10.154.248.134 reason=Not authorized to perform sts:AssumeRole | NO |
| `cloudtrail-logon-007478` | 2017-06-04 23:48:44+00:00 | aws:811596193553/us-east-1 / Level6 | success logon [Unknown] from 62.90.202.229 | NO |
| `cloudtrail-control-224294` | 2019-06-06 11:26:57+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get apigateway:rest-apis [denied] | yes |

**Computed:** 5 of 6 cited ids were not cited on this case by the deterministic pass.

---

## R015

**Case:** `comiset` / `CASE-002` (1 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-012` | HIGH | 1 distinct security-control change(s) on desktop-4pvps6e by 'system': a security service was stopped. A single change is often administrative; several in one window is the shape of an attacker clearing the way for what comes next. | 1: `comiset_slice.jsonl:4bdb0f0e83e0a62d3ca40b33ef0d892801fd4d3b` |

**Hypothesis (verbatim):**

> Disabling security tooling is typically preparatory; additional child processes of the same cmd.exe instance, new service creations, or payload writes on desktop-4pvps6e within minutes of this chain should be hunted as the likely next stage.

**Evidence it cites (1):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `comiset_slice.jsonl:4bdb0f0e83e0a62d3ca40b33ef0d892801fd4d3b` | 2022-11-19 19:12:55.683000+00:00 | desktop-4pvps6e / system | cmd.exe -> sc.exe \| sc stop windefend | yes |

**Computed:** 0 of 1 cited ids were not cited on this case by the deterministic pass.

---

## R016

**Case:** `flaws_cloud` / `CASE-122` (13 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-004` | HIGH | 'Level6' was refused authorization 84 times in 92s, across 13 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 13: `cloudtrail-control-1649380`, `cloudtrail-control-1649381`, `cloudtrail-control-1649382`, `cloudtrail-control-1649383`, `cloudtrail-control-1649386`, `cloudtrail-control-1649387`, `cloudtrail-control-1649388`, `cloudtrail-control-1649390`, `cloudtrail-control-1649391`, `cloudtrail-control-1649392`, `cloudtrail-control-1649393`, `cloudtrail-control-1649394` ... (+1 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The 61 successful authentications indicate at least one working credential path for 'Level6'; the ap-southeast-1 denial burst is plausibly the post-authentication action of one such successful session probing what that credential can reach, making correlation of the burst's session/access-key identifier against those 61 successes the highest-value next investigative step.

**Evidence it cites (4):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1649382` | 2019-08-28 21:53:05+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-acl (dev-eztax) [denied] | yes |
| `cloudtrail-control-1649386` | 2019-08-28 21:53:07+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-replication (dev-eztax) [denied] | yes |
| `cloudtrail-logon-000249` | 2017-03-03 11:43:45+00:00 | aws:811596193553/us-east-1 / Level6 | success logon [Unknown] from 191.93.93.252 | NO |
| `cloudtrail-logon-007478` | 2017-06-04 23:48:44+00:00 | aws:811596193553/us-east-1 / Level6 | success logon [Unknown] from 62.90.202.229 | NO |

**Computed:** 2 of 4 cited ids were not cited on this case by the deterministic pass.

---

## R017

**Case:** `synthetic:INC-004` / `CASE-001` (6 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-012` | CRITICAL | 3 distinct security-control change(s) on PC03 by 'achen': Defender real-time monitoring disabled; a Defender scanning exclusion was added; a security product process was terminated. A single change is often administrative; several in one window is the shape of an attacker clearing the way for what comes next. | 3: `evt-000901`, `evt-000905`, `evt-000909` |
| `ATH-011` | CRITICAL | 3 distinct recovery control(s) were destroyed on PC03 by 'achen': Windows backup catalog deleted; boot-time recovery disabled; volume shadow copies deleted. Destroying recovery paths removes the ability to roll back and commonly immediately precedes encryption. | 3: `evt-000922`, `evt-000925`, `evt-000927` |

**Hypothesis (verbatim):**

> PC03's outbound traffic is attributed almost entirely to chrome.exe against common cloud/CDN endpoints, which is consistent with a browser-delivered initial access vector (malicious download or drive-by) preceding the on-host destruction; the browser download history and process-creation chain from chrome.exe on 2026-08-17 warrant review.

**Evidence it cites (5):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `evt-000026` | 2026-08-17 08:00:19+00:00 | PC03 / achen | OUTLOOK.EXE -> 13.107.42.14:443 (outbound) | NO |
| `evt-000048` | 2026-08-17 08:05:30+00:00 | PC03 / achen | chrome.exe -> 52.113.194.132:443 (outbound) | NO |
| `evt-000059` | 2026-08-17 08:10:33+00:00 | PC03 / achen | chrome.exe -> 10.10.10.10:445 (outbound) | NO |
| `evt-000070` | 2026-08-17 08:12:19+00:00 | PC03 / achen | OUTLOOK.EXE -> 13.107.42.14:443 (outbound) | NO |
| `evt-000907` | 2026-08-17 11:12:38+00:00 | PC03 / SYSTEM | MsMpEng.exe -> 10.10.10.20:389 (outbound) | NO |

**Computed:** 5 of 5 cited ids were not cited on this case by the deterministic pass.

---

## R018

**Case:** `comiset` / `CASE-001` (2 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-002` | MEDIUM | PowerShell ran a base64-encoded command. The payload does not obviously fetch remote code, but the command line also suppresses the console window and/or the user profile. Evasion flags observed: no profile. | 1: `comiset_slice.jsonl:41ece3af25e0f38cccc6d27422a388c739761353` |
| `ATH-002` | MEDIUM | PowerShell ran a base64-encoded command. The payload does not obviously fetch remote code, but the command line also suppresses the console window and/or the user profile. Evasion flags observed: no profile. | 1: `comiset_slice.jsonl:574dffe7a299a4ad9d2b1150574e2cff72b4efb4` |

**Hypothesis (verbatim):**

> remotemouse.exe is a legitimate remote-control utility being abused as the initial access or hands-on-keyboard entry point (living-off-trusted-software), with cmd.exe used as the launcher for the implant.

**Evidence it cites (2):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `comiset_slice.jsonl:0a7e197d2e49a2d65785fa2efbca8a1bbdfcdb8a` | 2022-11-18 10:37:49.512000+00:00 | desktop-4pvps6e / system | cmd.exe -> beacon.exe \| beacon.exe | yes |
| `comiset_slice.jsonl:b9a5cb4bdabc2fe887d9224d6c42056e5b64ff90` | 2022-11-18 10:27:21.393000+00:00 | desktop-4pvps6e / system | remotemouse.exe -> cmd.exe \| "c:\windows\system32\cmd.exe" | yes |

**Computed:** 0 of 2 cited ids were not cited on this case by the deterministic pass.

---

## R019

**Case:** `synthetic:INC-001` / `CASE-001` (31 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-009` | MEDIUM | Outlook launched WINWORD.EXE to open a document in a macro-capable format. This is consistent with a malicious attachment being opened, independent of whether any embedded macro subsequently ran. | 1: `evt-000355` |
| `ATH-001` | HIGH | WINWORD.EXE started powershell.exe. Office applications have no routine need to launch script interpreters; this parent/child relationship is consistent with macro-based code execution from a document. | 1: `evt-000357` |
| `ATH-002` | HIGH | PowerShell ran a base64-encoded command. The decoded payload retrieves and executes remote content, which is consistent with a first-stage downloader. Evasion flags observed: hidden window, no profile. | 1: `evt-000357` |
| `ATH-003` | HIGH | powershell.exe made 7 outbound connection(s) to the external address 185.220.101.47 on port(s) 80, 443. Script interpreters do not normally initiate direct internet connections; this may indicate payload retrieval or command-and-control. The connection to port 80 indicates cleartext HTTP, which is commonly used to retrieve a second-stage script. | 7: `evt-000358`, `evt-000362`, `evt-000380`, `evt-000399`, `evt-000421`, `evt-000454`, `evt-000486` |
| `ATH-010` | MEDIUM | 3 distinct discovery commands (net.exe, nltest.exe, whoami.exe) ran from the same parent process (PID 6612) within 34s, consistent with systematic reconnaissance of the local environment and domain. | 3: `evt-000367`, `evt-000370`, `evt-000374` |
| `ATH-004` | CRITICAL | Command line matched credential-access indicators (comsvcs.dll MiniDump, explicit lsass reference, rundll32 MiniDump export). This may indicate an attempt to extract credential material from LSASS memory, which would enable authentication as other users. Requires immediate verification against the account's expected activity. | 1: `evt-000381` |
| `ATH-005` | CRITICAL | 14 failed logons for 'svc_backup' on FS02 from 10.10.20.15 within 143s. A successful logon followed at 09:33:47, 204s after the last failure. This may indicate the credential was successfully guessed and the account is now compromised. | 15: `evt-000419`, `evt-000422`, `evt-000425`, `evt-000427`, `evt-000429`, `evt-000431`, `evt-000432`, `evt-000433`, `evt-000437`, `evt-000438`, `evt-000439`, `evt-000440` ... (+3 more; all of them are in worksheet.csv) |
| `ATH-006` | HIGH | Account 'svc_backup' authenticated to FS02 from PC01, but has no interactive session on PC01 (observed owner(s): jdoe). Credential use originating from a host the account does not operate on is consistent with lateral movement using stolen credentials, though legitimate alternate-credential workflows produce the same pattern. | 1: `evt-000457` |
| `ATH-007` | HIGH | The Service Control Manager started an interactive command interpreter. This pattern is consistent with remote command execution via a temporary service. Command output is redirected to the administrative share '\\127.0.0.1\ADMIN$', which is characteristic of remote execution frameworks collecting results over SMB. | 1: `evt-000461` |
| `ATH-008` | HIGH | An archive utility was invoked and the source path uses a wildcard, implying bulk collection and the destination is a shared staging directory. This is consistent with staging data prior to exfiltration, but does not by itself show that any data left the network. | 1: `evt-000469` |
| `ATH-003` | MEDIUM | powershell.exe made 1 outbound connection(s) to the external address 185.220.101.47 on port(s) 443. Script interpreters do not normally initiate direct internet connections; this may indicate payload retrieval or command-and-control. | 1: `evt-000481` |

**Hypothesis (verbatim):**

> Data staged on disk may have been transferred to the external destination observed in this case. This is unverified: the telemetry records archive creation and outbound connections separately, and does not show the archive's contents leaving.

**Evidence it cites (0):**

_This hypothesis cites no event ids._

---

## R020

**Case:** `flaws_cloud` / `CASE-077` (15 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-004` | HIGH | 'Level6' was refused authorization 772 times in 221s, across 15 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 15: `cloudtrail-control-238972`, `cloudtrail-control-238973`, `cloudtrail-control-238974`, `cloudtrail-control-238975`, `cloudtrail-control-238977`, `cloudtrail-control-238978`, `cloudtrail-control-238979`, `cloudtrail-control-238980`, `cloudtrail-control-238981`, `cloudtrail-control-238982`, `cloudtrail-control-238983`, `cloudtrail-control-238984` ... (+3 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The event-identifier ordering suggests the reads preceded the write by a substantial number of intervening control-plane events (238972-238987 versus 239755). If that ordering reflects real time, it indicates reconnaissance first and action second, but identifier sequence is not a verified timestamp and this ordering should be confirmed against event times before being relied on.

**Evidence it cites (3):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-238972` | 2019-06-21 15:43:30+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-tagging (flaws.cloud) [denied] | yes |
| `cloudtrail-control-238987` | 2019-06-21 15:43:30+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-versioning (flaws.cloud) [denied] | yes |
| `cloudtrail-control-239755` | 2019-06-21 15:47:08+00:00 | aws:811596193553/us-west-1 / Level6 | Level6 create s3:bucket (pwnd) [denied] | yes |

**Computed:** 0 of 3 cited ids were not cited on this case by the deterministic pass.

---

## R021

**Case:** `flaws_cloud` / `CASE-205` (15 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | MEDIUM | 'Level6' made 563 read calls across 14 distinct services in 463s, 38 of them refused (7%). Breadth on this scale is consistent with account enumeration, and is also exactly what inventory and compliance tooling does. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 14: `cloudtrail-control-1760284`, `cloudtrail-control-1760328`, `cloudtrail-control-1760344`, `cloudtrail-control-1760376`, `cloudtrail-control-1760408`, `cloudtrail-control-1760425`, `cloudtrail-control-1760518`, `cloudtrail-control-1760534`, `cloudtrail-control-1760582`, `cloudtrail-control-1760662`, `cloudtrail-control-1760663`, `cloudtrail-control-1760664` ... (+2 more; all of them are in worksheet.csv) |
| `AWS-004` | MEDIUM | 'Level6' was refused authorization 38 times in 5s, across 3 distinct resource types. Concentrated on so few kinds of object, this is equally the shape of an application missing one permission and retrying. A refusal says what the platform would not do; it does not say what the caller intended. | 3: `cloudtrail-control-1760664`, `cloudtrail-control-1760670`, `cloudtrail-control-1760671` |

**Hypothesis (verbatim):**

> An alternative benign explanation fits equally well: a newly deployed multi-region inventory or backup agent running under the 'Level6' identity with an incomplete IAM policy would produce exactly this signature - wide read fan-out plus a tight cluster of denials on the three resource types its policy omits. Resolving this requires the userAgent, access-key identity, and whether the same pattern recurs on a schedule, none of which are in the cited evidence.

**Evidence it cites (4):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1760662` | 2020-06-01 19:29:07+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 list route53:hosted-zone [allowed] | yes |
| `cloudtrail-control-1760663` | 2020-06-01 19:29:09+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 list route53domains:domain [allowed] | yes |
| `cloudtrail-control-1760664` | 2020-06-01 19:29:15+00:00 | aws:811596193553/ap-south-1 / Level6 | Level6 list ses:identity [denied] | yes |
| `cloudtrail-control-1760670` | 2020-06-01 19:29:17+00:00 | aws:811596193553/ap-south-1 / Level6 | Level6 list sns:topic [denied] | yes |

**Computed:** 0 of 4 cited ids were not cited on this case by the deterministic pass.

---

## R022

**Case:** `flaws_cloud` / `CASE-122` (13 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-004` | HIGH | 'Level6' was refused authorization 84 times in 92s, across 13 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 13: `cloudtrail-control-1649380`, `cloudtrail-control-1649381`, `cloudtrail-control-1649382`, `cloudtrail-control-1649383`, `cloudtrail-control-1649386`, `cloudtrail-control-1649387`, `cloudtrail-control-1649388`, `cloudtrail-control-1649390`, `cloudtrail-control-1649391`, `cloudtrail-control-1649392`, `cloudtrail-control-1649393`, `cloudtrail-control-1649394` ... (+1 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> An equally consistent benign explanation is a misconfigured or newly deployed automation/inventory tool running under 'Level6' against a region where it holds no policy grants: such tooling produces exactly this signature - many denials, many resource types, sub-second spacing, zero successes - and the high background authentication failure count would then reflect the same broken configuration rather than an adversary.

**Evidence it cites (4):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1649387` | 2019-08-28 21:53:07+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-policy-status (dev-eztax) [denied] | yes |
| `cloudtrail-control-1649388` | 2019-08-28 21:53:07+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-notification (dev-eztax) [denied] | yes |
| `cloudtrail-control-1649391` | 2019-08-28 21:53:07+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-policy (dev-eztax) [denied] | yes |
| `cloudtrail-logon-000392` | 2017-03-07 18:28:28+00:00 | aws:811596193553/us-east-1 / Level6 | failure logon [Unknown] from 8.254.42.254 reason=User: arn:aws:iam::811596193553:user/Level6 is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/flaws | NO |

**Computed:** 1 of 4 cited ids were not cited on this case by the deterministic pass.

---

## R023

**Case:** `synthetic:INC-004` / `CASE-001` (6 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-012` | CRITICAL | 3 distinct security-control change(s) on PC03 by 'achen': Defender real-time monitoring disabled; a Defender scanning exclusion was added; a security product process was terminated. A single change is often administrative; several in one window is the shape of an attacker clearing the way for what comes next. | 3: `evt-000901`, `evt-000905`, `evt-000909` |
| `ATH-011` | CRITICAL | 3 distinct recovery control(s) were destroyed on PC03 by 'achen': Windows backup catalog deleted; boot-time recovery disabled; volume shadow copies deleted. Destroying recovery paths removes the ability to roll back and commonly immediately precedes encryption. | 3: `evt-000922`, `evt-000925`, `evt-000927` |

**Hypothesis (verbatim):**

> If the defense-impairment step succeeded before the vssadmin execution, endpoint telemetry collected after that point on PC03 may be incomplete or unreliable, meaning the absence of further malicious events on this host is weak evidence of containment.

**Evidence it cites (4):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `evt-000901` | 2026-08-17 11:12:00+00:00 | PC03 / achen | cmd.exe -> powershell.exe \| powershell.exe -nop -w hidden Set-MpPreference -DisableRealtimeMonitoring $true | yes |
| `evt-000905` | 2026-08-17 11:12:35+00:00 | PC03 / achen | cmd.exe -> powershell.exe \| powershell.exe Add-MpPreference -ExclusionPath C:\ProgramData\svc | yes |
| `evt-000909` | 2026-08-17 11:13:10+00:00 | PC03 / achen | cmd.exe -> taskkill.exe \| taskkill.exe /F /IM MsMpEng.exe | yes |
| `evt-000922` | 2026-08-17 11:14:30+00:00 | PC03 / achen | cmd.exe -> vssadmin.exe \| vssadmin.exe delete shadows /all /quiet | yes |

**Computed:** 0 of 4 cited ids were not cited on this case by the deterministic pass.

---

## R024

**Case:** `attack_data_aws` / `CASE-002` (5 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-004` | HIGH | 'cloudmapper' was refused authorization 37 times in 284s, across 5 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 5: `cloudtrail-control-001224`, `cloudtrail-control-001222`, `cloudtrail-control-001220`, `cloudtrail-control-001219`, `cloudtrail-control-001204` |

**Hypothesis (verbatim):**

> The Glue job and trigger reads are the one pair in this set that could serve execution rather than pure discovery, since Glue jobs run code and triggers schedule it. If the same identity later shows a Glue job create or update, the case should be re-scored as reconnaissance preceding execution rather than Discovery alone.

**Evidence it cites (2):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-001219` | 2021-04-13 13:34:57+00:00 | aws:731544447609/eu-north-1 / cloudmapper | cloudmapper get glue:job [denied] | yes |
| `cloudtrail-control-001204` | 2021-04-13 13:35:10+00:00 | aws:731544447609/eu-north-1 / cloudmapper | cloudmapper get glue:trigger [denied] | yes |

**Computed:** 0 of 2 cited ids were not cited on this case by the deterministic pass.

---

## R025

**Case:** `flaws_cloud` / `CASE-018` (10 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | HIGH | 'backup' made 35 read calls across 10 distinct services in 53s, 21 of them refused for want of authority (60%). Breadth with no permission behind it is enumeration rather than administration. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 10: `cloudtrail-control-110341`, `cloudtrail-control-110344`, `cloudtrail-control-110347`, `cloudtrail-control-110350`, `cloudtrail-control-110351`, `cloudtrail-control-110352`, `cloudtrail-control-110353`, `cloudtrail-control-110355`, `cloudtrail-control-110356`, `cloudtrail-control-110357` |

**Hypothesis (verbatim):**

> The competing benign explanation (a scheduled compliance or inventory scanner) is directly testable and should be resolved before escalation: a scanner would produce a near-identical service sweep on a fixed cadence from a stable source IP and user agent. If no equivalent enumeration band by 'backup' exists in the preceding days' control-plane logs, the benign explanation fails and the single-session interpretation strengthens substantially.

**Evidence it cites (5):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-110341` | 2018-08-02 07:04:50+00:00 | aws:811596193553/us-east-1 / backup | backup get iam:account-summary [denied] | yes |
| `cloudtrail-control-110350` | 2018-08-02 07:05:24+00:00 | aws:811596193553/ap-northeast-1 / backup | backup list dynamodb:table [denied] | yes |
| `cloudtrail-control-110353` | 2018-08-02 07:05:25+00:00 | aws:811596193553/ap-northeast-1 / backup | backup list lambda:function [denied] | yes |
| `cloudtrail-control-110355` | 2018-08-02 07:05:25+00:00 | aws:811596193553/ap-northeast-1 / backup | backup list s3:bucket [allowed] | yes |
| `cloudtrail-control-110356` | 2018-08-02 07:05:25+00:00 | aws:811596193553/ap-northeast-1 / backup | backup describe cloudformation:stack [denied] | yes |

**Computed:** 0 of 5 cited ids were not cited on this case by the deterministic pass.

---

## R026

**Case:** `synthetic:INC-001` / `CASE-001` (31 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-009` | MEDIUM | Outlook launched WINWORD.EXE to open a document in a macro-capable format. This is consistent with a malicious attachment being opened, independent of whether any embedded macro subsequently ran. | 1: `evt-000355` |
| `ATH-001` | HIGH | WINWORD.EXE started powershell.exe. Office applications have no routine need to launch script interpreters; this parent/child relationship is consistent with macro-based code execution from a document. | 1: `evt-000357` |
| `ATH-002` | HIGH | PowerShell ran a base64-encoded command. The decoded payload retrieves and executes remote content, which is consistent with a first-stage downloader. Evasion flags observed: hidden window, no profile. | 1: `evt-000357` |
| `ATH-003` | HIGH | powershell.exe made 7 outbound connection(s) to the external address 185.220.101.47 on port(s) 80, 443. Script interpreters do not normally initiate direct internet connections; this may indicate payload retrieval or command-and-control. The connection to port 80 indicates cleartext HTTP, which is commonly used to retrieve a second-stage script. | 7: `evt-000358`, `evt-000362`, `evt-000380`, `evt-000399`, `evt-000421`, `evt-000454`, `evt-000486` |
| `ATH-010` | MEDIUM | 3 distinct discovery commands (net.exe, nltest.exe, whoami.exe) ran from the same parent process (PID 6612) within 34s, consistent with systematic reconnaissance of the local environment and domain. | 3: `evt-000367`, `evt-000370`, `evt-000374` |
| `ATH-004` | CRITICAL | Command line matched credential-access indicators (comsvcs.dll MiniDump, explicit lsass reference, rundll32 MiniDump export). This may indicate an attempt to extract credential material from LSASS memory, which would enable authentication as other users. Requires immediate verification against the account's expected activity. | 1: `evt-000381` |
| `ATH-005` | CRITICAL | 14 failed logons for 'svc_backup' on FS02 from 10.10.20.15 within 143s. A successful logon followed at 09:33:47, 204s after the last failure. This may indicate the credential was successfully guessed and the account is now compromised. | 15: `evt-000419`, `evt-000422`, `evt-000425`, `evt-000427`, `evt-000429`, `evt-000431`, `evt-000432`, `evt-000433`, `evt-000437`, `evt-000438`, `evt-000439`, `evt-000440` ... (+3 more; all of them are in worksheet.csv) |
| `ATH-006` | HIGH | Account 'svc_backup' authenticated to FS02 from PC01, but has no interactive session on PC01 (observed owner(s): jdoe). Credential use originating from a host the account does not operate on is consistent with lateral movement using stolen credentials, though legitimate alternate-credential workflows produce the same pattern. | 1: `evt-000457` |
| `ATH-007` | HIGH | The Service Control Manager started an interactive command interpreter. This pattern is consistent with remote command execution via a temporary service. Command output is redirected to the administrative share '\\127.0.0.1\ADMIN$', which is characteristic of remote execution frameworks collecting results over SMB. | 1: `evt-000461` |
| `ATH-008` | HIGH | An archive utility was invoked and the source path uses a wildcard, implying bulk collection and the destination is a shared staging directory. This is consistent with staging data prior to exfiltration, but does not by itself show that any data left the network. | 1: `evt-000469` |
| `ATH-003` | MEDIUM | powershell.exe made 1 outbound connection(s) to the external address 185.220.101.47 on port(s) 443. Script interpreters do not normally initiate direct internet connections; this may indicate payload retrieval or command-and-control. | 1: `evt-000481` |

**Hypothesis (verbatim):**

> The 14 failed svc_backup logons indicate the attacker did not obtain a usable svc_backup credential from the LSASS dump and instead guessed or sprayed the password; a successful memory-derived credential or hash would normally authenticate on the first attempt rather than after a 143-second failure burst.

**Evidence it cites (5):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `evt-000419` | 2026-08-17 09:28:00+00:00 | FS02 / svc_backup | failure logon [Network (SMB / share access)] from 10.10.20.15 reason=bad_password | yes |
| `evt-000442` | 2026-08-17 09:30:12+00:00 | FS02 / svc_backup | failure logon [Network (SMB / share access)] from 10.10.20.15 reason=bad_password | yes |
| `evt-000444` | 2026-08-17 09:30:23+00:00 | FS02 / svc_backup | failure logon [Network (SMB / share access)] from 10.10.20.15 reason=bad_password | yes |
| `evt-000457` | 2026-08-17 09:33:47+00:00 | FS02 / svc_backup | success logon [Network (SMB / share access)] from 10.10.20.15 | yes |
| `evt-000381` | 2026-08-17 09:18:22+00:00 | PC01 / jdoe | powershell.exe -> rundll32.exe \| rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Users\Public\lsass.dmp full | yes |

**Computed:** 0 of 5 cited ids were not cited on this case by the deterministic pass.

---

## R027

**Case:** `synthetic:INC-001` / `CASE-001` (31 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-009` | MEDIUM | Outlook launched WINWORD.EXE to open a document in a macro-capable format. This is consistent with a malicious attachment being opened, independent of whether any embedded macro subsequently ran. | 1: `evt-000355` |
| `ATH-001` | HIGH | WINWORD.EXE started powershell.exe. Office applications have no routine need to launch script interpreters; this parent/child relationship is consistent with macro-based code execution from a document. | 1: `evt-000357` |
| `ATH-002` | HIGH | PowerShell ran a base64-encoded command. The decoded payload retrieves and executes remote content, which is consistent with a first-stage downloader. Evasion flags observed: hidden window, no profile. | 1: `evt-000357` |
| `ATH-003` | HIGH | powershell.exe made 7 outbound connection(s) to the external address 185.220.101.47 on port(s) 80, 443. Script interpreters do not normally initiate direct internet connections; this may indicate payload retrieval or command-and-control. The connection to port 80 indicates cleartext HTTP, which is commonly used to retrieve a second-stage script. | 7: `evt-000358`, `evt-000362`, `evt-000380`, `evt-000399`, `evt-000421`, `evt-000454`, `evt-000486` |
| `ATH-010` | MEDIUM | 3 distinct discovery commands (net.exe, nltest.exe, whoami.exe) ran from the same parent process (PID 6612) within 34s, consistent with systematic reconnaissance of the local environment and domain. | 3: `evt-000367`, `evt-000370`, `evt-000374` |
| `ATH-004` | CRITICAL | Command line matched credential-access indicators (comsvcs.dll MiniDump, explicit lsass reference, rundll32 MiniDump export). This may indicate an attempt to extract credential material from LSASS memory, which would enable authentication as other users. Requires immediate verification against the account's expected activity. | 1: `evt-000381` |
| `ATH-005` | CRITICAL | 14 failed logons for 'svc_backup' on FS02 from 10.10.20.15 within 143s. A successful logon followed at 09:33:47, 204s after the last failure. This may indicate the credential was successfully guessed and the account is now compromised. | 15: `evt-000419`, `evt-000422`, `evt-000425`, `evt-000427`, `evt-000429`, `evt-000431`, `evt-000432`, `evt-000433`, `evt-000437`, `evt-000438`, `evt-000439`, `evt-000440` ... (+3 more; all of them are in worksheet.csv) |
| `ATH-006` | HIGH | Account 'svc_backup' authenticated to FS02 from PC01, but has no interactive session on PC01 (observed owner(s): jdoe). Credential use originating from a host the account does not operate on is consistent with lateral movement using stolen credentials, though legitimate alternate-credential workflows produce the same pattern. | 1: `evt-000457` |
| `ATH-007` | HIGH | The Service Control Manager started an interactive command interpreter. This pattern is consistent with remote command execution via a temporary service. Command output is redirected to the administrative share '\\127.0.0.1\ADMIN$', which is characteristic of remote execution frameworks collecting results over SMB. | 1: `evt-000461` |
| `ATH-008` | HIGH | An archive utility was invoked and the source path uses a wildcard, implying bulk collection and the destination is a shared staging directory. This is consistent with staging data prior to exfiltration, but does not by itself show that any data left the network. | 1: `evt-000469` |
| `ATH-003` | MEDIUM | powershell.exe made 1 outbound connection(s) to the external address 185.220.101.47 on port(s) 443. Script interpreters do not normally initiate direct internet connections; this may indicate payload retrieval or command-and-control. | 1: `evt-000481` |

**Hypothesis (verbatim):**

> Data staged on disk may have been transferred to the external destination observed in this case. This is unverified: the telemetry records archive creation and outbound connections separately, and does not show the archive's contents leaving.

**Evidence it cites (0):**

_This hypothesis cites no event ids._

---

## R028

**Case:** `comiset` / `CASE-002` (1 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-012` | HIGH | 1 distinct security-control change(s) on desktop-4pvps6e by 'system': a security service was stopped. A single change is often administrative; several in one window is the shape of an attacker clearing the way for what comes next. | 1: `comiset_slice.jsonl:4bdb0f0e83e0a62d3ca40b33ef0d892801fd4d3b` |

**Hypothesis (verbatim):**

> The apparent confinement of the case to a single tactic reflects the narrow scope of the collected slice rather than the true extent of the intrusion; a remote-control tool spawning a SYSTEM shell normally implies preceding initial-access/persistence activity and following actions on objectives that were not captured.

**Evidence it cites (2):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `comiset_slice.jsonl:4bdb0f0e83e0a62d3ca40b33ef0d892801fd4d3b` | 2022-11-19 19:12:55.683000+00:00 | desktop-4pvps6e / system | cmd.exe -> sc.exe \| sc stop windefend | yes |
| `comiset_slice.jsonl:2123df97130430b012740761f3c88c0bbe4bc345` | 2022-11-19 19:00:59.545000+00:00 | desktop-4pvps6e / system | remotemouse.exe -> cmd.exe \| "c:\windows\system32\cmd.exe" | yes |

**Computed:** 0 of 2 cited ids were not cited on this case by the deterministic pass.

---

## R029

**Case:** `flaws_cloud` / `CASE-205` (15 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | MEDIUM | 'Level6' made 563 read calls across 14 distinct services in 463s, 38 of them refused (7%). Breadth on this scale is consistent with account enumeration, and is also exactly what inventory and compliance tooling does. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 14: `cloudtrail-control-1760284`, `cloudtrail-control-1760328`, `cloudtrail-control-1760344`, `cloudtrail-control-1760376`, `cloudtrail-control-1760408`, `cloudtrail-control-1760425`, `cloudtrail-control-1760518`, `cloudtrail-control-1760534`, `cloudtrail-control-1760582`, `cloudtrail-control-1760662`, `cloudtrail-control-1760663`, `cloudtrail-control-1760664` ... (+2 more; all of them are in worksheet.csv) |
| `AWS-004` | MEDIUM | 'Level6' was refused authorization 38 times in 5s, across 3 distinct resource types. Concentrated on so few kinds of object, this is equally the shape of an application missing one permission and retrying. A refusal says what the platform would not do; it does not say what the caller intended. | 3: `cloudtrail-control-1760664`, `cloudtrail-control-1760670`, `cloudtrail-control-1760671` |

**Hypothesis (verbatim):**

> sts:GetCallerIdentity carries the highest event identifier in the set, meaning the caller resolved its own principal at or near the END of the sweep rather than the beginning. Legitimate scanners and SDK sessions typically resolve identity first; establishing identity only after discovering which services respond is more consistent with an operator or tool confirming the provenance of a credential whose owner was not known in advance.

**Evidence it cites (3):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1760846` | 2020-06-01 19:29:37+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 get sts:caller-identity [allowed] | yes |
| `cloudtrail-control-1760284` | 2020-06-01 19:28:15+00:00 | aws:811596193553/ap-southeast-2 / Level6 | Level6 describe ec2:network-interface [allowed] | yes |
| `cloudtrail-control-1760671` | 2020-06-01 19:29:17+00:00 | aws:811596193553/ap-south-1 / Level6 | Level6 list sns:subscription [denied] | yes |

**Computed:** 0 of 3 cited ids were not cited on this case by the deterministic pass.

---

## R030

**Case:** `flaws_cloud` / `CASE-067` (1 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-002` | CRITICAL | 'Level6' stopped CloudTrail trail ''. Disabling the audit trail is not a routine operational action and is consistent with an intruder removing the record of subsequent activity. | 1: `cloudtrail-control-226797` |

**Hypothesis (verbatim):**

> The single-event case timeline (a 0-second window on 2019-06-07) understates the true incident scope; the actual intrusion likely extends both before the trail-stop (authentication attempts) and after it (unlogged activity), so the timeline should be treated as a visibility artifact rather than a bound on attacker dwell time.

**Evidence it cites (2):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-226797` | 2019-06-07 11:04:25+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 stop cloudtrail:logging [denied] | yes |
| `cloudtrail-logon-000144` | 2017-02-28 07:58:45+00:00 | aws:811596193553/us-east-1 / Level6 | success logon [Unknown] from 137.53.124.9 | NO |

**Computed:** 1 of 2 cited ids were not cited on this case by the deterministic pass.

---

## R031

**Case:** `flaws_cloud` / `CASE-077` (15 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-004` | HIGH | 'Level6' was refused authorization 772 times in 221s, across 15 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 15: `cloudtrail-control-238972`, `cloudtrail-control-238973`, `cloudtrail-control-238974`, `cloudtrail-control-238975`, `cloudtrail-control-238977`, `cloudtrail-control-238978`, `cloudtrail-control-238979`, `cloudtrail-control-238980`, `cloudtrail-control-238981`, `cloudtrail-control-238982`, `cloudtrail-control-238983`, `cloudtrail-control-238984` ... (+3 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The principal name 'Level6', the target bucket 'flaws.cloud', and the created bucket name 'pwnd' together are more consistent with a deliberate security-training or capture-the-flag exercise than with an unsanctioned intrusion. If confirmed, the authorization-refusal pattern is expected behaviour of the exercise rather than an incident.

**Evidence it cites (2):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-238972` | 2019-06-21 15:43:30+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-tagging (flaws.cloud) [denied] | yes |
| `cloudtrail-control-239755` | 2019-06-21 15:47:08+00:00 | aws:811596193553/us-west-1 / Level6 | Level6 create s3:bucket (pwnd) [denied] | yes |

**Computed:** 0 of 2 cited ids were not cited on this case by the deterministic pass.

---

## R032

**Case:** `synthetic:INC-001` / `CASE-001` (31 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-009` | MEDIUM | Outlook launched WINWORD.EXE to open a document in a macro-capable format. This is consistent with a malicious attachment being opened, independent of whether any embedded macro subsequently ran. | 1: `evt-000355` |
| `ATH-001` | HIGH | WINWORD.EXE started powershell.exe. Office applications have no routine need to launch script interpreters; this parent/child relationship is consistent with macro-based code execution from a document. | 1: `evt-000357` |
| `ATH-002` | HIGH | PowerShell ran a base64-encoded command. The decoded payload retrieves and executes remote content, which is consistent with a first-stage downloader. Evasion flags observed: hidden window, no profile. | 1: `evt-000357` |
| `ATH-003` | HIGH | powershell.exe made 7 outbound connection(s) to the external address 185.220.101.47 on port(s) 80, 443. Script interpreters do not normally initiate direct internet connections; this may indicate payload retrieval or command-and-control. The connection to port 80 indicates cleartext HTTP, which is commonly used to retrieve a second-stage script. | 7: `evt-000358`, `evt-000362`, `evt-000380`, `evt-000399`, `evt-000421`, `evt-000454`, `evt-000486` |
| `ATH-010` | MEDIUM | 3 distinct discovery commands (net.exe, nltest.exe, whoami.exe) ran from the same parent process (PID 6612) within 34s, consistent with systematic reconnaissance of the local environment and domain. | 3: `evt-000367`, `evt-000370`, `evt-000374` |
| `ATH-004` | CRITICAL | Command line matched credential-access indicators (comsvcs.dll MiniDump, explicit lsass reference, rundll32 MiniDump export). This may indicate an attempt to extract credential material from LSASS memory, which would enable authentication as other users. Requires immediate verification against the account's expected activity. | 1: `evt-000381` |
| `ATH-005` | CRITICAL | 14 failed logons for 'svc_backup' on FS02 from 10.10.20.15 within 143s. A successful logon followed at 09:33:47, 204s after the last failure. This may indicate the credential was successfully guessed and the account is now compromised. | 15: `evt-000419`, `evt-000422`, `evt-000425`, `evt-000427`, `evt-000429`, `evt-000431`, `evt-000432`, `evt-000433`, `evt-000437`, `evt-000438`, `evt-000439`, `evt-000440` ... (+3 more; all of them are in worksheet.csv) |
| `ATH-006` | HIGH | Account 'svc_backup' authenticated to FS02 from PC01, but has no interactive session on PC01 (observed owner(s): jdoe). Credential use originating from a host the account does not operate on is consistent with lateral movement using stolen credentials, though legitimate alternate-credential workflows produce the same pattern. | 1: `evt-000457` |
| `ATH-007` | HIGH | The Service Control Manager started an interactive command interpreter. This pattern is consistent with remote command execution via a temporary service. Command output is redirected to the administrative share '\\127.0.0.1\ADMIN$', which is characteristic of remote execution frameworks collecting results over SMB. | 1: `evt-000461` |
| `ATH-008` | HIGH | An archive utility was invoked and the source path uses a wildcard, implying bulk collection and the destination is a shared staging directory. This is consistent with staging data prior to exfiltration, but does not by itself show that any data left the network. | 1: `evt-000469` |
| `ATH-003` | MEDIUM | powershell.exe made 1 outbound connection(s) to the external address 185.220.101.47 on port(s) 443. Script interpreters do not normally initiate direct internet connections; this may indicate payload retrieval or command-and-control. | 1: `evt-000481` |

**Hypothesis (verbatim):**

> The svc_backup password-guessing burst may have been seeded by material recovered from the PC01 LSASS dump (e.g. a cached username or stale password), which would explain why guessing targeted this one service account rather than many accounts. Unverified: no telemetry ties the dump output to the authentication attempts.

**Evidence it cites (5):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `evt-000381` | 2026-08-17 09:18:22+00:00 | PC01 / jdoe | powershell.exe -> rundll32.exe \| rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Users\Public\lsass.dmp full | yes |
| `evt-000419` | 2026-08-17 09:28:00+00:00 | FS02 / svc_backup | failure logon [Network (SMB / share access)] from 10.10.20.15 reason=bad_password | yes |
| `evt-000422` | 2026-08-17 09:28:11+00:00 | FS02 / svc_backup | failure logon [Network (SMB / share access)] from 10.10.20.15 reason=bad_password | yes |
| `evt-000444` | 2026-08-17 09:30:23+00:00 | FS02 / svc_backup | failure logon [Network (SMB / share access)] from 10.10.20.15 reason=bad_password | yes |
| `evt-000457` | 2026-08-17 09:33:47+00:00 | FS02 / svc_backup | success logon [Network (SMB / share access)] from 10.10.20.15 | yes |

**Computed:** 0 of 5 cited ids were not cited on this case by the deterministic pass.

---

## R033

**Case:** `synthetic:INC-005` / `CASE-001` (2 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `K8S-001` | HIGH | 'system:serviceaccount:ci:ci-deployer' created clusterrolebindings 'ci-runner-escalation', granting the maximally-privileged role 'cluster-admin' to 'system:serviceaccount:ci:ci-runner'. Very few legitimate workloads need this level of access, and the grantor is not a superuser, so this grant confers standing the grantor did not itself hold; it is worth review even when the grantor is an ordinary ... (full text in worksheet.csv) | 1: `k8s-control-000003` |
| `K8S-002` | CRITICAL | 'system:serviceaccount:ci:ci-runner' was granted the 'cluster-admin' role 149s before exec'ing into pod 'web-1' (namespace 'prod'). A freshly-escalated identity acting on that escalation shortly after receiving it is consistent with the grant being used for exploration or post-exploitation access rather than left dormant. | 2: `k8s-control-000003`, `k8s-control-000004` |

**Hypothesis (verbatim):**

> The ~149s delay between grant and exec is consistent with scripted or semi-automated tooling executing a prepared escalation sequence, rather than interactive human exploration, which typically shows more variable and longer intervals.

**Evidence it cites (2):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `k8s-control-000003` | 2026-08-17 09:20:00.040000+00:00 | k8s:test-cluster / system:serviceaccount:ci:ci-runner | system:serviceaccount:ci:ci-deployer create clusterrolebindings (ci-runner-escalation) -> system:serviceaccount:ci:ci-runner [allowed] | yes |
| `k8s-control-000004` | 2026-08-17 09:22:30.015000+00:00 | k8s:test-cluster / system:serviceaccount:ci:ci-runner | system:serviceaccount:ci:ci-runner exec pods/exec (web-1) [allowed] | yes |

**Computed:** 0 of 2 cited ids were not cited on this case by the deterministic pass.

---

## R034

**Case:** `flaws_cloud` / `CASE-066` (1 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-002` | CRITICAL | 'Level6' stopped CloudTrail trail ''. Disabling the audit trail is not a routine operational action and is consistent with an intruder removing the record of subsequent activity. | 1: `cloudtrail-control-226796` |

**Hypothesis (verbatim):**

> The complete absence of resolved source addresses across all 5346 authentication events suggests either systematic source-IP redaction/normalisation loss in the ingestion pipeline or attacker use of AWS-internal/API-gateway paths; this gap, not attacker sophistication, is the primary blocker to attribution and should be treated as a collection defect to remediate.

**Evidence it cites (4):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-000144` | 2017-02-28 07:58:45+00:00 | aws:811596193553/us-east-1 / Level6 | success logon [Unknown] from 137.53.124.9 | NO |
| `cloudtrail-logon-017044` | 2018-01-18 20:26:38+00:00 | aws:811596193553/us-east-1 / Level6 | success logon [Unknown] from 250.253.254.5 | NO |
| `cloudtrail-logon-040037` | 2018-12-09 23:02:01+00:00 | aws:811596193553/us-east-1 / Level6 | failure logon [Unknown] from 5.1.242.5 reason=Not authorized to perform sts:AssumeRole | NO |
| `cloudtrail-logon-079347` | 2020-10-06 17:35:07+00:00 | aws:811596193553/us-east-1 / Level6 | failure logon [Unknown] from 0.0.58.4 reason=User: arn:aws:iam::811596193553:user/Level6 is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/service-role/Level6 | NO |

**Computed:** 4 of 4 cited ids were not cited on this case by the deterministic pass.

---

## R035

**Case:** `synthetic:INC-004` / `CASE-001` (6 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-012` | CRITICAL | 3 distinct security-control change(s) on PC03 by 'achen': Defender real-time monitoring disabled; a Defender scanning exclusion was added; a security product process was terminated. A single change is often administrative; several in one window is the shape of an attacker clearing the way for what comes next. | 3: `evt-000901`, `evt-000905`, `evt-000909` |
| `ATH-011` | CRITICAL | 3 distinct recovery control(s) were destroyed on PC03 by 'achen': Windows backup catalog deleted; boot-time recovery disabled; volume shadow copies deleted. Destroying recovery paths removes the ability to roll back and commonly immediately precedes encryption. | 3: `evt-000922`, `evt-000925`, `evt-000927` |

**Hypothesis (verbatim):**

> An encryption/impact payload likely executed on PC03 immediately after 2026-08-17T11:15:40Z; the case currently ends at the last recovery-destruction event, so telemetry after that timestamp (file-write bursts, ransom note creation, mass renames) should be pulled to confirm or rule out completed impact.

**Evidence it cites (3):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `evt-000922` | 2026-08-17 11:14:30+00:00 | PC03 / achen | cmd.exe -> vssadmin.exe \| vssadmin.exe delete shadows /all /quiet | yes |
| `evt-000925` | 2026-08-17 11:15:05+00:00 | PC03 / achen | cmd.exe -> wbadmin.exe \| wbadmin.exe delete catalog -quiet | yes |
| `evt-000927` | 2026-08-17 11:15:40+00:00 | PC03 / achen | cmd.exe -> bcdedit.exe \| bcdedit.exe /set {default} recoveryenabled no | yes |

**Computed:** 0 of 3 cited ids were not cited on this case by the deterministic pass.

---

## R036

**Case:** `synthetic:INC-005` / `CASE-001` (2 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `K8S-001` | HIGH | 'system:serviceaccount:ci:ci-deployer' created clusterrolebindings 'ci-runner-escalation', granting the maximally-privileged role 'cluster-admin' to 'system:serviceaccount:ci:ci-runner'. Very few legitimate workloads need this level of access, and the grantor is not a superuser, so this grant confers standing the grantor did not itself hold; it is worth review even when the grantor is an ordinary ... (full text in worksheet.csv) | 1: `k8s-control-000003` |
| `K8S-002` | CRITICAL | 'system:serviceaccount:ci:ci-runner' was granted the 'cluster-admin' role 149s before exec'ing into pod 'web-1' (namespace 'prod'). A freshly-escalated identity acting on that escalation shortly after receiving it is consistent with the grant being used for exploration or post-exploitation access rather than left dormant. | 2: `k8s-control-000003`, `k8s-control-000004` |

**Hypothesis (verbatim):**

> The exec into a production pod was plausibly aimed at credential or secret harvesting (mounted service account tokens, environment variables, or mounted Secret volumes inside 'web-1'), which would extend the chain from Execution/Persistence into Credential Access; validating this requires in-container process and file-read telemetry not present in the current evidence.

**Evidence it cites (1):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `k8s-control-000004` | 2026-08-17 09:22:30.015000+00:00 | k8s:test-cluster / system:serviceaccount:ci:ci-runner | system:serviceaccount:ci:ci-runner exec pods/exec (web-1) [allowed] | yes |

**Computed:** 0 of 1 cited ids were not cited on this case by the deterministic pass.

---

## R037

**Case:** `flaws_cloud` / `CASE-118` (1 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-002` | CRITICAL | 'flaws' deleted CloudTrail trail 'arn:aws:cloudtrail:us-west-2:811596193553:trail/cloudtrail'. Disabling the audit trail is not a routine operational action and is consistent with an intruder removing the record of subsequent activity. | 1: `cloudtrail-control-1576322` |

**Hypothesis (verbatim):**

> The identity name 'flaws' and the us-west-2 region are consistent with the flaws.cloud deliberately-vulnerable AWS training environment, meaning this may be sanctioned exercise traffic rather than a genuine intrusion. Confirming account 811596193553's ownership and purpose should precede escalation.

**Evidence it cites (1):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1576322` | 2019-08-23 15:48:50+00:00 | aws:811596193553/us-west-2 / flaws | flaws delete cloudtrail:trail (arn:aws:cloudtrail:us-west-2:811596193553:trail/cloudtrail) [allowed] | yes |

**Computed:** 0 of 1 cited ids were not cited on this case by the deterministic pass.

---

## R038

**Case:** `flaws_cloud` / `CASE-118` (1 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-002` | CRITICAL | 'flaws' deleted CloudTrail trail 'arn:aws:cloudtrail:us-west-2:811596193553:trail/cloudtrail'. Disabling the audit trail is not a routine operational action and is consistent with an intruder removing the record of subsequent activity. | 1: `cloudtrail-control-1576322` |

**Hypothesis (verbatim):**

> The trail deletion is preparatory rather than terminal — it precedes a higher-impact objective (credential harvesting, data exfiltration from S3, or resource hijacking for cryptomining) that the actor expected to be logged. Testing requires pivoting to log sources independent of the deleted trail (S3 server access logs, VPC flow logs, GuardDuty, billing/usage anomalies).

**Evidence it cites (1):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1576322` | 2019-08-23 15:48:50+00:00 | aws:811596193553/us-west-2 / flaws | flaws delete cloudtrail:trail (arn:aws:cloudtrail:us-west-2:811596193553:trail/cloudtrail) [allowed] | yes |

**Computed:** 0 of 1 cited ids were not cited on this case by the deterministic pass.

---

## R039

**Case:** `synthetic:INC-005` / `CASE-001` (2 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `K8S-001` | HIGH | 'system:serviceaccount:ci:ci-deployer' created clusterrolebindings 'ci-runner-escalation', granting the maximally-privileged role 'cluster-admin' to 'system:serviceaccount:ci:ci-runner'. Very few legitimate workloads need this level of access, and the grantor is not a superuser, so this grant confers standing the grantor did not itself hold; it is worth review even when the grantor is an ordinary ... (full text in worksheet.csv) | 1: `k8s-control-000003` |
| `K8S-002` | CRITICAL | 'system:serviceaccount:ci:ci-runner' was granted the 'cluster-admin' role 149s before exec'ing into pod 'web-1' (namespace 'prod'). A freshly-escalated identity acting on that escalation shortly after receiving it is consistent with the grant being used for exploration or post-exploitation access rather than left dormant. | 2: `k8s-control-000003`, `k8s-control-000004` |

**Hypothesis (verbatim):**

> The ClusterRoleBinding 'ci-runner-escalation' likely persists after the exec activity, since no revocation or deletion event appears among the verified claims; if so, ci-runner retains cluster-admin and the cluster remains in a compromised-authorization state independent of any containment applied to the exec session.

**Evidence it cites (2):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `k8s-control-000003` | 2026-08-17 09:20:00.040000+00:00 | k8s:test-cluster / system:serviceaccount:ci:ci-runner | system:serviceaccount:ci:ci-deployer create clusterrolebindings (ci-runner-escalation) -> system:serviceaccount:ci:ci-runner [allowed] | yes |
| `k8s-control-000004` | 2026-08-17 09:22:30.015000+00:00 | k8s:test-cluster / system:serviceaccount:ci:ci-runner | system:serviceaccount:ci:ci-runner exec pods/exec (web-1) [allowed] | yes |

**Computed:** 0 of 2 cited ids were not cited on this case by the deterministic pass.

---

## R040

**Case:** `attack_data_aws` / `CASE-001` (32 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | HIGH | 'cloudsploit' made 2164 read calls across 49 distinct services in 233s, 2072 of them refused for want of authority (96%). Breadth with no permission behind it is enumeration rather than administration. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 20: `cloudtrail-control-002337`, `cloudtrail-control-001181`, `cloudtrail-control-001182`, `cloudtrail-control-002326`, `cloudtrail-control-001156`, `cloudtrail-control-001170`, `cloudtrail-control-001108`, `cloudtrail-control-001115`, `cloudtrail-control-002281`, `cloudtrail-control-002247`, `cloudtrail-control-002231`, `cloudtrail-control-000942` ... (+8 more; all of them are in worksheet.csv) |
| `AWS-004` | HIGH | 'cloudsploit' was refused authorization 2092 times in 233s, across 100 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 20: `cloudtrail-control-002337`, `cloudtrail-control-001182`, `cloudtrail-control-002326`, `cloudtrail-control-001156`, `cloudtrail-control-001160`, `cloudtrail-control-001161`, `cloudtrail-control-001162`, `cloudtrail-control-001165`, `cloudtrail-control-001166`, `cloudtrail-control-001167`, `cloudtrail-control-001168`, `cloudtrail-control-001170` ... (+8 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The principal name 'cloudsploit' matches the open-source CloudSploit cloud security auditing scanner, whose normal behaviour is exactly a broad read-only sweep across every service with many AccessDenied responses; the episode may therefore be an authorised configuration scan rather than adversary reconnaissance, and identity ownership should be checked before escalation.

**Evidence it cites (4):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-002337` | 2021-04-13 11:32:51+00:00 | aws:731544447609/eu-central-1 / cloudsploit | cloudsploit list acm:certificate [denied] | yes |
| `cloudtrail-control-002326` | 2021-04-13 11:32:52+00:00 | aws:731544447609/us-east-1 / cloudsploit | cloudsploit list cloudfront:distribution [denied] | yes |
| `cloudtrail-control-001156` | 2021-04-13 11:32:53+00:00 | aws:111111111111/us-east-1 / cloudsploit | cloudsploit describe ec2:volume [denied] | yes |
| `cloudtrail-control-001170` | 2021-04-13 11:32:53+00:00 | aws:111111111111/us-east-1 / cloudsploit | cloudsploit describe config:configuration-recorder [denied] | yes |

**Computed:** 0 of 4 cited ids were not cited on this case by the deterministic pass.

---

## R041

**Case:** `flaws_cloud` / `CASE-219` (28 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | HIGH | 'i-aa2d3b42e5c6e801a' made 2712 read calls across 105 distinct services in 580s, 2637 of them refused for want of authority (97%). Breadth with no permission behind it is enumeration rather than administration. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 20: `cloudtrail-control-1776510`, `cloudtrail-control-1776511`, `cloudtrail-control-1776513`, `cloudtrail-control-1776514`, `cloudtrail-control-1776515`, `cloudtrail-control-1776516`, `cloudtrail-control-1776517`, `cloudtrail-control-1776518`, `cloudtrail-control-1776521`, `cloudtrail-control-1776522`, `cloudtrail-control-1776524`, `cloudtrail-control-1776525` ... (+8 more; all of them are in worksheet.csv) |
| `AWS-004` | HIGH | 'i-aa2d3b42e5c6e801a' was refused authorization 2637 times in 580s, across 621 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 20: `cloudtrail-control-1776510`, `cloudtrail-control-1776513`, `cloudtrail-control-1776514`, `cloudtrail-control-1776515`, `cloudtrail-control-1776516`, `cloudtrail-control-1776517`, `cloudtrail-control-1776518`, `cloudtrail-control-1776519`, `cloudtrail-control-1776520`, `cloudtrail-control-1776522`, `cloudtrail-control-1776523`, `cloudtrail-control-1776524` ... (+8 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The service list touched (snowball, mediaconnect, mediapackage, rekognition, gamelift, iotanalytics, datapipeline, amplify, appsync, route53domains) spans domains that a single application workload would almost never legitimately use together, which fits a fixed enumeration wordlist from off-the-shelf cloud recon tooling (e.g. Pacu, ScoutSuite, cloudfox) executed from the instance.

**Evidence it cites (11):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1776510` | 2020-06-11 21:47:49+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a list snowball:cluster [denied] | yes |
| `cloudtrail-control-1776511` | 2020-06-11 21:47:49+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a list mediaconnect:entitlement [failed] | yes |
| `cloudtrail-control-1776515` | 2020-06-11 21:47:50+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a list rekognition:collection [denied] | yes |
| `cloudtrail-control-1776516` | 2020-06-11 21:47:50+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a list mediapackage:channel [denied] | yes |
| `cloudtrail-control-1776522` | 2020-06-11 21:47:50+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a describe gamelift:vpc-peering-authorization [denied] | yes |
| `cloudtrail-control-1776527` | 2020-06-11 21:47:50+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a list gamelift:fleet [denied] | yes |
| `cloudtrail-control-1776545` | 2020-06-11 21:47:51+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a list appsync:graphql-apis [denied] | yes |
| `cloudtrail-control-1776552` | 2020-06-11 21:47:51+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a list amplify:app [denied] | yes |
| `cloudtrail-control-1776556` | 2020-06-11 21:47:51+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a list route53domains:domain [denied] | yes |
| `cloudtrail-control-1776571` | 2020-06-11 21:47:52+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a list datapipeline:pipeline [denied] | yes |
| `cloudtrail-control-1776597` | 2020-06-11 21:47:53+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a list iotanalytics:datastore [denied] | yes |

**Computed:** 0 of 11 cited ids were not cited on this case by the deterministic pass.

---

## R042

**Case:** `flaws_cloud` / `CASE-118` (1 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-002` | CRITICAL | 'flaws' deleted CloudTrail trail 'arn:aws:cloudtrail:us-west-2:811596193553:trail/cloudtrail'. Disabling the audit trail is not a routine operational action and is consistent with an intruder removing the record of subsequent activity. | 1: `cloudtrail-control-1576322` |

**Hypothesis (verbatim):**

> The principal 'flaws' held IAM permissions including cloudtrail:DeleteTrail, which is an administrative-grade privilege; either the identity was over-provisioned by design or a prior, unlogged privilege-escalation step occurred. Reviewing the IAM policy attached to 'flaws' and any preceding AttachUserPolicy/CreateAccessKey events would discriminate between these.

**Evidence it cites (1):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1576322` | 2019-08-23 15:48:50+00:00 | aws:811596193553/us-west-2 / flaws | flaws delete cloudtrail:trail (arn:aws:cloudtrail:us-west-2:811596193553:trail/cloudtrail) [allowed] | yes |

**Computed:** 0 of 1 cited ids were not cited on this case by the deterministic pass.

---

## R043

**Case:** `flaws_cloud` / `CASE-113` (5 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-004` | HIGH | 'Level6' was refused authorization 918 times in 598s, across 5 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 5: `cloudtrail-control-323923`, `cloudtrail-control-323928`, `cloudtrail-control-323933`, `cloudtrail-control-323942`, `cloudtrail-control-323974` |

**Hypothesis (verbatim):**

> The creation of a default VPC immediately before running an instance suggests the target region had no usable network prior to this activity, implying the region was previously unused by the organisation and was selected for that reason rather than for a business need. If true, the activity is unlikely to be legitimate operations.

**Evidence it cites (2):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-323942` | 2019-08-21 07:41:25+00:00 | aws:811596193553/ap-northeast-2 / Level6 | Level6 create ec2:default-vpc [denied] | yes |
| `cloudtrail-control-323974` | 2019-08-21 07:41:30+00:00 | aws:811596193553/ap-northeast-2 / Level6 | Level6 run ec2:instance [denied] | yes |

**Computed:** 0 of 2 cited ids were not cited on this case by the deterministic pass.

---

## R044

**Case:** `flaws_cloud` / `CASE-066` (1 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-002` | CRITICAL | 'Level6' stopped CloudTrail trail ''. Disabling the audit trail is not a routine operational action and is consistent with an intruder removing the record of subsequent activity. | 1: `cloudtrail-control-226796` |

**Hypothesis (verbatim):**

> The 'Level6' principal held permissions sufficient to alter trail configuration (cloudtrail:StopLogging / DeleteTrail), implying either a highly privileged administrative identity or a prior privilege-escalation step that is not represented in the current evidence; enumerating how that principal obtained those rights is a gap in the timeline.

**Evidence it cites (1):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-226796` | 2019-06-07 11:04:25+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 stop cloudtrail:logging [denied] | yes |

**Computed:** 0 of 1 cited ids were not cited on this case by the deterministic pass.

---

## R045

**Case:** `flaws_cloud` / `CASE-113` (5 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-004` | HIGH | 'Level6' was refused authorization 918 times in 598s, across 5 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 5: `cloudtrail-control-323923`, `cloudtrail-control-323928`, `cloudtrail-control-323933`, `cloudtrail-control-323942`, `cloudtrail-control-323974` |

**Hypothesis (verbatim):**

> The terminal step of the chain is compute instantiation with an attacker-controlled SSH key pair in a freshly created network, which fits resource hijacking (T1496) or the staging of an interactive foothold rather than Discovery alone. The case's single-tactic Discovery labelling may therefore understate the objective.

**Evidence it cites (3):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-323933` | 2019-08-21 07:41:24+00:00 | aws:811596193553/ap-northeast-2 / Level6 | Level6 create ec2:key-pair (811596193553_ap-northeast-2_my_key_pair) [denied] | yes |
| `cloudtrail-control-323942` | 2019-08-21 07:41:25+00:00 | aws:811596193553/ap-northeast-2 / Level6 | Level6 create ec2:default-vpc [denied] | yes |
| `cloudtrail-control-323974` | 2019-08-21 07:41:30+00:00 | aws:811596193553/ap-northeast-2 / Level6 | Level6 run ec2:instance [denied] | yes |

**Computed:** 0 of 3 cited ids were not cited on this case by the deterministic pass.

---

## R046

**Case:** `flaws_cloud` / `CASE-077` (15 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-004` | HIGH | 'Level6' was refused authorization 772 times in 221s, across 15 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 15: `cloudtrail-control-238972`, `cloudtrail-control-238973`, `cloudtrail-control-238974`, `cloudtrail-control-238975`, `cloudtrail-control-238977`, `cloudtrail-control-238978`, `cloudtrail-control-238979`, `cloudtrail-control-238980`, `cloudtrail-control-238981`, `cloudtrail-control-238982`, `cloudtrail-control-238983`, `cloudtrail-control-238984` ... (+3 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The same principal is active in at least two regions (authentication observed in both us-east-1 and us-west-2) while the denial burst is confined to us-west-2, so equivalent enumeration may have occurred in us-east-1 and either succeeded quietly or was not captured by the AWS-004 detector; a cross-region review of Level6 control-plane calls is warranted before scoping the case to one region.

**Evidence it cites (3):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-000144` | 2017-02-28 07:58:45+00:00 | aws:811596193553/us-east-1 / Level6 | success logon [Unknown] from 137.53.124.9 | NO |
| `cloudtrail-control-238972` | 2019-06-21 15:43:30+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-tagging (flaws.cloud) [denied] | yes |
| `cloudtrail-control-238986` | 2019-06-21 15:43:30+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-encryption (flaws.cloud) [denied] | yes |

**Computed:** 1 of 3 cited ids were not cited on this case by the deterministic pass.

---

## R047

**Case:** `flaws_cloud` / `CASE-066` (1 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-002` | CRITICAL | 'Level6' stopped CloudTrail trail ''. Disabling the audit trail is not a routine operational action and is consistent with an intruder removing the record of subsequent activity. | 1: `cloudtrail-control-226796` |

**Hypothesis (verbatim):**

> Defense impairment is rarely an end goal, so the logging stop is likely a precursor step taken to shield follow-on actions; investigation should pivot to non-CloudTrail sources (VPC flow logs, S3 server access logs, GuardDuty, billing/usage anomalies) for the window beginning at the stop event.

**Evidence it cites (1):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-226796` | 2019-06-07 11:04:25+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 stop cloudtrail:logging [denied] | yes |

**Computed:** 0 of 1 cited ids were not cited on this case by the deterministic pass.

---

## R048

**Case:** `synthetic:INC-002` / `CASE-001` (13 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-005` | CRITICAL | 12 failed logons for 'dev_alice' on aws:123456789012/us-east-1 from 203.0.113.42 within 220s. A successful logon followed at 09:16:30, 50s after the last failure. This may indicate the credential was successfully guessed and the account is now compromised. | 13: `cloudtrail-logon-000002`, `cloudtrail-logon-000003`, `cloudtrail-logon-000004`, `cloudtrail-logon-000005`, `cloudtrail-logon-000006`, `cloudtrail-logon-000007`, `cloudtrail-logon-000008`, `cloudtrail-logon-000009`, `cloudtrail-logon-000010`, `cloudtrail-logon-000011`, `cloudtrail-logon-000012`, `cloudtrail-logon-000013` ... (+1 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> Twelve attempts is a very small number for blind password guessing, so the adversary more likely worked from a short candidate list (prior-breach credentials, a predictable pattern, or partial knowledge of the password) than from an untargeted dictionary; this would imply prior reconnaissance or an external credential-dump source.

**Evidence it cites (4):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-000002` | 2026-08-17 09:12:00+00:00 | aws:123456789012/us-east-1 / dev_alice | failure logon [Unknown] from 203.0.113.42 reason=Failed authentication | yes |
| `cloudtrail-logon-000003` | 2026-08-17 09:12:20+00:00 | aws:123456789012/us-east-1 / dev_alice | failure logon [Unknown] from 203.0.113.42 reason=Failed authentication | yes |
| `cloudtrail-logon-000013` | 2026-08-17 09:15:40+00:00 | aws:123456789012/us-east-1 / dev_alice | failure logon [Unknown] from 203.0.113.42 reason=Failed authentication | yes |
| `cloudtrail-logon-000014` | 2026-08-17 09:16:30+00:00 | aws:123456789012/us-east-1 / dev_alice | success logon [Unknown] from 203.0.113.42 | yes |

**Computed:** 0 of 4 cited ids were not cited on this case by the deterministic pass.

---

## R049

**Case:** `flaws_cloud` / `CASE-077` (15 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-004` | HIGH | 'Level6' was refused authorization 772 times in 221s, across 15 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 15: `cloudtrail-control-238972`, `cloudtrail-control-238973`, `cloudtrail-control-238974`, `cloudtrail-control-238975`, `cloudtrail-control-238977`, `cloudtrail-control-238978`, `cloudtrail-control-238979`, `cloudtrail-control-238980`, `cloudtrail-control-238981`, `cloudtrail-control-238982`, `cloudtrail-control-238983`, `cloudtrail-control-238984` ... (+3 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The overwhelming authentication failure ratio for 'Level6' (5285 of 5346, ~98.9%) is more likely a chronic background condition of this account (misconfigured automation, expired or rotated credential retried in a loop) than a targeted credential-guessing campaign tied to the 221s denial burst, because failure volume of that scale is not concentrated in the case window.

**Evidence it cites (4):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-000144` | 2017-02-28 07:58:45+00:00 | aws:811596193553/us-east-1 / Level6 | success logon [Unknown] from 137.53.124.9 | NO |
| `cloudtrail-logon-000196` | 2017-03-01 21:50:25+00:00 | aws:811596193553/us-east-1 / Level6 | failure logon [Unknown] from 255.55.224.253 reason=User: arn:aws:iam::811596193553:user/Level6 is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/flaws | NO |
| `cloudtrail-logon-079346` | 2020-10-06 17:28:09+00:00 | aws:811596193553/us-east-1 / Level6 | success logon [Unknown] from 0.0.58.4 | NO |
| `cloudtrail-logon-079347` | 2020-10-06 17:35:07+00:00 | aws:811596193553/us-east-1 / Level6 | failure logon [Unknown] from 0.0.58.4 reason=User: arn:aws:iam::811596193553:user/Level6 is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/service-role/Level6 | NO |

**Computed:** 4 of 4 cited ids were not cited on this case by the deterministic pass.

---

## R050

**Case:** `flaws_cloud` / `CASE-067` (1 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-002` | CRITICAL | 'Level6' stopped CloudTrail trail ''. Disabling the audit trail is not a routine operational action and is consistent with an intruder removing the record of subsequent activity. | 1: `cloudtrail-control-226797` |

**Hypothesis (verbatim):**

> An alternative benign explanation is that 'Level6' is an automation, IaC, or administrative role performing a sanctioned trail reconfiguration or cost-reduction change; this can be distinguished by checking whether a replacement trail was created shortly afterwards and whether a change-management ticket exists.

**Evidence it cites (1):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-226797` | 2019-06-07 11:04:25+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 stop cloudtrail:logging [denied] | yes |

**Computed:** 0 of 1 cited ids were not cited on this case by the deterministic pass.

---

## R051

**Case:** `flaws_cloud` / `CASE-005` (54 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-005` | CRITICAL | 53 failed logons for 'SecurityMokey' on aws:811596193553/us-east-1 from 255.253.125.115 within 247s. A successful logon followed at 22:26:48, -148s after the last failure. This may indicate the credential was successfully guessed and the account is now compromised. | 54: `cloudtrail-logon-002652`, `cloudtrail-logon-002653`, `cloudtrail-logon-002654`, `cloudtrail-logon-002655`, `cloudtrail-logon-002656`, `cloudtrail-logon-002657`, `cloudtrail-logon-002658`, `cloudtrail-logon-002659`, `cloudtrail-logon-002660`, `cloudtrail-logon-002661`, `cloudtrail-logon-002665`, `cloudtrail-logon-002664` ... (+42 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The account name 'SecurityMokey' appears to be a misspelling of a security-tooling/automation identity; if so it likely carries elevated or broad read permissions, which would make successful credential guessing disproportionately impactful and should be confirmed against the IAM policy attached to the principal.

**Evidence it cites (3):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-002652` | 2017-05-26 22:25:09+00:00 | aws:811596193553/us-east-1 / SecurityMokey | failure logon [Unknown] from 255.253.125.115 reason=User: arn:aws:iam::811596193553:user/SecurityMokey is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/SecurityMonkey | yes |
| `cloudtrail-logon-002822` | 2017-05-26 22:29:16+00:00 | aws:811596193553/us-east-1 / SecurityMokey | failure logon [Unknown] from 255.253.125.115 reason=User: arn:aws:iam::811596193553:user/SecurityMokey is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/SecurityMonkey | yes |
| `cloudtrail-logon-007195` | 2017-05-27 15:15:15+00:00 | aws:811596193553/us-east-1 / SecurityMokey | success logon [Unknown] from 255.253.125.115 | yes |

**Computed:** 0 of 3 cited ids were not cited on this case by the deterministic pass.

---

## R052

**Case:** `flaws_cloud` / `CASE-005` (54 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-005` | CRITICAL | 53 failed logons for 'SecurityMokey' on aws:811596193553/us-east-1 from 255.253.125.115 within 247s. A successful logon followed at 22:26:48, -148s after the last failure. This may indicate the credential was successfully guessed and the account is now compromised. | 54: `cloudtrail-logon-002652`, `cloudtrail-logon-002653`, `cloudtrail-logon-002654`, `cloudtrail-logon-002655`, `cloudtrail-logon-002656`, `cloudtrail-logon-002657`, `cloudtrail-logon-002658`, `cloudtrail-logon-002659`, `cloudtrail-logon-002660`, `cloudtrail-logon-002661`, `cloudtrail-logon-002665`, `cloudtrail-logon-002664` ... (+42 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> An account averaging thousands of successful authentications with a brief interleaved burst of failures is more consistent with an automated client or service principal hitting a transient credential/rotation or throttling error than with an external password-guessing campaign; the T1110.001 mapping may be a false positive.

**Evidence it cites (3):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-002652` | 2017-05-26 22:25:09+00:00 | aws:811596193553/us-east-1 / SecurityMokey | failure logon [Unknown] from 255.253.125.115 reason=User: arn:aws:iam::811596193553:user/SecurityMokey is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/SecurityMonkey | yes |
| `cloudtrail-logon-002676` | 2017-05-26 22:26:48+00:00 | aws:811596193553/us-east-1 / SecurityMokey | failure logon [Unknown] from 255.253.125.115 reason=User: arn:aws:iam::811596193553:user/SecurityMokey is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/SecurityMonkey | yes |
| `cloudtrail-logon-007195` | 2017-05-27 15:15:15+00:00 | aws:811596193553/us-east-1 / SecurityMokey | success logon [Unknown] from 255.253.125.115 | yes |

**Computed:** 0 of 3 cited ids were not cited on this case by the deterministic pass.

---

## R053

**Case:** `flaws_cloud` / `CASE-219` (28 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | HIGH | 'i-aa2d3b42e5c6e801a' made 2712 read calls across 105 distinct services in 580s, 2637 of them refused for want of authority (97%). Breadth with no permission behind it is enumeration rather than administration. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 20: `cloudtrail-control-1776510`, `cloudtrail-control-1776511`, `cloudtrail-control-1776513`, `cloudtrail-control-1776514`, `cloudtrail-control-1776515`, `cloudtrail-control-1776516`, `cloudtrail-control-1776517`, `cloudtrail-control-1776518`, `cloudtrail-control-1776521`, `cloudtrail-control-1776522`, `cloudtrail-control-1776524`, `cloudtrail-control-1776525` ... (+8 more; all of them are in worksheet.csv) |
| `AWS-004` | HIGH | 'i-aa2d3b42e5c6e801a' was refused authorization 2637 times in 580s, across 621 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 20: `cloudtrail-control-1776510`, `cloudtrail-control-1776513`, `cloudtrail-control-1776514`, `cloudtrail-control-1776515`, `cloudtrail-control-1776516`, `cloudtrail-control-1776517`, `cloudtrail-control-1776518`, `cloudtrail-control-1776519`, `cloudtrail-control-1776520`, `cloudtrail-control-1776522`, `cloudtrail-control-1776523`, `cloudtrail-control-1776524` ... (+8 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The same principal's authentication record (45 failures against 5 successes, ~90% failure) mirrors the brute-force-by-breadth pattern seen in the API calls and may represent the credential-acquisition phase that preceded the discovery burst; the 5 successful logons are the highest-value pivot for identifying the true source.

**Evidence it cites (6):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-011279` | 2017-08-18 14:38:10+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | failure logon [Unknown] from 110.253.2.0 reason=User: arn:aws:sts::811596193553:assumed-role/flaws/i-aa2d3b42e5c6e801a is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/flaws | NO |
| `cloudtrail-logon-018208` | 2018-02-24 13:30:14+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | failure logon [Unknown] from 245.181.7.4 reason=Not authorized to perform sts:AssumeRole | NO |
| `cloudtrail-logon-047152` | 2019-03-26 18:54:34+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | failure logon [Unknown] from 4.225.0.1 reason=An unknown error occurred | NO |
| `cloudtrail-logon-057799` | 2019-09-18 04:27:58+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | success logon [Unknown] from 3.10.240.206 | NO |
| `cloudtrail-logon-072502` | 2020-06-11 21:40:01+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | failure logon [Unknown] from 251.105.254.1 reason=An unknown error occurred | NO |
| `cloudtrail-logon-079343` | 2020-10-06 16:39:53+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | failure logon [Unknown] from 0.0.58.4 reason=An unknown error occurred | NO |

**Computed:** 6 of 6 cited ids were not cited on this case by the deterministic pass.

---

## R054

**Case:** `flaws_cloud` / `CASE-067` (1 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-002` | CRITICAL | 'Level6' stopped CloudTrail trail ''. Disabling the audit trail is not a routine operational action and is consistent with an intruder removing the record of subsequent activity. | 1: `cloudtrail-control-226797` |

**Hypothesis (verbatim):**

> Disabling audit logging is typically a preparatory step rather than an end goal, so it is likely that 'Level6' intended or performed further actions (credential access, data access, resource creation, or persistence) immediately after the stop, which would be unlogged.

**Evidence it cites (1):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-226797` | 2019-06-07 11:04:25+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 stop cloudtrail:logging [denied] | yes |

**Computed:** 0 of 1 cited ids were not cited on this case by the deterministic pass.

---

## R055

**Case:** `flaws_cloud` / `CASE-143` (31 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | HIGH | 'backup' made 247 read calls across 69 distinct services in 599s, 234 of them refused for want of authority (95%). Breadth with no permission behind it is enumeration rather than administration. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 20: `cloudtrail-control-1678048`, `cloudtrail-control-1678050`, `cloudtrail-control-1678058`, `cloudtrail-control-1678059`, `cloudtrail-control-1678063`, `cloudtrail-control-1678064`, `cloudtrail-control-1678068`, `cloudtrail-control-1678070`, `cloudtrail-control-1678072`, `cloudtrail-control-1678074`, `cloudtrail-control-1678075`, `cloudtrail-control-1678076` ... (+8 more; all of them are in worksheet.csv) |
| `AWS-004` | HIGH | 'backup' was refused authorization 229 times in 599s, across 201 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 20: `cloudtrail-control-1678074`, `cloudtrail-control-1678075`, `cloudtrail-control-1678076`, `cloudtrail-control-1678077`, `cloudtrail-control-1678078`, `cloudtrail-control-1678079`, `cloudtrail-control-1678080`, `cloudtrail-control-1678081`, `cloudtrail-control-1678082`, `cloudtrail-control-1678083`, `cloudtrail-control-1678084`, `cloudtrail-control-1678085` ... (+8 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The 'backup' principal is likely compromised rather than misconfigured: a legitimate backup automation would issue a narrow, repeatable set of calls against services it is provisioned for, whereas a 95% denial rate across 69 services indicates the caller did not know its own entitlements.

**Evidence it cites (8):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1678074` | 2019-11-04 01:04:44+00:00 | aws:811596193553/eu-west-1 / backup | backup list events:rule [denied] | yes |
| `cloudtrail-control-1678075` | 2019-11-04 01:04:46+00:00 | aws:811596193553/eu-west-1 / backup | backup list firehose:delivery-stream [denied] | yes |
| `cloudtrail-control-1678076` | 2019-11-04 01:04:48+00:00 | aws:811596193553/eu-west-1 / backup | backup list fms:member-account [denied] | yes |
| `cloudtrail-control-1678077` | 2019-11-04 01:04:49+00:00 | aws:811596193553/eu-west-1 / backup | backup list fms:policy [denied] | yes |
| `cloudtrail-control-1678078` | 2019-11-04 01:04:51+00:00 | aws:811596193553/eu-west-1 / backup | backup list gamelift:alias [denied] | yes |
| `cloudtrail-control-1678079` | 2019-11-04 01:04:53+00:00 | aws:811596193553/eu-west-1 / backup | backup list gamelift:build [denied] | yes |
| `cloudtrail-control-1678080` | 2019-11-04 01:04:54+00:00 | aws:811596193553/eu-west-1 / backup | backup list gamelift:fleet [denied] | yes |
| `cloudtrail-control-1678081` | 2019-11-04 01:05:05+00:00 | aws:811596193553/eu-west-1 / backup | backup list greengrass:device-definition [denied] | yes |

**Computed:** 0 of 8 cited ids were not cited on this case by the deterministic pass.

---

## R056

**Case:** `flaws_cloud` / `CASE-256` (32 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | MEDIUM | 'Level6' made 671 read calls across 21 distinct services in 550s, 196 of them refused (29%). Breadth on this scale is consistent with account enumeration, and is also exactly what inventory and compliance tooling does. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 20: `cloudtrail-control-1817072`, `cloudtrail-control-1817082`, `cloudtrail-control-1817085`, `cloudtrail-control-1817088`, `cloudtrail-control-1817159`, `cloudtrail-control-1817175`, `cloudtrail-control-1817217`, `cloudtrail-control-1817317`, `cloudtrail-control-1817318`, `cloudtrail-control-1817321`, `cloudtrail-control-1817323`, `cloudtrail-control-1817324` ... (+8 more; all of them are in worksheet.csv) |
| `AWS-004` | HIGH | 'Level6' was refused authorization 196 times in 241s, across 17 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 17: `cloudtrail-control-1817217`, `cloudtrail-control-1817246`, `cloudtrail-control-1817318`, `cloudtrail-control-1817322`, `cloudtrail-control-1817358`, `cloudtrail-control-1817365`, `cloudtrail-control-1817368`, `cloudtrail-control-1817369`, `cloudtrail-control-1817371`, `cloudtrail-control-1817372`, `cloudtrail-control-1817373`, `cloudtrail-control-1817374` ... (+5 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The specific attribute set pulled per bucket (policy, ACL, public-access-block, encryption, logging, versioning) is the exact checklist used by open-source cloud posture scanners such as ScoutSuite, Prowler or CloudMapper; combined with the account-level s3:account-public-access-block, cloudtrail:trail, config:config-rule, config:configuration-recorder-status and monitoring:alarm reads, the run is better explained as a security-audit tool sweep than as targeted adversary reconnaissance.

**Evidence it cites (11):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1817217` | 2020-09-21 04:00:07+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 get s3:account-public-access-block [denied] | yes |
| `cloudtrail-control-1817317` | 2020-09-21 04:00:40+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 describe cloudtrail:trail [allowed] | yes |
| `cloudtrail-control-1817318` | 2020-09-21 04:00:40+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 describe config:config-rule [denied] | yes |
| `cloudtrail-control-1817322` | 2020-09-21 04:00:40+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 describe config:configuration-recorder [denied] | yes |
| `cloudtrail-control-1817321` | 2020-09-21 04:00:40+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 describe monitoring:alarm [allowed] | yes |
| `cloudtrail-control-1817369` | 2020-09-21 04:00:44+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 describe config:configuration-recorder-status [denied] | yes |
| `cloudtrail-control-1817373` | 2020-09-21 04:00:45+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-policy (b5677c799b465420d8e7b0a6689a0bb0c4afbc9e.flaws.cloud) [denied] | yes |
| `cloudtrail-control-1817374` | 2020-09-21 04:00:45+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-public-access-block (b5677c799b465420d8e7b0a6689a0bb0c4afbc9e.flaws.cloud) [denied] | yes |
| `cloudtrail-control-1817376` | 2020-09-21 04:00:45+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-logging (b5677c799b465420d8e7b0a6689a0bb0c4afbc9e.flaws.cloud) [denied] | yes |
| `cloudtrail-control-1817377` | 2020-09-21 04:00:45+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-acl (b5677c799b465420d8e7b0a6689a0bb0c4afbc9e.flaws.cloud) [denied] | yes |
| `cloudtrail-control-1817378` | 2020-09-21 04:00:45+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-encryption (b5677c799b465420d8e7b0a6689a0bb0c4afbc9e.flaws.cloud) [denied] | yes |

**Computed:** 0 of 11 cited ids were not cited on this case by the deterministic pass.

---

## R057

**Case:** `flaws_cloud` / `CASE-205` (15 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | MEDIUM | 'Level6' made 563 read calls across 14 distinct services in 463s, 38 of them refused (7%). Breadth on this scale is consistent with account enumeration, and is also exactly what inventory and compliance tooling does. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 14: `cloudtrail-control-1760284`, `cloudtrail-control-1760328`, `cloudtrail-control-1760344`, `cloudtrail-control-1760376`, `cloudtrail-control-1760408`, `cloudtrail-control-1760425`, `cloudtrail-control-1760518`, `cloudtrail-control-1760534`, `cloudtrail-control-1760582`, `cloudtrail-control-1760662`, `cloudtrail-control-1760663`, `cloudtrail-control-1760664` ... (+2 more; all of them are in worksheet.csv) |
| `AWS-004` | MEDIUM | 'Level6' was refused authorization 38 times in 5s, across 3 distinct resource types. Concentrated on so few kinds of object, this is equally the shape of an application missing one permission and retrying. A refusal says what the platform would not do; it does not say what the caller intended. | 3: `cloudtrail-control-1760664`, `cloudtrail-control-1760670`, `cloudtrail-control-1760671` |

**Hypothesis (verbatim):**

> The 5285 failed authentications attributed to 'Level6' occurred on us-east-1/us-west-2, which are disjoint from the ap-south-1/ap-southeast-2 regions of the discovery burst; if the authentication failures precede the burst, this would suggest credential-guessing followed by successful use of the account, but the provided claims contain no timestamps for the logon events and therefore no ordering can be established.

**Evidence it cites (4):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-000144` | 2017-02-28 07:58:45+00:00 | aws:811596193553/us-east-1 / Level6 | success logon [Unknown] from 137.53.124.9 | NO |
| `cloudtrail-logon-000145` | 2017-02-28 08:01:21+00:00 | aws:811596193553/us-east-1 / Level6 | failure logon [Unknown] from 137.53.124.9 reason=User: arn:aws:iam::811596193553:user/Level6 is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/service-role/Level6 | NO |
| `cloudtrail-logon-000146` | 2017-02-28 08:01:50+00:00 | aws:811596193553/us-east-1 / Level6 | failure logon [Unknown] from 137.53.124.9 reason=User: arn:aws:iam::811596193553:user/Level6 is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/service-role/Level6 | NO |
| `cloudtrail-control-1760284` | 2020-06-01 19:28:15+00:00 | aws:811596193553/ap-southeast-2 / Level6 | Level6 describe ec2:network-interface [allowed] | yes |

**Computed:** 3 of 4 cited ids were not cited on this case by the deterministic pass.

---

## R058

**Case:** `flaws_cloud` / `CASE-018` (10 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | HIGH | 'backup' made 35 read calls across 10 distinct services in 53s, 21 of them refused for want of authority (60%). Breadth with no permission behind it is enumeration rather than administration. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 10: `cloudtrail-control-110341`, `cloudtrail-control-110344`, `cloudtrail-control-110347`, `cloudtrail-control-110350`, `cloudtrail-control-110351`, `cloudtrail-control-110352`, `cloudtrail-control-110353`, `cloudtrail-control-110355`, `cloudtrail-control-110356`, `cloudtrail-control-110357` |

**Hypothesis (verbatim):**

> The 'backup' identity is active in both us-east-1 and us-west-2, but this case's discovery burst is confined to us-east-1; a parallel or subsequent enumeration burst in us-west-2 is plausible and the absence of one in the current case may reflect rule/region scoping rather than actor restraint.

**Evidence it cites (3):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-000120` | 2017-02-27 16:58:36+00:00 | aws:811596193553/us-east-1 / backup | success logon [Unknown] from 0.229.250.9 | NO |
| `cloudtrail-logon-079340` | 2020-10-06 15:12:58+00:00 | aws:811596193553/us-east-1 / backup | success logon [Unknown] from 0.0.58.4 | NO |
| `cloudtrail-control-110341` | 2018-08-02 07:04:50+00:00 | aws:811596193553/us-east-1 / backup | backup get iam:account-summary [denied] | yes |

**Computed:** 2 of 3 cited ids were not cited on this case by the deterministic pass.

---

## R059

**Case:** `flaws_cloud` / `CASE-143` (31 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | HIGH | 'backup' made 247 read calls across 69 distinct services in 599s, 234 of them refused for want of authority (95%). Breadth with no permission behind it is enumeration rather than administration. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 20: `cloudtrail-control-1678048`, `cloudtrail-control-1678050`, `cloudtrail-control-1678058`, `cloudtrail-control-1678059`, `cloudtrail-control-1678063`, `cloudtrail-control-1678064`, `cloudtrail-control-1678068`, `cloudtrail-control-1678070`, `cloudtrail-control-1678072`, `cloudtrail-control-1678074`, `cloudtrail-control-1678075`, `cloudtrail-control-1678076` ... (+8 more; all of them are in worksheet.csv) |
| `AWS-004` | HIGH | 'backup' was refused authorization 229 times in 599s, across 201 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 20: `cloudtrail-control-1678074`, `cloudtrail-control-1678075`, `cloudtrail-control-1678076`, `cloudtrail-control-1678077`, `cloudtrail-control-1678078`, `cloudtrail-control-1678079`, `cloudtrail-control-1678080`, `cloudtrail-control-1678081`, `cloudtrail-control-1678082`, `cloudtrail-control-1678083`, `cloudtrail-control-1678084`, `cloudtrail-control-1678085` ... (+8 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> If the 'backup' identity is a service account with a long-lived access key, the most likely origin is credential compromise followed by permission mapping; investigators should pull the source IP, user agent, and access key ID for these events and compare them against the identity's historical baseline, since a legitimate scheduled backup job would show a stable, narrow call profile.

**Evidence it cites (5):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1678048` | 2019-11-04 01:04:11+00:00 | aws:811596193553/eu-west-1 / backup | backup list codestar:project [denied] | yes |
| `cloudtrail-control-1678064` | 2019-11-04 01:04:32+00:00 | aws:811596193553/eu-west-1 / backup | backup list dynamodb:table [denied] | yes |
| `cloudtrail-control-1678087` | 2019-11-04 01:05:07+00:00 | aws:811596193553/eu-west-1 / backup | backup get guardduty:invitations-count [denied] | yes |
| `cloudtrail-control-1678090` | 2019-11-04 01:05:12+00:00 | aws:811596193553/eu-west-1 / backup | backup list kafka:cluster [denied] | yes |
| `cloudtrail-control-1678099` | 2019-11-04 01:05:26+00:00 | aws:811596193553/eu-west-1 / backup | backup list kinesisanalytics:application [denied] | yes |

**Computed:** 0 of 5 cited ids were not cited on this case by the deterministic pass.

---

## R060

**Case:** `synthetic:INC-004` / `CASE-001` (6 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-012` | CRITICAL | 3 distinct security-control change(s) on PC03 by 'achen': Defender real-time monitoring disabled; a Defender scanning exclusion was added; a security product process was terminated. A single change is often administrative; several in one window is the shape of an attacker clearing the way for what comes next. | 3: `evt-000901`, `evt-000905`, `evt-000909` |
| `ATH-011` | CRITICAL | 3 distinct recovery control(s) were destroyed on PC03 by 'achen': Windows backup catalog deleted; boot-time recovery disabled; volume shadow copies deleted. Destroying recovery paths removes the ability to roll back and commonly immediately precedes encryption. | 3: `evt-000922`, `evt-000925`, `evt-000927` |

**Hypothesis (verbatim):**

> The achen account is likely being operated by an adversary (via credential theft, session hijack, or an implant running in the user context) rather than by the legitimate user, since disabling protection and deleting shadow copies from an interactive cmd.exe session has no ordinary business justification for a standard user.

**Evidence it cites (2):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `evt-000901` | 2026-08-17 11:12:00+00:00 | PC03 / achen | cmd.exe -> powershell.exe \| powershell.exe -nop -w hidden Set-MpPreference -DisableRealtimeMonitoring $true | yes |
| `evt-000922` | 2026-08-17 11:14:30+00:00 | PC03 / achen | cmd.exe -> vssadmin.exe \| vssadmin.exe delete shadows /all /quiet | yes |

**Computed:** 0 of 2 cited ids were not cited on this case by the deterministic pass.

---

## R061

**Case:** `synthetic:INC-001` / `CASE-001` (31 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-009` | MEDIUM | Outlook launched WINWORD.EXE to open a document in a macro-capable format. This is consistent with a malicious attachment being opened, independent of whether any embedded macro subsequently ran. | 1: `evt-000355` |
| `ATH-001` | HIGH | WINWORD.EXE started powershell.exe. Office applications have no routine need to launch script interpreters; this parent/child relationship is consistent with macro-based code execution from a document. | 1: `evt-000357` |
| `ATH-002` | HIGH | PowerShell ran a base64-encoded command. The decoded payload retrieves and executes remote content, which is consistent with a first-stage downloader. Evasion flags observed: hidden window, no profile. | 1: `evt-000357` |
| `ATH-003` | HIGH | powershell.exe made 7 outbound connection(s) to the external address 185.220.101.47 on port(s) 80, 443. Script interpreters do not normally initiate direct internet connections; this may indicate payload retrieval or command-and-control. The connection to port 80 indicates cleartext HTTP, which is commonly used to retrieve a second-stage script. | 7: `evt-000358`, `evt-000362`, `evt-000380`, `evt-000399`, `evt-000421`, `evt-000454`, `evt-000486` |
| `ATH-010` | MEDIUM | 3 distinct discovery commands (net.exe, nltest.exe, whoami.exe) ran from the same parent process (PID 6612) within 34s, consistent with systematic reconnaissance of the local environment and domain. | 3: `evt-000367`, `evt-000370`, `evt-000374` |
| `ATH-004` | CRITICAL | Command line matched credential-access indicators (comsvcs.dll MiniDump, explicit lsass reference, rundll32 MiniDump export). This may indicate an attempt to extract credential material from LSASS memory, which would enable authentication as other users. Requires immediate verification against the account's expected activity. | 1: `evt-000381` |
| `ATH-005` | CRITICAL | 14 failed logons for 'svc_backup' on FS02 from 10.10.20.15 within 143s. A successful logon followed at 09:33:47, 204s after the last failure. This may indicate the credential was successfully guessed and the account is now compromised. | 15: `evt-000419`, `evt-000422`, `evt-000425`, `evt-000427`, `evt-000429`, `evt-000431`, `evt-000432`, `evt-000433`, `evt-000437`, `evt-000438`, `evt-000439`, `evt-000440` ... (+3 more; all of them are in worksheet.csv) |
| `ATH-006` | HIGH | Account 'svc_backup' authenticated to FS02 from PC01, but has no interactive session on PC01 (observed owner(s): jdoe). Credential use originating from a host the account does not operate on is consistent with lateral movement using stolen credentials, though legitimate alternate-credential workflows produce the same pattern. | 1: `evt-000457` |
| `ATH-007` | HIGH | The Service Control Manager started an interactive command interpreter. This pattern is consistent with remote command execution via a temporary service. Command output is redirected to the administrative share '\\127.0.0.1\ADMIN$', which is characteristic of remote execution frameworks collecting results over SMB. | 1: `evt-000461` |
| `ATH-008` | HIGH | An archive utility was invoked and the source path uses a wildcard, implying bulk collection and the destination is a shared staging directory. This is consistent with staging data prior to exfiltration, but does not by itself show that any data left the network. | 1: `evt-000469` |
| `ATH-003` | MEDIUM | powershell.exe made 1 outbound connection(s) to the external address 185.220.101.47 on port(s) 443. Script interpreters do not normally initiate direct internet connections; this may indicate payload retrieval or command-and-control. | 1: `evt-000481` |

**Hypothesis (verbatim):**

> The credentials for 'svc_backup' may have been obtained from memory on PC01. This is unverified: no telemetry links the credential-access activity to this specific account.

**Evidence it cites (0):**

_This hypothesis cites no event ids._

---

## R062

**Case:** `attack_data_aws` / `CASE-002` (5 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-004` | HIGH | 'cloudmapper' was refused authorization 37 times in 284s, across 5 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 5: `cloudtrail-control-001224`, `cloudtrail-control-001222`, `cloudtrail-control-001220`, `cloudtrail-control-001219`, `cloudtrail-control-001204` |

**Hypothesis (verbatim):**

> The account name 'cloudmapper' matches the well-known open-source AWS auditing tool CloudMapper, whose collection phase enumerates many resource types and predictably generates dense AccessDenied bursts when the role is under-privileged; this case may therefore be sanctioned security tooling rather than adversary discovery. Confirming or excluding this requires checking whether the principal is an approved audit role and whether the run was scheduled.

**Evidence it cites (2):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-001204` | 2021-04-13 13:35:10+00:00 | aws:731544447609/eu-north-1 / cloudmapper | cloudmapper get glue:trigger [denied] | yes |
| `cloudtrail-control-001224` | 2021-04-13 13:30:36+00:00 | aws:731544447609/us-east-1 / cloudmapper | cloudmapper list kms:key-policy [denied] | yes |

**Computed:** 0 of 2 cited ids were not cited on this case by the deterministic pass.

---

## R063

**Case:** `flaws_cloud` / `CASE-067` (1 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-002` | CRITICAL | 'Level6' stopped CloudTrail trail ''. Disabling the audit trail is not a routine operational action and is consistent with an intruder removing the record of subsequent activity. | 1: `cloudtrail-control-226797` |

**Hypothesis (verbatim):**

> The very high volume of failed authentications for 'Level6' is consistent with credential brute-forcing/password-spraying or repeated token replay against the account, and the 61 successes represent the subset where valid credentials were obtained; the CloudTrail stop at 2019-06-07T11:04:25Z would then be post-compromise defense evasion following that access.

**Evidence it cites (3):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-000144` | 2017-02-28 07:58:45+00:00 | aws:811596193553/us-east-1 / Level6 | success logon [Unknown] from 137.53.124.9 | NO |
| `cloudtrail-logon-000146` | 2017-02-28 08:01:50+00:00 | aws:811596193553/us-east-1 / Level6 | failure logon [Unknown] from 137.53.124.9 reason=User: arn:aws:iam::811596193553:user/Level6 is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/service-role/Level6 | NO |
| `cloudtrail-control-226797` | 2019-06-07 11:04:25+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 stop cloudtrail:logging [denied] | yes |

**Computed:** 2 of 3 cited ids were not cited on this case by the deterministic pass.

---

## R064

**Case:** `flaws_cloud` / `CASE-066` (1 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-002` | CRITICAL | 'Level6' stopped CloudTrail trail ''. Disabling the audit trail is not a routine operational action and is consistent with an intruder removing the record of subsequent activity. | 1: `cloudtrail-control-226796` |

**Hypothesis (verbatim):**

> The sequence is most consistent with credential-access-then-defense-evasion: sustained guessing produced at least one valid session, and the operator's first high-value action with that session was to stop the audit trail (T1685) to blind follow-on activity such as privilege escalation, persistence, or data access.

**Evidence it cites (3):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-226796` | 2019-06-07 11:04:25+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 stop cloudtrail:logging [denied] | yes |
| `cloudtrail-logon-018192` | 2018-02-24 12:49:58+00:00 | aws:811596193553/us-east-1 / Level6 | failure logon [Unknown] from 245.181.7.4 reason=User: arn:aws:iam::811596193553:user/Level6 is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/service-role/Level6 | NO |
| `cloudtrail-logon-045001` | 2019-03-07 20:33:16+00:00 | aws:811596193553/us-east-1 / Level6 | failure logon [Unknown] from 2.231.90.242 reason=Not authorized to perform sts:AssumeRole | NO |

**Computed:** 2 of 3 cited ids were not cited on this case by the deterministic pass.

---

## R065

**Case:** `flaws_cloud` / `CASE-113` (5 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-004` | HIGH | 'Level6' was refused authorization 918 times in 598s, across 5 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 5: `cloudtrail-control-323923`, `cloudtrail-control-323928`, `cloudtrail-control-323933`, `cloudtrail-control-323942`, `cloudtrail-control-323974` |

**Hypothesis (verbatim):**

> The denial burst is the discovery stage of an attacker-controlled credential obtained earlier; the absence of resolved source addresses on any 'Level6' authentication event would be consistent with access via an anonymising or non-attributable network path, but source attribution is currently unavailable and cannot confirm this.

**Evidence it cites (4):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-000144` | 2017-02-28 07:58:45+00:00 | aws:811596193553/us-east-1 / Level6 | success logon [Unknown] from 137.53.124.9 | NO |
| `cloudtrail-logon-000145` | 2017-02-28 08:01:21+00:00 | aws:811596193553/us-east-1 / Level6 | failure logon [Unknown] from 137.53.124.9 reason=User: arn:aws:iam::811596193553:user/Level6 is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/service-role/Level6 | NO |
| `cloudtrail-control-323923` | 2019-08-21 07:41:21+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 create iam:access-key (Level6) -> Level6 [denied] | yes |
| `cloudtrail-control-323928` | 2019-08-21 07:41:22+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 create iam:user [denied] | yes |

**Computed:** 2 of 4 cited ids were not cited on this case by the deterministic pass.

---

## R066

**Case:** `comiset` / `CASE-002` (1 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-012` | HIGH | 1 distinct security-control change(s) on desktop-4pvps6e by 'system': a security service was stopped. A single change is often administrative; several in one window is the shape of an attacker clearing the way for what comes next. | 1: `comiset_slice.jsonl:4bdb0f0e83e0a62d3ca40b33ef0d892801fd4d3b` |

**Hypothesis (verbatim):**

> An alternative reading of the same sc.exe execution is service creation for persistence rather than service disablement; the two are indistinguishable without the process command line, so the ATH-012 technique mapping should be treated as provisional until arguments are recovered.

**Evidence it cites (1):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `comiset_slice.jsonl:4bdb0f0e83e0a62d3ca40b33ef0d892801fd4d3b` | 2022-11-19 19:12:55.683000+00:00 | desktop-4pvps6e / system | cmd.exe -> sc.exe \| sc stop windefend | yes |

**Computed:** 0 of 1 cited ids were not cited on this case by the deterministic pass.

---

## R067

**Case:** `flaws_cloud` / `CASE-205` (15 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | MEDIUM | 'Level6' made 563 read calls across 14 distinct services in 463s, 38 of them refused (7%). Breadth on this scale is consistent with account enumeration, and is also exactly what inventory and compliance tooling does. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 14: `cloudtrail-control-1760284`, `cloudtrail-control-1760328`, `cloudtrail-control-1760344`, `cloudtrail-control-1760376`, `cloudtrail-control-1760408`, `cloudtrail-control-1760425`, `cloudtrail-control-1760518`, `cloudtrail-control-1760534`, `cloudtrail-control-1760582`, `cloudtrail-control-1760662`, `cloudtrail-control-1760663`, `cloudtrail-control-1760664` ... (+2 more; all of them are in worksheet.csv) |
| `AWS-004` | MEDIUM | 'Level6' was refused authorization 38 times in 5s, across 3 distinct resource types. Concentrated on so few kinds of object, this is equally the shape of an application missing one permission and retrying. A refusal says what the platform would not do; it does not say what the caller intended. | 3: `cloudtrail-control-1760664`, `cloudtrail-control-1760670`, `cloudtrail-control-1760671` |

**Hypothesis (verbatim):**

> The combination of broad read coverage (14 services) with denials concentrated on only 3 resource types is more consistent with a permission-boundary probe by a caller mapping what its credential can reach than with a compliance scanner, since an inventory tool is normally provisioned with the read permissions it needs and would not fail on a narrow, repeated set of object kinds.

**Evidence it cites (3):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1760664` | 2020-06-01 19:29:15+00:00 | aws:811596193553/ap-south-1 / Level6 | Level6 list ses:identity [denied] | yes |
| `cloudtrail-control-1760670` | 2020-06-01 19:29:17+00:00 | aws:811596193553/ap-south-1 / Level6 | Level6 list sns:topic [denied] | yes |
| `cloudtrail-control-1760671` | 2020-06-01 19:29:17+00:00 | aws:811596193553/ap-south-1 / Level6 | Level6 list sns:subscription [denied] | yes |

**Computed:** 0 of 3 cited ids were not cited on this case by the deterministic pass.

---

## R068

**Case:** `synthetic:INC-005` / `CASE-001` (2 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `K8S-001` | HIGH | 'system:serviceaccount:ci:ci-deployer' created clusterrolebindings 'ci-runner-escalation', granting the maximally-privileged role 'cluster-admin' to 'system:serviceaccount:ci:ci-runner'. Very few legitimate workloads need this level of access, and the grantor is not a superuser, so this grant confers standing the grantor did not itself hold; it is worth review even when the grantor is an ordinary ... (full text in worksheet.csv) | 1: `k8s-control-000003` |
| `K8S-002` | CRITICAL | 'system:serviceaccount:ci:ci-runner' was granted the 'cluster-admin' role 149s before exec'ing into pod 'web-1' (namespace 'prod'). A freshly-escalated identity acting on that escalation shortly after receiving it is consistent with the grant being used for exploration or post-exploitation access rather than left dormant. | 2: `k8s-control-000003`, `k8s-control-000004` |

**Hypothesis (verbatim):**

> The ci-deployer service account credential was likely abused by an attacker (e.g., via a compromised CI pipeline, leaked token, or malicious pipeline job) rather than acting on legitimate operator intent, since a deliberate operator grant of cluster-admin would normally be accompanied by a change-management artifact and would not be exercised within seconds.

**Evidence it cites (2):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `k8s-control-000003` | 2026-08-17 09:20:00.040000+00:00 | k8s:test-cluster / system:serviceaccount:ci:ci-runner | system:serviceaccount:ci:ci-deployer create clusterrolebindings (ci-runner-escalation) -> system:serviceaccount:ci:ci-runner [allowed] | yes |
| `k8s-control-000004` | 2026-08-17 09:22:30.015000+00:00 | k8s:test-cluster / system:serviceaccount:ci:ci-runner | system:serviceaccount:ci:ci-runner exec pods/exec (web-1) [allowed] | yes |

**Computed:** 0 of 2 cited ids were not cited on this case by the deterministic pass.

---

## R069

**Case:** `flaws_cloud` / `CASE-122` (13 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-004` | HIGH | 'Level6' was refused authorization 84 times in 92s, across 13 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 13: `cloudtrail-control-1649380`, `cloudtrail-control-1649381`, `cloudtrail-control-1649382`, `cloudtrail-control-1649383`, `cloudtrail-control-1649386`, `cloudtrail-control-1649387`, `cloudtrail-control-1649388`, `cloudtrail-control-1649390`, `cloudtrail-control-1649391`, `cloudtrail-control-1649392`, `cloudtrail-control-1649393`, `cloudtrail-control-1649394` ... (+1 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The near-exhaustive coverage of the S3 bucket-metadata API surface (encryption, CORS, ACL, location, replication, policy-status, notification, logging, policy, tagging, website, versioning, request-payment) in one contiguous block is more consistent with an automated tool or SDK enumeration routine iterating a fixed API list than with a human operator or an application performing a task-specific call.

**Evidence it cites (13):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1649380` | 2019-08-28 21:53:05+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-encryption (dev-eztax) [denied] | yes |
| `cloudtrail-control-1649381` | 2019-08-28 21:53:05+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-cor (dev-eztax) [denied] | yes |
| `cloudtrail-control-1649382` | 2019-08-28 21:53:05+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-acl (dev-eztax) [denied] | yes |
| `cloudtrail-control-1649383` | 2019-08-28 21:53:06+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-location (dev-eztax) [denied] | yes |
| `cloudtrail-control-1649386` | 2019-08-28 21:53:07+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-replication (dev-eztax) [denied] | yes |
| `cloudtrail-control-1649387` | 2019-08-28 21:53:07+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-policy-status (dev-eztax) [denied] | yes |
| `cloudtrail-control-1649388` | 2019-08-28 21:53:07+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-notification (dev-eztax) [denied] | yes |
| `cloudtrail-control-1649390` | 2019-08-28 21:53:07+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-logging (dev-eztax) [denied] | yes |
| `cloudtrail-control-1649391` | 2019-08-28 21:53:07+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-policy (dev-eztax) [denied] | yes |
| `cloudtrail-control-1649392` | 2019-08-28 21:53:08+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-tagging (dev-eztax) [denied] | yes |
| `cloudtrail-control-1649393` | 2019-08-28 21:53:08+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-website (dev-eztax) [denied] | yes |
| `cloudtrail-control-1649394` | 2019-08-28 21:53:08+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-versioning (dev-eztax) [denied] | yes |
| `cloudtrail-control-1649395` | 2019-08-28 21:53:08+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-request-payment (dev-eztax) [denied] | yes |

**Computed:** 0 of 13 cited ids were not cited on this case by the deterministic pass.

---

## R070

**Case:** `flaws_cloud` / `CASE-118` (1 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-002` | CRITICAL | 'flaws' deleted CloudTrail trail 'arn:aws:cloudtrail:us-west-2:811596193553:trail/cloudtrail'. Disabling the audit trail is not a routine operational action and is consistent with an intruder removing the record of subsequent activity. | 1: `cloudtrail-control-1576322` |

**Hypothesis (verbatim):**

> Because no source addresses resolved for any of the 26 authentication events, attribution and separation of attacker sessions from legitimate administrator sessions cannot currently be performed; enriching these events with sourceIPAddress, userAgent, and accessKeyId would likely reveal whether a subset of the 26 logons originated from infrastructure distinct from normal operations.

**Evidence it cites (4):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-023843` | 2018-07-05 18:49:34+00:00 | aws:811596193553/us-east-1 / flaws | success logon [Unknown] from 250.251.253.3 | NO |
| `cloudtrail-logon-023854` | 2018-07-06 04:14:52+00:00 | aws:811596193553/us-east-1 / flaws | success logon [Unknown] from 250.251.253.3 | NO |
| `cloudtrail-logon-027482` | 2018-09-30 23:46:06+00:00 | aws:811596193553/us-east-1 / flaws | success logon [Unknown] from 2.251.230.253 | NO |
| `cloudtrail-logon-057066` | 2019-08-27 14:34:27+00:00 | aws:811596193553/us-east-1 / flaws | success logon [Unknown] from 228.139.46.252 | NO |

**Computed:** 4 of 4 cited ids were not cited on this case by the deterministic pass.

---

## R071

**Case:** `flaws_cloud` / `CASE-050` (34 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | HIGH | 'backup' made 720 read calls across 87 distinct services in 596s, 498 of them refused for want of authority (69%). Breadth with no permission behind it is enumeration rather than administration. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 20: `cloudtrail-control-189268`, `cloudtrail-control-189271`, `cloudtrail-control-189274`, `cloudtrail-control-189276`, `cloudtrail-control-189278`, `cloudtrail-control-189290`, `cloudtrail-control-189293`, `cloudtrail-control-189312`, `cloudtrail-control-189320`, `cloudtrail-control-189322`, `cloudtrail-control-189323`, `cloudtrail-control-189330` ... (+8 more; all of them are in worksheet.csv) |
| `AWS-004` | HIGH | 'backup' was refused authorization 506 times in 161s, across 245 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 20: `cloudtrail-control-189271`, `cloudtrail-control-189274`, `cloudtrail-control-189276`, `cloudtrail-control-189278`, `cloudtrail-control-189279`, `cloudtrail-control-189280`, `cloudtrail-control-189281`, `cloudtrail-control-189286`, `cloudtrail-control-189287`, `cloudtrail-control-189290`, `cloudtrail-control-189291`, `cloudtrail-control-189292` ... (+8 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The 11,625 failed authentications on account 'backup' (98.9% failure rate across 11,750 attempts) and the permission-denied enumeration burst are two stages of one credential-abuse sequence: an actor first guessed or sprayed credentials, then used a low-privilege session to map what the credential could reach. This is unproven because the authentication events carry no resolved source and are not time-correlated in the available claims.

**Evidence it cites (4):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-000120` | 2017-02-27 16:58:36+00:00 | aws:811596193553/us-east-1 / backup | success logon [Unknown] from 0.229.250.9 | NO |
| `cloudtrail-logon-000121` | 2017-02-27 16:58:39+00:00 | aws:811596193553/us-east-1 / backup | success logon [Unknown] from 0.229.250.9 | NO |
| `cloudtrail-control-189271` | 2019-04-05 09:22:12+00:00 | aws:811596193553/us-east-1 / backup | backup get iam:account-summary [denied] | yes |
| `cloudtrail-control-189279` | 2019-04-05 09:22:15+00:00 | aws:811596193553/us-east-1 / backup | backup get apigateway:rest-apis [denied] | yes |

**Computed:** 2 of 4 cited ids were not cited on this case by the deterministic pass.

---

## R072

**Case:** `synthetic:INC-005` / `CASE-001` (2 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `K8S-001` | HIGH | 'system:serviceaccount:ci:ci-deployer' created clusterrolebindings 'ci-runner-escalation', granting the maximally-privileged role 'cluster-admin' to 'system:serviceaccount:ci:ci-runner'. Very few legitimate workloads need this level of access, and the grantor is not a superuser, so this grant confers standing the grantor did not itself hold; it is worth review even when the grantor is an ordinary ... (full text in worksheet.csv) | 1: `k8s-control-000003` |
| `K8S-002` | CRITICAL | 'system:serviceaccount:ci:ci-runner' was granted the 'cluster-admin' role 149s before exec'ing into pod 'web-1' (namespace 'prod'). A freshly-escalated identity acting on that escalation shortly after receiving it is consistent with the grant being used for exploration or post-exploitation access rather than left dormant. | 2: `k8s-control-000003`, `k8s-control-000004` |

**Hypothesis (verbatim):**

> ci-deployer is the earlier-compromised identity and ci-runner is a secondary identity it privileged; the investigation should pivot to ci-deployer's authentication source (token issuance, node/pod of origin, source IP) to locate the true initial access point, which is not represented in the current evidence.

**Evidence it cites (2):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `k8s-control-000003` | 2026-08-17 09:20:00.040000+00:00 | k8s:test-cluster / system:serviceaccount:ci:ci-runner | system:serviceaccount:ci:ci-deployer create clusterrolebindings (ci-runner-escalation) -> system:serviceaccount:ci:ci-runner [allowed] | yes |
| `k8s-control-000004` | 2026-08-17 09:22:30.015000+00:00 | k8s:test-cluster / system:serviceaccount:ci:ci-runner | system:serviceaccount:ci:ci-runner exec pods/exec (web-1) [allowed] | yes |

**Computed:** 0 of 2 cited ids were not cited on this case by the deterministic pass.

---

## R073

**Case:** `attack_data_aws` / `CASE-002` (5 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-004` | HIGH | 'cloudmapper' was refused authorization 37 times in 284s, across 5 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 5: `cloudtrail-control-001224`, `cloudtrail-control-001222`, `cloudtrail-control-001220`, `cloudtrail-control-001219`, `cloudtrail-control-001204` |

**Hypothesis (verbatim):**

> Because the finding is built exclusively from refusals, the case cannot distinguish a credential that reached nothing from one that also succeeded on calls not surfaced here; a targeted review of successful (non-denied) API calls by the same principal in the 13:25-13:45 window would be decisive and should be treated as the next investigative step.

**Evidence it cites (3):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-001220` | 2021-04-13 13:33:45+00:00 | aws:731544447609/us-east-1 / cloudmapper | cloudmapper list organizations:account [denied] | yes |
| `cloudtrail-control-001222` | 2021-04-13 13:31:05+00:00 | aws:731544447609/us-east-1 / cloudmapper | cloudmapper get kms:key-rotation-status [denied] | yes |
| `cloudtrail-control-001224` | 2021-04-13 13:30:36+00:00 | aws:731544447609/us-east-1 / cloudmapper | cloudmapper list kms:key-policy [denied] | yes |

**Computed:** 0 of 3 cited ids were not cited on this case by the deterministic pass.

---

## R074

**Case:** `flaws_cloud` / `CASE-018` (10 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | HIGH | 'backup' made 35 read calls across 10 distinct services in 53s, 21 of them refused for want of authority (60%). Breadth with no permission behind it is enumeration rather than administration. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 10: `cloudtrail-control-110341`, `cloudtrail-control-110344`, `cloudtrail-control-110347`, `cloudtrail-control-110350`, `cloudtrail-control-110351`, `cloudtrail-control-110352`, `cloudtrail-control-110353`, `cloudtrail-control-110355`, `cloudtrail-control-110356`, `cloudtrail-control-110357` |

**Hypothesis (verbatim):**

> The principal name 'backup' implies a role scoped to snapshot, restore and retention duties. Reads against cloudfront:distribution, sns:topic, elasticbeanstalk:application and iam:account-summary have no plausible backup function, so the observed breadth exceeds the identity's apparent business purpose. This is consistent either with an over-permissioned service role being exercised by an unintended consumer, or with a third party operating stolen 'backup' credentials.

**Evidence it cites (4):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-110341` | 2018-08-02 07:04:50+00:00 | aws:811596193553/us-east-1 / backup | backup get iam:account-summary [denied] | yes |
| `cloudtrail-control-110351` | 2018-08-02 07:05:24+00:00 | aws:811596193553/ap-northeast-1 / backup | backup list sns:topic [denied] | yes |
| `cloudtrail-control-110352` | 2018-08-02 07:05:25+00:00 | aws:811596193553/ap-northeast-1 / backup | backup describe elasticbeanstalk:application [allowed] | yes |
| `cloudtrail-control-110357` | 2018-08-02 07:05:26+00:00 | aws:811596193553/us-east-1 / backup | backup list cloudfront:distribution [denied] | yes |

**Computed:** 0 of 4 cited ids were not cited on this case by the deterministic pass.

---

## R075

**Case:** `flaws_cloud` / `CASE-065` (29 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | MEDIUM | 'Level6' made 1808 read calls across 20 distinct services in 316s, 282 of them refused (16%). Breadth on this scale is consistent with account enumeration, and is also exactly what inventory and compliance tooling does. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 20: `cloudtrail-control-224294`, `cloudtrail-control-224300`, `cloudtrail-control-224346`, `cloudtrail-control-224351`, `cloudtrail-control-224356`, `cloudtrail-control-224384`, `cloudtrail-control-224412`, `cloudtrail-control-224446`, `cloudtrail-control-224468`, `cloudtrail-control-224532`, `cloudtrail-control-224570`, `cloudtrail-control-224571` ... (+8 more; all of them are in worksheet.csv) |
| `AWS-004` | HIGH | 'Level6' was refused authorization 282 times in 307s, across 13 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 13: `cloudtrail-control-224294`, `cloudtrail-control-224468`, `cloudtrail-control-224469`, `cloudtrail-control-224696`, `cloudtrail-control-225208`, `cloudtrail-control-225228`, `cloudtrail-control-225510`, `cloudtrail-control-225648`, `cloudtrail-control-225649`, `cloudtrail-control-225650`, `cloudtrail-control-225651`, `cloudtrail-control-225652` ... (+1 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The bucket names ending in '.flaws.cloud' and the principal name 'Level6' correspond to the publicly published flAWS.cloud AWS security training challenge, in which 'Level6' is a deliberately-provisioned low-privilege IAM user and 'theend-...' is the terminal objective bucket. If correct, this entire case is sanctioned training/CTF activity rather than an intrusion, and the Discovery techniques attributed by AWS-003/AWS-004 are expected by design.

**Evidence it cites (4):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-224696` | 2019-06-06 11:31:23+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 get s3:bucket-location (theend-c1aad500c62e2a57cf12cebf93b282cf.flaws.cloud) [denied] | yes |
| `cloudtrail-control-225648` | 2019-06-06 11:31:59+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-acl (b5677c799b465420d8e7b0a6689a0bb0c4afbc9e.flaws.cloud) [denied] | yes |
| `cloudtrail-control-225659` | 2019-06-06 11:32:00+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-website (b5677c799b465420d8e7b0a6689a0bb0c4afbc9e.flaws.cloud) [denied] | yes |
| `cloudtrail-control-224300` | 2019-06-06 11:30:41+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 get sts:caller-identity [allowed] | yes |

**Computed:** 0 of 4 cited ids were not cited on this case by the deterministic pass.

---

## R076

**Case:** `flaws_cloud` / `CASE-219` (28 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | HIGH | 'i-aa2d3b42e5c6e801a' made 2712 read calls across 105 distinct services in 580s, 2637 of them refused for want of authority (97%). Breadth with no permission behind it is enumeration rather than administration. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 20: `cloudtrail-control-1776510`, `cloudtrail-control-1776511`, `cloudtrail-control-1776513`, `cloudtrail-control-1776514`, `cloudtrail-control-1776515`, `cloudtrail-control-1776516`, `cloudtrail-control-1776517`, `cloudtrail-control-1776518`, `cloudtrail-control-1776521`, `cloudtrail-control-1776522`, `cloudtrail-control-1776524`, `cloudtrail-control-1776525` ... (+8 more; all of them are in worksheet.csv) |
| `AWS-004` | HIGH | 'i-aa2d3b42e5c6e801a' was refused authorization 2637 times in 580s, across 621 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 20: `cloudtrail-control-1776510`, `cloudtrail-control-1776513`, `cloudtrail-control-1776514`, `cloudtrail-control-1776515`, `cloudtrail-control-1776516`, `cloudtrail-control-1776517`, `cloudtrail-control-1776518`, `cloudtrail-control-1776519`, `cloudtrail-control-1776520`, `cloudtrail-control-1776522`, `cloudtrail-control-1776523`, `cloudtrail-control-1776524` ... (+8 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The acting principal identifier 'i-aa2d3b42e5c6e801a' has EC2 instance-id form, suggesting the calls were made with an instance-role credential; combined with the low-privilege denial profile this is consistent with credentials harvested from an instance metadata service (e.g. via SSRF or on-host compromise) and then exercised from elsewhere.

**Evidence it cites (5):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1776510` | 2020-06-11 21:47:49+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a list snowball:cluster [denied] | yes |
| `cloudtrail-control-1776514` | 2020-06-11 21:47:50+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a list cloudfront:distribution [denied] | yes |
| `cloudtrail-control-1776522` | 2020-06-11 21:47:50+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a describe gamelift:vpc-peering-authorization [denied] | yes |
| `cloudtrail-logon-018208` | 2018-02-24 13:30:14+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | failure logon [Unknown] from 245.181.7.4 reason=Not authorized to perform sts:AssumeRole | NO |
| `cloudtrail-logon-072441` | 2020-06-10 22:44:35+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | failure logon [Unknown] from 251.105.254.1 reason=An unknown error occurred | NO |

**Computed:** 2 of 5 cited ids were not cited on this case by the deterministic pass.

---

## R077

**Case:** `synthetic:INC-002` / `CASE-001` (13 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-005` | CRITICAL | 12 failed logons for 'dev_alice' on aws:123456789012/us-east-1 from 203.0.113.42 within 220s. A successful logon followed at 09:16:30, 50s after the last failure. This may indicate the credential was successfully guessed and the account is now compromised. | 13: `cloudtrail-logon-000002`, `cloudtrail-logon-000003`, `cloudtrail-logon-000004`, `cloudtrail-logon-000005`, `cloudtrail-logon-000006`, `cloudtrail-logon-000007`, `cloudtrail-logon-000008`, `cloudtrail-logon-000009`, `cloudtrail-logon-000010`, `cloudtrail-logon-000011`, `cloudtrail-logon-000012`, `cloudtrail-logon-000013` ... (+1 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The case contains no post-authentication API or resource-access events for 'dev_alice', which is more likely a telemetry scoping gap (only logon events were collected) than evidence that the adversary took no action; CloudTrail management and data events for this principal after 000014 should be retrieved before concluding impact was nil.

**Evidence it cites (2):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-000014` | 2026-08-17 09:16:30+00:00 | aws:123456789012/us-east-1 / dev_alice | success logon [Unknown] from 203.0.113.42 | yes |
| `cloudtrail-logon-000015` | 2026-08-17 09:21:00+00:00 | aws:123456789012/us-east-1 / dev_alice | success logon [Unknown] from 203.0.113.42 | yes |

**Computed:** 0 of 2 cited ids were not cited on this case by the deterministic pass.

---

## R078

**Case:** `flaws_cloud` / `CASE-066` (1 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-002` | CRITICAL | 'Level6' stopped CloudTrail trail ''. Disabling the audit trail is not a routine operational action and is consistent with an intruder removing the record of subsequent activity. | 1: `cloudtrail-control-226796` |

**Hypothesis (verbatim):**

> A benign explanation remains open: scheduled maintenance, cost-reduction of duplicate trails, or an infrastructure-as-code change could produce the same telemetry. The malicious interpretation should be considered unconfirmed until the principal's authorisation, change-ticket context, and whether logging was restored are established.

**Evidence it cites (1):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-226796` | 2019-06-07 11:04:25+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 stop cloudtrail:logging [denied] | yes |

**Computed:** 0 of 1 cited ids were not cited on this case by the deterministic pass.

---

## R079

**Case:** `flaws_cloud` / `CASE-050` (34 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | HIGH | 'backup' made 720 read calls across 87 distinct services in 596s, 498 of them refused for want of authority (69%). Breadth with no permission behind it is enumeration rather than administration. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 20: `cloudtrail-control-189268`, `cloudtrail-control-189271`, `cloudtrail-control-189274`, `cloudtrail-control-189276`, `cloudtrail-control-189278`, `cloudtrail-control-189290`, `cloudtrail-control-189293`, `cloudtrail-control-189312`, `cloudtrail-control-189320`, `cloudtrail-control-189322`, `cloudtrail-control-189323`, `cloudtrail-control-189330` ... (+8 more; all of them are in worksheet.csv) |
| `AWS-004` | HIGH | 'backup' was refused authorization 506 times in 161s, across 245 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 20: `cloudtrail-control-189271`, `cloudtrail-control-189274`, `cloudtrail-control-189276`, `cloudtrail-control-189278`, `cloudtrail-control-189279`, `cloudtrail-control-189280`, `cloudtrail-control-189281`, `cloudtrail-control-189286`, `cloudtrail-control-189287`, `cloudtrail-control-189290`, `cloudtrail-control-189291`, `cloudtrail-control-189292` ... (+8 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> An equally consistent benign explanation is a misconfigured or credential-expired backup automation job: a looping agent would produce both a very high authentication failure rate and repetitive broad API calls that are uniformly denied, with no successful privileged action. Distinguishing this from intrusion requires the user-agent string, session type (IAM user vs assumed role), and whether the call sequence is alphabetical or ordered by service.

**Evidence it cites (4):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-000126` | 2017-02-27 19:38:50+00:00 | aws:811596193553/us-east-1 / backup | success logon [Unknown] from 5.165.77.250 | NO |
| `cloudtrail-logon-000141` | 2017-02-28 06:54:05+00:00 | aws:811596193553/us-east-1 / backup | success logon [Unknown] from 1.216.193.96 | NO |
| `cloudtrail-control-189290` | 2019-04-05 09:22:19+00:00 | aws:811596193553/us-east-1 / backup | backup describe autoscaling:auto-scaling-instance [denied] | yes |
| `cloudtrail-control-189312` | 2019-04-05 09:22:21+00:00 | aws:811596193553/us-east-1 / backup | backup describe batch:job-definition [denied] | yes |

**Computed:** 2 of 4 cited ids were not cited on this case by the deterministic pass.

---

## R080

**Case:** `flaws_cloud` / `CASE-065` (29 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | MEDIUM | 'Level6' made 1808 read calls across 20 distinct services in 316s, 282 of them refused (16%). Breadth on this scale is consistent with account enumeration, and is also exactly what inventory and compliance tooling does. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 20: `cloudtrail-control-224294`, `cloudtrail-control-224300`, `cloudtrail-control-224346`, `cloudtrail-control-224351`, `cloudtrail-control-224356`, `cloudtrail-control-224384`, `cloudtrail-control-224412`, `cloudtrail-control-224446`, `cloudtrail-control-224468`, `cloudtrail-control-224532`, `cloudtrail-control-224570`, `cloudtrail-control-224571` ... (+8 more; all of them are in worksheet.csv) |
| `AWS-004` | HIGH | 'Level6' was refused authorization 282 times in 307s, across 13 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 13: `cloudtrail-control-224294`, `cloudtrail-control-224468`, `cloudtrail-control-224469`, `cloudtrail-control-224696`, `cloudtrail-control-225208`, `cloudtrail-control-225228`, `cloudtrail-control-225510`, `cloudtrail-control-225648`, `cloudtrail-control-225649`, `cloudtrail-control-225650`, `cloudtrail-control-225651`, `cloudtrail-control-225652` ... (+1 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The 16% refusal rate argues against the benign inventory/compliance-tooling explanation offered in AWS-003: sanctioned inventory tooling is normally provisioned with a read-only policy matched to the services it scans and would not be denied across 13 distinct resource types. A caller probing the boundaries of an unfamiliar credential fits the observed denial spread better.

**Evidence it cites (8):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-224469` | 2019-06-06 11:31:11+00:00 | aws:811596193553/ap-northeast-1 / Level6 | Level6 describe config:config-rule [denied] | yes |
| `cloudtrail-control-224696` | 2019-06-06 11:31:23+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 get s3:bucket-location (theend-c1aad500c62e2a57cf12cebf93b282cf.flaws.cloud) [denied] | yes |
| `cloudtrail-control-225510` | 2019-06-06 11:31:53+00:00 | aws:811596193553/ap-northeast-1 / Level6 | Level6 describe config:configuration-recorder-status [denied] | yes |
| `cloudtrail-control-225648` | 2019-06-06 11:31:59+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-acl (b5677c799b465420d8e7b0a6689a0bb0c4afbc9e.flaws.cloud) [denied] | yes |
| `cloudtrail-control-225649` | 2019-06-06 11:31:59+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-encryption (b5677c799b465420d8e7b0a6689a0bb0c4afbc9e.flaws.cloud) [denied] | yes |
| `cloudtrail-control-225650` | 2019-06-06 11:31:59+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-versioning (b5677c799b465420d8e7b0a6689a0bb0c4afbc9e.flaws.cloud) [denied] | yes |
| `cloudtrail-control-225651` | 2019-06-06 11:31:59+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-policy (b5677c799b465420d8e7b0a6689a0bb0c4afbc9e.flaws.cloud) [denied] | yes |
| `cloudtrail-control-225652` | 2019-06-06 11:31:59+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-logging (b5677c799b465420d8e7b0a6689a0bb0c4afbc9e.flaws.cloud) [denied] | yes |

**Computed:** 0 of 8 cited ids were not cited on this case by the deterministic pass.

---

## R081

**Case:** `flaws_cloud` / `CASE-122` (13 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-004` | HIGH | 'Level6' was refused authorization 84 times in 92s, across 13 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 13: `cloudtrail-control-1649380`, `cloudtrail-control-1649381`, `cloudtrail-control-1649382`, `cloudtrail-control-1649383`, `cloudtrail-control-1649386`, `cloudtrail-control-1649387`, `cloudtrail-control-1649388`, `cloudtrail-control-1649390`, `cloudtrail-control-1649391`, `cloudtrail-control-1649392`, `cloudtrail-control-1649393`, `cloudtrail-control-1649394` ... (+1 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> Because no source address resolved for any of the 5346 authentication events, the denial burst cannot currently be attributed to a specific network origin or tied to the authentication history by infrastructure; until source-IP or user-agent enrichment is recovered, any linkage between the T1580 discovery activity and the credential-guessing volume remains circumstantial and rests only on the shared account name.

**Evidence it cites (4):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1649392` | 2019-08-28 21:53:08+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-tagging (dev-eztax) [denied] | yes |
| `cloudtrail-control-1649393` | 2019-08-28 21:53:08+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-website (dev-eztax) [denied] | yes |
| `cloudtrail-logon-000683` | 2017-03-16 18:45:24+00:00 | aws:811596193553/us-east-1 / Level6 | failure logon [Unknown] from 5.3.205.235 reason=User: arn:aws:iam::811596193553:user/Level6 is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/service-role/Level6 | NO |
| `cloudtrail-logon-002347` | 2017-05-16 23:04:44+00:00 | aws:811596193553/us-east-1 / Level6 | failure logon [Unknown] from 10.154.248.134 reason=Not authorized to perform sts:AssumeRole | NO |

**Computed:** 2 of 4 cited ids were not cited on this case by the deterministic pass.

---

## R082

**Case:** `attack_data_aws` / `CASE-002` (5 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-004` | HIGH | 'cloudmapper' was refused authorization 37 times in 284s, across 5 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 5: `cloudtrail-control-001224`, `cloudtrail-control-001222`, `cloudtrail-control-001220`, `cloudtrail-control-001219`, `cloudtrail-control-001204` |

**Hypothesis (verbatim):**

> The principal name 'cloudmapper' matches a well-known open-source AWS auditing tool whose normal operation issues exactly this kind of broad read-only sweep across KMS, Organizations and Glue. If a sanctioned security or compliance scan is scheduled in this account, the entire case is expected tooling behaviour and the Discovery mapping is a false positive.

**Evidence it cites (3):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-001220` | 2021-04-13 13:33:45+00:00 | aws:731544447609/us-east-1 / cloudmapper | cloudmapper list organizations:account [denied] | yes |
| `cloudtrail-control-001224` | 2021-04-13 13:30:36+00:00 | aws:731544447609/us-east-1 / cloudmapper | cloudmapper list kms:key-policy [denied] | yes |
| `cloudtrail-control-001219` | 2021-04-13 13:34:57+00:00 | aws:731544447609/eu-north-1 / cloudmapper | cloudmapper get glue:job [denied] | yes |

**Computed:** 0 of 3 cited ids were not cited on this case by the deterministic pass.

---

## R083

**Case:** `flaws_cloud` / `CASE-067` (1 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-002` | CRITICAL | 'Level6' stopped CloudTrail trail ''. Disabling the audit trail is not a routine operational action and is consistent with an intruder removing the record of subsequent activity. | 1: `cloudtrail-control-226797` |

**Hypothesis (verbatim):**

> The absence of any resolved source address across all 5346 'Level6' authentication events suggests either log-field stripping/normalization loss or use of AWS-internal/assumed-role invocation paths, either of which would frustrate source-based attribution and correlation of the trail-stop actor to the authentication attempts.

**Evidence it cites (3):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-000144` | 2017-02-28 07:58:45+00:00 | aws:811596193553/us-east-1 / Level6 | success logon [Unknown] from 137.53.124.9 | NO |
| `cloudtrail-logon-000145` | 2017-02-28 08:01:21+00:00 | aws:811596193553/us-east-1 / Level6 | failure logon [Unknown] from 137.53.124.9 reason=User: arn:aws:iam::811596193553:user/Level6 is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/service-role/Level6 | NO |
| `cloudtrail-control-226797` | 2019-06-07 11:04:25+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 stop cloudtrail:logging [denied] | yes |

**Computed:** 2 of 3 cited ids were not cited on this case by the deterministic pass.

---

## R084

**Case:** `comiset` / `CASE-001` (2 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-002` | MEDIUM | PowerShell ran a base64-encoded command. The payload does not obviously fetch remote code, but the command line also suppresses the console window and/or the user profile. Evasion flags observed: no profile. | 1: `comiset_slice.jsonl:41ece3af25e0f38cccc6d27422a388c739761353` |
| `ATH-002` | MEDIUM | PowerShell ran a base64-encoded command. The payload does not obviously fetch remote code, but the command line also suppresses the console window and/or the user profile. Evasion flags observed: no profile. | 1: `comiset_slice.jsonl:574dffe7a299a4ad9d2b1150574e2cff72b4efb4` |

**Hypothesis (verbatim):**

> beacon.exe is a command-and-control implant (the name matches Cobalt Strike Beacon), and the two encoded PowerShell launches are operator-issued or automated post-exploitation tasks delivered over that C2 channel.

**Evidence it cites (3):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `comiset_slice.jsonl:b9a5cb4bdabc2fe887d9224d6c42056e5b64ff90` | 2022-11-18 10:27:21.393000+00:00 | desktop-4pvps6e / system | remotemouse.exe -> cmd.exe \| "c:\windows\system32\cmd.exe" | yes |
| `comiset_slice.jsonl:41ece3af25e0f38cccc6d27422a388c739761353` | 2022-11-18 11:15:51.211000+00:00 | desktop-4pvps6e / system | beacon.exe -> powershell.exe \| powershell -nop -exec bypass -encodedcommand sqbfafgaiaaoae4azqb3ac0atwbiagoazqbjahqaiaboaguadaauafcazqbiagmababpaguabgb0ackalgbeag8adwbuagwabwbhagqauwb0ahiaaqb | yes |
| `comiset_slice.jsonl:574dffe7a299a4ad9d2b1150574e2cff72b4efb4` | 2022-11-18 11:17:30.010000+00:00 | desktop-4pvps6e / system | beacon.exe -> powershell.exe \| powershell -nop -exec bypass -encodedcommand sqbfafgaiaaoae4azqb3ac0atwbiagoazqbjahqaiaboaguadaauafcazqbiagmababpaguabgb0ackalgbeag8adwbuagwabwbhagqauwb0ahiaaqb | yes |

**Computed:** 0 of 3 cited ids were not cited on this case by the deterministic pass.

---

## R085

**Case:** `flaws_cloud` / `CASE-005` (54 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-005` | CRITICAL | 53 failed logons for 'SecurityMokey' on aws:811596193553/us-east-1 from 255.253.125.115 within 247s. A successful logon followed at 22:26:48, -148s after the last failure. This may indicate the credential was successfully guessed and the account is now compromised. | 54: `cloudtrail-logon-002652`, `cloudtrail-logon-002653`, `cloudtrail-logon-002654`, `cloudtrail-logon-002655`, `cloudtrail-logon-002656`, `cloudtrail-logon-002657`, `cloudtrail-logon-002658`, `cloudtrail-logon-002659`, `cloudtrail-logon-002660`, `cloudtrail-logon-002661`, `cloudtrail-logon-002665`, `cloudtrail-logon-002664` ... (+42 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> 255.253.125.115 lies in the reserved 255.0.0.0/8 space and is not a routable Internet source, indicating the source field is anonymized, synthesized, or a placeholder; geolocation- or reputation-based enrichment of this indicator would be meaningless.

**Evidence it cites (2):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-002652` | 2017-05-26 22:25:09+00:00 | aws:811596193553/us-east-1 / SecurityMokey | failure logon [Unknown] from 255.253.125.115 reason=User: arn:aws:iam::811596193553:user/SecurityMokey is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/SecurityMonkey | yes |
| `cloudtrail-logon-002822` | 2017-05-26 22:29:16+00:00 | aws:811596193553/us-east-1 / SecurityMokey | failure logon [Unknown] from 255.253.125.115 reason=User: arn:aws:iam::811596193553:user/SecurityMokey is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/SecurityMonkey | yes |

**Computed:** 0 of 2 cited ids were not cited on this case by the deterministic pass.

---

## R086

**Case:** `synthetic:INC-001` / `CASE-001` (31 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-009` | MEDIUM | Outlook launched WINWORD.EXE to open a document in a macro-capable format. This is consistent with a malicious attachment being opened, independent of whether any embedded macro subsequently ran. | 1: `evt-000355` |
| `ATH-001` | HIGH | WINWORD.EXE started powershell.exe. Office applications have no routine need to launch script interpreters; this parent/child relationship is consistent with macro-based code execution from a document. | 1: `evt-000357` |
| `ATH-002` | HIGH | PowerShell ran a base64-encoded command. The decoded payload retrieves and executes remote content, which is consistent with a first-stage downloader. Evasion flags observed: hidden window, no profile. | 1: `evt-000357` |
| `ATH-003` | HIGH | powershell.exe made 7 outbound connection(s) to the external address 185.220.101.47 on port(s) 80, 443. Script interpreters do not normally initiate direct internet connections; this may indicate payload retrieval or command-and-control. The connection to port 80 indicates cleartext HTTP, which is commonly used to retrieve a second-stage script. | 7: `evt-000358`, `evt-000362`, `evt-000380`, `evt-000399`, `evt-000421`, `evt-000454`, `evt-000486` |
| `ATH-010` | MEDIUM | 3 distinct discovery commands (net.exe, nltest.exe, whoami.exe) ran from the same parent process (PID 6612) within 34s, consistent with systematic reconnaissance of the local environment and domain. | 3: `evt-000367`, `evt-000370`, `evt-000374` |
| `ATH-004` | CRITICAL | Command line matched credential-access indicators (comsvcs.dll MiniDump, explicit lsass reference, rundll32 MiniDump export). This may indicate an attempt to extract credential material from LSASS memory, which would enable authentication as other users. Requires immediate verification against the account's expected activity. | 1: `evt-000381` |
| `ATH-005` | CRITICAL | 14 failed logons for 'svc_backup' on FS02 from 10.10.20.15 within 143s. A successful logon followed at 09:33:47, 204s after the last failure. This may indicate the credential was successfully guessed and the account is now compromised. | 15: `evt-000419`, `evt-000422`, `evt-000425`, `evt-000427`, `evt-000429`, `evt-000431`, `evt-000432`, `evt-000433`, `evt-000437`, `evt-000438`, `evt-000439`, `evt-000440` ... (+3 more; all of them are in worksheet.csv) |
| `ATH-006` | HIGH | Account 'svc_backup' authenticated to FS02 from PC01, but has no interactive session on PC01 (observed owner(s): jdoe). Credential use originating from a host the account does not operate on is consistent with lateral movement using stolen credentials, though legitimate alternate-credential workflows produce the same pattern. | 1: `evt-000457` |
| `ATH-007` | HIGH | The Service Control Manager started an interactive command interpreter. This pattern is consistent with remote command execution via a temporary service. Command output is redirected to the administrative share '\\127.0.0.1\ADMIN$', which is characteristic of remote execution frameworks collecting results over SMB. | 1: `evt-000461` |
| `ATH-008` | HIGH | An archive utility was invoked and the source path uses a wildcard, implying bulk collection and the destination is a shared staging directory. This is consistent with staging data prior to exfiltration, but does not by itself show that any data left the network. | 1: `evt-000469` |
| `ATH-003` | MEDIUM | powershell.exe made 1 outbound connection(s) to the external address 185.220.101.47 on port(s) 443. Script interpreters do not normally initiate direct internet connections; this may indicate payload retrieval or command-and-control. | 1: `evt-000481` |

**Hypothesis (verbatim):**

> FS02 was the objective of the intrusion rather than a waypoint: it is the host reached by lateral movement, the host where data was archived with a utility, and a host that also contacted the C2 address, making it the likely staging point for collection and exfiltration.

**Evidence it cites (3):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `evt-000457` | 2026-08-17 09:33:47+00:00 | FS02 / svc_backup | success logon [Network (SMB / share access)] from 10.10.20.15 | yes |
| `evt-000469` | 2026-08-17 09:35:40+00:00 | FS02 / svc_backup | cmd.exe -> powershell.exe \| powershell.exe -nop -c Compress-Archive -Path D:\Finance\* -DestinationPath C:\Windows\Temp\fin.zip | yes |
| `evt-000481` | 2026-08-17 09:37:05+00:00 | FS02 / svc_backup | powershell.exe -> 185.220.101.47:443 (outbound) | yes |

**Computed:** 0 of 3 cited ids were not cited on this case by the deterministic pass.

---

## R087

**Case:** `flaws_cloud` / `CASE-205` (15 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | MEDIUM | 'Level6' made 563 read calls across 14 distinct services in 463s, 38 of them refused (7%). Breadth on this scale is consistent with account enumeration, and is also exactly what inventory and compliance tooling does. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 14: `cloudtrail-control-1760284`, `cloudtrail-control-1760328`, `cloudtrail-control-1760344`, `cloudtrail-control-1760376`, `cloudtrail-control-1760408`, `cloudtrail-control-1760425`, `cloudtrail-control-1760518`, `cloudtrail-control-1760534`, `cloudtrail-control-1760582`, `cloudtrail-control-1760662`, `cloudtrail-control-1760663`, `cloudtrail-control-1760664` ... (+2 more; all of them are in worksheet.csv) |
| `AWS-004` | MEDIUM | 'Level6' was refused authorization 38 times in 5s, across 3 distinct resource types. Concentrated on so few kinds of object, this is equally the shape of an application missing one permission and retrying. A refusal says what the platform would not do; it does not say what the caller intended. | 3: `cloudtrail-control-1760664`, `cloudtrail-control-1760670`, `cloudtrail-control-1760671` |

**Hypothesis (verbatim):**

> The presence of iam:ListUsers within an otherwise infrastructure-focused sweep may indicate the enumeration was aimed at identifying privilege-escalation targets rather than at inventorying assets. If so, follow-on activity would be expected against iam:ListAttachedUserPolicies, GetPolicyVersion or sts:AssumeRole; the absence of such calls in the current evidence argues the sweep either stopped early or was blocked.

**Evidence it cites (2):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1760425` | 2020-06-01 19:28:42+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 list iam:user [allowed] | yes |
| `cloudtrail-control-1760846` | 2020-06-01 19:29:37+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 get sts:caller-identity [allowed] | yes |

**Computed:** 0 of 2 cited ids were not cited on this case by the deterministic pass.

---

## R088

**Case:** `flaws_cloud` / `CASE-077` (15 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-004` | HIGH | 'Level6' was refused authorization 772 times in 221s, across 15 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 15: `cloudtrail-control-238972`, `cloudtrail-control-238973`, `cloudtrail-control-238974`, `cloudtrail-control-238975`, `cloudtrail-control-238977`, `cloudtrail-control-238978`, `cloudtrail-control-238979`, `cloudtrail-control-238980`, `cloudtrail-control-238981`, `cloudtrail-control-238982`, `cloudtrail-control-238983`, `cloudtrail-control-238984` ... (+3 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> Two identifiers inside the otherwise contiguous read block are absent from the claim set (238976 and 238985), which is the expected position of two further GetBucket* calls. The enumeration may therefore be more complete than the fourteen verified events show, with the missing calls either filtered from the case or having failed differently.

**Evidence it cites (4):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-238975` | 2019-06-21 15:43:30+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-lifecycle (flaws.cloud) [denied] | yes |
| `cloudtrail-control-238977` | 2019-06-21 15:43:30+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-request-payment (flaws.cloud) [denied] | yes |
| `cloudtrail-control-238984` | 2019-06-21 15:43:30+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-location (flaws.cloud) [denied] | yes |
| `cloudtrail-control-238986` | 2019-06-21 15:43:30+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-encryption (flaws.cloud) [denied] | yes |

**Computed:** 0 of 4 cited ids were not cited on this case by the deterministic pass.

---

## R089

**Case:** `flaws_cloud` / `CASE-118` (1 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-002` | CRITICAL | 'flaws' deleted CloudTrail trail 'arn:aws:cloudtrail:us-west-2:811596193553:trail/cloudtrail'. Disabling the audit trail is not a routine operational action and is consistent with an intruder removing the record of subsequent activity. | 1: `cloudtrail-control-1576322` |

**Hypothesis (verbatim):**

> The trail deletion was preceded by reconnaissance and/or resource access (e.g., S3, IAM, or EC2 enumeration) by the same credentials, which would be recoverable from CloudTrail records written before 2019-08-23T15:48:50Z or from other regions' trails, data-event logs, or S3 server access logs.

**Evidence it cites (3):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1576322` | 2019-08-23 15:48:50+00:00 | aws:811596193553/us-west-2 / flaws | flaws delete cloudtrail:trail (arn:aws:cloudtrail:us-west-2:811596193553:trail/cloudtrail) [allowed] | yes |
| `cloudtrail-logon-039246` | 2018-11-13 16:48:47+00:00 | aws:811596193553/us-east-1 / flaws | success logon [Unknown] from 163.251.223.26 | NO |
| `cloudtrail-logon-044401` | 2019-03-03 16:27:05+00:00 | aws:811596193553/us-east-1 / flaws | success logon [Unknown] from 2.7.223.252 | NO |

**Computed:** 2 of 3 cited ids were not cited on this case by the deterministic pass.

---

## R090

**Case:** `flaws_cloud` / `CASE-256` (32 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | MEDIUM | 'Level6' made 671 read calls across 21 distinct services in 550s, 196 of them refused (29%). Breadth on this scale is consistent with account enumeration, and is also exactly what inventory and compliance tooling does. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 20: `cloudtrail-control-1817072`, `cloudtrail-control-1817082`, `cloudtrail-control-1817085`, `cloudtrail-control-1817088`, `cloudtrail-control-1817159`, `cloudtrail-control-1817175`, `cloudtrail-control-1817217`, `cloudtrail-control-1817317`, `cloudtrail-control-1817318`, `cloudtrail-control-1817321`, `cloudtrail-control-1817323`, `cloudtrail-control-1817324` ... (+8 more; all of them are in worksheet.csv) |
| `AWS-004` | HIGH | 'Level6' was refused authorization 196 times in 241s, across 17 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 17: `cloudtrail-control-1817217`, `cloudtrail-control-1817246`, `cloudtrail-control-1817318`, `cloudtrail-control-1817322`, `cloudtrail-control-1817358`, `cloudtrail-control-1817365`, `cloudtrail-control-1817368`, `cloudtrail-control-1817369`, `cloudtrail-control-1817371`, `cloudtrail-control-1817372`, `cloudtrail-control-1817373`, `cloudtrail-control-1817374` ... (+5 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The principal name 'Level6' and the target bucket names ending in '.flaws.cloud' (level4-974134b52e7c35aebcc4b45f19113936.flaws.cloud and b5677c799b465420d8e7b0a6689a0bb0c4afbc9e.flaws.cloud) correspond to the publicly published flAWS.cloud training/CTF exercise, whose levels are named Level1..Level6. If confirmed, this is a deliberately vulnerable teaching account and the case should be triaged as expected exercise traffic, not an intrusion.

**Evidence it cites (4):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1817246` | 2020-09-21 04:00:23+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-location (level4-974134b52e7c35aebcc4b45f19113936.flaws.cloud) [denied] | yes |
| `cloudtrail-control-1817371` | 2020-09-21 04:00:45+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-tagging (b5677c799b465420d8e7b0a6689a0bb0c4afbc9e.flaws.cloud) [denied] | yes |
| `cloudtrail-control-1817372` | 2020-09-21 04:00:45+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-versioning (b5677c799b465420d8e7b0a6689a0bb0c4afbc9e.flaws.cloud) [denied] | yes |
| `cloudtrail-control-1817373` | 2020-09-21 04:00:45+00:00 | aws:811596193553/us-west-2 / Level6 | Level6 get s3:bucket-policy (b5677c799b465420d8e7b0a6689a0bb0c4afbc9e.flaws.cloud) [denied] | yes |

**Computed:** 0 of 4 cited ids were not cited on this case by the deterministic pass.

---

## R091

**Case:** `flaws_cloud` / `CASE-067` (1 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-002` | CRITICAL | 'Level6' stopped CloudTrail trail ''. Disabling the audit trail is not a routine operational action and is consistent with an intruder removing the record of subsequent activity. | 1: `cloudtrail-control-226797` |

**Hypothesis (verbatim):**

> If the 'Level6' principal is not normally entitled to modify logging configuration, the stop action implies a prior, unobserved privilege-escalation or credential-compromise step that occurred before the visibility gap opened; reviewing IAM policy attachments and prior authentication events for that principal would test this.

**Evidence it cites (1):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-226797` | 2019-06-07 11:04:25+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 stop cloudtrail:logging [denied] | yes |

**Computed:** 0 of 1 cited ids were not cited on this case by the deterministic pass.

---

## R092

**Case:** `flaws_cloud` / `CASE-256` (32 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | MEDIUM | 'Level6' made 671 read calls across 21 distinct services in 550s, 196 of them refused (29%). Breadth on this scale is consistent with account enumeration, and is also exactly what inventory and compliance tooling does. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 20: `cloudtrail-control-1817072`, `cloudtrail-control-1817082`, `cloudtrail-control-1817085`, `cloudtrail-control-1817088`, `cloudtrail-control-1817159`, `cloudtrail-control-1817175`, `cloudtrail-control-1817217`, `cloudtrail-control-1817317`, `cloudtrail-control-1817318`, `cloudtrail-control-1817321`, `cloudtrail-control-1817323`, `cloudtrail-control-1817324` ... (+8 more; all of them are in worksheet.csv) |
| `AWS-004` | HIGH | 'Level6' was refused authorization 196 times in 241s, across 17 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 17: `cloudtrail-control-1817217`, `cloudtrail-control-1817246`, `cloudtrail-control-1817318`, `cloudtrail-control-1817322`, `cloudtrail-control-1817358`, `cloudtrail-control-1817365`, `cloudtrail-control-1817368`, `cloudtrail-control-1817369`, `cloudtrail-control-1817371`, `cloudtrail-control-1817372`, `cloudtrail-control-1817373`, `cloudtrail-control-1817374` ... (+5 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The successful authentications for 'Level6' are the likely enabling precursor to this burst: a small number of successes amid mass failures would give a caller a working credential of unknown scope, which the 17-resource-type refusal pattern then maps out. Confirming this requires correlating the specific successful logon immediately preceding 03:54:58Z with the session used for the control-plane calls.

**Evidence it cites (4):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-000144` | 2017-02-28 07:58:45+00:00 | aws:811596193553/us-east-1 / Level6 | success logon [Unknown] from 137.53.124.9 | NO |
| `cloudtrail-logon-000145` | 2017-02-28 08:01:21+00:00 | aws:811596193553/us-east-1 / Level6 | failure logon [Unknown] from 137.53.124.9 reason=User: arn:aws:iam::811596193553:user/Level6 is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/service-role/Level6 | NO |
| `cloudtrail-control-1817072` | 2020-09-21 03:54:58+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 list iam:user [allowed] | yes |
| `cloudtrail-control-1817082` | 2020-09-21 03:55:05+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 describe ec2:instance [allowed] | yes |

**Computed:** 2 of 4 cited ids were not cited on this case by the deterministic pass.

---

## R093

**Case:** `flaws_cloud` / `CASE-143` (31 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | HIGH | 'backup' made 247 read calls across 69 distinct services in 599s, 234 of them refused for want of authority (95%). Breadth with no permission behind it is enumeration rather than administration. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 20: `cloudtrail-control-1678048`, `cloudtrail-control-1678050`, `cloudtrail-control-1678058`, `cloudtrail-control-1678059`, `cloudtrail-control-1678063`, `cloudtrail-control-1678064`, `cloudtrail-control-1678068`, `cloudtrail-control-1678070`, `cloudtrail-control-1678072`, `cloudtrail-control-1678074`, `cloudtrail-control-1678075`, `cloudtrail-control-1678076` ... (+8 more; all of them are in worksheet.csv) |
| `AWS-004` | HIGH | 'backup' was refused authorization 229 times in 599s, across 201 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 20: `cloudtrail-control-1678074`, `cloudtrail-control-1678075`, `cloudtrail-control-1678076`, `cloudtrail-control-1678077`, `cloudtrail-control-1678078`, `cloudtrail-control-1678079`, `cloudtrail-control-1678080`, `cloudtrail-control-1678081`, `cloudtrail-control-1678082`, `cloudtrail-control-1678083`, `cloudtrail-control-1678084`, `cloudtrail-control-1678085` ... (+8 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The pattern is consistent with an off-the-shelf cloud enumeration framework (e.g. Pacu, ScoutSuite, CloudFox, or a scripted loop over the AWS SDK service list) executed with the 'backup' credential, since such tools walk every known service in sorted order and tolerate per-call AccessDenied responses rather than stopping.

**Evidence it cites (6):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1678048` | 2019-11-04 01:04:11+00:00 | aws:811596193553/eu-west-1 / backup | backup list codestar:project [denied] | yes |
| `cloudtrail-control-1678074` | 2019-11-04 01:04:44+00:00 | aws:811596193553/eu-west-1 / backup | backup list events:rule [denied] | yes |
| `cloudtrail-control-1678081` | 2019-11-04 01:05:05+00:00 | aws:811596193553/eu-west-1 / backup | backup list greengrass:device-definition [denied] | yes |
| `cloudtrail-control-1678087` | 2019-11-04 01:05:07+00:00 | aws:811596193553/eu-west-1 / backup | backup get guardduty:invitations-count [denied] | yes |
| `cloudtrail-control-1678093` | 2019-11-04 01:05:16+00:00 | aws:811596193553/eu-west-1 / backup | backup list inspector:assessment-target [denied] | yes |
| `cloudtrail-control-1678099` | 2019-11-04 01:05:26+00:00 | aws:811596193553/eu-west-1 / backup | backup list kinesisanalytics:application [denied] | yes |

**Computed:** 0 of 6 cited ids were not cited on this case by the deterministic pass.

---

## R094

**Case:** `synthetic:INC-004` / `CASE-001` (6 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-012` | CRITICAL | 3 distinct security-control change(s) on PC03 by 'achen': Defender real-time monitoring disabled; a Defender scanning exclusion was added; a security product process was terminated. A single change is often administrative; several in one window is the shape of an attacker clearing the way for what comes next. | 3: `evt-000901`, `evt-000905`, `evt-000909` |
| `ATH-011` | CRITICAL | 3 distinct recovery control(s) were destroyed on PC03 by 'achen': Windows backup catalog deleted; boot-time recovery disabled; volume shadow copies deleted. Destroying recovery paths removes the ability to roll back and commonly immediately precedes encryption. | 3: `evt-000922`, `evt-000925`, `evt-000927` |

**Hypothesis (verbatim):**

> cmd.exe (PID 7419) is itself a child of some unobserved process; its parent and the method by which it obtained execution (phishing payload, remote service, scheduled task, or lateral movement from another host) are the critical missing links and should be the next collection priority, since the identity of PID 7419 is noted as inferred rather than directly observed.

**Evidence it cites (2):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `evt-000901` | 2026-08-17 11:12:00+00:00 | PC03 / achen | cmd.exe -> powershell.exe \| powershell.exe -nop -w hidden Set-MpPreference -DisableRealtimeMonitoring $true | yes |
| `evt-000922` | 2026-08-17 11:14:30+00:00 | PC03 / achen | cmd.exe -> vssadmin.exe \| vssadmin.exe delete shadows /all /quiet | yes |

**Computed:** 0 of 2 cited ids were not cited on this case by the deterministic pass.

---

## R095

**Case:** `synthetic:INC-001` / `CASE-001` (31 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-009` | MEDIUM | Outlook launched WINWORD.EXE to open a document in a macro-capable format. This is consistent with a malicious attachment being opened, independent of whether any embedded macro subsequently ran. | 1: `evt-000355` |
| `ATH-001` | HIGH | WINWORD.EXE started powershell.exe. Office applications have no routine need to launch script interpreters; this parent/child relationship is consistent with macro-based code execution from a document. | 1: `evt-000357` |
| `ATH-002` | HIGH | PowerShell ran a base64-encoded command. The decoded payload retrieves and executes remote content, which is consistent with a first-stage downloader. Evasion flags observed: hidden window, no profile. | 1: `evt-000357` |
| `ATH-003` | HIGH | powershell.exe made 7 outbound connection(s) to the external address 185.220.101.47 on port(s) 80, 443. Script interpreters do not normally initiate direct internet connections; this may indicate payload retrieval or command-and-control. The connection to port 80 indicates cleartext HTTP, which is commonly used to retrieve a second-stage script. | 7: `evt-000358`, `evt-000362`, `evt-000380`, `evt-000399`, `evt-000421`, `evt-000454`, `evt-000486` |
| `ATH-010` | MEDIUM | 3 distinct discovery commands (net.exe, nltest.exe, whoami.exe) ran from the same parent process (PID 6612) within 34s, consistent with systematic reconnaissance of the local environment and domain. | 3: `evt-000367`, `evt-000370`, `evt-000374` |
| `ATH-004` | CRITICAL | Command line matched credential-access indicators (comsvcs.dll MiniDump, explicit lsass reference, rundll32 MiniDump export). This may indicate an attempt to extract credential material from LSASS memory, which would enable authentication as other users. Requires immediate verification against the account's expected activity. | 1: `evt-000381` |
| `ATH-005` | CRITICAL | 14 failed logons for 'svc_backup' on FS02 from 10.10.20.15 within 143s. A successful logon followed at 09:33:47, 204s after the last failure. This may indicate the credential was successfully guessed and the account is now compromised. | 15: `evt-000419`, `evt-000422`, `evt-000425`, `evt-000427`, `evt-000429`, `evt-000431`, `evt-000432`, `evt-000433`, `evt-000437`, `evt-000438`, `evt-000439`, `evt-000440` ... (+3 more; all of them are in worksheet.csv) |
| `ATH-006` | HIGH | Account 'svc_backup' authenticated to FS02 from PC01, but has no interactive session on PC01 (observed owner(s): jdoe). Credential use originating from a host the account does not operate on is consistent with lateral movement using stolen credentials, though legitimate alternate-credential workflows produce the same pattern. | 1: `evt-000457` |
| `ATH-007` | HIGH | The Service Control Manager started an interactive command interpreter. This pattern is consistent with remote command execution via a temporary service. Command output is redirected to the administrative share '\\127.0.0.1\ADMIN$', which is characteristic of remote execution frameworks collecting results over SMB. | 1: `evt-000461` |
| `ATH-008` | HIGH | An archive utility was invoked and the source path uses a wildcard, implying bulk collection and the destination is a shared staging directory. This is consistent with staging data prior to exfiltration, but does not by itself show that any data left the network. | 1: `evt-000469` |
| `ATH-003` | MEDIUM | powershell.exe made 1 outbound connection(s) to the external address 185.220.101.47 on port(s) 443. Script interpreters do not normally initiate direct internet connections; this may indicate payload retrieval or command-and-control. | 1: `evt-000481` |

**Hypothesis (verbatim):**

> The credentials for 'svc_backup' may have been obtained from memory on PC01. This is unverified: no telemetry links the credential-access activity to this specific account.

**Evidence it cites (0):**

_This hypothesis cites no event ids._

---

## R096

**Case:** `flaws_cloud` / `CASE-113` (5 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-004` | HIGH | 'Level6' was refused authorization 918 times in 598s, across 5 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 5: `cloudtrail-control-323923`, `cloudtrail-control-323928`, `cloudtrail-control-323933`, `cloudtrail-control-323942`, `cloudtrail-control-323974` |

**Hypothesis (verbatim):**

> The authorization refusals attributed to this identity and its successful create calls are two halves of the same behaviour: the denials mapped the permission boundary and the successes are the subset the credential could actually reach. Under this reading the denials are not evidence of misconfiguration, because a misconfigured role would not typically be followed by a coherent build-out ending in a running instance.

**Evidence it cites (5):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-323923` | 2019-08-21 07:41:21+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 create iam:access-key (Level6) -> Level6 [denied] | yes |
| `cloudtrail-control-323928` | 2019-08-21 07:41:22+00:00 | aws:811596193553/us-east-1 / Level6 | Level6 create iam:user [denied] | yes |
| `cloudtrail-control-323933` | 2019-08-21 07:41:24+00:00 | aws:811596193553/ap-northeast-2 / Level6 | Level6 create ec2:key-pair (811596193553_ap-northeast-2_my_key_pair) [denied] | yes |
| `cloudtrail-control-323942` | 2019-08-21 07:41:25+00:00 | aws:811596193553/ap-northeast-2 / Level6 | Level6 create ec2:default-vpc [denied] | yes |
| `cloudtrail-control-323974` | 2019-08-21 07:41:30+00:00 | aws:811596193553/ap-northeast-2 / Level6 | Level6 run ec2:instance [denied] | yes |

**Computed:** 0 of 5 cited ids were not cited on this case by the deterministic pass.

---

## R097

**Case:** `attack_data_aws` / `CASE-002` (5 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-004` | HIGH | 'cloudmapper' was refused authorization 37 times in 284s, across 5 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 5: `cloudtrail-control-001224`, `cloudtrail-control-001222`, `cloudtrail-control-001220`, `cloudtrail-control-001219`, `cloudtrail-control-001204` |

**Hypothesis (verbatim):**

> An adversary who had compromised a credential and was mapping infrastructure would be expected to leave traces in a second tactic (credential access, collection, or exfiltration) either alongside or shortly after the reads. The case being confined to Discovery suggests either that collection was truncated to a narrow window or that no follow-on activity occurred, the latter being more consistent with automated scanning than with an intrusion.

**Evidence it cites (5):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-001204` | 2021-04-13 13:35:10+00:00 | aws:731544447609/eu-north-1 / cloudmapper | cloudmapper get glue:trigger [denied] | yes |
| `cloudtrail-control-001219` | 2021-04-13 13:34:57+00:00 | aws:731544447609/eu-north-1 / cloudmapper | cloudmapper get glue:job [denied] | yes |
| `cloudtrail-control-001220` | 2021-04-13 13:33:45+00:00 | aws:731544447609/us-east-1 / cloudmapper | cloudmapper list organizations:account [denied] | yes |
| `cloudtrail-control-001222` | 2021-04-13 13:31:05+00:00 | aws:731544447609/us-east-1 / cloudmapper | cloudmapper get kms:key-rotation-status [denied] | yes |
| `cloudtrail-control-001224` | 2021-04-13 13:30:36+00:00 | aws:731544447609/us-east-1 / cloudmapper | cloudmapper list kms:key-policy [denied] | yes |

**Computed:** 0 of 5 cited ids were not cited on this case by the deterministic pass.

---

## R098

**Case:** `flaws_cloud` / `CASE-219` (28 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | HIGH | 'i-aa2d3b42e5c6e801a' made 2712 read calls across 105 distinct services in 580s, 2637 of them refused for want of authority (97%). Breadth with no permission behind it is enumeration rather than administration. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 20: `cloudtrail-control-1776510`, `cloudtrail-control-1776511`, `cloudtrail-control-1776513`, `cloudtrail-control-1776514`, `cloudtrail-control-1776515`, `cloudtrail-control-1776516`, `cloudtrail-control-1776517`, `cloudtrail-control-1776518`, `cloudtrail-control-1776521`, `cloudtrail-control-1776522`, `cloudtrail-control-1776524`, `cloudtrail-control-1776525` ... (+8 more; all of them are in worksheet.csv) |
| `AWS-004` | HIGH | 'i-aa2d3b42e5c6e801a' was refused authorization 2637 times in 580s, across 621 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 20: `cloudtrail-control-1776510`, `cloudtrail-control-1776513`, `cloudtrail-control-1776514`, `cloudtrail-control-1776515`, `cloudtrail-control-1776516`, `cloudtrail-control-1776517`, `cloudtrail-control-1776518`, `cloudtrail-control-1776519`, `cloudtrail-control-1776520`, `cloudtrail-control-1776522`, `cloudtrail-control-1776523`, `cloudtrail-control-1776524` ... (+8 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> A subset of the reads has direct follow-on value for an attacker rather than for a compliance scan - kms:custom-key-store and glue:database/catalog touch key material and data-catalog metadata, route53 hosted-zones and route53domains expose DNS control surface, and cloudfront distributions/field-level-encryption expose edge configuration - so these specific calls should be prioritised when deciding between benign inventory and targeted reconnaissance.

**Evidence it cites (9):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1776524` | 2020-06-11 21:47:50+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a describe kms:custom-key-store [denied] | yes |
| `cloudtrail-control-1776525` | 2020-06-11 21:47:50+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a get glue:catalog-import-status [denied] | yes |
| `cloudtrail-control-1776530` | 2020-06-11 21:47:51+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a get glue:database [denied] | yes |
| `cloudtrail-control-1776528` | 2020-06-11 21:47:50+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a list route53:hosted-zone [denied] | yes |
| `cloudtrail-control-1776529` | 2020-06-11 21:47:50+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a list route53:health-check [denied] | yes |
| `cloudtrail-control-1776556` | 2020-06-11 21:47:51+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a list route53domains:domain [denied] | yes |
| `cloudtrail-control-1776514` | 2020-06-11 21:47:50+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a list cloudfront:distribution [denied] | yes |
| `cloudtrail-control-1776519` | 2020-06-11 21:47:50+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a list cloudfront:field-level-encryption-config [denied] | yes |
| `cloudtrail-control-1776520` | 2020-06-11 21:47:50+00:00 | aws:811596193553/us-east-1 / i-aa2d3b42e5c6e801a | i-aa2d3b42e5c6e801a list cloudfront:streaming-distribution [denied] | yes |

**Computed:** 0 of 9 cited ids were not cited on this case by the deterministic pass.

---

## R099

**Case:** `flaws_cloud` / `CASE-050` (34 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-003` | HIGH | 'backup' made 720 read calls across 87 distinct services in 596s, 498 of them refused for want of authority (69%). Breadth with no permission behind it is enumeration rather than administration. The rule counts how many services were read, not which, so it cannot say whether the target was the account's service inventory or its infrastructure. | 20: `cloudtrail-control-189268`, `cloudtrail-control-189271`, `cloudtrail-control-189274`, `cloudtrail-control-189276`, `cloudtrail-control-189278`, `cloudtrail-control-189290`, `cloudtrail-control-189293`, `cloudtrail-control-189312`, `cloudtrail-control-189320`, `cloudtrail-control-189322`, `cloudtrail-control-189323`, `cloudtrail-control-189330` ... (+8 more; all of them are in worksheet.csv) |
| `AWS-004` | HIGH | 'backup' was refused authorization 506 times in 161s, across 245 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 20: `cloudtrail-control-189271`, `cloudtrail-control-189274`, `cloudtrail-control-189276`, `cloudtrail-control-189278`, `cloudtrail-control-189279`, `cloudtrail-control-189280`, `cloudtrail-control-189281`, `cloudtrail-control-189286`, `cloudtrail-control-189287`, `cloudtrail-control-189290`, `cloudtrail-control-189291`, `cloudtrail-control-189292` ... (+8 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The principal is named 'backup', yet the observed reads target ACM, ACM-PCA, API Gateway, Athena, CloudFront, CloudHSM, CodeCommit, CodePipeline and CloudTrail — none of which a backup function requires. This semantic mismatch between the identity's apparent purpose and its behaviour is consistent with either (a) an over-permissioned service identity being reused by a general-purpose tool, or (b) a compromised credential whose name no longer reflects who is driving it. Resolving this requires the identity type (IAM user vs assumed role), key age, source IP and user-agent, none of which are in the current evidence.

**Evidence it cites (7):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-189274` | 2019-04-05 09:22:13+00:00 | aws:811596193553/us-east-1 / backup | backup list acm:certificate [denied] | yes |
| `cloudtrail-control-189276` | 2019-04-05 09:22:14+00:00 | aws:811596193553/us-east-1 / backup | backup list acm-pca:certificate-authority [denied] | yes |
| `cloudtrail-control-189330` | 2019-04-05 09:22:25+00:00 | aws:811596193553/us-east-1 / backup | backup list cloudfront:distribution [denied] | yes |
| `cloudtrail-control-189336` | 2019-04-05 09:22:26+00:00 | aws:811596193553/us-east-1 / backup | backup list cloudhsm:hsm [denied] | yes |
| `cloudtrail-control-189352` | 2019-04-05 09:22:29+00:00 | aws:811596193553/us-east-1 / backup | backup describe cloudtrail:trail [denied] | yes |
| `cloudtrail-control-189368` | 2019-04-05 09:22:33+00:00 | aws:811596193553/us-east-1 / backup | backup list codecommit:repository [denied] | yes |
| `cloudtrail-control-189378` | 2019-04-05 09:22:35+00:00 | aws:811596193553/us-east-1 / backup | backup list codepipeline:pipeline [denied] | yes |

**Computed:** 0 of 7 cited ids were not cited on this case by the deterministic pass.

---

## R100

**Case:** `flaws_cloud` / `CASE-122` (13 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `AWS-004` | HIGH | 'Level6' was refused authorization 84 times in 92s, across 13 distinct resource types. Refusals spread across this many kinds of object are consistent with a caller establishing what its credential can reach. A refusal says what the platform would not do; it does not say what the caller intended. | 13: `cloudtrail-control-1649380`, `cloudtrail-control-1649381`, `cloudtrail-control-1649382`, `cloudtrail-control-1649383`, `cloudtrail-control-1649386`, `cloudtrail-control-1649387`, `cloudtrail-control-1649388`, `cloudtrail-control-1649390`, `cloudtrail-control-1649391`, `cloudtrail-control-1649392`, `cloudtrail-control-1649393`, `cloudtrail-control-1649394` ... (+1 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The principal name 'Level6' follows the naming convention of tiered lab, CTF, or training accounts (e.g. flAWS-style challenge levels), and the bucket name 'dev-eztax' indicates a development-tier resource. If confirmed, this activity may be sanctioned security exercise or assessment traffic rather than an intrusion, which would explain the benign-alternative reading already noted for AWS-004. Resolving the account's purpose should precede escalation.

**Evidence it cites (3):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-control-1649380` | 2019-08-28 21:53:05+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-encryption (dev-eztax) [denied] | yes |
| `cloudtrail-control-1649391` | 2019-08-28 21:53:07+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-policy (dev-eztax) [denied] | yes |
| `cloudtrail-control-1649394` | 2019-08-28 21:53:08+00:00 | aws:811596193553/ap-southeast-1 / Level6 | Level6 get s3:bucket-versioning (dev-eztax) [denied] | yes |

**Computed:** 0 of 3 cited ids were not cited on this case by the deterministic pass.

---

## R101

**Case:** `synthetic:INC-004` / `CASE-001` (6 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-012` | CRITICAL | 3 distinct security-control change(s) on PC03 by 'achen': Defender real-time monitoring disabled; a Defender scanning exclusion was added; a security product process was terminated. A single change is often administrative; several in one window is the shape of an attacker clearing the way for what comes next. | 3: `evt-000901`, `evt-000905`, `evt-000909` |
| `ATH-011` | CRITICAL | 3 distinct recovery control(s) were destroyed on PC03 by 'achen': Windows backup catalog deleted; boot-time recovery disabled; volume shadow copies deleted. Destroying recovery paths removes the ability to roll back and commonly immediately precedes encryption. | 3: `evt-000922`, `evt-000925`, `evt-000927` |

**Hypothesis (verbatim):**

> The sequence is consistent with ransomware pre-encryption staging: security tooling is neutralised first (T1585-style tampering via PowerShell) and shadow copies are then destroyed via vssadmin to prevent restoration, typically immediately preceding a file-encryption or wiper payload that may not yet appear in the telemetry reviewed.

**Evidence it cites (6):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `evt-000901` | 2026-08-17 11:12:00+00:00 | PC03 / achen | cmd.exe -> powershell.exe \| powershell.exe -nop -w hidden Set-MpPreference -DisableRealtimeMonitoring $true | yes |
| `evt-000905` | 2026-08-17 11:12:35+00:00 | PC03 / achen | cmd.exe -> powershell.exe \| powershell.exe Add-MpPreference -ExclusionPath C:\ProgramData\svc | yes |
| `evt-000909` | 2026-08-17 11:13:10+00:00 | PC03 / achen | cmd.exe -> taskkill.exe \| taskkill.exe /F /IM MsMpEng.exe | yes |
| `evt-000922` | 2026-08-17 11:14:30+00:00 | PC03 / achen | cmd.exe -> vssadmin.exe \| vssadmin.exe delete shadows /all /quiet | yes |
| `evt-000925` | 2026-08-17 11:15:05+00:00 | PC03 / achen | cmd.exe -> wbadmin.exe \| wbadmin.exe delete catalog -quiet | yes |
| `evt-000927` | 2026-08-17 11:15:40+00:00 | PC03 / achen | cmd.exe -> bcdedit.exe \| bcdedit.exe /set {default} recoveryenabled no | yes |

**Computed:** 0 of 6 cited ids were not cited on this case by the deterministic pass.

---

## R102

**Case:** `flaws_cloud` / `CASE-005` (54 events in the case)

**Deterministic findings on this case, as every pass saw them:**

| rule | severity | why it fired | events it cites |
| --- | --- | --- | --- |
| `ATH-005` | CRITICAL | 53 failed logons for 'SecurityMokey' on aws:811596193553/us-east-1 from 255.253.125.115 within 247s. A successful logon followed at 22:26:48, -148s after the last failure. This may indicate the credential was successfully guessed and the account is now compromised. | 54: `cloudtrail-logon-002652`, `cloudtrail-logon-002653`, `cloudtrail-logon-002654`, `cloudtrail-logon-002655`, `cloudtrail-logon-002656`, `cloudtrail-logon-002657`, `cloudtrail-logon-002658`, `cloudtrail-logon-002659`, `cloudtrail-logon-002660`, `cloudtrail-logon-002661`, `cloudtrail-logon-002665`, `cloudtrail-logon-002664` ... (+42 more; all of them are in worksheet.csv) |

**Hypothesis (verbatim):**

> The sustained high volume of successful authentications from one IP after the failure burst is more consistent with automated/scripted API access using a validated credential (e.g. programmatic token reuse) than with interactive human console use.

**Evidence it cites (5):**

| event id | timestamp (UTC) | device / actor | what the event shows | already cited on this case? |
| --- | --- | --- | --- | --- |
| `cloudtrail-logon-002822` | 2017-05-26 22:29:16+00:00 | aws:811596193553/us-east-1 / SecurityMokey | failure logon [Unknown] from 255.253.125.115 reason=User: arn:aws:iam::811596193553:user/SecurityMokey is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::811596193553:role/SecurityMonkey | yes |
| `cloudtrail-logon-004000` | 2017-05-27 00:08:45+00:00 | aws:811596193553/us-east-1 / SecurityMokey | success logon [Unknown] from 255.253.125.115 | yes |
| `cloudtrail-logon-005000` | 2017-05-27 02:44:56+00:00 | aws:811596193553/us-east-1 / SecurityMokey | success logon [Unknown] from 255.253.125.115 | yes |
| `cloudtrail-logon-006000` | 2017-05-27 05:01:14+00:00 | aws:811596193553/us-east-1 / SecurityMokey | success logon [Unknown] from 255.253.125.115 | yes |
| `cloudtrail-logon-007195` | 2017-05-27 15:15:15+00:00 | aws:811596193553/us-east-1 / SecurityMokey | success logon [Unknown] from 255.253.125.115 | yes |

**Computed:** 0 of 5 cited ids were not cited on this case by the deterministic pass.

---
