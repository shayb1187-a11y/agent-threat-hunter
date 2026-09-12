# M16: Held-out real-world validation

**The question.** M15 fixed seven defects that real telemetry exposed. Every one of those
defects was found on a dataset that was then used to design its own fix. That is the
textbook setup for overfitting, and the M14/M15 numbers cannot distinguish "ATH got
better" from "ATH got better *on those four corpora*".

M16 answers: **did the M15 fixes generalize, or did they fit the data that exposed them?**

**Frozen at** `9350149`, tag `m16-freeze`. No detector, correlator, triage or adapter
behaviour changes between that commit and the recording of a held-out result. This
document's *Frozen expectations* section was written and committed **before any held-out
dataset was fetched or run** — it is in git history ahead of the results, so the
predictions are falsifiable rather than reconstructed.

---

## 1. Datasets and provenance

M14/M15 corpora are **regression data** from here on. They found the bugs and were tuned
against; they can show a fix has not rotted, and nothing more.

| Id | Dataset | Provenance | Role | Tuned against? |
| --- | --- | --- | --- | --- |
| R1 | DEDALE D03 (benign, 2024-12-25) | emulated-testbed, INRIA/IRISA | regression | yes (M15-1) |
| R2 | DEDALE D15 (attack day 1, 2025-01-06) | emulated-testbed | regression | yes |
| R3 | Kubernetes CI e2e, GCE run `2065053743543488512` | real kube-apiserver, benign workload | regression | yes (M15-3) |
| R4 | K8NTEXT v1.0.0 | emulated kubeadm cluster | regression | no, but inspected during M14 |
| R5 | flaws.cloud CloudTrail | real AWS account | regression | yes (M15-2) |
| R6 | Synthetic incident benchmark | synthetic | regression | yes |
| **H1** | **DEDALE D07** (benign, week 1) | emulated-testbed | **held out** | **no — never fetched** |
| **H2** | **Kubernetes `gci-gce-ingress` workload** (re-scoped, §4.2) | real kube-apiserver, GCE provisioner | **held out** | **no** |
| **H3** | **splunk/attack_data AWS techniques** | emulated attacks in a real AWS account | **held out** | **no** |
| **H4** | **COMISET LAB** | emulated, Universidad Pontificia Comillas; Elastic/HELK export (§4.8) | **held out** | **no** |
| **S1** | **DEDALE D18** (mid-APT) | emulated-testbed | **sealed** | **no — opened last, after all remediation** |

Labels stay confined to `ath.evaluation`; adapters never see them. Nothing derived from a
licence-restricted corpus is committed.

## 2. Why each held-out dataset, and what it can expose that the corpus cannot

**H1 — DEDALE D07.** The ATH-004 fix (stop matching LSASS's own image path) was designed
against D03. D07 is a different day of the same estate, never fetched or looked at. It
holds the fix to a weaker but still real standard: *different hosts booting, different
administrative workflows, same semantics*. It is a **temporal/host holdout, not
environment diversity** — same domain, same generator, same Sysmon config — and is
labelled that way throughout.

**H2 — Kubernetes, a second workload.** The K8S-001 fix reads the grantor's standing and
stays silent when a `system:masters` member grants `cluster-admin`. Every one of the 55
false positives it was designed against came from a GCE-provisioned cluster, so the
intended test was *a different provisioner's identity model* — originally planned as a
`kind` job.

**That test proved impossible and the hypothesis was re-scoped before the run; see §4.2.**
No non-GCE Kubernetes job publishes an apiserver audit log, so what H2 actually measures
is a different *workload* on the same provisioner. The identity-model question is recorded
in §5.1 as untestable on public data rather than quietly answered by a weaker experiment.

**H3 — splunk/attack_data AWS.** Every cloud number ATH has is a false-positive number.
flaws.cloud carries no per-event labels, so `AWS-001`/`AWS-002` have **never been measured
against a known cloud attack**. These are per-technique captures with documented
techniques, in a different account with a different API mix. They measure **true positives
only** — there is no benign background, so no false-positive rate can be computed from
them, and none will be quoted.

**H4 — COMISET LAB.** A different organisation's Windows telemetry in a non-ECS
representation. It tests whether the Windows fixes depend on security semantics or on
Winlogbeat's field naming. Held back until H1–H3 reported, so that it stayed available as
an untouched cross-schema check.

Two plan corrections found during acquisition are detailed in §4.8: the schema is the
Elastic/HELK `logs-endpoint-winevent-*` layout rather than the flat `Process_name` columns
the M14 notes describe, and the archive is a single 159.7 GB zip member that can only be
read as one sequential pass.

**S1 — DEDALE D18, sealed.** Opened once, last, after every other result was frozen and
committed. No remediation was performed in M16, so in the event it answers the overfitting
question against the same implementation every other holdout met — which is stronger, not
weaker: nothing at all was fitted between the freeze and this run.

### Rejected, with reasons

- **COMISET REAL (31.7 GB)** — the genuinely *real* environment, and infeasible: Zenodo
  answers a `Range` request with `HTTP 200` and the whole file, so the DEDALE
  range-fetch approach does not transfer. Recorded as a gap, not silently dropped.
- **BOTS v3 hybrid** — still blocked on a Splunk `exporttool` export.
- **Stratus-injected Kubernetes attacks** — still blocked: no Docker, kind, kubectl.
- **More Kubernetes CI runs** — same workload, same provisioner. Volume, not diversity.

## 3. Frozen expectations

Written before fetching. Each is a number that can be wrong.

### Regression — these are assertions, not predictions

| Id | Expectation |
| --- | --- |
| R1 | DEDALE D03: **0 findings, 0 cases** (was 30 / 30 before M15-1) |
| R2 | DEDALE D15: **0 findings, 0 cases**, event recall **0 of 5** |
| R3 | k8s_ci: **0 findings, 0 cases** (was 55 / 55) |
| R4 | K8NTEXT: **0 findings, 0 cases** |
| R5 | flaws.cloud: **39 findings** (ATH-005 ×36, AWS-002 ×3), **4 cases** |
| R6 | Benchmark **5/5, 0 noise cases**; suite **810 passed, 0 failed, 0 xfailed** |

### Held out — genuine predictions

**H1 — DEDALE D07.** Predict **0 ATH-004 findings** and **≤ 2 findings total**.

The ATH-004 fix is semantic, so boot-time LSASS should stay silent on any day; if D07
produces even one ATH-004 finding, the fix was fitted to D03's specific boot pattern. The
residual risk is not ATH-004 but *unexercised rules*: D03 happened to contain no backup,
shadow-copy or security-tool administration, so `ATH-011`/`ATH-012`/`ATH-002` have never
seen a benign DEDALE day that exercises them. A finding from one of those is a **new**
defect, not an M15 regression, and will be recorded as such.

**H2 — `conformance-kind`.** Predict **0 K8S-001 findings** and **0 K8S-002 findings**.

The stated failure mode: `kind` bootstraps via kubeadm, whose bootstrap identities are
not necessarily `system:masters` members. If a `cluster-admin` binding there is created by
`system:node-bootstrapper`, a kubeadm bootstrap token, or a plain SA, the grantor-standing
fix will not suppress it and K8S-001 fires. **I expect this is the most likely of the
three to fail**, because the fix was derived from one provisioner's identity model.

**H3 — attack_data AWS.** Predict **≥ 1 finding across the sampled techniques**, and
frankly, **low recall**.

`AWS-001` requires a grant-then-use chain and `AWS-002` a specific credential-creation
pattern; per-technique captures are short, isolated and often a handful of events, so the
chain each rule needs may simply not be present in the capture. A zero here is ambiguous
between "the rules cannot detect cloud attacks" and "these captures are too thin to carry
the chain", and the report will distinguish the two by inspecting what the capture
contains rather than reporting a bare recall number.

### Cross-cutting

**No rule may be weakened to improve any number here**, and no host, service account,
path, process name or vendor observed in a validation corpus may be hardcoded unless it is
a justified general invariant (`system:masters` is one — it is a Kubernetes API contract,
not an artefact of a cluster).

## 4. Results

### 4.1 Regression — all six expectations met

Run against `9350149`. Records in `reports/m16/`.

| Id | Expected | Measured | |
| --- | --- | --- | --- |
| R1 | DEDALE D03: 0 findings | 58,279 events, **0 findings, 0 cases** | ✅ |
| R2 | DEDALE D15: 0 findings, recall 0/5 | 49,276 rows, **0 findings, 0 cases, recall 0.0 (0/5)** | ✅ |
| R3 | k8s_ci: 0 findings | 7,951 control rows, **0 findings, 0 cases** | ✅ |
| R4 | K8NTEXT: 0 findings | 31 control rows, **0 findings, 0 cases** | ✅ |
| R5 | flaws.cloud: 39 findings, 4 cases | 79,520 rows, **39 findings** (ATH-005 ×36, AWS-002 ×3), **4 cases** | ✅ |
| R6 | Benchmark 5/5, 0 noise; suite 810/0/0 | *see §4.5* | ✅ |

The M15 improvements have not rotted, and the M14/M15 numbers remain reproducible.

### 4.2 H2 — Kubernetes `conformance`/ingress workload: prediction held, evidence weak

**Amendment to the plan, recorded before the run.** H2 was specified as "a second
Kubernetes audit source from a different cluster/workload style", with the intended
failure mode being *a different provisioner's identity model*. That is **not testable with
available public data**, and my original probe was wrong: I read `HTTP 200` from a GCS
prefix listing as "job exists", but GCS answers 200 for an *empty* listing. Enumerating
all **6,496** jobs in `kubernetes-ci-logs` and checking artifacts directly:

- `kind` jobs exist (`ci-kind-dra-*`) but archive **no** audit log.
- AWS- and CAPZ-provisioned jobs archive **no** audit log.
- Only the GCE `artifacts/bootstrap-e2e-master/kube-apiserver-audit.log` convention
  publishes one.

So H2 was re-scoped to `ci-kubernetes-e2e-gci-gce-ingress` run `2064903754573942784`
(67 MB, sha256 `970c307f…`): **a different workload and a different cluster instance, on
the same provisioner.**

| Measure | Value |
| --- | --- |
| Rows read / kept | 48,974 / 234 (0.48%) |
| RBAC binding creates ingested | **154** (142 clusterrolebindings, 12 rolebindings) |
| Pod execs ingested | 80 |
| `cluster-admin` grants present | 1 |
| **K8S-001 findings** | **0** |
| **K8S-002 findings** | **0** |

**Not vacuous:** the rule had 154 binding creates to fire on, including
`system:apiserver` granting `cluster-admin` to `system:masters` — exactly the suppression
case — and stayed silent.

**But weak.** Comparing grantor identities against the corpus the fix was tuned on:

```
ingress binding-creating actors:  system:addon-manager, system:apiserver
ci      binding-creating actors:  kubecfg, system:addon-manager, system:apiserver
actors NEW in ingress:            (none)
roles  NEW in ingress:            (none)
```

Every grantor identity and every role in the held-out corpus was **already present in the
tuning corpus**. H2 therefore shows the fix is not specific to one CI *run*; it says
nothing about whether it generalises to a different identity model. The question the
holdout was designed to answer remains open, and is recorded as a coverage gap rather
than counted as a pass.

### 4.3 H1 — DEDALE D07: prediction held, but the test was underpowered

| Measure | D03 (tuning) | **D07 (held out)** |
| --- | --- | --- |
| Raw archive volume | 1.35 GB | **41.7 MB** |
| Process rows | 43,994 | **1,449** |
| **Active hosts** | **30** | **1** |
| **`lsass.exe` events (the ATH-004 trigger)** | **30** | **1** |
| ATH-004 findings | 0 (was 30 pre-M15) | **0** |
| Total findings | 0 | **0** |

The prediction (0 ATH-004, ≤2 total) held. **The test is much weaker than intended**, and
the cause is my day selection, not the data: D07 is Sunday 29 December. Reading per-day
volumes out of the archive index afterwards shows D06, D07, D13, D14, D20, D21, D27 and
D28 are all ≈30–48 MB against ≈1.3 GB for every weekday — the testbed is essentially idle
at weekends. I chose a holiday Sunday by accident and gave the fix **one** opportunity to
misfire instead of thirty.

This is recorded as a **low-power pass**, not a pass.

### 4.4 Amended pre-registration — written before H1b and H3 ran

**H1b — DEDALE D02.** Selection criterion, fixed before fetching and independent of any
ATH output: *the highest-volume unfetched benign day by compressed archive size*. That is
D02 at 1,447,695,645 bytes. Selecting on data volume is a power criterion; selecting on
findings would be tuning, and is not what happened here.

> **Prediction: 0 ATH-004 findings, and ≤ 2 findings in total, across ~30 hosts.**
> D02 should carry roughly D03's 30 boot-time LSASS events. If the ATH-004 fix were
> fitted to D03, this is where it shows. The residual risk remains unexercised rules —
> D03 contained no backup, shadow-copy or security-tool administration, so ATH-002,
> ATH-011 and ATH-012 have never met a full benign DEDALE weekday. A finding from one of
> those is a **new** defect, not an M15 regression.

**H3 — attack_data AWS.** Five native-CloudTrail captures kept
(`aws_login_sfa`, `aws_iam_delete_policy`, `aws_security_scanner`,
`aws_iam_accessdenied_discovery_events`, `aws_iam_assume_role_policy_brute_force`). The
`asl_ocsf_*` and `amazon_security_lake` variants are **excluded**: OCSF is a different
schema needing a different adapter, not a result being avoided.

> **Declared change to frozen behaviour.** These captures are NDJSON; `CloudTrailSource`
> requires a top-level `Records` array, so it would ingest **zero rows** and H3 would be
> vacuous. One **ingestion-format** change is therefore made — accept NDJSON as well as
> `Records` — which touches no rule, threshold, severity or correlation logic. Its
> neutrality is not assumed: R5 (flaws.cloud) is re-run afterwards and must still report
> **39 findings and 4 cases**. If it does not, the change is not neutral and the result
> is void.
>
> **Prediction: ≥ 1 finding across the five captures, and low recall overall.** `AWS-001`
> needs a grant-then-use chain and `AWS-002` a credential-creation pattern; per-technique
> captures are short and isolated, so the chain each rule needs may simply not be present.
> A zero is ambiguous between "cannot detect cloud attacks" and "captures too thin to
> carry the chain", so the result is reported alongside what each capture actually
> contains.

### 4.5 H3 — attack_data AWS: **prediction wrong, and a major new defect**

**Predicted ≥ 1 finding. Measured 0.** The reason is not the one I anticipated.

| Measure | Value |
| --- | --- |
| CloudTrail records read | 2,349 |
| **Rows ingested** | **2 (0.09%)** |
| Distinct `eventName`s present | **109** |
| `eventName`s ATH can map | **9** |
| …of those 9, present in the captures | **1** (`ConsoleLogin`, 2 records) |
| Findings | 0 |

The declared NDJSON change worked — the files parse, and the suite and R5 are unchanged
(810 passed; flaws.cloud still 1,939,207 read / 79,520 kept / 39 findings / 4 cases), so
the change is behaviour-neutral as required and the result stands.

**But the rules were never given the attack.** ATH's entire CloudTrail vocabulary is nine
event names:

```
AssumeRole  AttachUserPolicy  ConsoleLogin  CreateAccessKey  DeleteTrail
GetFederationToken  GetSessionToken  PutUserPolicy  StopLogging
```

The captures contain 109 distinct event names, of which exactly one is in that list. The
single most common attack action in the corpus — `DeletePolicy`, 116 records, the IAM
manipulation that *is* the T1098 technique — has no canonical home and is dropped, along
with every `Describe*` reconnaissance call.

**This is a newly discovered defect, not an M15 regression, and it is the most important
result in this milestone.** It was invisible to every previous corpus for a structural
reason: flaws.cloud has no labelled attacks, so cloud detection had only ever been
measured by its *false positives*, and a rule set that sees almost nothing scores
perfectly on that metric. The first held-out corpus containing actual cloud attacks put
the real number at **0.09% representability**.

It also reframes an earlier claim. flaws.cloud's 4.10% ingestion was reported in M14 as an
ingestion-coverage figure; H3 shows the same ceiling is what makes cloud *detection*
untestable. The two AWS rules have still never been measured against a cloud attack.

**Recorded before any remediation**, per the holdout protocol. No fix is attempted in this
section.

### 4.6 R6 — suite and benchmark at the frozen commit

810 passed, 1 skipped, 0 failed, 0 xfailed. Benchmark 5/5, 0 noise cases. Re-verified
after the NDJSON change with identical results.

### 4.7 H1b — DEDALE D02: **strong pass**

**Hypothesis (stated before the run):** 0 ATH-004 findings and ≤ 2 findings in total.
**Falsifier:** a single ATH-004 finding would show the fix was fitted to D03's boot
pattern; a finding from ATH-002/011/012 would be a new defect on a benign weekday.
**Provenance:** DEDALE D02 (2024-12-24), emulated-testbed, **truly held out** — never
fetched or inspected before this run, selected on compressed archive size alone.

| | hosts | users | process rows | logon rows | **`lsass.exe` events** | findings |
| --- | --- | --- | --- | --- | --- | --- |
| D03 (tuning) | 30 | 36 | 43,994 | 14,285 | **30** | 0 |
| D07 (H1, low-power) | 1 | 7 | 1,449 | 142 | **1** | 0 |
| **D02 (H1b, held out)** | **30** | **36** | **46,510** | **34,736** | **28** | **0** |

| Measure | Value |
| --- | --- |
| Representability | 81,246 of 122,978 kept (66.07%) |
| Findings / cases | **0 / 0** |
| TP / FP / FN | no attack present; every finding would be an FP. **FP = 0** |
| Correlation / triage | no findings, so neither engaged |
| Runtime | hunt 19.9 s on 81,246 events |
| **Verdict** | **strong** |

This is the test H1 was meant to be. D02 carries the same trigger material as the tuning
day — 28 boot-time LSASS events across the same 30 hosts — so the ATH-004 fix had 28
independent opportunities to misfire on a day it was never shown, and took none of them.
Before M15-1 the equivalent day produced 30 findings and 30 singleton cases.

It is also a harder authentication test than the tuning day by accident: 34,736 logon
rows against D03's 14,285, **2.4×**, with ATH-005 and ATH-006 still silent throughout.

The residual risk named in the pre-registration did not materialise — no ATH-002, ATH-011
or ATH-012 finding — but neither was it *exercised*: a benign DEDALE weekday simply
contains no backup, shadow-copy or security-tool administration. Those three rules remain
unmeasured against real benign Windows telemetry, which is a coverage gap, not a pass.

### 4.8 H4 — COMISET LAB: pre-registration and disclosure

**Disclosure first.** H1b and H3 had numeric predictions committed to git before they ran.
H4 does not. Its hypothesis was committed in §2 before the corpus was fetched — *do the
Windows fixes depend on security semantics, or on Winlogbeat's field naming?* — but by
the time I wrote a falsifier the profile was already running. The qualitative hypothesis
is pre-registered; a numeric one is not, and the result below is weaker evidence for it.

**Falsifier:** any ATH-004 finding on benign COMISET process events would show the M15-1
fix is tied to the ECS representation rather than to argv[0] semantics, since this corpus
reaches the rule through a completely different adapter and field map.

**Two corrections to the plan, both discovered during acquisition.**

1. The M14 candidate notes describe COMISET as flat `Process_name`/`CommandLine`/
   `process_parent_name` columns. It is not. It is an Elasticsearch export in the
   **HELK/OTRF `logs-endpoint-winevent-*` layout** — `process_name`, `process_parent_name`,
   `user_account`, `dst_ip_addr`, `hash_sha256`, wrapped in a `_source` envelope. That is
   the same layout OTRF Security-Datasets publish, which is why the adapter is written
   against the schema and not against this corpus.
2. The archive is **one zip member, 159.7 GB uncompressed**. It cannot be extracted and
   cannot be seeked; one sequential decompressing pass is the only access pattern. A
   **time-ordered prefix of 20,000,000 records was declared as the bound before the slice
   was taken**, and the per-channel totals of everything *seen* are recorded alongside it
   so representability is computed against the corpus rather than against the slice.

**What the slice contains** (`data/external/comiset/slice/comiset_seen.json`):

| Class | Seen | Kept |
| --- | --- | --- |
| `sysmon/12` registry | 13,355,348 | — (no canonical home) |
| `sysmon/10` process access | 4,476,856 | — (no canonical home) |
| `sysmon/3` network | 589,477 | **589,477** |
| `sysmon/11` file create | 517,273 | — |
| `sysmon/1` process create | 15,095 | **15,095** |
| `security/4624` logon success | 6,009 | **6,009** |
| `security/4625` logon failure | 54 | **54** |
| **Total** | **20,000,000** | **610,635 (3.05%)** |

Worth noting independently of any finding: this is **the first real Windows corpus that
populates ATH's network table**. DEDALE's Sysmon 3 channel was empty in every hour
fetched, so `ATH-003` and the network specialist have never run on real endpoint data
until now.

**H4 result.**

| Measure | Value |
| --- | --- |
| Records in corpus prefix | 20,000,000 |
| Ingested | 610,635 (**3.05%**) |
| Findings | **5** — ATH-002 ×3, ATH-010 ×1, ATH-012 ×1 |
| **ATH-004 findings** | **0** — the registered falsifier did not trigger |
| Cases | 1 (singleton) |
| Triage | 4 `likely_malicious`, 1 `needs_review`, **0 cleared**, 5 left to review |
| TP / FP / FN | **not computable — see below** |
| Runtime | ingest 890 s; hunt 9.2 s, environment 17.9 s, correlate 8.8 s |
| **Verdict** | **partial pass on the stated hypothesis; unclassified on volume** |

**The fix generalised across schema.** Zero ATH-004 findings on 15,095 process-create
events that reached the rule through a different adapter, a different field map and a
different organisation's Sysmon configuration. The M15-1 argv[0] fix is not tied to the
ECS representation. That is the one thing H4 was designed to test, and it passed.

**But the five findings cannot be scored, and the reason is a correction to M14.** The
M14 candidate assessment recorded COMISET under *"Labels / ground truth: per-event ATT&CK
technique columns"*. That is wrong. The fields carrying technique ids are
`RuleName`/`rule_technique_id`/`rule_technique_name`, and they are the **sysmon-modular
configuration's rule annotations** — the output of a competing detection heuristic
attached at collection time, not curated ground truth. In the first 200,000 kept records
they tag 98,046 events `T1036 Masquerading` and 90,515 `T1059.001 PowerShell`; those are
rule matches, not 188,000 attacks.

So for these five findings there is **no trustworthy answer to "was this real?"**. They
cannot be called false positives — the corpus is published as containing malicious
activity and may well contain these events deliberately — and they cannot be called true
positives either. Scoring them against the sysmon-modular tags would be measuring
agreement with another tool's heuristic and calling it precision.

**Recorded as unclassified — but the evidence is legible, and that is worth separating
from the label.** What the five findings actually cite:

| Rule | Severity | Evidence |
| --- | --- | --- |
| ATH-012 | HIGH | `sc stop windefend` — stopping Windows Defender |
| ATH-010 | MEDIUM | `cmd.exe -> whoami.exe: whoami /all`, ×4 |
| ATH-002 | MEDIUM | ×3 (evidence string truncated by a console encoding error, not re-run) |

Stopping Defender and enumerating one's own privileges from a shell are not activities a
detection engine should be embarrassed to surface on a corpus published under the title
*"analysis of malicious events in Windows systems"*. They are far more plausibly true
positives than false ones.

That is an argument, not a measurement, and it is left as one. Without trustworthy labels
the entry stays **unclassified**: 5 findings, 1 case, 0.0004 per day at this corpus's
event rate, none cleared by triage. The distinction being preserved is between *"we
measured these and they were right"* — which would be false — and *"these are defensible
on their face and we could not verify them"*, which is what happened.

**A second observation, independent of any finding.** This is the first real Windows
corpus that populates ATH's network table: 589,477 Sysmon-3 connection events, against
DEDALE's zero in every hour fetched. `ATH-003` and the network specialist had never run on
real endpoint telemetry before this. The scaling cost showed up immediately and is worth
recording: **the environment model took 17.9 s and correlation 8.8 s, against 9.2 s for
the entire hunt** — building a connection pattern per `(host, remote_ip)` pair is now the
dominant term, where on synthetic data detection always was.

### 4.9 S1 — DEDALE D18, sealed: run once, after everything

**Hypothesis:** with every M16 result already frozen, a mid-APT day from the same estate
that was never fetched, never inspected and never tuned against should (a) raise no false
positives, and (b) remain undetected for the same representation reason D15 did.
**Falsifier for (a):** any finding on this day is a false positive *or* a genuine
detection, and either would need explaining against a day nothing was fitted to.
**Provenance:** DEDALE D18 (2025-01-09), attack week, **sealed** — fetched as bytes only
while H4 ran, opened once, after H1b/H4 were recorded and committed.
**Frozen implementation:** `git diff m16-freeze..HEAD` over `hunting/`, `correlation/`,
`triage/` and `mitre/` is empty; the only `src/` changes in this milestone are two
telemetry adapters, and D18 reaches the rules through the untouched Winlogbeat path.

| Measure | Value |
| --- | --- |
| Rows read / ingested | 60,435 / **48,893 (80.9%)** |
| Labelled malicious refs | 9,567 |
| **…resolvable in ingested telemetry** | **2 (0.02%)** |
| …never ingested | **9,565** |
| Findings / cases / noise cases | **0 / 0 / 0** |
| TP / FP / FN | **0 / 0 / 2** |
| Precision / recall | undefined (no findings) / **0.0** |
| Correlation / triage | neither engaged — nothing to work on |
| Conclusions | `CLIENT2` missed |
| Trust | 0 fabricated citations, 0 rejected claims, 0 overclaims |
| **Verdict** | **(a) strong pass, (b) confirmed representation failure** |

Both halves matter and they point opposite ways. **No false positives on a day nothing
was fitted to** is the strongest single piece of generalisation evidence in this
milestone, because it is the only dataset that was sealed through the entire remediation
history. And **0 of 2 recall, with 9,565 of 9,567 labelled events never ingested**, is
the same ceiling H3 found in the cloud, in a second environment: the attack is not missed
by the rules, it is invisible to the reader.

## 5. Conclusion

### 5.1 Results by class

**Regression success.** R1–R6 all reproduced at the frozen commit: DEDALE D03 and D15,
`k8s_ci` and K8NTEXT silent; flaws.cloud 39 findings in 4 cases; benchmark 5/5, 0 noise
cases; suite green. M15 has not rotted and its numbers remain reproducible.

**Generalization success — three results, in descending strength.**

1. **DEDALE D02 (H1b).** 28 boot-time LSASS events across 30 hosts and 36 users on a day
   never inspected, and **0 findings**, where the equivalent day produced 30 findings and
   30 singleton cases before M15-1. Plus 2.4× the tuning day's logon volume with ATH-005
   and ATH-006 silent throughout.
2. **DEDALE D18 (S1, sealed).** 0 findings on a mid-APT day that was sealed through the
   entire milestone. Nothing was fitted to it, and nothing fired.
3. **COMISET (H4).** 0 ATH-004 findings on 15,095 process creates arriving through a
   different adapter, field map and Sysmon configuration — the argv[0] fix is not tied to
   the ECS representation.

Together with the metamorphic layer — 36 invariance assertions across host, user, PID,
timestamp, path, cluster, namespace and service account — the M15 fixes key on security
semantics rather than on the corpora that exposed them. **That is the milestone's answer,
and it is a positive one.**

**Weak or inconclusive evidence — held to that label deliberately.**

- **H2 (Kubernetes ingress).** 0 findings on 154 binding creates including a
  `cluster-admin` grant to `system:masters`, so not vacuous — but **every grantor identity
  and role in the holdout already appeared in the tuning corpus**. It shows the fix is not
  specific to one CI *run*. It says nothing about a different identity model.
- **H1 (DEDALE D07).** 0 findings, but a weekend day: 1 active host and 1 LSASS event
  against 30 and 30. One chance to misfire, not thirty. A low-power pass, superseded by
  H1b but kept in the record because the fault was my day selection.
- **H4's five findings.** ATH-002 ×3, ATH-010, ATH-012, none cleared by triage, and
  **unclassifiable**: COMISET's technique fields are sysmon-modular `RuleName` annotations,
  not ground truth, so they can be called neither true nor false positives. Their evidence
  is defensible on its face — `sc stop windefend`, `whoami /all` from a shell — and that
  is an argument rather than a measurement, so the label stays unclassified.

**Representation failure — the dominant limitation, found twice, in two environments.**

| | H3 (AWS, held out) | S1 (DEDALE D18, sealed) |
| --- | --- | --- |
| Attack telemetry present | 2,349 CloudTrail records | 9,567 labelled events |
| Operations / events ATH can represent | **2 (0.09%)** | **2 (0.02%)** |
| Findings | 0 | 0 |
| Cause | 109 distinct API operations, ATH maps 9, 1 present | labelled events live in channels with no canonical table |

Neither is a detection failure. In both cases the rules were never shown the attack. The
cloud form of it is the sharper statement:

```
109 observed API operations -> ATH maps 9 -> only 1 supported operation present
   -> 0.09% ingestion -> attack invisible
```

**Newly discovered defects, frozen before remediation.**

- **M16-1** (metamorphic). ATH-004 strips `argv[0]` with `split(None, 1)`, so an unquoted
  image path containing a space leaks a path fragment into the arguments and fires
  CRITICAL on a process that is merely starting. Unreachable from DEDALE, whose LSASS
  lives in a space-free system path. Pinned as a strict xfail.
- **M16-2** (H3). Cloud representability is 0.09% on real attack telemetry. Recorded as
  the pre-remediation baseline for the next milestone.
- **M16-3** (H4, measurement). M14's dataset assessment recorded COMISET as carrying
  per-event ATT&CK ground truth. It does not, and any precision computed against those
  fields would have been agreement with another tool's heuristic.

**Untestable on available public data.**

- **A different Kubernetes identity model.** Of **6,496** jobs in `kubernetes-ci-logs`,
  only the GCE `bootstrap-e2e-master` convention publishes an apiserver audit log; `kind`,
  AWS and CAPZ jobs publish none. The provisioner-generalisation question cannot be
  answered from public CI data, and my original probe was wrong to claim otherwise — GCS
  answers `HTTP 200` for an empty prefix listing.
- **A real-environment Windows corpus.** COMISET REAL (31.7 GB) is the genuinely
  non-laboratory dataset, and Zenodo serves no range requests, so it cannot be
  subset-fetched the way DEDALE was.
- **Recall on real telemetry, anywhere.** Every corpus reached either has no attack, or
  has an attack ATH cannot represent. No held-out true positive was measured in this
  milestone, and none was measurable.
- Still blocked from M14: Stratus injection (no Docker/kind/kubectl) and BOTS v3
  (Splunk export).

### 5.2 The question

> **Did M15 generalize beyond the datasets used to develop its fixes, and where did
> held-out validation show that ATH still fails because of representation, detection, or
> environment assumptions?**

**M15 generalized.** The fixes were not fitted to their corpora. The strongest evidence is
DEDALE D02 — 28 independent opportunities to reproduce the original false positive on an
uninspected day, none taken — corroborated by a sealed attack day that stayed silent, by a
different-schema corpus reaching the same rule through a different adapter, and by 36
metamorphic invariance assertions. On the question M16 was convened to answer, the answer
is yes.

**The generalisation is narrower than that sentence sounds, in three specific ways.**

*Representation is the dominant failure, and it is not close.* Held-out validation put two
independent numbers on it: **0.09%** of a real cloud attack and **0.02%** of a sealed
Windows attack day were representable at all. Every cloud and Windows recall figure in
this project is bounded by ingestion, not by detection, and no amount of rule work moves
them. This is where the next milestone belongs, and it should model **control-plane
behaviour families** — credential lifecycle, policy modification, reconnaissance,
audit-trail tampering — rather than adding `DeletePolicy` and the rest of the current
attack_data corpus one event name at a time, which would reproduce in cloud exactly the
overfitting M16 was built to detect.

*Detection failures are real but second-order.* M16-1 is a genuine one — and notably, it
is an **environment assumption inside a fix that was otherwise correct**: M15-1 reasoned
rightly that argv[0] is what a process *is*, then implemented it with a whitespace split
that only works where paths have no spaces. It was invisible to every corpus and took a
metamorphic permutation to reach, which is an argument for keeping that layer.

*Environment assumptions were tested unevenly.* Windows generalisation is now
well-evidenced across day, host, user and schema. Kubernetes is evidenced only within a
single identity model, and the experiment that would settle it cannot be run on public
data. flaws.cloud and COMISET both turned out to carry weaker ground truth than M14
recorded. The honest position is that **ATH is validated on Windows endpoint telemetry,
provisionally validated on Kubernetes, and unvalidated for detection on cloud** — not
because the cloud rules are wrong, but because nothing has ever shown them an attack they
could see.
