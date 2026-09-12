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
| **H2** | **Kubernetes `conformance-kind` job** | real kube-apiserver, `kind` provisioner | **held out** | **no** |
| **H3** | **splunk/attack_data AWS techniques** | emulated attacks in a real AWS account | **held out** | **no** |
| **H4** | **COMISET LAB** (conditional) | emulated, Universidad Pontificia Comillas | **held out** | **no** |
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

**H2 — Kubernetes `conformance-kind`.** The K8S-001 fix reads the grantor's standing and
stays silent when a `system:masters` member grants `cluster-admin`. Every one of the 55
false positives it was designed against came from a GCE-provisioned cluster. `kind`
bootstraps through a different path with different `system:*` identities, so if the fix
happened to encode "GCE's bootstrap pattern" rather than "the grantor already outranks the
grantee", this is where it breaks. Same publisher and project as R3 — **a different
provisioner and workload, not a different organisation**.

**H3 — splunk/attack_data AWS.** Every cloud number ATH has is a false-positive number.
flaws.cloud carries no per-event labels, so `AWS-001`/`AWS-002` have **never been measured
against a known cloud attack**. These are per-technique captures with documented
techniques, in a different account with a different API mix. They measure **true positives
only** — there is no benign background, so no false-positive rate can be computed from
them, and none will be quoted.

**H4 — COMISET LAB (conditional).** Fields are `Process_name`, `CommandLine`,
`process_parent_name` — not ECS. It tests whether the Windows fixes depend on security
semantics or on Winlogbeat's field naming. Held back until H1–H3 report, so that if those
expose defects it can serve as an untouched cross-schema check *after* remediation.

**S1 — DEDALE D18, sealed.** Opened once, last, after every remediation in this milestone.
Its only job is to answer the overfitting question about M16 itself.

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

## 5. Conclusion

*Written last — pending H4 (COMISET) and the sealed D18 run.*
