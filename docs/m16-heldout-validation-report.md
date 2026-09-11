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

*Recorded after each run against the frozen commit. Populated below as runs complete.*

## 5. Conclusion

*Written last.*
