# M17: does ATH understand real telemetry well enough to be useful outside its own environment?

**Verdict up front: ingestion and false-positive control are genuinely good; representation
and cross-channel reasoning are not; and the agent layer has produced essentially nothing
on real data.** The detection rules are defensible. Almost everything above them is
currently unproven outside the synthetic benchmark.

Frozen artifacts: [`reports/m17/H4_FROZEN.json`](../reports/m17/H4_FROZEN.json),
[`reports/m17/D18_FROZEN.json`](../reports/m17/D18_FROZEN.json). Both were written before
any ATH behaviour was changed in response to them.

---

## 1. What changed

| Change | Why |
| --- | --- |
| `_arguments()` reads the authoritative image field | Fix for M16-1, **after** H4 and D18 were frozen |
| 12 adversarial argv[0] tests; strict xfail → passing regression | The defect must not return quietly |
| 16 ATH-005/ATH-006 discrimination tests | Both rules had only false-positive evidence |
| `scripts/m17_comiset_eval.py`, `m17_freeze_h4.py`, `m17_freeze_d18.py` | Measurements regenerable, not quoted from a terminal |

Test suite: **860 passed / 1 xfailed → 889 passed / 0 xfailed.** Benchmark unchanged at
5/5 with 0 noise cases.

## 2. What I deliberately did not change

- **The H4 slice.** Declared as the first 20,000,000 records before anything was seen. On
  measuring it I found it is one host and 98.5% concentrated in three days — a serious
  weakness — and left it exactly as declared.
- **M17-1 through M17-5.** Five defects found during H4, all recorded and none fixed,
  because the artifact had to exist first.
- **The canonical schema.** No columns added for source IP, source port or `process_guid`
  despite measuring what their absence costs. That is the next milestone's decision, made
  on evidence, not a reflex during evaluation.
- **Rule thresholds.** Nothing was loosened or tightened to move a number.
- **D18.** Run once. Not converted into tuning data.

## 3. H4 — COMISET, frozen

**Corpus.** COMISET Lab (CC BY 4.0), 4.91 GB archive, single ZIP member, 159.7 GB
uncompressed, sequential streaming only. Schema is Elasticsearch/HELK
`logs-endpoint-winevent-*`. Slice: first 20,000,000 records, pre-declared.

### 3.1 Channel coverage — the number a global percentage hides

| Category | Source events | Mapped | Representability |
| --- | ---: | ---: | ---: |
| registry | 13,760,383 | 0 | **0.00%** |
| process access | 4,476,856 | 0 | **0.00%** |
| network connection | 589,477 | 589,477 | **100.00%** ¹ |
| file activity | 549,251 | 0 | 0.00% |
| other windows event | 337,192 | 0 | 0.00% |
| named pipe | 145,452 | 0 | 0.00% |
| audit policy | 41,062 | 0 | 0.00% |
| **process creation** | 16,551 | 15,095 | **91.20%** ² |
| image loaded | 14,003 | 0 | 0.00% |
| **logon/authentication** | 13,389 | 6,063 | **45.28%** ³ |
| dns | 7,677 | 0 | 0.00% |
| group enumeration | 5,552 | 0 | 0.00% |
| powershell/script | 3,615 | 0 | 0.00% |
| **TOTAL** | **20,000,000** | **610,635** | **3.05%** |

¹ **Event-level only.** Attribute-level is near zero — see M17-2.
² The 8.8% gap is Security 4688; Sysmon 1 maps, 4688 does not.
³ Only 4624/4625; 4634/4648/4672/4768/4769/4776 are unmapped.

The global 3.05% is misleading in both directions and would have hidden both the 91%
process coverage and the total registry blindness.

### 3.2 Time and host diversity — measured after declaring, reported not fixed

| | |
| --- | --- |
| Calendar days present | 10 |
| Days holding 98.5% of records | **3** (2022-11-16..18) |
| Hosts, process/logon tables | **1** |
| Hosts, network table | 2 |
| Verdict | **CONCENTRATED — not time-diverse** |

This is materially weaker than the M16 conclusion implied, and weaker than DEDALE D02's
30 hosts.

### 3.3 Detection — every zero attributed

| Rule | Eligible | Findings | Severity | Why zero |
| --- | ---: | ---: | --- | --- |
| ATH-002 | 15,095 | **3** | MEDIUM | — |
| ATH-010 | 15,095 | **1** | MEDIUM | — |
| ATH-012 | 15,095 | **1** | HIGH | — |
| **ATH-003** | 589,477 | 0 | — | **required fields lost in ingestion (M17-2)** |
| ATH-001, 004, 008, 009, 011 | 15,095 | 0 | — | eligible and silent |
| ATH-005, ATH-006 | 6,063 | 0 | — | eligible and silent |
| ATH-007 | 21,158 | 0 | — | eligible and silent |
| AWS-001/002, K8S-001/002 | 0 | 0 | — | not eligible — control table empty |

ATH-003's zero is the important one. It is **not** "clean data": the rule needs ports and
direction and received neither.

**Are the five findings coherent?** Yes. Decoded evidence:

| Rule | Evidence |
| --- | --- |
| ATH-002 ×3 | `powershell -nop -exec bypass -encodedcommand …` → `IEX (New-Obje…`, a download cradle |
| ATH-010 | `whoami /all`, `net users` |
| ATH-012 | `sc stop windefend` |

One host, four days, cradle → discovery → defence impairment. That reads as a coherent
intrusion. **They still cannot be scored**: the corpus's technique fields are
sysmon-modular `RuleName` annotations — a competing heuristic's output — not ground truth.
They are defensible on their face and unverifiable; recorded as *unclassified*.

### 3.4 Network — the first serious test

| Attribute | Canonical column | Preserved |
| --- | --- | --- |
| source host | `device` | ✅ 589,477 |
| initiating process name / id | `process_name` / `process_id` | ✅ 589,477 |
| destination IP | `remote_ip` | ✅ 589,477 |
| timestamp | `timestamp` | ✅ 589,477 |
| provenance | `source_ref` | ✅ 589,477 |
| **destination port** | `remote_port` | ❌ **1 of 589,477** |
| **protocol** | `protocol` | ❌ **1 of 589,477** |
| **source IP** | — | ❌ **no such column** |
| **source port** | — | ❌ **no such column** |

**IP classification: 172/177 agree (97.18%) with the corpus's own labels.** All five
disagreements are malformed IPv4-as-IPv6 (`c0a8:4b02::` = 192.168.75.2, `a0a:7580::` =
10.10.117.128, `e000:fc::` = multicast) where **the corpus label is wrong and ATH is
right**. ATH errs toward *not public* — the opposite direction from the old
internal-as-external bug. **No regression.**

### 3.5 Cross-channel joins — high success, low reliability

| | |
| --- | --- |
| Join keys available | `device`, `process_id`, `process_name`, `timestamp` |
| Join key **lost** in ingestion | **`process_guid`** (unique per process instance) |
| Network rows matching a known process | 589,359 / 589,477 — **99.98%** |
| **`(device, pid)` keys that are ambiguous** | **86.5%** |
| Worst key | **27 distinct process instances** |

The join looks excellent and is not trustworthy. `process_guid` is present on both Sysmon
1 and Sysmon 3 and is discarded, so "which process opened this connection" is ambiguous
for most keys.

### 3.6 Provenance — 6/6

Every sampled finding walks back finding → canonical event → `source_ref` → original
corpus record, with channel, event id and timestamp intact. An earlier 33% was my own
400,000-line scan limit, not a failure.

## 4. D18 — first run, frozen

9,220,694 source events → **48,893 ingested (0.53%)**. Process creation **100%**, logon
**47.2%**, everything else **0%**. 30 hosts, 36 users, one working day, **0 ingestion
issues**.

| | |
| --- | --- |
| Findings / cases / noise cases | **0 / 0 / 0** |
| TP / FP / FN | **0 / 0 / 2** |
| Recall | **0.0** |
| Labelled malicious refs | 9,567 |
| …resolvable in ingested telemetry | **2** |
| …never ingested | **9,565** |
| Provenance | n/a — no findings |

Both halves matter and point opposite ways. **Zero false positives on a mid-APT day
nothing was fitted to** is the strongest generalisation evidence available. **Zero recall,
with 9,565 of 9,567 labelled events never ingested**, is the same representation ceiling
H3 found in the cloud.

D18's network events *do* carry port and protocol, so **M17-2 is specific to the
Elastic/HELK adapter**, not to canonicalisation generally.

## 5. Defects discovered

| Id | Sev | Defect | Fixed? |
| --- | --- | --- | --- |
| M16-1 | high | `argv[0]` stripped by whitespace split; unquoted spaced path fires ATH-004 CRITICAL on a starting process | ✅ after freeze |
| M17-1 | medium | Adapter globs `*.json`/`*.jsonl` and parses every line of every file; ingested its own sidecar stats file. A sidecar with valid-JSON lines would be **silently ingested as telemetry** | ❌ recorded |
| M17-2 | **high** | Port/protocol/direction lost on 589,476/589,477 network events; mixed-schema corpus, adapter inferred field names from **one** sampled record | ❌ recorded |
| M17-3 | medium | `process_guid` discarded; joins fall back to ambiguous `(device, pid)` — 86.5% ambiguous | ❌ recorded |
| M17-4 | low | Corrupt source timestamp (1990-12-18) passes canonicalisation unflagged | ❌ recorded |
| M17-5 | medium | All 12 endpoint rules declare `channels=frozenset()`; eligibility not computable from the detector | ❌ recorded |

## 6. Evidence table

| Dimension | Measurement | Source |
| --- | --- | --- |
| Ingestion, new environment | 4 adapters; COMISET read with 0 real-event losses | H4 |
| Representability, global | 3.05% (COMISET), 0.53% (D18) | both |
| Representability, best channel | process creation 91.2% / 100% | both |
| Representability, worst | registry 0% of 13.76M events | H4 |
| Detection, real corpus | 5 findings, coherent, unscoreable | H4 |
| False positives, held out | **0** on D02 (30 hosts), **0** on D18 (30 hosts) | M16, D18 |
| Rule discrimination | 16 tests: TP, benign neighbour, boundary, missing field, repeat | M17 |
| Cross-channel join ambiguity | **86.5%** | H4 |
| Provenance | **6/6** | H4 |
| IP classification | 172/177, all 5 disagreements ATH-correct | H4 |
| **Agent output on real data** | **3 facts, 2 inferences, 4 tool calls — total, ever, all on one fixed FP** | all corpora |

## 7. Verdict by dimension

### A. Ingestion maturity — **STRONG**
Four adapters across Windows ECS, Windows HELK, CloudTrail and Kubernetes audit. COMISET —
a 159.7 GB single-member archive in a schema ATH had never seen — was read with zero real
events lost, and D18 ingested with **0 issues**. The generic adapter was written against
the schema family, not the corpus. *Caveat:* M17-1 shows directory handling is naive, and
M17-2 shows field-name inference from a single sample is unsafe.

### B. Representability — **WEAK**
3.05% and 0.53% globally. Per channel it is bimodal: process creation 91–100%, network
100% at event level, and **0% for registry, process access, file activity, DNS, PowerShell,
image load, named pipes** — categories that are 89% of COMISET and 97% of D18 by volume.
Two independent corpora put recall's ceiling at ingestion, not detection.

### C. Detection correctness — **PROMISING**
The five COMISET findings are individually defensible and jointly coherent: a download
cradle, discovery, and Defender being stopped, on one host in four days. Every zero is
attributed rather than assumed, and one of them (ATH-003) turned out to be an ingestion
defect wearing a detection zero. Not STRONG because nothing here is *confirmable* — no
corpus reached has usable ground truth.

### D. False-positive control — **STRONG**
0 findings on DEDALE D02 (30 hosts, 28 LSASS events, 2.4× the tuning day's logon volume),
0 on D18 (30 hosts, mid-APT, sealed), 0 on three Kubernetes corpora, and the M15
regressions all hold. 30 → 0 and 55 → 0 on the corpora that exposed them. This is the
dimension the project has most convincingly earned.

### E. Cross-channel reasoning — **WEAK**
99.98% join rate, **86.5% of keys ambiguous**, worst key covering 27 process instances,
because the unique identifier present in the source is discarded at ingestion. An
investigation that says "this process made this connection" is currently unable to
substantiate it two times in three. D18 could not test this at all — 2 network events in
a day.

### F. Evidence / provenance correctness — **STRONG**
6/6 reconstruction through the full chain, with channel, event id and original timestamp
recovered. Combined with zero fabricated citations across every corpus, an analyst can
check every claim ATH makes.

### G. Agent usefulness — **UNPROVEN**
Across **every real external corpus ever run**, the investigation layer has produced **3
facts, 2 inferences and 4 tool calls in total** — all on a single M14 false positive that
has since been fixed. Every post-M15 real-corpus run yields **0 facts, 0 tool calls**,
because investigation runs only on cases, cases form only from findings, and findings on
real telemetry are rare. All measured agent value comes from the synthetic benchmark.
Deterministic rules are doing essentially 100% of the value-producing work on real data.

### H. Product readiness — **WEAK**
Three things block a real SOC today, in order: (1) **representation** — ATH is blind to
registry, file, DNS, script-block and process-access telemetry, which is where most modern
detection lives; (2) **cross-channel identity** — without `process_guid` the core
investigative claim cannot be substantiated; (3) **the agent layer is unexercised** on
anything real. False-positive behaviour and provenance are genuinely ready.

## 8. Five highest-priority risks

1. **Representation ceiling is the binding constraint on everything.** 0% of registry,
   file, DNS, PowerShell and process-access telemetry. No rule work moves recall while
   this holds.
2. **Silent attribute loss.** M17-2 destroyed port/protocol on 589,476 events and the
   pipeline reported 100% event-level coverage throughout. Coverage metrics measured rows,
   not fields, so the system could not see its own blindness.
3. **Ambiguous process identity.** 86.5% join ambiguity undermines every cross-channel
   claim an investigation would make.
4. **No ground truth on any real corpus.** Precision and recall remain unmeasurable
   outside synthetic data; every real number is a false-positive number.
5. **The agent layer has never been exercised on real telemetry.** Its value is entirely
   unevidenced outside the benchmark it was built against.

## 9. Recommended next milestone

**M18: Field-level representation — measure and close the ingestion ceiling.**

Not more rules, not more agents, not more datasets. Both frozen artifacts say the same
thing from two independent environments: ATH's limit is what it can represent.

Three pieces, smallest first:

1. **Field-level coverage metrics.** Today's coverage counts rows. M17-2 proves rows are
   the wrong unit — 100% of network events were "covered" while ~0% of their attributes
   survived. Per-field population must be measured and asserted, so silent attribute loss
   becomes a test failure rather than a discovery two milestones later.
2. **Carry process identity and connection endpoints.** Add `process_guid`, source IP and
   source port to the canonical schema, driven by the 86.5% ambiguity number rather than
   by tidiness. Fix M17-1 through M17-5 in the same pass.
3. **Then, and only then, one new channel.** Registry or script-block — chosen on the
   volume evidence above — modelled as a behaviour family rather than by adding event ids
   one at a time, which is the same mistake the cloud recommendation warned against.

The question M18 should answer: **does representability rise above single digits, and does
anything detect the DEDALE attack that 9,565 unrepresentable events currently hide?**
