# M14 Data Acquisition Plan: real-data validation

Date: 2026-09-10. State at planning time: M1-M13 committed (HEAD `e5dc495`), 652 tests
passing. No detection logic is changed by this plan.

## What M14 is actually for

The milestone is renamed from "data collection" to **"Real-data validation"**, because the
question it has to answer is not "which datasets exist" but:

1. Does ATH's architecture (deterministic rules -> correlation -> gated investigation ->
   calibrated report) hold up on telemetry nobody in this project wrote?
2. Does an LLM in the investigation loop make the analyst better off than `NullLLM`, or
   does it only add cost and overclaim risk?
3. Is the output something a SOC would accept as automation: findings per day an analyst
   can absorb, cases that are mostly real, conclusions that are right and cited?

Data acquisition is Phase A of that. Everything below is chosen to challenge ATH, not to
make it look good. Every measured number that comes out of Phase B replaces a number in
the README, including the ones that get worse.

Worker findings are in full in the appendix source (`dataset_candidates.md`, produced by
the research worker on 2026-09-10); this document records the manager's decisions.

---

## 1. Candidate dataset table (worker output, condensed)

| # | Dataset | Real / synthetic | Telemetry | Size / window | Benign? | Labels | License | ATH tables | Adapter work | Tests | Decision |
|---|---------|------------------|-----------|---------------|---------|--------|---------|------------|--------------|-------|----------|
| 1 | DEDALE (INRIA, 2025) | Emulated on real 40-VM testbed, AD domain | Winlogbeat ECS NDJSON (Sysmon, PowerShell; Security channel UNVERIFIED), Zeek, Suricata, auditbeat | 27.1 GB zip, 4 weeks (2 benign, 8-day APT) | Yes, 2 full weeks | Per-event (9,566 class-1), attack narrative with timestamps | CC BY 4.0 | process, network (if Sysmon 3), logon (if Security) | large (new ECS adapter) | W1 W2 W3 W4 W5 W8 | **USE NOW: Windows** |
| 2 | Splunk BOTS v3 (2018) | Emulated lab + real cloud accounts | Splunk buckets: wineventlog, Sysmon XML, aws:cloudtrail, o365, osquery | 320 MB compressed | Yes | Narrative + 61 graded Q&A | CC0 | process, network, logon, control | large (Splunk export + 3 parsers) | W5 W7 W8 | **USE, last: hybrid** |
| 3 | flaws.cloud CloudTrail | Real (public training account) | CloudTrail json.gz in tar | 252 MB, 1.94M events, 2017-2020 | Owner admin ops + thousands of attackers | Narrative only | UNVERIFIED | logon, control | small (tar + gzip) | W2 W6 W8 W1 | **USE NOW: AWS noise** |
| 4 | Kubernetes CI e2e audit logs | Real kube-apiserver | audit.k8s.io/v1 NDJSON | ~508 MB per run | Benign only | None | UNVERIFIED (public bucket) | control | small (NDJSON, metadata-level) | W2 W6 | **USE NOW: K8s benign** |
| 5 | K8NTEXT (FBK, 2025) | Emulated, human admin on kubeadm | audit NDJSON, all RequestResponse | 64 MB, 18,478 lines | Benign admin incl. exec/secrets/token | Context ids only | CC BY-NC-ND 4.0 | control | small | W2 W6 | **USE NOW: K8s benign, internal only** |
| 6 | DARPA OpTC | Emulated on 1,000 real hosts | eCAR JSON | ~1.1 TB, 9 days | Yes, massive | Red-team PDF | Public domain | process, network | medium-large | W1 W3 W4 W5 W8 | LATER (size) |
| 7 | LANL Unified 2017 | Real, de-identified | Security-log JSON, NetFlow | 90 days, email-gated | 100% | None | CC0 | logon, process (no cmdline) | medium | W1 W4 | LATER |
| 8 | LANL 2015 | Real, de-identified | CSV auth/proc/flows + redteam | 12 GB, 58 days | 100% | Per auth event | CC0 | logon | medium | W1 W4 W5 partial | LATER (E4 only) |
| 9 | COMISET | Real lab + emulated | Sysmon flat JSON/CSV | 4.9-31.7 GB zips | Yes | Per-event ATT&CK | CC BY 4.0 | process only | medium | W1 W2 W3 W8 | LATER |
| 10 | OTRF APT29 evals | Emulated | Flat Windows JSON | 367 MB day1 | Minimal | Emulation plan | MIT | process, network, logon | medium | W5 | LATER (second W5 case) |
| 11 | OTRF atomic Windows/AWS | Emulated | Flat JSON | KB-MB each | No | Per technique | MIT | all | small-medium | technique controls | LATER (positive controls) |
| 12 | Splunk attack_data | Emulated | Sysmon XML, CloudTrail JSON | ~9 GB LFS | No | Per technique | Apache-2.0 | all | medium | AWS-001/002 controls | LATER |
| 13 | Stratus Red Team | Generator | Real CloudTrail / k8s audit in own account | n/a | No | Per technique | Apache-2.0 | control | none | AWS/K8S coverage | USE as K8s attack injector |
| 14 | EVTX-ATTACK-SAMPLES | Emulated | EVTX | small | No | Per file | GPL-3.0 | needs EVTX parser | large | coverage | REJECT for now |
| 15 | Windows-APT 2025 (Guelph) | Emulated | Wazuh-processed Sysmon CSV | 102k rows, 3 hosts | 38k benign | Per event | CC BY 4.0 | process | medium | coverage | REJECT |
| 16 | AIT-LDS, Kyoushi | Synthetic | Linux only | 130 GB | Yes | Line-level | CC BY-NC-SA | none | n/a | none | REJECT |
| 17 | PWNJUTSU, CIC-IDS2018, DARPA TC E3/E5, Unraveled | various | see appendix | huge | mixed | weak/none | mixed/UNVERIFIED | weak | large | none | REJECT |
| 18 | flaws2.cloud logs | Real CTF | CloudTrail | 37 events | No | Narrative | UNVERIFIED | none of ATH's eventNames | none | smoke test | REJECT |
| 19 | K8s flow/metric sets (Kaggle, yigitsever) | Emulated | not audit logs | - | - | - | - | none | - | none | REJECT |

W1-W8 are the known ATH weaknesses: W1 short-window prevalence baselines, W2 rule FP rate on
real admin noise, W3 singleton MEDIUM gate, W4 ATH-006 ownership window, W5 investigation
correctness on a foreign incident, W6 coverage gaps (dropped events), W7 hybrid incidents,
W8 case precision under many benign findings.

---

## 2. Chosen datasets and why

**Windows: DEDALE.** The only public Windows source that combines two weeks of benign
domain activity, an 8-day labelled APT with a written timeline, per-event labels keyed by
`host.name` + `winlog.channel` + `winlog.record_id`, and a permissive license. It has a
macro-to-PowerShell-to-C2 chain that ATH-001/002/003/008/010 should reach, plus behaviour
ATH cannot see today (Sysmon 10 LSASS handle access, registry persistence) which measures
W6 honestly. Risk accepted: the Security channel is unverified. If it is absent, DEDALE's
logon table is empty, ATH-005/006/007 cannot be exercised on it, and step 0 below routes
that coverage to OTRF APT29 day 1 (Security events present, MIT).

**AWS: flaws.cloud, then BOTS v3 CloudTrail.** flaws.cloud is real, large (1.94M events,
1,242 distinct APIs) and hostile in exactly the way that pressures ATH: 99% of its
eventNames are ones the adapter refuses to map, so E0 produces the first honest "what
fraction of a real trail can ATH see" number, and the remaining 1% is enough attacker
noise to measure findings per day and singleton-case load. It has no label file, so it is
a noise and coverage source, not a recall source. The labelled AWS incident comes from
BOTS v3 (compromised access key, public S3 bucket) once its export exists. License for
flaws.cloud is unverified: it is used for internal evaluation only, never redistributed,
and nothing derived from it is committed.

**Kubernetes: CI e2e audit logs + K8NTEXT as benign baselines, attacks generated.** The
worker searched Zenodo, IEEE DataPort, Kaggle, arXiv, GitHub, Splunk, Falco, Datadog and
Sysdig and found no public Kubernetes audit dataset containing both realistic
administration and labelled attacks. Rather than pretend, the plan is: two real
kube-apiserver logs (CI bootstrap, which contains a real `cluster-admin`
ClusterRoleBinding create and `serviceaccounts/token` requests, so K8S-001 gets a
ready-made false positive to explain) plus K8NTEXT's human `kubectl exec`/secrets/token
traffic, with attacks generated in a `kind` cluster running Stratus Red Team techniques
and spliced in at offset timestamps. This is synthetic attack on real benign. It is stated
as such wherever the numbers appear. K8NTEXT is CC BY-NC-ND: internal evaluation only, no
committed fixtures or derived files.

**Hybrid: BOTS v3.** The only verified single incident spanning Windows endpoint and AWS
CloudTrail, with 61 published graded questions that become the W5 rubric for the
deterministic-vs-LLM comparison. It is last because it needs a throwaway Splunk Free
instance and `exporttool` before any adapter can read it. It is gated: if export is not
working within one working day, it drops to LATER and BOTS v1 raw JSON (CC0, 4 GB Security
log, no Splunk needed) substitutes for the Windows-Security-log noise test.

---

## 3. Rejected and deferred candidates

- **OpTC (LATER):** best long-baseline Windows source, 1.1 TB. Revisit for E4 once a
  2-5 GB per-host slice can be cut; the Drive layout is unverified.
- **LANL 2015/2017 (LATER, E4 only):** real, CC0, 58-90 days, but logon-only or no
  command lines, and email-gated. Exactly the W4 test, useless for everything else.
- **COMISET (LATER):** process-creation only; 155-914 GB uncompressed.
- **OTRF APT29 / atomic, attack_data (LATER, positive controls):** attack-only. Useful to
  prove a rule fires on a real Sysmon record of the technique (the `comsvcs MiniDump`
  4688 is a direct ATH-004 control), never as evidence of realistic behaviour.
- **EVTX-ATTACK-SAMPLES, Windows-APT 2025:** attack-only or single-format; a parser for
  ~200 EVTX files buys nothing DEDALE does not.
- **AIT-LDS, Kyoushi:** Linux only; ATH has no Linux endpoint schema.
- **PWNJUTSU, CIC-IDS2018, DARPA TC, Unraveled:** unlabelled hosts, undocumented formats
  or unverified licenses.
- **flaws2.cloud, flow-only K8s sets:** contain nothing ATH can map.

---

## 4. Expected schema and normalization gaps

Measured facts about ATH at M13 that these datasets will hit:

- **G1 No Windows-native parser.** DEDALE needs a Winlogbeat/ECS NDJSON adapter: Sysmon 1
  -> process (`process.command_line/executable/pid`, `process.parent.*`, `user.name`,
  `hash.sha256`); Sysmon 3 -> network (`Initiated` -> direction; no URL); Security
  4624/4625 -> logon (numeric LogonType maps 1:1 to `LOGON_TYPE_NAMES`, `IpAddress` ->
  `source_ip`, `WorkstationName` -> `source_device`, 4625 Status -> `failure_reason`).
  BOTS v3 needs Sysmon XML and WinEventLog text parsers on top of a Splunk CSV export.
- **G2 `signature_status` is `unknown` on every real source.** Sysmon 1 carries no
  signature verdict. `is_known_security_tool` requires `signed_valid`, so the
  known-tool benign signal is structurally dead on real data. Measured in E1, not patched.
- **G3 Logon vocabulary.** Security log is numeric; Defender is strings; Sysmon has no
  logons. Adapter-level only.
- **G4 CloudTrail.** `CloudTrailSource` reads `*.json` only, no gzip, no tar, no
  recursion; 5 management eventNames map. flaws.cloud will show >99% unmapped by event
  count. `AssumedRole` principal naming via `sessionIssuer` and `errorCode` handling on
  management events are untested on real data.
- **G5 Kubernetes.** Real audit logs are NDJSON; the adapter requires an `items` array.
  Metadata-level events have no `requestObject`, so RBAC `target_actor`/`role_ref` are
  empty and K8S-001 is blind to them; the adapter must report that per row, not crash.
  `serviceaccounts/token`, `secrets` get/list, and `pods/attach` are dropped today.
- **G6 Scale.** `correlate()` scores finding pairs (O(F^2)); ATH-005/006 are linear.
  Never measured beyond ~1,100 events. Working slices are capped (section 6) until a
  measured runtime exists.
- **G7 Long windows.** `WindowedPrevalence.recent` is the final quarter of the window;
  ATH-006 uses the environment median. Both were designed on a 4-hour window and will run
  on 28 days for the first time. Expect surprises; that is the point of E4.
- **G8 Label id space.** External labels are in native ids (DEDALE: host + channel +
  record_id; CloudTrail `eventID`; K8s `auditID`). ATH mints `event_id` at load. A
  resolver in `ath.evaluation` maps native id -> `event_id` through `source_ref`.
  Adapters never read a label file; nothing outside `ath.evaluation` imports one.

---

## 5. The M14 deliverable: one evaluation table

The main output of M14 is not a list of ingested datasets. It is a single table with one
row per (dataset, system configuration) and these columns, every one of them measured by
`ath.evaluation` and reproducible from the manifest:

| Column | Definition | Source |
|--------|------------|--------|
| Event precision | labelled-malicious events among all events any finding cites | labels |
| Event recall | labelled-malicious events cited by any finding / all labelled | labels |
| Case precision | cases containing at least one labelled event / all cases | labels |
| Chain recall / purity | labelled events in the primary case / all labelled; labelled in primary / all in primary | labels |
| Evidence correctness | claims whose cited event_ids exist and whose FACT statements are verified by `ClaimVerifier` / all claims; hallucinated citations reported separately as a count | verifier |
| Investigation completeness | `must_conclude` items hit / total, per incident | rubric |
| Unsupported claims | rejected claims + `never_as_fact` overclaims + calibration warnings | verifier, `audit_calibration` |
| Triage reduction | 1 - findings_after_triage / findings, and malicious findings called benign (must be 0) | triage |
| Analyst load | findings and cases per host-day on benign windows | hunt, correlate |
| Cost | tool calls, wall time, and for the LLM arm input/output tokens | orchestrator |

System configurations are rows, not footnotes: `deterministic` (`NullLLM`), `llm` (same
pipeline, real model, planner and synthesis on), and where relevant `llm-planner-only`. A
dataset that could not be ingested still gets a row, with its E0 numbers and the reason.

Datasets with no labels (flaws.cloud, the two Kubernetes benign sources on their own) fill
only the label-free columns; the label columns read "no labels", never a number.

### 5.1 LLM evaluation criteria, fixed before any run

An "LLM arm" is the identical ATH pipeline with a real model in place of `NullLLM`. Same
rules, same correlation, same specialists, same tools, same verifier, same cases. The model
plans and synthesises; it still cannot author a FACT or create a finding.

The LLM arm counts as beneficial only if, on the same cases, it measurably improves at
least one of:

- investigation completeness (`must_conclude` hits),
- correct evidence use (evidence-correctness ratio, or claims per conclusion that cite the
  right events),
- analyst-question coverage (BOTS v3 questions answered correctly with citations),
- triage value (a finding correctly explained that the deterministic arm left as
  `needs_review`),

**and** does not materially worsen unsupported claims (rejected claims, overclaims,
calibration warnings, hallucinated citations) or false-positive behaviour (malicious
findings called benign, benign findings escalated). "Materially" is fixed now: more than
one additional unsupported claim per case, or any malicious finding called benign.

Explicitly not evidence of improvement: longer reports, more claims, more fluent prose,
more hypotheses, more tool calls. Claim count is reported so that inflation is visible, not
credited.

The LLM arm runs three times per case; the table reports the median and the spread. The
model id, prompt versions and raw responses are stored as JSON under `reports/m14/` because
the runs are not reproducible. If the LLM arm is unavailable (no key) the row says so rather
than being omitted.

### 5.2 Experiments per dataset

| Exp | Question | DEDALE | flaws | K8s | BOTS v3 |
|-----|----------|--------|-------|-----|---------|
| E0 Ingestion fidelity: rows read / mapped / dropped by reason per native event type | how much of real telemetry can ATH see? | yes | yes | yes | yes |
| E1 Noise pressure: analyst load, triage split, case precision on benign windows | is the load survivable? | benign weeks | whole | benign logs | yes |
| E2 Detection: event precision/recall, chain recall/purity | does ATH find a foreign incident? | APT week | no labels | injected attacks | yes |
| E3 Deterministic vs LLM per 5.1 | does the agent help? | primary | - | secondary | primary (Q&A rubric) |
| E4 Baseline length 1d / 7d / 14d: triage flips, ATH-006 count | do long windows change verdicts? | yes | yes (years) | - | - |
| E5 Singleton gate: incidents whose only finding is one MEDIUM | detected but never investigated? | yes | - | yes | yes |
| E6 Crew assembly: platform set, standing/excluded capabilities | is the environment read correctly? | yes | yes | yes | yes |
| E7 Hybrid correlation: cases spanning >1 source, purity | do cross-source chains link or fragment? | - | - | - | yes |
| E8 Scaling: hunt / correlate / investigate wall time vs event and finding count | where does O(F^2) bite? | yes | yes | yes | - |

E3 needs one evaluation change before any real data runs: `run_incident` hardcodes
`NullLLM` and `use_llm_planner/synthesis=False`. It gains an `llm` and
`InvestigationConfig` parameter so both arms run on identical cases. No new agents.

Grading for E3 on DEDALE uses `must_conclude` / `never_as_fact` derived from the published
attack page (must name `172.19.1.1` as the download host, `scvhost.exe`, CLIENT2,
`Invoke-WebRequest`; must never state exfiltration as FACT since bytes leaving are only in
Zeek). For BOTS v3 the 61 published questions are the rubric directly.

### 5.3 Injected attacks are labelled as injected

Kubernetes attacks are generated, and every place they appear says so. The label file for
a spliced dataset carries, per event, whether it came from the real source (`real:k8s_ci`,
`real:k8ntext`) or was injected (`injected:stratus:<technique>`). The evaluation table has
a "telemetry provenance" column with values `real`, `real+injected`, `emulated-testbed`,
`synthetic`. A report produced from spliced telemetry states which events were injected in
its data-sources section, using the existing `source` column: injected rows are loaded with
`source="k8s_audit_injected"` so the distinction survives into every finding, case and
citation without any change to detection code.

---

## 6. Download and storage strategy

- `data/external/` is in `.gitignore` (added 2026-09-10). Nothing under it is committed.
- `data/external/MANIFEST.json` is committed: per dataset, URL, sha256, byte size, license,
  download date, subset kept, and the exact command used. A ~50-line
  `scripts/fetch_external.py` downloads by manifest entry and verifies the checksum.
- DEDALE's Winlogbeat archive is a *stored* zip of 673 hourly `.jsonl.bz2` files (309
  non-empty; probe 2026-09-10), so individual hours are range-fetched by offset from the
  committed zip index; the 27 GB archive is never downloaded whole. Hours are filtered into
  per-host NDJSON under `data/external/dedale/winlogbeat/<host>/<day>.jsonl`.
- Working slices start at **2 GB raw per dataset and ~200k canonical events per pipeline
  run. This is an engineering safety cap, not the benchmark definition.** E8 measures hunt,
  correlate and investigate wall time against event and finding counts on each dataset;
  the cap is raised deliberately, in the manifest, once the measured curve says the next
  step is affordable, and the table records which cap each row ran under.
- Normalized canonical CSVs go under `data/external/<name>/normalized/` and are
  regenerated, not stored.
- Labels: `data/external/<name>/labels/` holds raw label files. A compact derived label
  file (native ids only, a few hundred KB) is committed under
  `tests/fixtures/external_labels/` for CC BY / CC0 / MIT sources only. Nothing derived from
  flaws.cloud or K8NTEXT is committed.
- Test fixtures: at most one <100 KB hand-cut sample per adapter, from CC0/CC BY/MIT
  sources, with attribution in the fixture directory.
- No DVC or Git LFS now. Revisit if committed derived files exceed ~5 MB total.
- Disk budget: ~35 GB for DEDALE hourly files plus slices, <2 GB for everything else.

---

## 7. Ingest and validate order

0. **Probes first, before any further ingestion code.** (a) DEDALE: list channels and
   Sysmon event ids present in one attack-week hour and one benign hour; this decides
   whether logon rules can run on DEDALE at all. (b) flaws.cloud: `eventName` histogram
   over the whole tar; this decides whether AWS-001/002 can fire. (c) One full Kubernetes
   CI audit log: count `pods/exec`, `serviceaccounts/token`, RBAC creates and audit
   levels. Probe results are recorded in the manifest and **may change the dataset
   choice**: DEDALE without a Security channel routes logon coverage to OTRF APT29 day 1;
   flaws.cloud without any mapped management event becomes E0/E1-only and BOTS v3
   CloudTrail carries the AWS detection rows. Results: section 8.
1. **flaws.cloud** (adapter: tar + gzip, small). E0, E1, E4, E5, E6, E8. Also builds the
   external-label resolver and manifest tooling on small data before the large one.
2. **Kubernetes CI + K8NTEXT** (adapter: NDJSON + metadata-level tolerance, small). E0, E1,
   E6, E8. Then `kind` + Stratus generation and splice with injected provenance (5.3),
   then E2, E3 (secondary), E5.
3. **DEDALE** (adapter: Winlogbeat/ECS, large; started in parallel with 1-2). E0 on benign
   week 1, E8 to set the cap, E1 on both benign weeks, E4 across 1d/7d/14d, then E2/E3/E5
   on the APT week. This is the milestone's main result.
4. **BOTS v3** (gated on Splunk export). E7, and E3 with the Q&A rubric.
5. **M14 report.** The evaluation table of section 5, per dataset and configuration, with
   every regression and every failed ingestion left in. README's "How useful is this,
   actually?" section is replaced by the real-data table.

## What this plan does not do

It does not change any rule, threshold, or benign signal to fit a dataset. It adds no agent
and no major abstraction; if real data reveals a concrete architectural defect, that defect
is written up in the report with the evidence and becomes its own milestone, not a
mid-validation fix. It adds exactly two things to code before data flows: an LLM arm in
`run_incident`, and the external-label resolver inside `ath.evaluation`. Adapter work is
per-dataset and reported as normalization issues, not hidden.

---

## 8. Step 0 probe results (2026-09-10)

No code was changed. Raw numbers, checksums and fetch commands are in
`data/external/MANIFEST.json`; per-probe histograms sit beside each dataset.

### 8.1 DEDALE: channels verified, and one finding that changes the Windows picture

The archive is a deflate zip of 673 hourly `.jsonl.bz2` files (309 non-empty), and the
Dataverse endpoint honours HTTP Range requests, so any hour can be fetched by offset from
the committed zip index without downloading the 27 GB whole. Two hours were pulled:

| Hour | Events | Sysmon | Security | Sysmon 1 (process) | Sysmon 3 (network) | Sysmon 22 (DNS) | Sec 4624 | Sec 4625 | Sec 4688 |
|------|--------|--------|----------|--------------------|--------------------|-----------------|----------|----------|----------|
| 2025-01-06T10 (attack start) | 650,004 | 648,681 | 1,025 | 3,115 | **0** | 24,139 | 392 | **0** | **0** |
| 2024-12-25T15 (benign week 1) | 733,833 | 732,843 | 796 | 2,819 | **0** | 27,934 | 254 | **0** | **0** |

About 30 clients report; the raw JSON is ~1.8 GB per busy hour, so the 150-300 GB
uncompressed estimate holds and filter-at-fetch is mandatory.

- **Security channel is present**, so the logon table can be populated from 4624 and
  ATH-006 can run. Only successes appear in the sampled hours; whether 4625 failures occur
  during the APT (PrintNightmare lateral movement) decides ATH-005 and is checked when the
  attack week is fetched.
- **No Sysmon event 3 in either hour.** The Sysmon configuration does not log network
  connections. On DEDALE the network table will be empty, ATH-003 cannot fire, the network
  specialist is excluded by crew assembly, and the C2 beacon to `172.19.0.2` is invisible
  to ATH. This is the correct outcome for the visibility model to report and it is
  recorded as a W6 result, not patched: Sysmon 22 DNS queries are not connections and are
  not coerced into `network_flow`. Zeek `conn.log` (host-less, 3.5 GB) is the LATER route
  if process-less network evidence is judged worth a new source.
- Sysmon 10 (LSASS-style process access) runs at ~115k per hour and Sysmon 11/7/26 dominate
  the volume; none has a canonical table. The filtered slice keeps Sysmon 1, Security,
  PowerShell 4103/4104 and Sysmon 22 only, roughly 5k events per hour.

Decision: DEDALE stays the Windows source. Its scope is process + logon, with network
coverage measured as absent.

### 8.2 flaws.cloud: the existing adapter, unchanged, on 1.94M real CloudTrail events

| Measure | Value |
|---------|-------|
| Records read | 1,939,207 (20 files, 2017-02-12 to 2020-10-07, 1,242 distinct eventNames) |
| Kept by the current adapter | 21,904 (1.13%): 21,808 logon, 96 control |
| Dropped: eventName not mapped | 1,859,391 across 1,233 names (RunInstances alone 1,323,105) |
| Dropped: auth event with no usable principal | 57,912 (AWSService-invoked AssumeRole; `_principal()` does not read `invokedBy`) |
| Adapter wall time | 88 s |
| Management events present | AttachUserPolicy 32, PutUserPolicy 8, CreateAccessKey 53, StopLogging 2, DeleteTrail 1; 71 of 96 denied |
| Hunt | 39 findings in 2 s: ATH-005 x36 (35 HIGH, 1 CRITICAL), AWS-002 x3 (CRITICAL); AWS-001 0 |
| Correlate | 39 cases, all singletons, 0 links, all `confidence=low`, 2 s |
| Triage | 39 of 39 `likely_malicious`, every one by the `graded_high_by_detection` veto, score 0; triage reduction 0% |
| Crew | platforms=aws; identity, attack, control_plane standing; endpoint, network excluded |

Three observations go straight into the M14 report:

1. **ATH-005 fires HIGH on failure bursts with no success.** 35 of 36 findings say "no
   successful logon was observed", including an 11-role AssumeRole enumeration in 10 s.
   The rule's name promises "followed by successful authentication"; its severity does not
   depend on it. Whether that is the right behaviour is a design question the report has
   to answer with the false-positive count, not a threshold tweak now.
2. **Triage cannot touch anything here.** Every finding on this dataset is HIGH or above,
   and the benign layer defers to the detection's own grade at that severity. On real
   cloud telemetry the layer that exists to reduce analyst load has no purchase at all.
3. **AWS-001 never fires** despite 32 attach and 53 access-key events, because 71 of the 96
   are denied attempts by CTF players and the allowed ones do not form the attach-then-key
   chain for one identity. Either the chain does not exist in this account or the rule's
   window misses it; the report needs the per-identity timeline before saying which.

Two adapter gaps are recorded for step 1: tar/gzip input, and `invokedBy` as a principal
fallback so service-invoked AssumeRole is not dropped.

### 8.3 Kubernetes: both benign sources are dense in exactly the events K8S-001/002 watch

| Source | Lines | Window | Levels | RBAC binding creates (with body) | pods/exec | serviceaccounts/token | secrets ops | Users |
|--------|-------|--------|--------|----------------------------------|-----------|-----------------------|-------------|-------|
| CI e2e run (real apiserver) | 289,503 | 40 min | Request 170k, Metadata 52k, RequestResponse 45.6k | 1,989 (1,989) | 5,962 | 2,421 | 3,329 | 213 |
| K8NTEXT (human admin, kubeadm) | 18,478 | 2024-05-28 to 07-23 | all RequestResponse | 13 (13) | 18 | 120 | 90 | 40 |

Both are NDJSON, which the adapter cannot read today (it requires an `items` array). Every
RBAC binding create in both sources carries a `requestObject`, so K8S-001 will see the
grants once the NDJSON change lands; 1,989 legitimate binding creates in 40 minutes is the
false-positive pressure the plan wanted. K8NTEXT carries two extra top-level keys (`label`,
`cplabel`) that must be ignored by the adapter and never read by it as labels.

### 8.4 What the probes changed

- The dataset portfolio stands. No probe result routed a dataset to LATER.
- DEDALE's network coverage is now a known-absent channel, which makes the OTRF APT29
  day 1 set (has Sysmon 3) the LATER candidate for ATH-003 on Windows.
- The first real-data numbers already show a triage layer with zero purchase on cloud
  telemetry and a brute-force rule whose severity ignores its own success condition.
  Both go into the evaluation table as measured; neither is changed during M14.
