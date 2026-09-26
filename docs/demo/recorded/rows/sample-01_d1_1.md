# Incident: Failed logon burst followed by successful authentication (+1 related finding)

**Case:** CASE-001  
**Generated:** 2026-09-26 11:07:32 UTC  
**Status:** complete  
**Severity:** CRITICAL  |  **Grouping confidence:** medium  
**Hosts:** WS-2924, WS-6254  
**Accounts:** acct-7085  
**Window:** 2026-08-01 08:00:00 -> 08:06:00 UTC (360s)

> This report was produced by an automated investigation over telemetry from: **generated_auth_execution**. It presents evidence-backed findings for analyst review and does not authorise or perform any response action.

## Verdict

**Disposition:** Malicious  
**Engine:** d1  |  **Profile:** operational-v6  |  **Model:** qwen3.5:9b  
**Decided by:** the model's concluding round  
**Evidence basis:** 3 of 3 cited event id(s) name events the investigation retrieved; 18 typed observation(s) checked against recorded telemetry; 0 claim(s) rejected by verification; 1 probe(s) run; 8 tool call(s) served, 0 refused.  
**Evidence gap (model-written):** "none"  
**Supporting event ids:** `ccec78fe2c3fa29b518b` (retrieved), `703eeb16d25835efecb7` (retrieved), `0f504253fd98db142c3c` (retrieved)

*This system does not compute a confidence score for its verdict. The evidence basis is a count of what was checked, not a measure of how likely the verdict is.*

## Investigation Tree

```text
Initial alert: Failed logon burst followed by successful authentication (+1 related finding)
  rules ATH-005, ATH-007; 14 seed event(s): 00bb709b987db814f5f7, 044f5c9c5bf34ddb9030, 0f504253fd98db142c3c, 2dbb1b538a03d94bbf88, 3266b536dc39708fc00c, 3608f02fef656b43e91e +8 more
  ↓
ATH investigation (engine d1)
  └── process_tree (device='WS-2924', pid=500, process_guid='sysmon:5b6186501e6faefbb89acd575f1415ab')
        model's reason: "Probe P1 will retrieve the child processes of cmd.exe (pid 500) to observe the actual commands run by job.cmd, which is necessary to determine intent."
        new events: 2 retrieved; shown: 77646b919268d3358b14, ccec78fe2c3fa29b518b
  stopped: model chose no probe
  ↓
Verdict: Malicious
```

## Reasoning Summary

*Quoted text below is model output, reproduced verbatim. It is not verified fact: the checks applied to it cover the event ids it cites and any typed premises it declared, not what its sentences assert. Each cited id is marked by whether it names an event the investigation retrieved.*

1. **Model label: malicious** -- verifier: accepted
   > Model wrote: "The process tree reveals reg.exe saving the SAM hive to a file. This action dumps user credentials, confirming malicious intent."
   - Cited: `ccec78fe2c3fa29b518b` (retrieved), `703eeb16d25835efecb7` (retrieved)
2. **Model label: insufficient** -- verifier: accepted
   > Model wrote: "The logon burst could be benign (stale password) or malicious. The subsequent credential dump confirms the attack."
   - Cited: `0f504253fd98db142c3c` (retrieved), `ccec78fe2c3fa29b518b` (retrieved)
3. **Model label: insufficient** -- verifier: accepted
   > Model wrote: "A remote service started a command interpreter. Without observing the child processes of cmd.exe, we cannot confirm if it is performing maintenance or exfiltrating data."
   - Cited: `703eeb16d25835efecb7` (retrieved)

## Executive Summary

This report covers CASE-001, correlating 2 detection finding(s) across 2 host(s) (WS-2924, WS-6254) and 1 account(s) (acct-7085) between 08:00:00 and 08:06:00 UTC on 2026-08-01. The evidence is consistent with activity spanning 4 MITRE ATT&CK tactic(s): Execution -> Persistence -> Credential Access -> Lateral Movement. Each mapping is an interpretation of observed behaviour against a public taxonomy, not a determination that an intrusion occurred. 18 statement(s) below are directly established by telemetry, 11 are evidence-supported inferences, and 0 are explicitly unverified hypotheses requiring analyst confirmation. This report does not authorise or perform any response action. All recommendations below require human review before action is taken.

## Attack Timeline

| Time | Rule | Severity | User | Host / Movement | ATT&CK | Events |
| --- | --- | --- | --- | --- | --- | --- |
| 08:00:00 | ATH-005 | CRITICAL | acct-7085 | WS-2924 | T1078, T1110.001 | 72d5a08e0d2a8522ca5a (+12) |
| 08:06:00 | ATH-007 | HIGH | acct-7085 | WS-2924 | T1021.002, T1569.002 | 703eeb16d25835efecb7 |

## MITRE ATT&CK Summary

Tactics observed, in kill-chain order: **Execution -> Persistence -> Credential Access -> Lateral Movement**.

Each row below is a candidate interpretation of observed behaviour, not a verdict -- see the confidence column and the reasoning beside it.

| Technique | Tactic | Confidence | Rule | Reasoning |
| --- | --- | --- | --- | --- |
| T1110.001 Brute Force: Password Guessing | Credential Access | high | ATH-005 | Repeated failed authentications for a single account from a single source are consistent with systematically guessing that account's password. (A spray against many accounts would be T1110.003 and is not what was observed.) |
| T1569.002 System Services: Service Execution | Execution | high | ATH-007 | A command interpreter was started by the Service Control Manager, which is the defining behaviour of executing a payload as a Windows service. |
| T1021.002 Remote Services: SMB/Windows Admin Shares | Lateral Movement | medium | ATH-007 | Command output was redirected to an administrative share, indicating the service was driven over an authenticated SMB session from another host. |
| T1078 Valid Accounts | Persistence | medium | ATH-005 | A successful authentication followed the failure burst, which is consistent with the account credential now being under adversary control. |

## Findings

### Confirmed (FACT) (18)

*Typed observations checked against recorded telemetry.*

- Confirmed: Event ccec78fe2c3fa29b518b records process identity sysmon:3b438f257d488c7aa682ff0330ba9507.
  - Evidence: `ccec78fe2c3fa29b518b`
- Confirmed: Process event ccec78fe2c3fa29b518b identifies the instance in 703eeb16d25835efecb7 as its parent.
  - Evidence: `703eeb16d25835efecb7, ccec78fe2c3fa29b518b`
- Confirmed: Authentication event 0f504253fd98db142c3c records outcome success.
  - Evidence: `0f504253fd98db142c3c`
- Confirmed: Event 703eeb16d25835efecb7 records process identity sysmon:5b6186501e6faefbb89acd575f1415ab.
  - Evidence: `703eeb16d25835efecb7`
- Confirmed: Authentication event 00bb709b987db814f5f7 records outcome failure.
  - Evidence: `00bb709b987db814f5f7`
- Confirmed: Authentication event 044f5c9c5bf34ddb9030 records outcome failure.
  - Evidence: `044f5c9c5bf34ddb9030`
- Confirmed: Authentication event 2dbb1b538a03d94bbf88 records outcome failure.
  - Evidence: `2dbb1b538a03d94bbf88`
- Confirmed: Authentication event 3266b536dc39708fc00c records outcome failure.
  - Evidence: `3266b536dc39708fc00c`
- Confirmed: Authentication event 3608f02fef656b43e91e records outcome failure.
  - Evidence: `3608f02fef656b43e91e`
- Confirmed: Authentication event 680a11b09c06415c434a records outcome failure.
  - Evidence: `680a11b09c06415c434a`
- Confirmed: Authentication event 6cab6426bbe2ef08ea74 records outcome failure.
  - Evidence: `6cab6426bbe2ef08ea74`
- Confirmed: Authentication event 72d5a08e0d2a8522ca5a records outcome failure.
  - Evidence: `72d5a08e0d2a8522ca5a`
- Confirmed: Event 77646b919268d3358b14 records process identity sysmon:a985464622e9b1d8aead361db1929408.
  - Evidence: `77646b919268d3358b14`
- Confirmed: Authentication event 7b13f31085bbf14dad61 records outcome failure.
  - Evidence: `7b13f31085bbf14dad61`
- Confirmed: Authentication event 96d505a664df60a94a7c records outcome failure.
  - Evidence: `96d505a664df60a94a7c`
- Confirmed: Authentication event edf4a27fb63329509cc1 records outcome failure.
  - Evidence: `edf4a27fb63329509cc1`
- Confirmed: Authentication event f0ebb167f3e1fca60b93 records outcome failure.
  - Evidence: `f0ebb167f3e1fca60b93`
- Confirmed: Process event 703eeb16d25835efecb7 identifies the instance in 77646b919268d3358b14 as its parent.
  - Evidence: `77646b919268d3358b14, 703eeb16d25835efecb7`

### Assessed (INFERENCE) (11)

*Interpretations and summaries; citation or predicate checks do not verify their free-text meaning.*

- Assessed: Unverified summary: ATH-005 (CRITICAL) on WS-2924 under account acct-7085: Failed logon burst followed by successful authentication. 12 failed logons for 'acct-7085' on WS-2924 from 10.10.2.8 within 220s. A successful logon followed at 08:05:00, 80s after the last failure. This may indicate the credential was successfully guessed and the account is now compromised.
  - Evidence: `72d5a08e0d2a8522ca5a, 2dbb1b538a03d94bbf88, 7b13f31085bbf14dad61, 6cab6426bbe2ef08ea74, 00bb709b987db814f5f7, 3266b536dc39708fc00c, +7 more (see Evidence Appendix)`
- Assessed: Unverified summary: ATH-007 (HIGH) on WS-2924 under account acct-7085: Remote service execution (PsExec-style). The Service Control Manager started an interactive command interpreter. This pattern is consistent with remote command execution via a temporary service. Command output is redirected to the administrative share '\\127.0.0.1\ADMIN$', which is characteristic of remote execution frameworks collecting results over SMB.
  - Evidence: `703eeb16d25835efecb7`
- Assessed: Unverified summary: The case's cited telemetry comprises 14 of 14 event(s), from 2026-08-01T08:00:00+00:00 to 2026-08-01T08:06:00+00:00.
  - Evidence: `72d5a08e0d2a8522ca5a, 2dbb1b538a03d94bbf88, 7b13f31085bbf14dad61, 6cab6426bbe2ef08ea74, 00bb709b987db814f5f7, 3266b536dc39708fc00c, +8 more (see Evidence Appendix)`
- Assessed: Unverified summary: T1021.002 (SMB/Windows Admin Shares) is catalogued under Lateral Movement and is mapped to this case by ATH-007.
  - Evidence: `703eeb16d25835efecb7`
- Assessed: Unverified summary: T1078 (Valid Accounts) is catalogued under Persistence, Privilege Escalation, Initial Access, Stealth and is mapped to this case by ATH-005.
  - Evidence: `00bb709b987db814f5f7, 044f5c9c5bf34ddb9030, 0f504253fd98db142c3c, 2dbb1b538a03d94bbf88, 3266b536dc39708fc00c, 3608f02fef656b43e91e, +7 more (see Evidence Appendix)`
- Assessed: Unverified summary: T1110.001 (Password Guessing) is catalogued under Credential Access and is mapped to this case by ATH-005.
  - Evidence: `00bb709b987db814f5f7, 044f5c9c5bf34ddb9030, 0f504253fd98db142c3c, 2dbb1b538a03d94bbf88, 3266b536dc39708fc00c, 3608f02fef656b43e91e, +7 more (see Evidence Appendix)`
- Assessed: Unverified summary: T1569.002 (Service Execution) is catalogued under Execution and is mapped to this case by ATH-007.
  - Evidence: `703eeb16d25835efecb7`
- Assessed: Unverified summary: On WS-2924, cmd.exe (PID 500) ran under account acct-7085 with execution chain wininit.exe -> services.exe -> cmd.exe, spawning 1 child process(es): reg.exe. Resolution: identity.
  - Evidence: `703eeb16d25835efecb7, 77646b919268d3358b14, ccec78fe2c3fa29b518b`
- Assessed: [malicious] The process tree reveals reg.exe saving the SAM hive to a file. This action dumps user credentials, confirming malicious intent.
  - Evidence: `ccec78fe2c3fa29b518b, 703eeb16d25835efecb7`
- Assessed: [insufficient] The logon burst could be benign (stale password) or malicious. The subsequent credential dump confirms the attack.
  - Evidence: `0f504253fd98db142c3c, ccec78fe2c3fa29b518b`
- Assessed: [insufficient] A remote service started a command interpreter. Without observing the child processes of cmd.exe, we cannot confirm if it is performing maintenance or exfiltrating data.
  - Evidence: `703eeb16d25835efecb7`

### Unconfirmed Hypotheses (0)

*Possible explanations that have NOT been verified. Treat as open questions for the analyst, not as findings.*

_None._

## Evidence Checks

18 typed observations verified; 8 unstructured summaries retained as interpretations.

Predicate support does not establish malicious intent or verify the accompanying prose.
- process_identity [ccec78fe2c3fa29b518b]: **supported** — recorded process identity: sysmon:3b438f257d488c7aa682ff0330ba9507
- parent_child [703eeb16d25835efecb7, ccec78fe2c3fa29b518b]: **supported** — matching source-qualified identity on the same host
- auth_outcome [0f504253fd98db142c3c]: **supported** — recorded authentication outcome: success
- process_identity [ccec78fe2c3fa29b518b]: **supported** — recorded process identity: sysmon:3b438f257d488c7aa682ff0330ba9507
- process_identity [703eeb16d25835efecb7]: **supported** — recorded process identity: sysmon:5b6186501e6faefbb89acd575f1415ab

## Recommended Next Steps

*These are investigative recommendations for a human analyst. No response action has been taken or is authorised by this report.*

1. **Retrieve email gateway or web-proxy logs to establish the initial access vector.**
   - Rationale: No detection in this case targets initial access, so the delivery mechanism (e.g. a phishing attachment) is inferred from process lineage rather than confirmed from delivery telemetry.
   - Based on: MITRE ATT&CK tactic coverage gap: Initial Access
2. **Independently verify account activity on all hosts in scope (WS-2924, WS-6254) rather than relying solely on the correlated case, in case related activity exists that current detections did not flag.**
   - Rationale: This case spans multiple hosts, which increases the possible blast radius.
   - Based on: case.is_multi_host
3. **Escalate to a human analyst for validation before any remediation action is taken.**
   - Rationale: This system performs read-only investigation only. It has no capability to disable accounts, isolate hosts, or otherwise remediate, and this report is not authorisation to do so.
   - Based on: system design constraint

## Limitations & Scope

- Telemetry underlying this report came from: generated_auth_execution. Field coverage depends entirely on what the originating export or sensor captured; this project's canonical schema does not model every field a real EDR product exposes (e.g. file hashes, signer information, session identifiers), and any of those were dropped during normalization.
- ATT&CK mappings are interpretations of observed behaviour against a public taxonomy. They indicate that behaviour is consistent with a technique, not that an adversary performed it.
- Grouping confidence describes how strongly correlated findings are linked to each other, not whether an intrusion occurred.
- No evidence was found for the following ATT&CK tactics: Initial Access, Discovery, Collection, Exfiltration. Their absence may reflect that the activity did not occur, or that available telemetry cannot observe it.
- Typed predicates are checked against recorded telemetry; free-text interpretations are not semantically verified. Missing identity is not a confirmed process link, and recorded event order does not establish causation.
- disposition: malicious
- evidence gap: none

## Investigation Trace

Agents run: investigator:seed, investigator:probe, investigator:conclude  
Tool calls made: 8

- step 1: investigator:seed -- findings, cited rows, techniques
- step 2: investigator:probe -- P1 process_tree: Probe P1 will retrieve the child processes of cmd.exe (pid 500) to observe the actual commands run by job.cmd, which is necessary to determine intent.
- conclude: 3 explanation(s) proposed, 0 with out-of-scope citations dropped; disposition malicious
- conclude: accepted 3, rejected 0
- stop -- model chose no probe
- evidence verification: 18 checked observations; 8 summaries reclassified

## Evidence Appendix

All 16 telemetry events underlying this report, chronologically. Every claim above cites specific event ids from this list.

| Event ID | Time | Device | User | Summary |
| --- | --- | --- | --- | --- |
| `72d5a08e0d2a8522ca5a` | 08:00:00 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `77646b919268d3358b14` | 08:00:00 | WS-2924 | acct-7085 | wininit.exe -> services.exe \| services.exe |
| `2dbb1b538a03d94bbf88` | 08:00:20 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `7b13f31085bbf14dad61` | 08:00:40 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `6cab6426bbe2ef08ea74` | 08:01:00 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `00bb709b987db814f5f7` | 08:01:20 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `3266b536dc39708fc00c` | 08:01:40 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `edf4a27fb63329509cc1` | 08:02:00 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `680a11b09c06415c434a` | 08:02:20 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `044f5c9c5bf34ddb9030` | 08:02:40 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `f0ebb167f3e1fca60b93` | 08:03:00 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `96d505a664df60a94a7c` | 08:03:20 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `3608f02fef656b43e91e` | 08:03:40 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `0f504253fd98db142c3c` | 08:05:00 | WS-2924 | acct-7085 | success logon [Network (SMB / share access)] from 10.10.2.8 |
| `703eeb16d25835efecb7` | 08:06:00 | WS-2924 | acct-7085 | services.exe -> cmd.exe \| cmd.exe /Q /c job.cmd 1> \\127.0.0.1\ADMIN$\job.log 2>&1 |
| `ccec78fe2c3fa29b518b` | 08:06:05 | WS-2924 | acct-7085 | cmd.exe -> reg.exe \| reg.exe save HKLM\SAM C:\ProgramData\sam.hiv /y |
