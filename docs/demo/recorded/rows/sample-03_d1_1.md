# Incident: Failed logon burst followed by successful authentication (+1 related finding)

**Case:** CASE-001  
**Generated:** 2026-09-26 11:08:27 UTC  
**Status:** complete  
**Severity:** CRITICAL  |  **Grouping confidence:** medium  
**Hosts:** WS-3250, WS-7003  
**Accounts:** acct-8592  
**Window:** 2026-08-01 08:00:00 -> 08:06:00 UTC (360s)

> This report was produced by an automated investigation over telemetry from: **generated_auth_execution**. It presents evidence-backed findings for analyst review and does not authorise or perform any response action.

## Verdict

**Disposition:** Abstain  
**Engine:** d1  |  **Profile:** operational-v6  |  **Model:** qwen3.5:9b  
**Decided by:** the model's concluding round  
**Evidence basis:** 3 of 3 cited event id(s) name events the investigation retrieved; 17 typed observation(s) checked against recorded telemetry; 0 claim(s) rejected by verification; 1 probe(s) run; 8 tool call(s) served, 0 refused.  
**Evidence gap (model-written):** "script contents"  
**Supporting event ids:** `8e3b9127b110d0908581` (retrieved), `a6ae0903817573695f09` (retrieved), `c239520d9ca451aa0921` (retrieved)

*This system does not compute a confidence score for its verdict. The evidence basis is a count of what was checked, not a measure of how likely the verdict is.*

## Investigation Tree

```text
Initial alert: Failed logon burst followed by successful authentication (+1 related finding)
  rules ATH-005, ATH-007; 14 seed event(s): 1f776b2d12b6e1b38138, 4b7981dfd851184e370d, 7ae112de50a7ef35212b, 80fa003ab0d4b9fb50d3, 880b1242f36a26407c74, 8e3b9127b110d0908581 +8 more
  ↓
ATH investigation (engine d1)
  └── process_tree (device='WS-3250', pid=500, process_guid='sysmon:f7a5977e9afb5cc7e63853a79236e480')
        model's reason: "Need child processes of pid 500 to determine if 'job.cmd' performs malicious actions or standard maintenance."
        new events: 1 retrieved; shown: 21cfbf2f84aba973509b
  stopped: model chose no probe
  ↓
Verdict: Abstain
```

## Reasoning Summary

*Quoted text below is model output, reproduced verbatim. It is not verified fact: the checks applied to it cover the event ids it cites and any typed premises it declared, not what its sentences assert. Each cited id is marked by whether it names an event the investigation retrieved.*

1. **Model label: insufficient** -- verifier: accepted
   > Model wrote: "The script 'job.cmd' is executed but its children are not observed. Without seeing the command's output or arguments, intent cannot be determined."
   - Cited: `8e3b9127b110d0908581` (retrieved)
2. **Model label: insufficient** -- verifier: accepted
   > Model wrote: "The logon burst pattern is ambiguous; it could be a stale password retry or an attack. The script execution adds uncertainty without further evidence."
   - Cited: `a6ae0903817573695f09` (retrieved), `c239520d9ca451aa0921` (retrieved)

## Executive Summary

This report covers CASE-001, correlating 2 detection finding(s) across 2 host(s) (WS-3250, WS-7003) and 1 account(s) (acct-8592) between 08:00:00 and 08:06:00 UTC on 2026-08-01. The evidence is consistent with activity spanning 4 MITRE ATT&CK tactic(s): Execution -> Persistence -> Credential Access -> Lateral Movement. Each mapping is an interpretation of observed behaviour against a public taxonomy, not a determination that an intrusion occurred. 17 statement(s) below are directly established by telemetry, 10 are evidence-supported inferences, and 0 are explicitly unverified hypotheses requiring analyst confirmation. This report does not authorise or perform any response action. All recommendations below require human review before action is taken.

## Attack Timeline

| Time | Rule | Severity | User | Host / Movement | ATT&CK | Events |
| --- | --- | --- | --- | --- | --- | --- |
| 08:00:00 | ATH-005 | CRITICAL | acct-8592 | WS-3250 | T1078, T1110.001 | 7ae112de50a7ef35212b (+12) |
| 08:06:00 | ATH-007 | HIGH | acct-8592 | WS-3250 | T1021.002, T1569.002 | 8e3b9127b110d0908581 |

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

### Confirmed (FACT) (17)

*Typed observations checked against recorded telemetry.*

- Confirmed: Event 8e3b9127b110d0908581 records process identity sysmon:f7a5977e9afb5cc7e63853a79236e480.
  - Evidence: `8e3b9127b110d0908581`
- Confirmed: Authentication event a6ae0903817573695f09 records outcome success.
  - Evidence: `a6ae0903817573695f09`
- Confirmed: Event c239520d9ca451aa0921 precedes a6ae0903817573695f09 by recorded timestamp; this does not establish causation.
  - Evidence: `c239520d9ca451aa0921, a6ae0903817573695f09`
- Confirmed: Authentication event 1f776b2d12b6e1b38138 records outcome failure.
  - Evidence: `1f776b2d12b6e1b38138`
- Confirmed: Event 21cfbf2f84aba973509b records process identity sysmon:2a0296a72747c0b9019b2d5f243aed94.
  - Evidence: `21cfbf2f84aba973509b`
- Confirmed: Authentication event 4b7981dfd851184e370d records outcome failure.
  - Evidence: `4b7981dfd851184e370d`
- Confirmed: Authentication event 7ae112de50a7ef35212b records outcome failure.
  - Evidence: `7ae112de50a7ef35212b`
- Confirmed: Authentication event 80fa003ab0d4b9fb50d3 records outcome failure.
  - Evidence: `80fa003ab0d4b9fb50d3`
- Confirmed: Authentication event 880b1242f36a26407c74 records outcome failure.
  - Evidence: `880b1242f36a26407c74`
- Confirmed: Authentication event ab491e62927ff53ad2e9 records outcome failure.
  - Evidence: `ab491e62927ff53ad2e9`
- Confirmed: Authentication event c239520d9ca451aa0921 records outcome failure.
  - Evidence: `c239520d9ca451aa0921`
- Confirmed: Authentication event cbe095d06fbe19e71c8c records outcome failure.
  - Evidence: `cbe095d06fbe19e71c8c`
- Confirmed: Authentication event f07d391db002d3c8dc2c records outcome failure.
  - Evidence: `f07d391db002d3c8dc2c`
- Confirmed: Authentication event f23f1f0ad8cd6cc0a54a records outcome failure.
  - Evidence: `f23f1f0ad8cd6cc0a54a`
- Confirmed: Authentication event f2c578af54d2a3cf2d60 records outcome failure.
  - Evidence: `f2c578af54d2a3cf2d60`
- Confirmed: Authentication event ffe190ee68fa49888037 records outcome failure.
  - Evidence: `ffe190ee68fa49888037`
- Confirmed: Process event 8e3b9127b110d0908581 identifies the instance in 21cfbf2f84aba973509b as its parent.
  - Evidence: `21cfbf2f84aba973509b, 8e3b9127b110d0908581`

### Assessed (INFERENCE) (10)

*Interpretations and summaries; citation or predicate checks do not verify their free-text meaning.*

- Assessed: Unverified summary: ATH-005 (CRITICAL) on WS-3250 under account acct-8592: Failed logon burst followed by successful authentication. 12 failed logons for 'acct-8592' on WS-3250 from 10.10.2.8 within 220s. A successful logon followed at 08:05:00, 80s after the last failure. This may indicate the credential was successfully guessed and the account is now compromised.
  - Evidence: `7ae112de50a7ef35212b, cbe095d06fbe19e71c8c, f2c578af54d2a3cf2d60, 880b1242f36a26407c74, ab491e62927ff53ad2e9, ffe190ee68fa49888037, +7 more (see Evidence Appendix)`
- Assessed: Unverified summary: ATH-007 (HIGH) on WS-3250 under account acct-8592: Remote service execution (PsExec-style). The Service Control Manager started an interactive command interpreter. This pattern is consistent with remote command execution via a temporary service. Command output is redirected to the administrative share '\\127.0.0.1\ADMIN$', which is characteristic of remote execution frameworks collecting results over SMB.
  - Evidence: `8e3b9127b110d0908581`
- Assessed: Unverified summary: The case's cited telemetry comprises 14 of 14 event(s), from 2026-08-01T08:00:00+00:00 to 2026-08-01T08:06:00+00:00.
  - Evidence: `7ae112de50a7ef35212b, cbe095d06fbe19e71c8c, f2c578af54d2a3cf2d60, 880b1242f36a26407c74, ab491e62927ff53ad2e9, ffe190ee68fa49888037, +8 more (see Evidence Appendix)`
- Assessed: Unverified summary: T1021.002 (SMB/Windows Admin Shares) is catalogued under Lateral Movement and is mapped to this case by ATH-007.
  - Evidence: `8e3b9127b110d0908581`
- Assessed: Unverified summary: T1078 (Valid Accounts) is catalogued under Persistence, Privilege Escalation, Initial Access, Stealth and is mapped to this case by ATH-005.
  - Evidence: `1f776b2d12b6e1b38138, 4b7981dfd851184e370d, 7ae112de50a7ef35212b, 80fa003ab0d4b9fb50d3, 880b1242f36a26407c74, a6ae0903817573695f09, +7 more (see Evidence Appendix)`
- Assessed: Unverified summary: T1110.001 (Password Guessing) is catalogued under Credential Access and is mapped to this case by ATH-005.
  - Evidence: `1f776b2d12b6e1b38138, 4b7981dfd851184e370d, 7ae112de50a7ef35212b, 80fa003ab0d4b9fb50d3, 880b1242f36a26407c74, a6ae0903817573695f09, +7 more (see Evidence Appendix)`
- Assessed: Unverified summary: T1569.002 (Service Execution) is catalogued under Execution and is mapped to this case by ATH-007.
  - Evidence: `8e3b9127b110d0908581`
- Assessed: Unverified summary: On WS-3250, cmd.exe (PID 500) ran under account acct-8592 with execution chain wininit.exe -> services.exe -> cmd.exe, spawning no observed child process. Resolution: identity.
  - Evidence: `8e3b9127b110d0908581, 21cfbf2f84aba973509b`
- Assessed: [insufficient] The script 'job.cmd' is executed but its children are not observed. Without seeing the command's output or arguments, intent cannot be determined.
  - Evidence: `8e3b9127b110d0908581`
- Assessed: [insufficient] The logon burst pattern is ambiguous; it could be a stale password retry or an attack. The script execution adds uncertainty without further evidence.
  - Evidence: `a6ae0903817573695f09, c239520d9ca451aa0921`

### Unconfirmed Hypotheses (0)

*Possible explanations that have NOT been verified. Treat as open questions for the analyst, not as findings.*

_None._

## Evidence Checks

17 typed observations verified; 8 unstructured summaries retained as interpretations.

Predicate support does not establish malicious intent or verify the accompanying prose.
- process_identity [8e3b9127b110d0908581]: **supported** — recorded process identity: sysmon:f7a5977e9afb5cc7e63853a79236e480
- auth_outcome [a6ae0903817573695f09]: **supported** — recorded authentication outcome: success
- before [c239520d9ca451aa0921, a6ae0903817573695f09]: **supported** — recorded times: 2026-08-01T08:03:40+00:00 and 2026-08-01T08:05:00+00:00; no causal claim

## Recommended Next Steps

*These are investigative recommendations for a human analyst. No response action has been taken or is authorised by this report.*

1. **Retrieve email gateway or web-proxy logs to establish the initial access vector.**
   - Rationale: No detection in this case targets initial access, so the delivery mechanism (e.g. a phishing attachment) is inferred from process lineage rather than confirmed from delivery telemetry.
   - Based on: MITRE ATT&CK tactic coverage gap: Initial Access
2. **Independently verify account activity on all hosts in scope (WS-3250, WS-7003) rather than relying solely on the correlated case, in case related activity exists that current detections did not flag.**
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
- disposition: abstain
- evidence gap: script contents

## Investigation Trace

Agents run: investigator:seed, investigator:probe, investigator:conclude  
Tool calls made: 8

- step 1: investigator:seed -- findings, cited rows, techniques
- step 2: investigator:probe -- P1 process_tree: Need child processes of pid 500 to determine if 'job.cmd' performs malicious actions or standard maintenance.
- conclude: 2 explanation(s) proposed, 0 with out-of-scope citations dropped; disposition abstain
- conclude: accepted 2, rejected 0
- stop -- model chose no probe
- evidence verification: 17 checked observations; 8 summaries reclassified

## Evidence Appendix

All 15 telemetry events underlying this report, chronologically. Every claim above cites specific event ids from this list.

| Event ID | Time | Device | User | Summary |
| --- | --- | --- | --- | --- |
| `7ae112de50a7ef35212b` | 08:00:00 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `21cfbf2f84aba973509b` | 08:00:00 | WS-3250 | acct-8592 | wininit.exe -> services.exe \| services.exe |
| `cbe095d06fbe19e71c8c` | 08:00:20 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `f2c578af54d2a3cf2d60` | 08:00:40 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `880b1242f36a26407c74` | 08:01:00 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `ab491e62927ff53ad2e9` | 08:01:20 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `ffe190ee68fa49888037` | 08:01:40 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `f07d391db002d3c8dc2c` | 08:02:00 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `1f776b2d12b6e1b38138` | 08:02:20 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `80fa003ab0d4b9fb50d3` | 08:02:40 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `4b7981dfd851184e370d` | 08:03:00 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `f23f1f0ad8cd6cc0a54a` | 08:03:20 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `c239520d9ca451aa0921` | 08:03:40 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `a6ae0903817573695f09` | 08:05:00 | WS-3250 | acct-8592 | success logon [Network (SMB / share access)] from 10.10.2.8 |
| `8e3b9127b110d0908581` | 08:06:00 | WS-3250 | acct-8592 | services.exe -> cmd.exe \| cmd.exe /Q /c job.cmd 1> \\127.0.0.1\ADMIN$\job.log 2>&1 |
