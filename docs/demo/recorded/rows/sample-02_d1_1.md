# Incident: Failed logon burst followed by successful authentication (+1 related finding)

**Case:** CASE-001  
**Generated:** 2026-09-26 11:08:02 UTC  
**Status:** complete  
**Severity:** CRITICAL  |  **Grouping confidence:** medium  
**Hosts:** WS-2138, WS-9673  
**Accounts:** acct-2520  
**Window:** 2026-08-01 08:00:00 -> 08:06:00 UTC (360s)

> This report was produced by an automated investigation over telemetry from: **generated_auth_execution**. It presents evidence-backed findings for analyst review and does not authorise or perform any response action.

## Verdict

**Disposition:** Benign  
**Engine:** d1  |  **Profile:** operational-v6  |  **Model:** qwen3.5:9b  
**Decided by:** the model's concluding round  
**Evidence basis:** 4 of 4 cited event id(s) name events the investigation retrieved; 20 typed observation(s) checked against recorded telemetry; 0 claim(s) rejected by verification; 1 probe(s) run; 8 tool call(s) served, 0 refused.  
**Evidence gap (model-written):** "intent"  
**Supporting event ids:** `bc5bc87bcd4bf9827807` (retrieved), `67a9f5bfab28871757dd` (retrieved), `c1aa4d45ddf2102946f7` (retrieved), `0b092d00f3798939dd00` (retrieved)

*This system does not compute a confidence score for its verdict. The evidence basis is a count of what was checked, not a measure of how likely the verdict is.*

## Investigation Tree

```text
Initial alert: Failed logon burst followed by successful authentication (+1 related finding)
  rules ATH-005, ATH-007; 14 seed event(s): 0adbb9ef85b9188c8683, 0cb61159ea3d69dcc87a, 0cc680d6694f1f8615a1, 2108af7a380995a548b5, 3bdd60cc3a5a97b84519, 67a9f5bfab28871757dd +8 more
  ↓
ATH investigation (engine d1)
  └── process_tree (device='WS-9673', pid=500, process_guid='sysmon:ffa91f20286f6ae3e86e4b01e0c39444')
        model's reason: "Retrieving the child process tree for pid 500 is required to observe the actual commands run by 'job.cmd' and distinguish between data exfiltration and benign maintenance."
        new events: 2 retrieved; shown: 98c80712635dec2f3738, 0b092d00f3798939dd00
  stopped: model chose no probe
  ↓
Verdict: Benign
```

## Reasoning Summary

*Quoted text below is model output, reproduced verbatim. It is not verified fact: the checks applied to it cover the event ids it cites and any typed premises it declared, not what its sentences assert. Each cited id is marked by whether it names an event the investigation retrieved.*

1. **Model label: benign** -- verifier: accepted
   > Model wrote: "The failed logons were a stale password retry. The executed command 'dism.exe /Online /Cleanup-Image /ScanHealth' is standard maintenance, not exfiltration."
   - Cited: `bc5bc87bcd4bf9827807` (retrieved), `67a9f5bfab28871757dd` (retrieved), `c1aa4d45ddf2102946f7` (retrieved), `0b092d00f3798939dd00` (retrieved)
2. **Model label: benign** -- verifier: accepted
   > Model wrote: "The process tree shows 'dism.exe' running a health scan. This is a legitimate system maintenance task, contradicting the malicious exfiltration hypothesis."
   - Cited: `0b092d00f3798939dd00` (retrieved), `c1aa4d45ddf2102946f7` (retrieved)
3. **Model label: insufficient** -- verifier: accepted
   > Model wrote: "The script 'job.cmd' contents are not observed. We cannot confirm if it exfiltrated data or performed maintenance."
   - Cited: `c1aa4d45ddf2102946f7` (retrieved)

## Executive Summary

This report covers CASE-001, correlating 2 detection finding(s) across 2 host(s) (WS-2138, WS-9673) and 1 account(s) (acct-2520) between 08:00:00 and 08:06:00 UTC on 2026-08-01. The evidence is consistent with activity spanning 4 MITRE ATT&CK tactic(s): Execution -> Persistence -> Credential Access -> Lateral Movement. Each mapping is an interpretation of observed behaviour against a public taxonomy, not a determination that an intrusion occurred. 20 statement(s) below are directly established by telemetry, 11 are evidence-supported inferences, and 0 are explicitly unverified hypotheses requiring analyst confirmation. This report does not authorise or perform any response action. All recommendations below require human review before action is taken.

## Attack Timeline

| Time | Rule | Severity | User | Host / Movement | ATT&CK | Events |
| --- | --- | --- | --- | --- | --- | --- |
| 08:00:00 | ATH-005 | CRITICAL | acct-2520 | WS-9673 | T1078, T1110.001 | 0cb61159ea3d69dcc87a (+12) |
| 08:06:00 | ATH-007 | HIGH | acct-2520 | WS-9673 | T1021.002, T1569.002 | c1aa4d45ddf2102946f7 |

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

### Confirmed (FACT) (20)

*Typed observations checked against recorded telemetry.*

- Confirmed: Event bc5bc87bcd4bf9827807 precedes 67a9f5bfab28871757dd by recorded timestamp; this does not establish causation.
  - Evidence: `bc5bc87bcd4bf9827807, 67a9f5bfab28871757dd`
- Confirmed: Event c1aa4d45ddf2102946f7 precedes 0b092d00f3798939dd00 by recorded timestamp; this does not establish causation.
  - Evidence: `c1aa4d45ddf2102946f7, 0b092d00f3798939dd00`
- Confirmed: Event 0b092d00f3798939dd00 records process identity sysmon:399d50933db741bad79daec0f397fe8d.
  - Evidence: `0b092d00f3798939dd00`
- Confirmed: Event c1aa4d45ddf2102946f7 records process identity sysmon:ffa91f20286f6ae3e86e4b01e0c39444.
  - Evidence: `c1aa4d45ddf2102946f7`
- Confirmed: Authentication event 0adbb9ef85b9188c8683 records outcome failure.
  - Evidence: `0adbb9ef85b9188c8683`
- Confirmed: Authentication event 0cb61159ea3d69dcc87a records outcome failure.
  - Evidence: `0cb61159ea3d69dcc87a`
- Confirmed: Authentication event 0cc680d6694f1f8615a1 records outcome failure.
  - Evidence: `0cc680d6694f1f8615a1`
- Confirmed: Authentication event 2108af7a380995a548b5 records outcome failure.
  - Evidence: `2108af7a380995a548b5`
- Confirmed: Authentication event 3bdd60cc3a5a97b84519 records outcome failure.
  - Evidence: `3bdd60cc3a5a97b84519`
- Confirmed: Authentication event 67a9f5bfab28871757dd records outcome success.
  - Evidence: `67a9f5bfab28871757dd`
- Confirmed: Authentication event 6e10a5cc29314bc6a964 records outcome failure.
  - Evidence: `6e10a5cc29314bc6a964`
- Confirmed: Authentication event 8407329aafd15d9c0a9e records outcome failure.
  - Evidence: `8407329aafd15d9c0a9e`
- Confirmed: Event 98c80712635dec2f3738 records process identity sysmon:b06bb26c2e219a238c5b67fc124fd6ea.
  - Evidence: `98c80712635dec2f3738`
- Confirmed: Authentication event a068ff51cd2cb23d2f8d records outcome failure.
  - Evidence: `a068ff51cd2cb23d2f8d`
- Confirmed: Authentication event a3bf61cc981c8d0cdd5d records outcome failure.
  - Evidence: `a3bf61cc981c8d0cdd5d`
- Confirmed: Authentication event bc5bc87bcd4bf9827807 records outcome failure.
  - Evidence: `bc5bc87bcd4bf9827807`
- Confirmed: Authentication event d92873fb243f9f0bcb0d records outcome failure.
  - Evidence: `d92873fb243f9f0bcb0d`
- Confirmed: Authentication event f6497a719ee487d49e5a records outcome failure.
  - Evidence: `f6497a719ee487d49e5a`
- Confirmed: Process event 0b092d00f3798939dd00 identifies the instance in c1aa4d45ddf2102946f7 as its parent.
  - Evidence: `c1aa4d45ddf2102946f7, 0b092d00f3798939dd00`
- Confirmed: Process event c1aa4d45ddf2102946f7 identifies the instance in 98c80712635dec2f3738 as its parent.
  - Evidence: `98c80712635dec2f3738, c1aa4d45ddf2102946f7`

### Assessed (INFERENCE) (11)

*Interpretations and summaries; citation or predicate checks do not verify their free-text meaning.*

- Assessed: Unverified summary: ATH-005 (CRITICAL) on WS-9673 under account acct-2520: Failed logon burst followed by successful authentication. 12 failed logons for 'acct-2520' on WS-9673 from 10.10.2.8 within 220s. A successful logon followed at 08:05:00, 80s after the last failure. This may indicate the credential was successfully guessed and the account is now compromised.
  - Evidence: `0cb61159ea3d69dcc87a, d92873fb243f9f0bcb0d, 3bdd60cc3a5a97b84519, a068ff51cd2cb23d2f8d, 2108af7a380995a548b5, 6e10a5cc29314bc6a964, +7 more (see Evidence Appendix)`
- Assessed: Unverified summary: ATH-007 (HIGH) on WS-9673 under account acct-2520: Remote service execution (PsExec-style). The Service Control Manager started an interactive command interpreter. This pattern is consistent with remote command execution via a temporary service. Command output is redirected to the administrative share '\\127.0.0.1\ADMIN$', which is characteristic of remote execution frameworks collecting results over SMB.
  - Evidence: `c1aa4d45ddf2102946f7`
- Assessed: Unverified summary: The case's cited telemetry comprises 14 of 14 event(s), from 2026-08-01T08:00:00+00:00 to 2026-08-01T08:06:00+00:00.
  - Evidence: `0cb61159ea3d69dcc87a, d92873fb243f9f0bcb0d, 3bdd60cc3a5a97b84519, a068ff51cd2cb23d2f8d, 2108af7a380995a548b5, 6e10a5cc29314bc6a964, +8 more (see Evidence Appendix)`
- Assessed: Unverified summary: T1021.002 (SMB/Windows Admin Shares) is catalogued under Lateral Movement and is mapped to this case by ATH-007.
  - Evidence: `c1aa4d45ddf2102946f7`
- Assessed: Unverified summary: T1078 (Valid Accounts) is catalogued under Persistence, Privilege Escalation, Initial Access, Stealth and is mapped to this case by ATH-005.
  - Evidence: `0adbb9ef85b9188c8683, 0cb61159ea3d69dcc87a, 0cc680d6694f1f8615a1, 2108af7a380995a548b5, 3bdd60cc3a5a97b84519, 67a9f5bfab28871757dd, +7 more (see Evidence Appendix)`
- Assessed: Unverified summary: T1110.001 (Password Guessing) is catalogued under Credential Access and is mapped to this case by ATH-005.
  - Evidence: `0adbb9ef85b9188c8683, 0cb61159ea3d69dcc87a, 0cc680d6694f1f8615a1, 2108af7a380995a548b5, 3bdd60cc3a5a97b84519, 67a9f5bfab28871757dd, +7 more (see Evidence Appendix)`
- Assessed: Unverified summary: T1569.002 (Service Execution) is catalogued under Execution and is mapped to this case by ATH-007.
  - Evidence: `c1aa4d45ddf2102946f7`
- Assessed: Unverified summary: On WS-9673, cmd.exe (PID 500) ran under account acct-2520 with execution chain wininit.exe -> services.exe -> cmd.exe, spawning 1 child process(es): dism.exe. Resolution: identity.
  - Evidence: `c1aa4d45ddf2102946f7, 98c80712635dec2f3738, 0b092d00f3798939dd00`
- Assessed: [benign] The failed logons were a stale password retry. The executed command 'dism.exe /Online /Cleanup-Image /ScanHealth' is standard maintenance, not exfiltration.
  - Evidence: `bc5bc87bcd4bf9827807, 67a9f5bfab28871757dd, c1aa4d45ddf2102946f7, 0b092d00f3798939dd00`
- Assessed: [benign] The process tree shows 'dism.exe' running a health scan. This is a legitimate system maintenance task, contradicting the malicious exfiltration hypothesis.
  - Evidence: `0b092d00f3798939dd00, c1aa4d45ddf2102946f7`
- Assessed: [insufficient] The script 'job.cmd' contents are not observed. We cannot confirm if it exfiltrated data or performed maintenance.
  - Evidence: `c1aa4d45ddf2102946f7`

### Unconfirmed Hypotheses (0)

*Possible explanations that have NOT been verified. Treat as open questions for the analyst, not as findings.*

_None._

## Evidence Checks

20 typed observations verified; 8 unstructured summaries retained as interpretations.

Predicate support does not establish malicious intent or verify the accompanying prose.
- before [bc5bc87bcd4bf9827807, 67a9f5bfab28871757dd]: **supported** — recorded times: 2026-08-01T08:03:40+00:00 and 2026-08-01T08:05:00+00:00; no causal claim
- before [c1aa4d45ddf2102946f7, 0b092d00f3798939dd00]: **supported** — recorded times: 2026-08-01T08:06:00+00:00 and 2026-08-01T08:06:05+00:00; no causal claim
- process_identity [0b092d00f3798939dd00]: **supported** — recorded process identity: sysmon:399d50933db741bad79daec0f397fe8d
- before [c1aa4d45ddf2102946f7, 0b092d00f3798939dd00]: **supported** — recorded times: 2026-08-01T08:06:00+00:00 and 2026-08-01T08:06:05+00:00; no causal claim
- process_identity [c1aa4d45ddf2102946f7]: **supported** — recorded process identity: sysmon:ffa91f20286f6ae3e86e4b01e0c39444

## Recommended Next Steps

*These are investigative recommendations for a human analyst. No response action has been taken or is authorised by this report.*

1. **Retrieve email gateway or web-proxy logs to establish the initial access vector.**
   - Rationale: No detection in this case targets initial access, so the delivery mechanism (e.g. a phishing attachment) is inferred from process lineage rather than confirmed from delivery telemetry.
   - Based on: MITRE ATT&CK tactic coverage gap: Initial Access
2. **Independently verify account activity on all hosts in scope (WS-2138, WS-9673) rather than relying solely on the correlated case, in case related activity exists that current detections did not flag.**
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
- disposition: benign
- evidence gap: intent

## Investigation Trace

Agents run: investigator:seed, investigator:probe, investigator:conclude  
Tool calls made: 8

- step 1: investigator:seed -- findings, cited rows, techniques
- step 2: investigator:probe -- P1 process_tree: Retrieving the child process tree for pid 500 is required to observe the actual commands run by 'job.cmd' and distinguish between data exfiltration and benign maintenance.
- conclude: 3 explanation(s) proposed, 0 with out-of-scope citations dropped; disposition benign
- conclude: accepted 3, rejected 0
- stop -- model chose no probe
- evidence verification: 20 checked observations; 8 summaries reclassified

## Evidence Appendix

All 16 telemetry events underlying this report, chronologically. Every claim above cites specific event ids from this list.

| Event ID | Time | Device | User | Summary |
| --- | --- | --- | --- | --- |
| `0cb61159ea3d69dcc87a` | 08:00:00 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `98c80712635dec2f3738` | 08:00:00 | WS-9673 | acct-2520 | wininit.exe -> services.exe \| services.exe |
| `d92873fb243f9f0bcb0d` | 08:00:20 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `3bdd60cc3a5a97b84519` | 08:00:40 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `a068ff51cd2cb23d2f8d` | 08:01:00 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `2108af7a380995a548b5` | 08:01:20 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `6e10a5cc29314bc6a964` | 08:01:40 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `a3bf61cc981c8d0cdd5d` | 08:02:00 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `f6497a719ee487d49e5a` | 08:02:20 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `0cc680d6694f1f8615a1` | 08:02:40 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `8407329aafd15d9c0a9e` | 08:03:00 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `0adbb9ef85b9188c8683` | 08:03:20 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `bc5bc87bcd4bf9827807` | 08:03:40 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `67a9f5bfab28871757dd` | 08:05:00 | WS-9673 | acct-2520 | success logon [Network (SMB / share access)] from 10.10.2.8 |
| `c1aa4d45ddf2102946f7` | 08:06:00 | WS-9673 | acct-2520 | services.exe -> cmd.exe \| cmd.exe /Q /c job.cmd 1> \\127.0.0.1\ADMIN$\job.log 2>&1 |
| `0b092d00f3798939dd00` | 08:06:05 | WS-9673 | acct-2520 | cmd.exe -> dism.exe \| dism.exe /Online /Cleanup-Image /ScanHealth |
