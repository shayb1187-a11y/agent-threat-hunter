# Investigation Report: CASE-001

**Generated:** 2026-09-22 19:02:31 UTC  
**Status:** complete  
**Severity:** CRITICAL  |  **Grouping confidence:** medium  
**Hosts:** WS-6981, WS-7323  
**Accounts:** acct-9945  
**Window:** 2026-08-09 08:00:00 -> 08:06:00 UTC (360s)

> This report was produced by an automated investigation over telemetry from: **generated_auth_execution**. It presents evidence-backed findings for analyst review and does not authorise or perform any response action.

## Executive Summary

This report covers CASE-001, correlating 2 detection finding(s) across 2 host(s) (WS-6981, WS-7323) and 1 account(s) (acct-9945) between 08:00:00 and 08:06:00 UTC on 2026-08-09. The evidence is consistent with activity spanning 4 MITRE ATT&CK tactic(s): Execution -> Persistence -> Credential Access -> Lateral Movement. Each mapping is an interpretation of observed behaviour against a public taxonomy, not a determination that an intrusion occurred. 28 statement(s) below are directly established by telemetry, 10 are evidence-supported inferences, and 0 are explicitly unverified hypotheses requiring analyst confirmation. This report does not authorise or perform any response action. All recommendations below require human review before action is taken.

## Attack Timeline

| Time | Rule | Severity | User | Host / Movement | ATT&CK | Events |
| --- | --- | --- | --- | --- | --- | --- |
| 08:00:00 | ATH-005 | CRITICAL | acct-9945 | WS-6981 | T1078, T1110.001 | cf632d6941a273c52001 (+12) |
| 08:06:00 | ATH-007 | HIGH | acct-9945 | WS-6981 | T1021.002, T1569.002 | b09aaa4337dd2da6554d |

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

### Confirmed (FACT) (28)

*Typed observations checked against recorded telemetry.*

- Confirmed: Event 251ad6addce167f689a0 records process identity sysmon:a279b549565744c9bb43d6fadf53587a.
  - Evidence: `251ad6addce167f689a0`
- Confirmed: Authentication event 292c0e504283324471b9 records outcome success.
  - Evidence: `292c0e504283324471b9`
- Confirmed: Authentication event 3b365104c157df16fe4d records outcome failure.
  - Evidence: `3b365104c157df16fe4d`
- Confirmed: Authentication event 3bb96d7d1c92f4c58489 records outcome success.
  - Evidence: `3bb96d7d1c92f4c58489`
- Confirmed: Authentication event 5ba2e1cef49c9b69b2d1 records outcome success.
  - Evidence: `5ba2e1cef49c9b69b2d1`
- Confirmed: Authentication event 62eaeb8decfad37c0b3e records outcome success.
  - Evidence: `62eaeb8decfad37c0b3e`
- Confirmed: Authentication event 6d284dbbab3fe8bf01ab records outcome success.
  - Evidence: `6d284dbbab3fe8bf01ab`
- Confirmed: Authentication event 705b93a6e3a4ab3edb9e records outcome success.
  - Evidence: `705b93a6e3a4ab3edb9e`
- Confirmed: Authentication event 729451128323490ab545 records outcome failure.
  - Evidence: `729451128323490ab545`
- Confirmed: Authentication event 7c0b6705c41b1afe5847 records outcome failure.
  - Evidence: `7c0b6705c41b1afe5847`
- Confirmed: Authentication event 88bce714d45e7bd9b193 records outcome failure.
  - Evidence: `88bce714d45e7bd9b193`
- Confirmed: Authentication event 89e97aedbcb901799ebd records outcome failure.
  - Evidence: `89e97aedbcb901799ebd`
- Confirmed: Authentication event 8ade5cc400fdf5cdcbb6 records outcome failure.
  - Evidence: `8ade5cc400fdf5cdcbb6`
- Confirmed: Authentication event 9cd0f58e424b17dad6c1 records outcome failure.
  - Evidence: `9cd0f58e424b17dad6c1`
- Confirmed: Authentication event 9da148ed37848b3cc45c records outcome success.
  - Evidence: `9da148ed37848b3cc45c`
- Confirmed: Authentication event 9ed8e910a61672b676c0 records outcome failure.
  - Evidence: `9ed8e910a61672b676c0`
- Confirmed: Authentication event a7a83bbdb4372246b01f records outcome failure.
  - Evidence: `a7a83bbdb4372246b01f`
- Confirmed: Event b09aaa4337dd2da6554d records process identity sysmon:cf5fc2065c8d519ef7063fb440ab951c.
  - Evidence: `b09aaa4337dd2da6554d`
- Confirmed: Authentication event ba3ddf893c4ede593333 records outcome success.
  - Evidence: `ba3ddf893c4ede593333`
- Confirmed: Authentication event c75485b35ac71e25a20c records outcome success.
  - Evidence: `c75485b35ac71e25a20c`
- Confirmed: Authentication event c99d2e9e431a55ce77d0 records outcome success.
  - Evidence: `c99d2e9e431a55ce77d0`
- Confirmed: Authentication event cf632d6941a273c52001 records outcome failure.
  - Evidence: `cf632d6941a273c52001`
- Confirmed: Authentication event d36cd7aa15af40d5ff2b records outcome success.
  - Evidence: `d36cd7aa15af40d5ff2b`
- Confirmed: Authentication event d43cf69ee68bc6981d73 records outcome success.
  - Evidence: `d43cf69ee68bc6981d73`
- Confirmed: Authentication event db9db8d5f576b3703080 records outcome failure.
  - Evidence: `db9db8d5f576b3703080`
- Confirmed: Authentication event ecdd90fb562084aa4e04 records outcome failure.
  - Evidence: `ecdd90fb562084aa4e04`
- Confirmed: Authentication event f586b9f4e66f9f57317b records outcome success.
  - Evidence: `f586b9f4e66f9f57317b`
- Confirmed: Process event b09aaa4337dd2da6554d identifies the instance in 251ad6addce167f689a0 as its parent.
  - Evidence: `251ad6addce167f689a0, b09aaa4337dd2da6554d`

### Assessed (INFERENCE) (10)

*Interpretations and summaries; citation or predicate checks do not verify their free-text meaning.*

- Assessed: Unverified summary: On WS-6981, cmd.exe (PID 500) was started by services.exe under account acct-9945.
  - Evidence: `b09aaa4337dd2da6554d`
- Assessed: Unverified summary: Execution chain on WS-6981: wininit.exe -> services.exe -> cmd.exe.
  - Evidence: `b09aaa4337dd2da6554d, 251ad6addce167f689a0`
- Assessed: Unverified summary: Account 'acct-9945' has 25 authentication events (12 failed, 13 successful) across hosts OFFICE-01, WS-6981.
  - Evidence: `3bb96d7d1c92f4c58489, cf632d6941a273c52001, a7a83bbdb4372246b01f, f586b9f4e66f9f57317b, 7c0b6705c41b1afe5847, 5ba2e1cef49c9b69b2d1, +19 more (see Evidence Appendix)`
- Assessed: Unverified summary: Account 'acct-9945' authenticated from more than one source host: OFFICE-01, WS-7323.
  - Evidence: `3bb96d7d1c92f4c58489, cf632d6941a273c52001, a7a83bbdb4372246b01f, f586b9f4e66f9f57317b, 7c0b6705c41b1afe5847, 5ba2e1cef49c9b69b2d1, +19 more (see Evidence Appendix)`
- Assessed: The 12 failed authentications for 'acct-9945' followed by success are consistent with the account's password having been guessed rather than with ordinary user error. (confidence 0.85)
  - Evidence: `cf632d6941a273c52001, a7a83bbdb4372246b01f, 7c0b6705c41b1afe5847, 8ade5cc400fdf5cdcbb6, ecdd90fb562084aa4e04, 88bce714d45e7bd9b193, +6 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-005 is consistent with T1110.001 Brute Force: Password Guessing (Credential Access). Repeated failed authentications for a single account from a single source are consistent with systematically guessing that account's password. (A spray against many accounts would be T1110.003 and is not what was observed.) (confidence 0.90)
  - Evidence: `cf632d6941a273c52001, a7a83bbdb4372246b01f, 7c0b6705c41b1afe5847, 8ade5cc400fdf5cdcbb6, ecdd90fb562084aa4e04, 88bce714d45e7bd9b193, +7 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-007 is consistent with T1569.002 System Services: Service Execution (Execution). A command interpreter was started by the Service Control Manager, which is the defining behaviour of executing a payload as a Windows service. (confidence 0.90)
  - Evidence: `b09aaa4337dd2da6554d`
- Assessed: Behaviour cited by ATH-005 is consistent with T1078 Valid Accounts (Persistence). A successful authentication followed the failure burst, which is consistent with the account credential now being under adversary control. (confidence 0.60)
  - Evidence: `cf632d6941a273c52001, a7a83bbdb4372246b01f, 7c0b6705c41b1afe5847, 8ade5cc400fdf5cdcbb6, ecdd90fb562084aa4e04, 88bce714d45e7bd9b193, +7 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-007 is consistent with T1021.002 Remote Services: SMB/Windows Admin Shares (Lateral Movement). Command output was redirected to an administrative share, indicating the service was driven over an authenticated SMB session from another host. (confidence 0.60)
  - Evidence: `b09aaa4337dd2da6554d`
- Assessed: The case spans 4 ATT&CK tactics (Execution -> Persistence -> Credential Access -> Lateral Movement). Progression across multiple tactics is harder to explain as coincidental than activity confined to one. (confidence 0.80)
  - Evidence: `3b365104c157df16fe4d, 6d284dbbab3fe8bf01ab, 729451128323490ab545, 7c0b6705c41b1afe5847, 88bce714d45e7bd9b193, 89e97aedbcb901799ebd, +8 more (see Evidence Appendix)`

### Unconfirmed Hypotheses (0)

*Possible explanations that have NOT been verified. Treat as open questions for the analyst, not as findings.*

_None._

## Evidence Checks

28 typed observations verified; 4 unstructured summaries retained as interpretations.

Predicate support does not establish malicious intent or verify the accompanying prose.

## Recommended Next Steps

*These are investigative recommendations for a human analyst. No response action has been taken or is authorised by this report.*

1. **Retrieve email gateway or web-proxy logs to establish the initial access vector.**
   - Rationale: No detection in this case targets initial access, so the delivery mechanism (e.g. a phishing attachment) is inferred from process lineage rather than confirmed from delivery telemetry.
   - Based on: MITRE ATT&CK tactic coverage gap: Initial Access
2. **Independently verify account activity on all hosts in scope (WS-6981, WS-7323) rather than relying solely on the correlated case, in case related activity exists that current detections did not flag.**
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
- No evidence was found for the following tactics: Collection. Their absence may reflect either that the activity did not occur or that we lack the telemetry to see it.

## Investigation Trace

Agents run: endpoint, identity, attack  
Tool calls made: 8

- step 1: endpoint -- deterministic priority order; case evidence rests on process_command_line, process_execution, process_lineage telemetry (from ATH-007)
- step 2: identity -- deterministic priority order; case evidence rests on auth_source_attribution, authentication telemetry (from ATH-005)
- step 3: attack -- only eligible specialist; case has ATT&CK mappings and domain evidence has been gathered
- step 4: stop -- no specialist has further useful work on the available evidence
- evidence verification: 28 checked observations; 4 summaries reclassified

## Evidence Appendix

All 27 telemetry events underlying this report, chronologically. Every claim above cites specific event ids from this list.

| Event ID | Time | Device | User | Summary |
| --- | --- | --- | --- | --- |
| `3bb96d7d1c92f4c58489` | 08:00:00 | OFFICE-01 | acct-9945 | success logon [Interactive (console)] from 10.10.1.5 |
| `cf632d6941a273c52001` | 08:00:00 | WS-6981 | acct-9945 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `251ad6addce167f689a0` | 08:00:00 | WS-6981 | acct-9945 | wininit.exe -> services.exe \| services.exe |
| `a7a83bbdb4372246b01f` | 08:00:20 | WS-6981 | acct-9945 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `f586b9f4e66f9f57317b` | 08:00:29 | OFFICE-01 | acct-9945 | success logon [Interactive (console)] from 10.10.1.5 |
| `7c0b6705c41b1afe5847` | 08:00:40 | WS-6981 | acct-9945 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `5ba2e1cef49c9b69b2d1` | 08:00:58 | OFFICE-01 | acct-9945 | success logon [Interactive (console)] from 10.10.1.5 |
| `8ade5cc400fdf5cdcbb6` | 08:01:00 | WS-6981 | acct-9945 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `ecdd90fb562084aa4e04` | 08:01:20 | WS-6981 | acct-9945 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `9da148ed37848b3cc45c` | 08:01:27 | OFFICE-01 | acct-9945 | success logon [Interactive (console)] from 10.10.1.5 |
| `88bce714d45e7bd9b193` | 08:01:40 | WS-6981 | acct-9945 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `62eaeb8decfad37c0b3e` | 08:01:56 | OFFICE-01 | acct-9945 | success logon [Interactive (console)] from 10.10.1.5 |
| `89e97aedbcb901799ebd` | 08:02:00 | WS-6981 | acct-9945 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `db9db8d5f576b3703080` | 08:02:20 | WS-6981 | acct-9945 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `ba3ddf893c4ede593333` | 08:02:25 | OFFICE-01 | acct-9945 | success logon [Interactive (console)] from 10.10.1.5 |
| `9cd0f58e424b17dad6c1` | 08:02:40 | WS-6981 | acct-9945 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `c99d2e9e431a55ce77d0` | 08:02:54 | OFFICE-01 | acct-9945 | success logon [Interactive (console)] from 10.10.1.5 |
| `9ed8e910a61672b676c0` | 08:03:00 | WS-6981 | acct-9945 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `729451128323490ab545` | 08:03:20 | WS-6981 | acct-9945 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `c75485b35ac71e25a20c` | 08:03:23 | OFFICE-01 | acct-9945 | success logon [Interactive (console)] from 10.10.1.5 |
| `3b365104c157df16fe4d` | 08:03:40 | WS-6981 | acct-9945 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `292c0e504283324471b9` | 08:03:52 | OFFICE-01 | acct-9945 | success logon [Interactive (console)] from 10.10.1.5 |
| `d43cf69ee68bc6981d73` | 08:04:21 | OFFICE-01 | acct-9945 | success logon [Interactive (console)] from 10.10.1.5 |
| `d36cd7aa15af40d5ff2b` | 08:04:50 | OFFICE-01 | acct-9945 | success logon [Interactive (console)] from 10.10.1.5 |
| `6d284dbbab3fe8bf01ab` | 08:05:00 | WS-6981 | acct-9945 | success logon [Network (SMB / share access)] from 10.10.2.8 |
| `705b93a6e3a4ab3edb9e` | 08:05:19 | OFFICE-01 | acct-9945 | success logon [Interactive (console)] from 10.10.1.5 |
| `b09aaa4337dd2da6554d` | 08:06:00 | WS-6981 | acct-9945 | services.exe -> cmd.exe \| cmd.exe /Q /c job.cmd 1> \\127.0.0.1\ADMIN$\job.log 2>&1 |
