# Investigation Report: CASE-001

**Generated:** 2026-09-22 19:02:31 UTC  
**Status:** complete  
**Severity:** CRITICAL  |  **Grouping confidence:** medium  
**Hosts:** WS-6906, WS-9059  
**Accounts:** acct-2721  
**Window:** 2026-08-09 08:00:00 -> 08:06:00 UTC (360s)

> This report was produced by an automated investigation over telemetry from: **generated_auth_execution**. It presents evidence-backed findings for analyst review and does not authorise or perform any response action.

## Executive Summary

This report covers CASE-001, correlating 2 detection finding(s) across 2 host(s) (WS-6906, WS-9059) and 1 account(s) (acct-2721) between 08:00:00 and 08:06:00 UTC on 2026-08-09. The evidence is consistent with activity spanning 4 MITRE ATT&CK tactic(s): Execution -> Persistence -> Credential Access -> Lateral Movement. Each mapping is an interpretation of observed behaviour against a public taxonomy, not a determination that an intrusion occurred. 30 statement(s) below are directly established by telemetry, 11 are evidence-supported inferences, and 0 are explicitly unverified hypotheses requiring analyst confirmation. This report does not authorise or perform any response action. All recommendations below require human review before action is taken.

## Attack Timeline

| Time | Rule | Severity | User | Host / Movement | ATT&CK | Events |
| --- | --- | --- | --- | --- | --- | --- |
| 08:00:00 | ATH-005 | CRITICAL | acct-2721 | WS-9059 | T1078, T1110.001 | 4af091d7e83c22c040da (+12) |
| 08:06:00 | ATH-007 | HIGH | acct-2721 | WS-9059 | T1021.002, T1569.002 | 1b9772fcbb7e6cf70a48 |

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

### Confirmed (FACT) (30)

*Typed observations checked against recorded telemetry.*

- Confirmed: Authentication event 003d64b618880bd24552 records outcome success.
  - Evidence: `003d64b618880bd24552`
- Confirmed: Event 066556a9277f95ed8bef records process identity sysmon:a716a605feed9ae3d4d01b46f4da0461.
  - Evidence: `066556a9277f95ed8bef`
- Confirmed: Authentication event 0ed6bec515bbe377f5bc records outcome failure.
  - Evidence: `0ed6bec515bbe377f5bc`
- Confirmed: Event 1b9772fcbb7e6cf70a48 records process identity sysmon:5371a1891d3fc1fefdca8d3f7ba3f1ef.
  - Evidence: `1b9772fcbb7e6cf70a48`
- Confirmed: Authentication event 1cd18d3ea728e523ebc7 records outcome failure.
  - Evidence: `1cd18d3ea728e523ebc7`
- Confirmed: Authentication event 1fa772c23539f5c22a28 records outcome success.
  - Evidence: `1fa772c23539f5c22a28`
- Confirmed: Authentication event 39a16744079223169997 records outcome failure.
  - Evidence: `39a16744079223169997`
- Confirmed: Authentication event 45c23219e73b7ae6e1d2 records outcome failure.
  - Evidence: `45c23219e73b7ae6e1d2`
- Confirmed: Authentication event 49c29ea372971682809b records outcome success.
  - Evidence: `49c29ea372971682809b`
- Confirmed: Authentication event 4af091d7e83c22c040da records outcome failure.
  - Evidence: `4af091d7e83c22c040da`
- Confirmed: Authentication event 4e58f1eb06f34984178b records outcome success.
  - Evidence: `4e58f1eb06f34984178b`
- Confirmed: Authentication event 533ce40e2cdb5490ccb5 records outcome success.
  - Evidence: `533ce40e2cdb5490ccb5`
- Confirmed: Authentication event 5a0cf2ef3612a3925fcf records outcome success.
  - Evidence: `5a0cf2ef3612a3925fcf`
- Confirmed: Authentication event 76fd149ccd3be844490d records outcome failure.
  - Evidence: `76fd149ccd3be844490d`
- Confirmed: Authentication event 77b9df8fc8af3c786fc6 records outcome failure.
  - Evidence: `77b9df8fc8af3c786fc6`
- Confirmed: Event 7dad9e6dcd99a0c43a0c records process identity sysmon:c251b15d7b2420ef28b4ef156644be80.
  - Evidence: `7dad9e6dcd99a0c43a0c`
- Confirmed: Authentication event 82ad2af3d4b12dfd5197 records outcome failure.
  - Evidence: `82ad2af3d4b12dfd5197`
- Confirmed: Authentication event 91bab52a1a85941f2154 records outcome success.
  - Evidence: `91bab52a1a85941f2154`
- Confirmed: Authentication event a9b34c568efd2f392012 records outcome failure.
  - Evidence: `a9b34c568efd2f392012`
- Confirmed: Authentication event b00e036c47ea4253dba3 records outcome success.
  - Evidence: `b00e036c47ea4253dba3`
- Confirmed: Authentication event b01e3c6c361392ab7e96 records outcome failure.
  - Evidence: `b01e3c6c361392ab7e96`
- Confirmed: Authentication event b679fc31dffe4b205c43 records outcome success.
  - Evidence: `b679fc31dffe4b205c43`
- Confirmed: Authentication event c49b71ff2455ca069f6e records outcome failure.
  - Evidence: `c49b71ff2455ca069f6e`
- Confirmed: Authentication event cb196d2470424068ab8c records outcome success.
  - Evidence: `cb196d2470424068ab8c`
- Confirmed: Authentication event cdc766872d9aab9e4794 records outcome success.
  - Evidence: `cdc766872d9aab9e4794`
- Confirmed: Authentication event e1065da39e77ccb8381e records outcome success.
  - Evidence: `e1065da39e77ccb8381e`
- Confirmed: Authentication event ec9f45b4bad008f7d319 records outcome failure.
  - Evidence: `ec9f45b4bad008f7d319`
- Confirmed: Authentication event faf99a2e9c9e3d575fc1 records outcome success.
  - Evidence: `faf99a2e9c9e3d575fc1`
- Confirmed: Process event 1b9772fcbb7e6cf70a48 identifies the instance in 066556a9277f95ed8bef as its parent.
  - Evidence: `066556a9277f95ed8bef, 1b9772fcbb7e6cf70a48`
- Confirmed: Process event 7dad9e6dcd99a0c43a0c identifies the instance in 1b9772fcbb7e6cf70a48 as its parent.
  - Evidence: `1b9772fcbb7e6cf70a48, 7dad9e6dcd99a0c43a0c`

### Assessed (INFERENCE) (11)

*Interpretations and summaries; citation or predicate checks do not verify their free-text meaning.*

- Assessed: Unverified summary: On WS-9059, cmd.exe (PID 500) was started by services.exe under account acct-2721.
  - Evidence: `1b9772fcbb7e6cf70a48`
- Assessed: Unverified summary: Execution chain on WS-9059: wininit.exe -> services.exe -> cmd.exe.
  - Evidence: `1b9772fcbb7e6cf70a48, 066556a9277f95ed8bef`
- Assessed: Unverified summary: cmd.exe (PID 500) on WS-9059 spawned 1 child process(es): reg.exe.
  - Evidence: `7dad9e6dcd99a0c43a0c`
- Assessed: Unverified summary: Account 'acct-2721' has 25 authentication events (12 failed, 13 successful) across hosts OFFICE-01, WS-9059.
  - Evidence: `1fa772c23539f5c22a28, 4af091d7e83c22c040da, c49b71ff2455ca069f6e, 533ce40e2cdb5490ccb5, ec9f45b4bad008f7d319, b00e036c47ea4253dba3, +19 more (see Evidence Appendix)`
- Assessed: Unverified summary: Account 'acct-2721' authenticated from more than one source host: OFFICE-01, WS-6906.
  - Evidence: `1fa772c23539f5c22a28, 4af091d7e83c22c040da, c49b71ff2455ca069f6e, 533ce40e2cdb5490ccb5, ec9f45b4bad008f7d319, b00e036c47ea4253dba3, +19 more (see Evidence Appendix)`
- Assessed: The 12 failed authentications for 'acct-2721' followed by success are consistent with the account's password having been guessed rather than with ordinary user error. (confidence 0.85)
  - Evidence: `4af091d7e83c22c040da, c49b71ff2455ca069f6e, ec9f45b4bad008f7d319, 0ed6bec515bbe377f5bc, 39a16744079223169997, b01e3c6c361392ab7e96, +6 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-005 is consistent with T1110.001 Brute Force: Password Guessing (Credential Access). Repeated failed authentications for a single account from a single source are consistent with systematically guessing that account's password. (A spray against many accounts would be T1110.003 and is not what was observed.) (confidence 0.90)
  - Evidence: `4af091d7e83c22c040da, c49b71ff2455ca069f6e, ec9f45b4bad008f7d319, 0ed6bec515bbe377f5bc, 39a16744079223169997, b01e3c6c361392ab7e96, +7 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-007 is consistent with T1569.002 System Services: Service Execution (Execution). A command interpreter was started by the Service Control Manager, which is the defining behaviour of executing a payload as a Windows service. (confidence 0.90)
  - Evidence: `1b9772fcbb7e6cf70a48`
- Assessed: Behaviour cited by ATH-005 is consistent with T1078 Valid Accounts (Persistence). A successful authentication followed the failure burst, which is consistent with the account credential now being under adversary control. (confidence 0.60)
  - Evidence: `4af091d7e83c22c040da, c49b71ff2455ca069f6e, ec9f45b4bad008f7d319, 0ed6bec515bbe377f5bc, 39a16744079223169997, b01e3c6c361392ab7e96, +7 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-007 is consistent with T1021.002 Remote Services: SMB/Windows Admin Shares (Lateral Movement). Command output was redirected to an administrative share, indicating the service was driven over an authenticated SMB session from another host. (confidence 0.60)
  - Evidence: `1b9772fcbb7e6cf70a48`
- Assessed: The case spans 4 ATT&CK tactics (Execution -> Persistence -> Credential Access -> Lateral Movement). Progression across multiple tactics is harder to explain as coincidental than activity confined to one. (confidence 0.80)
  - Evidence: `0ed6bec515bbe377f5bc, 1b9772fcbb7e6cf70a48, 1cd18d3ea728e523ebc7, 39a16744079223169997, 45c23219e73b7ae6e1d2, 4af091d7e83c22c040da, +8 more (see Evidence Appendix)`

### Unconfirmed Hypotheses (0)

*Possible explanations that have NOT been verified. Treat as open questions for the analyst, not as findings.*

_None._

## Evidence Checks

30 typed observations verified; 5 unstructured summaries retained as interpretations.

Predicate support does not establish malicious intent or verify the accompanying prose.

## Recommended Next Steps

*These are investigative recommendations for a human analyst. No response action has been taken or is authorised by this report.*

1. **Retrieve email gateway or web-proxy logs to establish the initial access vector.**
   - Rationale: No detection in this case targets initial access, so the delivery mechanism (e.g. a phishing attachment) is inferred from process lineage rather than confirmed from delivery telemetry.
   - Based on: MITRE ATT&CK tactic coverage gap: Initial Access
2. **Independently verify account activity on all hosts in scope (WS-6906, WS-9059) rather than relying solely on the correlated case, in case related activity exists that current detections did not flag.**
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
- evidence verification: 30 checked observations; 5 summaries reclassified

## Evidence Appendix

All 28 telemetry events underlying this report, chronologically. Every claim above cites specific event ids from this list.

| Event ID | Time | Device | User | Summary |
| --- | --- | --- | --- | --- |
| `4af091d7e83c22c040da` | 08:00:00 | WS-9059 | acct-2721 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `066556a9277f95ed8bef` | 08:00:00 | WS-9059 | acct-2721 | wininit.exe -> services.exe \| services.exe |
| `1fa772c23539f5c22a28` | 08:00:00 | OFFICE-01 | acct-2721 | success logon [Interactive (console)] from 10.10.1.5 |
| `c49b71ff2455ca069f6e` | 08:00:20 | WS-9059 | acct-2721 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `533ce40e2cdb5490ccb5` | 08:00:29 | OFFICE-01 | acct-2721 | success logon [Interactive (console)] from 10.10.1.5 |
| `ec9f45b4bad008f7d319` | 08:00:40 | WS-9059 | acct-2721 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `b00e036c47ea4253dba3` | 08:00:58 | OFFICE-01 | acct-2721 | success logon [Interactive (console)] from 10.10.1.5 |
| `0ed6bec515bbe377f5bc` | 08:01:00 | WS-9059 | acct-2721 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `39a16744079223169997` | 08:01:20 | WS-9059 | acct-2721 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `49c29ea372971682809b` | 08:01:27 | OFFICE-01 | acct-2721 | success logon [Interactive (console)] from 10.10.1.5 |
| `b01e3c6c361392ab7e96` | 08:01:40 | WS-9059 | acct-2721 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `5a0cf2ef3612a3925fcf` | 08:01:56 | OFFICE-01 | acct-2721 | success logon [Interactive (console)] from 10.10.1.5 |
| `45c23219e73b7ae6e1d2` | 08:02:00 | WS-9059 | acct-2721 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `76fd149ccd3be844490d` | 08:02:20 | WS-9059 | acct-2721 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `003d64b618880bd24552` | 08:02:25 | OFFICE-01 | acct-2721 | success logon [Interactive (console)] from 10.10.1.5 |
| `a9b34c568efd2f392012` | 08:02:40 | WS-9059 | acct-2721 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `cdc766872d9aab9e4794` | 08:02:54 | OFFICE-01 | acct-2721 | success logon [Interactive (console)] from 10.10.1.5 |
| `1cd18d3ea728e523ebc7` | 08:03:00 | WS-9059 | acct-2721 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `77b9df8fc8af3c786fc6` | 08:03:20 | WS-9059 | acct-2721 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `faf99a2e9c9e3d575fc1` | 08:03:23 | OFFICE-01 | acct-2721 | success logon [Interactive (console)] from 10.10.1.5 |
| `82ad2af3d4b12dfd5197` | 08:03:40 | WS-9059 | acct-2721 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `4e58f1eb06f34984178b` | 08:03:52 | OFFICE-01 | acct-2721 | success logon [Interactive (console)] from 10.10.1.5 |
| `e1065da39e77ccb8381e` | 08:04:21 | OFFICE-01 | acct-2721 | success logon [Interactive (console)] from 10.10.1.5 |
| `cb196d2470424068ab8c` | 08:04:50 | OFFICE-01 | acct-2721 | success logon [Interactive (console)] from 10.10.1.5 |
| `b679fc31dffe4b205c43` | 08:05:00 | WS-9059 | acct-2721 | success logon [Network (SMB / share access)] from 10.10.2.8 |
| `91bab52a1a85941f2154` | 08:05:19 | OFFICE-01 | acct-2721 | success logon [Interactive (console)] from 10.10.1.5 |
| `1b9772fcbb7e6cf70a48` | 08:06:00 | WS-9059 | acct-2721 | services.exe -> cmd.exe \| cmd.exe /Q /c job.cmd 1> \\127.0.0.1\ADMIN$\job.log 2>&1 |
| `7dad9e6dcd99a0c43a0c` | 08:06:05 | WS-9059 | acct-2721 | cmd.exe -> reg.exe \| reg.exe save HKLM\SECURITY C:\ProgramData\security.hiv /y |
