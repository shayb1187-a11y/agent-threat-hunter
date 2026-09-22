# Investigation Report: CASE-001

**Generated:** 2026-09-22 19:02:32 UTC  
**Status:** complete  
**Severity:** CRITICAL  |  **Grouping confidence:** medium  
**Hosts:** WS-8490, WS-9184  
**Accounts:** acct-4250  
**Window:** 2026-08-09 08:00:00 -> 08:06:00 UTC (360s)

> This report was produced by an automated investigation over telemetry from: **generated_auth_execution**. It presents evidence-backed findings for analyst review and does not authorise or perform any response action.

## Executive Summary

This report covers CASE-001, correlating 2 detection finding(s) across 2 host(s) (WS-8490, WS-9184) and 1 account(s) (acct-4250) between 08:00:00 and 08:06:00 UTC on 2026-08-09. The evidence is consistent with activity spanning 4 MITRE ATT&CK tactic(s): Execution -> Persistence -> Credential Access -> Lateral Movement. Each mapping is an interpretation of observed behaviour against a public taxonomy, not a determination that an intrusion occurred. 30 statement(s) below are directly established by telemetry, 11 are evidence-supported inferences, and 0 are explicitly unverified hypotheses requiring analyst confirmation. This report does not authorise or perform any response action. All recommendations below require human review before action is taken.

## Attack Timeline

| Time | Rule | Severity | User | Host / Movement | ATT&CK | Events |
| --- | --- | --- | --- | --- | --- | --- |
| 08:00:00 | ATH-005 | CRITICAL | acct-4250 | WS-9184 | T1078, T1110.001 | 0972c99bf16b26e932fc (+12) |
| 08:06:00 | ATH-007 | HIGH | acct-4250 | WS-9184 | T1021.002, T1569.002 | f4f80277a2e8b1fb6657 |

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

- Confirmed: Authentication event 0056f38a56f9c4c13ce9 records outcome failure.
  - Evidence: `0056f38a56f9c4c13ce9`
- Confirmed: Event 03dd620ad1f77837422f records process identity sysmon:bea78c4544ee920ea30be19794259dc9.
  - Evidence: `03dd620ad1f77837422f`
- Confirmed: Authentication event 0972c99bf16b26e932fc records outcome failure.
  - Evidence: `0972c99bf16b26e932fc`
- Confirmed: Authentication event 10a10aa7bafb5d777dc5 records outcome failure.
  - Evidence: `10a10aa7bafb5d777dc5`
- Confirmed: Authentication event 12b2b6c2b4d09c8d10aa records outcome failure.
  - Evidence: `12b2b6c2b4d09c8d10aa`
- Confirmed: Authentication event 2ffcc1ac3e48f7032579 records outcome failure.
  - Evidence: `2ffcc1ac3e48f7032579`
- Confirmed: Authentication event 4189601279963e5a71d9 records outcome success.
  - Evidence: `4189601279963e5a71d9`
- Confirmed: Authentication event 5a09e85ad8b8296ddc60 records outcome success.
  - Evidence: `5a09e85ad8b8296ddc60`
- Confirmed: Authentication event 5eba2bb1016dbde9bdb5 records outcome failure.
  - Evidence: `5eba2bb1016dbde9bdb5`
- Confirmed: Authentication event 62331760ea4bc8b065aa records outcome failure.
  - Evidence: `62331760ea4bc8b065aa`
- Confirmed: Authentication event 7dc3492b877b15737185 records outcome success.
  - Evidence: `7dc3492b877b15737185`
- Confirmed: Authentication event 8d533a2ce6a51ef133e8 records outcome failure.
  - Evidence: `8d533a2ce6a51ef133e8`
- Confirmed: Authentication event 979d694e1db6c60bee08 records outcome success.
  - Evidence: `979d694e1db6c60bee08`
- Confirmed: Authentication event b14495d2c7677ccb6348 records outcome success.
  - Evidence: `b14495d2c7677ccb6348`
- Confirmed: Authentication event b6b149d9211ba45a8711 records outcome success.
  - Evidence: `b6b149d9211ba45a8711`
- Confirmed: Authentication event b82f1b93f262777ba16b records outcome success.
  - Evidence: `b82f1b93f262777ba16b`
- Confirmed: Authentication event b9e25dda2fc008a2e423 records outcome success.
  - Evidence: `b9e25dda2fc008a2e423`
- Confirmed: Authentication event bcd71db9d5240b28117b records outcome success.
  - Evidence: `bcd71db9d5240b28117b`
- Confirmed: Authentication event bdfc75faeb5a0ba30dc8 records outcome success.
  - Evidence: `bdfc75faeb5a0ba30dc8`
- Confirmed: Authentication event be90d16889c44c1ee390 records outcome success.
  - Evidence: `be90d16889c44c1ee390`
- Confirmed: Authentication event c8fab03bb6264a9275e5 records outcome failure.
  - Evidence: `c8fab03bb6264a9275e5`
- Confirmed: Authentication event ca0c421fbaf2809482e5 records outcome success.
  - Evidence: `ca0c421fbaf2809482e5`
- Confirmed: Authentication event cd590c97577b0db343e7 records outcome failure.
  - Evidence: `cd590c97577b0db343e7`
- Confirmed: Authentication event d179abf5a29ee91a687d records outcome success.
  - Evidence: `d179abf5a29ee91a687d`
- Confirmed: Event d30d6b7a24b4d344a0d4 records process identity sysmon:e5fd7af34bb12cf5e1485d8206e110f2.
  - Evidence: `d30d6b7a24b4d344a0d4`
- Confirmed: Authentication event df22ba50c660b932fa9d records outcome failure.
  - Evidence: `df22ba50c660b932fa9d`
- Confirmed: Authentication event eebea4c9b8159c728c8c records outcome failure.
  - Evidence: `eebea4c9b8159c728c8c`
- Confirmed: Event f4f80277a2e8b1fb6657 records process identity sysmon:abd65e778c3f0364c80d33809a8289ed.
  - Evidence: `f4f80277a2e8b1fb6657`
- Confirmed: Process event 03dd620ad1f77837422f identifies the instance in f4f80277a2e8b1fb6657 as its parent.
  - Evidence: `f4f80277a2e8b1fb6657, 03dd620ad1f77837422f`
- Confirmed: Process event f4f80277a2e8b1fb6657 identifies the instance in d30d6b7a24b4d344a0d4 as its parent.
  - Evidence: `d30d6b7a24b4d344a0d4, f4f80277a2e8b1fb6657`

### Assessed (INFERENCE) (11)

*Interpretations and summaries; citation or predicate checks do not verify their free-text meaning.*

- Assessed: Unverified summary: On WS-9184, cmd.exe (PID 500) was started by services.exe under account acct-4250.
  - Evidence: `f4f80277a2e8b1fb6657`
- Assessed: Unverified summary: Execution chain on WS-9184: wininit.exe -> services.exe -> cmd.exe.
  - Evidence: `f4f80277a2e8b1fb6657, d30d6b7a24b4d344a0d4`
- Assessed: Unverified summary: cmd.exe (PID 500) on WS-9184 spawned 1 child process(es): dism.exe.
  - Evidence: `03dd620ad1f77837422f`
- Assessed: Unverified summary: Account 'acct-4250' has 25 authentication events (12 failed, 13 successful) across hosts OFFICE-01, WS-9184.
  - Evidence: `bdfc75faeb5a0ba30dc8, 0972c99bf16b26e932fc, eebea4c9b8159c728c8c, be90d16889c44c1ee390, 2ffcc1ac3e48f7032579, b82f1b93f262777ba16b, +19 more (see Evidence Appendix)`
- Assessed: Unverified summary: Account 'acct-4250' authenticated from more than one source host: OFFICE-01, WS-8490.
  - Evidence: `bdfc75faeb5a0ba30dc8, 0972c99bf16b26e932fc, eebea4c9b8159c728c8c, be90d16889c44c1ee390, 2ffcc1ac3e48f7032579, b82f1b93f262777ba16b, +19 more (see Evidence Appendix)`
- Assessed: The 12 failed authentications for 'acct-4250' followed by success are consistent with the account's password having been guessed rather than with ordinary user error. (confidence 0.85)
  - Evidence: `0972c99bf16b26e932fc, eebea4c9b8159c728c8c, 2ffcc1ac3e48f7032579, 12b2b6c2b4d09c8d10aa, 5eba2bb1016dbde9bdb5, 8d533a2ce6a51ef133e8, +6 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-005 is consistent with T1110.001 Brute Force: Password Guessing (Credential Access). Repeated failed authentications for a single account from a single source are consistent with systematically guessing that account's password. (A spray against many accounts would be T1110.003 and is not what was observed.) (confidence 0.90)
  - Evidence: `0972c99bf16b26e932fc, eebea4c9b8159c728c8c, 2ffcc1ac3e48f7032579, 12b2b6c2b4d09c8d10aa, 5eba2bb1016dbde9bdb5, 8d533a2ce6a51ef133e8, +7 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-007 is consistent with T1569.002 System Services: Service Execution (Execution). A command interpreter was started by the Service Control Manager, which is the defining behaviour of executing a payload as a Windows service. (confidence 0.90)
  - Evidence: `f4f80277a2e8b1fb6657`
- Assessed: Behaviour cited by ATH-005 is consistent with T1078 Valid Accounts (Persistence). A successful authentication followed the failure burst, which is consistent with the account credential now being under adversary control. (confidence 0.60)
  - Evidence: `0972c99bf16b26e932fc, eebea4c9b8159c728c8c, 2ffcc1ac3e48f7032579, 12b2b6c2b4d09c8d10aa, 5eba2bb1016dbde9bdb5, 8d533a2ce6a51ef133e8, +7 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-007 is consistent with T1021.002 Remote Services: SMB/Windows Admin Shares (Lateral Movement). Command output was redirected to an administrative share, indicating the service was driven over an authenticated SMB session from another host. (confidence 0.60)
  - Evidence: `f4f80277a2e8b1fb6657`
- Assessed: The case spans 4 ATT&CK tactics (Execution -> Persistence -> Credential Access -> Lateral Movement). Progression across multiple tactics is harder to explain as coincidental than activity confined to one. (confidence 0.80)
  - Evidence: `0056f38a56f9c4c13ce9, 0972c99bf16b26e932fc, 10a10aa7bafb5d777dc5, 12b2b6c2b4d09c8d10aa, 2ffcc1ac3e48f7032579, 4189601279963e5a71d9, +8 more (see Evidence Appendix)`

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
2. **Independently verify account activity on all hosts in scope (WS-8490, WS-9184) rather than relying solely on the correlated case, in case related activity exists that current detections did not flag.**
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
| `0972c99bf16b26e932fc` | 08:00:00 | WS-9184 | acct-4250 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `d30d6b7a24b4d344a0d4` | 08:00:00 | WS-9184 | acct-4250 | wininit.exe -> services.exe \| services.exe |
| `bdfc75faeb5a0ba30dc8` | 08:00:00 | OFFICE-01 | acct-4250 | success logon [Interactive (console)] from 10.10.1.5 |
| `eebea4c9b8159c728c8c` | 08:00:20 | WS-9184 | acct-4250 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `be90d16889c44c1ee390` | 08:00:29 | OFFICE-01 | acct-4250 | success logon [Interactive (console)] from 10.10.1.5 |
| `2ffcc1ac3e48f7032579` | 08:00:40 | WS-9184 | acct-4250 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `b82f1b93f262777ba16b` | 08:00:58 | OFFICE-01 | acct-4250 | success logon [Interactive (console)] from 10.10.1.5 |
| `12b2b6c2b4d09c8d10aa` | 08:01:00 | WS-9184 | acct-4250 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `5eba2bb1016dbde9bdb5` | 08:01:20 | WS-9184 | acct-4250 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `bcd71db9d5240b28117b` | 08:01:27 | OFFICE-01 | acct-4250 | success logon [Interactive (console)] from 10.10.1.5 |
| `8d533a2ce6a51ef133e8` | 08:01:40 | WS-9184 | acct-4250 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `ca0c421fbaf2809482e5` | 08:01:56 | OFFICE-01 | acct-4250 | success logon [Interactive (console)] from 10.10.1.5 |
| `62331760ea4bc8b065aa` | 08:02:00 | WS-9184 | acct-4250 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `0056f38a56f9c4c13ce9` | 08:02:20 | WS-9184 | acct-4250 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `b6b149d9211ba45a8711` | 08:02:25 | OFFICE-01 | acct-4250 | success logon [Interactive (console)] from 10.10.1.5 |
| `10a10aa7bafb5d777dc5` | 08:02:40 | WS-9184 | acct-4250 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `b9e25dda2fc008a2e423` | 08:02:54 | OFFICE-01 | acct-4250 | success logon [Interactive (console)] from 10.10.1.5 |
| `c8fab03bb6264a9275e5` | 08:03:00 | WS-9184 | acct-4250 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `df22ba50c660b932fa9d` | 08:03:20 | WS-9184 | acct-4250 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `b14495d2c7677ccb6348` | 08:03:23 | OFFICE-01 | acct-4250 | success logon [Interactive (console)] from 10.10.1.5 |
| `cd590c97577b0db343e7` | 08:03:40 | WS-9184 | acct-4250 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `7dc3492b877b15737185` | 08:03:52 | OFFICE-01 | acct-4250 | success logon [Interactive (console)] from 10.10.1.5 |
| `5a09e85ad8b8296ddc60` | 08:04:21 | OFFICE-01 | acct-4250 | success logon [Interactive (console)] from 10.10.1.5 |
| `979d694e1db6c60bee08` | 08:04:50 | OFFICE-01 | acct-4250 | success logon [Interactive (console)] from 10.10.1.5 |
| `4189601279963e5a71d9` | 08:05:00 | WS-9184 | acct-4250 | success logon [Network (SMB / share access)] from 10.10.2.8 |
| `d179abf5a29ee91a687d` | 08:05:19 | OFFICE-01 | acct-4250 | success logon [Interactive (console)] from 10.10.1.5 |
| `f4f80277a2e8b1fb6657` | 08:06:00 | WS-9184 | acct-4250 | services.exe -> cmd.exe \| cmd.exe /Q /c job.cmd 1> \\127.0.0.1\ADMIN$\job.log 2>&1 |
| `03dd620ad1f77837422f` | 08:06:05 | WS-9184 | acct-4250 | cmd.exe -> dism.exe \| dism.exe /Online /Get-Packages /Format:Table |
