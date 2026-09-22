# Investigation Report: CASE-001

**Generated:** 2026-09-22 19:02:53 UTC  
**Status:** complete  
**Severity:** CRITICAL  |  **Grouping confidence:** medium  
**Hosts:** WS-3250, WS-7003  
**Accounts:** acct-8592  
**Window:** 2026-08-01 08:00:00 -> 08:06:00 UTC (360s)

> This report was produced by an automated investigation over telemetry from: **generated_auth_execution**. It presents evidence-backed findings for analyst review and does not authorise or perform any response action.

## Executive Summary

This report covers CASE-001, correlating 2 detection finding(s) across 2 host(s) (WS-3250, WS-7003) and 1 account(s) (acct-8592) between 08:00:00 and 08:06:00 UTC on 2026-08-01. The evidence is consistent with activity spanning 4 MITRE ATT&CK tactic(s): Execution -> Persistence -> Credential Access -> Lateral Movement. Each mapping is an interpretation of observed behaviour against a public taxonomy, not a determination that an intrusion occurred. 28 statement(s) below are directly established by telemetry, 10 are evidence-supported inferences, and 0 are explicitly unverified hypotheses requiring analyst confirmation. This report does not authorise or perform any response action. All recommendations below require human review before action is taken.

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

### Confirmed (FACT) (28)

*Typed observations checked against recorded telemetry.*

- Confirmed: Authentication event 1f776b2d12b6e1b38138 records outcome failure.
  - Evidence: `1f776b2d12b6e1b38138`
- Confirmed: Event 21cfbf2f84aba973509b records process identity sysmon:2a0296a72747c0b9019b2d5f243aed94.
  - Evidence: `21cfbf2f84aba973509b`
- Confirmed: Authentication event 3de8d5b15fb19024a732 records outcome success.
  - Evidence: `3de8d5b15fb19024a732`
- Confirmed: Authentication event 4b7981dfd851184e370d records outcome failure.
  - Evidence: `4b7981dfd851184e370d`
- Confirmed: Authentication event 4e51bb11a05d061eaa79 records outcome success.
  - Evidence: `4e51bb11a05d061eaa79`
- Confirmed: Authentication event 644fcfd5011068a13cc3 records outcome success.
  - Evidence: `644fcfd5011068a13cc3`
- Confirmed: Authentication event 70070eda726d0ffa9b62 records outcome success.
  - Evidence: `70070eda726d0ffa9b62`
- Confirmed: Authentication event 7794c2b19501be2cb80b records outcome success.
  - Evidence: `7794c2b19501be2cb80b`
- Confirmed: Authentication event 7a605231a8b8245ac918 records outcome success.
  - Evidence: `7a605231a8b8245ac918`
- Confirmed: Authentication event 7ae112de50a7ef35212b records outcome failure.
  - Evidence: `7ae112de50a7ef35212b`
- Confirmed: Authentication event 7e3cdc7f3dd94475bd36 records outcome success.
  - Evidence: `7e3cdc7f3dd94475bd36`
- Confirmed: Authentication event 80fa003ab0d4b9fb50d3 records outcome failure.
  - Evidence: `80fa003ab0d4b9fb50d3`
- Confirmed: Authentication event 880b1242f36a26407c74 records outcome failure.
  - Evidence: `880b1242f36a26407c74`
- Confirmed: Event 8e3b9127b110d0908581 records process identity sysmon:f7a5977e9afb5cc7e63853a79236e480.
  - Evidence: `8e3b9127b110d0908581`
- Confirmed: Authentication event 9ad04b5d0a58bac4bdd3 records outcome success.
  - Evidence: `9ad04b5d0a58bac4bdd3`
- Confirmed: Authentication event a33f9b609b50fbceb453 records outcome success.
  - Evidence: `a33f9b609b50fbceb453`
- Confirmed: Authentication event a55b4f1c91b1348a0f1c records outcome success.
  - Evidence: `a55b4f1c91b1348a0f1c`
- Confirmed: Authentication event a6ae0903817573695f09 records outcome success.
  - Evidence: `a6ae0903817573695f09`
- Confirmed: Authentication event a9f7b2ac81c66bda1ed3 records outcome success.
  - Evidence: `a9f7b2ac81c66bda1ed3`
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
- Confirmed: Authentication event f95a47ccf206aedc0264 records outcome success.
  - Evidence: `f95a47ccf206aedc0264`
- Confirmed: Authentication event ffe190ee68fa49888037 records outcome failure.
  - Evidence: `ffe190ee68fa49888037`
- Confirmed: Process event 8e3b9127b110d0908581 identifies the instance in 21cfbf2f84aba973509b as its parent.
  - Evidence: `21cfbf2f84aba973509b, 8e3b9127b110d0908581`

### Assessed (INFERENCE) (10)

*Interpretations and summaries; citation or predicate checks do not verify their free-text meaning.*

- Assessed: Unverified summary: On WS-3250, cmd.exe (PID 500) was started by services.exe under account acct-8592.
  - Evidence: `8e3b9127b110d0908581`
- Assessed: Unverified summary: Execution chain on WS-3250: wininit.exe -> services.exe -> cmd.exe.
  - Evidence: `8e3b9127b110d0908581, 21cfbf2f84aba973509b`
- Assessed: Unverified summary: Account 'acct-8592' has 25 authentication events (12 failed, 13 successful) across hosts OFFICE-01, WS-3250.
  - Evidence: `644fcfd5011068a13cc3, 7ae112de50a7ef35212b, cbe095d06fbe19e71c8c, 7794c2b19501be2cb80b, f2c578af54d2a3cf2d60, 70070eda726d0ffa9b62, +19 more (see Evidence Appendix)`
- Assessed: Unverified summary: Account 'acct-8592' authenticated from more than one source host: OFFICE-01, WS-7003.
  - Evidence: `644fcfd5011068a13cc3, 7ae112de50a7ef35212b, cbe095d06fbe19e71c8c, 7794c2b19501be2cb80b, f2c578af54d2a3cf2d60, 70070eda726d0ffa9b62, +19 more (see Evidence Appendix)`
- Assessed: The 12 failed authentications for 'acct-8592' followed by success are consistent with the account's password having been guessed rather than with ordinary user error. (confidence 0.85)
  - Evidence: `7ae112de50a7ef35212b, cbe095d06fbe19e71c8c, f2c578af54d2a3cf2d60, 880b1242f36a26407c74, ab491e62927ff53ad2e9, ffe190ee68fa49888037, +6 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-005 is consistent with T1110.001 Brute Force: Password Guessing (Credential Access). Repeated failed authentications for a single account from a single source are consistent with systematically guessing that account's password. (A spray against many accounts would be T1110.003 and is not what was observed.) (confidence 0.90)
  - Evidence: `7ae112de50a7ef35212b, cbe095d06fbe19e71c8c, f2c578af54d2a3cf2d60, 880b1242f36a26407c74, ab491e62927ff53ad2e9, ffe190ee68fa49888037, +7 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-007 is consistent with T1569.002 System Services: Service Execution (Execution). A command interpreter was started by the Service Control Manager, which is the defining behaviour of executing a payload as a Windows service. (confidence 0.90)
  - Evidence: `8e3b9127b110d0908581`
- Assessed: Behaviour cited by ATH-005 is consistent with T1078 Valid Accounts (Persistence). A successful authentication followed the failure burst, which is consistent with the account credential now being under adversary control. (confidence 0.60)
  - Evidence: `7ae112de50a7ef35212b, cbe095d06fbe19e71c8c, f2c578af54d2a3cf2d60, 880b1242f36a26407c74, ab491e62927ff53ad2e9, ffe190ee68fa49888037, +7 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-007 is consistent with T1021.002 Remote Services: SMB/Windows Admin Shares (Lateral Movement). Command output was redirected to an administrative share, indicating the service was driven over an authenticated SMB session from another host. (confidence 0.60)
  - Evidence: `8e3b9127b110d0908581`
- Assessed: The case spans 4 ATT&CK tactics (Execution -> Persistence -> Credential Access -> Lateral Movement). Progression across multiple tactics is harder to explain as coincidental than activity confined to one. (confidence 0.80)
  - Evidence: `1f776b2d12b6e1b38138, 4b7981dfd851184e370d, 7ae112de50a7ef35212b, 80fa003ab0d4b9fb50d3, 880b1242f36a26407c74, 8e3b9127b110d0908581, +8 more (see Evidence Appendix)`

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
| `644fcfd5011068a13cc3` | 08:00:00 | OFFICE-01 | acct-8592 | success logon [Interactive (console)] from 10.10.1.5 |
| `7ae112de50a7ef35212b` | 08:00:00 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `21cfbf2f84aba973509b` | 08:00:00 | WS-3250 | acct-8592 | wininit.exe -> services.exe \| services.exe |
| `cbe095d06fbe19e71c8c` | 08:00:20 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `7794c2b19501be2cb80b` | 08:00:29 | OFFICE-01 | acct-8592 | success logon [Interactive (console)] from 10.10.1.5 |
| `f2c578af54d2a3cf2d60` | 08:00:40 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `70070eda726d0ffa9b62` | 08:00:58 | OFFICE-01 | acct-8592 | success logon [Interactive (console)] from 10.10.1.5 |
| `880b1242f36a26407c74` | 08:01:00 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `ab491e62927ff53ad2e9` | 08:01:20 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `3de8d5b15fb19024a732` | 08:01:27 | OFFICE-01 | acct-8592 | success logon [Interactive (console)] from 10.10.1.5 |
| `ffe190ee68fa49888037` | 08:01:40 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `4e51bb11a05d061eaa79` | 08:01:56 | OFFICE-01 | acct-8592 | success logon [Interactive (console)] from 10.10.1.5 |
| `f07d391db002d3c8dc2c` | 08:02:00 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `1f776b2d12b6e1b38138` | 08:02:20 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `a55b4f1c91b1348a0f1c` | 08:02:25 | OFFICE-01 | acct-8592 | success logon [Interactive (console)] from 10.10.1.5 |
| `80fa003ab0d4b9fb50d3` | 08:02:40 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `a9f7b2ac81c66bda1ed3` | 08:02:54 | OFFICE-01 | acct-8592 | success logon [Interactive (console)] from 10.10.1.5 |
| `4b7981dfd851184e370d` | 08:03:00 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `f23f1f0ad8cd6cc0a54a` | 08:03:20 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `a33f9b609b50fbceb453` | 08:03:23 | OFFICE-01 | acct-8592 | success logon [Interactive (console)] from 10.10.1.5 |
| `c239520d9ca451aa0921` | 08:03:40 | WS-3250 | acct-8592 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `7e3cdc7f3dd94475bd36` | 08:03:52 | OFFICE-01 | acct-8592 | success logon [Interactive (console)] from 10.10.1.5 |
| `f95a47ccf206aedc0264` | 08:04:21 | OFFICE-01 | acct-8592 | success logon [Interactive (console)] from 10.10.1.5 |
| `7a605231a8b8245ac918` | 08:04:50 | OFFICE-01 | acct-8592 | success logon [Interactive (console)] from 10.10.1.5 |
| `a6ae0903817573695f09` | 08:05:00 | WS-3250 | acct-8592 | success logon [Network (SMB / share access)] from 10.10.2.8 |
| `9ad04b5d0a58bac4bdd3` | 08:05:19 | OFFICE-01 | acct-8592 | success logon [Interactive (console)] from 10.10.1.5 |
| `8e3b9127b110d0908581` | 08:06:00 | WS-3250 | acct-8592 | services.exe -> cmd.exe \| cmd.exe /Q /c job.cmd 1> \\127.0.0.1\ADMIN$\job.log 2>&1 |
