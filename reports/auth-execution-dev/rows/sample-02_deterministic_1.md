# Investigation Report: CASE-001

**Generated:** 2026-09-22 19:02:53 UTC  
**Status:** complete  
**Severity:** CRITICAL  |  **Grouping confidence:** medium  
**Hosts:** WS-2138, WS-9673  
**Accounts:** acct-2520  
**Window:** 2026-08-01 08:00:00 -> 08:06:00 UTC (360s)

> This report was produced by an automated investigation over telemetry from: **generated_auth_execution**. It presents evidence-backed findings for analyst review and does not authorise or perform any response action.

## Executive Summary

This report covers CASE-001, correlating 2 detection finding(s) across 2 host(s) (WS-2138, WS-9673) and 1 account(s) (acct-2520) between 08:00:00 and 08:06:00 UTC on 2026-08-01. The evidence is consistent with activity spanning 4 MITRE ATT&CK tactic(s): Execution -> Persistence -> Credential Access -> Lateral Movement. Each mapping is an interpretation of observed behaviour against a public taxonomy, not a determination that an intrusion occurred. 30 statement(s) below are directly established by telemetry, 11 are evidence-supported inferences, and 0 are explicitly unverified hypotheses requiring analyst confirmation. This report does not authorise or perform any response action. All recommendations below require human review before action is taken.

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

### Confirmed (FACT) (30)

*Typed observations checked against recorded telemetry.*

- Confirmed: Authentication event 0adbb9ef85b9188c8683 records outcome failure.
  - Evidence: `0adbb9ef85b9188c8683`
- Confirmed: Event 0b092d00f3798939dd00 records process identity sysmon:399d50933db741bad79daec0f397fe8d.
  - Evidence: `0b092d00f3798939dd00`
- Confirmed: Authentication event 0cb61159ea3d69dcc87a records outcome failure.
  - Evidence: `0cb61159ea3d69dcc87a`
- Confirmed: Authentication event 0cc680d6694f1f8615a1 records outcome failure.
  - Evidence: `0cc680d6694f1f8615a1`
- Confirmed: Authentication event 0ce208dd57c057228f55 records outcome success.
  - Evidence: `0ce208dd57c057228f55`
- Confirmed: Authentication event 0d4ac76c0560bdbb704b records outcome success.
  - Evidence: `0d4ac76c0560bdbb704b`
- Confirmed: Authentication event 2108af7a380995a548b5 records outcome failure.
  - Evidence: `2108af7a380995a548b5`
- Confirmed: Authentication event 3bdd60cc3a5a97b84519 records outcome failure.
  - Evidence: `3bdd60cc3a5a97b84519`
- Confirmed: Authentication event 5c0abbbce84e1b2a43fa records outcome success.
  - Evidence: `5c0abbbce84e1b2a43fa`
- Confirmed: Authentication event 67a9f5bfab28871757dd records outcome success.
  - Evidence: `67a9f5bfab28871757dd`
- Confirmed: Authentication event 6e10a5cc29314bc6a964 records outcome failure.
  - Evidence: `6e10a5cc29314bc6a964`
- Confirmed: Authentication event 78274bf69ec1ff508093 records outcome success.
  - Evidence: `78274bf69ec1ff508093`
- Confirmed: Authentication event 7c156d83425329cf030a records outcome success.
  - Evidence: `7c156d83425329cf030a`
- Confirmed: Authentication event 8144033a5e9cd2c19c38 records outcome success.
  - Evidence: `8144033a5e9cd2c19c38`
- Confirmed: Authentication event 8407329aafd15d9c0a9e records outcome failure.
  - Evidence: `8407329aafd15d9c0a9e`
- Confirmed: Event 98c80712635dec2f3738 records process identity sysmon:b06bb26c2e219a238c5b67fc124fd6ea.
  - Evidence: `98c80712635dec2f3738`
- Confirmed: Authentication event 9ad22469dab49a3df6fc records outcome success.
  - Evidence: `9ad22469dab49a3df6fc`
- Confirmed: Authentication event 9b73d640145c27f1eddb records outcome success.
  - Evidence: `9b73d640145c27f1eddb`
- Confirmed: Authentication event a068ff51cd2cb23d2f8d records outcome failure.
  - Evidence: `a068ff51cd2cb23d2f8d`
- Confirmed: Authentication event a3bf61cc981c8d0cdd5d records outcome failure.
  - Evidence: `a3bf61cc981c8d0cdd5d`
- Confirmed: Authentication event bc5bc87bcd4bf9827807 records outcome failure.
  - Evidence: `bc5bc87bcd4bf9827807`
- Confirmed: Event c1aa4d45ddf2102946f7 records process identity sysmon:ffa91f20286f6ae3e86e4b01e0c39444.
  - Evidence: `c1aa4d45ddf2102946f7`
- Confirmed: Authentication event c532eb018e1154acca2e records outcome success.
  - Evidence: `c532eb018e1154acca2e`
- Confirmed: Authentication event d92873fb243f9f0bcb0d records outcome failure.
  - Evidence: `d92873fb243f9f0bcb0d`
- Confirmed: Authentication event dfd20d6fe31907ff2b86 records outcome success.
  - Evidence: `dfd20d6fe31907ff2b86`
- Confirmed: Authentication event e5a3cce5c1c4a821f59d records outcome success.
  - Evidence: `e5a3cce5c1c4a821f59d`
- Confirmed: Authentication event f6497a719ee487d49e5a records outcome failure.
  - Evidence: `f6497a719ee487d49e5a`
- Confirmed: Authentication event fbe91286e9d9acc93b9e records outcome success.
  - Evidence: `fbe91286e9d9acc93b9e`
- Confirmed: Process event 0b092d00f3798939dd00 identifies the instance in c1aa4d45ddf2102946f7 as its parent.
  - Evidence: `c1aa4d45ddf2102946f7, 0b092d00f3798939dd00`
- Confirmed: Process event c1aa4d45ddf2102946f7 identifies the instance in 98c80712635dec2f3738 as its parent.
  - Evidence: `98c80712635dec2f3738, c1aa4d45ddf2102946f7`

### Assessed (INFERENCE) (11)

*Interpretations and summaries; citation or predicate checks do not verify their free-text meaning.*

- Assessed: Unverified summary: On WS-9673, cmd.exe (PID 500) was started by services.exe under account acct-2520.
  - Evidence: `c1aa4d45ddf2102946f7`
- Assessed: Unverified summary: Execution chain on WS-9673: wininit.exe -> services.exe -> cmd.exe.
  - Evidence: `c1aa4d45ddf2102946f7, 98c80712635dec2f3738`
- Assessed: Unverified summary: cmd.exe (PID 500) on WS-9673 spawned 1 child process(es): dism.exe.
  - Evidence: `0b092d00f3798939dd00`
- Assessed: Unverified summary: Account 'acct-2520' has 25 authentication events (12 failed, 13 successful) across hosts OFFICE-01, WS-9673.
  - Evidence: `0ce208dd57c057228f55, 0cb61159ea3d69dcc87a, d92873fb243f9f0bcb0d, 8144033a5e9cd2c19c38, 3bdd60cc3a5a97b84519, 78274bf69ec1ff508093, +19 more (see Evidence Appendix)`
- Assessed: Unverified summary: Account 'acct-2520' authenticated from more than one source host: OFFICE-01, WS-2138.
  - Evidence: `0ce208dd57c057228f55, 0cb61159ea3d69dcc87a, d92873fb243f9f0bcb0d, 8144033a5e9cd2c19c38, 3bdd60cc3a5a97b84519, 78274bf69ec1ff508093, +19 more (see Evidence Appendix)`
- Assessed: The 12 failed authentications for 'acct-2520' followed by success are consistent with the account's password having been guessed rather than with ordinary user error. (confidence 0.85)
  - Evidence: `0cb61159ea3d69dcc87a, d92873fb243f9f0bcb0d, 3bdd60cc3a5a97b84519, a068ff51cd2cb23d2f8d, 2108af7a380995a548b5, 6e10a5cc29314bc6a964, +6 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-005 is consistent with T1110.001 Brute Force: Password Guessing (Credential Access). Repeated failed authentications for a single account from a single source are consistent with systematically guessing that account's password. (A spray against many accounts would be T1110.003 and is not what was observed.) (confidence 0.90)
  - Evidence: `0cb61159ea3d69dcc87a, d92873fb243f9f0bcb0d, 3bdd60cc3a5a97b84519, a068ff51cd2cb23d2f8d, 2108af7a380995a548b5, 6e10a5cc29314bc6a964, +7 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-007 is consistent with T1569.002 System Services: Service Execution (Execution). A command interpreter was started by the Service Control Manager, which is the defining behaviour of executing a payload as a Windows service. (confidence 0.90)
  - Evidence: `c1aa4d45ddf2102946f7`
- Assessed: Behaviour cited by ATH-005 is consistent with T1078 Valid Accounts (Persistence). A successful authentication followed the failure burst, which is consistent with the account credential now being under adversary control. (confidence 0.60)
  - Evidence: `0cb61159ea3d69dcc87a, d92873fb243f9f0bcb0d, 3bdd60cc3a5a97b84519, a068ff51cd2cb23d2f8d, 2108af7a380995a548b5, 6e10a5cc29314bc6a964, +7 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-007 is consistent with T1021.002 Remote Services: SMB/Windows Admin Shares (Lateral Movement). Command output was redirected to an administrative share, indicating the service was driven over an authenticated SMB session from another host. (confidence 0.60)
  - Evidence: `c1aa4d45ddf2102946f7`
- Assessed: The case spans 4 ATT&CK tactics (Execution -> Persistence -> Credential Access -> Lateral Movement). Progression across multiple tactics is harder to explain as coincidental than activity confined to one. (confidence 0.80)
  - Evidence: `0adbb9ef85b9188c8683, 0cb61159ea3d69dcc87a, 0cc680d6694f1f8615a1, 2108af7a380995a548b5, 3bdd60cc3a5a97b84519, 67a9f5bfab28871757dd, +8 more (see Evidence Appendix)`

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
| `0cb61159ea3d69dcc87a` | 08:00:00 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `98c80712635dec2f3738` | 08:00:00 | WS-9673 | acct-2520 | wininit.exe -> services.exe \| services.exe |
| `0ce208dd57c057228f55` | 08:00:00 | OFFICE-01 | acct-2520 | success logon [Interactive (console)] from 10.10.1.5 |
| `d92873fb243f9f0bcb0d` | 08:00:20 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `8144033a5e9cd2c19c38` | 08:00:29 | OFFICE-01 | acct-2520 | success logon [Interactive (console)] from 10.10.1.5 |
| `3bdd60cc3a5a97b84519` | 08:00:40 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `78274bf69ec1ff508093` | 08:00:58 | OFFICE-01 | acct-2520 | success logon [Interactive (console)] from 10.10.1.5 |
| `a068ff51cd2cb23d2f8d` | 08:01:00 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `2108af7a380995a548b5` | 08:01:20 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `c532eb018e1154acca2e` | 08:01:27 | OFFICE-01 | acct-2520 | success logon [Interactive (console)] from 10.10.1.5 |
| `6e10a5cc29314bc6a964` | 08:01:40 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `7c156d83425329cf030a` | 08:01:56 | OFFICE-01 | acct-2520 | success logon [Interactive (console)] from 10.10.1.5 |
| `a3bf61cc981c8d0cdd5d` | 08:02:00 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `f6497a719ee487d49e5a` | 08:02:20 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `0d4ac76c0560bdbb704b` | 08:02:25 | OFFICE-01 | acct-2520 | success logon [Interactive (console)] from 10.10.1.5 |
| `0cc680d6694f1f8615a1` | 08:02:40 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `dfd20d6fe31907ff2b86` | 08:02:54 | OFFICE-01 | acct-2520 | success logon [Interactive (console)] from 10.10.1.5 |
| `8407329aafd15d9c0a9e` | 08:03:00 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `0adbb9ef85b9188c8683` | 08:03:20 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `fbe91286e9d9acc93b9e` | 08:03:23 | OFFICE-01 | acct-2520 | success logon [Interactive (console)] from 10.10.1.5 |
| `bc5bc87bcd4bf9827807` | 08:03:40 | WS-9673 | acct-2520 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `e5a3cce5c1c4a821f59d` | 08:03:52 | OFFICE-01 | acct-2520 | success logon [Interactive (console)] from 10.10.1.5 |
| `9ad22469dab49a3df6fc` | 08:04:21 | OFFICE-01 | acct-2520 | success logon [Interactive (console)] from 10.10.1.5 |
| `5c0abbbce84e1b2a43fa` | 08:04:50 | OFFICE-01 | acct-2520 | success logon [Interactive (console)] from 10.10.1.5 |
| `67a9f5bfab28871757dd` | 08:05:00 | WS-9673 | acct-2520 | success logon [Network (SMB / share access)] from 10.10.2.8 |
| `9b73d640145c27f1eddb` | 08:05:19 | OFFICE-01 | acct-2520 | success logon [Interactive (console)] from 10.10.1.5 |
| `c1aa4d45ddf2102946f7` | 08:06:00 | WS-9673 | acct-2520 | services.exe -> cmd.exe \| cmd.exe /Q /c job.cmd 1> \\127.0.0.1\ADMIN$\job.log 2>&1 |
| `0b092d00f3798939dd00` | 08:06:05 | WS-9673 | acct-2520 | cmd.exe -> dism.exe \| dism.exe /Online /Cleanup-Image /ScanHealth |
