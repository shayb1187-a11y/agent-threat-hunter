# Investigation Report: CASE-001

**Generated:** 2026-09-22 19:02:31 UTC  
**Status:** complete  
**Severity:** CRITICAL  |  **Grouping confidence:** medium  
**Hosts:** WS-7458, WS-8619  
**Accounts:** acct-1313  
**Window:** 2026-08-09 08:00:00 -> 08:06:00 UTC (360s)

> This report was produced by an automated investigation over telemetry from: **generated_auth_execution**. It presents evidence-backed findings for analyst review and does not authorise or perform any response action.

## Executive Summary

This report covers CASE-001, correlating 2 detection finding(s) across 2 host(s) (WS-7458, WS-8619) and 1 account(s) (acct-1313) between 08:00:00 and 08:06:00 UTC on 2026-08-09. The evidence is consistent with activity spanning 4 MITRE ATT&CK tactic(s): Execution -> Persistence -> Credential Access -> Lateral Movement. Each mapping is an interpretation of observed behaviour against a public taxonomy, not a determination that an intrusion occurred. 30 statement(s) below are directly established by telemetry, 11 are evidence-supported inferences, and 0 are explicitly unverified hypotheses requiring analyst confirmation. This report does not authorise or perform any response action. All recommendations below require human review before action is taken.

## Attack Timeline

| Time | Rule | Severity | User | Host / Movement | ATT&CK | Events |
| --- | --- | --- | --- | --- | --- | --- |
| 08:00:00 | ATH-005 | CRITICAL | acct-1313 | WS-8619 | T1078, T1110.001 | c5e3afb8d54931ae0dca (+12) |
| 08:06:00 | ATH-007 | HIGH | acct-1313 | WS-8619 | T1021.002, T1569.002 | 63c1e83caaba3c08d9ec |

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

- Confirmed: Authentication event 056d1678640c167ae2a0 records outcome failure.
  - Evidence: `056d1678640c167ae2a0`
- Confirmed: Authentication event 05f0d4732452aeca5b6e records outcome failure.
  - Evidence: `05f0d4732452aeca5b6e`
- Confirmed: Authentication event 12ead705cc51aa1e0152 records outcome success.
  - Evidence: `12ead705cc51aa1e0152`
- Confirmed: Authentication event 16e423554c6a68be22ef records outcome success.
  - Evidence: `16e423554c6a68be22ef`
- Confirmed: Authentication event 1c20079dfc4475241c30 records outcome failure.
  - Evidence: `1c20079dfc4475241c30`
- Confirmed: Authentication event 1c31f1fa7e6998f81cc5 records outcome success.
  - Evidence: `1c31f1fa7e6998f81cc5`
- Confirmed: Event 235f16a8a6b79e284641 records process identity sysmon:eefc789597b131528cf33d3527de487e.
  - Evidence: `235f16a8a6b79e284641`
- Confirmed: Authentication event 2962a7270535216dd530 records outcome success.
  - Evidence: `2962a7270535216dd530`
- Confirmed: Authentication event 4745b0cfaf0b6d325caa records outcome success.
  - Evidence: `4745b0cfaf0b6d325caa`
- Confirmed: Event 52aa1553a007e4027c64 records process identity sysmon:de8bc2f8f4f3fabe37118ef27adf7353.
  - Evidence: `52aa1553a007e4027c64`
- Confirmed: Authentication event 566b54da8cbfe8e27fca records outcome failure.
  - Evidence: `566b54da8cbfe8e27fca`
- Confirmed: Authentication event 6031cc8c418b04931235 records outcome success.
  - Evidence: `6031cc8c418b04931235`
- Confirmed: Authentication event 606ca2ec1c34d0517eb6 records outcome failure.
  - Evidence: `606ca2ec1c34d0517eb6`
- Confirmed: Authentication event 61d535cc98b78c19f67f records outcome success.
  - Evidence: `61d535cc98b78c19f67f`
- Confirmed: Event 63c1e83caaba3c08d9ec records process identity sysmon:4bddd7e2926f36c6f0d98fc7ef0a2776.
  - Evidence: `63c1e83caaba3c08d9ec`
- Confirmed: Authentication event 795c611f979c8784040f records outcome failure.
  - Evidence: `795c611f979c8784040f`
- Confirmed: Authentication event 86c65b5776abfdc13ba3 records outcome failure.
  - Evidence: `86c65b5776abfdc13ba3`
- Confirmed: Authentication event a07d3f98ebe51dfe4a3f records outcome failure.
  - Evidence: `a07d3f98ebe51dfe4a3f`
- Confirmed: Authentication event a74b038b46181467aa7e records outcome success.
  - Evidence: `a74b038b46181467aa7e`
- Confirmed: Authentication event adb72b1a80cff4c355f5 records outcome success.
  - Evidence: `adb72b1a80cff4c355f5`
- Confirmed: Authentication event bc1d83addde9d96e96cb records outcome success.
  - Evidence: `bc1d83addde9d96e96cb`
- Confirmed: Authentication event c5cb2b8e404195e08507 records outcome failure.
  - Evidence: `c5cb2b8e404195e08507`
- Confirmed: Authentication event c5e3afb8d54931ae0dca records outcome failure.
  - Evidence: `c5e3afb8d54931ae0dca`
- Confirmed: Authentication event d68297fe57c6df6555a1 records outcome success.
  - Evidence: `d68297fe57c6df6555a1`
- Confirmed: Authentication event d874be7e08b1d016c5f0 records outcome success.
  - Evidence: `d874be7e08b1d016c5f0`
- Confirmed: Authentication event da2f5a9c16bc6df98e73 records outcome failure.
  - Evidence: `da2f5a9c16bc6df98e73`
- Confirmed: Authentication event e01bb06f50ebce41f9f5 records outcome success.
  - Evidence: `e01bb06f50ebce41f9f5`
- Confirmed: Authentication event f31c0028b09094ef945a records outcome failure.
  - Evidence: `f31c0028b09094ef945a`
- Confirmed: Process event 235f16a8a6b79e284641 identifies the instance in 63c1e83caaba3c08d9ec as its parent.
  - Evidence: `63c1e83caaba3c08d9ec, 235f16a8a6b79e284641`
- Confirmed: Process event 63c1e83caaba3c08d9ec identifies the instance in 52aa1553a007e4027c64 as its parent.
  - Evidence: `52aa1553a007e4027c64, 63c1e83caaba3c08d9ec`

### Assessed (INFERENCE) (11)

*Interpretations and summaries; citation or predicate checks do not verify their free-text meaning.*

- Assessed: Unverified summary: On WS-8619, cmd.exe (PID 500) was started by services.exe under account acct-1313.
  - Evidence: `63c1e83caaba3c08d9ec`
- Assessed: Unverified summary: Execution chain on WS-8619: wininit.exe -> services.exe -> cmd.exe.
  - Evidence: `63c1e83caaba3c08d9ec, 52aa1553a007e4027c64`
- Assessed: Unverified summary: cmd.exe (PID 500) on WS-8619 spawned 1 child process(es): sfc.exe.
  - Evidence: `235f16a8a6b79e284641`
- Assessed: Unverified summary: Account 'acct-1313' has 25 authentication events (12 failed, 13 successful) across hosts OFFICE-01, WS-8619.
  - Evidence: `e01bb06f50ebce41f9f5, c5e3afb8d54931ae0dca, da2f5a9c16bc6df98e73, 1c31f1fa7e6998f81cc5, a07d3f98ebe51dfe4a3f, 16e423554c6a68be22ef, +19 more (see Evidence Appendix)`
- Assessed: Unverified summary: Account 'acct-1313' authenticated from more than one source host: OFFICE-01, WS-7458.
  - Evidence: `e01bb06f50ebce41f9f5, c5e3afb8d54931ae0dca, da2f5a9c16bc6df98e73, 1c31f1fa7e6998f81cc5, a07d3f98ebe51dfe4a3f, 16e423554c6a68be22ef, +19 more (see Evidence Appendix)`
- Assessed: The 12 failed authentications for 'acct-1313' followed by success are consistent with the account's password having been guessed rather than with ordinary user error. (confidence 0.85)
  - Evidence: `c5e3afb8d54931ae0dca, da2f5a9c16bc6df98e73, a07d3f98ebe51dfe4a3f, 86c65b5776abfdc13ba3, 566b54da8cbfe8e27fca, 056d1678640c167ae2a0, +6 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-005 is consistent with T1110.001 Brute Force: Password Guessing (Credential Access). Repeated failed authentications for a single account from a single source are consistent with systematically guessing that account's password. (A spray against many accounts would be T1110.003 and is not what was observed.) (confidence 0.90)
  - Evidence: `c5e3afb8d54931ae0dca, da2f5a9c16bc6df98e73, a07d3f98ebe51dfe4a3f, 86c65b5776abfdc13ba3, 566b54da8cbfe8e27fca, 056d1678640c167ae2a0, +7 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-007 is consistent with T1569.002 System Services: Service Execution (Execution). A command interpreter was started by the Service Control Manager, which is the defining behaviour of executing a payload as a Windows service. (confidence 0.90)
  - Evidence: `63c1e83caaba3c08d9ec`
- Assessed: Behaviour cited by ATH-005 is consistent with T1078 Valid Accounts (Persistence). A successful authentication followed the failure burst, which is consistent with the account credential now being under adversary control. (confidence 0.60)
  - Evidence: `c5e3afb8d54931ae0dca, da2f5a9c16bc6df98e73, a07d3f98ebe51dfe4a3f, 86c65b5776abfdc13ba3, 566b54da8cbfe8e27fca, 056d1678640c167ae2a0, +7 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-007 is consistent with T1021.002 Remote Services: SMB/Windows Admin Shares (Lateral Movement). Command output was redirected to an administrative share, indicating the service was driven over an authenticated SMB session from another host. (confidence 0.60)
  - Evidence: `63c1e83caaba3c08d9ec`
- Assessed: The case spans 4 ATT&CK tactics (Execution -> Persistence -> Credential Access -> Lateral Movement). Progression across multiple tactics is harder to explain as coincidental than activity confined to one. (confidence 0.80)
  - Evidence: `056d1678640c167ae2a0, 05f0d4732452aeca5b6e, 1c20079dfc4475241c30, 2962a7270535216dd530, 566b54da8cbfe8e27fca, 606ca2ec1c34d0517eb6, +8 more (see Evidence Appendix)`

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
2. **Independently verify account activity on all hosts in scope (WS-7458, WS-8619) rather than relying solely on the correlated case, in case related activity exists that current detections did not flag.**
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
| `c5e3afb8d54931ae0dca` | 08:00:00 | WS-8619 | acct-1313 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `52aa1553a007e4027c64` | 08:00:00 | WS-8619 | acct-1313 | wininit.exe -> services.exe \| services.exe |
| `e01bb06f50ebce41f9f5` | 08:00:00 | OFFICE-01 | acct-1313 | success logon [Interactive (console)] from 10.10.1.5 |
| `da2f5a9c16bc6df98e73` | 08:00:20 | WS-8619 | acct-1313 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `1c31f1fa7e6998f81cc5` | 08:00:29 | OFFICE-01 | acct-1313 | success logon [Interactive (console)] from 10.10.1.5 |
| `a07d3f98ebe51dfe4a3f` | 08:00:40 | WS-8619 | acct-1313 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `16e423554c6a68be22ef` | 08:00:58 | OFFICE-01 | acct-1313 | success logon [Interactive (console)] from 10.10.1.5 |
| `86c65b5776abfdc13ba3` | 08:01:00 | WS-8619 | acct-1313 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `566b54da8cbfe8e27fca` | 08:01:20 | WS-8619 | acct-1313 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `61d535cc98b78c19f67f` | 08:01:27 | OFFICE-01 | acct-1313 | success logon [Interactive (console)] from 10.10.1.5 |
| `056d1678640c167ae2a0` | 08:01:40 | WS-8619 | acct-1313 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `6031cc8c418b04931235` | 08:01:56 | OFFICE-01 | acct-1313 | success logon [Interactive (console)] from 10.10.1.5 |
| `05f0d4732452aeca5b6e` | 08:02:00 | WS-8619 | acct-1313 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `f31c0028b09094ef945a` | 08:02:20 | WS-8619 | acct-1313 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `d874be7e08b1d016c5f0` | 08:02:25 | OFFICE-01 | acct-1313 | success logon [Interactive (console)] from 10.10.1.5 |
| `1c20079dfc4475241c30` | 08:02:40 | WS-8619 | acct-1313 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `d68297fe57c6df6555a1` | 08:02:54 | OFFICE-01 | acct-1313 | success logon [Interactive (console)] from 10.10.1.5 |
| `606ca2ec1c34d0517eb6` | 08:03:00 | WS-8619 | acct-1313 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `795c611f979c8784040f` | 08:03:20 | WS-8619 | acct-1313 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `bc1d83addde9d96e96cb` | 08:03:23 | OFFICE-01 | acct-1313 | success logon [Interactive (console)] from 10.10.1.5 |
| `c5cb2b8e404195e08507` | 08:03:40 | WS-8619 | acct-1313 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `4745b0cfaf0b6d325caa` | 08:03:52 | OFFICE-01 | acct-1313 | success logon [Interactive (console)] from 10.10.1.5 |
| `12ead705cc51aa1e0152` | 08:04:21 | OFFICE-01 | acct-1313 | success logon [Interactive (console)] from 10.10.1.5 |
| `adb72b1a80cff4c355f5` | 08:04:50 | OFFICE-01 | acct-1313 | success logon [Interactive (console)] from 10.10.1.5 |
| `2962a7270535216dd530` | 08:05:00 | WS-8619 | acct-1313 | success logon [Network (SMB / share access)] from 10.10.2.8 |
| `a74b038b46181467aa7e` | 08:05:19 | OFFICE-01 | acct-1313 | success logon [Interactive (console)] from 10.10.1.5 |
| `63c1e83caaba3c08d9ec` | 08:06:00 | WS-8619 | acct-1313 | services.exe -> cmd.exe \| cmd.exe /Q /c job.cmd 1> \\127.0.0.1\ADMIN$\job.log 2>&1 |
| `235f16a8a6b79e284641` | 08:06:05 | WS-8619 | acct-1313 | cmd.exe -> sfc.exe \| sfc.exe /verifyonly |
