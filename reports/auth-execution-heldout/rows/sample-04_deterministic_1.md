# Investigation Report: CASE-001

**Generated:** 2026-09-22 19:02:31 UTC  
**Status:** complete  
**Severity:** CRITICAL  |  **Grouping confidence:** medium  
**Hosts:** WS-5457, WS-8970  
**Accounts:** acct-9059  
**Window:** 2026-08-09 08:00:00 -> 08:06:00 UTC (360s)

> This report was produced by an automated investigation over telemetry from: **generated_auth_execution**. It presents evidence-backed findings for analyst review and does not authorise or perform any response action.

## Executive Summary

This report covers CASE-001, correlating 2 detection finding(s) across 2 host(s) (WS-5457, WS-8970) and 1 account(s) (acct-9059) between 08:00:00 and 08:06:00 UTC on 2026-08-09. The evidence is consistent with activity spanning 4 MITRE ATT&CK tactic(s): Execution -> Persistence -> Credential Access -> Lateral Movement. Each mapping is an interpretation of observed behaviour against a public taxonomy, not a determination that an intrusion occurred. 30 statement(s) below are directly established by telemetry, 11 are evidence-supported inferences, and 0 are explicitly unverified hypotheses requiring analyst confirmation. This report does not authorise or perform any response action. All recommendations below require human review before action is taken.

## Attack Timeline

| Time | Rule | Severity | User | Host / Movement | ATT&CK | Events |
| --- | --- | --- | --- | --- | --- | --- |
| 08:00:00 | ATH-005 | CRITICAL | acct-9059 | WS-8970 | T1078, T1110.001 | d4a2658973d95e6b6fcc (+12) |
| 08:06:00 | ATH-007 | HIGH | acct-9059 | WS-8970 | T1021.002, T1569.002 | 1ef7515e5a7e4b7ff8f2 |

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

- Confirmed: Authentication event 0066f70d2a460cb4c368 records outcome failure.
  - Evidence: `0066f70d2a460cb4c368`
- Confirmed: Authentication event 03eab2e802d7ed633859 records outcome success.
  - Evidence: `03eab2e802d7ed633859`
- Confirmed: Authentication event 112f7d662d5f4fc66bc7 records outcome success.
  - Evidence: `112f7d662d5f4fc66bc7`
- Confirmed: Authentication event 1c3b7e7344d21cd95602 records outcome failure.
  - Evidence: `1c3b7e7344d21cd95602`
- Confirmed: Authentication event 1d6731fb665b8d587408 records outcome failure.
  - Evidence: `1d6731fb665b8d587408`
- Confirmed: Event 1ef7515e5a7e4b7ff8f2 records process identity sysmon:d267f8abbf3b61f619ee17b14e39853b.
  - Evidence: `1ef7515e5a7e4b7ff8f2`
- Confirmed: Authentication event 34bfbecaae10c13d321e records outcome success.
  - Evidence: `34bfbecaae10c13d321e`
- Confirmed: Authentication event 365d58ce78edc919d023 records outcome success.
  - Evidence: `365d58ce78edc919d023`
- Confirmed: Authentication event 3cbb42be0b7385c241cc records outcome failure.
  - Evidence: `3cbb42be0b7385c241cc`
- Confirmed: Authentication event 3e1f800c10c8a00a22f3 records outcome failure.
  - Evidence: `3e1f800c10c8a00a22f3`
- Confirmed: Authentication event 54d810617eb96787bf4c records outcome failure.
  - Evidence: `54d810617eb96787bf4c`
- Confirmed: Authentication event 5664ff226c6c4a55ccd3 records outcome success.
  - Evidence: `5664ff226c6c4a55ccd3`
- Confirmed: Authentication event 787fcab9e01b5780b13d records outcome success.
  - Evidence: `787fcab9e01b5780b13d`
- Confirmed: Event 791897726164acd6df98 records process identity sysmon:9b18c19b14606d744f8a8accc229e5aa.
  - Evidence: `791897726164acd6df98`
- Confirmed: Authentication event 7d4dddb2e7c6bdc5cd7a records outcome failure.
  - Evidence: `7d4dddb2e7c6bdc5cd7a`
- Confirmed: Authentication event 88f0166c03bdf7e6f9e1 records outcome success.
  - Evidence: `88f0166c03bdf7e6f9e1`
- Confirmed: Authentication event a867703fea3829900d93 records outcome success.
  - Evidence: `a867703fea3829900d93`
- Confirmed: Authentication event b32d84afa941e4e7831a records outcome success.
  - Evidence: `b32d84afa941e4e7831a`
- Confirmed: Authentication event b86189c1454d4520a0c1 records outcome success.
  - Evidence: `b86189c1454d4520a0c1`
- Confirmed: Authentication event bea238084a7223fa45e5 records outcome success.
  - Evidence: `bea238084a7223fa45e5`
- Confirmed: Authentication event d4a2658973d95e6b6fcc records outcome failure.
  - Evidence: `d4a2658973d95e6b6fcc`
- Confirmed: Authentication event e5d6bad15fc506b9b23a records outcome failure.
  - Evidence: `e5d6bad15fc506b9b23a`
- Confirmed: Authentication event ea6f6056ebcbcdb6dbae records outcome failure.
  - Evidence: `ea6f6056ebcbcdb6dbae`
- Confirmed: Authentication event efdeb8421c8697ee6380 records outcome failure.
  - Evidence: `efdeb8421c8697ee6380`
- Confirmed: Authentication event f198f5762f6d1a574edd records outcome failure.
  - Evidence: `f198f5762f6d1a574edd`
- Confirmed: Authentication event f4a7063ce24ea1df27a6 records outcome success.
  - Evidence: `f4a7063ce24ea1df27a6`
- Confirmed: Authentication event f89750a4f8561b16cbb2 records outcome success.
  - Evidence: `f89750a4f8561b16cbb2`
- Confirmed: Event fd3cdf8005f7bbcb5ecb records process identity sysmon:ed1d9b919426a9b3bb06f5d4102fac1d.
  - Evidence: `fd3cdf8005f7bbcb5ecb`
- Confirmed: Process event 1ef7515e5a7e4b7ff8f2 identifies the instance in fd3cdf8005f7bbcb5ecb as its parent.
  - Evidence: `fd3cdf8005f7bbcb5ecb, 1ef7515e5a7e4b7ff8f2`
- Confirmed: Process event 791897726164acd6df98 identifies the instance in 1ef7515e5a7e4b7ff8f2 as its parent.
  - Evidence: `1ef7515e5a7e4b7ff8f2, 791897726164acd6df98`

### Assessed (INFERENCE) (11)

*Interpretations and summaries; citation or predicate checks do not verify their free-text meaning.*

- Assessed: Unverified summary: On WS-8970, cmd.exe (PID 500) was started by services.exe under account acct-9059.
  - Evidence: `1ef7515e5a7e4b7ff8f2`
- Assessed: Unverified summary: Execution chain on WS-8970: wininit.exe -> services.exe -> cmd.exe.
  - Evidence: `1ef7515e5a7e4b7ff8f2, fd3cdf8005f7bbcb5ecb`
- Assessed: Unverified summary: cmd.exe (PID 500) on WS-8970 spawned 1 child process(es): esentutl.exe.
  - Evidence: `791897726164acd6df98`
- Assessed: Unverified summary: Account 'acct-9059' has 25 authentication events (12 failed, 13 successful) across hosts OFFICE-01, WS-8970.
  - Evidence: `03eab2e802d7ed633859, d4a2658973d95e6b6fcc, 54d810617eb96787bf4c, 34bfbecaae10c13d321e, 0066f70d2a460cb4c368, bea238084a7223fa45e5, +19 more (see Evidence Appendix)`
- Assessed: Unverified summary: Account 'acct-9059' authenticated from more than one source host: OFFICE-01, WS-5457.
  - Evidence: `03eab2e802d7ed633859, d4a2658973d95e6b6fcc, 54d810617eb96787bf4c, 34bfbecaae10c13d321e, 0066f70d2a460cb4c368, bea238084a7223fa45e5, +19 more (see Evidence Appendix)`
- Assessed: The 12 failed authentications for 'acct-9059' followed by success are consistent with the account's password having been guessed rather than with ordinary user error. (confidence 0.85)
  - Evidence: `d4a2658973d95e6b6fcc, 54d810617eb96787bf4c, 0066f70d2a460cb4c368, 3e1f800c10c8a00a22f3, 1d6731fb665b8d587408, efdeb8421c8697ee6380, +6 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-005 is consistent with T1110.001 Brute Force: Password Guessing (Credential Access). Repeated failed authentications for a single account from a single source are consistent with systematically guessing that account's password. (A spray against many accounts would be T1110.003 and is not what was observed.) (confidence 0.90)
  - Evidence: `d4a2658973d95e6b6fcc, 54d810617eb96787bf4c, 0066f70d2a460cb4c368, 3e1f800c10c8a00a22f3, 1d6731fb665b8d587408, efdeb8421c8697ee6380, +7 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-007 is consistent with T1569.002 System Services: Service Execution (Execution). A command interpreter was started by the Service Control Manager, which is the defining behaviour of executing a payload as a Windows service. (confidence 0.90)
  - Evidence: `1ef7515e5a7e4b7ff8f2`
- Assessed: Behaviour cited by ATH-005 is consistent with T1078 Valid Accounts (Persistence). A successful authentication followed the failure burst, which is consistent with the account credential now being under adversary control. (confidence 0.60)
  - Evidence: `d4a2658973d95e6b6fcc, 54d810617eb96787bf4c, 0066f70d2a460cb4c368, 3e1f800c10c8a00a22f3, 1d6731fb665b8d587408, efdeb8421c8697ee6380, +7 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-007 is consistent with T1021.002 Remote Services: SMB/Windows Admin Shares (Lateral Movement). Command output was redirected to an administrative share, indicating the service was driven over an authenticated SMB session from another host. (confidence 0.60)
  - Evidence: `1ef7515e5a7e4b7ff8f2`
- Assessed: The case spans 4 ATT&CK tactics (Execution -> Persistence -> Credential Access -> Lateral Movement). Progression across multiple tactics is harder to explain as coincidental than activity confined to one. (confidence 0.80)
  - Evidence: `0066f70d2a460cb4c368, 1c3b7e7344d21cd95602, 1d6731fb665b8d587408, 1ef7515e5a7e4b7ff8f2, 3cbb42be0b7385c241cc, 3e1f800c10c8a00a22f3, +8 more (see Evidence Appendix)`

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
2. **Independently verify account activity on all hosts in scope (WS-5457, WS-8970) rather than relying solely on the correlated case, in case related activity exists that current detections did not flag.**
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
| `d4a2658973d95e6b6fcc` | 08:00:00 | WS-8970 | acct-9059 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `fd3cdf8005f7bbcb5ecb` | 08:00:00 | WS-8970 | acct-9059 | wininit.exe -> services.exe \| services.exe |
| `03eab2e802d7ed633859` | 08:00:00 | OFFICE-01 | acct-9059 | success logon [Interactive (console)] from 10.10.1.5 |
| `54d810617eb96787bf4c` | 08:00:20 | WS-8970 | acct-9059 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `34bfbecaae10c13d321e` | 08:00:29 | OFFICE-01 | acct-9059 | success logon [Interactive (console)] from 10.10.1.5 |
| `0066f70d2a460cb4c368` | 08:00:40 | WS-8970 | acct-9059 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `bea238084a7223fa45e5` | 08:00:58 | OFFICE-01 | acct-9059 | success logon [Interactive (console)] from 10.10.1.5 |
| `3e1f800c10c8a00a22f3` | 08:01:00 | WS-8970 | acct-9059 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `1d6731fb665b8d587408` | 08:01:20 | WS-8970 | acct-9059 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `5664ff226c6c4a55ccd3` | 08:01:27 | OFFICE-01 | acct-9059 | success logon [Interactive (console)] from 10.10.1.5 |
| `efdeb8421c8697ee6380` | 08:01:40 | WS-8970 | acct-9059 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `b86189c1454d4520a0c1` | 08:01:56 | OFFICE-01 | acct-9059 | success logon [Interactive (console)] from 10.10.1.5 |
| `ea6f6056ebcbcdb6dbae` | 08:02:00 | WS-8970 | acct-9059 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `e5d6bad15fc506b9b23a` | 08:02:20 | WS-8970 | acct-9059 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `b32d84afa941e4e7831a` | 08:02:25 | OFFICE-01 | acct-9059 | success logon [Interactive (console)] from 10.10.1.5 |
| `1c3b7e7344d21cd95602` | 08:02:40 | WS-8970 | acct-9059 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `365d58ce78edc919d023` | 08:02:54 | OFFICE-01 | acct-9059 | success logon [Interactive (console)] from 10.10.1.5 |
| `3cbb42be0b7385c241cc` | 08:03:00 | WS-8970 | acct-9059 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `f198f5762f6d1a574edd` | 08:03:20 | WS-8970 | acct-9059 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `a867703fea3829900d93` | 08:03:23 | OFFICE-01 | acct-9059 | success logon [Interactive (console)] from 10.10.1.5 |
| `7d4dddb2e7c6bdc5cd7a` | 08:03:40 | WS-8970 | acct-9059 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `787fcab9e01b5780b13d` | 08:03:52 | OFFICE-01 | acct-9059 | success logon [Interactive (console)] from 10.10.1.5 |
| `f4a7063ce24ea1df27a6` | 08:04:21 | OFFICE-01 | acct-9059 | success logon [Interactive (console)] from 10.10.1.5 |
| `f89750a4f8561b16cbb2` | 08:04:50 | OFFICE-01 | acct-9059 | success logon [Interactive (console)] from 10.10.1.5 |
| `88f0166c03bdf7e6f9e1` | 08:05:00 | WS-8970 | acct-9059 | success logon [Network (SMB / share access)] from 10.10.2.8 |
| `112f7d662d5f4fc66bc7` | 08:05:19 | OFFICE-01 | acct-9059 | success logon [Interactive (console)] from 10.10.1.5 |
| `1ef7515e5a7e4b7ff8f2` | 08:06:00 | WS-8970 | acct-9059 | services.exe -> cmd.exe \| cmd.exe /Q /c job.cmd 1> \\127.0.0.1\ADMIN$\job.log 2>&1 |
| `791897726164acd6df98` | 08:06:05 | WS-8970 | acct-9059 | cmd.exe -> esentutl.exe \| esentutl.exe /y C:\Windows\NTDS\ntds.dit /d C:\ProgramData\cache.db /o |
