# Investigation Report: CASE-001

**Generated:** 2026-09-22 19:02:32 UTC  
**Status:** complete  
**Severity:** CRITICAL  |  **Grouping confidence:** medium  
**Hosts:** WS-3115, WS-7019  
**Accounts:** acct-8900  
**Window:** 2026-08-09 08:00:00 -> 08:06:00 UTC (360s)

> This report was produced by an automated investigation over telemetry from: **generated_auth_execution**. It presents evidence-backed findings for analyst review and does not authorise or perform any response action.

## Executive Summary

This report covers CASE-001, correlating 2 detection finding(s) across 2 host(s) (WS-3115, WS-7019) and 1 account(s) (acct-8900) between 08:00:00 and 08:06:00 UTC on 2026-08-09. The evidence is consistent with activity spanning 4 MITRE ATT&CK tactic(s): Execution -> Persistence -> Credential Access -> Lateral Movement. Each mapping is an interpretation of observed behaviour against a public taxonomy, not a determination that an intrusion occurred. 28 statement(s) below are directly established by telemetry, 10 are evidence-supported inferences, and 0 are explicitly unverified hypotheses requiring analyst confirmation. This report does not authorise or perform any response action. All recommendations below require human review before action is taken.

## Attack Timeline

| Time | Rule | Severity | User | Host / Movement | ATT&CK | Events |
| --- | --- | --- | --- | --- | --- | --- |
| 08:00:00 | ATH-005 | CRITICAL | acct-8900 | WS-7019 | T1078, T1110.001 | 6f0d570d130548abd43f (+12) |
| 08:06:00 | ATH-007 | HIGH | acct-8900 | WS-7019 | T1021.002, T1569.002 | 400ac84113afe2e98ed1 |

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

- Confirmed: Authentication event 304935d30830924de162 records outcome success.
  - Evidence: `304935d30830924de162`
- Confirmed: Authentication event 3291a689dee23bd1c30a records outcome success.
  - Evidence: `3291a689dee23bd1c30a`
- Confirmed: Authentication event 3c43b043330d32f62e20 records outcome failure.
  - Evidence: `3c43b043330d32f62e20`
- Confirmed: Authentication event 3e5de22084805790001f records outcome success.
  - Evidence: `3e5de22084805790001f`
- Confirmed: Authentication event 3f6f45afdf53fa398bf7 records outcome failure.
  - Evidence: `3f6f45afdf53fa398bf7`
- Confirmed: Event 400ac84113afe2e98ed1 records process identity sysmon:f7202b401aa705f295e01a705e066ea5.
  - Evidence: `400ac84113afe2e98ed1`
- Confirmed: Authentication event 542170421fecafd9f69d records outcome success.
  - Evidence: `542170421fecafd9f69d`
- Confirmed: Authentication event 56ea6448d193360884ec records outcome failure.
  - Evidence: `56ea6448d193360884ec`
- Confirmed: Authentication event 5b2fa4b61cec0bf277e2 records outcome success.
  - Evidence: `5b2fa4b61cec0bf277e2`
- Confirmed: Authentication event 6c87f310e2729818e66e records outcome success.
  - Evidence: `6c87f310e2729818e66e`
- Confirmed: Authentication event 6cd8de256ca10e280a8b records outcome failure.
  - Evidence: `6cd8de256ca10e280a8b`
- Confirmed: Authentication event 6f0d570d130548abd43f records outcome failure.
  - Evidence: `6f0d570d130548abd43f`
- Confirmed: Authentication event 84e0ade769b4dd9a34e3 records outcome failure.
  - Evidence: `84e0ade769b4dd9a34e3`
- Confirmed: Authentication event 8b416c6ea133de490d41 records outcome success.
  - Evidence: `8b416c6ea133de490d41`
- Confirmed: Authentication event 9ae2d03199d547f7336f records outcome success.
  - Evidence: `9ae2d03199d547f7336f`
- Confirmed: Authentication event 9c330e4fda3a1a87eb61 records outcome failure.
  - Evidence: `9c330e4fda3a1a87eb61`
- Confirmed: Authentication event 9d0a6f410ea4899cb410 records outcome failure.
  - Evidence: `9d0a6f410ea4899cb410`
- Confirmed: Authentication event a309c5b96ca757467916 records outcome failure.
  - Evidence: `a309c5b96ca757467916`
- Confirmed: Event a3f7e528683312f66d29 records process identity sysmon:5fa8de4c29bd6d6abf1092f1c9afe4fa.
  - Evidence: `a3f7e528683312f66d29`
- Confirmed: Authentication event b160110d835e988ba71a records outcome failure.
  - Evidence: `b160110d835e988ba71a`
- Confirmed: Authentication event b38cbb3bc656a422c0a3 records outcome failure.
  - Evidence: `b38cbb3bc656a422c0a3`
- Confirmed: Authentication event b8ce4e4c650352a2d0d0 records outcome success.
  - Evidence: `b8ce4e4c650352a2d0d0`
- Confirmed: Authentication event c1df2b13ccc709792921 records outcome success.
  - Evidence: `c1df2b13ccc709792921`
- Confirmed: Authentication event cdfb1cc9d95760173835 records outcome success.
  - Evidence: `cdfb1cc9d95760173835`
- Confirmed: Authentication event dec9ab3e1252d14bbbe5 records outcome success.
  - Evidence: `dec9ab3e1252d14bbbe5`
- Confirmed: Authentication event e0dc8a65a5e0ee2e31d3 records outcome failure.
  - Evidence: `e0dc8a65a5e0ee2e31d3`
- Confirmed: Authentication event fa506911596b7f548cad records outcome success.
  - Evidence: `fa506911596b7f548cad`
- Confirmed: Process event 400ac84113afe2e98ed1 identifies the instance in a3f7e528683312f66d29 as its parent.
  - Evidence: `a3f7e528683312f66d29, 400ac84113afe2e98ed1`

### Assessed (INFERENCE) (10)

*Interpretations and summaries; citation or predicate checks do not verify their free-text meaning.*

- Assessed: Unverified summary: On WS-7019, cmd.exe (PID 500) was started by services.exe under account acct-8900.
  - Evidence: `400ac84113afe2e98ed1`
- Assessed: Unverified summary: Execution chain on WS-7019: wininit.exe -> services.exe -> cmd.exe.
  - Evidence: `400ac84113afe2e98ed1, a3f7e528683312f66d29`
- Assessed: Unverified summary: Account 'acct-8900' has 25 authentication events (12 failed, 13 successful) across hosts OFFICE-01, WS-7019.
  - Evidence: `c1df2b13ccc709792921, 6f0d570d130548abd43f, 3f6f45afdf53fa398bf7, b8ce4e4c650352a2d0d0, 56ea6448d193360884ec, fa506911596b7f548cad, +19 more (see Evidence Appendix)`
- Assessed: Unverified summary: Account 'acct-8900' authenticated from more than one source host: OFFICE-01, WS-3115.
  - Evidence: `c1df2b13ccc709792921, 6f0d570d130548abd43f, 3f6f45afdf53fa398bf7, b8ce4e4c650352a2d0d0, 56ea6448d193360884ec, fa506911596b7f548cad, +19 more (see Evidence Appendix)`
- Assessed: The 12 failed authentications for 'acct-8900' followed by success are consistent with the account's password having been guessed rather than with ordinary user error. (confidence 0.85)
  - Evidence: `6f0d570d130548abd43f, 3f6f45afdf53fa398bf7, 56ea6448d193360884ec, 9c330e4fda3a1a87eb61, 84e0ade769b4dd9a34e3, 3c43b043330d32f62e20, +6 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-005 is consistent with T1110.001 Brute Force: Password Guessing (Credential Access). Repeated failed authentications for a single account from a single source are consistent with systematically guessing that account's password. (A spray against many accounts would be T1110.003 and is not what was observed.) (confidence 0.90)
  - Evidence: `6f0d570d130548abd43f, 3f6f45afdf53fa398bf7, 56ea6448d193360884ec, 9c330e4fda3a1a87eb61, 84e0ade769b4dd9a34e3, 3c43b043330d32f62e20, +7 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-007 is consistent with T1569.002 System Services: Service Execution (Execution). A command interpreter was started by the Service Control Manager, which is the defining behaviour of executing a payload as a Windows service. (confidence 0.90)
  - Evidence: `400ac84113afe2e98ed1`
- Assessed: Behaviour cited by ATH-005 is consistent with T1078 Valid Accounts (Persistence). A successful authentication followed the failure burst, which is consistent with the account credential now being under adversary control. (confidence 0.60)
  - Evidence: `6f0d570d130548abd43f, 3f6f45afdf53fa398bf7, 56ea6448d193360884ec, 9c330e4fda3a1a87eb61, 84e0ade769b4dd9a34e3, 3c43b043330d32f62e20, +7 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-007 is consistent with T1021.002 Remote Services: SMB/Windows Admin Shares (Lateral Movement). Command output was redirected to an administrative share, indicating the service was driven over an authenticated SMB session from another host. (confidence 0.60)
  - Evidence: `400ac84113afe2e98ed1`
- Assessed: The case spans 4 ATT&CK tactics (Execution -> Persistence -> Credential Access -> Lateral Movement). Progression across multiple tactics is harder to explain as coincidental than activity confined to one. (confidence 0.80)
  - Evidence: `3291a689dee23bd1c30a, 3c43b043330d32f62e20, 3f6f45afdf53fa398bf7, 400ac84113afe2e98ed1, 56ea6448d193360884ec, 6cd8de256ca10e280a8b, +8 more (see Evidence Appendix)`

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
2. **Independently verify account activity on all hosts in scope (WS-3115, WS-7019) rather than relying solely on the correlated case, in case related activity exists that current detections did not flag.**
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
| `c1df2b13ccc709792921` | 08:00:00 | OFFICE-01 | acct-8900 | success logon [Interactive (console)] from 10.10.1.5 |
| `6f0d570d130548abd43f` | 08:00:00 | WS-7019 | acct-8900 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `a3f7e528683312f66d29` | 08:00:00 | WS-7019 | acct-8900 | wininit.exe -> services.exe \| services.exe |
| `3f6f45afdf53fa398bf7` | 08:00:20 | WS-7019 | acct-8900 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `b8ce4e4c650352a2d0d0` | 08:00:29 | OFFICE-01 | acct-8900 | success logon [Interactive (console)] from 10.10.1.5 |
| `56ea6448d193360884ec` | 08:00:40 | WS-7019 | acct-8900 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `fa506911596b7f548cad` | 08:00:58 | OFFICE-01 | acct-8900 | success logon [Interactive (console)] from 10.10.1.5 |
| `9c330e4fda3a1a87eb61` | 08:01:00 | WS-7019 | acct-8900 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `84e0ade769b4dd9a34e3` | 08:01:20 | WS-7019 | acct-8900 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `6c87f310e2729818e66e` | 08:01:27 | OFFICE-01 | acct-8900 | success logon [Interactive (console)] from 10.10.1.5 |
| `3c43b043330d32f62e20` | 08:01:40 | WS-7019 | acct-8900 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `cdfb1cc9d95760173835` | 08:01:56 | OFFICE-01 | acct-8900 | success logon [Interactive (console)] from 10.10.1.5 |
| `b160110d835e988ba71a` | 08:02:00 | WS-7019 | acct-8900 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `9d0a6f410ea4899cb410` | 08:02:20 | WS-7019 | acct-8900 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `3e5de22084805790001f` | 08:02:25 | OFFICE-01 | acct-8900 | success logon [Interactive (console)] from 10.10.1.5 |
| `e0dc8a65a5e0ee2e31d3` | 08:02:40 | WS-7019 | acct-8900 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `9ae2d03199d547f7336f` | 08:02:54 | OFFICE-01 | acct-8900 | success logon [Interactive (console)] from 10.10.1.5 |
| `b38cbb3bc656a422c0a3` | 08:03:00 | WS-7019 | acct-8900 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `6cd8de256ca10e280a8b` | 08:03:20 | WS-7019 | acct-8900 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `542170421fecafd9f69d` | 08:03:23 | OFFICE-01 | acct-8900 | success logon [Interactive (console)] from 10.10.1.5 |
| `a309c5b96ca757467916` | 08:03:40 | WS-7019 | acct-8900 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `8b416c6ea133de490d41` | 08:03:52 | OFFICE-01 | acct-8900 | success logon [Interactive (console)] from 10.10.1.5 |
| `304935d30830924de162` | 08:04:21 | OFFICE-01 | acct-8900 | success logon [Interactive (console)] from 10.10.1.5 |
| `5b2fa4b61cec0bf277e2` | 08:04:50 | OFFICE-01 | acct-8900 | success logon [Interactive (console)] from 10.10.1.5 |
| `3291a689dee23bd1c30a` | 08:05:00 | WS-7019 | acct-8900 | success logon [Network (SMB / share access)] from 10.10.2.8 |
| `dec9ab3e1252d14bbbe5` | 08:05:19 | OFFICE-01 | acct-8900 | success logon [Interactive (console)] from 10.10.1.5 |
| `400ac84113afe2e98ed1` | 08:06:00 | WS-7019 | acct-8900 | services.exe -> cmd.exe \| cmd.exe /Q /c job.cmd 1> \\127.0.0.1\ADMIN$\job.log 2>&1 |
