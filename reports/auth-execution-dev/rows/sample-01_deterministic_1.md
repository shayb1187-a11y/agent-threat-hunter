# Investigation Report: CASE-001

**Generated:** 2026-09-22 19:01:56 UTC  
**Status:** complete  
**Severity:** CRITICAL  |  **Grouping confidence:** medium  
**Hosts:** WS-2924, WS-6254  
**Accounts:** acct-7085  
**Window:** 2026-08-01 08:00:00 -> 08:06:00 UTC (360s)

> This report was produced by an automated investigation over telemetry from: **generated_auth_execution**. It presents evidence-backed findings for analyst review and does not authorise or perform any response action.

## Executive Summary

This report covers CASE-001, correlating 2 detection finding(s) across 2 host(s) (WS-2924, WS-6254) and 1 account(s) (acct-7085) between 08:00:00 and 08:06:00 UTC on 2026-08-01. The evidence is consistent with activity spanning 4 MITRE ATT&CK tactic(s): Execution -> Persistence -> Credential Access -> Lateral Movement. Each mapping is an interpretation of observed behaviour against a public taxonomy, not a determination that an intrusion occurred. 30 statement(s) below are directly established by telemetry, 11 are evidence-supported inferences, and 0 are explicitly unverified hypotheses requiring analyst confirmation. This report does not authorise or perform any response action. All recommendations below require human review before action is taken.

## Attack Timeline

| Time | Rule | Severity | User | Host / Movement | ATT&CK | Events |
| --- | --- | --- | --- | --- | --- | --- |
| 08:00:00 | ATH-005 | CRITICAL | acct-7085 | WS-2924 | T1078, T1110.001 | 72d5a08e0d2a8522ca5a (+12) |
| 08:06:00 | ATH-007 | HIGH | acct-7085 | WS-2924 | T1021.002, T1569.002 | 703eeb16d25835efecb7 |

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

- Confirmed: Authentication event 00bb709b987db814f5f7 records outcome failure.
  - Evidence: `00bb709b987db814f5f7`
- Confirmed: Authentication event 044f5c9c5bf34ddb9030 records outcome failure.
  - Evidence: `044f5c9c5bf34ddb9030`
- Confirmed: Authentication event 0970881ea56161a67f86 records outcome success.
  - Evidence: `0970881ea56161a67f86`
- Confirmed: Authentication event 0f504253fd98db142c3c records outcome success.
  - Evidence: `0f504253fd98db142c3c`
- Confirmed: Authentication event 20f4c8a616092dce879f records outcome success.
  - Evidence: `20f4c8a616092dce879f`
- Confirmed: Authentication event 2dbb1b538a03d94bbf88 records outcome failure.
  - Evidence: `2dbb1b538a03d94bbf88`
- Confirmed: Authentication event 3266b536dc39708fc00c records outcome failure.
  - Evidence: `3266b536dc39708fc00c`
- Confirmed: Authentication event 3608f02fef656b43e91e records outcome failure.
  - Evidence: `3608f02fef656b43e91e`
- Confirmed: Authentication event 5003aa10b50984605fdb records outcome success.
  - Evidence: `5003aa10b50984605fdb`
- Confirmed: Authentication event 67d1611c59fa66806fc5 records outcome success.
  - Evidence: `67d1611c59fa66806fc5`
- Confirmed: Authentication event 680a11b09c06415c434a records outcome failure.
  - Evidence: `680a11b09c06415c434a`
- Confirmed: Authentication event 6cab6426bbe2ef08ea74 records outcome failure.
  - Evidence: `6cab6426bbe2ef08ea74`
- Confirmed: Event 703eeb16d25835efecb7 records process identity sysmon:5b6186501e6faefbb89acd575f1415ab.
  - Evidence: `703eeb16d25835efecb7`
- Confirmed: Authentication event 72d5a08e0d2a8522ca5a records outcome failure.
  - Evidence: `72d5a08e0d2a8522ca5a`
- Confirmed: Event 77646b919268d3358b14 records process identity sysmon:a985464622e9b1d8aead361db1929408.
  - Evidence: `77646b919268d3358b14`
- Confirmed: Authentication event 77a081a8abe68e4b98fb records outcome success.
  - Evidence: `77a081a8abe68e4b98fb`
- Confirmed: Authentication event 7b13f31085bbf14dad61 records outcome failure.
  - Evidence: `7b13f31085bbf14dad61`
- Confirmed: Authentication event 8673afefe5f419af246a records outcome success.
  - Evidence: `8673afefe5f419af246a`
- Confirmed: Authentication event 8ef9c0146e5d74005d89 records outcome success.
  - Evidence: `8ef9c0146e5d74005d89`
- Confirmed: Authentication event 96d505a664df60a94a7c records outcome failure.
  - Evidence: `96d505a664df60a94a7c`
- Confirmed: Authentication event 9e17252a5ff4c89350e3 records outcome success.
  - Evidence: `9e17252a5ff4c89350e3`
- Confirmed: Authentication event b555ce4aa91f923b04ff records outcome success.
  - Evidence: `b555ce4aa91f923b04ff`
- Confirmed: Authentication event c786d4eda4108402ebd7 records outcome success.
  - Evidence: `c786d4eda4108402ebd7`
- Confirmed: Event ccec78fe2c3fa29b518b records process identity sysmon:3b438f257d488c7aa682ff0330ba9507.
  - Evidence: `ccec78fe2c3fa29b518b`
- Confirmed: Authentication event ce61a2216c4bafb83a03 records outcome success.
  - Evidence: `ce61a2216c4bafb83a03`
- Confirmed: Authentication event dcedb070ce7492a69e6a records outcome success.
  - Evidence: `dcedb070ce7492a69e6a`
- Confirmed: Authentication event edf4a27fb63329509cc1 records outcome failure.
  - Evidence: `edf4a27fb63329509cc1`
- Confirmed: Authentication event f0ebb167f3e1fca60b93 records outcome failure.
  - Evidence: `f0ebb167f3e1fca60b93`
- Confirmed: Process event 703eeb16d25835efecb7 identifies the instance in 77646b919268d3358b14 as its parent.
  - Evidence: `77646b919268d3358b14, 703eeb16d25835efecb7`
- Confirmed: Process event ccec78fe2c3fa29b518b identifies the instance in 703eeb16d25835efecb7 as its parent.
  - Evidence: `703eeb16d25835efecb7, ccec78fe2c3fa29b518b`

### Assessed (INFERENCE) (11)

*Interpretations and summaries; citation or predicate checks do not verify their free-text meaning.*

- Assessed: Unverified summary: On WS-2924, cmd.exe (PID 500) was started by services.exe under account acct-7085.
  - Evidence: `703eeb16d25835efecb7`
- Assessed: Unverified summary: Execution chain on WS-2924: wininit.exe -> services.exe -> cmd.exe.
  - Evidence: `703eeb16d25835efecb7, 77646b919268d3358b14`
- Assessed: Unverified summary: cmd.exe (PID 500) on WS-2924 spawned 1 child process(es): reg.exe.
  - Evidence: `ccec78fe2c3fa29b518b`
- Assessed: Unverified summary: Account 'acct-7085' has 25 authentication events (12 failed, 13 successful) across hosts OFFICE-01, WS-2924.
  - Evidence: `77a081a8abe68e4b98fb, 72d5a08e0d2a8522ca5a, 2dbb1b538a03d94bbf88, ce61a2216c4bafb83a03, 7b13f31085bbf14dad61, 8ef9c0146e5d74005d89, +19 more (see Evidence Appendix)`
- Assessed: Unverified summary: Account 'acct-7085' authenticated from more than one source host: OFFICE-01, WS-6254.
  - Evidence: `77a081a8abe68e4b98fb, 72d5a08e0d2a8522ca5a, 2dbb1b538a03d94bbf88, ce61a2216c4bafb83a03, 7b13f31085bbf14dad61, 8ef9c0146e5d74005d89, +19 more (see Evidence Appendix)`
- Assessed: The 12 failed authentications for 'acct-7085' followed by success are consistent with the account's password having been guessed rather than with ordinary user error. (confidence 0.85)
  - Evidence: `72d5a08e0d2a8522ca5a, 2dbb1b538a03d94bbf88, 7b13f31085bbf14dad61, 6cab6426bbe2ef08ea74, 00bb709b987db814f5f7, 3266b536dc39708fc00c, +6 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-005 is consistent with T1110.001 Brute Force: Password Guessing (Credential Access). Repeated failed authentications for a single account from a single source are consistent with systematically guessing that account's password. (A spray against many accounts would be T1110.003 and is not what was observed.) (confidence 0.90)
  - Evidence: `72d5a08e0d2a8522ca5a, 2dbb1b538a03d94bbf88, 7b13f31085bbf14dad61, 6cab6426bbe2ef08ea74, 00bb709b987db814f5f7, 3266b536dc39708fc00c, +7 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-007 is consistent with T1569.002 System Services: Service Execution (Execution). A command interpreter was started by the Service Control Manager, which is the defining behaviour of executing a payload as a Windows service. (confidence 0.90)
  - Evidence: `703eeb16d25835efecb7`
- Assessed: Behaviour cited by ATH-005 is consistent with T1078 Valid Accounts (Persistence). A successful authentication followed the failure burst, which is consistent with the account credential now being under adversary control. (confidence 0.60)
  - Evidence: `72d5a08e0d2a8522ca5a, 2dbb1b538a03d94bbf88, 7b13f31085bbf14dad61, 6cab6426bbe2ef08ea74, 00bb709b987db814f5f7, 3266b536dc39708fc00c, +7 more (see Evidence Appendix)`
- Assessed: Behaviour cited by ATH-007 is consistent with T1021.002 Remote Services: SMB/Windows Admin Shares (Lateral Movement). Command output was redirected to an administrative share, indicating the service was driven over an authenticated SMB session from another host. (confidence 0.60)
  - Evidence: `703eeb16d25835efecb7`
- Assessed: The case spans 4 ATT&CK tactics (Execution -> Persistence -> Credential Access -> Lateral Movement). Progression across multiple tactics is harder to explain as coincidental than activity confined to one. (confidence 0.80)
  - Evidence: `00bb709b987db814f5f7, 044f5c9c5bf34ddb9030, 0f504253fd98db142c3c, 2dbb1b538a03d94bbf88, 3266b536dc39708fc00c, 3608f02fef656b43e91e, +8 more (see Evidence Appendix)`

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
2. **Independently verify account activity on all hosts in scope (WS-2924, WS-6254) rather than relying solely on the correlated case, in case related activity exists that current detections did not flag.**
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
| `72d5a08e0d2a8522ca5a` | 08:00:00 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `77646b919268d3358b14` | 08:00:00 | WS-2924 | acct-7085 | wininit.exe -> services.exe \| services.exe |
| `77a081a8abe68e4b98fb` | 08:00:00 | OFFICE-01 | acct-7085 | success logon [Interactive (console)] from 10.10.1.5 |
| `2dbb1b538a03d94bbf88` | 08:00:20 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `ce61a2216c4bafb83a03` | 08:00:29 | OFFICE-01 | acct-7085 | success logon [Interactive (console)] from 10.10.1.5 |
| `7b13f31085bbf14dad61` | 08:00:40 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `8ef9c0146e5d74005d89` | 08:00:58 | OFFICE-01 | acct-7085 | success logon [Interactive (console)] from 10.10.1.5 |
| `6cab6426bbe2ef08ea74` | 08:01:00 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `00bb709b987db814f5f7` | 08:01:20 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `9e17252a5ff4c89350e3` | 08:01:27 | OFFICE-01 | acct-7085 | success logon [Interactive (console)] from 10.10.1.5 |
| `3266b536dc39708fc00c` | 08:01:40 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `0970881ea56161a67f86` | 08:01:56 | OFFICE-01 | acct-7085 | success logon [Interactive (console)] from 10.10.1.5 |
| `edf4a27fb63329509cc1` | 08:02:00 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `680a11b09c06415c434a` | 08:02:20 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `20f4c8a616092dce879f` | 08:02:25 | OFFICE-01 | acct-7085 | success logon [Interactive (console)] from 10.10.1.5 |
| `044f5c9c5bf34ddb9030` | 08:02:40 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `8673afefe5f419af246a` | 08:02:54 | OFFICE-01 | acct-7085 | success logon [Interactive (console)] from 10.10.1.5 |
| `f0ebb167f3e1fca60b93` | 08:03:00 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `96d505a664df60a94a7c` | 08:03:20 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `67d1611c59fa66806fc5` | 08:03:23 | OFFICE-01 | acct-7085 | success logon [Interactive (console)] from 10.10.1.5 |
| `3608f02fef656b43e91e` | 08:03:40 | WS-2924 | acct-7085 | failure logon [Network (SMB / share access)] from 10.10.2.8 reason=bad_password |
| `c786d4eda4108402ebd7` | 08:03:52 | OFFICE-01 | acct-7085 | success logon [Interactive (console)] from 10.10.1.5 |
| `5003aa10b50984605fdb` | 08:04:21 | OFFICE-01 | acct-7085 | success logon [Interactive (console)] from 10.10.1.5 |
| `dcedb070ce7492a69e6a` | 08:04:50 | OFFICE-01 | acct-7085 | success logon [Interactive (console)] from 10.10.1.5 |
| `0f504253fd98db142c3c` | 08:05:00 | WS-2924 | acct-7085 | success logon [Network (SMB / share access)] from 10.10.2.8 |
| `b555ce4aa91f923b04ff` | 08:05:19 | OFFICE-01 | acct-7085 | success logon [Interactive (console)] from 10.10.1.5 |
| `703eeb16d25835efecb7` | 08:06:00 | WS-2924 | acct-7085 | services.exe -> cmd.exe \| cmd.exe /Q /c job.cmd 1> \\127.0.0.1\ADMIN$\job.log 2>&1 |
| `ccec78fe2c3fa29b518b` | 08:06:05 | WS-2924 | acct-7085 | cmd.exe -> reg.exe \| reg.exe save HKLM\SAM C:\ProgramData\sam.hiv /y |
