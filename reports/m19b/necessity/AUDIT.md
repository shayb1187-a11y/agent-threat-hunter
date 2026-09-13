# M19b T4: cross-specialist necessity audit

Generated 2026-09-13T22:33:19.915184+00:00 at `41c0d97`. Audit digest `b57c8149c585fd0a73ae14dbe76001bde514af091579492d207b2a0d27cab3ee`.

Every claim in this file is MEASURED unless labelled otherwise: each row was produced by loading the corpus through the pipeline's own adapters, running `run_hunt` / `assess_findings` / `correlate` exactly as `scripts/m19_ablation.py` does, and then running arm A's deterministic investigation over every case. No rule, threshold or fixture was changed, and no model was called.

## The test, restated

A case qualifies only if (1) two or more *domain* specialists (endpoint / identity / network / control_plane -- the ATT&CK mapper does not count) have materially relevant evidence, (2) removing either domain removes a stage rather than a duplicate, and (3) cross-domain synthesis could change the verdict, the priority or the next action. `docs/m19b-plan.md` fixed this before any case was looked at.

## Summary by corpus

| corpus | provenance | cases | qualifying | cases offering the planner >=2 domain specialists at step 0 | domains present | load status |
| --- | --- | --- | --- | --- | --- | --- |
| `attack_data_aws` | real labelled multi-domain | 2 | 0 | 0 | control_plane | loaded |
| `comiset` | real labelled multi-domain | 2 | 0 | 0 | endpoint | loaded |
| `comiset_m17_freeze` | real labelled multi-domain | 1 | 0 | 0 | endpoint | loaded |
| `flaws_cloud` | real, unlabelled | 281 | 0 | 0 | control_plane, identity | loaded |
| `k8s_ci` | real benign, no attack present | 0 | 0 | 0 | -- | loaded |
| `k8ntext` | realistic emulation | 0 | 0 | 0 | -- | loaded |
| `k8s_ingress` | real benign, no attack present | 0 | 0 | 0 | -- | loaded |
| `fixture:cloudtrail` | synthetic | 2 | 0 | 0 | control_plane, identity | loaded |
| `fixture:k8s_audit` | synthetic | 1 | 0 | 0 | control_plane | loaded |
| `fixture:defender_export` | synthetic | 1 | 0 | 1 | endpoint, network | loaded |
| `fixture:real_shaped/dedale` | real-shaped fixture | 0 | 0 | 0 | -- | loaded |
| `fixture:real_shaped/k8s_ci` | real-shaped fixture | 0 | 0 | 0 | -- | loaded |
| `fixture:real_shaped/cloudtrail_shaped` | real-shaped fixture | 0 | 0 | 0 | -- | loaded |
| `dedale:D02` | realistic emulation | 0 | 0 | 0 | -- | loaded |
| `dedale:D03` | realistic emulation | 0 | 0 | 0 | -- | loaded |
| `dedale:D07` | realistic emulation | 0 | 0 | 0 | -- | loaded |
| `dedale:D15` | realistic emulation | 0 | 0 | 0 | -- | loaded |
| `dedale:D18` | realistic emulation | 0 | 0 | 0 | -- | loaded |
| `synthetic:INC-001` | synthetic | 1 | 1 | 1 | endpoint, identity, network | loaded |
| `synthetic:INC-002` | synthetic | 1 | 0 | 0 | identity | loaded |
| `synthetic:INC-005` | synthetic | 1 | 0 | 0 | control_plane | loaded |
| `synthetic:INC-004` | synthetic | 1 | 0 | 0 | endpoint | loaded |
| `synthetic:INC-003` | synthetic | 0 | 0 | 0 | -- | loaded |

## Telemetry each corpus carries at all

| corpus | process rows | network rows | logon rows | control rows | findings | telemetry channels the corpus has at all |
| --- | --- | --- | --- | --- | --- | --- |
| `attack_data_aws` | 0 | 0 | 2 | 2347 | 33 | auth_source_attribution, authentication, cloud_control_plane, cloud_management_activity |
| `comiset` | 15095 | 589476 | 6063 | 0 | 5 | auth_source_attribution, authentication, network_flow, process_command_line, process_execution, process_lineage |
| `comiset_m17_freeze` | 15095 | 589477 | 6063 | 0 | 5 | auth_source_attribution, authentication, network_flow, process_command_line, process_execution, process_lineage |
| `flaws_cloud` | 0 | 0 | 79424 | 1857154 | 1476 | auth_source_attribution, authentication, cloud_control_plane, cloud_management_activity |
| `k8s_ci` | 0 | 0 | 0 | 7951 | 0 | container_audit |
| `k8ntext` | 0 | 0 | 0 | 31 | 0 | container_audit |
| `k8s_ingress` | 0 | 0 | 0 | 234 | 0 | container_audit |
| `fixture:cloudtrail` | 0 | 0 | 15 | 6 | 2 | auth_source_attribution, authentication, cloud_control_plane, cloud_management_activity |
| `fixture:k8s_audit` | 0 | 0 | 0 | 4 | 2 | container_audit |
| `fixture:defender_export` | 3 | 3 | 1 | 0 | 4 | auth_source_attribution, authentication, network_flow, network_url, process_command_line, process_execution, process_lineage |
| `fixture:real_shaped/dedale` | 19 | 0 | 6 | 0 | 0 | authentication, process_command_line, process_execution, process_lineage |
| `fixture:real_shaped/k8s_ci` | 0 | 0 | 0 | 9 | 0 | container_audit |
| `fixture:real_shaped/cloudtrail_shaped` | 0 | 0 | 19 | 49 | 1 | auth_source_attribution, authentication, cloud_control_plane, cloud_management_activity |
| `dedale:D02` | 46510 | 0 | 34736 | 0 | 0 | auth_source_attribution, authentication, process_command_line, process_execution, process_lineage |
| `dedale:D03` | 43994 | 0 | 14285 | 0 | 0 | auth_source_attribution, authentication, process_command_line, process_execution, process_lineage |
| `dedale:D07` | 1449 | 0 | 142 | 0 | 0 | auth_source_attribution, authentication, process_command_line, process_execution, process_lineage |
| `dedale:D15` | 44876 | 0 | 4400 | 0 | 0 | auth_source_attribution, authentication, process_command_line, process_execution, process_lineage |
| `dedale:D18` | 44363 | 2 | 4528 | 0 | 0 | auth_source_attribution, authentication, network_flow, network_inbound, process_command_line, process_execution, process_lineage |
| `synthetic:INC-001` | 456 | 389 | 267 | 0 | 13 | auth_source_attribution, authentication, network_flow, network_url, process_command_line, process_execution, process_lineage |
| `synthetic:INC-002` | 0 | 0 | 15 | 0 | 1 | auth_source_attribution, authentication, cloud_control_plane |
| `synthetic:INC-005` | 0 | 0 | 0 | 4 | 2 | container_audit |
| `synthetic:INC-004` | 454 | 381 | 252 | 0 | 4 | auth_source_attribution, authentication, network_flow, network_url, process_command_line, process_execution, process_lineage |
| `synthetic:INC-003` | 448 | 381 | 252 | 0 | 2 | auth_source_attribution, authentication, network_flow, network_url, process_command_line, process_execution, process_lineage |

## Every case

### `attack_data_aws`

*Provenance:* real labelled multi-domain. *Source:* `<local-checkout>\agentic-threat-hunter\data\external\attack_data_aws\raw`.

Splunk attack_data: five single-technique CloudTrail captures. Each capture is one ATT&CK technique executed against a real AWS account, so the label is real and the attack is emulated. CloudTrail only: no process, no network flow. Loaded in 0.1s.

*Ground truth:* {"labelled": true, "kind": "capture file name carries the ATT&CK technique", "domains_of_labelled_evidence": ["control_plane"], "note": "Each capture is one technique. Every row the adapter keeps is a CloudTrail management or authentication event, so the whole labelled chain lives in one or two channels of one table.", "captures": ["T1526__aws_security_scanner__aws_security_scanner.json", "T1580__aws_iam_accessdenied_discovery_events__aws_iam_accessdenied_discovery_events.json"], "labelled_technique": "", "stage_domains": {"the whole capture": "control_plane"}}

| case | rules | domains with material evidence | independent evidence sources | eligible at step 0 | domain specialists at step 0 | specialists_eligible (whole run) | qualifies | why |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `CASE-001` | AWS-003, AWS-004 | control_plane | 1 | control_plane | 1 | 2 | no | one domain only (control_plane): every finding rests on cloud_management_activity -- there is no second domain to synthesise with |
| `CASE-002` | AWS-004 | control_plane | 1 | control_plane | 1 | 2 | no | one domain only (control_plane): every finding rests on cloud_management_activity -- there is no second domain to synthesise with |

### `comiset`

*Provenance:* real labelled multi-domain. *Source:* `<local-checkout>\ath-m19b-audit\reports\m18b\canonical`.

COMISET, read from the M18b canonical freeze -- the same bytes M19 investigated. Windows endpoint + network + logon telemetry from a real enterprise environment. Loaded in 1.5s.

*Ground truth:* {"labelled": false, "note": "COMISET ships no attack labels usable here; M17 recorded it as an unlabelled real corpus. Any 'chain' is the correlator's, not ground truth's."}

| case | rules | domains with material evidence | independent evidence sources | eligible at step 0 | domain specialists at step 0 | specialists_eligible (whole run) | qualifies | why |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `CASE-001` | ATH-002 | endpoint | 1 | endpoint | 1 | 2 | no | one domain only (endpoint): every finding rests on process_command_line, process_execution, process_lineage -- there is no second domain to synthesise with |
| `CASE-002` | ATH-012 | endpoint | 1 | endpoint | 1 | 2 | no | one domain only (endpoint): every finding rests on process_command_line, process_execution -- there is no second domain to synthesise with |

### `comiset_m17_freeze`

*Provenance:* real labelled multi-domain. *Source:* `<local-checkout>\ath-m19b-audit\reports\m17\canonical`.

The M17 freeze of the same corpus, audited to show whether the M18b widening changed which specialists a case reaches. Loaded in 1.6s.

*Ground truth:* {"labelled": false, "note": "COMISET ships no attack labels usable here; M17 recorded it as an unlabelled real corpus. Any 'chain' is the correlator's, not ground truth's."}

| case | rules | domains with material evidence | independent evidence sources | eligible at step 0 | domain specialists at step 0 | specialists_eligible (whole run) | qualifies | why |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `CASE-001` | ATH-012 | endpoint | 1 | endpoint | 1 | 2 | no | one domain only (endpoint): every finding rests on process_command_line, process_execution -- there is no second domain to synthesise with |

### `flaws_cloud`

*Provenance:* real, unlabelled (no attack ground truth). *Source:* `<local-checkout>\agentic-threat-hunter\data\external\flaws_cloud\raw`.

flaws.cloud: 1.9M real CloudTrail events from a deliberately vulnerable AWS account played with by the public for three years. Real attacker behaviour, and no labels at all -- the narrative on the site names no event ids. Loaded in 205.9s.

*Ground truth:* {"labelled": false, "note": "No labels. The published narrative describes levels of a CTF, not event ids, so no stage of any case can be confirmed."}

281 cases; the per-case table is in `AUDIT.json`. Distribution:


```
domains with material evidence:
  control_plane                              280 cases
  identity                                     1 cases
domain specialists eligible at step 0:
                                         1   281 cases
specialists_eligible over the whole run (arm A's number):
                                         2   281 cases
```

Representative / qualifying cases:

| case | rules | domains with material evidence | independent evidence sources | eligible at step 0 | domain specialists at step 0 | specialists_eligible (whole run) | qualifies | why |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `CASE-001` | AWS-004 | control_plane | 1 | control_plane | 1 | 2 | no | one domain only (control_plane): every finding rests on cloud_management_activity -- there is no second domain to synthesise with |
| `CASE-002` | AWS-004 | control_plane | 1 | control_plane | 1 | 2 | no | one domain only (control_plane): every finding rests on cloud_management_activity -- there is no second domain to synthesise with |
| `CASE-003` | AWS-004 | control_plane | 1 | control_plane | 1 | 2 | no | one domain only (control_plane): every finding rests on cloud_management_activity -- there is no second domain to synthesise with |

### `k8s_ci`

*Provenance:* real benign, no attack present. *Source:* `<local-checkout>\agentic-threat-hunter\data\external\k8s_ci\raw`.

Real kube-apiserver audit log from a CI cluster. Benign only. Loaded in 33.6s.

No case was raised on this corpus.

### `k8ntext`

*Provenance:* realistic emulation (labelled testbed attack). *Source:* `<local-checkout>\agentic-threat-hunter\data\external\k8ntext\raw`.

k8ntext: a real kubeadm cluster driven by a human administrator. Context ids, no attack labels; benign by construction. Loaded in 2.2s.

No case was raised on this corpus.

### `k8s_ingress`

*Provenance:* real benign, no attack present. *Source:* `<local-checkout>\agentic-threat-hunter\data\external\k8s_ingress\raw`.

A second real kube-apiserver audit log. Benign only. Loaded in 2.7s.

No case was raised on this corpus.

### `fixture:cloudtrail`

*Provenance:* synthetic (generated by this repository). *Source:* `<local-checkout>\ath-m19b-audit\tests\fixtures\cloudtrail`.

INC-002's telemetry: a hand-written CloudTrail fixture. Loaded in 0.1s.

*Ground truth:* {"labelled": false, "note": "no attack ground truth for this corpus"}

| case | rules | domains with material evidence | independent evidence sources | eligible at step 0 | domain specialists at step 0 | specialists_eligible (whole run) | qualifies | why |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `CASE-001` | ATH-005 | identity | 1 | identity | 1 | 2 | no | one domain only (identity): every finding rests on auth_source_attribution, authentication -- there is no second domain to synthesise with |
| `CASE-002` | AWS-002 | control_plane | 1 | control_plane | 1 | 2 | no | one domain only (control_plane): every finding rests on cloud_management_activity -- there is no second domain to synthesise with |

### `fixture:k8s_audit`

*Provenance:* synthetic (generated by this repository). *Source:* `<local-checkout>\ath-m19b-audit\tests\fixtures\k8s_audit`.

INC-005's telemetry: a hand-written Kubernetes audit fixture. Loaded in 0.1s.

*Ground truth:* {"labelled": false, "note": "no attack ground truth for this corpus"}

| case | rules | domains with material evidence | independent evidence sources | eligible at step 0 | domain specialists at step 0 | specialists_eligible (whole run) | qualifies | why |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `CASE-001` | K8S-001, K8S-002 | control_plane | 1 | control_plane | 1 | 2 | no | one domain only (control_plane): every finding rests on container_audit -- there is no second domain to synthesise with |

### `fixture:defender_export`

*Provenance:* synthetic (generated by this repository). *Source:* `<local-checkout>\ath-m19b-audit\tests\fixtures\defender_export`.

A hand-written Microsoft Defender advanced-hunting export: the only fixture in the repository carrying process, network and logon rows at once. Loaded in 0.1s.

*Ground truth:* {"labelled": false, "note": "no attack ground truth for this corpus"}

| case | rules | domains with material evidence | independent evidence sources | eligible at step 0 | domain specialists at step 0 | specialists_eligible (whole run) | qualifies | why |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `CASE-001` | ATH-001, ATH-002, ATH-003, ATH-009 | endpoint, network | 2 | endpoint, network | 2 | 3 | no | redundant: only endpoint carries a finding no other domain also reads, so removing the other domain(s) removes a second view of one stage, not a stage |

### `fixture:real_shaped/dedale`

*Provenance:* real-shaped fixture (hand-cut from real data, committed). *Source:* `<local-checkout>\ath-m19b-audit\tests\fixtures\real_shaped\dedale`.

A committed slice of DEDALE Winlogbeat NDJSON (CLIENT2, 2024-12-25 boot hour). Real bytes, benign hour. Loaded in 0.1s.

No case was raised on this corpus.

### `fixture:real_shaped/k8s_ci`

*Provenance:* real-shaped fixture (hand-cut from real data, committed). *Source:* `<local-checkout>\ath-m19b-audit\tests\fixtures\real_shaped\k8s_ci`.

A committed slice of the real CI kube-apiserver audit log. Loaded in 0.1s.

No case was raised on this corpus.

### `fixture:real_shaped/cloudtrail_shaped`

*Provenance:* real-shaped fixture (hand-cut from real data, committed). *Source:* `<local-checkout>\ath-m19b-audit\tests\fixtures\real_shaped\cloudtrail_shaped`.

A committed tar slice of real flaws.cloud CloudTrail records. Loaded in 0.1s.

No case was raised on this corpus.

### `dedale:D02`

*Provenance:* realistic emulation (labelled testbed attack). *Source:* `<local-checkout>\agentic-threat-hunter\data\external\dedale\winlogbeat\D02`.

DEDALE 2024-12-24. Before the APT begins: no labelled events. Loaded in 19.2s.

No case was raised on this corpus.

### `dedale:D03`

*Provenance:* realistic emulation (labelled testbed attack). *Source:* `<local-checkout>\agentic-threat-hunter\data\external\dedale\winlogbeat\D03`.

DEDALE 2024-12-25. Before the APT begins: no labelled events. Loaded in 14.0s.

No case was raised on this corpus.

### `dedale:D07`

*Provenance:* realistic emulation (labelled testbed attack). *Source:* `<local-checkout>\agentic-threat-hunter\data\external\dedale\winlogbeat\D07`.

DEDALE 2024-12-29. Before the APT begins: no labelled events. Loaded in 0.5s.

No case was raised on this corpus.

### `dedale:D15`

*Provenance:* realistic emulation (labelled testbed attack). *Source:* `<local-checkout>\agentic-threat-hunter\data\external\dedale\winlogbeat\D15`.

DEDALE 2025-01-06: day one of the labelled APT. 434 class-1 events on CLIENT2 across Sysmon and PowerShell channels. Loaded in 11.1s.

No case was raised on this corpus.

### `dedale:D18`

*Provenance:* realistic emulation (labelled testbed attack). *Source:* `<local-checkout>\agentic-threat-hunter\data\external\dedale\winlogbeat\D18`.

DEDALE 2025-01-09: a labelled APT day on CLIENT1 (195 class-1 Sysmon events), i.e. after lateral movement. Loaded in 11.4s.

No case was raised on this corpus.

### `synthetic:INC-001`

*Provenance:* synthetic (generated by this repository). *Source:* `ath.evaluation.suite`.

Macro-enabled attachment opened from Outlook, hidden encoded PowerShell, C2 beaconing, LSASS access, discovery, credential reuse to a file server, and archive staging.

*Ground truth:* {"labelled": true, "incident_id": "INC-001", "name": "Windows macro-to-collection intrusion", "description": "Macro-enabled attachment opened from Outlook, hidden encoded PowerShell, C2 beaconing, LSASS access, discovery, credential reuse to a file server, and archive staging.", "malicious_events": 31, "expected_techniques": ["T1003.001", "T1021.002", "T1027.010", "T1033", "T1059.001", "T1071.001", "T1078", "T1105", "T1110.001", "T1204.002", "T1560.001", "T1569.002"], "must_conclude": ["WINWORD.EXE", "185.220.101.47", "svc_backup", "guessed"], "stages": [{"stage": "1-initial-access", "note": "macro-enabled attachment opened from Outlook", "evidence_by_domain": {"endpoint": 1}}, {"stage": "2-execution", "note": "Office application spawning hidden encoded PowerShell", "evidence_by_domain": {"endpoint": 1}}, {"stage": "3-payload-download", "note": "PowerShell retrieving remote script over cleartext HTTP", "evidence_by_domain": {"network": 1}}, {"stage": "4-command-and-control", "note": "regular-interval outbound connections to a fixed remote host", "evidence_by_domain": {"network": 6}}, {"stage": "5-discovery", "note": "account and domain enumeration from the PowerShell session", "evidence_by_domain": {"endpoint": 3}}, {"stage": "6-credential-access", "note": "LSASS process memory dumped via signed Microsoft DLL", "evidence_by_domain": {"endpoint": 1}}, {"stage": "7-brute-force", "note": "repeated failed network logons for one account from one source", "evidence_by_domain": {"identity": 15}}, {"stage": "8-lateral-movement", "note": "command shell spawned by the service control manager, output redirected to an admin share", "evidence_by_domain": {"endpoint": 1}}, {"stage": "9-collection", "note": "bulk archive of a finance file share into a temp directory", "evidence_by_domain": {"endpoint": 1}}, {"stage": "10-exfiltration", "note": "server-side process contacting the same external host as PC01", "evidence_by_domain": {"network": 1}}]}

| case | rules | domains with material evidence | independent evidence sources | eligible at step 0 | domain specialists at step 0 | specialists_eligible (whole run) | qualifies | why |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `CASE-001` | ATH-001, ATH-002, ATH-003, ATH-004, ATH-005, ATH-006, ATH-007, ATH-008, ATH-009, ATH-010 | endpoint, identity, network | 3 | endpoint, identity, network | 3 | 4 | YES | Synthesis across endpoint (what executed on the host and what started it), identity (whose credentials were used and from where), network (who the host talked to and whether the timing looks automated) can change the verdict: each domain's finding is explicable on its own, and the other domain's rows are what decide whether that explanation survives. The case carries 8 endpoint row(s), 15 identity row(s), 8 network row(s), spanning the Execution, Persistence, Stealth, Credential Access, Discovery, Lateral Movement, Collection, Command and Control tactic(s); a verdict reached from one domain alone cannot exclude the benign reading the other domain's rows rule out. |

### `synthetic:INC-002`

*Provenance:* synthetic (generated by this repository). *Source:* `ath.evaluation.suite`.

Twelve failed AWS console logins for one IAM user from a single external address, followed by a successful login and role assumption.

*Ground truth:* {"labelled": true, "incident_id": "INC-002", "name": "Cloud credential stuffing (AWS CloudTrail)", "description": "Twelve failed AWS console logins for one IAM user from a single external address, followed by a successful login and role assumption.", "malicious_events": 14, "expected_techniques": ["T1078", "T1110.001"], "must_conclude": ["dev_alice", "203.0.113.42"], "stages": []}

| case | rules | domains with material evidence | independent evidence sources | eligible at step 0 | domain specialists at step 0 | specialists_eligible (whole run) | qualifies | why |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `CASE-001` | ATH-005 | identity | 1 | identity | 1 | 2 | no | one domain only (identity): every finding rests on auth_source_attribution, authentication -- there is no second domain to synthesise with |

### `synthetic:INC-005`

*Provenance:* synthetic (generated by this repository). *Source:* `ath.evaluation.suite`.

A CI deployer service account grants itself-adjacent cluster-admin to a second service account via a ClusterRoleBinding, which then execs into a production pod shortly after.

*Ground truth:* {"labelled": true, "incident_id": "INC-005", "name": "Kubernetes privilege escalation (RBAC grant then pod exec)", "description": "A CI deployer service account grants itself-adjacent cluster-admin to a second service account via a ClusterRoleBinding, which then execs into a production pod shortly after.", "malicious_events": 2, "expected_techniques": ["T1098.006", "T1609"], "must_conclude": ["ci-runner", "cluster-admin", "web-1"], "stages": []}

| case | rules | domains with material evidence | independent evidence sources | eligible at step 0 | domain specialists at step 0 | specialists_eligible (whole run) | qualifies | why |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `CASE-001` | K8S-001, K8S-002 | control_plane | 1 | control_plane | 1 | 2 | no | one domain only (control_plane): every finding rests on container_audit -- there is no second domain to synthesise with |

### `synthetic:INC-004`

*Provenance:* synthetic (generated by this repository). *Source:* `ath.evaluation.suite`.

Defender real-time protection disabled, a staging directory excluded from scanning, the AV process killed, then shadow copies, the backup catalogue and boot-time recovery all destroyed.

*Ground truth:* {"labelled": true, "incident_id": "INC-004", "name": "Ransomware preparation (recovery inhibition + defence impairment)", "description": "Defender real-time protection disabled, a staging directory excluded from scanning, the AV process killed, then shadow copies, the backup catalogue and boot-time recovery all destroyed.", "malicious_events": 6, "expected_techniques": ["T1490", "T1685"], "must_conclude": ["PC03"], "stages": [{"stage": "1-defense-impairment", "note": "powershell.exe -nop -w hidden Set-MpPreference -DisableRealtimeMonitoring $true", "evidence_by_domain": {"endpoint": 3}}, {"stage": "2-recovery-inhibition", "note": "vssadmin.exe delete shadows /all /quiet", "evidence_by_domain": {"endpoint": 3}}]}

| case | rules | domains with material evidence | independent evidence sources | eligible at step 0 | domain specialists at step 0 | specialists_eligible (whole run) | qualifies | why |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `CASE-001` | ATH-011, ATH-012 | endpoint | 1 | endpoint | 1 | 2 | no | one domain only (endpoint): every finding rests on process_command_line, process_execution -- there is no second domain to synthesise with |

### `synthetic:INC-003`

*Provenance:* synthetic (generated by this repository). *Source:* `ath.evaluation.suite`.

The identical benign background -- including the IT administrator's encoded-PowerShell look-alike -- with the intrusion removed. Any case raised here is unambiguously a false positive.

No case was raised on this corpus.

## The 22 M19 cases, against the test

The last column is the check `tests/test_m19b_audit.py` runs: this audit's whole-run eligibility against the `specialists_eligible` arm A recorded in `reports/m19/ablation/arm_A.json`. Agreement is what makes every other number here a statement about the pipeline M19 measured.

| M19 case | domains | domain specialists at step 0 | verdict | agrees with arm A |
| --- | --- | --- | --- | --- |
| `attack_data_aws` / `CASE-001` | control_plane | 1 | one domain only (control_plane): every finding rests on cloud_management_activity -- there is no second domain to synthesise with | yes |
| `attack_data_aws` / `CASE-002` | control_plane | 1 | one domain only (control_plane): every finding rests on cloud_management_activity -- there is no second domain to synthesise with | yes |
| `comiset` / `CASE-001` | endpoint | 1 | one domain only (endpoint): every finding rests on process_command_line, process_execution, process_lineage -- there is no second domain to synthesise with | yes |
| `comiset` / `CASE-002` | endpoint | 1 | one domain only (endpoint): every finding rests on process_command_line, process_execution -- there is no second domain to synthesise with | yes |
| `synthetic:INC-001` / `CASE-001` | endpoint, identity, network | 3 | **QUALIFIES** | yes |
| `synthetic:INC-002` / `CASE-001` | identity | 1 | one domain only (identity): every finding rests on auth_source_attribution, authentication -- there is no second domain to synthesise with | yes |
| `synthetic:INC-005` / `CASE-001` | control_plane | 1 | one domain only (control_plane): every finding rests on container_audit -- there is no second domain to synthesise with | yes |
| `synthetic:INC-004` / `CASE-001` | endpoint | 1 | one domain only (endpoint): every finding rests on process_command_line, process_execution -- there is no second domain to synthesise with | yes |
| `flaws_cloud` / `CASE-005` | identity | 1 | one domain only (identity): every finding rests on auth_source_attribution, authentication -- there is no second domain to synthesise with | yes |
| `flaws_cloud` / `CASE-018` | control_plane | 1 | one domain only (control_plane): every finding rests on cloud_management_activity -- there is no second domain to synthesise with | yes |
| `flaws_cloud` / `CASE-050` | control_plane | 1 | one domain only (control_plane): every finding rests on cloud_management_activity -- there is no second domain to synthesise with | yes |
| `flaws_cloud` / `CASE-065` | control_plane | 1 | one domain only (control_plane): every finding rests on cloud_management_activity -- there is no second domain to synthesise with | yes |
| `flaws_cloud` / `CASE-066` | control_plane | 1 | one domain only (control_plane): every finding rests on cloud_management_activity -- there is no second domain to synthesise with | yes |
| `flaws_cloud` / `CASE-067` | control_plane | 1 | one domain only (control_plane): every finding rests on cloud_management_activity -- there is no second domain to synthesise with | yes |
| `flaws_cloud` / `CASE-077` | control_plane | 1 | one domain only (control_plane): every finding rests on cloud_management_activity -- there is no second domain to synthesise with | yes |
| `flaws_cloud` / `CASE-113` | control_plane | 1 | one domain only (control_plane): every finding rests on cloud_management_activity -- there is no second domain to synthesise with | yes |
| `flaws_cloud` / `CASE-118` | control_plane | 1 | one domain only (control_plane): every finding rests on cloud_management_activity -- there is no second domain to synthesise with | yes |
| `flaws_cloud` / `CASE-122` | control_plane | 1 | one domain only (control_plane): every finding rests on cloud_management_activity -- there is no second domain to synthesise with | yes |
| `flaws_cloud` / `CASE-143` | control_plane | 1 | one domain only (control_plane): every finding rests on cloud_management_activity -- there is no second domain to synthesise with | yes |
| `flaws_cloud` / `CASE-205` | control_plane | 1 | one domain only (control_plane): every finding rests on cloud_management_activity -- there is no second domain to synthesise with | yes |
| `flaws_cloud` / `CASE-219` | control_plane | 1 | one domain only (control_plane): every finding rests on cloud_management_activity -- there is no second domain to synthesise with | yes |
| `flaws_cloud` / `CASE-256` | control_plane | 1 | one domain only (control_plane): every finding rests on cloud_management_activity -- there is no second domain to synthesise with | yes |

**1 of 22 M19 cases qualify**: `synthetic:INC-001`/`CASE-001`. MEASURED.

## Qualifying candidates, ranked by provenance

| # | case | provenance | domains | independent sources | rules | held out? |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `synthetic:INC-001` / `CASE-001` | synthetic (generated by this repository) | endpoint, identity, network | 3 | ATH-001, ATH-002, ATH-003, ATH-004, ATH-005, ATH-006, ATH-007, ATH-008, ATH-009, ATH-010 | no -- ATH-001: 20 commits, ATH-002: 26 commits, ATH-003: 26 commits, ATH-004: 31 commits, ATH-005: 41 commits, ATH-006: 24 commits, ATH-007: 20 commits, ATH-008: 18 commits, ATH-009: 15 commits, ATH-010: 20 commits |

*Held out* is answered by `git log`: a rule id edited across many commits, or a fixture rewritten repeatedly, has been iterated against in this repository whatever anyone intended. On this evidence no existing case can be presented as held-out data. MEASURED.

## Near misses: two domains present, still not qualifying

| case | domains | rules | domain specialists at step 0 | why it fails |
| --- | --- | --- | --- | --- |
| `fixture:defender_export` / `CASE-001` | endpoint, network | ATH-001, ATH-002, ATH-003, ATH-009 | 2 | redundant: only endpoint carries a finding no other domain also reads, so removing the other domain(s) removes a second view of one stage, not a stage |

### Corpora whose cases split cleanly along the domain boundary

These corpora carry two domains' worth of telemetry and raise cases in both -- never in the same case. This is the shape that matters most for T5, because it is the shape a correlator change (not a data change) would address:

| corpus | domains raised | cases | split |
| --- | --- | --- | --- |
| `flaws_cloud` | control_plane, identity | 281 | control_plane: 280 / identity: 1 |
| `fixture:cloudtrail` | control_plane, identity | 2 | control_plane: 1 / identity: 1 |

## Why the corpora look like this (VERIFIED FROM CODE)

A case is multi-domain only if its member findings are, and the rule catalogue decides that before any corpus is loaded:

| domains a rule's findings carry | rules | which |
| --- | --- | --- |
| endpoint | 9 | ATH-001, ATH-002, ATH-004, ATH-007, ATH-008, ATH-009, ATH-010, ATH-011, ATH-012 |
| control_plane | 8 | AWS-001, AWS-002, AWS-003, AWS-004, AWS-005, AWS-006, K8S-001, K8S-002 |
| identity | 2 | ATH-005, ATH-006 |
| endpoint, network | 1 | ATH-003 |

Exactly one rule spans two domains on its own (`ATH-003`, endpoint + network), and it does so *within a single finding* -- which is one stage described twice, not two stages, so it fails condition 2 by itself.

For findings from two different domains to land in one case, `ath.correlation.correlator.score_pair` must find a **structural** signal between them. Of its six, four (`shared_evidence`, `same_process`, `process_lineage`, `sibling_lineage`) require the two findings to cite the same telemetry event or the same process instance, which two different canonical tables cannot do across the endpoint/identity/control-plane boundary except where a rule reads both. `host_movement` needs a directed host relationship, which no cloud or Kubernetes finding carries. That leaves `auth_then_exec`, and it is gated by a **hardcoded rule-id allowlist**:

```python
_AUTH_RULES = ['ATH-005', 'ATH-006']
_REMOTE_EXEC_RULES = ['ATH-007']
```

So the identity -> endpoint link this project can form at all is exactly `ATH-005`/`ATH-006` followed by `ATH-007` on the same host inside the `auth_exec_window`. **No pair of rule ids outside that product can ever produce a cross-domain case**, whatever the telemetry contains -- an identity finding and a control-plane finding about the same AWS principal cannot be correlated by this codebase today. That is the structural reason for every row in the tables above, and it is the same stale-allowlist failure mode `ath.agent.specialists.Specialist` documents having removed from the specialist gates, still in place one layer down. VERIFIED FROM CODE.

## If more cases are needed

**1 qualifying case(s) exist against a target of about 8; the shortfall is 7.** What follows is a specification for T5, not work done here: nothing below was built, and the plan forbids adjusting a case after a model has seen it.

### The constraint that decides every option

Only **one** cross-domain pair can qualify under the code as it stands, and it is not a matter of which data is fetched:

* **endpoint x identity** -- reachable. `auth_then_exec` links `ATH-005` or `ATH-006` to `ATH-007` on one host inside the auth-exec window, and the two findings are domain-exclusive, so removing either removes a stage. This is the pair `synthetic:INC-001` already uses.
* **endpoint x network** -- unreachable. `ATH-003` is the only rule producing network channels and it produces process channels from the same finding, so the network domain can never carry a finding the endpoint domain does not also read. Condition 2 fails by construction, not by data.
* **anything x control_plane** -- unreachable. No structural signal in `score_pair` can join a `control` row to a `process` or `logon` row, so a control-plane finding is always alone in its case. This holds for the Kubernetes route as well: `K8S-001` (the RBAC grant) and `K8S-002` (the grantee's exec) are **both** `control_plane`, so 'K8s CI plus a grantee exec' yields one domain, not two, however real the cluster is. VERIFIED FROM CODE.

So T5 has two admissible routes, and they are not equivalent:

**Route A -- build within the architecture.** Construct the shortfall as endpoint x identity cases. Every one of them is the same shape as INC-001, which is a real limitation of the resulting benchmark and must be stated in the pre-registration: it measures whether a crew helps on *one* kind of cross-domain investigation.

**Route B -- change the architecture first, then audit again.** A link predicate joining a cloud authentication finding to a control-plane finding by *principal and time* (the relationship `flaws_cloud` and the CloudTrail fixture already contain in their rows and never in their cases) would make identity x control_plane cases form from **real, unlabelled data** with no fabrication at all. That is a change to `ath.correlation`, not to a detection rule, so it is not forbidden by the plan -- but it changes which cases exist, which means M19's arm A is no longer a baseline for them, and it must be decided and frozen before any B or C run. HYPOTHESIS: the predicate would produce cases; how many, and whether they satisfy condition 2, is not known and this audit does not claim it.

### Route A, case by case

Each case below is one row of telemetry design. The 'synthetic' column is the part no data source supplies and this repository would have to write, and it is the part a reader is entitled to discount.

| case(s) | domains | chain | provenance it would carry | most realistic construction route available | what would be synthetic |
| --- | --- | --- | --- | --- | --- |
| 1-3 | endpoint + identity | credential guessing -> successful logon -> service-launched shell on the target host | real benign background + injected attack | DEDALE D02/D03/D07 benign Winlogbeat hours as background (real bytes, real hosts, real accounts), with the `ATH-005` burst and the `ATH-007` service-launched shell written as Winlogbeat records shaped on `tests/fixtures/real_shaped/dedale/` | the attack rows themselves: the failed-logon burst, the successful logon and the `services.exe` -> `cmd.exe` pair |
| 4-5 | endpoint + identity | the same chain across two hosts, so `host_movement` and `auth_then_exec` both fire and the case spans a boundary | real benign background + injected attack | the same DEDALE background on two hosts | as above, plus the second host's rows |
| 6-7 | endpoint + identity | a *benign* version of the same shape -- an administrator whose logon burst is a mistyped password and whose shell is patch management | real benign background + injected benign look-alike | DEDALE benign hours; the look-alike is modelled on the `benign_lookalike` scenario already in `data/raw/ground_truth.json` | the look-alike rows. These are the cases that make the benchmark discriminative rather than a recall test, and without them a crew that always says 'intrusion' scores perfectly |
| 8 | endpoint + identity | held out: generated by the same committed code under a seed that is not read until final evaluation | real benign background + injected attack | as 1-3 | as 1-3; what makes it held out is the seal, not the construction |

### Routes this audit examined and rejected

| route | why it does not yield a qualifying case |
| --- | --- |
| DEDALE D15-D22 attack days | **The premise is wrong: D15 and D18 were fetched and are on disk.** D15 (2025-01-06, 434 labelled events) and D18 (2025-01-09, 195) are the first and fourth labelled APT days. Measured at this HEAD: dedale:D02 0 findings / 0 cases; dedale:D03 0 findings / 0 cases; dedale:D07 0 findings / 0 cases; dedale:D15 0 findings / 0 cases; dedale:D18 0 findings / 0 cases. `reports/m14/dedale_d15.json` recorded 30 findings, all `ATH-004` and all CRITICAL, on identical row counts -- and M16-1 established those were false positives from argv[0] guessing, fixed in `626e037`. The 30 findings were the defect; their absence is the fix. HYPOTHESIS: fetching D16-D22 would not change this, because the rules that would have to fire read command lines and lineage this export does not carry in a shape they match -- untested, and testable by fetching one more day. Separately, DEDALE's labels cover Sysmon and PowerShell only -- the label file says so outright -- so the identity half of any DEDALE chain could not be scored even if a case formed. |
| flaws.cloud actors that both authenticate and mutate IAM | The corpus does carry both: 79,424 authentication rows and 1,857,154 control rows, and it raises cases in both domains. It raises **no case containing both**, and cannot, because no structural signal joins a `logon` finding to a `control` finding. This is Route B's territory, not a data-collection task. |
| K8s CI plus a grantee exec | Both halves are `control_plane`. `INC-005` already builds exactly this chain and the audit scores it one domain. Real cluster data would not change the domain count. |
| `tests/fixtures/defender_export` | The only fixture in the repository carrying process, network and logon rows at once, and its single case still fails condition 2 -- the network half is `ATH-003`, which the endpoint specialist reads too. |

## Defects this audit surfaced (reported, not fixed)

Running arm A's deterministic investigation over 294 cases from 23 corpora is a wider sweep than the pipeline normally gets. Two things fell out of it. Neither is fixed here -- a worker that repairs the code it is measuring has measured its own repair -- and neither changes a number in this audit.

### 1. `NetworkAgent` raises `KeyError: 'robust_cv'` on 3-connection destinations. MEASURED, VERIFIED FROM CODE.

`tests/fixtures/defender_export` triggers it, and `ath.agent.orchestrator.act` catches it, logs `Specialist network failed`, and the run completes with the network specialist silently contributing nothing.

The cause is an off-by-one between two thresholds that are both spelled `3`:

* `ToolBox.analyse_beacon` returns a payload **without** `robust_cv` or `median_interval_seconds` when `ConnectionPattern.has_measurable_regularity` is false, which requires `interarrival_count >= 3` -- that is, **four** connections.
* `NetworkAgent.investigate` reaches its irregular-timing branch on `beacon.get("samples", 0) >= 3` -- that is, **three** connections -- and then indexes `beacon['robust_cv']` unconditionally.

Three connections to one destination therefore satisfy the agent's guard and not the tool's, and the agent indexes a key the tool did not write. The narrow fix is to gate that branch on the key the branch reads (`"robust_cv" in beacon`) rather than on a count that only implies it.

### 2. `DefenderExportSource` returns no `control` table, and callers index for one. MEASURED.

`load().tables["control"]` raises `KeyError`, so any caller assembling `Telemetry` from that adapter's tables by subscript fails on a fixture that loads perfectly well. This script works around it in its own `_telemetry_of` rather than changing the adapter; the question of whether an adapter should return an empty frame for a table its source cannot carry belongs to whoever owns `ath.telemetry`.

## Limitations of this audit

* **Condition 3 is a rule, not a judgement.** `_synthesis_statement` derives its answer from conditions 1 and 2 rather than reasoning about each case, so it can neither rescue a case the first two conditions reject nor reject one they accept. On this corpus the question never arises -- one case passes the first two conditions -- but on a richer corpus condition 3 would need a human reading rather than this function.
* **Condition 2 is strict about a finding that spans two domains.** A single finding relevant to two specialists counts as one stage. `ATH-003` is the only rule this affects, and the choice is stated rather than hidden: a looser reading would qualify any case containing `ATH-003`, and the planner would still be choosing between two specialists reading the same rows.
* **Domain membership is computed from `fields_used`, so it can over-count.** `ATH-003` reads only the network table yet declares `process_name` and `process_id`, which map to the process-execution channel -- so the endpoint specialist is eligible on a case built from network rows alone. That is the pipeline's own behaviour, reported as measured, not an artefact of this script.
* **'Held out' is answered by `git log`, which is a lower bound.** A rule tuned by editing a threshold in a file the rule id does not appear in is not counted.
* **Unlabelled corpora cannot be scored on condition 1's 'belongs to the labelled attack chain' clause.** For `flaws_cloud` and `comiset` the audit falls back to the plan's second clause -- the same actor/host/time story the case's findings tell -- which the correlator has already enforced by construction.
* **No model was called and no rule was changed**, so nothing here is a statement about detection quality.
