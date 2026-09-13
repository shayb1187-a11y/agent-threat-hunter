# M19b link: what replacing the cross-domain allowlist changed

Generated 2026-09-13T23:42:22.147528+00:00 at `ba25e2e`. BEFORE arm `ba25e2e` (`96ecf41151d7`), AFTER arm `ba25e2e` (`ae9a6900891e`). Comparison digest `44bfae63c8a6006ddd0c0e814b1a308fbad3cc535e4f19abd5c4cd7fe44ec1f9`.

Every number below is MEASURED: each arm is `scripts/m19b_link_measure.py` run over every corpus `reports/m19b/necessity/AUDIT.md` covers, loading through the pipeline's own adapters and correlating exactly as `scripts/m19_ablation.py` does. The two arms differ only in `src/ath/correlation/correlator.py`: no rule, threshold, fixture, prompt or scoring path was touched, and no model was called.

## The link, as the code defines it

`shared_principal` (+3) links two findings when their **channel families are disjoint and non-empty**, their evidence **names the same principal** -- exact match on the canonical string the adapters already wrote, counting both `actor` and `target_actor` on a control row -- and their time windows are no more than `CorrelationConfig.cross_domain_window` = **15 minutes** apart. Order decides only the evidence text ("identity then control_plane"), never eligibility. `auth_then_exec` keeps its name and its meaning as the one cross-family relationship that needs no shared principal -- identity telemetry landing on a host, endpoint telemetry running on that host inside `auth_exec_window` -- with its rule-id allowlist replaced by the same family test. Weight 3 against `min_score` 5 means a shared principal alone never links: a circumstantial signal has to agree with it.

Families are read from each finding's declared channels (`Finding.channels`, else `fields_used`), through a table exhaustive over `ath.channels.TelemetryChannel`: endpoint = `file_events`, `handle_access`, `process_command_line`, `process_execution`, `process_lineage`, `registry`, `script_block`; identity = `auth_factor`, `auth_source_attribution`, `authentication`; network = `dns_query`, `network_flow`, `network_inbound`, `network_url`; control_plane = `cloud_control_plane`, `cloud_management_activity`, `container_audit`. No detection rule id appears anywhere in the correlator's code.

## Cases, by corpus

| corpus | cases | singletons | largest case | cases with >=2 domains | cases offering >=2 domain specialists at step 0 | qualifying | links |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `attack_data_aws` | 2 -> 2 | 1 -> 1 | 2 -> 2 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 1 -> 1 |
| `comiset` | 2 -> 2 | 1 -> 1 | 2 -> 2 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 1 -> 1 |
| `comiset_m17_freeze` | 1 -> 1 | 1 -> 1 | 1 -> 1 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 |
| `flaws_cloud` | 281 -> 279 | 97 -> 96 | 6 -> 7 | 0 -> 2 | 0 -> 2 | 0 -> 2 | 194 -> 201 |
| `k8s_ci` | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 |
| `k8ntext` | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 |
| `k8s_ingress` | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 |
| `fixture:cloudtrail` | 2 -> 1 | 2 -> 0 | 1 -> 2 | 0 -> 1 | 0 -> 1 | 0 -> 1 | 0 -> 1 |
| `fixture:k8s_audit` | 1 -> 1 | 0 -> 0 | 2 -> 2 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 1 -> 1 |
| `fixture:defender_export` | 1 -> 1 | 0 -> 0 | 4 -> 4 | 1 -> 1 | 1 -> 1 | 0 -> 0 | 5 -> 5 |
| `fixture:real_shaped/dedale` | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 |
| `fixture:real_shaped/k8s_ci` | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 |
| `fixture:real_shaped/cloudtrail_shaped` | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 |
| `dedale:D02` | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 |
| `dedale:D03` | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 |
| `dedale:D07` | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 |
| `dedale:D15` | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 |
| `dedale:D18` | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 |
| `synthetic:INC-001` | 1 -> 1 | 0 -> 0 | 11 -> 11 | 1 -> 1 | 1 -> 1 | 1 -> 1 | 21 -> 25 |
| `synthetic:INC-002` | 1 -> 1 | 1 -> 1 | 1 -> 1 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 |
| `synthetic:INC-005` | 1 -> 1 | 0 -> 0 | 2 -> 2 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 1 -> 1 |
| `synthetic:INC-004` | 1 -> 1 | 0 -> 0 | 2 -> 2 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 2 -> 2 |
| `synthetic:INC-003` | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 1 -> 1 |

## Case size distribution

| corpus | before (count x size) | after |
| --- | --- | --- |
| `attack_data_aws` | 1x1, 1x2 | 1x1, 1x2 |
| `comiset` | 1x1, 1x2 | 1x1, 1x2 |
| `comiset_m17_freeze` | 1x1 | 1x1 |
| `flaws_cloud` | 97x1, 179x2, 2x3, 2x4, 1x6 | 96x1, 177x2, 2x3, 2x4, 1x6, 1x7 |
| `k8s_ci` | -- | -- |
| `k8ntext` | -- | -- |
| `k8s_ingress` | -- | -- |
| `fixture:cloudtrail` | 2x1 | 1x2 |
| `fixture:k8s_audit` | 1x2 | 1x2 |
| `fixture:defender_export` | 1x4 | 1x4 |
| `fixture:real_shaped/dedale` | -- | -- |
| `fixture:real_shaped/k8s_ci` | -- | -- |
| `fixture:real_shaped/cloudtrail_shaped` | -- | -- |
| `dedale:D02` | -- | -- |
| `dedale:D03` | -- | -- |
| `dedale:D07` | -- | -- |
| `dedale:D15` | -- | -- |
| `dedale:D18` | -- | -- |
| `synthetic:INC-001` | 1x11 | 1x11 |
| `synthetic:INC-002` | 1x1 | 1x1 |
| `synthetic:INC-005` | 1x2 | 1x2 |
| `synthetic:INC-004` | 1x2 | 1x2 |
| `synthetic:INC-003` | -- | -- |

## Links, by signal

| corpus | signal: before -> after |
| --- | --- |
| `attack_data_aws` | same_device 1->1, same_user 1->1, shared_evidence 1->1, temporal_close 1->1 |
| `comiset` | same_device 1->1, same_user 1->1, sibling_lineage 1->1, temporal_close 1->1 |
| `flaws_cloud` | same_device 121->128, same_user 194->201, shared_evidence 194->194, shared_principal 0->7, temporal_close 194->197, temporal_near 0->4 |
| `fixture:cloudtrail` | same_device 0->1, same_user 0->1, shared_principal 0->1, temporal_close 0->1 |
| `fixture:k8s_audit` | same_device 1->1, same_user 1->1, shared_evidence 1->1, temporal_close 1->1 |
| `fixture:defender_export` | process_lineage 2->2, same_device 5->5, same_process 3->3, same_user 5->5, shared_evidence 1->1, sibling_lineage 1->1, temporal_close 5->5 |
| `synthetic:INC-001` | auth_then_exec 2->6, host_movement 3->3, process_lineage 9->9, same_device 18->22, same_process 5->5, same_user 18->22, shared_evidence 2->2, sibling_lineage 2->2, temporal_close 21->25 |
| `synthetic:INC-005` | same_device 1->1, same_user 1->1, shared_evidence 1->1, temporal_close 1->1 |
| `synthetic:INC-004` | same_device 2->2, same_process 1->1, same_user 2->2, sibling_lineage 1->1, temporal_close 2->2 |
| `synthetic:INC-003` | same_device 1->1, same_process 1->1, same_user 1->1, temporal_close 1->1 |

## Chain quality on the labelled corpora

| incident | findings | cases | noise cases | primary-case recall | primary-case purity | event recall | passed |
| --- | --- | --- | --- | --- | --- | --- | --- |
| INC-001 | 13 -> 13 | 1 -> 1 | 0 -> 0 | 1.0 -> 1.0 | 1.0 -> 1.0 | 1.0 -> 1.0 | True -> True |
| INC-002 | 1 -> 1 | 1 -> 1 | 0 -> 0 | 0.9286 -> 0.9286 | 1.0 -> 1.0 | 0.9286 -> 0.9286 | True -> True |
| INC-005 | 2 -> 2 | 1 -> 1 | 0 -> 0 | 1.0 -> 1.0 | 1.0 -> 1.0 | 1.0 -> 1.0 | True -> True |
| INC-004 | 4 -> 4 | 1 -> 1 | 0 -> 0 | 1.0 -> 1.0 | 1.0 -> 1.0 | 1.0 -> 1.0 | True -> True |
| INC-003 | 2 -> 2 | 0 -> 0 | 0 -> 0 | 0.0 -> 0.0 | 1.0 -> 1.0 | 1.0 -> 1.0 | True -> True |

`python main.py benchmark`: **5/5 before, 5/5 after**, 0 noise case(s) before and 0 after.

### `attack_data_aws` capture-level chain quality

| capture | primary case size | recall | purity | noise cases |
| --- | --- | --- | --- | --- |
| `T1078.004__aws_login_sfa__cloudtrail.json` | 2 -> 2 | 0.0 -> 0.0 | 0.0 -> 0.0 | 2 -> 2 |
| `T1098__aws_iam_delete_policy__aws_iam_delete_policy.json` | 2 -> 2 | 0.0 -> 0.0 | 0.0 -> 0.0 | 2 -> 2 |
| `T1526__aws_security_scanner__aws_security_scanner.json` | 2 -> 2 | 0.0168 -> 0.0168 | 0.5625 -> 0.5625 | 1 -> 1 |
| `T1580__aws_iam_accessdenied_discovery_events__aws_iam_accessdenied_discovery_events.json` | 2 -> 2 | 0.0122 -> 0.0122 | 0.4375 -> 0.4375 | 0 -> 0 |
| `T1580__aws_iam_assume_role_policy_brute_force__aws_iam_assume_role_policy_brute_force.json` | 2 -> 2 | 0.0 -> 0.0 | 0.0 -> 0.0 | 2 -> 2 |

### `synthetic:INC-001` capture-level chain quality

| capture | primary case size | recall | purity | noise cases |
| --- | --- | --- | --- | --- |
| `INC-001` | 11 -> 11 | 1.0 -> 1.0 | 1.0 -> 1.0 | 0 -> 0 |

### `synthetic:INC-002` capture-level chain quality

| capture | primary case size | recall | purity | noise cases |
| --- | --- | --- | --- | --- |
| `INC-002` | 1 -> 1 | 0.9286 -> 0.9286 | 1.0 -> 1.0 | 0 -> 0 |

### `synthetic:INC-005` capture-level chain quality

| capture | primary case size | recall | purity | noise cases |
| --- | --- | --- | --- | --- |
| `INC-005` | 2 -> 2 | 1.0 -> 1.0 | 1.0 -> 1.0 | 0 -> 0 |

### `synthetic:INC-004` capture-level chain quality

| capture | primary case size | recall | purity | noise cases |
| --- | --- | --- | --- | --- |
| `INC-004` | 2 -> 2 | 1.0 -> 1.0 | 1.0 -> 1.0 | 0 -> 0 |

### `synthetic:INC-003` capture-level chain quality

| capture | primary case size | recall | purity | noise cases |
| --- | --- | --- | --- | --- |
| `INC-003` | 0 -> 0 | 0.0 -> 0.0 | 0.0 -> 0.0 | None -> None |

## Newly formed cross-domain cases

### `flaws_cloud` -- 2 new cross-domain case(s)

| case | domains | rules | findings | principals | span | start | link signals |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CASE-182 | control_plane, identity | ATH-005, AWS-004 | 2 | backup | 1009s | 2020-04-11 12:40:01+00:00 | 1 same_device, 1 same_user, 1 shared_principal, 1 temporal_close |
| CASE-256 | control_plane, identity | ATH-005, AWS-003, AWS-004 | 7 | Level6 | 2017s | 2020-09-21 03:54:58+00:00 | 9 same_device, 9 same_user, 3 shared_evidence, 6 shared_principal, 5 temporal_close, 4 temporal_near |

### `fixture:cloudtrail` -- 1 new cross-domain case(s)

| case | domains | rules | findings | principals | span | start | link signals |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CASE-001 | control_plane, identity | ATH-005, AWS-002 | 2 | dev_alice | 420s | 2026-08-17 09:12:00+00:00 | 1 same_device, 1 same_user, 1 shared_principal, 1 temporal_close |

## What changed, in one paragraph

3 new cross-domain case(s) formed, on 2 of the 23 corpora measured: `flaws_cloud`, `fixture:cloudtrail`. Every other corpus is identical case for case -- 21 of them, including every endpoint-only corpus (COMISET, both COMISET freezes, all five DEDALE days, the real-shaped fixtures) and every Kubernetes corpus, where no pair of findings has disjoint channel families to begin with. No link that existed before was lost: every signal count in the table above is greater than or equal to its before value.

1 corpus/corpora gained links without gaining a case: `synthetic:INC-001` (21 -> 25 links). That is `auth_then_exec` losing its allowlist -- on `synthetic:INC-001` the identity findings now link to every endpoint finding on the host they authenticated to, not only to `ATH-007` -- and it changes nothing downstream, because those findings were already one connected component. More reasons for a case that already existed is the whole of it.

One divergence is worth stating because it looks like an inconsistency and is not: `fixture:cloudtrail` merges its two cases into one cross-domain case, while `INC-002` -- the benchmark incident built from that same fixture -- does not move. `ath.evaluation.suite.cloud_credential_stuffing` hands the incident the logon table only, so the control rows the merge rests on are not in the incident's telemetry at all. The corpus and the incident are two different inputs, and only the corpus carries both domains.

The two shapes this reaches are the two the audit named as unreachable. **identity x control_plane** now forms on real, unlabelled CloudTrail: a console-login burst by one IAM principal joins that principal's own management-API activity, which is evidence the corpus always carried and the correlator could not read. **endpoint x network** is reachable in principle and fires nowhere in this repository, because `ATH-003` remains the only rule producing network channels and it declares process execution in the same finding -- so its family set is never disjoint from an endpoint finding's. That is a rule-catalogue limit, not a correlator limit, and this task changed no rule.

## Contamination candidates

A case whose size grew to more than 2.0x the largest case it absorbed. The threshold is a constant declared in `scripts/m19b_link_report.py`, fixed before the arms were compared; being listed here is a flag for a reader, not a verdict.

| corpus | case | largest predecessor -> size | cases merged | domains | rules | principals |
| --- | --- | --- | --- | --- | --- | --- |
| `flaws_cloud` | CASE-256 | 2 -> 7 (3.5x) | 3 | control_plane, identity | ATH-005, AWS-003, AWS-004 | Level6 |

A case listed here grew by absorbing more than one predecessor, which is transitive drift: cases are connected components, so one finding linking to two clusters puts all three in one case even where the clusters share nothing with each other. `ath.correlation.correlator` documented that property before this change; what is new is a signal that can bridge two *kinds* of telemetry, so the bridge is now available to a principal as well as to a process tree. Whether a listed case is *wrong* cannot be settled on an unlabelled corpus, and this report does not claim it either way.

## Limitations

* **The window is a choice, and on the merged cases it is the binding one.** 15 minutes is `auth_exec_window`'s value, taken because it is the only existing window in the file that already answers "did A plausibly cause B across two kinds of telemetry". Nothing here measures whether it is the right value; a sweep would be a separate, pre-registered experiment.
* **Principals are compared as strings.** Two spellings of one identity -- an IAM user and an assumed-role session name for the same human -- are two principals here. That under-links, and it is the direction this errs in deliberately: the alternative is an identity-resolution rule nothing else in the pipeline applies.
* **`cloud_control_plane` is classified as control_plane and no rule declares it.** If a future rule does, a cloud console-login finding would be control-plane rather than identity telemetry and would stop crossing with management activity. The placement is stated in the family table above and changes nothing measured here.
* **Unlabelled corpora cannot grade the new cases.** flaws.cloud ships no labels, so "these are real chains" is not a claim this report makes. What is measured is that they exist, which principals they rest on, and what they merged.
* **The `attack_data_aws` capture-level figures are weak by construction**: the answer key is every ingested row of a capture and a case holds a handful of rows, so recall is near zero in both arms. They are reported because they are unchanged, not because they are informative.
* **No model was called**, and no rule, triage, specialist, tool, prompt, scoring or ablation path was touched. The only source change between the two arms is `src/ath/correlation/correlator.py`.
