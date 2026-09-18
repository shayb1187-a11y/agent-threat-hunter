# V1 dev split (20 cases)

Generated 2026-09-15T10:24:26+00:00 at `195e369`, seed 260915, manifest hash `2298b0e81f2a`. V1 local-model development split; never used to grade a frozen benchmark.

**Substitutions:** (1) the decided composition had 6 flaws.cloud + 3 k8s_ci/k8ntext/attack_data_aws cases; MEASURED 2026-09-15 at 195e369: k8s_ci and k8ntext form 0 cases and attack_data_aws forms only the two cases M19 froze, so those three seats went to flaws.cloud. (2) synthetic:INC-003 forms no case under the current correlator; its seat went to flaws.cloud.

| corpus | case | leading rule | rules | findings | evidence ids | verdict |
| --- | --- | --- | --- | ---: | ---: | --- |
| dedale_injected_dev:V1 | CASE-001 | ATH-005 | ATH-005, ATH-006, ATH-007 | 3 | 15 | malicious |
| dedale_injected_dev:V2 | CASE-001 | ATH-005 | ATH-005, ATH-006, ATH-007 | 3 | 13 | malicious |
| dedale_injected_dev:V3 | CASE-001 | ATH-007 | ATH-005, ATH-007 | 2 | 13 | malicious |
| dedale_injected_dev:V4 | CASE-001 | ATH-005 | ATH-005, ATH-006, ATH-007 | 3 | 22 | malicious |
| dedale_injected_dev:V5 | CASE-001 | ATH-005 | ATH-005, ATH-006, ATH-007 | 3 | 12 | malicious |
| dedale_injected_dev:V6 | CASE-001 | ATH-005 | ATH-005, ATH-006, ATH-007 | 3 | 17 | malicious |
| dedale_injected_dev:V7 | CASE-001 | ATH-005 | ATH-005, ATH-006, ATH-007 | 3 | 14 | benign |
| dedale_injected_dev:V8 | CASE-001 | ATH-005 | ATH-005, ATH-006, ATH-007 | 3 | 14 | benign |
| dedale_injected_dev:V9 | CASE-001 | ATH-005 | ATH-005, ATH-006, ATH-007 | 3 | 12 | benign |
| dedale_injected_dev:V10 | CASE-001 | ATH-005 | ATH-005, ATH-006, ATH-007 | 3 | 14 | benign |
| flaws_cloud | CASE-020 | AWS-003 | AWS-003, AWS-004 | 2 | 25 | unlabelled |
| flaws_cloud | CASE-121 | AWS-004 | AWS-004 | 1 | 13 | unlabelled |
| flaws_cloud | CASE-186 | AWS-003 | AWS-003, AWS-004 | 2 | 27 | unlabelled |
| flaws_cloud | CASE-252 | AWS-004 | AWS-003, AWS-004 | 2 | 24 | unlabelled |
| flaws_cloud | CASE-141 | AWS-003 | AWS-003, AWS-004 | 2 | 33 | unlabelled |
| flaws_cloud | CASE-199 | AWS-004 | AWS-003, AWS-004 | 2 | 29 | unlabelled |
| flaws_cloud | CASE-098 | AWS-003 | AWS-003, AWS-004 | 2 | 18 | unlabelled |
| flaws_cloud | CASE-071 | AWS-004 | AWS-004 | 1 | 15 | unlabelled |
| flaws_cloud | CASE-221 | AWS-003 | AWS-003, AWS-004 | 2 | 27 | unlabelled |
| flaws_cloud | CASE-003 | AWS-004 | AWS-004 | 1 | 11 | unlabelled |

## Disjointness

no shared (telemetry_hash, case_id) pair and no shared finding id with any frozen entry; asserted before writing and by tests/test_contamination.py.

- `reports/m19/ablation/MANIFEST.json` (hash `1764be3cea5a`)
- `reports/m19b/MANIFEST.json` (hash `0ced14fb387c`)

## Limitations

- ten of twenty cases share one shape (endpoint x identity via auth_then_exec), the same shape as six of the nine M19b benchmark cases; tuning on them tunes to that shape
- the nine flaws.cloud cases are unlabelled: no completeness or discrimination metric
