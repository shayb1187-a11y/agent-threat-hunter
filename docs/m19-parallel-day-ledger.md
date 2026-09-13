# Parallel-day ledger, 2026-09-13 (branch `parallel-dev-2026-09-13`)

Work done while the M19 ablation stays frozen in the main checkout. Nothing here is
merged into `m14-real-data-validation` before the preregistered experiment is scored.

| # | Item | Status | Verdict | Evidence |
|---|------|--------|---------|----------|
| P3 | AWS-006 vs T1580 label | done | ACCEPT: `dataset label questionable`; no mapping change | `docs/aws006-attack-mapping-investigation.md`; independently re-counted: capture = 10 rows, 2 eventIDs, 5x duplicated, all `CreatePolicy` / `MalformedPolicyDocumentException`; Splunk detection `aws_iam_assume_role_policy_brute_force` annotated T1110+T1580 filtering on errorCode only |
| P1 | Defender adapter, absent optional columns | done | ACCEPT, committed `eec9eb7` | derived optional set; 44 tests; independently: subset 130 passed, full 1649 passed / 5 skipped (= baseline 1605 + 44); no fabricated value |
| P2 | ATH-005 negative follow-up interval | characterised, fix deferred | ACCEPT (semantics; 1 of 22 frozen M19 cases affected: `flaws_cloud/CASE-005`) | `docs/ath005-follow-up-defect.md`; independently: `-148s` twice in `reports/m19/ablation/scripted/arm_B.json`, manifest evidence holds `cloudtrail-logon-002675` not `...002823` |
| P4 | M20 benign-cloud tooling | done, nothing run against AWS | ACCEPT | `scripts/m20/` (sessions plan/record, split by object key, provenance, validate_dev, measure_dev, 13 workflow scripts, CloudFormation, policies), `docs/m20-aws-setup.md`, 32 tests; independently: 32 passed, full 1681 passed / 5 skipped (= 1649 + 32); holdout sealing proven with an invalid gzip; plan corrections recorded in plan section 8 |
| P5 | history cleanup | prepared, not executed | addendum committed `09fac9f` | `docs/m19-history-cleanup-plan.md` §5 |

## Side findings (recorded, not fixed today: they touch ingestion or frozen artefacts)

1. `CloudTrailSource` never deduplicates on `eventID`; five copies of one record became five
   canonical rows and met AWS-006's threshold of 5 in a zero-second window
   (`window_start == window_end` in `reports/m18/cloud_detection/attack_data_aws.json`).
   Duplication measured per capture: brute_force 5x (2 of 10 distinct), delete_policy 3x
   (110 of 116), login_sfa 2x (1 of 2), the two large captures 1x. Whether the duplication
   is upstream or from the fetch is INCONCLUSIVE.
2. `data/external/attack_data_aws` has no `MANIFEST.json` entry (no URL, sha256, licence,
   fetch command) unlike the other four datasets.
3. M18 §8 P3 "MATCH" is weaker than it reads: one rejected write per actor at the event
   level. The threshold's provenance (flaws.cloud background max 4) is unaffected.
