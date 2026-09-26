# Holdout-v1-windows: pre-registration

> Windows telemetry excerpts in this document come from DEDALE (INRIA / IRISA, PIRAT team), CC BY 4.0, https://dedale.inria.fr/ (doi:10.57745/Y5JLDG). See [external datasets](project-reference.md#external-datasets).

Recorded on 2026-09-26, **before any model call on these cases**. It covers the first fresh, balanced evaluation of deterministic ATH against qwen3.5:9b. After this record, the cases, labels, rules, profile and source must not change until the results are in. Any change means a new holdout.

## What is sealed

| Item | Value |
|---|---|
| Protocol | `holdout-v1-windows` (`HOLDOUT_WINDOWS_PROTOCOL` in `src/ath/evaluation/real_cases.py`) |
| ATH source hash (`source_hash()`) | `6c90c15f2f0ddea14ae82b6f0f7c87a9327b7b9885e56e132e1e42fb95525890` |
| Case bundle (`bundle_sha256`) | `479190ce056a2575f2bd6e8907b5021a39ff6e1c174a7f0a7a17d3625af3d128` |
| Upload ZIP of the bundle (sha256) | `d43d2b87c1a9cb557d50fba93157d311e773eadc9e624768404bbb8431f17ef1` |
| Colab notebook source bundle | `ecd865890442ab22814e421e15235236b661f0dc6eee99ff04259ad488eead0e` (`notebooks/ath_holdout_gpu.ipynb` as run; see the note below) |
| Profile | operational-v6, unchanged from the v6 regression run |
| Model | qwen3.5:9b, temperature 0, 1 repeat |
| Seed mode | analyst-seeded investigation, not end-to-end ATH; one initial record per case |

The telemetry is not committed. DEDALE slices are CC BY 4.0. The injected Kubernetes cases sit on `k8s_ingress` background, whose licence is not recorded. The builder, `scripts/build_holdout_v1.py`, regenerates the spec deterministically from `data/external`.

**Note added after the run (2026-09-26), before publication.** Two test files bundled in
the notebook carried values from a dataset whose licence forbids derived content
(K8NTEXT). They were replaced with invented values, and the notebook was regenerated
(source bundle `baf0f4b6a7979e1cdc05f019b7994bef6720f16d0d7ad8480973d519149cfe2e`).
Only tests changed. The embedded application source still hashes to `6c90c15f…`, the
source that was sealed and run. The run's own `SOURCE.zip` is kept with its results.

## Decision rule (primary cases only)

Investigative value on Windows counts as **demonstrated** only if all of these hold:
1. D1 correct minus deterministic correct is at least **3** (declared for 12 cases).
2. D1 makes at most 1 unsafe clear (a malicious case called benign).
3. D1 makes at most 1 false accusation (a benign case called malicious).
4. On Windows, D1's balanced accuracy is above 0.5, with at least one correct malicious case and at least one correct benign case. An abstention is not a correct answer.

If any of these fails, the result is **not demonstrated**, and every failing criterion is named. Only completed rows can be correct. Missing, blocked, errored or uninvestigable primary rows count as incorrect. The result counts as complete only when all 24 primary rows (12 cases × 2 arms) are present. Any scripted row voids the result.

**Secondary check.** The 6 Kubernetes cases are all benign and do not count toward the verdict. For each arm they are reported as called malicious, called benign, abstained, or incomplete.

**Not evaluated.** Kubernetes malicious discrimination was not evaluated. No suitable fresh, labelled Kubernetes attack dataset was available, and recording malicious Kubernetes activity could not be completed. No synthetic malicious Kubernetes cases were created to fill the gap. This statement is sealed in the freeze and summary, and every report of this holdout must quote it.

**Reported alongside the verdict, not used to decide it:**
- malicious recall split by seed type (implant or non-implant)
- per-case decisions
- evidence retrieved and cited
- tool usage
- completion
- latency

## Cases

Case keys come from a seeded shuffle (seed 20260925). "Events" is the size of the case's telemetry slice.

| Key | Quadrant | Role | Seed type | Seed image | Day | Window (h) | Events |
|---|---|---|---|---|---|---|---|
| h01 | windows-malicious | primary | non-implant | cmd.exe | D22 | 3.854 | 683 |
| h03 | windows-malicious | primary | non-implant | cmd.exe | D17 | 8.017 | 2572 |
| h05 | windows-malicious | primary | non-implant | cmd.exe | D19 | 4.708 | 818 |
| h07 | windows-malicious | primary | implant | svcmon.exe | D16 | 1.001 | 345 |
| h16 | windows-malicious | primary | implant | svcmon.exe | D20 | 1.002 | 325 |
| h17 | windows-malicious | primary | implant | svcmon.exe | D21 | 1.002 | 321 |
| h04 | windows-benign | primary | – | svchost.exe | D10 | 1.002 | 212 |
| h09 | windows-benign | primary | – | cmd.exe | D13 | 1.002 | 173 |
| h13 | windows-benign | primary | – | conhost.exe | D10 | 4.708 | 498 |
| h14 | windows-benign | primary | – | firefox.exe | D06 | 1.001 | 104 |
| h15 | windows-benign | primary | – | cmd.exe | D01 | 3.854 | 807 |
| h18 | windows-benign | primary | – | RuntimeBroker.exe | D14 | 8.017 | 1340 |
| h02, h06, h08, h10, h11, h12 | k8s-benign | secondary | – | – | – | – | 19, 7, 7, 7, 8, 7 |

Freshness:
- The malicious cases are DEDALE APT stages 2025-01-07, -08, -10, -11, -12 and -13. None of them was used before; the earlier stages 01-06 and 01-09 are excluded.
- The benign cases come from DEDALE days that carry no labels and were never used before.
- The Kubernetes cases are injected scenarios on the `k8s_ingress` background, which was never used for real-case evaluation.
- The full exclusion list is in `HOLDOUT-MANIFEST.json`.

## Selection rules (declared before the final build)

- **Malicious seed.** The seed is the earliest labelled record the loader can ingest whose image is not the campaign implant (fixed list: `svcmon.exe`). It falls back to the implant only when a stage has nothing else. That gives 3 non-implant seeds and 3 implant seeds.
- **Window matching.** Each benign case is paired with a malicious case by a seeded pairing. It copies its partner's window duration, and its seed sits at the partner's seed offset. When the seed offset would place the window outside the day file, duration takes priority: the window is shifted rather than clipped. Two windows were shifted: h15 by +3.19 h and h18 by +6.52 h.
- **Benign sampler.** It is seeded and draws only Sysmon process-creation records. It requires at least 4 days, at least 4 hosts and at least 2 admin-looking picks.
- **Kubernetes cases.** They are injected RBAC binding creations and pod execs. A label-leak check runs over every injected string, and each rationale is kept in the manifest, never in the telemetry.

Three earlier builds were superseded before any freeze or model call. They are kept as `bundle-superseded-1..3` and `bundle-built-pre-integration`. The changes that superseded them:
1. The same implant was the seed of every malicious case.
2. Window length predicted the label.
3. Clipped benign windows.
4. The last one was built with pre-integration code that dropped the holdout metadata.

## Known limitations (declared now, not discovered later)

- All six malicious cases come from **one** DEDALE APT campaign, so they are correlated, not independent samples.
- The implant seed type is the same binary in all three implant cases, and all three non-implant seeds are cmd.exe. Benign h09 and h15 are also cmd.exe.
- Malicious cases usually carry more events than their benign partners, though not in every pair. The difference comes from the data and was not volume-matched.
- Benign here means "no labelled attack activity that day". The publisher has not verified these cases as benign.
- The three CLIENT1 benign cases fall on days that hold only CLIENT1 telemetry, so their surroundings are quieter.
- Only two benign picks look like admin activity, and both are cmd.exe.
- The DEDALE labels resolve only to Sysmon process-creation records. Some stages therefore have very little follow-up evidence the loader can ingest.
- With 12 primary cases, one decision moves accuracy by 8 points. The result is a first measurement, not a precise estimate.

## Deterministic dry run (disclosed)

The deterministic arm was run locally on this exact bundle before the 9B run, to check the pipeline end to end: `Downloads/ath-holdout-v1/results-deterministic-local-dryrun`. The freeze records the local model identity; the model is never called. The arm abstained on all 18 cases. The decision rule was fixed before this run and does not depend on its outcome. The official comparison is the Colab run, which runs both arms under one freeze.
