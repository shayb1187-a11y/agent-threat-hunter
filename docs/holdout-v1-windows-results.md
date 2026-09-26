# Holdout-v1-windows: results

> Windows telemetry excerpts in this document come from DEDALE (INRIA / IRISA, PIRAT team), CC BY 4.0, https://dedale.inria.fr/ (doi:10.57745/Y5JLDG). See [external datasets](project-reference.md#external-datasets).

First fresh evaluation of deterministic ATH against qwen3.5:9b (operational-v6), run on the pre-registered design in [holdout-v1-windows-preregistration.md](holdout-v1-windows-preregistration.md). Colab T4 run `holdout-9b-v6-ecd865890442`, 2026-09-26.

**Verdict under the sealed rule: investigative value on Windows not demonstrated.** It fails two criteria. D1 cleared three malicious cases as benign (criterion 2, which allows at most 1). D1 also got no malicious case right, so Windows balanced accuracy is 0.42 (criterion 4 requires more than 0.5 with at least one correct case per class).

> Kubernetes malicious discrimination was not evaluated: no suitable fresh, labelled Kubernetes attack dataset was available, and recording malicious Kubernetes activity could not be completed. Kubernetes cases appear only as a secondary benign false-accusation check, and no claim about discriminating Kubernetes attacks is made.

## Integrity

- The run matches every pre-registered hash:
  - ATH source `6c90c15f…`
  - case bundle `479190ce…`
  - upload ZIP `d43d2b87…`
  - notebook source bundle `ecd86589…`
- All 36 rows (18 cases × 2 arms) are present and complete. Each validated against the freeze locally after download.
- No row was scripted, blocked or errored at the end of the run.
- The RAM guard blocked `h11 / d1` once, with 4.03 GiB available plus 5.40 GiB resident, below the 9.5 GiB floor. The block was recorded as an attempt stub. The notebook then restarted Ollama and preloaded again, and the row completed on retry. This is the recovery path added after the v6 regression lost a row silently.
- The synthetic dev gate passed 3/3 before any holdout case ran.

## Decision rule, criterion by criterion (12 primary Windows cases)

| Criterion | Rule | Observed | Result |
|---|---|---|---|
| complete | every primary row present | 24/24 | pass |
| live-model | no scripted rows | none scripted | pass |
| 1. correct gain | D1 − deterministic ≥ 3 | 5 − 0 = 5 | pass |
| 2. unsafe clears | ≤ 1 | **3** | **fail** |
| 3. false accusations | ≤ 1 | 1 | pass |
| 4. Windows discrimination | balanced accuracy > 0.5, ≥ 1 correct per class | **0.42**; malicious 0/6, benign 5/6 | **fail** |

The gain in criterion 1 comes entirely from benign cases. The deterministic arm abstained on all 18 cases.

## Per case (D1)

| Key | Quadrant | Seed | D1 | Probes | What D1 said (model text, abridged) |
|---|---|---|---|---|---|
| h01 | malicious | cmd.exe (non-implant) | **benign (unsafe clear)** | none | "deletes a local temporary directory … standard maintenance" |
| h03 | malicious | cmd.exe (non-implant) | **benign (unsafe clear)** | none | "kills … soffice.exe via taskkill … standard administrative maintenance" |
| h05 | malicious | cmd.exe (non-implant) | **benign (unsafe clear)** | process_tree | "conhost.exe and whoami.exe are standard Windows utilities signed by Microsoft" |
| h07 | malicious | svcmon.exe (implant) | abstain | process_tree ×2 | child command line "identical to the parent and opaque" |
| h16 | malicious | svcmon.exe (implant) | abstain | process_tree ×2 | same |
| h17 | malicious | svcmon.exe (implant) | abstain | process_tree ×2 | same |
| h04 | benign | svchost.exe | benign ✓ | process_tree | AppXSvc under svchost |
| h09 | benign | cmd.exe | **malicious (false accusation)** | host_network_activity | "ssh … as root, bypassing host key checking" |
| h13 | benign | conhost.exe | benign ✓ | process_tree | dsregcmd spawning conhost |
| h14 | benign | firefox.exe | benign ✓ | process_tree | user opening a local PDF |
| h15 | benign | cmd.exe | benign ✓ | process_tree | OneDrive updater cleanup |
| h18 | benign | RuntimeBroker.exe | benign ✓ | process_tree | launched by svchost |

**Malicious recall by seed type:**

| Seed type | Correct | Unsafe clears | Abstentions |
|---|---|---|---|
| implant | 0/3 | 0 | 3 |
| non-implant | 0/3 | 3 | 0 |

The implant cases did not produce a recognition shortcut: D1 never called the implant malicious. The failure sits in the non-implant cases.

**Secondary Kubernetes benign check** (not part of the verdict):
- D1 called 3 of 6 benign, abstained on 2 and accused 1: h02, a deployer granting `admin` to its own app service account.
- The deterministic arm abstained on all 6.

## Descriptive metrics (D1, all 18 rows)

- Latency per case: median 14.9 s, p90 24.4 s, max 24.8 s.
- Tools: 57 tool calls served, none refused or truncated. 21 probes in total, 1.17 per case.
- Evidence:
  - D1 surfaced 7 of the 72 labelled follow-up events (all 7 were also cited).
  - The parent–child link was not recovered.
  - There were 0 rejected claims and 0 accepted invalid predicates.

## What failed, read from the rows

1. **Seed-only judgement on malicious activity.** In h01 and h03, D1 decided on the seed command alone and ran no probe. Deleting a temp directory and killing soffice.exe look like maintenance in isolation. In this campaign they are steps run from the implant. The malicious context sits in the process ancestry, which D1 never requested in h01 and h03. In h05 it ran one process-tree probe, but its conclusion cites only the child processes.
2. **Absence of evidence read as evidence of benign intent.** Every unsafe clear cites "no evidence of data exfiltration or credential theft" as grounds for "benign". That is the same failure the v5 pilot showed, in a new form.
3. **Signer still used as a benign cue.** In h05, D1 cleared whoami.exe partly because it is "signed by Microsoft". operational-v6 keeps the v5 prompt unchanged, so the v5 lesson ("a signature is not evidence of benign intent") was never applied to it.
4. **Implant cases: safe but uninformative.** D1 probed the process tree twice. It found child processes whose command lines match the parent, and it abstained. The failure is safe but gives no answer.
5. **Low evidence recovery.** At about one probe per case, D1 surfaced 7 of 72 labelled follow-up events.
6. **h09 false accusation.** D1 called an ssh-as-root command with host-key checking disabled malicious. The case is labelled benign because its day carries no labelled attack activity. The pre-registration declared that this label is not publisher-verified. The label stands as sealed and the row is scored as an error.

## What this result does and does not show

- **It shows** that on 12 fresh, balanced Windows cases, operational-v6 with qwen3.5:9b is not safe to trust with a benign disposition on malicious activity. It cleared 3 of 6 attacks. On the non-implant seeds it cleared all three. It also shows the evaluation harness working end to end on unseen data: sealed design, complete rows, recovery from a RAM block, and per-case reports.
- **It does not show** anything about Kubernetes attack discrimination (not evaluated). It is also not a precise estimate: the six malicious cases come from one correlated campaign, and one decision moves accuracy by 8 points.
- **These cases are now seen.** Any prompt or profile change motivated by this result, such as requiring an ancestry probe before a benign call, or removing absence-of-evidence and signer cues, must be judged on a new holdout, not this one.

## Artifacts (outside git)

`Downloads/ath-holdout-v1/results-9b-colab/ath-results-holdout-9b-v6-ecd865890442/` contains:
- `real/index.html`: the run index, linking the Markdown and HTML report for every row.
- `real/FREEZE.json`
- `real/SUMMARY.json`
- `real/rows/`: 36 sealed rows, each with `.md` and `.html` reports, plus `attempts/`
- `dev-gate/`, `preloads/`, `timings.log`

## Follow-up: operational-v7 (dev only)

> **These cases are now seen.** operational-v7 was written after reading the rows above. Nothing in this section is a result. Any claim about v7 needs a fresh holdout.

operational-v7 is operational-v6 with three changes:

- **A benign guard, enforced in code** (`ath.agent.benign_guard`). Suppose the case's seed holds a process-creation record and the model concludes benign. The benign stands only if a tool showed the parent of that process during the run.
  - The parent is identified by the rule `process_tree` walks with: rows carrying the seed's parent instance identity, or else the single process instance that held the parent pid.
  - The seed row does not count, although it records the parent's name.
  - Otherwise the disposition becomes abstain. The run stays complete, and `benign_guard` in the operational audit records the reason. The report's Verdict shows the reason under "Decided by".
  - Malicious and abstain answers are not touched. Seeds with no process record, such as control-plane actions or logons, are not guarded; the audit records "not a process seed".
- **A new system prompt** (`ANCESTRY_SYSTEM`; the v5/v6 prompt is unchanged).
  - It drops the "signed … supports benign" cue and says a valid signature is not evidence of benign intent.
  - It says absence of evidence of exfiltration or credential theft is not evidence of benign intent.
  - It asks for the ancestry of a process before a benign.
- **One menu line reworded.** The seed's process_tree probe no longer says "the parent shown in the cited row is already known".

### Guard replay on the sealed v6 rows

`scripts/replay_benign_guard.py` applies the same guard function to each sealed D1 row's recorded tool calls. No model is called, and only the guard is replayed. The v7 prompt would change the model's answers, and that cannot be replayed.

**SEEN CASES — dev evidence only; not a result.**

| Key | Quadrant | Expected | v6 decision | Probes | Parent retrieved? | v7 guard would |
|---|---|---|---|---|---|---|
| h01 | windows-malicious | malicious | benign | none | no | abstain (guard applied) |
| h02 | k8s-benign | benign | malicious | identity_grants | n/a (not a process seed) | malicious (unchanged) |
| h03 | windows-malicious | malicious | benign | none | no | abstain (guard applied) |
| h04 | windows-benign | benign | benign | process_tree | no (parent not in telemetry) | abstain (guard applied) |
| h05 | windows-malicious | malicious | benign | process_tree | yes | benign (unchanged) |
| h06 | k8s-benign | benign | abstain | resource_control_history, actor_control_history | n/a (not a process seed) | abstain (unchanged) |
| h07 | windows-malicious | malicious | abstain | process_tree, process_tree | yes | abstain (unchanged) |
| h08 | k8s-benign | benign | benign | actor_control_history | n/a (not a process seed) | benign (unchanged) |
| h09 | windows-benign | benign | malicious | host_network_activity | no | malicious (unchanged) |
| h10 | k8s-benign | benign | benign | identity_grants | n/a (not a process seed) | benign (unchanged) |
| h11 | k8s-benign | benign | abstain | resource_control_history | n/a (not a process seed) | abstain (unchanged) |
| h12 | k8s-benign | benign | benign | actor_control_history, identity_grants | n/a (not a process seed) | benign (unchanged) |
| h13 | windows-benign | benign | benign | process_tree | yes | benign (unchanged) |
| h14 | windows-benign | benign | benign | process_tree | yes | benign (unchanged) |
| h15 | windows-benign | benign | benign | process_tree | yes | benign (unchanged) |
| h16 | windows-malicious | malicious | abstain | process_tree, process_tree | yes | abstain (unchanged) |
| h17 | windows-malicious | malicious | abstain | process_tree, process_tree | yes | abstain (unchanged) |
| h18 | windows-benign | benign | benign | process_tree | yes | benign (unchanged) |

What the replay shows, and its limits:

- **Guard alone, on the same answers.** Unsafe clears fall from 3 to 1: h01 and h03 are withheld. Correct Windows benign calls fall from 5 to 4: h04 is withheld because its parent (services.exe) started before the capture and has no record, so no probe could retrieve it. No malicious case becomes correct, so the guard alone does not meet criterion 4.
- **h05 still clears.** Its process_tree probe did retrieve the parent, so the guard passes. The model then cited only the children and reasoned from the signer. Only the v7 prompt addresses that, and its effect is unmeasured.
- **Parents that started before the capture.** Any benign on a process whose parent started before the capture, typically a long-running system process, is now withheld. The guard trades benign accuracy for safety, by design.
