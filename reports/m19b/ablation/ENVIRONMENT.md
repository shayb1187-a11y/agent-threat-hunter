# M19b ablation: the frozen experiment environment

## The one pre-registered divergence from M19

* field: `InvestigationConfig.tool_output_budget`
* M19: `None` on every arm
* M19b: `A_deterministic` = `None`, `B_single_llm` = `4096`, `C_crew_llm` = `4096`
* source: reports/m19b/PREREGISTERED.md section 1; reports/m19b/http413/
* agrees with the live arm definitions: true
* `InvestigationConfig` default still unbounded: true

> the T2 mitigation. Without it arm B degrades on any case whose tool results are large; flaws_cloud/CASE-256 carries 108 deterministic facts from 17 tool calls. The bound changes only how already-verified claim evidence is rendered for synthesis. Arm A never synthesises and is unaffected; B and C receive the same bound.

A model arm may not run unless the live `ArmConfig` still carries these values; see `run`'s refusal.

---
# M19b: the frozen experiment environment

Equal to M19's on everything that could make two arms differ other than their reasoning architecture. Scoring is asserted by reproduction rather than by a hash, because T6 added the necessity metrics to `scoring.py` -- `docs/m19b-plan.md`, amended before any T8 run.

## Equality with M19

* compared: prompts, request, retry, budgets, model_ids, tool_surface
* M19 freeze: `reports/m19/ablation/ENVIRONMENT.json` at `5b8c3f2b464d`
* **equal: true**

## Scoring

* **reproduces GRADING.json: true**
* recomputed from `reports/m19/ablation/arm_{A,B,C}.json` by this checkout's `scoring.py`
* sections reproduced: arms
* not reproduced: planner (parsed from run_*.log, not from any score)
* not reproduced: vii_decision_rule (joins claim and tool-call ids across arms; grader logic)
* not reproduced: i..vi, labels, degraded, identity_hygiene (row fields the grader re-counts; the scores they count are covered by the per-row round trip)

---
# M19 Phase 1: the frozen experiment environment

Everything that could differ between the arms other than the reasoning architecture, written down before the first arm runs. `ENVIRONMENT.json` carries the same values in machine-readable form.

## The gate

A **real** run of a model arm (`run --arm B` / `--arm C`) refuses to start unless the commit, the four prompt hashes, the scoring-code hashes, the manifest hash and the per-arm model ids all still match this file, and unless the working tree is clean outside `reports/` and `data/`. Committing this file moves HEAD, so a commit that differs from the frozen one is accepted only when every path changed since lives under `reports/`; one changed line of code, test or script and the run is refused.

A `--scripted` run is exempt. It contains no model output, is written under `scripted/` and is labelled `*_SCRIPTED`, so there is no comparison for it to drift out of.

## Code

* commit `4e61bf6d5bbc4060df53bd714674fded570a5fc2` on branch `m19b/harness`
* working tree: no uncommitted change outside `reports/` and `data/` (the code at this commit is the code that runs)
  * `reports/m19b/ablation/ENVIRONMENT.json`
  * `reports/m19b/ablation/ENVIRONMENT.md`
  * `reports/m19b/ablation/ORACLE.json`
  * `reports/m19b/ablation/arm_A_rep1.json`
  * `reports/m19b/ablation/arm_A_rep2.json`
  * `reports/m19b/ablation/scores_A.json`
* manifest `0ced14fb387c` (built at `49c0980`)

## The arms

| arm | model | planner | synthesis | max_steps | tool call cap |
| --- | --- | --- | --- | --- | --- |
| `A_deterministic` | `none` | False | False | 8 | uncapped |
| `B_single_llm` | `claude-opus-5` | True | True | 8 | 40 |
| `C_crew_llm` | `claude-opus-5` | True | True | 8 | 40 |

The model id is pinned by the experiment on `ArmConfig`, not read from configuration: `ath.config.DEFAULT_MODEL` is unchanged and out of scope.

## The request

* endpoint `https://api.anthropic.com/v1/messages`
* `anthropic-version: 2023-06-01`
* `thinking`: `{'type': 'adaptive'}` -- sent explicitly
* effort: provider default (high); output_config is not sent
* `max_tokens`: planner 8192, synthesis 8192
* sampling: none sent; temperature, top_p and top_k are rejected with a 400 by the models this experiment runs
* body fields: model, max_tokens, system, messages, thinking
* transport: urllib (stdlib); no SDK, by project choice

## Timeout and retry

* 60s per attempt
* up to 3 attempt(s), exponential: backoff_seconds * 2**attempt from 1.0s
* retried statuses: [408, 409, 429, 500, 502, 503, 504, 529]
* a non-retryable status (400/401/403/404) fails immediately; a truncated or textless reply is not retried either -- it is returned as an error so the row degrades rather than spending the budget again on the same cap

## Prompts (sha256)

* `planner_system`: `c8bca1694a015878e05751c9a5c9b5f0e841d0be360c204e30a67ad07f629bf6`
* `planner_user_template`: `9136d5d63c5ad470b756fc7797d659468047ce5992640752a39649a6b302b67d`
* `synthesis_system`: `9d1a547b0006abd87fb2c8764194ad1174546491038e91f91cd50f680f7f3d6f`
* `synthesis_user_template`: `e15896466418b847e8f7357fbd76edcfe5090fe3cc05db820e521a1568bf4d31`

## Scoring code (sha256)

* `arms.py`: `37daf4df704b0c4500e9278f048729d6d40fe2c1d2ac8f4816e605264405a06f`
* `incidents.py`: `25aa44cdbe00032aef2db42c931c0f8009415d383d0358d4c54705f9653db6cb`
* `scoring.py`: `3b8e8bb2d76c65af36105e33305c9e3f391f0c61d4153bb1ad7bb09c0bea0ec8`

## Tool surface

Identical for arms B and C -- asserted when this file is written, and the freeze is refused if it is not. The difference between B and C is what the planner chooses among, never what it can call.

* `analyse_beacon(self, device: 'str', remote_ip: 'str', agent: 'str' = 'network') -> 'dict[str, Any]'`
* `get_case(self, case_id: 'str', agent: 'str' = 'orchestrator') -> 'dict[str, Any]'`
* `get_events(self, event_ids: 'list[str]', agent: 'str' = 'orchestrator') -> 'dict[str, Any]'`
* `get_finding(self, finding_id: 'str', agent: 'str' = 'orchestrator') -> 'dict[str, Any]'`
* `host_network_activity(self, device: 'str', remote_ip: 'str | None' = None, agent: 'str' = 'network') -> 'dict[str, Any]'`
* `lookup_technique(self, technique_id: 'str', agent: 'str' = 'attack') -> 'dict[str, Any]'`
* `process_tree(self, device: 'str', pid: 'int | None' = None, depth: 'int' = 3, agent: 'str' = 'endpoint', process_guid: 'str' = '') -> 'dict[str, Any]'`
* `search_processes(self, device: 'str | None' = None, contains: 'str | None' = None, process_name: 'str | None' = None, limit: 'int' = 25, agent: 'str' = 'endpoint') -> 'dict[str, Any]'`
* `user_auth_history(self, user: 'str', agent: 'str' = 'identity') -> 'dict[str, Any]'`

## Runtime

* Python 3.9.2 (CPython) on Windows-10-10.0.26100-SP0
* numpy 2.0.2
* pandas 2.2.3
* pyarrow 21.0.0
* python-dotenv 1.2.1

## Credential

* `ATH_LLM_API_KEY`: not set -- presence only; the value is never recorded anywhere
