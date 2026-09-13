# M19 Phase 1: the frozen experiment environment

Everything that could differ between the arms other than the reasoning architecture, written down before the first arm runs. `ENVIRONMENT.json` carries the same values in machine-readable form.

## The gate

A **real** run of a model arm (`run --arm B` / `--arm C`) refuses to start unless the commit, the four prompt hashes, the scoring-code hashes, the manifest hash and the per-arm model ids all still match this file, and unless the working tree is clean outside `reports/` and `data/`. Committing this file moves HEAD, so a commit that differs from the frozen one is accepted only when every path changed since lives under `reports/`; one changed line of code, test or script and the run is refused.

A `--scripted` run is exempt. It contains no model output, is written under `scripted/` and is labelled `*_SCRIPTED`, so there is no comparison for it to drift out of.

## Code

* commit `8891a05aea65c6d1908a3cf3098c86dc57b366fc` on branch `m14-real-data-validation`
* working tree: no uncommitted change outside `reports/` and `data/` (the code at this commit is the code that runs)
  * `data/raw/control_events.csv`
  * `reports/m19/ablation/ENVIRONMENT.json`
  * `reports/m19/ablation/ENVIRONMENT.md`
* manifest `1764be3cea5a` (built at `ffc31d5`)

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

* `arms.py`: `f6e18fad3812389f27df434e0d7384b6d1dcc6062464443796137ec528c34f40`
* `scoring.py`: `a958d692ee7c26f796b09c1bfe83807c12c8e993562beaad1a476d4e416fb806`

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
