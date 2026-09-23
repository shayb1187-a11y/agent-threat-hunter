# Structured evidence verification (operational step 2)

`operational-v2` checks explicit telemetry predicates and separates those observations
from detector summaries and model interpretations. Existing legacy and operational-v1
behavior, frozen D1 prompts, and experiment scoring remain unchanged.

```powershell
.\.venv\Scripts\python.exe main.py investigate --profile operational-v2 --no-llm --json reports/evidence.json
# Omit --no-llm to use the configured model.
```

The profile inherits operational-v1's limits, ledger, retrieval requirements and
incomplete outcomes. Its output allowance is 1,536 tokens to accommodate assertions.
An unsupported typed premise rejects the claim and makes the operational result
incomplete, with disposition `abstain`. The report retains the rejection reason.

## Checked predicates

| Predicate | What is established |
| --- | --- |
| `auth_outcome` | The cited authentication event records exactly success or failure. |
| `process_identity` | The event records the stated source-qualified instance identity. |
| `same_process` | Both events carry matching comparable instance identities on the same host, without conflicting PIDs. |
| `parent_child` | The child's recorded parent identity matches the parent event, on the same host, without conflicting PIDs or reversed process-start times. |
| `before` | The first recorded timestamp strictly precedes the second; this makes no causal claim. |

Every check returns `supported`, `contradicted`, or `unverifiable`. Missing fields,
duplicate event IDs, and incomparable identity authorities are unverifiable. Matching
PIDs alone never prove a process relationship. These checks assume normalized source
telemetry; they do not authenticate the source or prove its clock is accurate.

Model explanations supply an `assertions` array. Each assertion's IDs must also be
cited by that explanation and retrieved in the investigation. For example:

```json
{"kind": "auth_outcome", "event_id": "an-actual-event-id", "expected": "success"}
```

A real failed-login event cannot support that predicate. An empty array is allowed
but explicitly leaves the interpretation with reference checks only. Typed checks
do not verify every sentence in free text; a model that omits its premise has not
provided a semantically verified explanation.

## Report behavior

Only template-rendered, checked assertions become `FACT`. Existing unstructured
detector/tool summaries become `INFERENCE`, prefixed `Unverified summary:`. Model
attack interpretations remain inferences even when their attached predicates pass.
JSON and Markdown expose the predicate results and this limitation.

The verifier also builds authentication, identity and parent-child observations from
events already returned by row-bearing tools. This enrichment applies equally to
deterministic and model investigations. It considers at most 100 distinct retrieved
events, ordered by ID, and reports the omitted count. Omission is not negative evidence.
No extra investigative tools or model calls are made for these checks.

The v2 menu calls the internal source identity argument `instance` in its presentation;
execution retains the original bound process identity. The prompt contract stays on.
System-prompt and schema hashes identify this extension separately from frozen D1.

Tests: `tests/test_evidence_verification.py`, including false-authentication premises,
PID reuse, cross-host identity, missing identities, duplicate IDs, chronology,
unretrieved citations, arbitrary prose disguised as FACT, and end-to-end reports.

The next evaluation is documented in [authentication-to-execution evaluation](auth-execution-evaluation.md).
