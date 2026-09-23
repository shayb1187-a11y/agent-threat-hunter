# Milestone 1: operational investigation policy

## Repository audit and decision

The starting checkout was `6951a77` on `m14-real-data-validation`. The audit found:

| Component | Existing implementation | Milestone 1 action |
| --- | --- | --- |
| Deterministic investigation | Orchestrator, specialists, read-only toolbox, environment gates | Reuse for explicitly model-free operation. |
| D1 investigation | Competing explanations, bounded probe menu, observations and diagnostics | Reuse with an operational policy; do not rewrite D1 v3. |
| Evidence checks | ID existence, permitted claim sources, optional cited-within-shown validation | Enable the existing strict citation check. Semantic support remains a separate milestone. |
| Resource controls | Optional tool caps, budgets, prompt-contract checks | Enable them together through `OperationalProfile`. |
| Completion | An earlier D1 answer can survive a later model failure; tool/probe exhaustion need not be a non-complete state | Classify operational outcomes separately and withhold final model conclusions on incomplete runs. |
| Audit ledger | Optional hashes, but some return paths omit the result and some arguments are summarized | Hash empty/error/refusal results and complete invocation arguments when the ledger is enabled. |
| Research | Experiment specifications, resumability machinery, digest versions, source and identity pins | Preserve the research entry points, defaults, prompts, manifests and scoring. Compatibility tests remain authoritative. |

This milestone establishes an operational composition. It does not establish model
quality, multi-agent superiority, streaming readiness, or production suitability.
Historical M19b and D1 evaluation limitations remain as documented in their reports.

## Usage

From the repository root, using the existing configured normalized telemetry:

```powershell
.\.venv\Scripts\python.exe main.py investigate --profile operational-v1 --no-llm --json reports/local/operational.json
```

Omit `--no-llm` to use the existing configured model client. With a model, the
operational profile uses D1; without one it uses deterministic specialists. The CLI
announces deterministic operation when no model is configured. An explicitly supplied
but unavailable model client in the Python API yields an incomplete investigation.

`--profile legacy` remains the default, preserving the existing command behavior.
`ath-experiment`, evaluation arms, and `ath report` retain their existing configurations;
they do not silently opt in. `--max-steps` applies to either profile; operational-v1
requires at least four steps for its seed, two possible probes, and conclusion.

Operational investigations return CLI exit code **3** if any case is incomplete. JSON
is still written, including its evidence and reasons. Code **0** indicates completed
execution, not a benign security verdict. Existing command-error behavior is unchanged.

Python callers can use local or hosted implementations of the existing `LLMClient`:

```python
from ath.agent.operational import OperationalProfile, investigate_operational
from ath.reporting import build_report

state = investigate_operational(
    case, telemetry, findings,
    llm=client,  # omit for deterministic investigation
    profile=OperationalProfile(),
    environment=environment,
)
report = build_report(state, telemetry)
```

## Effective defaults and output

Each case gets a fresh toolbox, verifier, budget counters, and run UUID. Sharing a
model client across cases does not share their token allowance or tool ledger.

| Control | operational-v1 default |
| --- | --- |
| Investigation steps / evidence probes | 8 / 2 |
| Served tool calls | 64 |
| Existing tool row-list / text caps | 100 rows / 2,048 characters |
| Investigation time | 120 seconds |
| Reported input + output tokens | 24,000 |
| Output tokens per model request | 768 |
| Combined system + user prompt text | 65,536 UTF-8 bytes |
| Reject citations never shown to the model | Enabled |
| Existing prompt-contract check | Enabled |
| Tool argument and result hashes | Enabled |

The Python API accepts validated finite overrides. The effective values, version and
canonical configuration SHA-256 are recorded under
`state.investigation.operational`, along with engine, completion outcome, reasons,
elapsed time, reported tokens, and tool counters. Overrides change the hash. The hash
identifies policy values, not the complete source tree or model configuration; this
is not a replacement for the experiment freeze machinery.

The 64-call default accommodates the local deterministic CASE-001, which requests
43 calls. A 40-call trial correctly returned incomplete with three refusals. CASE-002
uses six calls. Existing duplicate specialist lookups are retained for compatibility;
optimizing them is separate from setting an adequate finite operational allowance.

An incomplete run retains deterministic observations, rejected claims, tool records
and provisional model output in its audit history. Its reportable model claims are
withheld and its final model disposition is `abstain`. The original engine status and
model disposition are explicitly preserved as diagnostics. The report builder adds
an incomplete-investigation limitation and labels provisional conclusion notes.

Triggers include model failure, invalid replies, unavailable usage accounting,
failed evidence verification, refused tools, and termination with requested work
remaining. Exceeding time or tokens on the **last** reply is also detected.
Successful execution may itself conclude `abstain`; uncertainty is not a runtime error.

## Boundaries and remaining work

- The verifier establishes citation integrity and allowed claim provenance. It does
  not establish that an event supports a sentence, that a detector is correct, or that
  temporal proximity proves causation. The separately versioned
  [operational-v2 profile](evidence-verification.md) adds typed evidence assertions.
- Time limits are checked by the engines and passed as request timeouts. They do not
  preempt CPU-bound pandas work or a client that ignores its timeout. A late reply is
  marked incomplete. Hard deadlines require cancellable worker isolation later.
- Token limits use reported usage and stop further calls. Prompt token cost and an
  in-flight request can exceed the allowance; no strict billing ceiling is claimed.
  Missing input or output usage stops the operational model path.
- Existing row/text caps cover selected toolbox result collections, not every nested
  field or every computation. The aggregate prompt-text byte check prevents oversized
  prompts being sent. It does not cap JSON transport overhead, whole-dataset memory,
  the audit artifact, or provider response-body allocation.
- The prompt-contract check detects forbidden schema field names. It is not a proof
  of prompt-injection resistance; a matching word in otherwise legitimate telemetry
  may conservatively stop a run. Applying untrusted-text envelopes throughout D1 is
  a separately versioned prompt change.
- Tool hashes support comparison of arguments and returned payloads. They are not
  signatures, immutable storage, or a tamper-proof chain. Durable jobs, attempts and
  report revisions are [milestone 4](persistence-and-background-execution.md); source
  retention remains out of scope.

## Acceptance checks

`tests/test_operational.py` exercises deterministic and scripted-model success,
per-case isolation, unseen citations, output caps, prompt rejection, model failures
after a successful probe, missing usage, late final replies, exhausted budgets,
ledger coverage and CLI/JSON/report behavior. Existing safeguard tests and frozen
source/identity/surface checks must pass without regenerating their fixtures.

Run with the repository's Python 3.11 virtual environment, not the machine's default
Python 3.9 (the package requires Python 3.10 or newer):

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests scripts
```
