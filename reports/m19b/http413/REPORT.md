# M19b Phase 2 / T2 -- arm B's HTTP 413, characterised

Branch `m19b/http413`. `reports/m19/` was read and never written. Every claim carries a
label: **MEASURED** (this milestone measured it), **VERIFIED FROM CODE** (read from the
source that ran), **PROJECTED** (derived from a measurement by a stated rule),
**HYPOTHESIS**.

## The answer in one paragraph

MEASURED. Arm B's synthesis request on `comiset/CASE-001` was **36,827,172 bytes**. The
API's limit is **33,554,432 bytes (32 MiB) exactly**. Of those 36.8 MB, **36,547,510 --
99.24% -- were the evidence ids of a single claim**, and those ids are the verbatim
output of a single `host_network_activity` call on a corpus with 589,476 network rows.
Conversation history contributed **0 bytes**, because this system has no conversation:
every request is `{system, one user message}` rebuilt from the state. Arm C's synthesis
request on the same case, same telemetry, same prompt template, was **3,984 bytes** --
not because arm C bounds anything, but because arm C's crew never called that tool. The
cause is therefore **pathological tool output**, and the fix is a bound on how much of
one tool result reaches a prompt.

## 1. Reconstruction: what arm B actually sent

`scripts/m19b_http413.py measure` rebuilds each investigation offline. The planner's
answers are replayed from the plan log M19 committed, so the walk is the walk that ran;
synthesis always answers with an empty claim list, which cannot change any request being
measured because it is the last call of the case. Request bytes come from
`ath.agent.llm.build_request_body` / `encode_request_body` -- the same functions
`AnthropicLLM.complete` puts on the wire -- not from a second builder in a script.

**Fidelity check (MEASURED).** For all four reconstructions the rebuilt specialist
claims are identical to the committed M19 row, statement by statement and id-count by
id-count: `fidelity.identical == true` in `measurements.json`. A reconstruction nobody
checked would be a second guess.

### Per-call request sizes

| Arm | Case | Call | Kind | Request bytes | Input tokens | Tool calls so far | Accumulated evidence ids |
|---|---|---|---|---|---|---|---|
| B | comiset/CASE-001 | 1-5 | planner | 1,161 - 1,663 | 375 - 562 (MEASURED) | 0 - 5 | 0 - 589,478 |
| B | comiset/CASE-001 | 6 | synthesis | **36,827,172** | ~23,322,038 (PROJECTED) | 8 | 593,936 |
| B | comiset/CASE-002 | 1-5 | planner | 1,161 - 1,663 | 374 - 561 (MEASURED) | 0 - 4 | 0 - 589,477 |
| B | comiset/CASE-002 | 6 | synthesis | **36,826,399** | ~23,339,594 (PROJECTED) | 6 | 593,935 |
| B | flaws_cloud/CASE-018 | 1-5 | planner | 1,160 - 1,665 | 377 - 562 (MEASURED) | 0 - 4 | 0 - 11,760 |
| B | flaws_cloud/CASE-018 | 6 | synthesis | 297,298 | **154,165 (MEASURED)** | 7 | 11,760 |
| C | comiset/CASE-001 | 1 | synthesis | **3,984** | 1,789 (MEASURED) | 8 | 6 |

Token counts come from `POST /v1/messages/count_tokens` with the frozen headers and
model. The two oversized requests cannot be counted directly -- the counter is itself an
API request subject to the same size limit -- so a 200,000-byte prefix was counted and
scaled linearly; that is labelled PROJECTED and is defensible only because past the
first few hundred bytes the message is one repeated shape. The `chars / 4` rule of thumb
is recorded beside every call in `measurements.json` and under-estimates by about 2.1x
on this input (74,281 approximated against 154,165 measured on CASE-018) -- recorded
rather than used.

### Where the bytes of the synthesis request come from (MEASURED)

| Contribution | comiset/CASE-001 | comiset/CASE-002 | flaws_cloud/CASE-018 | C comiset/CASE-001 |
|---|---|---|---|---|
| Evidence ids (tool output, verbatim) | 36,824,512 | 36,824,144 | 295,088 | 970 |
| Claim statements | 1,482 | 1,125 | 1,080 | 1,739 |
| Line scaffolding | 184 | 138 | 138 | 278 |
| **Conversation history** | **0** | **0** | **0** | **0** |
| System prompt | 787 | 787 | 787 | 787 |

### The largest single tool result (MEASURED)

| Arm / case | Tool | Called by | Event ids returned | Bytes of those ids | Share of the request |
|---|---|---|---|---|---|
| B comiset/CASE-001 | `host_network_activity` | `generalist:host` | 589,476 | 36,547,510 | 99.24% |
| B comiset/CASE-002 | `host_network_activity` | `generalist:host` | 589,476 | 36,547,510 | 99.24% |
| B flaws_cloud/CASE-018 | `user_auth_history` | `generalist:account` | 11,750 | 293,748 | 98.8% |
| C comiset/CASE-001 | `process_tree` | `endpoint` | 4 | 246 | 6.2% |

Second largest on `comiset/CASE-001`: `user_auth_history`, 4,458 ids, 276,394 bytes --
0.75% of the request. Everything that is not those two claims is 1,666 bytes.

## 2. The threshold, and what it counts

`scripts/m19b_http413.py probe` / `confirm`. Frozen endpoint, frozen `anthropic-version`
header, frozen model (`claude-opus-5`), `max_tokens: 1`, a system prompt of filler.
Full log: `probe_log.json`, `probe_confirm.json`, `probe_boundary.json`.

The search exploits a fact that makes it nearly free: ASCII filler tokenises at about
one token per byte (MEASURED: a 1,000,123-byte request counts 1,000,009 input tokens),
so every probe above a megabyte is rejected *before inference* either way -- 400 while
the body is accepted, 413 once it is not. Neither is billed. One deliberate 200 at
2,140 bytes proves the endpoint, headers and model answer this script at all.

| Request bytes | Filler | Status | What the API said |
|---|---|---|---|
| 1,000,140 | A | 400 | prompt is too long: 1000059 tokens > 1000000 maximum |
| 2,000,140 | A | 400 | prompt is too long: 2000059 tokens > 1000000 maximum |
| 4,000,140 | A | 400 | prompt is too long |
| 8,000,140 | A | 400 | prompt is too long |
| 16,000,140 | A | 400 | prompt is too long |
| 32,000,140 | A | 400 | too many total text bytes: 32000002 > 32000000 |
| 64,000,140 | A | **413** | Request exceeds the maximum size |
| 48,000,140 | A | **413** | Request exceeds the maximum size |
| 40,000,140 | A | **413** | Request exceeds the maximum size |
| 36,000,140 | A | **413** | Request exceeds the maximum size |
| 34,000,140 | A | **413** | Request exceeds the maximum size |
| 33,000,140 | A | 400 | too many total text bytes: 33000002 > 32000000 |
| 2,140 | A | 200 | a real success (stop_reason max_tokens) |
| 33,553,432 | A | 400 | too many total text bytes |
| 33,554,332 | A | 400 | too many total text bytes |
| **33,554,431** | A | 400 | too many total text bytes: 33554293 > 32000000 |
| **33,554,432** | A | 400 | too many total text bytes: 33554294 > 32000000 |
| **33,554,433** | A | **413** | Request exceeds the maximum size |
| 33,554,434 | A | **413** | Request exceeds the maximum size |
| 33,553,430 | U+00E9 (5,592,215 chars) | 400 | prompt is too long: 2796168 tokens > 1000000 |
| 33,554,330 | U+00E9 (5,592,365 chars) | 400 | prompt is too long: 2796243 tokens > 1000000 |
| 33,554,528 | U+00E9 (5,592,398 chars) | **413** | Request exceeds the maximum size |
| 33,555,428 | U+00E9 (5,592,548 chars) | **413** | Request exceeds the maximum size |

**MEASURED: the 413 boundary is 33,554,432 bytes -- 32 MiB -- exactly and inclusively.**
The bracket was closed to one byte, far inside the 5% the task asked for.

**MEASURED: it counts bytes of the HTTP request body, not characters and not tokens.**
The multi-byte filler is JSON-escaped to six payload bytes per character, so at the same
payload size it carries six times fewer characters and, per the API's own count, 2,796,243
tokens against 33,554,194 -- and it flips to 413 at the same byte count. A limit counting
characters or tokens would have let it through.

**MEASURED: there are three nested limits, and the 413 is the outermost of them.**

1. HTTP body <= 33,554,432 bytes (32 MiB), else `413 Request exceeds the maximum size`.
2. Total text content <= 32,000,000 bytes (decimal), else `400 too many total text bytes`.
3. Prompt <= 1,000,000 tokens, else `400 prompt is too long`.

Arm B's request violated all three: 36,827,172 body bytes (1.098x limit 1), 36,826,996
text bytes (1.15x limit 2), ~23.3 M projected tokens (23x limit 3). No plausible setting
of any of them would have accepted it.

## 3. Classification

**Pathological tool output.** Exactly one of the five, and the measurements that decide
it:

| Candidate | Verdict | Deciding measurement |
|---|---|---|
| Implementation bug | **No** | The client built and sent a well-formed request; the reconstruction reproduces it byte-for-byte from the shipped `build_request_body`. Nothing malfunctioned. |
| API request-size limit | **No** -- proximate, not the cause | The limit is 32 MiB and generous; the request was 1.098x the body limit, 1.15x the text limit and 23x the context window. A limit is the cause of a rejection only when the request was reasonable. |
| **Pathological tool output** | **Yes** | 36,547,510 of 36,827,172 bytes (99.24%) are one claim's `evidence_ids`, which are one `host_network_activity` return value verbatim: 589,476 ids for a host with 589,476 network rows. Remove that one claim and the request is 279,662 bytes -- 0.83% of the limit. |
| Unbounded context accumulation | **No** | Conversation-history contribution is **0 bytes**, structurally: each request carries one user message rebuilt from the state (VERIFIED FROM CODE -- `AnthropicLLM.complete` sends `messages=[{role, content}]` and nothing else). Across the five planner calls the request *shrinks*, 1,663 to 1,161 bytes. The growth is inside one tool result, not across turns. |
| Inherent architectural scaling | **No** | Arm C on the same case, same corpus, same telemetry hash: 3,984 bytes. Arm B on four other corpora: largest request 297,298 bytes. The same architecture on 21 of 22 cases stayed three orders of magnitude below the limit. |

VERIFIED FROM CODE. `ToolBox.host_network_activity` already truncates its *summary* --
`by_destination.head(15)` -- and returns `event_ids = tuple(rows["event_id"])`
untruncated. The tool bounds what it says and not what it cites; the claim then carries
every id, and `synthesise` rendered every id of every claim. `MAX_SERIALISED_IDS = 5000`
bounds the *results file* and explicitly nothing else, which is why the 372 MB artifact
was caught in M19-2 and the 36.8 MB request was not.

### Why arm C did not hit it on the same case

MEASURED, from the committed M19 rows. Across all 22 cases arm B called
`host_network_activity` **24 times** -- its `host` facet is eligible on every case that
names an unwalked host, and calls the tool unfiltered on the device. Arm C called it
**twice, never on COMISET**; on `comiset/CASE-001` and `CASE-002` only the `endpoint`
and `attack` specialists ran at all.

VERIFIED FROM CODE. `NetworkAgent.has_work` requires the case to carry findings that
evidence the `network_flow` channel. Both COMISET cases are led by process-channel rules
(ATH-002 encoded PowerShell, ATH-012 security-product tampering), so the network
specialist's gate never passed and the tool was never called. When `NetworkAgent` *does*
call it, it passes a `remote_ip` from a finding, which filters the rows.

This is **not** a bounding difference: the rendering path is shared and was unbounded in
both arms, and arm A -- the same crew with no model -- shows the same tool profile as arm
C. **HYPOTHESIS:** arm C would produce the same 413 on a COMISET case whose findings
evidence the network channel with no `remote_ip` to filter on. Untested; M19 contains no
such case.

## 4. The mitigation

`InvestigationConfig.tool_output_budget: int | None = None` -- **off by default**, so the
frozen M19 behaviour is unchanged when it is unset. It bounds the bytes of evidence ids
**one claim** may contribute to the synthesis prompt. Two passes inside that budget:

1. ids another claim also cites, first -- those are the only ids in a long list whose
   loss can cost a cross-claim *relationship*, which is the only thing synthesis is asked
   to find;
2. then the rest in the tool's own order, until the budget is spent.

A truncated list ends with `+589410 more of 589476 not shown`, so the count survives:
"this host made 589,476 connections, here are 66 ids" is a different premise from "this
host made these 66 connections", and the second would be a lie the prompt told on the
system's behalf. Nothing about the tool, the claim, the verifier, the scoring or the
state changes -- only what the prompt renders. No RAG, no vector store, no
context-window change.

Rejected alternatives: bounding the tool's return value would change what the claims
cite and therefore every evidence score in the ablation; bounding history would save
nothing, because history is 0 bytes; paginating `host_network_activity` would fix one
tool and leave `user_auth_history` -- already 293,748 bytes on flaws.cloud -- on the same
path.

### Before and after (MEASURED)

Budget 4,096 bytes per claim. Offline request sizes from `measurements_mitigated.json`;
the run rows from `mitigated/arm_B.json`, whose `ENVIRONMENT.json` asserts this run's
prompt hashes, scoring hashes, request and retry configuration, model ids, step budget,
tool-call cap and tool surface are equal to `reports/m19/ablation/ENVIRONMENT.json` --
the mitigation flag is the one permitted difference.

| | CASE-001 before | CASE-001 after | CASE-002 before | CASE-002 after |
|---|---|---|---|---|
| Synthesis request bytes | 36,827,172 | **11,512** | 36,826,399 | **10,739** |
| share of the 32 MiB limit | 109.8% | 0.034% | 109.8% | 0.032% |
| `llm_degraded` | **true** (HTTP 413) | **false** | **true** (HTTP 413) | **false** |
| Row label | `B_single_llm_DEGRADED` | `B_single_llm` | `B_single_llm_DEGRADED` | `B_single_llm` |
| Tokens (provider-reported) | 2,992 | 12,365 | 3,389 | 12,151 |
| Facts | 8 | 8 | 6 | 6 |
| Inferences | **0** | **3** | **0** | **4** |
| Hypotheses | **0** | **3** | **0** | **2** |
| Rejected claims | 0 | **0** | 0 | **0** |
| Evidence correctness | 1.0 | **1.0** | 1.0 | **1.0** |
| Cited event ids / existing | 593,936 / 593,936 | 593,936 / 593,936 | 593,935 / 593,935 | 593,935 / 593,935 |
| Evidence coverage | 1.0 | 1.0 | 1.0 | 1.0 |
| Planner steps chosen by the model | 5 of 5 | 5 of 5 | 5 of 5 | 5 of 5 |

Twelve synthesis claims were accepted across the two cases and **none was rejected or
discarded as out of scope** -- including claims citing ids that survived only *because*
they were inside the truncated host list (the beacon.exe and lsass.exe outbound
connections). The bound did not cost the model the evidence it reasoned from.

## 5. Reproducible regression

`tests/test_llm_request_size.py`, 16 tests, no network:

* the oversized request rebuilt offline from the committed M19 row weighs exactly
  36,827,172 bytes and exceeds the measured limit by 3,272,740;
* 99% of it is one claim and the statements total under 2 KB -- the measurement that
  distinguishes "pathological tool output" from "accumulated context";
* with the flag off, the rendered prompt is byte-identical to the old expression on five
  committed cases across three corpora and both model arms;
* with the flag on, both COMISET requests fall under 40 KB, every id arm C cited that
  arm B's prompt contained is still present, the omitted count is stated, a shared id is
  never the one dropped, and no claim renders more than the budget;
* the constant the tests assert against is checked against the committed probe log.

One test sends a request. It is skipped unless `ATH_LLM_API_KEY` **and**
`ATH_NETWORK_TESTS=1` are both set, so the default suite never runs it; with both set it
re-measures the boundary with two unbilled rejections.

## 6. Unexpected findings

1. **`max_tokens` was never the problem, and neither was the context window alone.** The
   first plausible reading of a 413 -- "the prompt got long" -- is wrong by an order of
   magnitude: this prompt was 23x the *context window*, which is itself 1,000,000 tokens.
2. **The API rejects at three different thresholds with three different messages**, and
   `_describe_http_error` collapses the outermost into `HTTP 413` with no hint, unlike
   400/401/403/404 which all carry one. 413 is the one status in that map that names a
   fixable property of the request and says nothing about it.
3. **`chars / 4` is not a safe approximation on security telemetry.** On these prompts it
   under-estimates by about 2.1x (74,281 against 154,165 measured). A budget computed
   from it would be twice as loose as intended.
4. **The 400 at 32,000,000 text bytes is a decimal limit nested inside a binary one.** A
   mitigation aimed at "32 MB" would be aimed at the wrong one of the two.
5. **flaws.cloud was already near 1% of the limit and nobody noticed**: `CASE-018` sent a
   297 KB / 154,165-token synthesis request, 75x larger than arm C's request on the same
   experiment's COMISET case, and passed. The 413 was the first case to cross a line, not
   the first case to be pathological.

## 7. Limitations

* The reconstruction replays the planner's committed choices; it does not re-ask a model.
  It reproduces the *requests*, verified claim by claim against the committed row, and
  says nothing about what a model would answer today.
* The ~23.3 M token figure for the two oversized requests is PROJECTED from a
  200,000-byte prefix, because the counter is subject to the same limit. The byte figures
  are exact.
* The threshold was measured on one model id, one endpoint and one key, on one day. It is
  a property of the service, not of this repository, and can move.
* The mitigated run is two cases, once each, reported beside M19 and never averaged into
  it. Whether the six synthesis claims per case are *good* is a question for T1's blinded
  review; what is measured here is that they exist, that the verifier accepted them, and
  that every id they cite exists in the telemetry.
* The budget value 4,096 is a run parameter chosen to sit comfortably inside the limit and
  comfortably above what an analyst reads; it is not a measured optimum.
* **HYPOTHESIS, untested:** arm C hits the same wall on a COMISET case whose findings
  evidence the network channel. M19 contains no such case, so nothing here demonstrates
  that the crew is structurally safer -- only that on these two cases it did not call the
  tool that is unbounded.

## 8. Artifacts and commands

```
reports/m19b/http413/
  REPORT.md                     this file
  measurements.json             per-call sizes, decomposition, fidelity check
  measurements_mitigated.json   the same reconstructions with the budget on
  probe_log.json                the bisection, every status
  probe_confirm.json            the ASCII / multi-byte boundary comparison
  probe_boundary.json           the four probes that pin 33,554,432 exactly
  mitigated/arm_B.json          the two mitigated rows and their scores
  mitigated/ENVIRONMENT.json    the frozen-equality assertion for this run
```

```sh
python scripts/m19b_http413.py measure                  # key used only for count_tokens
python scripts/m19b_http413.py measure --no-network     # fully offline
python scripts/m19b_http413.py probe                    # needs ATH_LLM_API_KEY
python scripts/m19b_http413.py confirm --size 33554431 33554432 33554433 33554434 --filler A
python scripts/m19b_http413.py run --tool-output-budget 4096
python -m pytest -q
```

`scripts/m19_ablation.py run --arm B --corpus comiset --out-dir reports/m19b/http413/mitigated`
was **not** used, and the reason is structural rather than a preference: `cmd_run` calls
`guard_environment`, which refuses any run whose commit differs from the freeze or whose
working tree carries uncommitted changes outside `reports/`. The mitigation is a code
change, so every run this branch can make fails that gate, and weakening the gate to get
past it would defeat the one mechanism that makes M19's arms comparable.
`scripts/m19b_http413.py run` therefore makes the assertion M19b rule 2 actually asks for
-- prompt hashes, scoring hashes, request and retry configuration, model ids and budgets
equal to M19's, with the flag named as the one permitted difference -- writes it into the
run directory, and reuses `m19_ablation`'s own loaders, manifest reader and `run_arm`, so
the rows are built by the code that built M19's.
