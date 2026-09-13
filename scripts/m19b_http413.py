"""M19b-T2: what arm B actually sent when the API answered 413, and what fixes it.

Three subcommands, in the order the task was done:

``measure``
    Rebuilds arm B's and arm C's investigations of named cases **offline** and records
    the size of every request the orchestrator would have sent. No network, no key, no
    model: the planner's answers are replayed from the plan log M19 already committed
    (``reports/m19/ablation/arm_*.json``), so the walk is the walk that ran and the
    prompts are the prompts that were built. The claims the reconstruction produces are
    diffed against the recorded ones, and the diff is written into the artifact -- a
    reconstruction nobody checked is a second guess, not a measurement.

``probe``
    Finds the provider's actual request-size limit by binary search: a system prompt of
    N bytes of filler, ``max_tokens`` 1, the frozen endpoint, headers and model. Every
    response status is logged. Needs ``ATH_LLM_API_KEY``; a 413 is not billed and
    ``max_tokens=1`` bounds what the successes cost.

``run``
    Arm B over named cases with the mitigation flag on, into its own directory, with an
    ``ENVIRONMENT.json`` that asserts the frozen prompt, scoring, budget and model
    values are still M19's. It does not go through ``scripts/m19_ablation.py run``:
    that command's ``guard_environment`` refuses any run whose commit or working tree
    differs from the freeze, which is every run this branch can make. The assertion
    M19b rule 2 actually asks for -- equality of prompt, scoring, budget and model
    hashes -- is made here instead, and recorded beside the rows.

Nothing here writes under ``reports/m19/``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import m19_ablation  # noqa: E402

from ath.agent.claims import ClaimVerifier  # noqa: E402
from ath.agent.generalist import build_generalist_crew  # noqa: E402
from ath.agent.llm import (  # noqa: E402
    ANTHROPIC_VERSION,
    API_ENDPOINT,
    LLMResponse,
    build_request_body,
    encode_request_body,
    request_measurement,
)
from ath.agent.orchestrator import (  # noqa: E402
    PLANNER_SYSTEM,
    SYNTHESIS_SYSTEM,
    InvestigationOrchestrator,
)
from ath.agent.tools import ToolBox  # noqa: E402
from ath.evaluation.ablation import ARM_BUILDERS, CaseResult, aggregate, run_arm  # noqa: E402
from ath.evaluation.ablation.arms import ARM_B, ARM_C  # noqa: E402
from ath.evaluation.ablation.environment import (  # noqa: E402
    ENVIRONMENT_JSON,
    arm_environment,
    prompt_hashes,
    request_configuration,
    retry_policy,
    scoring_hashes,
)

M19_DIR = ROOT / "reports" / "m19" / "ablation"
OUT_DIR = ROOT / "reports" / "m19b" / "http413"

COUNT_TOKENS_ENDPOINT = "https://api.anthropic.com/v1/messages/count_tokens"
"""The Messages API's token counter, called with the frozen headers and model.

Used in preference to any local estimate, because the only authority on how many tokens
a request costs is the thing that charges for them.
"""

COUNT_TOKENS_CEILING = 400_000
"""Largest request, in bytes, this script will hand to ``count_tokens``.

The counter is itself an API request and is subject to the same size limit as the call
it is counting -- so counting the 33 MB request directly is not possible, which is the
whole problem restated. Above this, a prefix of the user message is counted and the
result is scaled; the artifact labels that number PROJECTED, never MEASURED.
"""

COUNT_TOKENS_PREFIX_BYTES = 200_000
"""Bytes of the user message counted when the whole message is too large to count.

Scaling is linear and is defensible **only** because the region being scaled is
homogeneous: past the first few hundred bytes the oversized message is one repeated
shape, ``comiset_slice.jsonl:<40 hex chars>, ``. A prefix of a heterogeneous prompt
would not license this and the artifact would have to say so.
"""

APPROX_BYTES_PER_TOKEN = 4.0
"""The documented fallback approximation: one token per four characters.

Recorded for every call beside the measured count, so a reader can see how wrong the
rule of thumb is on this input rather than take it on faith. On these prompts it is
wrong in a specific direction -- a 40-character hex id is not four-character English --
and the artifact reports both numbers rather than choosing.
"""


# --------------------------------------------------------------------------------------
# Replaying a committed run without a network
# --------------------------------------------------------------------------------------


def planner_choices(row: dict[str, Any]) -> list[str]:
    """The specialists the model chose, in order, from a committed row's plan log.

    The orchestrator consults the model only on a step with more than one eligible
    candidate, and writes ``step N: <name> -- planner: <reason>`` when it acted on the
    answer. Those lines, in order, are exactly the answers that have to be replayed for
    the walk to be the walk that ran; a step the model was never asked about carries
    ``only eligible specialist`` and consumes nothing.
    """
    choices: list[str] = []
    for line in row["state"]["plan_log"]:
        if " -- planner: " not in line or not line.startswith("step "):
            continue
        choices.append(line.split(": ", 1)[1].split(" -- ", 1)[0])
    return choices


@dataclass
class ReplayLLM:
    """A client that answers from a committed run and never opens a socket.

    ``available`` is True because the arm under measurement is an arm that had a model:
    an orchestrator told there is no model plans differently, and a reconstruction that
    plans differently reconstructs nothing. What it returns is not a model's output and
    is never scored -- the planner answers are the ones M19 recorded, and synthesis
    always answers with an empty claim list, because the synthesis request is the last
    call of the case and its *reply* cannot change any request this script measures.
    """

    choices: list[str] = field(default_factory=list)
    name: str = "replay-no-network"
    available: bool = True
    observer: Callable[[str, str, str, dict[str, Any]], None] | None = None
    model: str = ""
    _index: int = 0

    def complete(self, system: str, prompt: str, max_tokens: int = 1024) -> LLMResponse:
        kind = "synthesis" if system == SYNTHESIS_SYSTEM else "planner"
        if kind == "planner" and system != PLANNER_SYSTEM:  # pragma: no cover
            raise AssertionError(
                "the orchestrator sent a system prompt that is neither the planner's "
                "nor the synthesiser's; the reconstruction cannot say what it measured"
            )
        body = build_request_body(
            model=self.model, max_tokens=max_tokens, system=system, prompt=prompt,
        )
        measurement = request_measurement(body, encode_request_body(body))
        measurement["kind"] = kind
        if self.observer is not None:
            self.observer(kind, system, prompt, measurement)
        if kind == "synthesis":
            return _canned('{"claims": []}')
        if self._index < len(self.choices):
            choice = self.choices[self._index]
            self._index += 1
        else:  # pragma: no cover -- a walk longer than the one recorded
            choice = "none"
        return _canned(json.dumps({
            "next_agent": choice,
            "reason": "replayed from the M19 plan log; not a model's answer",
        }))


def _canned(text: str) -> LLMResponse:
    return LLMResponse(
        text=text, model="replay-no-network", parsed=json.loads(text),
        stop_reason="end_turn",
    )


class ObservedOrchestrator(InvestigationOrchestrator):
    """The orchestrator, with the live state reachable from the client's observer.

    ``plan`` and ``synthesise`` are the only two nodes that call the model, and both are
    handed the state, so stashing it in the override is enough to let a measurement
    taken inside ``complete`` say how many tool calls had been made and how much
    evidence had accumulated *at that moment*. Nothing about the run changes.
    """

    current_state: Any = None

    def plan(self, state):  # type: ignore[override]
        self.current_state = state
        return super().plan(state)

    def synthesise(self, state):  # type: ignore[override]
        self.current_state = state
        return super().synthesise(state)


# --------------------------------------------------------------------------------------
# Decomposing one synthesis request
# --------------------------------------------------------------------------------------

CLAIM_LINE_OVERHEAD = len("- [] " + " (evidence: )")
"""Fixed bytes per rendered claim line, excluding the statement and the ids."""


def decompose_claims(state: Any, budget: int | None = None) -> dict[str, Any]:
    """Where the bytes of a synthesis user message come from.

    Three buckets, and the third is the point of the exercise:

    * **claims** -- the statements the specialists wrote, plus the line scaffolding.
    * **tool output** -- the evidence id lists. These are not a summary of a tool
      result; they *are* the tool result, one id per row the tool matched, restated
      verbatim in the prompt.
    * **conversation history** -- zero, always. Every call this system makes carries one
      user message built fresh from the state; no prior request or reply is resent.
      Reported rather than omitted, because "the context grew across turns" is the
      explanation a reader will reach for first and it is not what happened here.
    """
    per_claim: list[dict[str, Any]] = []
    for claim in state.claims:
        ids = list(claim.evidence_ids)
        id_bytes = len(", ".join(ids).encode("utf-8"))
        statement_bytes = len(claim.statement.encode("utf-8"))
        per_claim.append({
            "agent": claim.agent,
            "type": claim.claim_type.value,
            "statement_bytes": statement_bytes,
            "evidence_ids": len(ids),
            "evidence_id_bytes": id_bytes,
            "line_bytes": statement_bytes + id_bytes + CLAIM_LINE_OVERHEAD
            + len(claim.claim_type.value),
        })
    evidence_bytes = sum(c["evidence_id_bytes"] for c in per_claim)
    statement_bytes = sum(c["statement_bytes"] for c in per_claim)
    scaffold = sum(
        CLAIM_LINE_OVERHEAD + len(c["type"]) + 1 for c in per_claim
    )
    largest = max(per_claim, key=lambda c: c["evidence_id_bytes"], default=None)
    return {
        "claims": len(per_claim),
        "describes": (
            "the claims as they stand on the state, before any rendering bound. With a "
            "budget set these figures are what the prompt *would* have carried unbounded; "
            "what it actually carried is the call's request_bytes."
            if budget is not None else
            "the claims as they stand on the state, which with no budget set is exactly "
            "what the prompt carried"
        ),
        "rendered_under_budget": budget,
        "tool_output_bytes": evidence_bytes,
        "claim_statement_bytes": statement_bytes,
        "scaffolding_bytes": scaffold,
        "conversation_history_bytes": 0,
        "conversation_history_note": (
            "structurally zero: every request is {system, one user message} built from "
            "the state; no earlier request or reply is ever resent"
        ),
        "largest_claim": largest,
        "per_claim": per_claim,
    }


def tool_call_sizes(state: Any) -> dict[str, Any]:
    """Every tool call's result size, and the largest one."""
    calls = [
        {
            "tool": call.tool,
            "agent": call.agent,
            "arguments": {k: str(v) for k, v in call.arguments.items()},
            "event_ids": len(call.event_ids),
            "event_id_bytes": len(", ".join(call.event_ids).encode("utf-8")),
            "refused": bool(call.refused),
        }
        for call in state.tool_calls
    ]
    largest = max(calls, key=lambda c: c["event_id_bytes"], default=None)
    return {"tool_calls": len(calls), "largest_tool_result": largest, "calls": calls}


# --------------------------------------------------------------------------------------
# Token counting
# --------------------------------------------------------------------------------------


def _api_key() -> str | None:
    return os.getenv("ATH_LLM_API_KEY") or None


def count_tokens(
    model: str, system: str, prompt: str, *, key: str
) -> tuple[int | None, str, int | None]:
    """``(input_tokens, how, status)`` from the provider's counter.

    ``how`` is ``"measured"`` when the whole request was counted and
    ``"projected-from-prefix"`` when it was too large to send and a prefix was scaled.
    """
    body = {
        "model": model,
        "system": system,
        "messages": [{"role": "user", "content": prompt}],
        "thinking": {"type": "adaptive"},
    }
    payload = encode_request_body(body)
    if len(payload) <= COUNT_TOKENS_CEILING:
        counted, status = _count(payload, key)
        return counted, "measured", status
    encoded = prompt.encode("utf-8")
    prefix = encoded[:COUNT_TOKENS_PREFIX_BYTES].decode("utf-8", errors="ignore")
    body["messages"] = [{"role": "user", "content": prefix}]
    counted, status = _count(encode_request_body(body), key)
    if counted is None:
        return None, "unavailable", status
    scale = len(encoded) / max(1, len(prefix.encode("utf-8")))
    return int(counted * scale), "projected-from-prefix", status


def _count(payload: bytes, key: str) -> tuple[int | None, int | None]:
    request = urllib.request.Request(
        COUNT_TOKENS_ENDPOINT, data=payload,
        headers={
            "content-type": "application/json",
            "x-api-key": key,
            "anthropic-version": ANTHROPIC_VERSION,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            body = json.loads(response.read().decode("utf-8"))
        value = body.get("input_tokens")
        return (value if isinstance(value, int) else None), 200
    except urllib.error.HTTPError as exc:
        return None, exc.code
    except Exception:  # noqa: BLE001 -- an unavailable counter is a fact, not a crash
        return None, None


def approximate_tokens(measurement: dict[str, Any]) -> int:
    chars = int(measurement["system_chars"]) + int(measurement["user_chars"])
    return int(chars / APPROX_BYTES_PER_TOKEN)


# --------------------------------------------------------------------------------------
# measure
# --------------------------------------------------------------------------------------

TARGETS: tuple[tuple[str, str, str], ...] = (
    ("B", "comiset", "CASE-001"),
    ("B", "comiset", "CASE-002"),
    ("B", "flaws_cloud", "CASE-018"),
    ("C", "comiset", "CASE-001"),
)
"""The two degraded cases, one arm B case that was not degraded, and arm C's contrast."""


def _committed_rows(letter: str) -> dict[tuple[str, str], dict[str, Any]]:
    payload = json.loads((M19_DIR / f"arm_{letter}.json").read_text(encoding="utf-8"))
    return {(r["corpus"], r["case_id"]): r for r in payload["cases"]}


def reconstruct(
    letter: str,
    corpus: str,
    case_id: str,
    bundle: Any,
    row: dict[str, Any],
    *,
    key: str | None,
    tool_output_budget: int | None = None,
) -> dict[str, Any]:
    """One case, replayed offline, with every request it would have sent measured."""
    arm = ARM_BUILDERS[ARM_B if letter == "B" else ARM_C]()
    if tool_output_budget is not None:
        arm = replace(
            arm, config=replace(arm.config, tool_output_budget=tool_output_budget)
        )
    case = next(c for c in bundle.cases if c.case_id == case_id)
    tools = ToolBox(
        bundle.telemetry, list(bundle.findings), list(bundle.cases),
        tool_call_budget=arm.tool_call_cap,
    )
    crew = build_generalist_crew(tools) if arm.generalist else None
    client = ReplayLLM(choices=planner_choices(row), model=str(arm.model))
    orchestrator = ObservedOrchestrator(
        tools, ClaimVerifier(bundle.telemetry), llm=client, config=arm.config,
        environment=bundle.environment, specialists=crew,
    )

    calls: list[dict[str, Any]] = []

    def observe(kind: str, system: str, prompt: str, measurement: dict[str, Any]) -> None:
        state = orchestrator.current_state
        record: dict[str, Any] = dict(measurement)
        record["call_index"] = len(calls) + 1
        record["state_at_call"] = {
            "step": state.step,
            "agents_run": list(state.agents_run),
            "claims": len(state.claims),
            "tool_calls": len(state.tool_calls),
            "accumulated_evidence_ids": len(state.evidence_ids),
            "accumulated_evidence_id_bytes": len(
                ", ".join(sorted(state.evidence_ids)).encode("utf-8")
            ),
        }
        if kind == "synthesis":
            record["decomposition"] = decompose_claims(state, tool_output_budget)
            record["tools"] = tool_call_sizes(state)
        if key:
            counted, how, status = count_tokens(
                str(arm.model), system, prompt, key=key,
            )
            record["input_tokens"] = counted
            record["input_tokens_source"] = how
            record["count_tokens_status"] = status
        else:
            record["input_tokens"] = None
            record["input_tokens_source"] = "unavailable (no ATH_LLM_API_KEY)"
        record["approx_input_tokens_chars_over_4"] = approximate_tokens(measurement)
        calls.append(record)

    client.observer = observe
    started = time.perf_counter()
    state = orchestrator.investigate(case)
    elapsed = time.perf_counter() - started

    return {
        "arm": arm.name,
        "corpus": corpus,
        "case_id": case_id,
        "tool_output_budget": tool_output_budget,
        "m19_llm_status": row["llm_status"],
        "m19_llm_degraded": bool(row["llm_degraded"]),
        "fidelity": fidelity(state, row),
        "wall_seconds": round(elapsed, 2),
        "calls": calls,
        "largest_request_bytes": max((c["request_bytes"] for c in calls), default=0),
        "total_request_bytes": sum(c["request_bytes"] for c in calls),
    }


def fidelity(state: Any, row: dict[str, Any]) -> dict[str, Any]:
    """Did the offline replay rebuild the run that ran?

    Compares the specialist claims -- statement and evidence-id count -- against the
    committed row, ignoring the model's own synthesis claims, which no replay can or
    should reproduce. A mismatch here invalidates every byte this script reports, so it
    is computed and written rather than assumed.
    """
    recorded = [
        (c["statement"], len(c["evidence_ids"]) + int(c.get("evidence_ids_omitted") or 0))
        for c in row["state"]["claims"] if c.get("agent") != "synthesis"
    ]
    rebuilt = [
        (c.statement, len(c.evidence_ids)) for c in state.claims if c.agent != "synthesis"
    ]
    return {
        "recorded_claims": len(recorded),
        "rebuilt_claims": len(rebuilt),
        "identical": recorded == rebuilt,
        "differences": [
            {"recorded": a, "rebuilt": b}
            for a, b in zip(recorded, rebuilt) if a != b
        ][:5],
        "plan_log_steps_replayed": len(planner_choices(row)),
    }


def cmd_measure(args: argparse.Namespace) -> int:
    key = _api_key() if not args.no_network else None
    targets = [t for t in TARGETS if not args.case or f"{t[1]}/{t[2]}" in args.case]
    by_corpus: dict[str, list[tuple[str, str, str]]] = {}
    for target in targets:
        by_corpus.setdefault(target[1], []).append(target)

    rows = {letter: _committed_rows(letter) for letter in ("B", "C")}
    measured: list[dict[str, Any]] = []
    for bundle in m19_ablation.load_bundles(sorted(by_corpus)):
        if bundle.name not in by_corpus:
            continue
        for letter, corpus, case_id in by_corpus[bundle.name]:
            print(f"measuring arm {letter} on {corpus}/{case_id} ...", flush=True)
            measured.append(reconstruct(
                letter, corpus, case_id, bundle, rows[letter][(corpus, case_id)],
                key=key, tool_output_budget=args.tool_output_budget,
            ))

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "head": m19_ablation._head(),
        "method": {
            "network": "none for the reconstruction; the planner replays the committed "
                       "M19 plan log and synthesis always answers with an empty claim "
                       "list",
            "request_bytes": "ath.agent.llm.build_request_body + encode_request_body, "
                             "the same functions AnthropicLLM.complete sends",
            "input_tokens": (
                "POST /v1/messages/count_tokens with the frozen headers and model where "
                "the request fits under "
                f"{COUNT_TOKENS_CEILING} bytes; otherwise a {COUNT_TOKENS_PREFIX_BYTES}"
                "-byte prefix is counted and scaled linearly (labelled "
                "projected-from-prefix)"
            ),
            "approximation": (
                f"chars / {APPROX_BYTES_PER_TOKEN} is reported beside every measured "
                "count as the documented fallback, never instead of one"
            ),
        },
        "cases": measured,
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / args.out_name
    out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    print(f"wrote {out}")
    for case in measured:
        print(
            f"  {case['arm']} {case['corpus']}/{case['case_id']}: "
            f"largest request {case['largest_request_bytes'] / 1e6:.3f} MB "
            f"over {len(case['calls'])} call(s); "
            f"fidelity identical={case['fidelity']['identical']}"
        )
    return 0


# --------------------------------------------------------------------------------------
# probe
# --------------------------------------------------------------------------------------


def _envelope_bytes(model: str) -> int:
    """Payload bytes of the probe request with an empty system prompt."""
    return len(encode_request_body(build_request_body(
        model=model, max_tokens=1, system="", prompt="hi",
    )))


def _filler_cost(filler: str) -> int:
    """Payload bytes one filler character costs, after JSON escaping.

    ``json.dumps`` escapes non-ASCII, so ``é`` costs six payload bytes and one
    character. That is the lever the bytes-versus-tokens test pulls: at a fixed payload
    size the multi-byte filler carries six times fewer characters, and therefore roughly
    six times fewer tokens, than the ASCII one.
    """
    return len(json.dumps(filler)) - 2


def probe_once(
    size: int, key: str, model: str, *, filler: str = "A"
) -> dict[str, Any]:
    """One request whose payload is as close to ``size`` bytes as the filler allows.

    ``max_tokens`` is 1 and the prompt asks for nothing, so a success costs one output
    token; a 413 is rejected before inference and is not billed at all, and neither is
    the 400 an over-long prompt earns.
    """
    cost = _filler_cost(filler)
    characters = max(1, (size - _envelope_bytes(model)) // cost)
    system = filler * characters
    body = build_request_body(
        model=model, max_tokens=1, system=system, prompt="hi",
    )
    payload = encode_request_body(body)
    request = urllib.request.Request(
        API_ENDPOINT, data=payload,
        headers={
            "content-type": "application/json",
            "x-api-key": key,
            "anthropic-version": ANTHROPIC_VERSION,
        },
    )
    started = time.perf_counter()
    record: dict[str, Any] = {
        "request_bytes": len(payload),
        "system_bytes": len(system.encode("utf-8")),
        "system_chars": len(system),
        "filler": filler,
        "bytes_per_filler_char": len(filler.encode("utf-8")),
    }
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            body_text = response.read().decode("utf-8")
        record["status"] = 200
        parsed = json.loads(body_text)
        record["stop_reason"] = parsed.get("stop_reason")
        record["usage"] = parsed.get("usage")
    except urllib.error.HTTPError as exc:
        record["status"] = exc.code
        try:
            record["error"] = json.loads(exc.read().decode("utf-8"))
        except Exception:  # noqa: BLE001
            record["error"] = None
    except Exception as exc:  # noqa: BLE001
        record["status"] = None
        record["error"] = f"{type(exc).__name__}: {exc}"
    record["seconds"] = round(time.perf_counter() - started, 2)
    return record


def cmd_probe(args: argparse.Namespace) -> int:
    key = _api_key()
    if not key:
        print("ATH_LLM_API_KEY is not set; the probe needs the real endpoint.",
              file=sys.stderr)
        return 2
    model = args.model
    log: list[dict[str, Any]] = []

    def attempt(size: int, filler: str = "A") -> dict[str, Any]:
        record = probe_once(size, key, model, filler=filler)
        log.append(record)
        print(
            f"  {record['request_bytes']:>12,} bytes ({filler!r} filler) -> "
            f"{record['status']}", flush=True,
        )
        return record

    # What counts as "accepted" here is *not* 200. Above roughly a million tokens the
    # API answers 400 (the prompt exceeds the context window) -- a rejection, but one
    # that happened *after* the body was accepted and tokenised, which is exactly the
    # boundary being searched for. ASCII filler tokenises at about one token per byte
    # (measured: 1,000,009 tokens for a 1,000,123-byte request), so every probe above a
    # megabyte is a 400 until the transport-level size limit takes over and answers 413
    # instead. That is the fact this search exploits, and it is why the search is nearly
    # free: a 400 and a 413 are both rejected before inference and neither is billed.
    def transport_accepted(record: dict[str, Any]) -> bool:
        return record["status"] != 413

    low = args.start
    attempt(low)
    high = low
    while True:
        high = min(high * 2, args.ceiling)
        record = attempt(high)
        if not transport_accepted(record) or high >= args.ceiling:
            break
        low = high

    while (high - low) / max(1, low) > args.precision:
        middle = (low + high) // 2
        record = attempt(middle)
        if record["status"] is None:
            print(f"  no status (transport error); stopping the bisection")
            break
        if transport_accepted(record):
            low = middle
        else:
            high = middle

    # One real success, well under the boundary, so the log contains proof that the
    # frozen endpoint, headers and model answer this script at all -- a search that only
    # ever recorded rejections could be searching a typo.
    attempt(2_000)

    # Bytes or tokens? At a fixed payload size the multi-byte filler carries six times
    # fewer characters -- and this input tokenises at roughly one token per character --
    # so a limit counting tokens would let it through where the ASCII one is rejected.
    multibyte_low = attempt(low, filler="é")
    multibyte = attempt(high, filler="é")
    ascii_at_high = [r for r in log if r["filler"] == "A" and r["status"] == 413]

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "endpoint": API_ENDPOINT,
        "model": model,
        "anthropic_version": ANTHROPIC_VERSION,
        "max_tokens": 1,
        "largest_accepted_bytes": low,
        "smallest_rejected_bytes": high,
        "accepted_means": (
            "the body was accepted by the transport and answered by the API -- 200, or "
            "400 because the prompt exceeded the context window. Only 413 counts as a "
            "size rejection."
        ),
        "relative_gap": (high - low) / max(1, low),
        "unit_test": {
            "question": "does the limit count bytes, characters or tokens?",
            "multibyte_below": {
                "request_bytes": multibyte_low["request_bytes"],
                "system_chars": multibyte_low["system_chars"],
                "status": multibyte_low["status"],
            },
            "multibyte_above": {
                "request_bytes": multibyte["request_bytes"],
                "system_chars": multibyte["system_chars"],
                "status": multibyte["status"],
            },
            "smallest_ascii_rejection_bytes": min(
                (r["request_bytes"] for r in ascii_at_high), default=None
            ),
        },
        "attempts": log,
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / "probe_log.json"
    out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    print(f"wrote {out}")
    print(f"largest accepted {low:,} bytes; smallest rejected {high:,} bytes")
    return 0


# --------------------------------------------------------------------------------------
# run -- the mitigated arm B, in its own directory, with its own freeze assertion
# --------------------------------------------------------------------------------------


def frozen_equality(out_dir: Path) -> dict[str, Any]:
    """Assert this run's prompts, scoring, budgets and models are M19's.

    M19b rule 2: an M19b run directory carries its own ``ENVIRONMENT.json`` whose
    prompt, scoring, budget and model hashes are asserted equal to M19's -- the commit
    may differ, and on this branch it must, because the mitigation is a code change.
    The assertion is the point, so a difference raises rather than being noted.
    """
    frozen = json.loads((M19_DIR / ENVIRONMENT_JSON).read_text(encoding="utf-8"))
    arms = {name: ARM_BUILDERS[name]() for name in (ARM_B, ARM_C)}
    live = {
        "prompts": prompt_hashes(),
        "scoring": scoring_hashes(),
        "request": request_configuration(),
        "retry": retry_policy(),
        "arms": {name: arm_environment(arm) for name, arm in arms.items()},
    }
    differences: list[str] = []
    for field_name in ("prompts", "scoring"):
        for key in sorted(set(frozen.get(field_name, {})) | set(live[field_name])):
            if frozen.get(field_name, {}).get(key) != live[field_name].get(key):
                differences.append(
                    f"{field_name}.{key}: frozen "
                    f"{str(frozen.get(field_name, {}).get(key))[:12]}, now "
                    f"{str(live[field_name].get(key))[:12]}"
                )
    for name, arm in live["arms"].items():
        recorded = (frozen.get("arms") or {}).get(name) or {}
        for key in ("model", "max_steps", "tool_call_cap", "use_llm_planner",
                    "use_llm_synthesis", "generalist", "tool_surface"):
            if recorded.get(key) != arm.get(key):
                differences.append(
                    f"arms.{name}.{key}: frozen {recorded.get(key)!r}, now "
                    f"{arm.get(key)!r}"
                )
    if frozen.get("request") != live["request"] or frozen.get("retry") != live["retry"]:
        differences.append("request/retry configuration differs from the freeze")
    if differences:
        raise SystemExit(
            "this run is not the frozen experiment apart from the mitigation:\n  "
            + "\n  ".join(differences)
        )
    return {
        "asserted_equal_to": str(M19_DIR / ENVIRONMENT_JSON),
        "fields": ["prompts", "scoring", "request", "retry",
                   "arms.model/budgets/tool_surface"],
        "frozen_commit": frozen.get("git", {}).get("commit"),
        "running_commit": m19_ablation._head(),
        "permitted_difference": (
            "InvestigationConfig.tool_output_budget, the M19b Phase 2 mitigation, which "
            "is None (off) everywhere else and changes no prompt template, no scoring "
            "code, no budget and no model id"
        ),
        **live,
    }


def cmd_run(args: argparse.Namespace) -> int:
    key = _api_key()
    if not key:
        print("ATH_LLM_API_KEY is not set; arm B requires a model.", file=sys.stderr)
        return 2
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    environment = frozen_equality(out_dir)
    environment["tool_output_budget"] = args.tool_output_budget
    (out_dir / ENVIRONMENT_JSON).write_text(
        json.dumps(environment, indent=2, default=str), encoding="utf-8"
    )

    payload, entries, digest = m19_ablation._read_manifest(M19_DIR)
    wanted = {f"{c}" for c in args.case}
    selected = [
        e for e in entries
        if e.corpus == args.corpus and (not wanted or e.case_id in wanted)
    ]
    if not selected:
        raise SystemExit(f"no manifest entry matches {args.corpus} {sorted(wanted)}")

    arm = ARM_BUILDERS[ARM_B]()
    arm = replace(
        arm, config=replace(arm.config, tool_output_budget=args.tool_output_budget)
    )
    results: list[CaseResult] = []
    for bundle in m19_ablation.load_bundles([args.corpus.split(":", 1)[0]]):
        if bundle.name != args.corpus:
            continue
        results += run_arm(
            arm, selected, bundle.telemetry, bundle.cases, manifest_digest=digest,
            findings=bundle.findings, environment=bundle.environment,
        )

    record = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "head": m19_ablation._head(),
        "arm": arm.to_dict(),
        "mitigation": {
            "tool_output_budget": args.tool_output_budget,
            "note": (
                "M19b Phase 2. OFF by default; this run set it. Everything else is the "
                "M19 freeze, asserted in ENVIRONMENT.json in this directory."
            ),
        },
        "manifest_hash": digest,
        "manifest_head": payload.get("head"),
        "cases": [r.to_dict() for r in results],
        "summary": aggregate(results),
    }
    out = out_dir / "arm_B.json"
    out.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
    print(f"wrote {out} ({len(results)} row(s))")
    for row in results:
        print(f"  {row.corpus}/{row.case_id}: {row.llm_status}")
    return 0


def cmd_confirm(args: argparse.Namespace) -> int:
    """Probe named payload sizes with named fillers. Free: every answer is a rejection.

    Used to turn the bisection's bracket into an exact number, and to ask the
    bytes-versus-characters question at the boundary rather than near it.
    """
    key = _api_key()
    if not key:
        print("ATH_LLM_API_KEY is not set.", file=sys.stderr)
        return 2
    log: list[dict[str, Any]] = []
    for filler in args.filler:
        for size in args.size:
            record = probe_once(size, key, args.model, filler=filler)
            log.append(record)
            print(
                f"  {record['request_bytes']:>12,} bytes, "
                f"{record['system_chars']:>12,} chars ({filler!r}) -> "
                f"{record['status']}", flush=True,
            )
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / args.out_name
    out.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "endpoint": API_ENDPOINT,
        "model": args.model,
        "attempts": log,
    }, indent=2, default=str), encoding="utf-8")
    print(f"wrote {out}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p_measure = sub.add_parser("measure", help="reconstruct requests offline")
    p_measure.add_argument("--case", nargs="*", default=[],
                           help="corpus/CASE-ID; default is every target")
    p_measure.add_argument("--no-network", action="store_true",
                           help="skip count_tokens even when a key is present")
    p_measure.add_argument("--tool-output-budget", type=int, default=None)
    p_measure.add_argument("--out-name", default="measurements.json")
    p_measure.set_defaults(func=cmd_measure)

    p_probe = sub.add_parser("probe", help="binary-search the request-size limit")
    p_probe.add_argument("--model", default="claude-opus-5")
    p_probe.add_argument("--start", type=int, default=1_000_000)
    p_probe.add_argument("--ceiling", type=int, default=64 * 1024 * 1024)
    p_probe.add_argument("--precision", type=float, default=0.05)
    p_probe.set_defaults(func=cmd_probe)

    p_confirm = sub.add_parser(
        "confirm", help="probe explicit payload sizes, to pin a boundary exactly",
    )
    p_confirm.add_argument("--model", default="claude-opus-5")
    p_confirm.add_argument("--size", type=int, nargs="+", required=True)
    p_confirm.add_argument("--filler", nargs="+", default=["A"])
    p_confirm.add_argument("--out-name", default="probe_confirm.json")
    p_confirm.set_defaults(func=cmd_confirm)

    p_run = sub.add_parser("run", help="arm B with the mitigation on")
    p_run.add_argument("--corpus", default="comiset")
    p_run.add_argument("--case", nargs="*", default=["CASE-001", "CASE-002"])
    p_run.add_argument("--tool-output-budget", type=int, required=True)
    p_run.add_argument("--out-dir", type=Path, default=OUT_DIR / "mitigated")
    p_run.set_defaults(func=cmd_run)

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
