"""V1 stage 1, step 4: measure one local model on this machine before anything is scored.

What this answers
------------------
The V1 plan's first hardware instruction: *measure your own per-call time first -- five
real calls, then multiply.* Every later budget (how many overnight runs a rung needs,
whether the 9B fits in the evening) is a multiple of the numbers this script writes.

The prompts are the arm's prompts
----------------------------------
A probe timed on a toy prompt measures the toy. The two shapes here are built from the
same four strings the orchestrator sends -- ``PLANNER_SYSTEM``, ``PLANNER_USER_TEMPLATE``,
``SYNTHESIS_SYSTEM``, ``SYNTHESIS_USER_TEMPLATE`` -- filled with a representative
planner menu (the seven generalist facets) and a synthesis claim block at the M19b
``tool_output_budget`` over enough claims that the bound bites. The report records the
sha256 of each string beside the frozen prompt hashes, so a reader can check the probe
timed what the arm sends.

What is measured and why the first call is separate
-----------------------------------------------------
Per call: wall time, the daemon's load / prompt-eval / eval durations, tokens per second
derived from them, the daemon's ``prompt_eval_count`` beside this client's pre-send
estimate (so the estimator can be calibrated), whether the reply parsed, and available
RAM before and after. The first call of a shape pays the model load and is reported on
its own as the cold call: averaging it into the warm calls would misstate both.

What is refused
----------------
No daemon, no model, or RAM below the model's floor -- each with the action to take.
Any output path under ``reports/m19/`` or ``reports/m19b/``.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ath.agent.claims import Claim, ClaimType  # noqa: E402
from ath.agent.generalist import FAMILY, KIND_ORDER  # noqa: E402
from ath.agent.llm import LLMClient  # noqa: E402
from ath.agent.ollama_llm import (  # noqa: E402
    D1_SAMPLING,
    DEFAULT_BASE_URL,
    DEFAULT_NUM_CTX,
    OllamaLLM,
    OllamaUnavailable,
    Sampling,
)
from ath.agent.orchestrator import (  # noqa: E402
    ELISION,
    PLANNER_MAX_TOKENS,
    PLANNER_SYSTEM,
    PLANNER_USER_TEMPLATE,
    SYNTHESIS_MAX_TOKENS,
    SYNTHESIS_SYSTEM,
    SYNTHESIS_USER_TEMPLATE,
    render_synthesis_claims,
)
from ath.evaluation.ablation.environment import prompt_hashes, sha256_text  # noqa: E402
from ath.evaluation.ablation.local import (  # noqa: E402
    GIB,
    LOCAL_TOOL_OUTPUT_BUDGET,
    ModelSpec,
    available_ram_bytes,
    check_ram,
    ram_floor_for,
    refuse_frozen_path,
)

PROBE_DIR = ROOT / "reports" / "local" / "probe"
CALLS_PER_SHAPE = 5
SYNTHESIS_CLAIMS = 30
"""Claims in the synthesis shape, three of them with long evidence lists.

Sized to the M19b measurement, not to the largest imaginable case: with the 4096-byte
bound on, arm B's synthesis request on comiset/CASE-001 was 11,512 bytes
(``reports/m19b/http413/measurements_mitigated.json``). Thirty claims of which three carry
a 400-id list bounded to 4096 bytes render to about 16 KB -- the same order, a little
above it. A first draft of this probe used sixty claims with twelve long lists (~60 KB,
~20K estimated tokens) and every synthesis call was refused by the ``num_ctx`` guard: a
useful negative result (a case that large needs rung 2's compaction before a 10K window
can see it), but not a measurement of the arm's typical call.
"""
LONG_EVERY = 10
"""Every tenth claim carries the long list."""

PROBE_CASE_ID = "PROBE-001"


# --------------------------------------------------------------------------------------
# The two prompt shapes, from the arm's own strings
# --------------------------------------------------------------------------------------


def planner_prompt(variant: int = 0) -> tuple[str, str]:
    """The planner call as arm D1 sends it, with the seven facets on the menu.

    ``variant`` changes the case id and nothing else, so five calls are five *different*
    prompts of one size. Ollama caches the KV state of an identical prompt and a repeat
    costs a fraction of a second of prefill -- a number the arm, which never sends the
    same prompt twice, will never see.
    """
    candidates = "\n".join(
        f"  {FAMILY}:{kind}: generalist (eligible because the facet has not run)"
        for kind in KIND_ORDER
    )
    user = PLANNER_USER_TEMPLATE.format(
        case_id=f"{PROBE_CASE_ID}-{variant}",
        hosts="CLIENT7, CLIENT9",
        accounts="client9",
        rule_ids="ATH-005, ATH-007",
        tactics="credential-access, lateral-movement",
        agents_run=f"{FAMILY}:{KIND_ORDER[0]}",
        facts=12, inferences=3, hypotheses=1,
        candidates=candidates,
    )
    return PLANNER_SYSTEM, user


def synthesis_claims(count: int = SYNTHESIS_CLAIMS, variant: int = 0) -> list[Claim]:
    """Deterministic claims shaped like a large deterministic pass.

    Every :data:`LONG_EVERY`-th claim cites a long list so the per-claim bound bites and
    the prompt carries :data:`ELISION` markers, as a real bounded prompt does;
    neighbouring claims share ids so the "shared first" pass has something to prefer.
    """
    claims: list[Claim] = []
    for index in range(count):
        # The variant shifts every evidence id, so the prompt differs per call at the same
        # size (see :func:`planner_prompt`).
        base = index * 40 + variant * 100_000
        if index % LONG_EVERY == LONG_EVERY - 1:
            ids = tuple(f"evt-{base + offset:06d}" for offset in range(400))
            statement = (
                f"host CLIENT{index % 9 + 1} made {len(ids)} outbound connections to "
                f"10.0.{index % 7}.{index % 13} on port 445 within 10 minutes"
            )
        else:
            ids = tuple(f"evt-{base + offset:06d}" for offset in range(3))
            if index > 0:
                ids = ids + (f"evt-{(index - 1) * 40:06d}",)
            statement = (
                f"process cmd.exe (pid {4000 + index}) on CLIENT{index % 9 + 1} was "
                f"started by services.exe with a command line redirecting to ADMIN$"
            )
        claims.append(Claim(
            claim_type=ClaimType.FACT if index % 7 else ClaimType.INFERENCE,
            statement=statement, evidence_ids=ids, source="tool",
            agent=f"{FAMILY}:{KIND_ORDER[index % len(KIND_ORDER)]}",
        ))
    return claims


def synthesis_prompt(variant: int = 0, count: int = SYNTHESIS_CLAIMS) -> tuple[str, str]:
    """The synthesis call as arm D1 sends it, at the M19b evidence bound."""
    rendered = render_synthesis_claims(
        synthesis_claims(count, variant), budget=LOCAL_TOOL_OUTPUT_BUDGET,
    )
    return SYNTHESIS_SYSTEM, SYNTHESIS_USER_TEMPLATE.format(
        case_id=f"{PROBE_CASE_ID}-{variant}", claims=rendered,
    )


def template_linkage() -> dict[str, Any]:
    """The hashes of the strings this probe used, beside the frozen prompt hashes.

    Equal by construction today; recorded so a report can prove it rather than say it.
    """
    frozen = prompt_hashes()
    used = {
        "planner_system": sha256_text(PLANNER_SYSTEM),
        "synthesis_system": sha256_text(SYNTHESIS_SYSTEM),
        "planner_user_template": sha256_text(PLANNER_USER_TEMPLATE),
        "synthesis_user_template": sha256_text(SYNTHESIS_USER_TEMPLATE),
    }
    return {
        "used": used,
        "frozen": frozen,
        "identical": all(used[name] == frozen.get(name) for name in used),
    }


SHAPES: tuple[tuple[str, Callable[[int], tuple[str, str]], int], ...] = (
    ("planner", planner_prompt, PLANNER_MAX_TOKENS),
    ("synthesis", synthesis_prompt, SYNTHESIS_MAX_TOKENS),
)


# --------------------------------------------------------------------------------------
# Measuring
# --------------------------------------------------------------------------------------


def _median(values: Sequence[float | None]) -> float | None:
    present = [v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)]
    return round(statistics.median(present), 3) if present else None


def probe_call(
    client: LLMClient,
    system: str,
    user: str,
    max_tokens: int,
    *,
    ram_reader: Callable[[], int | None] = available_ram_bytes,
) -> dict[str, Any]:
    """One timed call. Reads the daemon's figures from the client's last token-log entry."""
    ram_before = ram_reader()
    started = time.perf_counter()
    reply = client.complete(system, user, max_tokens=max_tokens)
    wall = time.perf_counter() - started
    ram_after = ram_reader()
    log = getattr(client, "token_log", None) or []
    entry: dict[str, Any] = dict(log[-1]) if log else {}
    return {
        "wall_seconds": round(wall, 3),
        "ok": reply.ok,
        "error": reply.error,
        "parsed": reply.parsed is not None,
        "stop_reason": reply.stop_reason,
        "prompt_eval_count": reply.input_tokens,
        "eval_count": reply.output_tokens,
        "estimated_prompt_tokens": entry.get("estimated_prompt_tokens"),
        "num_predict": entry.get("num_predict"),
        "load_seconds": entry.get("load_seconds"),
        "prompt_eval_seconds": entry.get("prompt_eval_seconds"),
        "eval_seconds": entry.get("eval_seconds"),
        "prompt_tokens_per_second": entry.get("prompt_tokens_per_second"),
        "eval_tokens_per_second": entry.get("eval_tokens_per_second"),
        "ram_before_bytes": ram_before,
        "ram_after_bytes": ram_after,
        "reply_chars": len(reply.text),
    }


def probe_shape(
    client: LLMClient,
    name: str,
    builder: Callable[[int], tuple[str, str]],
    max_tokens: int,
    calls: int,
    *,
    ram_reader: Callable[[], int | None] = available_ram_bytes,
) -> dict[str, Any]:
    """``calls`` timed calls of one shape, each a different prompt of the same size; the
    first reported apart as the cold call (it pays the model load)."""
    if calls < 1:
        raise ValueError("a shape needs at least one call")
    prompts = [builder(variant) for variant in range(calls)]
    if len({user for _, user in prompts}) != len(prompts):
        raise ValueError(
            f"shape {name!r} repeated a prompt; the daemon would serve it from its cache "
            "and the warm figures would measure the cache, not the model"
        )
    system, user = prompts[0]
    results = [
        probe_call(client, sys_, user_, max_tokens, ram_reader=ram_reader)
        for sys_, user_ in prompts
    ]
    cold, warm = results[0], results[1:]
    measured = [r["prompt_eval_count"] for r in results]
    estimated = results[0]["estimated_prompt_tokens"]
    median_measured = _median(measured)
    return {
        "shape": name,
        "system_sha256": sha256_text(system),
        "user_sha256_first": sha256_text(user),
        "distinct_prompts": len({u for _, u in prompts}),
        "system_chars": len(system),
        "user_chars": len(user),
        "user_bytes": len(user.encode("utf-8")),
        "max_tokens_requested": max_tokens,
        "calls": results,
        "cold_call": cold,
        "aggregate": {
            "calls": len(results),
            "warm_calls": len(warm),
            "parse_rate": round(sum(1 for r in results if r["parsed"]) / len(results), 3),
            "ok_rate": round(sum(1 for r in results if r["ok"]) / len(results), 3),
            "median_wall_seconds_all": _median([r["wall_seconds"] for r in results]),
            "median_wall_seconds_warm": _median([r["wall_seconds"] for r in warm]),
            "cold_wall_seconds": cold["wall_seconds"],
            "cold_load_seconds": cold["load_seconds"],
            "median_prompt_tokens_per_second_warm": _median(
                [r["prompt_tokens_per_second"] for r in warm]
            ),
            "median_eval_tokens_per_second_warm": _median(
                [r["eval_tokens_per_second"] for r in warm]
            ),
            "median_eval_count": _median([r["eval_count"] for r in results]),
            "estimated_prompt_tokens": estimated,
            "median_prompt_eval_count": median_measured,
            "estimate_over_measured": (
                round(estimated / median_measured, 3)
                if isinstance(estimated, int) and median_measured else None
            ),
            "min_ram_bytes": min(
                (r[k] for r in results for k in ("ram_before_bytes", "ram_after_bytes")
                 if isinstance(r[k], int)), default=None,
            ),
        },
    }


def run_probe(
    client: LLMClient,
    *,
    calls: int = CALLS_PER_SHAPE,
    ram_reader: Callable[[], int | None] = available_ram_bytes,
    shapes: Sequence[tuple[str, Callable[[], tuple[str, str]], int]] = SHAPES,
) -> dict[str, Any]:
    """Every shape over ``client``. Pure with respect to the file system."""
    return {
        "shapes": {
            name: probe_shape(client, name, builder, max_tokens, calls, ram_reader=ram_reader)
            for name, builder, max_tokens in shapes
        },
        "template_linkage": template_linkage(),
        "synthesis_bound_bytes": LOCAL_TOOL_OUTPUT_BUDGET,
    }


# --------------------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------------------


def _head() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:  # noqa: BLE001 -- a missing git is not a reason to lose the probe
        return "unknown"


def _gib(value: Any) -> str:
    return f"{value / GIB:.2f}" if isinstance(value, int) else "--"


def _num(value: Any) -> str:
    return "--" if value is None else str(value)


def _table(header: list[str], rows: list[list[Any]]) -> str:
    lines = [
        "| " + " | ".join(header) + " |",
        "| " + " | ".join("---" for _ in header) + " |",
    ]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def render_markdown(payload: dict[str, Any]) -> str:
    model = payload.get("model") or {}
    configuration = payload.get("configuration") or {}
    ram = payload.get("ram_preflight") or {}
    lines = [
        f"# Local model probe: `{model.get('model', '?')}`",
        "",
        f"Generated {payload.get('generated_at')} at `{payload.get('head')}`. Every number is "
        "MEASURED on this machine by `scripts/local_probe.py`. Every call of a shape sends a "
        "*different* prompt of the same size, so no call is served from the daemon's prompt "
        "cache; the first call of each shape is the cold call (it pays the model load) and is "
        "reported apart from the warm ones.",
        "",
        "## What ran",
        "",
        _table(["setting", "value"], [
            ["provider / model", f"{model.get('provider')} / {model.get('model')}"],
            ["digest", model.get("digest")],
            ["quantisation / size", f"{model.get('quantization')} / {model.get('parameter_size')}"],
            ["daemon version", payload.get("daemon_version")],
            ["sampling", json.dumps(configuration.get("sampling"))],
            ["think", configuration.get("think")],
            ["format", configuration.get("format")],
            ["num_ctx / num_predict cap", f"{configuration.get('num_ctx')} / {configuration.get('num_predict_cap')}"],
            ["synthesis bound (bytes/claim)", payload.get("synthesis_bound_bytes")],
            ["RAM at preflight (GiB) / floor (GiB)", f"{_gib(ram.get('available_bytes'))} / {_gib(ram.get('floor_bytes'))}"],
            ["prompts identical to the frozen ones", payload.get("template_linkage", {}).get("identical")],
        ]),
        "",
    ]
    for name, shape in (payload.get("shapes") or {}).items():
        agg = shape["aggregate"]
        lines += [
            f"## Shape: {name}",
            "",
            f"System {shape['system_chars']} chars, user {shape['user_chars']} chars "
            f"({shape['user_bytes']} bytes), {shape['distinct_prompts']} distinct prompts; "
            f"`max_tokens` requested {shape['max_tokens_requested']}, "
            f"`num_predict` sent {_num(shape['cold_call'].get('num_predict'))}.",
            "",
            _table(
                ["call", "wall s", "load s", "prompt-eval s", "eval s", "prompt tok/s",
                 "gen tok/s", "prompt tokens", "est. tokens", "gen tokens", "parsed",
                 "RAM before GiB", "RAM after GiB"],
                [[
                    "cold" if i == 0 else f"warm {i}",
                    c["wall_seconds"], _num(c["load_seconds"]), _num(c["prompt_eval_seconds"]),
                    _num(c["eval_seconds"]), _num(c["prompt_tokens_per_second"]),
                    _num(c["eval_tokens_per_second"]), _num(c["prompt_eval_count"]),
                    _num(c["estimated_prompt_tokens"]), _num(c["eval_count"]),
                    "yes" if c["parsed"] else ("no: " + str(c["error"]) if c["error"] else "no (prose)"),
                    _gib(c["ram_before_bytes"]), _gib(c["ram_after_bytes"]),
                ] for i, c in enumerate(shape["calls"])],
            ),
            "",
            _table(["aggregate", "value"], [
                ["parse rate", agg["parse_rate"]],
                ["median wall s (all / warm)", f"{_num(agg['median_wall_seconds_all'])} / {_num(agg['median_wall_seconds_warm'])}"],
                ["cold wall s (of which load)", f"{_num(agg['cold_wall_seconds'])} ({_num(agg['cold_load_seconds'])})"],
                ["median prompt tok/s (warm)", _num(agg["median_prompt_tokens_per_second_warm"])],
                ["median gen tok/s (warm)", _num(agg["median_eval_tokens_per_second_warm"])],
                ["estimated / measured prompt tokens", f"{_num(agg['estimated_prompt_tokens'])} / {_num(agg['median_prompt_eval_count'])} (ratio {_num(agg['estimate_over_measured'])})"],
                ["min RAM seen (GiB)", _gib(agg["min_ram_bytes"])],
            ]),
            "",
        ]
    linkage = payload.get("template_linkage") or {}
    lines += [
        "## Prompt linkage",
        "",
        "sha256 of each string this probe sent, beside the hash the M19b freeze recorded.",
        "",
        _table(["string", "used", "frozen", "same"], [
            [name, used[:12], str(linkage.get("frozen", {}).get(name, ""))[:12],
             used == linkage.get("frozen", {}).get(name)]
            for name, used in (linkage.get("used") or {}).items()
        ]),
        "",
    ]
    return "\n".join(lines)


def slug(model: str, think: bool) -> str:
    text = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in model)
    return text + ("_think" if think else "")


def write_reports(out_dir: Path, payload: dict[str, Any], *, root: Path = ROOT) -> tuple[Path, Path]:
    """The JSON and the Markdown, both inside the frozen-path guard."""
    name = f"PROBE_{payload['slug']}"
    json_path = refuse_frozen_path(Path(out_dir) / f"{name}.json", root)
    md_path = refuse_frozen_path(Path(out_dir) / f"{name}.md", root)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(payload) + "\n", encoding="utf-8")
    return json_path, md_path


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--model", default="qwen3.5:4b", help="Ollama model tag")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--think", action="store_true", help="send think=true (default: false)")
    parser.add_argument("--calls", type=int, default=CALLS_PER_SHAPE)
    parser.add_argument("--num-ctx", type=int, default=DEFAULT_NUM_CTX)
    parser.add_argument("--seed", type=int, default=D1_SAMPLING.seed)
    parser.add_argument("--temperature", type=float, default=D1_SAMPLING.temperature)
    parser.add_argument("--out-dir", type=Path, default=PROBE_DIR)
    parser.add_argument(
        "--ignore-ram-floor", action="store_true",
        help="run below the RAM floor anyway; the report records that the guard was overridden",
    )
    args = parser.parse_args(argv)

    client = OllamaLLM(
        args.model, base_url=args.base_url, think=bool(args.think), num_ctx=args.num_ctx,
        sampling=Sampling(temperature=args.temperature, seed=args.seed),
    )
    try:
        described = client.describe()
    except OllamaUnavailable as exc:
        raise SystemExit(f"REFUSED: {exc}") from exc
    spec = ModelSpec.from_description(described)

    verdict = check_ram(
        ram_floor_for(spec.parameter_size), available_ram_bytes(), client.resident_bytes(),
    )
    print(f"RAM: {verdict.message}", file=sys.stderr)
    if verdict.ok is False and not args.ignore_ram_floor:
        raise SystemExit("REFUSED: " + verdict.message)

    print(
        f"probing {spec.model} ({spec.quantization}, {spec.parameter_size}) on Ollama "
        f"{described.get('daemon_version')}: {args.calls} call(s) x {len(SHAPES)} shape(s), "
        f"think={bool(args.think)}", file=sys.stderr,
    )
    payload = run_probe(client, calls=args.calls)
    payload.update({
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "head": _head(),
        "slug": slug(args.model, bool(args.think)),
        "model": spec.to_dict(),
        "daemon_version": described.get("daemon_version"),
        "model_details": {
            k: described.get(k) for k in ("family", "format", "size_bytes", "capabilities",
                                          "model_context_length")
        },
        "configuration": client.configuration(),
        "ram_preflight": {**verdict.to_dict(), "overridden": bool(args.ignore_ram_floor and verdict.ok is False)},
        "calls_per_shape": args.calls,
    })
    json_path, md_path = write_reports(args.out_dir, payload)
    for name, shape in payload["shapes"].items():
        agg = shape["aggregate"]
        print(
            f"{name}: parse {agg['parse_rate']}, median wall {agg['median_wall_seconds_all']}s "
            f"(warm {agg['median_wall_seconds_warm']}s, cold {agg['cold_wall_seconds']}s), "
            f"gen {agg['median_eval_tokens_per_second_warm']} tok/s, "
            f"prompt {agg['median_prompt_eval_count']} tokens (est. {agg['estimated_prompt_tokens']})",
            file=sys.stderr,
        )
    print(f"wrote {json_path}\nwrote {md_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
