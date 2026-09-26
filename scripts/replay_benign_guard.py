"""Replay operational-v7's benign guard over sealed operational-v6 D1 rows, offline.

For each sealed D1 row this reads what the run recorded -- the model's disposition, the
operational outcome and every tool call -- and the case's sealed telemetry, and asks the
same pure function the live v7 path uses (:func:`ath.agent.benign_guard.guard_from_row`)
what it would have done. No model is called.

What this is not: a v7 result. Only the guard is replayed. The v7 prompt and menu wording
would change what the model does, and that cannot be replayed from v6 rows. The default
input is holdout-v1-windows, whose cases have now been read; the output is labelled as
dev evidence on seen cases, and any claim about v7 needs a fresh holdout.

Usage::

    python scripts/replay_benign_guard.py [--results DIR] [--bundle DIR] [--out FILE]

Output is Markdown on stdout, or written to ``--out`` (refused inside the repository).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ath.agent.benign_guard import NOT_PROCESS_SEED, guard_from_row
from ath.evaluation.real_cases import read_bundle, real_cases

ROOT = Path(__file__).resolve().parent.parent
HOLDOUT = Path(r"C:\Users\shayb\Downloads\ath-holdout-v1")
DEFAULT_RESULTS = HOLDOUT / "results-9b-colab" / "ath-results-holdout-9b-v6-ecd865890442" / "real"
DEFAULT_BUNDLE = HOLDOUT / "bundle"
LABEL = "SEEN CASES — dev evidence only; not a result"


def _parent_column(guard: dict) -> str:
    if guard["reason"] == NOT_PROCESS_SEED:
        return "n/a (not a process seed)"
    seeds = guard["seeds"]
    if all(s["parent_retrieved"] for s in seeds):
        return "yes"
    if any(not s["parent_event_ids"] for s in seeds if not s["parent_retrieved"]):
        return "no (parent not in telemetry)"
    return "no"


def _v7_column(guard: dict, v6_decision: str) -> str:
    if guard["applied"]:
        return "abstain (guard applied)"
    return f"{v6_decision} (unchanged)"


def replay(results_dir: Path, bundle_dir: Path) -> list[dict]:
    """One record per sealed D1 row, in key order. Refuses a bundle the run did not use."""
    freeze = json.loads((results_dir / "FREEZE.json").read_text(encoding="utf-8"))
    bundle = read_bundle(bundle_dir)
    if bundle["bundle_sha256"] != freeze["bundle_sha256"]:
        raise SystemExit("the bundle is not the one these rows were frozen against")
    cases = {c.key: c for c in real_cases(bundle_dir)}
    sealed = {m["key"]: m for m in freeze["manifest"]}
    records = []
    for path in sorted((results_dir / "rows").glob("*_d1_*.json")):
        row = json.loads(path.read_text(encoding="utf-8"))
        key = row["sample"]
        case = cases[key]
        if list(case.case_ids) != sealed[key]["case_ids"]:
            raise SystemExit(f"{key}: the seed differs from the frozen manifest")
        state = row["state"]
        guard = guard_from_row(state, case.telemetry, case.case_ids)
        records.append({
            "key": key, "expected": row["scores"]["expected_decision"],
            "quadrant": (row.get("case_metadata") or {}).get("quadrant", ""),
            "v6_decision": row["scores"]["decision"],
            "probes": ", ".join(state["investigation"].get("probes_run") or ()) or "none",
            "parent_retrieved": _parent_column(guard),
            "v7_guard": _v7_column(guard, row["scores"]["decision"]),
            "guard": guard,
        })
    return records


def render(records: list[dict], results_dir: Path) -> str:
    lines = [
        f"# Benign-guard replay: {LABEL}",
        "",
        f"Rows: `{results_dir}` (operational-v6, sealed). Only the v7 guard is replayed; the",
        "v7 prompt and menu would change the model's answers, and that cannot be replayed.",
        "",
        "| Key | Quadrant | Expected | v6 decision | Probes | Parent retrieved? | v7 guard would |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in records:
        lines.append(f"| {r['key']} | {r['quadrant']} | {r['expected']} | {r['v6_decision']} | "
                     f"{r['probes']} | {r['parent_retrieved']} | {r['v7_guard']} |")
    lines += ["", "Guard reasons (benign rows only):", ""]
    for r in records:
        if r["guard"].get("model_disposition") == "benign" or r["guard"]["applied"]:
            lines.append(f"- {r['key']}: {r['guard']['reason']}")
    lines += ["", f"_{LABEL}. Any claim about operational-v7 needs a fresh holdout._", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS, help="Sealed results dir (FREEZE.json, rows/).")
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE, help="The sealed case bundle the run used.")
    parser.add_argument("--out", type=Path, help="Write Markdown here instead of stdout (outside the repository).")
    args = parser.parse_args(argv)
    text = render(replay(args.results, args.bundle), args.results)
    if args.out is None:
        sys.stdout.reconfigure(encoding="utf-8")
        print(text)
        return 0
    if args.out.resolve().is_relative_to(ROOT):
        raise SystemExit("refusing to write replay output into the repository")
    args.out.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
