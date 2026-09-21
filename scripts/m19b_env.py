"""M19b's environment freeze: equal to M19's, except where it provably cannot be.

Why this exists beside ``scripts/m19_ablation.py freeze`` rather than inside it
--------------------------------------------------------------------------------
M19's freeze is part of a finished experiment and is not touched: ``m19_ablation.py
freeze`` still writes and still gates exactly what it did. This is the M19b variant,
and it differs in one place for one reason.

Plan rule 2 said every M19b run asserts its ``ENVIRONMENT.json`` equal to M19's,
including the hash of ``scoring.py``. T6 adds the necessity metrics to ``scoring.py``,
so that hash can no longer match -- and the amendment (``docs/m19b-plan.md``, dated
before any T8 run) says what replaces it:

* **equality**, still, on prompts, request configuration, retry policy, budgets, model
  ids and the tool surface -- everything that could make two arms differ other than
  their reasoning architecture; and
* for scoring, **reproduction** instead of a hash: the M19 metrics, recomputed by the
  new code over the committed ``reports/m19/ablation/arm_{A,B,C}.json``, must reproduce
  ``GRADING.json`` exactly.

The second is the stronger statement of the two, and that is the point of accepting it
as a substitute. A hash says the file's bytes did not change. The reproduction says the
*numbers* did not change -- it would catch an edit that rewrote a metric and left the
file the same length, and it fails the instant a published figure moves, which is the
only thing the hash was ever standing in for. What it does not catch is a change that
alters no M19 number, which is exactly what adding a new metric is.

What is recomputed, and what is read
-------------------------------------
``recompute_m19_metrics`` rebuilds every row's :class:`CaseScores` from the committed
arm files **through the new scoring code** (``scores_from_dict`` -> ``aggregate``) and
compares the result to the per-arm summaries ``GRADING.json`` carries. It also asserts
every row's score block survives a round trip through the new code unchanged, which is
what proves no metric field was dropped, renamed or re-rounded.

The sections of ``GRADING.json`` that are not a function of the arm files' scores --
the planner counts, which ``scripts/m19_grade.py`` parses out of ``run_*.log``, and the
decision rule, which joins claim and tool-call ids across arms -- are named in the
result rather than silently omitted, so "reproduces GRADING.json: true" says exactly
what it covered.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ath.evaluation.ablation import environment as env  # noqa: E402
from ath.evaluation.ablation.scoring import aggregate, scores_from_dict  # noqa: E402

M19_DIR = ROOT / "reports" / "m19" / "ablation"

ARM_FILES: dict[str, str] = {
    "A": "A_deterministic", "B": "B_single_llm", "C": "C_crew_llm",
}

REPRODUCED_SECTIONS: tuple[str, ...] = ("arms",)
"""The part of ``GRADING.json`` this recomputation covers: the per-arm summaries, which
are ``aggregate()`` over the rows and therefore the output of ``scoring.py`` itself."""

NOT_REPRODUCED_SECTIONS: tuple[str, ...] = (
    "planner (parsed from run_*.log, not from any score)",
    "vii_decision_rule (joins claim and tool-call ids across arms; grader logic)",
    "i..vi, labels, degraded, identity_hygiene (row fields the grader re-counts; the "
    "scores they count are covered by the per-row round trip)",
)
"""Named rather than omitted: a reproduction claim that does not say what it left out is
not a reproduction claim."""

M19_EQUALITY_FIELDS: tuple[str, ...] = (
    "prompts", "request", "retry", "budgets", "model_ids", "tool_surface",
)
"""What an M19b environment must still match M19's on, per the amended rule 2.

``scoring`` is deliberately absent -- see the module docstring. ``manifest_hash`` is
absent because M19b runs a different benchmark by design, and ``git``/``runtime`` are
recorded in both files but were never gated in M19 either.
"""


# --------------------------------------------------------------------------------------
# Scoring: reproduction in place of a hash
# --------------------------------------------------------------------------------------


def _rows(path: Path) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


def recompute_m19_metrics(ablation_dir: Path = M19_DIR) -> dict[str, Any]:
    """The M19 metrics, recomputed from the committed arm files by the current code.

    Returns the per-arm summaries in the shape ``GRADING.json`` records them, plus the
    rows whose score block did not survive a round trip through this code -- which would
    mean a field was dropped, renamed or rounded differently, and therefore that a
    published number had moved even if the aggregate happened to agree.
    """
    summaries: dict[str, Any] = {}
    round_trip_failures: list[str] = []
    rows_read = 0
    for letter, arm in ARM_FILES.items():
        rows = _rows(ablation_dir / f"arm_{letter}.json")
        rebuilt = []
        for row in rows:
            rows_read += 1
            scores = scores_from_dict(row["scores"])
            if scores.to_dict() != row["scores"]:
                round_trip_failures.append(f"{row['corpus']}/{row['case_id']} ({arm})")
            rebuilt.append(SimpleNamespace(
                labelled_arm=row["labelled_arm"],
                corpus=row["corpus"],
                scores=scores,
                llm_degraded=row["llm_degraded"],
            ))
        summaries[arm] = {
            label: summary["overall"]
            for label, summary in aggregate(rebuilt)["arms"].items()
        }
    return {
        "arms": summaries,
        "rows": rows_read,
        "round_trip_failures": round_trip_failures,
    }


def grading_differences(ablation_dir: Path = M19_DIR) -> list[str]:
    """Ways the recomputed M19 metrics differ from ``GRADING.json``. Empty when none."""
    grading = json.loads(
        (ablation_dir / "GRADING.json").read_text(encoding="utf-8")
    )
    recomputed = recompute_m19_metrics(ablation_dir)
    differences = [
        f"row score block does not round trip: {row}"
        for row in recomputed["round_trip_failures"]
    ]
    recorded = grading.get("arms", {})
    for arm in sorted(set(recorded) | set(recomputed["arms"])):
        was, now = recorded.get(arm), recomputed["arms"].get(arm)
        if was == now:
            continue
        if was is None or now is None:
            differences.append(f"arms.{arm}: present in only one of the two")
            continue
        for label in sorted(set(was) | set(now)):
            if was.get(label) != now.get(label):
                differences.append(
                    f"arms.{arm}.{label}: recomputed {now.get(label)} against recorded "
                    f"{was.get(label)}"
                )
    return differences


def reproduces_grading(ablation_dir: Path = M19_DIR) -> tuple[bool, list[str]]:
    """``(reproduces, differences)`` -- the line the M19b freeze prints for scoring."""
    differences = grading_differences(ablation_dir)
    return (not differences), differences


# --------------------------------------------------------------------------------------
# Equality with M19 on everything else
# --------------------------------------------------------------------------------------


def _budgets(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        name: {"max_steps": arm.get("max_steps"), "tool_call_cap": arm.get("tool_call_cap")}
        for name, arm in sorted((payload.get("arms") or {}).items())
    }


def _model_ids(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        name: arm.get("model")
        for name, arm in sorted((payload.get("arms") or {}).items())
    }


def _tool_surface(payload: dict[str, Any]) -> dict[str, Any]:
    surfaces = {
        name: list(arm.get("tool_surface") or ())
        for name, arm in sorted((payload.get("arms") or {}).items())
    }
    surfaces["shared"] = list(payload.get("shared_tool_surface") or ())
    return surfaces


_COMPARATORS = {
    "prompts": lambda payload: dict(payload.get("prompts") or {}),
    "request": lambda payload: dict(payload.get("request") or {}),
    "retry": lambda payload: dict(payload.get("retry") or {}),
    "budgets": _budgets,
    "model_ids": _model_ids,
    "tool_surface": _tool_surface,
}


def m19_equality_differences(
    m19b: dict[str, Any], m19: dict[str, Any]
) -> list[str]:
    """Ways an M19b environment is not M19's environment where it must be.

    Compares :data:`M19_EQUALITY_FIELDS` and nothing else. The commit will differ (M19b
    is later work), the manifest will differ (M19b runs its own benchmark), and the
    scoring hashes will differ (T6 added metrics) -- the first two were never gated
    against M19 at all and the third is replaced by :func:`reproduces_grading`.
    """
    differences: list[str] = []
    for field in M19_EQUALITY_FIELDS:
        comparator = _COMPARATORS[field]
        theirs, ours = comparator(m19), comparator(m19b)
        if theirs == ours:
            continue
        keys = sorted(set(theirs) | set(ours)) if isinstance(theirs, dict) else []
        named = [key for key in keys if theirs.get(key) != ours.get(key)]
        differences.append(
            f"{field}: differs from M19"
            + (f" on {named}" if named else f" ({theirs!r} -> {ours!r})")
        )
    return differences


def capture_m19b_environment(
    root: Path = ROOT,
    *,
    manifest_hash: str,
    manifest_head: str = "",
    ablation_dir: Path = M19_DIR,
    arm_configs: Sequence[Any] | None = None,
    credential_present: bool = False,
) -> dict[str, Any]:
    """The M19b freeze: the live environment, its equality with M19, and the scoring
    reproduction that replaces M19's scoring hash.

    Written as one payload so a run directory carries the whole assertion rather than a
    claim that it was made somewhere.
    """
    environment = env.capture_environment(
        root,
        manifest_hash=manifest_hash,
        manifest_head=manifest_head,
        arm_configs=arm_configs,
        credential_present=credential_present,
    )
    m19 = json.loads(
        (ablation_dir / env.ENVIRONMENT_JSON).read_text(encoding="utf-8")
    )
    differences = m19_equality_differences(environment, m19)
    reproduces, scoring_differences = reproduces_grading(ablation_dir)
    return {
        "environment": environment,
        "m19": {
            "environment": str(
                (ablation_dir / env.ENVIRONMENT_JSON).relative_to(root)
            ).replace("\\", "/"),
            "commit": m19.get("git", {}).get("commit"),
            "compared": list(M19_EQUALITY_FIELDS),
            "equal": not differences,
            "differences": differences,
        },
        "scoring": {
            "instead_of": (
                "a hash of scoring.py, which T6 changed by adding the necessity metrics"
            ),
            "reproduces_grading": reproduces,
            "grading": str((ablation_dir / "GRADING.json").relative_to(root)).replace(
                "\\", "/"
            ),
            "sections_reproduced": list(REPRODUCED_SECTIONS),
            "sections_not_reproduced": list(NOT_REPRODUCED_SECTIONS),
            "differences": scoring_differences,
            "files": {
                name: digest for name, digest in environment["scoring"].items()
            },
        },
    }


def render_markdown(payload: dict[str, Any]) -> str:
    """``ENVIRONMENT.md`` for an M19b run: M19's own rendering plus the two assertions."""
    m19 = payload.get("m19", {})
    scoring = payload.get("scoring", {})
    lines = [
        "# M19b: the frozen experiment environment",
        "",
        "Equal to M19's on everything that could make two arms differ other than their "
        "reasoning architecture. Scoring is asserted by reproduction rather than by a "
        "hash, because T6 added the necessity metrics to `scoring.py` -- "
        "`docs/m19b-plan.md`, amended before any T8 run.",
        "",
        "## Equality with M19",
        "",
        f"* compared: {', '.join(m19.get('compared', []))}",
        f"* M19 freeze: `{m19.get('environment')}` at `{(m19.get('commit') or '')[:12]}`",
        f"* **equal: {str(m19.get('equal')).lower()}**",
    ]
    for difference in m19.get("differences", []):
        lines.append(f"  * {difference}")
    lines += [
        "",
        "## Scoring",
        "",
        f"* **reproduces GRADING.json: {str(scoring.get('reproduces_grading')).lower()}**",
        "* recomputed from `reports/m19/ablation/arm_{A,B,C}.json` by this checkout's "
        "`scoring.py`",
        f"* sections reproduced: {', '.join(scoring.get('sections_reproduced', []))}",
    ]
    for section in scoring.get("sections_not_reproduced", []):
        lines.append(f"* not reproduced: {section}")
    for difference in scoring.get("differences", []):
        lines.append(f"  * {difference}")
    lines += ["", "---", ""]
    return "\n".join(lines) + env.render_markdown(payload.get("environment", {}))


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------


def cmd_check(args: argparse.Namespace) -> int:
    payload = capture_m19b_environment(
        ROOT, manifest_hash=args.manifest_hash, manifest_head=args.manifest_head,
    )
    print(json.dumps({
        "m19": payload["m19"],
        "scoring": {k: v for k, v in payload["scoring"].items() if k != "files"},
    }, indent=2))
    ok = payload["m19"]["equal"] and payload["scoring"]["reproduces_grading"]
    print("EQUAL AND REPRODUCING" if ok else "REFUSED")
    return 0 if ok else 1


def cmd_freeze(args: argparse.Namespace) -> int:
    import os

    payload = capture_m19b_environment(
        ROOT,
        manifest_hash=args.manifest_hash,
        manifest_head=args.manifest_head,
        credential_present=bool(os.getenv(env.CREDENTIAL_VARIABLE)),
    )
    if not (payload["m19"]["equal"] and payload["scoring"]["reproduces_grading"]):
        print(json.dumps(payload["m19"]["differences"], indent=2))
        print(json.dumps(payload["scoring"]["differences"], indent=2))
        print(
            "REFUSED: an M19b environment that is not M19's, or a scoring change that "
            "moved an M19 number, is not a difference to record -- it is a run to stop."
        )
        return 1
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / env.ENVIRONMENT_JSON).write_text(
        json.dumps(payload, indent=2), encoding="utf-8",
    )
    (out / env.ENVIRONMENT_MD).write_text(render_markdown(payload), encoding="utf-8")
    print(f"wrote {out / env.ENVIRONMENT_JSON}")
    print(f"wrote {out / env.ENVIRONMENT_MD}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    for name, handler in (("check", cmd_check), ("freeze", cmd_freeze)):
        command = sub.add_parser(name)
        command.add_argument("--manifest-hash", default="")
        command.add_argument("--manifest-head", default="")
        if name == "freeze":
            command.add_argument(
                "--out", required=True,
                help="run directory to write ENVIRONMENT.json/.md into",
            )
        command.set_defaults(handler=handler)

    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
