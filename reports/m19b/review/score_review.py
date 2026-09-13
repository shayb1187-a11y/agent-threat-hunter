"""Read a human reviewer's filled answer sheet back against the sealed key.

This script is the *only* place the review's answers and the arm identities meet. It
computes nothing about a hypothesis: every classification and every flag in its output
was typed by a person. What it adds is the arm, the corpus and the per-case denominator,
none of which the reviewer could see.

The question it is built to answer
-----------------------------------
M19b asks whether a crew is better than a single investigator, and the failure mode this
review exists to catch is an arm that looks better only because it says *more*. So the
tallies are reported twice: as rates over the arm's own hypotheses, and as counts per
case investigated. An arm that emits three hypotheses a case and an arm that emits one
cannot be compared on "fraction useful" alone -- a 33% useful rate over three is the same
delivered value as 100% over one, and the per-case numbers are the ones that say so.

Refusing to run
----------------
A partly-filled sheet scored as though it were complete would silently count every
unanswered row as absent rather than unanswered, and the denominators would be wrong in
the direction that flatters whichever arm the reviewer happened to reach first. So an
answers file with an unfilled row is refused unless ``--partial`` is passed, and with
``--partial`` the skipped rows are counted and printed beside every rate.

Usage::

    python reports/m19b/review/score_review.py --answers answers_filled.csv
    python reports/m19b/review/score_review.py --answers partial.csv --partial --json out.json
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Sequence

HERE = Path(__file__).resolve().parent

CLASSIFICATIONS = (
    "NEW_ACTIONABLE",
    "NEW_USEFUL_NONACTIONABLE",
    "RESTATEMENT",
    "SPECULATIVE_PLAUSIBLE",
    "UNSUPPORTED",
    "WRONG",
)

USEFUL_CLASSIFICATIONS = ("NEW_ACTIONABLE", "NEW_USEFUL_NONACTIONABLE")
"""The two the "more hypotheses versus more useful investigation" comparison counts.

Both are hypotheses the reviewer judged to have added something the deterministic pass
did not have. They are kept separate everywhere else, and summed only here, because the
comparison is about delivered value per case rather than about which of the two it was.
"""

FLAGS = (
    "introduced_new_evidence",
    "connected_existing_evidence_usefully",
    "paraphrased_deterministic_finding",
    "would_change_next_action",
)

ANSWER_COLUMNS = ("review_id", "classification", *FLAGS, "reviewer_note")

YES = "y"
NO = "n"


class ReviewError(Exception):
    """A refusal: the answers and the key do not describe one complete review."""


# --------------------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------------------


def load_key(path: Path) -> dict[str, Any]:
    key = json.loads(Path(path).read_text(encoding="utf-8"))
    if "entries" not in key:
        raise ReviewError(f"{path} has no 'entries': this is not a review key")
    return key


def read_answers(path: Path) -> list[dict[str, str]]:
    with Path(path).open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = [c for c in ANSWER_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise ReviewError(
                f"{path} is missing column(s) {', '.join(missing)}; it must have the "
                f"columns answers_template.csv has"
            )
        return [{k: (v or "").strip() for k, v in row.items() if k is not None}
                for row in reader]


def _row_is_unfilled(row: dict[str, str]) -> bool:
    """A row is unfilled if the classification or any flag is blank.

    The note is deliberately not required: a reviewer who has nothing to add to a clear
    RESTATEMENT should not be pushed into writing something so that a script is happy.
    """
    return not row["classification"] or any(not row[flag] for flag in FLAGS)


def validate(
    rows: Sequence[dict[str, str]], key: dict[str, Any], *, partial: bool,
) -> list[dict[str, str]]:
    """Return the filled rows, or raise with everything that is wrong at once."""
    problems: list[str] = []
    expected = set(key["entries"])
    seen = Counter(row["review_id"] for row in rows)

    unknown = sorted(set(seen) - expected)
    if unknown:
        problems.append(f"{len(unknown)} answer row(s) name no key entry: {unknown[:10]}")
    duplicated = sorted(rid for rid, count in seen.items() if count > 1)
    if duplicated:
        problems.append(f"{len(duplicated)} review id(s) answered twice: {duplicated[:10]}")
    absent = sorted(expected - set(seen))
    if absent and not partial:
        problems.append(
            f"{len(absent)} review id(s) have no answer row at all: {absent[:10]} "
            f"-- pass --partial to score what is filled"
        )

    for row in rows:
        rid = row["review_id"]
        if row["classification"] and row["classification"] not in CLASSIFICATIONS:
            problems.append(
                f"{rid}: classification {row['classification']!r} is not one of "
                f"{', '.join(CLASSIFICATIONS)}"
            )
        for flag in FLAGS:
            if row[flag] and row[flag].lower() not in (YES, NO):
                problems.append(f"{rid}: {flag}={row[flag]!r} is not y or n")

    unfilled = [row["review_id"] for row in rows if _row_is_unfilled(row)]
    if unfilled and not partial:
        problems.append(
            f"{len(unfilled)} row(s) are unfilled: {unfilled[:10]} -- scoring a partly "
            f"filled sheet as a complete one would make every rate's denominator wrong. "
            f"Pass --partial to score the filled rows and count the rest as skipped."
        )

    if problems:
        raise ReviewError("\n".join(problems))
    return [row for row in rows if not _row_is_unfilled(row)]


# --------------------------------------------------------------------------------------
# tallying
# --------------------------------------------------------------------------------------


def _rate(count: int, total: int) -> float:
    return round(count / total, 4) if total else 0.0


def tally(rows: Sequence[dict[str, str]], key: dict[str, Any]) -> dict[str, Any]:
    """Per-arm counts, rates and per-case numbers. No judgement is made here."""
    entries = key["entries"]
    arms_meta = key.get("arms", {})
    cases_run = {
        meta["name"]: meta.get("cases_run", 0) for meta in arms_meta.values()
    }
    degraded = {
        meta["name"]: (
            meta.get("cases_model_degraded", 0), meta.get("cases_incomplete", 0),
        )
        for meta in arms_meta.values()
    }

    scored_by_arm: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        scored_by_arm[entries[row["review_id"]]["arm"]].append(row)

    # Denominators come from the key, not from the answers: an arm whose rows a reviewer
    # has not reached yet still emitted the hypotheses it emitted, and a per-case rate
    # computed over answered rows alone would move as the review progressed.
    emitted_by_arm: Counter[str] = Counter(e["arm"] for e in entries.values())
    cases_with_hypothesis: dict[str, set[str]] = defaultdict(set)
    for entry in entries.values():
        cases_with_hypothesis[entry["arm"]].add(f"{entry['corpus']}/{entry['case_id']}")

    per_arm: dict[str, Any] = {}
    for arm in sorted(emitted_by_arm):
        scored = scored_by_arm.get(arm, [])
        total = len(scored)
        classifications = Counter(row["classification"] for row in scored)
        flags = {
            flag: sum(1 for row in scored if row[flag].lower() == YES) for flag in FLAGS
        }
        useful = sum(classifications[c] for c in USEFUL_CLASSIFICATIONS)
        per_corpus: dict[str, Counter[str]] = defaultdict(Counter)
        for row in scored:
            per_corpus[entries[row["review_id"]]["corpus"]][row["classification"]] += 1

        cases = cases_run.get(arm) or len(cases_with_hypothesis[arm])
        per_arm[arm] = {
            "hypotheses_emitted": emitted_by_arm[arm],
            "hypotheses_scored": total,
            "hypotheses_unscored": emitted_by_arm[arm] - total,
            "cases_run": cases,
            "cases_with_at_least_one_hypothesis": len(cases_with_hypothesis[arm]),
            # Reported, never quietly removed from the denominator: dropping a case
            # because one arm was degraded on it would compare the arms over different
            # case sets, which is the one thing the ablation may not do.
            "cases_model_degraded": degraded.get(arm, (0, 0))[0],
            "cases_incomplete": degraded.get(arm, (0, 0))[1],
            "classifications": {
                c: {"count": classifications[c], "rate": _rate(classifications[c], total)}
                for c in CLASSIFICATIONS
            },
            "flags": {
                flag: {"count": count, "rate": _rate(count, total)}
                for flag, count in flags.items()
            },
            "per_corpus": {
                corpus: dict(counts) for corpus, counts in sorted(per_corpus.items())
            },
            "more_hypotheses_vs_more_useful_investigation": {
                "hypotheses_per_case": (
                    round(emitted_by_arm[arm] / cases, 4) if cases else 0.0
                ),
                "scored_hypotheses_per_case": (
                    round(total / cases, 4) if cases else 0.0
                ),
                "useful_per_case": round(useful / cases, 4) if cases else 0.0,
                "useful_count": useful,
                "useful_rate": _rate(useful, total),
                # `hypotheses_per_case` counts what the arm emitted and
                # `useful_per_case` counts what a human has judged so far, so on a
                # partial sheet the second is a floor, not an estimate. Saying which is
                # which here is cheaper than a reader inferring it from two numbers.
                "caveat": (
                    ""
                    if total == emitted_by_arm[arm]
                    else (
                        f"useful_per_case is a lower bound: "
                        f"{emitted_by_arm[arm] - total} of {emitted_by_arm[arm]} "
                        f"hypotheses are unscored"
                    )
                ),
            },
        }

    return {
        "key_head": key.get("head", ""),
        "seed": key.get("seed"),
        "baseline_arm": key.get("baseline_arm", ""),
        "entries_in_key": len(entries),
        "rows_scored": len(rows),
        "rows_skipped_unfilled": len(entries) - len(rows),
        "per_arm": per_arm,
    }


# --------------------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------------------


def render(result: dict[str, Any]) -> str:
    lines = [
        "M19b blinded hypothesis review -- tallies",
        "=" * 60,
        f"key commit {result['key_head']}  seed {result['seed']}  "
        f"baseline arm {result['baseline_arm']}",
        f"{result['rows_scored']} of {result['entries_in_key']} entries scored "
        f"({result['rows_skipped_unfilled']} unfilled or absent)",
        "",
    ]
    for arm, stats in result["per_arm"].items():
        lines += [
            f"-- {arm} " + "-" * max(0, 57 - len(arm)),
            f"   {stats['hypotheses_scored']} scored of {stats['hypotheses_emitted']} "
            f"emitted over {stats['cases_run']} cases "
            f"({stats['cases_with_at_least_one_hypothesis']} of them produced one; "
            f"{stats['cases_model_degraded']} degraded, "
            f"{stats['cases_incomplete']} did not finish)",
            "",
            "   classification                           count    rate",
        ]
        for name, cell in stats["classifications"].items():
            lines.append(f"     {name:<38} {cell['count']:>5}  {cell['rate']:>6.2%}")
        lines += ["", "   flag (answered y)                        count    rate"]
        for name, cell in stats["flags"].items():
            lines.append(f"     {name:<38} {cell['count']:>5}  {cell['rate']:>6.2%}")
        lines += ["", "   per corpus"]
        for corpus, counts in stats["per_corpus"].items():
            rendered = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
            lines.append(f"     {corpus:<38} {rendered}")
        compare = stats["more_hypotheses_vs_more_useful_investigation"]
        lines += [
            "",
            "   more hypotheses vs more useful investigation",
            f"     hypotheses per case        {compare['hypotheses_per_case']:>8.3f}"
            f"   (scored: {compare['scored_hypotheses_per_case']:.3f})",
            f"     useful per case            {compare['useful_per_case']:>8.3f}"
            f"   (NEW_ACTIONABLE + NEW_USEFUL_NONACTIONABLE = {compare['useful_count']})",
            f"     useful rate                {compare['useful_rate']:>8.2%}",
        ]
        if compare["caveat"]:
            lines.append(f"     ! {compare['caveat']}")
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Score a filled M19b review answer sheet against the sealed key.",
    )
    parser.add_argument("--answers", type=Path, required=True)
    parser.add_argument("--key", type=Path, default=HERE / "KEY.sealed.json")
    parser.add_argument(
        "--partial", action="store_true",
        help="score the filled rows and count the rest as skipped",
    )
    parser.add_argument("--json", type=Path, default=None, help="also write the tallies")
    args = parser.parse_args(argv)

    try:
        key = load_key(args.key)
        rows = read_answers(args.answers)
        filled = validate(rows, key, partial=args.partial)
    except ReviewError as error:
        print(f"refusing to score {args.answers}:\n{error}")
        return 2

    result = tally(filled, key)
    print(render(result))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
