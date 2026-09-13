"""The M19b blinded review package: is it actually blind, complete, and scored right?

Four properties, and why each one is a test rather than a check somebody did once
---------------------------------------------------------------------------------
1. **The worksheet reveals no arm.** The result this package produces is a human's
   judgement of a hypothesis made without knowing which set-up wrote it. One leaked
   facet name in one of 102 entries is enough to contaminate the rows around it, and
   leaks arrive by accident -- a field added to the renderer later, a statement that
   happens to name an agent. So the ban is asserted over the bytes of every file the
   reviewer opens, not over the renderer's intentions.
2. **The key round-trips.** Every review id appears in the key exactly once and the key
   invents none. If it did not, an answer row would be scored against the wrong arm, or
   silently dropped -- and both failures look like a result rather than like a bug.
3. **Nothing was lost on the way in.** The entry count equals the number of HYPOTHESIS
   claims in the three frozen arm artifacts. A filter that quietly dropped a claim type,
   a case or an arm would otherwise show up as "that arm produced fewer hypotheses",
   which is exactly the measurement M19b is making.
4. **The scorer's arithmetic.** Checked on a synthetic answer sheet whose tallies are
   known by construction, so the test fails on a wrong number rather than on a changed
   one.
"""

from __future__ import annotations

import csv
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

REVIEW_DIR = ROOT / "reports" / "m19b" / "review"
M19_DIR = ROOT / "reports" / "m19" / "ablation"

BANNED = (
    "generalist",
    "B_single",
    "C_crew",
    "facet",
    "endpoint agent",
    "identity agent",
    "network agent",
    "control_plane",
)
"""Strings that would tell a reviewer which set-up wrote a hypothesis.

``control_plane`` is the specialist's name; the event ids of cloud control-plane rows
(``cloudtrail-control-000001``) are not it and are allowed, which is why the banned
string carries the underscore.
"""

REVIEWER_FACING = ("worksheet.md", "worksheet.csv", "answers_template.csv", "README.md")
"""Every file the reviewer is told to open. The key is deliberately not among them."""


def _load_scorer():
    spec = importlib.util.spec_from_file_location(
        "m19b_score_review", REVIEW_DIR / "score_review.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scorer = _load_scorer()


@pytest.fixture(scope="module")
def key() -> dict:
    return json.loads((REVIEW_DIR / "KEY.sealed.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def worksheet_rows() -> list[dict[str, str]]:
    with (REVIEW_DIR / "worksheet.csv").open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


# --------------------------------------------------------------------------------------
# 1. blinding
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("filename", REVIEWER_FACING)
def test_reviewer_facing_files_name_no_arm(filename: str) -> None:
    """No reviewer-facing file may contain a string that identifies an arm.

    Asserted per file and case-insensitively: the leak that matters is the one a reader
    can see, and "Generalist" at the start of a sentence is the same leak as
    "generalist".
    """
    text = (REVIEW_DIR / filename).read_text(encoding="utf-8").lower()
    found = [banned for banned in BANNED if banned.lower() in text]
    assert not found, f"{filename} reveals the arm through {found}"


def test_worksheet_carries_no_cost_or_ordering_signal() -> None:
    """Tokens, wall time and the arms' own ordering are not in the worksheet either.

    They are as identifying as a name: one arm's entries would all carry a latency the
    others' do not, and an entry's position in its arm's output is a fingerprint of the
    run it came from.
    """
    text = (REVIEW_DIR / "worksheet.md").read_text(encoding="utf-8").lower()
    # Field names, not English words: "token" appears in a hypothesis about a leaked
    # credential, and banning the word rather than the field would fail on the verbatim
    # text this worksheet exists to show.
    for signal in (
        "wall_seconds", "claim_index", "arm_a", "arm_b", "arm_c",
        "labelled_arm", "llm_status", "_deterministic", "_single_llm", "_crew",
    ):
        assert signal not in text, f"worksheet.md leaks {signal!r}"


# --------------------------------------------------------------------------------------
# 2. the key round-trips
# --------------------------------------------------------------------------------------


def test_key_round_trips_every_review_id_exactly_once(key, worksheet_rows) -> None:
    """Worksheet, CSV, answer template and key name exactly the same review ids."""
    from_csv = [row["review_id"] for row in worksheet_rows]
    assert len(from_csv) == len(set(from_csv)), "worksheet.csv repeats a review id"

    with (REVIEW_DIR / "answers_template.csv").open(encoding="utf-8", newline="") as fh:
        template = [row["review_id"] for row in csv.DictReader(fh)]
    assert template == from_csv, "answers_template.csv and worksheet.csv disagree"

    assert sorted(key["entries"]) == sorted(from_csv)

    markdown = (REVIEW_DIR / "worksheet.md").read_text(encoding="utf-8")
    for review_id in from_csv:
        assert f"\n## {review_id}\n" in markdown, f"{review_id} has no worksheet entry"

    for review_id, entry in key["entries"].items():
        assert entry["arm"], f"{review_id} has no arm in the key"
        assert entry["corpus"] and entry["case_id"]
        assert isinstance(entry["claim_index"], int)


def test_key_case_matches_the_worksheet_case(key, worksheet_rows) -> None:
    """The key's case must be the case the reviewer was shown.

    A key that pointed at a different case would unblind onto the wrong findings, and
    the mistake would be invisible in every tally the scorer prints.
    """
    for row in worksheet_rows:
        entry = key["entries"][row["review_id"]]
        assert (entry["corpus"], entry["case_id"]) == (row["corpus"], row["case_id"])


# --------------------------------------------------------------------------------------
# 3. every hypothesis is in the package
# --------------------------------------------------------------------------------------


def _hypotheses_in_artifacts() -> list[tuple[str, str, str, int]]:
    hypotheses: list[tuple[str, str, str, int]] = []
    for arm in ("A", "B", "C"):
        document = json.loads((M19_DIR / f"arm_{arm}.json").read_text(encoding="utf-8"))
        for case in document["cases"]:
            for index, claim in enumerate(case["state"].get("claims", [])):
                if claim.get("type") == "HYPOTHESIS":
                    hypotheses.append(
                        (arm, case["corpus"], case["case_id"], index)
                    )
    return hypotheses


def test_entry_count_equals_the_hypothesis_claims_in_the_artifacts(
    key, worksheet_rows,
) -> None:
    """102 entries: every HYPOTHESIS claim in arm A, B and C, and nothing else."""
    expected = _hypotheses_in_artifacts()
    assert len(worksheet_rows) == len(expected)
    assert len(key["entries"]) == len(expected)

    # And the same claims, not merely the same number of them.
    in_key = sorted(
        (entry["corpus"], entry["case_id"], entry["claim_index"])
        for entry in key["entries"].values()
    )
    assert in_key == sorted((c, i, x) for _, c, i, x in expected)


def test_every_hypothesis_statement_is_verbatim(worksheet_rows) -> None:
    """The worksheet must not paraphrase what it asks a human to judge."""
    statements = set()
    for arm in ("A", "B", "C"):
        document = json.loads((M19_DIR / f"arm_{arm}.json").read_text(encoding="utf-8"))
        for case in document["cases"]:
            for claim in case["state"].get("claims", []):
                if claim.get("type") == "HYPOTHESIS":
                    statements.add(" ".join(str(claim["statement"]).split()))
    for row in worksheet_rows:
        assert row["hypothesis"] in statements, (
            f"{row['review_id']} does not match any claim in the arm artifacts"
        )


# --------------------------------------------------------------------------------------
# 4. the scorer
# --------------------------------------------------------------------------------------


SYNTHETIC_KEY = {
    "head": "test",
    "seed": 1,
    "baseline_arm": "arm_one",
    "arms": {
        "A": {"name": "arm_one", "model": "", "cases_run": 2,
              "cases_model_degraded": 0, "cases_incomplete": 0},
        "B": {"name": "arm_two", "model": "m", "cases_run": 4,
              "cases_model_degraded": 1, "cases_incomplete": 0},
    },
    "entries": {
        "R001": {"arm": "arm_one", "corpus": "cx", "case_id": "CASE-001",
                 "claim_index": 0, "agent": "a", "source": "analysis"},
        "R002": {"arm": "arm_one", "corpus": "cx", "case_id": "CASE-002",
                 "claim_index": 1, "agent": "a", "source": "analysis"},
        "R003": {"arm": "arm_two", "corpus": "cx", "case_id": "CASE-001",
                 "claim_index": 0, "agent": "s", "source": "llm"},
        "R004": {"arm": "arm_two", "corpus": "cy", "case_id": "CASE-003",
                 "claim_index": 2, "agent": "s", "source": "llm"},
        "R005": {"arm": "arm_two", "corpus": "cy", "case_id": "CASE-003",
                 "claim_index": 3, "agent": "s", "source": "llm"},
        "R006": {"arm": "arm_two", "corpus": "cy", "case_id": "CASE-004",
                 "claim_index": 0, "agent": "s", "source": "llm"},
    },
}

SYNTHETIC_ANSWERS = [
    # review_id, classification, new_ev, connected, paraphrase, next_action
    ("R001", "RESTATEMENT", "n", "n", "y", "n"),
    ("R002", "NEW_ACTIONABLE", "y", "y", "n", "y"),
    ("R003", "NEW_ACTIONABLE", "y", "y", "n", "y"),
    ("R004", "NEW_USEFUL_NONACTIONABLE", "n", "y", "n", "n"),
    ("R005", "SPECULATIVE_PLAUSIBLE", "n", "n", "n", "n"),
    ("R006", "WRONG", "y", "n", "n", "y"),
]


def _write_synthetic(tmp_path: Path, rows=SYNTHETIC_ANSWERS) -> tuple[Path, Path]:
    key_path = tmp_path / "KEY.sealed.json"
    key_path.write_text(json.dumps(SYNTHETIC_KEY), encoding="utf-8")
    answers_path = tmp_path / "answers.csv"
    with answers_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(scorer.ANSWER_COLUMNS)
        for row in rows:
            writer.writerow([*row, ""])
    return key_path, answers_path


def test_scorer_tallies_are_right_on_a_synthetic_sheet(tmp_path: Path) -> None:
    """Known-by-construction numbers, including the per-case comparison.

    arm_one: 2 hypotheses over 2 cases -> 1.0 per case, 1 useful -> 0.5 useful per case.
    arm_two: 4 hypotheses over 4 cases -> 1.0 per case, 2 useful -> 0.5 useful per case.
    The two arms are deliberately given the same per-case numbers from different rates
    (50% of 2 versus 50% of 4): a scorer that divided by the wrong denominator would
    make them differ.
    """
    key_path, answers_path = _write_synthetic(tmp_path)
    key = scorer.load_key(key_path)
    rows = scorer.validate(scorer.read_answers(answers_path), key, partial=False)
    result = scorer.tally(rows, key)

    one = result["per_arm"]["arm_one"]
    two = result["per_arm"]["arm_two"]

    assert one["hypotheses_scored"] == 2
    assert one["classifications"]["RESTATEMENT"]["count"] == 1
    assert one["classifications"]["NEW_ACTIONABLE"]["count"] == 1
    assert one["classifications"]["WRONG"]["count"] == 0
    assert one["classifications"]["RESTATEMENT"]["rate"] == 0.5
    assert one["flags"]["paraphrased_deterministic_finding"]["count"] == 1
    assert one["flags"]["would_change_next_action"]["rate"] == 0.5

    assert two["hypotheses_scored"] == 4
    assert two["classifications"]["NEW_ACTIONABLE"]["count"] == 1
    assert two["classifications"]["NEW_USEFUL_NONACTIONABLE"]["count"] == 1
    assert two["classifications"]["SPECULATIVE_PLAUSIBLE"]["count"] == 1
    assert two["classifications"]["WRONG"]["count"] == 1
    assert two["flags"]["introduced_new_evidence"]["count"] == 2
    assert two["flags"]["connected_existing_evidence_usefully"]["rate"] == 0.5
    assert two["per_corpus"]["cy"] == {
        "NEW_USEFUL_NONACTIONABLE": 1, "SPECULATIVE_PLAUSIBLE": 1, "WRONG": 1,
    }
    assert two["per_corpus"]["cx"] == {"NEW_ACTIONABLE": 1}
    # A degraded case is reported beside the denominator, not removed from it.
    assert two["cases_run"] == 4
    assert two["cases_model_degraded"] == 1
    assert one["cases_model_degraded"] == 0

    for arm, useful in ((one, 1), (two, 2)):
        compare = arm["more_hypotheses_vs_more_useful_investigation"]
        assert compare["useful_count"] == useful
        assert compare["hypotheses_per_case"] == 1.0
        assert compare["useful_per_case"] == 0.5
        assert compare["caveat"] == ""

    assert one["more_hypotheses_vs_more_useful_investigation"]["useful_rate"] == 0.5
    assert two["more_hypotheses_vs_more_useful_investigation"]["useful_rate"] == 0.5
    assert scorer.render(result)  # the renderer must survive its own output shape


def test_scorer_refuses_an_unfilled_sheet_and_accepts_it_with_partial(
    tmp_path: Path,
) -> None:
    """An unfilled row is a refusal, not a zero.

    Counting an unanswered row as "no" would make every rate's denominator include rows
    nobody judged -- a silent under-count of whichever arm the reviewer had not reached.
    """
    rows = list(SYNTHETIC_ANSWERS)
    rows[3] = ("R004", "", "", "", "", "")
    key_path, answers_path = _write_synthetic(tmp_path, rows)
    key = scorer.load_key(key_path)

    with pytest.raises(scorer.ReviewError, match="unfilled"):
        scorer.validate(scorer.read_answers(answers_path), key, partial=False)

    assert scorer.main(["--answers", str(answers_path), "--key", str(key_path)]) == 2

    filled = scorer.validate(scorer.read_answers(answers_path), key, partial=True)
    assert len(filled) == 5
    result = scorer.tally(filled, key)
    two = result["per_arm"]["arm_two"]
    assert two["hypotheses_emitted"] == 4
    assert two["hypotheses_scored"] == 3
    assert two["hypotheses_unscored"] == 1
    assert result["rows_skipped_unfilled"] == 1
    # The per-case comparison still divides by what the arm emitted, and says so.
    assert two["more_hypotheses_vs_more_useful_investigation"]["hypotheses_per_case"] == 1.0
    assert "lower bound" in two["more_hypotheses_vs_more_useful_investigation"]["caveat"]
    assert scorer.main(
        ["--answers", str(answers_path), "--key", str(key_path), "--partial"]
    ) == 0


def test_scorer_refuses_a_bad_value_or_an_unknown_review_id(tmp_path: Path) -> None:
    """A typo in a classification or a review id is refused, never coerced."""
    rows = list(SYNTHETIC_ANSWERS)
    rows[0] = ("R001", "RESTATEMNT", "n", "n", "y", "n")
    rows[1] = ("R999", "NEW_ACTIONABLE", "y", "y", "n", "y")
    key_path, answers_path = _write_synthetic(tmp_path, rows)
    key = scorer.load_key(key_path)

    with pytest.raises(scorer.ReviewError) as raised:
        scorer.validate(scorer.read_answers(answers_path), key, partial=True)
    message = str(raised.value)
    assert "RESTATEMNT" in message
    assert "R999" in message


def test_scorer_refuses_a_sheet_missing_a_column(tmp_path: Path) -> None:
    """The answer sheet's shape is checked before anything is counted from it."""
    path = tmp_path / "short.csv"
    path.write_text("review_id,classification\nR001,RESTATEMENT\n", encoding="utf-8")
    with pytest.raises(scorer.ReviewError, match="missing column"):
        scorer.read_answers(path)
