"""The scripted harness: it proves the arm's path runs, and says nothing about a model.

Why these tests exist
----------------------
A scripted run is the most dangerous artifact in this milestone. It looks exactly like an
arm B result -- same file shape, same scores, same case ids -- and it contains no model
output at all. Two mechanisms keep it from being read as one, and both are tested here:
the row label (``*_SCRIPTED``, asserted in ``test_ablation_harness.py``) and the output
directory.

How each fails
---------------
*Paths.* ``arm_output_path`` fails if a scripted run can ever address ``arm_B.json``.
``refuse_mislabelled_output`` fails if it stops checking the rows themselves -- it must
refuse on what the rows say they are, not on the flag that produced them, because the
flag is gone by the time anybody reads the file.

*The client.* The planner answer must name an eligible candidate and the synthesis answer
must exercise the accepted, the unsupported and the out-of-scope paths. These fail if the
canned text stops matching the prompt shape the orchestrator actually sends, in which
case the "harness proof" would prove only that a fallback works.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from ath.agent.orchestrator import PLANNER_SYSTEM, SYNTHESIS_SYSTEM  # noqa: E402
from m19_ablation import (  # noqa: E402
    SCRIPTED_DIR_NAME,
    ScriptedArmLLM,
    arm_output_path,
    refuse_mislabelled_output,
)


class _Row:
    def __init__(self, scripted: bool) -> None:
        self.scripted = scripted


def test_a_scripted_run_cannot_address_the_real_arm_file(tmp_path) -> None:
    assert arm_output_path(tmp_path, "B", False) == tmp_path / "arm_B.json"
    assert arm_output_path(tmp_path, "B", True) == (
        tmp_path / SCRIPTED_DIR_NAME / "arm_B.json"
    )


def test_writing_scripted_rows_beside_real_ones_is_refused(tmp_path) -> None:
    """Fails if the guard trusts the path instead of checking the rows."""
    with pytest.raises(SystemExit, match="scripted"):
        refuse_mislabelled_output(tmp_path / "arm_B.json", [_Row(True)])


def test_writing_real_rows_into_the_scripted_directory_is_refused(tmp_path) -> None:
    with pytest.raises(SystemExit, match="reserved"):
        refuse_mislabelled_output(
            tmp_path / SCRIPTED_DIR_NAME / "arm_B.json", [_Row(False)]
        )


def test_the_expected_pairing_is_allowed(tmp_path) -> None:
    refuse_mislabelled_output(tmp_path / "arm_B.json", [_Row(False)])
    refuse_mislabelled_output(
        tmp_path / SCRIPTED_DIR_NAME / "arm_B.json", [_Row(True)]
    )


def test_the_planner_answer_names_an_eligible_candidate() -> None:
    """And names the *last* one, so the plan log distinguishes it from the fallback."""
    prompt = "\n".join([
        "Case: CASE-001",
        "Candidates:",
        "  endpoint: process execution (eligible because x)",
        "  attack: ATT&CK (eligible because y)",
    ])
    response = ScriptedArmLLM().complete(PLANNER_SYSTEM, prompt)
    assert response.parsed["next_agent"] == "attack"


def test_the_planner_reads_a_candidate_name_that_contains_a_colon() -> None:
    """Arm B's candidates are ``generalist:<facet>``. The separator is colon-space.

    Fails if the candidate parser splits on the first colon: it then answers
    ``"generalist"``, which is not an eligible name, the orchestrator discards it, and
    every scripted step falls back to the deterministic order -- a harness proof that
    proves only the fallback. That is exactly what happened on the first M19-3 run.
    """
    prompt = "\n".join([
        "Case: CASE-001",
        "Candidates:",
        "  generalist:case: the case record itself (eligible because x)",
        "  generalist:technique: the verified ATT&CK entry (eligible because y)",
    ])
    response = ScriptedArmLLM().complete(PLANNER_SYSTEM, prompt)
    assert response.parsed["next_agent"] == "generalist:technique"


def test_the_planner_declines_rather_than_inventing_a_name() -> None:
    """A candidate list it cannot read must produce "none", never a guess."""
    response = ScriptedArmLLM().complete(PLANNER_SYSTEM, "Case: CASE-001\n")
    assert response.parsed["next_agent"] == "none"


def test_the_synthesis_answer_exercises_all_three_guardrails() -> None:
    prompt = "Case CASE-001. Verified claims:\n- [FACT] a thing (evidence: evt-1, evt-2)"
    response = ScriptedArmLLM().complete(SYNTHESIS_SYSTEM, prompt)
    claims = response.parsed["claims"]
    assert [c["type"] for c in claims] == ["INFERENCE", "HYPOTHESIS", "INFERENCE"]
    assert claims[0]["evidence_ids"] == ["evt-1"], "cites evidence it was shown"
    assert claims[1]["evidence_ids"] == [], "a hypothesis may cite nothing"
    assert claims[2]["evidence_ids"] == ["evt-does-not-exist"], "out-of-scope guard"


def test_the_scripted_client_never_authors_a_fact() -> None:
    """Structurally impossible downstream, and not attempted here either."""
    prompt = "Case CASE-001. Verified claims:\n- [FACT] a thing (evidence: evt-1)"
    payload = json.loads(ScriptedArmLLM().complete(SYNTHESIS_SYSTEM, prompt).text)
    assert all(c["type"] != "FACT" for c in payload["claims"])
