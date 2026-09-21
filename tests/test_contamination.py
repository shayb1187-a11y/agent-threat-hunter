"""Contamination check: the dev split and the prompts never touch a frozen case.

Why this test exists
---------------------
The repository has no CI, so this is the CI job the V1 plan asks for. Two leaks would make
every later dev-split number worthless without anyone noticing: a dev case that is also a
frozen benchmark case (tuning on the test set), and a frozen case's name or id inside a
prompt or few-shot file (teaching the model the answer key).

How it fails
-------------
*Structural overlap.* Fails if any dev entry shares a ``(telemetry_hash, case_id)`` pair or a
single finding id with an M19 or M19b entry. Case-id strings alone are not compared --
every corpus has a ``CASE-001`` -- which is what makes the negative control below
meaningful: it inserts a real frozen entry and the check must catch it.

*Nominal leak.* Fails if a frozen case name (``INC-001``, ``M1``..``M4``, ``L1``, ``L2``,
``HELDOUT_H1``) or a dev case name (``V1``..``V10``) appears as a whole token in any of the
four prompt constants or in any file under ``prompts/``.

The dev manifest is built by a script over external data, so when it is absent the
structural tests skip with a reason rather than pass vacuously.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from ath.agent.orchestrator import (  # noqa: E402
    PLANNER_SYSTEM,
    PLANNER_USER_TEMPLATE,
    SYNTHESIS_SYSTEM,
    SYNTHESIS_USER_TEMPLATE,
)
from ath.evaluation.ablation import load_manifest  # noqa: E402
from local_manifest import (  # noqa: E402
    FROZEN_MANIFESTS,
    MANIFEST_PATH,
    contamination,
    frozen_entries,
)

FROZEN_NAMES = ("INC-001", "M1", "M2", "M3", "M4", "L1", "L2", "HELDOUT_H1")
DEV_NAMES = tuple(f"V{i}" for i in range(1, 11))


def _dev_entries():
    if not MANIFEST_PATH.exists():
        pytest.skip("dev manifest not built yet (python scripts/local_manifest.py build)")
    return load_manifest(json.loads(MANIFEST_PATH.read_text(encoding="utf-8")))


def test_the_frozen_manifests_exist_and_are_the_ones_the_check_reads() -> None:
    for path in FROZEN_MANIFESTS:
        assert path.exists(), path
    assert len(frozen_entries()) == 22 + 9


def test_the_dev_split_is_structurally_disjoint_from_every_frozen_benchmark() -> None:
    problems = contamination(_dev_entries(), frozen_entries())
    assert problems == [], "\n".join(problems)


def test_the_dev_split_has_twenty_cases_and_no_frozen_corpus_key() -> None:
    dev = _dev_entries()
    assert len(dev) == 20
    frozen_keys = {e.key for e in frozen_entries()}
    assert not ({e.key for e in dev} & frozen_keys)


def test_the_negative_control_is_caught() -> None:
    """A copy of the dev split with one real frozen entry inserted must fail the check."""
    dev = list(_dev_entries())
    frozen = frozen_entries()
    poisoned = dev + [frozen[0]]
    problems = contamination(poisoned, frozen)
    assert problems, "inserting a frozen entry must be detected"
    assert frozen[0].key in "\n".join(problems)


def test_a_shared_finding_id_alone_is_caught_even_under_a_new_case_id() -> None:
    """The correlator can renumber cases; a shared finding id is the leak that survives."""
    from dataclasses import replace

    dev = list(_dev_entries())
    frozen = frozen_entries()
    disguised = replace(frozen[0], corpus="somewhere_else", case_id="CASE-999", telemetry_hash="0" * 64)
    problems = contamination(dev + [disguised], frozen)
    assert any("shares finding id" in p for p in problems)


@pytest.mark.parametrize("name", FROZEN_NAMES + DEV_NAMES)
def test_no_case_name_appears_in_a_prompt(name: str) -> None:
    pattern = re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(name)}(?![A-Za-z0-9_-])")
    texts = {
        "PLANNER_SYSTEM": PLANNER_SYSTEM, "PLANNER_USER_TEMPLATE": PLANNER_USER_TEMPLATE,
        "SYNTHESIS_SYSTEM": SYNTHESIS_SYSTEM, "SYNTHESIS_USER_TEMPLATE": SYNTHESIS_USER_TEMPLATE,
    }
    prompts_dir = ROOT / "prompts"
    if prompts_dir.is_dir():
        for path in sorted(prompts_dir.rglob("*")):
            if path.is_file():
                texts[str(path.relative_to(ROOT))] = path.read_text(encoding="utf-8", errors="replace")
    leaks = [where for where, text in texts.items() if pattern.search(text)]
    assert leaks == [], f"{name!r} appears in {leaks}"
