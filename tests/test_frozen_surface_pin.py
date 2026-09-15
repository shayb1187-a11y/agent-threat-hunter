"""The V1 local-model work must not move anything the M19b freeze gates on.

Why this test exists
---------------------
V1's first stage adds a local-model adapter, a D1 arm, a row store and a probe. Every one
of those is meant to be a *plugin*: new modules beside the frozen ones, never an edit to
them. The M19b freeze (``reports/m19b/ablation/ENVIRONMENT.json``) records the four prompt
hashes and the three scoring-file hashes that the pending Phase 8 run must reproduce, and
``scripts/m19b_ablation.py run`` refuses a model arm on any drift. That refusal fires only
when someone runs the harness. This test fires on every ``pytest``.

How it fails
-------------
If any V1 change edits ``arms.py``, ``scoring.py``, ``incidents.py`` or one of the four
prompt constants in ``orchestrator.py``, the live hash stops matching the committed one and
the test names which. That is a *decision*, not a defect -- but it has to be taken in the
open, recorded in ``PREREGISTERED.md`` as a divergence, followed by a re-freeze. What it
must never be is an accident discovered on the night the 9B run starts.

The values are read from the committed freeze rather than typed here, so this file does
not become a second copy of the truth that can drift from the first.
"""

from __future__ import annotations

import json
from pathlib import Path

from ath.evaluation.ablation.environment import prompt_hashes, scoring_hashes

ROOT = Path(__file__).resolve().parent.parent
M19B_FREEZE = ROOT / "reports" / "m19b" / "ablation" / "ENVIRONMENT.json"


def _recorded() -> dict:
    payload = json.loads(M19B_FREEZE.read_text(encoding="utf-8"))
    return payload["environment"]


def test_the_four_prompts_are_the_ones_the_m19b_freeze_recorded() -> None:
    recorded = _recorded()["prompts"]
    live = prompt_hashes()
    moved = sorted(name for name in set(recorded) | set(live) if recorded.get(name) != live.get(name))
    assert not moved, (
        f"prompt(s) {moved} differ from reports/m19b/ablation/ENVIRONMENT.json. A prompt "
        "edit is a divergence from the M19b pre-registration: record it and re-freeze, or "
        "put the new prompt in a new module."
    )


def test_the_three_scoring_files_are_the_ones_the_m19b_freeze_recorded() -> None:
    recorded = _recorded()["scoring"]
    live = scoring_hashes()
    moved = sorted(name for name in set(recorded) | set(live) if recorded.get(name) != live.get(name))
    assert not moved, (
        f"scoring file(s) {moved} differ from reports/m19b/ablation/ENVIRONMENT.json. The "
        "V1 local-model stage is additive by design; new arms, stores and metrics belong "
        "in new modules."
    )
