"""The files and objects the upgrade plan says must not change, held by source hash.

The identity pin catches a value drifting. This one catches an *edit* to a frozen file or
function before it has a chance to move a value: ``arms.py``, ``scoring.py``, the pinned
generator scripts, the committed manifests, the pending-comparison notebook, and the
row-store and digest functions whose bodies define row identity. Regenerate after a
deliberate re-freeze with ``python -m ath.experiments.identity --write``.
"""

from __future__ import annotations

import json

from ath.experiments.identity import SOURCES_FIXTURE, frozen_sources


def test_no_frozen_file_or_object_was_edited() -> None:
    recorded = json.loads(SOURCES_FIXTURE.read_text(encoding="utf-8"))
    live = frozen_sources()
    moved = sorted(
        name for name in set(recorded) | set(live) if recorded.get(name) != live.get(name)
    )
    assert not moved, (
        f"frozen source(s) edited: {moved}. Editing one is a re-freeze decision; record "
        "it and run `python -m ath.experiments.identity --write`."
    )
