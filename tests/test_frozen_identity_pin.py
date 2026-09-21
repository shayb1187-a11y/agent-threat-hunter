"""Every value a comparison gate reads must recompute to what the checkout recorded.

Why this test exists
---------------------
The architecture upgrade (2026-09-21 plan) moves the experiment runner into a package and
adds opt-in behaviour to the agent layer while a D1 v3 model comparison is pending. The
rule is hash-neutral: rows written before the refactor must validate and compare after
it. ``tests/fixtures/frozen_identity.json`` holds the values captured before the first
change; this test recomputes them live. A difference is a decision to re-freeze, not a
defect, and must be taken by regenerating the fixture on purpose::

    python -m ath.experiments.identity --write
"""

from __future__ import annotations

import json

from ath.experiments.identity import (
    IDENTITY_FIXTURE,
    frozen_surface,
    frozen_surface_sha256,
)


def _recorded() -> dict:
    return json.loads(IDENTITY_FIXTURE.read_text(encoding="utf-8"))


def _diff(recorded, live, path=""):
    if isinstance(recorded, dict) and isinstance(live, dict):
        out = []
        for key in sorted(set(recorded) | set(live)):
            out += _diff(recorded.get(key), live.get(key), f"{path}/{key}")
        return out
    return [] if recorded == live else [f"{path}: recorded={recorded!r} live={live!r}"]


def test_every_gated_value_recomputes_to_the_recorded_one() -> None:
    live = frozen_surface()
    moved = _diff(_recorded()["surface"], live)
    assert not moved, "frozen surface moved:\n  " + "\n  ".join(moved)


def test_the_combined_identity_digest_is_unchanged() -> None:
    assert frozen_surface_sha256() == _recorded()["frozen_surface_sha256"]


def test_committed_manifests_still_hash_to_their_recorded_value() -> None:
    for relative, hashes in frozen_surface()["manifests"].items():
        assert hashes["recorded"] == hashes["recomputed"], relative
