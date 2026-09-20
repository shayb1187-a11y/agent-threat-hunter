"""Artifacts nobody can open, refused at the writer and again over the committed tree.

The failure this exists for
----------------------------
M19-2 committed a **372 MB** ``reports/m19/ablation/scripted/arm_B.json``, replaced it,
and left the blob in this repository's history where it will stay. One unfiltered
``host_network_activity`` call on a COMISET host returns 589,476 event ids, and both the
tool call and the claim it fed recorded every one of them, twice per case. The id lists
are now bounded by :data:`~ath.evaluation.ablation.arms.MAX_SERIALISED_IDS`; that fixes
the field that was known to grow. These tests are about the field that is not known yet.

Two guards, and why both
-------------------------
*The writer* (:func:`m19_ablation.write_artifact`) refuses a single file above 50 MB,
prints where the bytes were, and exits non-zero, so the file never reaches the working
tree. It fails if the refusal is downgraded to a truncation -- a results file silently
trimmed to fit has numbers that no longer add up, and recomputability is the only reason
these artifacts are committed at all.

*The sweep* asserts that every file under ``reports/`` is below 60 MB, with no
exceptions. It fails the moment an oversized artifact is produced by any route the
writer does not own -- a different script, a manual copy, a future milestone -- which is
what actually happened: the 372 MB file was committed before anybody measured it. The
two limits differ on purpose: a writer that refuses at 50 MB cannot grow the tree to the
60 MB the sweep would reject, so the two guards can never disagree about a file between
them.

The sweep used to carry two named exceptions, the ~53 MB COMISET canonical network
parquet for M17 and M18b. Those files were removed from the tree and from history
before publication (see README "External datasets"), so the allowlist is empty and the
sweep is unconditional. It should stay that way: an exception list is a statement about
the tree, and the next unbounded artifact deserves a red test, not an entry.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from m19_ablation import (  # noqa: E402
    MAX_ARTIFACT_BYTES,
    largest_fields,
    write_artifact,
)

REPORTS_SIZE_LIMIT = 60 * 1024 * 1024
"""Largest committed file ``reports/`` may contain, outside the named exceptions."""

KNOWN_LARGE: tuple[str, ...] = ()
"""Files under ``reports/`` allowed at or above the limit, by exact path. Empty, and
meant to stay empty: the two COMISET parquet freezes this once named were removed from
the repository before publication. If an entry is ever added, add the existence test
back with it, so a stale entry cannot silently cover nothing.
"""


# --------------------------------------------------------------------------------------
# The writer
# --------------------------------------------------------------------------------------


def test_an_oversized_artifact_is_refused_and_no_file_is_written(tmp_path, capsys):
    """The refusal is the whole feature: no file, non-zero exit, and where the bytes were.

    Fails if the guard is removed, if it truncates instead of refusing, or if it writes
    the file first and complains afterwards -- which would leave exactly the artifact it
    exists to prevent.
    """
    out = tmp_path / "arm_B.json"
    payload = {"cases": [{"state": {"blob": "x" * (MAX_ARTIFACT_BYTES + 4096)}}]}

    with pytest.raises(SystemExit) as excinfo:
        write_artifact(out, payload)

    assert excinfo.value.code != 0
    assert not out.exists(), "a refused artifact must leave nothing behind"
    printed = capsys.readouterr().err
    assert "REFUSED" in printed
    assert str(out) in printed
    assert "largest fields:" in printed
    assert "cases[0].state" in printed, "the refusal must name where the bytes were"


def test_an_artifact_within_the_limit_is_written_unchanged(tmp_path):
    """Fails if the guard starts rewriting the payloads it accepts."""
    out = tmp_path / "nested" / "arm_A.json"
    payload = {"cases": [{"case_id": "CASE-001", "scores": {"facts": 3}}]}

    write_artifact(out, payload)

    assert json.loads(out.read_text(encoding="utf-8")) == payload


def test_the_refusal_names_the_largest_field_first():
    """Fails if the diagnostic stops being ordered, which makes it noise rather than a
    pointer at the field that grew."""
    payload = {
        "small": ["a"],
        "cases": [{"event_ids": ["evt-%06d" % i for i in range(5000)]}],
    }

    ranked = largest_fields(payload, depth=3, top=3)

    assert ranked[0][0] == "cases"
    assert [size for _path, size in ranked] == sorted(
        (size for _path, size in ranked), reverse=True
    )


# --------------------------------------------------------------------------------------
# The committed tree
# --------------------------------------------------------------------------------------


def test_every_file_under_reports_is_small_enough_to_open():
    """The sweep that would have caught the 372 MB file before it was committed.

    Fails when any file under ``reports/`` reaches 60 MB -- including one produced by a
    script this test has never heard of, which is the case the writer's own guard cannot
    cover.
    """
    allowed = set(KNOWN_LARGE)
    oversized = []
    for path in sorted((ROOT / "reports").rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT).as_posix()
        if relative in allowed:
            continue
        size = path.stat().st_size
        if size >= REPORTS_SIZE_LIMIT:
            oversized.append(f"{relative} ({size / 1e6:.1f} MB)")

    assert not oversized, (
        "artifacts at or above 60 MB, and not in the named exception list: "
        + ", ".join(oversized)
    )

