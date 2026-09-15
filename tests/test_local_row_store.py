"""The row store: one file per key, resumable, and never inside a frozen experiment.

Why these tests exist
----------------------
An overnight local run is twenty-odd cases at a minute or more each. M19b's harness wrote
its file once at the end; a crash at case 19 lost the night, and a restart had no memory.
The store's contract is small and each clause has a way to be wrong silently:

*Injectivity.* Two keys that differ only in a character the filename slugs away (``:``
vs ``_``) would share a file, and one would overwrite the other's row. Fails if the digest
leaves the filename.

*Resumability.* A complete row must be skipped and a half-written one must not. Fails if
``read_row`` accepts any JSON as a row, or if a degraded row is treated as incomplete
(then the failure would be silently retried until it passed -- the exact behaviour the V1
plan forbids).

*Guards.* Fails if a path under ``reports/m19/`` or ``reports/m19b/`` can be written,
or if an oversized row is written rather than refused.
"""

from __future__ import annotations

import json

import pytest

from ath.evaluation.ablation import CaseScores
from ath.evaluation.ablation.arms import CaseResult
from ath.evaluation.ablation.local import (
    FrozenPathRefused,
    RowKey,
    RowTooLarge,
    completed_rows,
    is_complete,
    read_row,
    refuse_frozen_path,
    row_path,
    write_row,
)


def _key(**overrides) -> RowKey:
    base = dict(
        corpus="dedale_injected:M1", case_id="CASE-001", arm="D1_local_single",
        provider="ollama", model="qwen3.5:4b", quantization="Q4_K_M", repeat=1, seed=0,
    )
    base.update(overrides)
    return RowKey(**base)


def _result(*, degraded: bool = False, state: dict | None = None) -> CaseResult:
    return CaseResult(
        arm="D1_local_single", corpus="dedale_injected:M1", case_id="CASE-001",
        manifest_hash="m" * 64, telemetry_hash="t" * 64, configuration="ollama",
        llm_degraded=degraded, llm_status="ok" if not degraded else "DEGRADED -- x",
        state=state or {"agents_run": []}, scores=CaseScores(),
    )


# --------------------------------------------------------------------------------------
# Keys and paths
# --------------------------------------------------------------------------------------


def test_the_filename_is_readable_and_carries_every_key_field() -> None:
    name = _key().filename
    for part in ("dedale_injected_M1", "CASE-001", "D1_local_single", "ollama",
                 "qwen3.5_4b", "Q4_K_M", "rep1", "seed0"):
        assert part in name, part
    assert name.endswith(".json")


def test_keys_that_slug_alike_do_not_share_a_file() -> None:
    a, b = _key(model="qwen3.5:4b"), _key(model="qwen3.5_4b")
    assert a.filename != b.filename
    assert a.digest != b.digest


@pytest.mark.parametrize("field,value", [
    ("repeat", 2), ("seed", 7), ("seed", None), ("quantization", "Q8_0"),
    ("provider", "cerebras"), ("arm", "D2_self_consistency"), ("case_id", "CASE-002"),
])
def test_every_key_field_changes_the_path(field, value, tmp_path) -> None:
    assert row_path(tmp_path, _key()) != row_path(tmp_path, _key(**{field: value}))


def test_a_key_round_trips_through_its_dict() -> None:
    key = _key(seed=None)
    assert RowKey.from_dict(json.loads(json.dumps(key.to_dict()))) == key


# --------------------------------------------------------------------------------------
# Writing, reading, skipping
# --------------------------------------------------------------------------------------


def test_a_written_row_is_complete_and_reads_back(tmp_path) -> None:
    key = _key()
    path = write_row(tmp_path / "rows", key, _result(), {"head": "abc"}, root=tmp_path)
    assert path == row_path(tmp_path / "rows", key)
    assert is_complete(path)
    payload = read_row(path)
    assert payload["key"] == key.to_dict()
    assert payload["header"] == {"head": "abc"}
    assert payload["row"]["arm"] == "D1_local_single"
    assert not list((tmp_path / "rows").glob("*.partial")), "no temp file left behind"


def test_a_degraded_row_is_complete_and_is_not_rerun(tmp_path) -> None:
    """Silently retrying a failure until it passes is how reliability disappears."""
    path = write_row(tmp_path / "rows", _key(), _result(degraded=True), {}, root=tmp_path)
    assert is_complete(path)
    assert read_row(path)["row"]["llm_degraded"] is True


def test_a_missing_row_is_incomplete(tmp_path) -> None:
    assert not is_complete(row_path(tmp_path, _key()))
    assert read_row(row_path(tmp_path, _key())) is None


@pytest.mark.parametrize("content", [
    "", "{", '{"key": {}}', '{"row": {}}', '[1, 2]', '{"key": {}, "row": {"arm": "x"}}',
    '{"key": {}, "row": {"scores": {}}}',
])
def test_a_partial_or_foreign_file_is_incomplete_and_will_be_rewritten(tmp_path, content) -> None:
    path = row_path(tmp_path, _key())
    path.write_text(content, encoding="utf-8")
    assert read_row(path) is None
    written = write_row(tmp_path, _key(), _result(), {}, root=tmp_path)
    assert written == path and is_complete(path)


def test_completed_rows_lists_only_complete_ones(tmp_path) -> None:
    rows = tmp_path / "rows"
    write_row(rows, _key(repeat=1), _result(), {}, root=tmp_path)
    write_row(rows, _key(repeat=2), _result(), {}, root=tmp_path)
    (rows / "broken.json").write_text("{", encoding="utf-8")
    (rows / "notes.txt").write_text("x", encoding="utf-8")
    assert len(completed_rows(rows)) == 2
    assert completed_rows(tmp_path / "absent") == []


# --------------------------------------------------------------------------------------
# Guards
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("relative", [
    "reports/m19", "reports/m19/ablation/arm_A.json", "reports/m19b",
    "reports/m19b/ablation/rows/x.json", "reports/m19b/review/KEY.sealed.json",
])
def test_writes_under_a_frozen_experiment_are_refused(tmp_path, relative) -> None:
    with pytest.raises(FrozenPathRefused):
        refuse_frozen_path(tmp_path / relative, tmp_path)
    with pytest.raises(FrozenPathRefused):
        write_row((tmp_path / relative).parent if relative.endswith(".json") else tmp_path / relative,
                  _key(), _result(), {}, root=tmp_path)


@pytest.mark.parametrize("relative", ["reports/local/dev/rows", "reports/m19c", "reports/m19b-notes"])
def test_writes_beside_a_frozen_experiment_are_allowed(tmp_path, relative) -> None:
    assert refuse_frozen_path(tmp_path / relative / "x.json", tmp_path)


def test_an_oversized_row_is_refused_not_truncated(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("ath.evaluation.ablation.local.MAX_ROW_BYTES", 1000)
    big = _result(state={"agents_run": [], "blob": "x" * 5000})
    with pytest.raises(RowTooLarge):
        write_row(tmp_path, _key(), big, {}, root=tmp_path)
    assert not row_path(tmp_path, _key()).exists()
