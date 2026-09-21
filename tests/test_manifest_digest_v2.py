"""The v2 telemetry digest: every encoding rule stated in the plan, one test each, and a
pinned digest for a constructed frame so a runtime that renders values differently is
caught here rather than on Colab.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from ath.evaluation.ablation import manifest as m


def _digest(frame: pd.DataFrame) -> str:
    return m.table_digest_v2(frame)


def _cells(series: pd.Series) -> list[str]:
    tag, text = m.canonical_column(series)
    return [tag, *text.astype(object).tolist()]


def test_every_null_kind_is_one_sentinel() -> None:
    assert _cells(pd.Series([1, None], dtype="Int64")) == ["int", "1", m._NULL]
    assert _cells(pd.Series([1.0, np.nan])) == ["float", "1.0", m._NULL]
    assert _cells(pd.Series(["a", None], dtype="string")) == ["str", "a", m._NULL]
    assert _cells(pd.Series([pd.Timestamp("2026-01-01", tz="UTC"), pd.NaT]))[2] == m._NULL
    assert _cells(pd.Series([None, pd.NA, np.nan], dtype=object)) == ["str", m._NULL, m._NULL, m._NULL]


def test_floats_are_shortest_repr_with_signed_zero_and_infinities_normalised() -> None:
    assert _cells(pd.Series([0.1 + 0.2, -0.0, float("inf"), float("-inf")])) == [
        "float", "0.30000000000000004", "0.0", "\x00INF", "\x00-INF",
    ]


def test_integers_are_decimal_whatever_their_width() -> None:
    assert _cells(pd.Series([1, 2], dtype="int32")) == _cells(pd.Series([1, 2], dtype="int64"))


def test_bools_are_zero_and_one() -> None:
    assert _cells(pd.Series([True, False])) == ["bool", "1", "0"]


def test_datetimes_are_utc_nanoseconds_and_a_naive_column_says_so() -> None:
    aware = pd.Series([pd.Timestamp("2026-01-01T00:00:00", tz="Europe/Paris")])
    naive = pd.Series([pd.Timestamp("2025-12-31T23:00:00")])
    assert _cells(aware) == ["datetime", str(pd.Timestamp("2025-12-31T23:00:00").value)]
    assert _cells(naive) == ["datetime-naive", str(pd.Timestamp("2025-12-31T23:00:00").value)]
    micro = pd.Series([pd.Timestamp("2026-01-01T00:00:00.5")]).astype("datetime64[us]")
    nano = pd.Series([pd.Timestamp("2026-01-01T00:00:00.5")]).astype("datetime64[ns]")
    assert _cells(micro) == _cells(nano)


def test_strings_are_nfc_normalised() -> None:
    composed = pd.Series(["é"], dtype="string")
    decomposed = pd.Series(["é"], dtype="string")
    assert _cells(composed) == _cells(decomposed) == ["str", "é"]


def test_an_object_column_that_mixes_types_tags_every_cell() -> None:
    assert _cells(pd.Series(["1", 1, 1.5, True, None], dtype=object)) == [
        "object", "str:1", "int:1", "float:1.5", "bool:1", m._NULL,
    ]


def test_a_str_one_and_an_int_one_hash_differently() -> None:
    assert _digest(pd.DataFrame({"x": pd.Series(["1"], dtype="string")})) != _digest(pd.DataFrame({"x": [1]}))


def test_column_order_does_not_matter_but_row_order_does() -> None:
    a = pd.DataFrame({"x": [1, 2], "y": ["a", "b"]})
    assert _digest(a) == _digest(a[["y", "x"]])
    assert _digest(a) != _digest(a.iloc[::-1].reset_index(drop=True))


def test_the_pinned_digest_of_a_constructed_frame() -> None:
    frame = pd.DataFrame({
        "n": pd.Series([1, None, 3], dtype="Int64"),
        "f": [0.5, -0.0, np.nan],
        "s": pd.Series(["a", "é", None], dtype="string"),
        "t": pd.to_datetime(["2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", None]),
        "b": [True, False, True],
        "o": pd.Series(["x", 2, None], dtype=object),
    })
    assert _digest(frame) == "a8d93b005b59c4b594994fe596503517663a2560bc791cfaaad407d869387f05"
    assert _digest(frame) == _digest(frame.copy())
    assert m.column_digests(frame, 2).keys() == {"b", "f", "n", "o", "s", "t"}


def test_the_dispatcher_keeps_version_one_byte_for_byte() -> None:
    from tests._builders import telemetry as build

    from ath.telemetry.loader import Telemetry

    corpus = build()
    assert m.telemetry_digest(corpus, 1) == m.telemetry_hash(corpus)
    assert m.telemetry_digest(corpus, 2) != m.telemetry_hash(corpus)
    with pytest.raises(ValueError):
        m.telemetry_digest(corpus, 3)
    assert isinstance(corpus, Telemetry)


def test_a_version_one_entry_serialises_exactly_as_before_and_a_v2_entry_says_so() -> None:
    v1 = m.CaseManifest("c", "CASE-001", ("R",), "R", ("f",), ("e",), "h")
    assert "digest_version" not in v1.to_dict()
    assert m.CaseManifest.from_dict(v1.to_dict()) == v1
    v2 = m.CaseManifest("c", "CASE-001", ("R",), "R", ("f",), ("e",), "h", digest_version=2)
    assert v2.to_dict()["digest_version"] == 2
    assert m.CaseManifest.from_dict(v2.to_dict()) == v2
    assert m.manifest_hash([v1]) != m.manifest_hash([v2])
