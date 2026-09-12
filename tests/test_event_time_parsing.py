"""Equivalence tests for the per-record timestamp fast path.

``ath.telemetry.normalize.parse_event_time`` exists for one reason -- speed -- and an
optimisation that changes a single canonical value is not an optimisation, it is a
second parser with its own semantics. Every test here therefore asserts the *same*
thing in three different ways: for this input, the fast path and
``pd.to_datetime(value, utc=True, errors="coerce")`` produce the same timestamp, or
both produce ``NaT``.

Three populations, because each can fail the others' way:

* a hand-picked table of the forms that exist in the wild and the forms that break
  parsers (fractional seconds of every legal length, offsets in both directions, a
  lowercase ``z``, a missing ``T``, an impossible month, 24:00, a leap day, non-strings);
* 2,000 generated strings, valid and corrupted, so the table cannot be the whole
  specification;
* every distinct ``eventTime`` in a real CloudTrail corpus, opt-in because reading it
  takes minutes (see :data:`REAL_SAMPLE_ENV`).
"""

from __future__ import annotations

import os
import random
from pathlib import Path

import pandas as pd
import pytest

from ath.telemetry.normalize import parse_event_time

ROOT = Path(__file__).resolve().parent.parent
FLAWS_RAW = ROOT / "data" / "external" / "flaws_cloud" / "raw"

REAL_SAMPLE_ENV = "ATH_EVENT_TIME_REAL_SAMPLE"
"""Set to ``1`` to run the real-corpus comparison.

Opt-in rather than automatic: the sample is drawn by streaming a 250MB CloudTrail tar,
which costs minutes. The measurement it produces belongs in the milestone report, not
in every developer's edit-test loop.
"""

REAL_SAMPLE_TARGET = 50_000
"""Distinct ``eventTime`` strings to compare. Distinct, not first-N: a million copies
of one string proves one string."""


def fallback(value: object) -> pd.Timestamp:
    """The definition the fast path must not disagree with."""
    return pd.to_datetime(value, utc=True, errors="coerce")


def agree(value: object) -> bool:
    """Whether both paths give the same instant, or both give ``NaT``."""
    fast, slow = parse_event_time(value), fallback(value)
    if pd.isna(fast) or pd.isna(slow):
        return bool(pd.isna(fast) and pd.isna(slow))
    return bool(fast == slow)


def assert_same(value: object) -> None:
    """Both paths agree on this input -- same instant, or both NaT."""
    fast = parse_event_time(value)
    slow = fallback(value)
    if pd.isna(slow):
        assert pd.isna(fast), f"{value!r}: fallback NaT, fast path {fast!r}"
        return
    assert not pd.isna(fast), f"{value!r}: fallback {slow!r}, fast path NaT"
    assert fast == slow, f"{value!r}: fast {fast!r} != fallback {slow!r}"
    assert fast.tz is not None and str(fast.tz) == "UTC", f"{value!r}: {fast.tz}"


# --------------------------------------------------------------------------------------
# 1. The hand-picked table
# --------------------------------------------------------------------------------------

HAND_PICKED: tuple[object, ...] = (
    # -- the shapes the fast path claims -------------------------------------------
    "2017-02-12T21:23:20Z",                    # the CloudTrail / Kubernetes form
    "2017-02-12T21:23:20.1Z",                  # 1 fractional digit
    "2017-02-12T21:23:20.123Z",                # 3 -- milliseconds (winlogbeat)
    "2017-02-12T21:23:20.123456Z",             # 6 -- microseconds
    "2017-02-12T21:23:20.1234567Z",            # 7 -- beyond datetime's resolution
    "2017-02-12T21:23:20.12345678Z",           # 8
    "2017-02-12T21:23:20.123456789Z",          # 9 -- full nanoseconds
    "2017-02-12T21:23:20.000000000Z",          # 9 zeros: a fraction that is not a value
    "2017-02-12T21:23:20+00:00",               # explicit zero offset
    "2017-02-12T21:23:20-05:00",               # behind UTC: the day may roll forward
    "2017-02-12T21:23:20+03:00",               # ahead of UTC
    "2017-02-12T21:23:20.500-05:30",           # half-hour offset with a fraction
    "2017-02-12T21:23:20+14:00",               # the largest real offset
    "2016-02-29T12:00:00Z",                    # leap day in a leap year
    "1970-01-01T00:00:00Z",                    # Unix epoch zero
    "2262-04-11T23:47:16Z",                    # the last instant pandas can hold in ns
    # -- shapes it must hand to the fallback ---------------------------------------
    "2017-02-12t21:23:20z",                    # lowercase z
    "2017-02-12 21:23:20Z",                    # space instead of T
    "2017-02-12T21:23:20",                     # no zone at all
    "2017-02-12",                              # date only
    "2017-02-12T21:23:20.123456789012Z",       # 12 fractional digits: beyond the pattern
    "٢٠١٧-02-12T21:23:20Z",  # Arabic-Indic digits in the year
    # -- well-shaped strings naming no instant -------------------------------------
    "2017-13-01T00:00:00Z",                    # month 13
    "2017-02-30T00:00:00Z",                    # 30 February
    "2017-02-29T00:00:00Z",                    # leap day in a common year
    "2017-02-12T24:00:00Z",                    # 24:00 -- legal ISO-8601, illegal here
    "2017-02-12T21:60:00Z",                    # minute 60
    "1500-01-01T00:00:00Z",                    # before pandas' nanosecond range
    "9999-12-31T23:59:59Z",                    # after it
    # -- not a timestamp at all ----------------------------------------------------
    "garbage",
    "",
    "   ",
    None,
    1_486_934_600,                             # an integer
    1.5,                                       # a float
    True,                                      # a bool
    pd.NaT,
    float("nan"),
)


@pytest.mark.parametrize("value", HAND_PICKED, ids=lambda v: repr(v)[:40])
def test_hand_picked_values_parse_identically(value: object) -> None:
    """Fails the moment the fast path's answer differs from pandas' for any of them.

    Concretely: it fails if the pattern ever accepts a form pandas reads differently
    (a lowercase ``z``, Unicode digits, 24:00), if a fraction is scaled wrongly (``.1``
    is 100ms, not 1ns), if an offset is applied with the wrong sign, or if a
    non-string stops being delegated.
    """
    assert_same(value)


def test_the_table_is_not_all_of_one_kind() -> None:
    """The table is only evidence if it contains both outcomes, in quantity.

    Fails if someone "fixes" a failing case by deleting it until only easy inputs are
    left.
    """
    parsed = [v for v in HAND_PICKED if not pd.isna(fallback(v))]
    nat = [v for v in HAND_PICKED if pd.isna(fallback(v))]
    assert len(HAND_PICKED) >= 25
    assert len(parsed) >= 10 and len(nat) >= 10


def test_fractional_digits_are_read_as_a_fraction_not_as_a_count() -> None:
    """``.1`` means 100 milliseconds, and the fast path must not read it as 1 of anything.

    The single most likely way to write this optimisation wrongly, and one the equality
    assertions above would catch only because pandas gets it right -- asserted directly
    here so the expected value is stated rather than inherited.
    """
    assert parse_event_time("2017-02-12T21:23:20.1Z").microsecond == 100_000
    assert parse_event_time("2017-02-12T21:23:20.1Z").nanosecond == 0
    assert parse_event_time("2017-02-12T21:23:20.000000001Z").nanosecond == 1
    assert parse_event_time("2017-02-12T21:23:20.123456789Z").nanosecond == 789


def test_an_offset_moves_the_instant_in_the_right_direction() -> None:
    """``+03:00`` is three hours *ahead* of UTC, so the UTC instant is three hours earlier.

    Fails if the sign is inverted -- a six-hour error that every window, rate and
    correlation downstream would inherit silently.
    """
    zulu = parse_event_time("2017-02-12T21:23:20Z")
    assert parse_event_time("2017-02-12T21:23:20+03:00") == zulu - pd.Timedelta(hours=3)
    assert parse_event_time("2017-02-12T21:23:20-05:00") == zulu + pd.Timedelta(hours=5)


# --------------------------------------------------------------------------------------
# 2. The generated population
# --------------------------------------------------------------------------------------

def _generated(count: int, seed: int = 20260913) -> list[str]:
    """Valid and corrupted ISO-8601-ish strings, deterministic for a given seed."""
    rng = random.Random(seed)
    out: list[str] = []
    zones = ["Z", "z", "+00:00", "-05:00", "+05:45", "-12:00", "+14:00", "", " UTC", "+0000"]
    separators = ["T", " ", "t", "_", ""]
    while len(out) < count:
        # Mostly inside pandas' representable range, so roughly half the population is
        # a timestamp both paths can produce; a tenth deliberately outside it, so the
        # out-of-bounds branch is exercised rather than assumed.
        year = rng.randint(1990, 2260) if rng.random() < 0.9 else rng.randint(1400, 9999)
        month = rng.randint(1, 13)          # 13 exists: the pattern must not accept it
        day = rng.randint(1, 32)            # and so does the 31st of February
        hour = rng.randint(0, 24)
        minute = rng.randint(0, 60)
        second = rng.randint(0, 60)
        digits = rng.choice([0, 0, 0, 1, 3, 6, 7, 9, 10, 12])
        fraction = "." + "".join(str(rng.randint(0, 9)) for _ in range(digits)) if digits else ""
        text = (
            f"{year:04d}-{month:02d}-{day:02d}{rng.choice(separators)}"
            f"{hour:02d}:{minute:02d}:{second:02d}{fraction}{rng.choice(zones)}"
        )
        if rng.random() < 0.15:             # corrupt one character outright
            position = rng.randrange(len(text))
            text = text[:position] + rng.choice("-:.+ 09") + text[position + 1:]
        out.append(text)
    return out


def test_two_thousand_generated_strings_parse_identically() -> None:
    """The table cannot be the whole specification; this is the rest of it.

    Fails on any generated string where the two paths disagree -- and the generator is
    built to produce month 13, day 33, hour 25, minute 61, fractions of 0-12 digits and
    one-character corruptions precisely so that both "the pattern accepted too much"
    and "the pattern accepted too little" are reachable failures.
    """
    values = _generated(2_000)
    assert len(values) == 2_000

    mismatches = [
        (v, parse_event_time(v), fallback(v)) for v in values if not agree(v)
    ]
    assert not mismatches, f"{len(mismatches)} mismatch(es), e.g. {mismatches[:5]}"

    # The population must actually exercise both outcomes, or it proves nothing.
    parsed = sum(1 for v in values if not pd.isna(fallback(v)))
    assert 200 < parsed < 1_800, f"{parsed}/2000 parsed -- the generator is one-sided"


# --------------------------------------------------------------------------------------
# 3. The real corpus
# --------------------------------------------------------------------------------------

def _distinct_event_times(directory: Path, target: int) -> list[str]:
    """Stream a real CloudTrail corpus until ``target`` distinct eventTime values seen."""
    from ath.telemetry.cloudtrail_source import _classify, _iter_payloads

    files = sorted(
        p for p in directory.iterdir() if p.is_file() and _classify(p.name) is not None
    )
    seen: set[str] = set()
    for _, _, records in _iter_payloads(files):
        for record in records:
            if isinstance(record, dict):
                raw = record.get("eventTime")
                if isinstance(raw, str):
                    seen.add(raw)
        if len(seen) >= target:
            break
    return sorted(seen)


@pytest.mark.skipif(
    os.environ.get(REAL_SAMPLE_ENV) != "1",
    reason=f"set {REAL_SAMPLE_ENV}=1 to compare against the real CloudTrail corpus",
)
def test_real_event_times_parse_identically() -> None:
    """Every distinct eventTime a real trail actually contains, both paths, no diff.

    Fails if the corpus contains a form the pattern accepts and pandas reads
    differently -- the one failure mode the synthetic populations above cannot rule
    out, because they were written by the same person who wrote the pattern.
    """
    if not FLAWS_RAW.is_dir():
        pytest.skip("external corpus not present in this checkout")

    values = _distinct_event_times(FLAWS_RAW, REAL_SAMPLE_TARGET)
    assert len(values) >= REAL_SAMPLE_TARGET, (
        f"only {len(values)} distinct eventTime values available"
    )

    mismatches = [value for value in values if not agree(value)]
    print(f"\ncompared {len(values):,} distinct real eventTime strings; "
          f"{len(mismatches)} mismatch(es)")
    assert not mismatches, mismatches[:5]


# --------------------------------------------------------------------------------------
# 4. The fast path is actually on the path
# --------------------------------------------------------------------------------------

def test_every_per_record_adapter_uses_the_shared_parser() -> None:
    """No adapter may keep its own scalar ``pd.to_datetime`` call.

    This is the test that fails if the regression comes back: a new adapter (or a
    revert) parsing timestamps per record with ``pd.to_datetime`` costs ~230us a row,
    which is invisible on a fixture and is 25 minutes on a real trail.

    Frame-level parsing is explicitly allowed and explicitly recognised: a call whose
    argument is a Series or a column is vectorised, and already fast.
    """
    telemetry_dir = ROOT / "src" / "ath" / "telemetry"
    offenders: list[str] = []
    for path in sorted(telemetry_dir.glob("*.py")):
        if path.name == "normalize.py":  # the fallback lives here, by design
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "pd.to_datetime(" not in line:
                continue
            argument = line.split("pd.to_datetime(", 1)[1]
            first = argument.split(",")[0].strip()
            vectorised = first.endswith("]") or first.startswith("raw") or first.startswith("df")
            if not vectorised:
                offenders.append(f"{path.name}:{number}: {line.strip()}")
    assert not offenders, (
        "scalar pd.to_datetime in an adapter; use normalize.parse_event_time:\n"
        + "\n".join(offenders)
    )
