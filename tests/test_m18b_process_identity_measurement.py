"""The M18b-1 measurement script, held to a corpus whose answers are known by hand.

Why a measurement script needs tests at all
--------------------------------------------
This script's output is the milestone's claim. A join study that silently counts the
wrong thing does not crash and does not look wrong -- it reports a number, and the
number is believed. The three properties below are exactly the ones that would make the
COMISET result meaningless while still printing:

* ambiguity counted over the wrong denominator (all keys vs. the keys network rows use),
* the guid join credited with rows whose identity is empty,
* "matched by pid but not by guid" conflated with "not matched at all".

The fixture is eight rows, so every expected number is derivable by reading it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from m18b_process_identity import join_study, population  # noqa: E402

from ath.instance_identity import start_identity, sysmon_identity  # noqa: E402
from ath.schema import EVENT_NETWORK, EVENT_PROCESS  # noqa: E402
from ath.telemetry.normalize import coerce_and_validate  # noqa: E402

DEVICE = "kiosk-14"

# One PID, 4100, run twice on one host: the ambiguity the whole milestone is about.
FIRST = sysmon_identity("{aaaa0000-0000-0000-0000-000000000001}")
SECOND = sysmon_identity("{aaaa0000-0000-0000-0000-000000000002}")
# A third process on a different PID, so not every key is ambiguous.
OTHER = sysmon_identity("{aaaa0000-0000-0000-0000-000000000003}")
# An instance whose process-create event is outside the window: no process row carries it.
OFF_WINDOW = sysmon_identity("{aaaa0000-0000-0000-0000-0000000000ff}")


def _processes() -> pd.DataFrame:
    rows = [
        ("p-1", "08:00", 4100, FIRST), ("p-2", "09:00", 4100, SECOND),
        ("p-3", "09:05", 7000, OTHER),
    ]
    return coerce_and_validate(pd.DataFrame([
        {
            "event_id": event_id, "timestamp": f"2026-06-01T{clock}:00Z",
            "event_type": EVENT_PROCESS, "device": DEVICE, "user": "hana",
            "source": "test", "source_ref": "", "process_name": "curl.exe",
            "process_id": pid, "command_line": "curl.exe", "parent_process_name": "",
            "parent_process_id": pd.NA, "file_path": "", "sha256": "", "signer": "",
            "signature_status": "unknown", "process_guid": guid,
            "parent_process_guid": "",
        }
        for event_id, clock, pid, guid in rows
    ]), EVENT_PROCESS)


def _network(rows: list[tuple[str, int, str]]) -> pd.DataFrame:
    return coerce_and_validate(pd.DataFrame([
        {
            "event_id": event_id, "timestamp": "2026-06-01T09:30:00Z",
            "event_type": EVENT_NETWORK, "device": DEVICE, "user": "hana",
            "source": "test", "source_ref": "", "process_name": "curl.exe",
            "process_id": pid, "process_guid": guid, "remote_ip": "203.0.113.5",
            "remote_port": 443, "protocol": "tcp", "direction": "outbound",
            "remote_url": "",
        }
        for event_id, pid, guid in rows
    ]), EVENT_NETWORK)


def test_ambiguity_is_reported_over_both_denominators() -> None:
    """All keys, and the keys network rows actually use -- they differ, and both matter.

    Two keys exist (4100, 7000) and one is ambiguous, so the "all keys" rate is 1/2.
    Only 4100 is used by a network row, and it is the ambiguous one, so the "used" rate
    is 1/1. Reporting only one of these is how 86.5% and 94.8% become interchangeable.

    Failure mode: the two denominators are collapsed, and the COMISET figure stops being
    comparable to the M17 number it is put beside.
    """
    report = join_study(_processes(), _network([("n-1", 4100, SECOND)]))
    ambiguity = report["device_pid_ambiguity"]
    assert ambiguity["all_process_keys"] == {
        "keys": 2, "ambiguous": 1, "rate": 0.5,
        "worst_key": f"{DEVICE}|4100", "worst_count": 2, "unit": "instances",
    }
    assert ambiguity["keys_used_by_network_rows"]["keys"] == 1
    assert ambiguity["keys_used_by_network_rows"]["rate"] == 1.0
    # The identity itself is unambiguous -- verified, not assumed.
    assert report["process_guid_ambiguity"]["ambiguous"] == 0


def test_the_guid_join_credits_only_rows_that_carry_an_identity() -> None:
    """An empty identity is a gap, not a match, however the pid join happens to fare.

    Row n-1 joins both ways. Row n-2 has no identity: the pid finds *an* instance (two,
    in fact) and the guid join must not be credited. Row n-3 carries an identity no
    process row holds -- the off-window case -- so the pid join succeeds on the wrong
    instance and the guid join correctly fails.

    Failure mode: empty identities are treated as wildcards, the guid join reports 100%,
    and the number it exists to produce becomes meaningless.
    """
    report = join_study(_processes(), _network([
        ("n-1", 4100, SECOND), ("n-2", 4100, ""), ("n-3", 4100, OFF_WINDOW),
    ]))
    assert report["pid_join"]["matched"] == 3
    assert report["guid_join"]["carries_identity"] == 2
    assert report["guid_join"]["matched"] == 1
    assert report["matched_by_pid_not_by_guid"]["count"] == 2

    reasons = [e["reason"] for e in report["matched_by_pid_not_by_guid"]["examples"]]
    assert any("carries no instance identity" in r for r in reasons)
    assert any("started before the capture window" in r for r in reasons)
    assert all(
        e["distinct_instances_behind_that_pid"] == 2
        for e in report["matched_by_pid_not_by_guid"]["examples"]
    )


def test_a_row_matched_by_neither_key_is_not_counted_as_a_disagreement() -> None:
    """"The two joins disagree" and "nothing matched" are different facts.

    Failure mode: the disagreement count becomes "everything the guid join missed",
    including rows no key could ever have reached, and the diagnosis in the report points
    at PID reuse when the real answer is that the process is simply not in the corpus.
    """
    report = join_study(_processes(), _network([("n-1", 9999, OFF_WINDOW)]))
    assert report["pid_join"]["matched"] == 0
    assert report["guid_join"]["matched"] == 0
    assert report["matched_by_pid_not_by_guid"]["count"] == 0


def test_population_splits_by_scheme_and_by_source() -> None:
    """Population is per authority, because the two schemes are not interchangeable.

    Failure mode: the schemes are summed, and a corpus carrying only weak `start` keys
    reads identically to one carrying the source's own identifiers.
    """
    processes = _processes()
    processes.loc[2, "process_guid"] = start_identity(DEVICE, 7000, "2026-06-01T09:05:00Z")
    measured = population(processes, "process_guid")
    assert measured["populated"] == 3
    assert measured["by_scheme"] == {"sysmon": 2, "start": 1}
    assert measured["by_source"]["test"]["rows"] == 3


@pytest.mark.parametrize("column", ["process_guid", "parent_process_guid"])
def test_population_of_an_empty_column_is_zero_and_not_an_error(column: str) -> None:
    """A wholly unpopulated column is a measurement, and the commonest real one.

    Failure mode: the script divides by zero, or skips the column, and a corpus that
    carries no identity at all produces no row saying so.
    """
    measured = population(_processes(), "parent_process_guid")
    assert measured["populated"] == 0 and measured["fraction"] == 0.0
    assert measured["by_scheme"] == {}
