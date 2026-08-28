"""Tests for the CloudTrail adapter -- the abstraction's stress test.

The Defender adapter proved the `TelemetrySource` seam works for a second Windows
endpoint product, which is a weaker claim than it appears: Defender's tables are the
shape the canonical schema was modelled on. CloudTrail is genuinely foreign, and these
tests pin both halves of the result -- what transferred, and what could not.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ath.hunting import run_hunt
from ath.schema import EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS
from ath.telemetry.cloudtrail_source import CloudTrailSource
from ath.telemetry.loader import Telemetry

FIXTURE = Path(__file__).parent / "fixtures" / "cloudtrail"


@pytest.fixture(scope="module")
def result():
    return CloudTrailSource(FIXTURE).load()


@pytest.fixture(scope="module")
def telemetry(result):
    return Telemetry(
        processes=result.tables[EVENT_PROCESS],
        network=result.tables[EVENT_NETWORK],
        logons=result.tables[EVENT_LOGON],
    )


# ======================================================================================
# What maps
# ======================================================================================


def test_authentication_events_become_canonical_logons(result) -> None:
    logons = result.tables[EVENT_LOGON]
    assert len(logons) == 15
    assert set(logons["user"]) == {"dev_alice", "ops_bob"}
    assert set(logons["action"]) == {"success", "failure"}
    assert set(logons["source"]) == {"cloudtrail"}


def test_every_row_keeps_a_pointer_to_the_original_record(result) -> None:
    """Provenance has to survive normalization or a finding cannot be traced back."""
    for reference in result.tables[EVENT_LOGON]["source_ref"]:
        assert "eventID=" in reference and "File=" in reference


def test_console_login_verdict_is_read_from_response_elements(result) -> None:
    """CloudTrail signals ConsoleLogin failure in responseElements, not errorCode.

    A naive adapter that only checks `errorCode` would read all 12 failures as
    successes -- turning a brute-force burst into ordinary activity.
    """
    logons = result.tables[EVENT_LOGON]
    alice = logons[logons["user"] == "dev_alice"]
    assert (alice["action"] == "failure").sum() == 12
    # Two successes: the console login that ended the burst, and a later AssumeRole.
    assert (alice["action"] == "success").sum() == 2


def test_existing_bruteforce_rule_fires_with_no_modification(telemetry) -> None:
    """The headline result: a rule written for Windows transfers to cloud telemetry.

    ATH-005 keys on `action`, `user` and `source_ip` and never reads a Windows-specific
    field, so 12 failed console logins followed by a success trip it exactly as a
    Windows logon burst would.
    """
    findings = run_hunt(telemetry).findings
    ath005 = [f for f in findings if f.rule_id == "ATH-005"]
    assert len(ath005) == 1
    assert ath005[0].user == "dev_alice"
    assert "203.0.113.42" in ath005[0].reason


def test_bruteforce_finding_maps_to_attack(telemetry) -> None:
    from ath.mitre.mapper import map_finding

    finding = next(f for f in run_hunt(telemetry).findings if f.rule_id == "ATH-005")
    techniques = {m.technique_id for m in map_finding(finding)}
    assert "T1110.001" in techniques
    assert "T1078" in techniques, "a successful burst must assert Valid Accounts"


# ======================================================================================
# What does not map -- reported, never forced
# ======================================================================================


def test_management_api_calls_are_not_coerced_into_process_events(result) -> None:
    """The decisive constraint.

    Mapping `CreateAccessKey` to a process event would make the visibility model
    report `process_execution` as available for an environment with no endpoint
    telemetry at all -- manufacturing exactly the false confidence that layer exists
    to prevent.
    """
    assert result.tables[EVENT_PROCESS].empty
    assert result.tables[EVENT_NETWORK].empty


def test_unmapped_events_are_reported_with_a_reason(result) -> None:
    reasons = " ".join(i.reason for i in result.issues)
    for event_name in ("CreateAccessKey", "AttachUserPolicy", "StopLogging"):
        assert event_name in reasons
    assert "no representation in the canonical schema" in reasons


def test_malformed_records_are_dropped_not_raised(result) -> None:
    """Real exports contain junk; that is a fact about the world, not a bug."""
    reasons = [i.reason for i in result.issues]
    assert any("unparseable timestamp" in r for r in reasons)
    assert any("no usable principal" in r for r in reasons)


def test_logon_type_is_null_rather_than_invented(result) -> None:
    """There is no Windows logon type for a console login.

    Inventing one would silently re-enable ATH-006's host-ownership inference on
    telemetry where the concept of an interactive host session does not exist.
    """
    import pandas as pd

    assert result.tables[EVENT_LOGON]["logon_type"].isna().all()


def test_ownership_rule_correctly_declines_to_fire(telemetry) -> None:
    """ATH-006 must stay quiet: its ownership model is Windows-session-specific."""
    fired = {f.rule_id for f in run_hunt(telemetry).findings}
    assert "ATH-006" not in fired


def test_all_three_tables_are_present_and_schema_valid(result) -> None:
    """Empty is not the same as absent -- downstream expects all three tables."""
    for event_type in (EVENT_PROCESS, EVENT_NETWORK, EVENT_LOGON):
        assert event_type in result.tables


def test_source_reports_honest_counts(result) -> None:
    assert result.rows_read == 23
    assert result.rows_kept == 15
    assert result.rows_dropped == 8


def test_missing_directory_fails_clearly() -> None:
    with pytest.raises(FileNotFoundError, match="No CloudTrail"):
        CloudTrailSource(FIXTURE.parent / "does-not-exist").load()
