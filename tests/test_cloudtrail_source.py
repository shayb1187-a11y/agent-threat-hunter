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
from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS
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
        controls=result.tables[EVENT_CONTROL],
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
# Management-API calls -- the control-plane table, not the process table
# ======================================================================================


def test_management_api_calls_are_not_coerced_into_process_events(result) -> None:
    """The decisive constraint.

    Mapping `CreateAccessKey` to a process event would make the visibility model
    report `process_execution` as available for an environment with no endpoint
    telemetry at all -- manufacturing exactly the false confidence that layer exists
    to prevent. These calls have a real home now (EVENT_CONTROL), so they stop being
    coerced into the process table AND stop being merely dropped.
    """
    assert result.tables[EVENT_PROCESS].empty
    assert result.tables[EVENT_NETWORK].empty


def test_management_api_calls_map_to_the_control_table(result) -> None:
    controls = result.tables[EVENT_CONTROL]
    assert len(controls) == 3
    assert set(controls["source"]) == {"cloudtrail_mgmt"}
    assert set(controls["verb"]) == {"attach", "create", "stop"}


def test_fixture_grant_is_self_service(result) -> None:
    """In the shared fixture, dev_alice attaches the policy to their own account.

    actor == target_actor here -- correctly, because that is what the record says.
    The *distinct*-identity case is exercised separately below with a constructed
    record, since asserting `!=` against this fixture would just be wrong.
    """
    controls = result.tables[EVENT_CONTROL]
    grant = controls[controls["verb"] == "attach"].iloc[0]
    assert grant["actor"] == grant["target_actor"] == "dev_alice"
    assert grant["role_ref"] == "arn:aws:iam::aws:policy/AdministratorAccess"


def test_grant_events_carry_a_target_actor_distinct_from_the_caller() -> None:
    """AttachUserPolicy's beneficiary must not be conflated with its caller.

    An administrator attaching a policy to *someone else's* account is the normal
    case, not the exception. Reporting the admin as the identity that gained the
    privilege would point any escalation chain at the wrong account -- this is the
    exact mistake the user_identity/target_actor split exists to prevent. Constructed
    directly rather than via the shared fixture (whose own grant happens to be
    self-service) so the distinct-identity case is actually exercised.
    """
    from ath.telemetry.cloudtrail_source import _normalise_control_record

    record = {
        "eventName": "AttachUserPolicy",
        "eventTime": "2026-08-17T09:18:00Z",
        "eventID": "constructed-0001",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "sourceIPAddress": "203.0.113.99",
        "userIdentity": {"type": "IAMUser", "userName": "ops_bob"},
        "requestParameters": {
            "userName": "dev_alice",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
    }
    row, issue = _normalise_control_record(record, "constructed.json", 0)

    assert issue is None
    assert row["actor"] == "ops_bob"
    assert row["target_actor"] == "dev_alice"
    assert row["actor"] != row["target_actor"]
    assert row["role_ref"] == "arn:aws:iam::aws:policy/AdministratorAccess"
    # The row's canonical `user` names the identity gaining power, not the grantor.
    assert row["user"] == "dev_alice"


def test_unmapped_events_are_reported_with_a_reason(result) -> None:
    """ListBuckets/DescribeInstances/GetObject are outside both mapped event sets.

    This project does not attempt full CloudTrail coverage -- only the specific
    authentication and management-API calls it names. Everything else stays visibly
    unmapped rather than silently dropped or forced somewhere it does not belong.
    """
    reasons = " ".join(i.reason for i in result.issues)
    for event_name in ("ListBuckets", "DescribeInstances", "GetObject"):
        assert event_name in reasons
    assert "is not one of the authentication or management-API calls" in reasons
    # The events this adapter now DOES map must not still be reported as unmapped.
    for event_name in ("CreateAccessKey", "AttachUserPolicy", "StopLogging"):
        assert event_name not in reasons


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


def test_all_four_tables_are_present_and_schema_valid(result) -> None:
    """Empty is not the same as absent -- downstream expects all four tables."""
    for event_type in (EVENT_PROCESS, EVENT_NETWORK, EVENT_LOGON, EVENT_CONTROL):
        assert event_type in result.tables


def test_source_reports_honest_counts(result) -> None:
    assert result.rows_read == 23
    # 15 authentication rows (ConsoleLogin/AssumeRole, minus 2 malformed) + 3
    # management-activity rows (CreateAccessKey/AttachUserPolicy/StopLogging) now kept,
    # where the earlier adapter dropped all 3 as unmapped.
    assert result.rows_kept == 18
    assert result.rows_dropped == 5


def test_missing_directory_fails_clearly() -> None:
    with pytest.raises(FileNotFoundError, match="No CloudTrail"):
        CloudTrailSource(FIXTURE.parent / "does-not-exist").load()
