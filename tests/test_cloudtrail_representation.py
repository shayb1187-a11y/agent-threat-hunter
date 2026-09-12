"""M18-3: CloudTrail management activity is represented by shape, not by an allowlist.

The defect these tests guard: the adapter used to name five management API calls and
refuse every other record, which measured as 2 of 2,349 records ingested from a real AWS
attack capture (0.09%) and 96 of 1.9M from a public trail. A detection cannot miss what
it was never given, so "0 findings" on those corpora was a statement about the reader.

The invariant: every admitted, time-valid CloudTrail record becomes a control row whose
verb, resource type, actor and decision are derived from the record's own shape --
``eventSource``, ``eventName`` morphology, ``userIdentity``, ``errorCode`` -- with no
enumeration of API names anywhere in the adapter.

Representation is not detection, and these tests keep the two apart: the newly
represented calls include several that an analyst would call alarming, and this task
deliberately leaves every one of them undetected.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from ath.behavior.control_plane import VERB_CLASS_NAMES, VERB_CLASSES, verb_class
from ath.hunting import run_hunt
from ath.hunting.finding import Severity
from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS
from ath.telemetry.cloudtrail_source import (
    AUTH_EVENTS,
    CloudTrailSource,
    parse_event_name,
    resource_type_for,
)
from ath.telemetry.loader import Telemetry

ROOT = Path(__file__).resolve().parent.parent
ADAPTER = ROOT / "src" / "ath" / "telemetry" / "cloudtrail_source.py"
H3_RAW = ROOT / "data" / "external" / "attack_data_aws" / "raw"
FLAWS_HISTOGRAM = ROOT / "data" / "external" / "flaws_cloud" / "probe_eventname_histogram.json"

# The five API names the adapter used to enumerate. Retired: nothing in the adapter may
# name them any more, because naming any call is the defect.
RETIRED_EVENT_NAMES = (
    "AttachUserPolicy", "PutUserPolicy", "CreateAccessKey", "StopLogging", "DeleteTrail",
)

# Every event name invented by this module. Held in one place so a single test can prove
# they are absent from both real corpora: a parser that happened to be tuned to the data
# it was measured on would pass its own tests and fail on the next trail.
INVENTED_EVENT_NAMES = (
    "RotateSecret", "TerminateInstances", "DescribeWidgetFleets", "PutBucketAcl",
    "ListWidgetFleets20150331", "ListWidgetFleets2020_05_31", "GetWidgetCatalog202224v2",
    "CreateQuantumLedger", "DescribeQuantumLedgers", "AttachLedgerPolicy",
    "DeleteQuantumLedger", "CreateVoiceConnector", "DescribeVoiceConnectors",
    "AttachVoiceConnectorPolicy", "DeleteVoiceConnector", "CreateSigningProfile",
    "DescribeSigningProfiles", "AttachSigningProfilePolicy", "DeleteSigningProfile",
    "CreateWorkbookRow", "DescribeWorkbookRows", "AttachWorkbookPolicy",
    "DeleteWorkbookRow", "CreateApplianceFleet", "DescribeApplianceFleets",
    "AttachAppliancePolicy", "DeleteApplianceFleet", "ListLedgerAliases",
    "GetVoiceConnectorStatus", "DescribeApplianceAddresses", "ListWorkbookRepositories",
    # M18-5: the identity-service calls that separate "changed an authority" from
    # "mentioned an identity". Added to this tuple, not a second one, so the same
    # programmatic disjointness check covers them.
    "ListWidgetUserGrants", "GetLedgerUserSummary", "DescribeLedgerUserGrants",
    "AttachQuokkaPolicy", "DetachQuokkaPolicy", "UpdateLedgerLoginProfile",
    "IssueAccessKey", "DeleteLedgerUser", "AttachApplianceVolume",
    "AuthorizeApplianceFleetIngress",
    # M18-6: the rows where an empty beneficiary is a gap, and the rows where it is not.
    "DeleteQuokkaPolicy", "CreateQuokkaPolicy", "GenerateQuokkaReport",
    "AddQuokkaUserToLedgerGroup", "AttachLedgerGroupPolicy",
    "AddLedgerRoleToApplianceProfile",
)


def _record(**overrides) -> dict:
    """One CloudTrail record with the fields every real record carries."""
    record = {
        "eventVersion": "1.08",
        "eventTime": "2026-03-04T11:00:00Z",
        "eventSource": "braket.amazonaws.com",
        "eventName": "CreateQuantumLedger",
        "awsRegion": "eu-north-1",
        "sourceIPAddress": "192.0.2.11",
        "eventID": "invented-0000",
        "recipientAccountId": "900000000001",
        "userIdentity": {"type": "IAMUser", "userName": "kestrel", "accountId": "900000000001"},
        "requestParameters": {},
    }
    record.update(overrides)
    return record


def _load(tmp_path: Path, records: list[dict]):
    (tmp_path / "CloudTrail_invented.json").write_text(
        json.dumps({"Records": records}), encoding="utf-8",
    )
    return CloudTrailSource(tmp_path).load()


def _telemetry(result) -> Telemetry:
    return Telemetry(
        processes=result.tables[EVENT_PROCESS], network=result.tables[EVENT_NETWORK],
        logons=result.tables[EVENT_LOGON], controls=result.tables[EVENT_CONTROL],
    )


# ======================================================================================
# Anti-overfitting: the names these tests parse appear in neither corpus
# ======================================================================================


def test_invented_names_appear_in_neither_corpus() -> None:
    """Fails if a test name is borrowed from the data the parser was measured on.

    Checked programmatically rather than asserted in prose: against every event name in
    the attack_data_aws capture, and against the 100 most frequent names on the
    flaws.cloud trail. Skipped, not silently passed, when the corpora are not present.
    """
    if not H3_RAW.is_dir() or not FLAWS_HISTOGRAM.exists():
        pytest.skip("external corpora not present in this checkout")

    h3_names = set()
    for path in sorted(H3_RAW.glob("*.json")):
        text = path.read_text(encoding="utf-8")
        try:
            payload = json.loads(text)
            records = payload["Records"] if isinstance(payload, dict) else payload
        except (json.JSONDecodeError, KeyError):
            records = [json.loads(line) for line in text.splitlines() if line.strip()]
        h3_names.update(str(r.get("eventName", "")) for r in records)

    histogram = json.loads(FLAWS_HISTOGRAM.read_text(encoding="utf-8"))["eventNames"]
    flaws_top = {
        name for name, _ in sorted(histogram.items(), key=lambda kv: -kv[1])[:100]
    }

    borrowed = sorted(set(INVENTED_EVENT_NAMES) & (h3_names | flaws_top))
    assert not borrowed, f"test names taken from the measured corpora: {borrowed}"


# ======================================================================================
# The parser
# ======================================================================================


@pytest.mark.parametrize(
    "event_name,verb,family",
    [
        ("RotateSecret", "rotate", "secret"),
        ("TerminateInstances", "terminate", "instance"),
        ("DescribeWidgetFleets", "describe", "widget-fleet"),
        ("PutBucketAcl", "put", "bucket-acl"),
        # Version-stamped variants collapse onto the family they are variants of.
        ("ListWidgetFleets20150331", "list", "widget-fleet"),
        ("ListWidgetFleets2020_05_31", "list", "widget-fleet"),
        ("GetWidgetCatalog202224v2", "get", "widget-catalog"),
        # Singularisation, including the endings that only look plural.
        ("ListLedgerAliases", "list", "ledger-alias"),
        ("GetVoiceConnectorStatus", "get", "voice-connector-status"),
        ("DescribeApplianceAddresses", "describe", "appliance-address"),
        ("ListWorkbookRepositories", "list", "workbook-repository"),
        # A bare verb: a real name with no resource noun at all.
        ("Decrypt", "decrypt", ""),
    ],
)
def test_parser_reads_verb_and_family_from_the_name(event_name, verb, family) -> None:
    """Fails if the verb split, version strip or singularisation rules change behaviour.

    None of these names is in either corpus, so passing means the *rules* are right
    rather than the lookups.
    """
    parsed = parse_event_name(event_name)
    assert parsed.parsed is True
    assert parsed.verb == verb
    assert parsed.family == family


def test_lowercase_start_is_still_represented_and_reported() -> None:
    """Fails if an unparseable name silently becomes a row, or silently becomes nothing.

    A name that does not begin with a capitalised word yields no verb token. The row is
    still represented -- with the whole name as the verb -- so representation never
    depends on morphology holding; and it is *also* reported, so the fraction of names
    the morphology does not cover stays a measured number.
    """
    parsed = parse_event_name("listWidgetFleets")
    assert parsed.parsed is False
    assert parsed.verb == "listwidgetfleets"
    assert parsed.family == ""

    empty = parse_event_name("")
    assert empty.parsed is False
    assert (empty.verb, empty.family) == ("", "")


def test_resource_type_is_service_and_family() -> None:
    """Fails if the service is aliased, or if a noun-less name invents a family."""
    verb, resource_type, family = resource_type_for(
        "braket.amazonaws.com", "DescribeQuantumLedgers",
    )
    assert (verb, resource_type, family) == ("describe", "braket:quantum-ledger", "quantum-ledger")

    # No noun: the service alone is the honest answer, not an invented family.
    assert resource_type_for("kms.amazonaws.com", "Decrypt")[1] == "kms"

    # Literal service names. "monitoring" is CloudWatch's event source; renaming it here
    # would make the family of a resource depend on someone maintaining an alias table.
    assert resource_type_for("monitoring.amazonaws.com", "DescribeAlarmHistory")[1] == (
        "monitoring:alarm-history"
    )


# ======================================================================================
# The adapter: five services, four kinds of verb, every record represented
# ======================================================================================

_SERVICES = ("braket", "chime", "signer", "honeycode", "panorama")
_CALLS = {
    "braket": ("CreateQuantumLedger", "DescribeQuantumLedgers", "AttachLedgerPolicy",
               "DeleteQuantumLedger"),
    "chime": ("CreateVoiceConnector", "DescribeVoiceConnectors",
              "AttachVoiceConnectorPolicy", "DeleteVoiceConnector"),
    "signer": ("CreateSigningProfile", "DescribeSigningProfiles",
               "AttachSigningProfilePolicy", "DeleteSigningProfile"),
    "honeycode": ("CreateWorkbookRow", "DescribeWorkbookRows", "AttachWorkbookPolicy",
                  "DeleteWorkbookRow"),
    "panorama": ("CreateApplianceFleet", "DescribeApplianceFleets",
                 "AttachAppliancePolicy", "DeleteApplianceFleet"),
}
_ACTORS = ("kestrel", "marlin", "quokka", "tapir", "vireo")
_REGIONS = ("eu-north-1", "ap-south-1", "sa-east-1", "me-south-1", "af-south-1")


@pytest.fixture(scope="module")
def matrix(tmp_path_factory):
    """Five services x four verb classes, each with its own account, region and actor."""
    records = []
    for index, service in enumerate(_SERVICES):
        for offset, event_name in enumerate(_CALLS[service]):
            records.append(_record(
                eventSource=f"{service}.amazonaws.com",
                eventName=event_name,
                awsRegion=_REGIONS[index],
                recipientAccountId=f"90000000000{index}",
                eventID=f"invented-{index}{offset}",
                eventTime=f"2026-03-04T11:{index:02d}:{offset:02d}Z",
                userIdentity={"type": "IAMUser", "userName": _ACTORS[index]},
                # Every fourth record was refused by the API itself.
                **({"errorCode": "AccessDenied"} if offset == 3 else {}),
            ))
    return _load(tmp_path_factory.mktemp("matrix"), records)


def test_every_record_becomes_a_control_row(matrix) -> None:
    """Fails if any service or verb is dropped for not being on a list."""
    assert matrix.rows_read == 20
    assert len(matrix.tables[EVENT_CONTROL]) == 20
    assert matrix.issues == []
    assert matrix.tables[EVENT_LOGON].empty


def test_core_control_fields_are_populated_on_every_row(matrix) -> None:
    """Fails if representation is partial -- a row with no verb is not a description."""
    controls = matrix.tables[EVENT_CONTROL]
    for column in ("verb", "resource_type", "actor", "decision"):
        populated = (controls[column].fillna("") != "").mean()
        assert populated == 1.0, f"{column} populated on {populated:.2%} of rows"

    assert set(controls["actor"]) == set(_ACTORS)
    assert len({d.split("/")[-1] for d in controls["device"]}) == len(_REGIONS)
    assert set(controls["resource_type"]) == {
        "braket:quantum-ledger", "braket:ledger-policy",
        "chime:voice-connector", "chime:voice-connector-policy",
        "signer:signing-profile", "signer:signing-profile-policy",
        "honeycode:workbook-row", "honeycode:workbook-policy",
        "panorama:appliance-fleet", "panorama:appliance-policy",
    }


def test_refused_calls_carry_a_denied_decision(matrix) -> None:
    """Fails if an API refusal is recorded as an allowed action."""
    controls = matrix.tables[EVENT_CONTROL]
    denied = controls[controls["decision"] == "denied"]
    assert len(denied) == 5
    assert set(denied["verb"]) == {"delete"}
    assert set(controls[controls["decision"] == "allowed"]["verb"]) == {
        "create", "describe", "attach",
    }


def test_verb_classes_group_the_matrix(matrix) -> None:
    """Fails if the shared vocabulary stops covering the verbs the adapter produces."""
    classes = sorted({verb_class(v) for v in matrix.tables[EVENT_CONTROL]["verb"]})
    assert classes == ["create", "delete", "grant", "read"]


# ======================================================================================
# Representation is not detection
# ======================================================================================


def test_reconnaissance_burst_is_represented_and_silent(tmp_path) -> None:
    """A benign look-alike: enumeration across five services is exactly what recon is.

    Fails if a burst of reads produces a finding (this task adds no detection) or if the
    reads are not represented (the failure the task exists to fix).
    """
    records = [
        _record(
            eventSource=f"{service}.amazonaws.com",
            eventName=_CALLS[service][1],
            eventID=f"recon-{index}-{minute}",
            eventTime=f"2026-03-04T12:{minute:02d}:00Z",
            userIdentity={"type": "IAMUser", "userName": "vireo"},
        )
        for minute in range(12)
        for index, service in enumerate(_SERVICES)
    ]
    result = _load(tmp_path, records)
    controls = result.tables[EVENT_CONTROL]

    assert len(controls) == 60
    assert {verb_class(v) for v in controls["verb"]} == {"read"}
    assert run_hunt(_telemetry(result)).findings == []


def test_alarming_calls_are_represented_and_deliberately_undetected(tmp_path) -> None:
    """Detection is out of scope for M18-3, and this test says so on purpose.

    Deleting an IAM policy, detaching a user policy, rewriting a role's trust policy and
    deleting VPC flow logs are all actions an analyst would want to see. Before this
    change they were not even *visible*: they were refused at the adapter. They are now
    represented, and they produce no findings -- because no rule was written for them.
    Adding one is a separate decision with its own false-positive budget, and this test
    fails loudly if such a rule is added without revisiting this file.
    """
    records = [
        _record(eventSource="iam.amazonaws.com", eventName="DeletePolicy", eventID="m-1",
                requestParameters={"policyArn": "arn:aws:iam::900000000001:policy/ledger-rw"}),
        _record(eventSource="iam.amazonaws.com", eventName="DetachUserPolicy", eventID="m-2",
                eventTime="2026-03-04T11:01:00Z",
                requestParameters={"userName": "quokka",
                                   "policyArn": "arn:aws:iam::900000000001:policy/ledger-rw"}),
        _record(eventSource="iam.amazonaws.com", eventName="UpdateAssumeRolePolicy",
                eventID="m-3", eventTime="2026-03-04T11:02:00Z",
                requestParameters={"roleName": "ledger-operator", "policyDocument": "{}"}),
        _record(eventSource="ec2.amazonaws.com", eventName="DeleteFlowLogs", eventID="m-4",
                eventTime="2026-03-04T11:03:00Z",
                requestParameters={"flowLogIds": ["fl-0abc"]}),
    ]
    result = _load(tmp_path, records)
    controls = result.tables[EVENT_CONTROL].set_index("source_ref")

    represented = {
        row["source_ref"].split(";")[0]: (row["verb"], row["resource_type"])
        for _, row in result.tables[EVENT_CONTROL].iterrows()
    }
    assert represented == {
        "eventID=m-1": ("delete", "iam:policy"),
        "eventID=m-2": ("detach", "iam:user-policy"),
        "eventID=m-3": ("update", "iam:assume-role-policy"),
        "eventID=m-4": ("delete", "ec2:flow-log"),
    }
    assert len(controls) == 4
    assert run_hunt(_telemetry(result)).findings == []


# ======================================================================================
# Beneficiary and role, by convention rather than by call name
# ======================================================================================


@pytest.mark.parametrize(
    "event_name,params,target_actor,role_ref",
    [
        ("AttachRolePolicy",
         {"roleName": "ledger-operator", "policyArn": "arn:aws:iam::900000000001:policy/ledger-rw"},
         "ledger-operator", "arn:aws:iam::900000000001:policy/ledger-rw"),
        ("AttachGroupPolicy",
         {"groupName": "ledger-admins", "policyArn": "arn:aws:iam::900000000001:policy/ledger-rw"},
         "ledger-admins", "arn:aws:iam::900000000001:policy/ledger-rw"),
        # userName wins over groupName: the beneficiary is the identity, not the
        # container -- and the container is then what conferred the authority, so the
        # group falls through to `role_ref` (M18-6). One ordering serves both shapes:
        # the row above names no user, so there the group *is* the beneficiary.
        ("AddUserToGroup", {"userName": "quokka", "groupName": "ledger-admins"},
         "quokka", "ledger-admins"),
        # A role handed over inside an instance profile: the profile is the vehicle, and
        # it is what `role_ref` records when no policy is named.
        ("AddRoleToInstanceProfile",
         {"roleName": "ledger-operator", "instanceProfileName": "ledger-fleet"},
         "ledger-operator", "ledger-fleet"),
        # An inline policy has a name, not an ARN -- the same column, the next field down.
        ("PutRolePolicy", {"roleName": "ledger-operator", "policyName": "ledger-inline"},
         "ledger-operator", "ledger-inline"),
        ("CreateAccessKey", {"userName": "marlin"}, "marlin", ""),
    ],
)
def test_beneficiary_and_role_are_read_by_convention(
    event_name, params, target_actor, role_ref
) -> None:
    """Fails if beneficiary extraction regresses to a per-call-name table.

    None of these six calls is named anywhere in the adapter, and four of them were not
    mapped at all before M18-3. The last three exercise `_ROLE_FIELDS` end to end: a
    policy ARN, an instance profile and a group are three different answers to "what
    conferred this", read from one ordered tuple rather than from the call's name.
    """
    from ath.telemetry.cloudtrail_source import _normalise_control_record

    row, issue = _normalise_control_record(
        _record(eventSource="iam.amazonaws.com", eventName=event_name,
                requestParameters=params,
                userIdentity={"type": "IAMUser", "userName": "tapir"}),
        "invented.json", 0,
    )
    assert issue is None
    assert row["actor"] == "tapir"
    assert row["target_actor"] == target_actor
    assert row["role_ref"] == role_ref
    # The canonical `user` names the identity the action is about, not the caller.
    assert row["user"] == target_actor


def test_access_key_with_no_named_user_targets_the_caller() -> None:
    """Fails if the self-service rule becomes a name check again.

    Creating an access key without naming a user creates one for yourself. That is a
    property of the access-key *family* -- true of every call on it -- not of one call's
    name, and it is what lets the key creation chain to a prior grant.
    """
    from ath.telemetry.cloudtrail_source import _normalise_control_record

    row, issue = _normalise_control_record(
        _record(eventSource="iam.amazonaws.com", eventName="CreateAccessKey",
                requestParameters={},
                userIdentity={"type": "IAMUser", "userName": "marlin"}),
        "invented.json", 0,
    )
    assert issue is None
    assert row["resource_type"] == "iam:access-key"
    assert row["target_actor"] == row["actor"] == "marlin"


def test_non_identity_services_assert_no_beneficiary() -> None:
    """Fails if a role name on some other service is read as a grant to an identity.

    `roleName` means "the role this cluster runs as" on a dozen services. Reading it as
    a beneficiary would point an escalation chain at a role nobody granted anything to.
    """
    from ath.telemetry.cloudtrail_source import _normalise_control_record

    row, _ = _normalise_control_record(
        _record(eventSource="panorama.amazonaws.com", eventName="CreateApplianceFleet",
                requestParameters={"roleName": "fleet-runtime", "name": "fleet-7"}),
        "invented.json", 0,
    )
    assert row["target_actor"] == ""
    assert row["role_ref"] == ""
    assert row["resource_name"] == "fleet-7"


# ======================================================================================
# M18-5: target_actor means "the identity whose authority this action changed"
# ======================================================================================
#
# The conventions above used to be read on *every* row of the identity service, which is
# not the same question. IAM's reads name a user in the same `requestParameters` its
# grants do, so a `ListAttachedUserPolicies` call filled `target_actor` with the user it
# was asking about -- and, because the canonical `user` column is `target_actor or
# actor`, filed the caller's reconnaissance under the person being enumerated. 11,388
# rows of the flaws.cloud trail carried the field on that basis, almost all of them
# reads (M18-4).
#
# Identities and account here appear in no other fixture, and every event name is in
# INVENTED_EVENT_NAMES, which the disjointness test above checks against both corpora.


def _identity_row(event_name: str, params: dict, *, source: str = "iam.amazonaws.com",
                  actor: str = "gannet") -> dict:
    """One normalised control row for a call on ``source``, made by ``actor``."""
    from ath.telemetry.cloudtrail_source import _normalise_control_record

    row, issue = _normalise_control_record(
        _record(eventSource=source, eventName=event_name, requestParameters=params,
                recipientAccountId="900000000077",
                userIdentity={"type": "IAMUser", "userName": actor,
                              "accountId": "900000000077"}),
        "invented.json", 0,
    )
    assert issue is None
    return row


@pytest.mark.parametrize("event_name,params", [
    ("ListWidgetUserGrants", {"userName": "shrike"}),
    ("GetLedgerUserSummary", {"userName": "shrike"}),
    ("DescribeLedgerUserGrants",
     {"userName": "shrike", "policyArn": "arn:aws:iam::900000000077:policy/ledger-rw"}),
])
def test_a_read_about_an_identity_is_attributed_to_the_caller(event_name, params) -> None:
    """Asking what a user has does not change what that user has.

    Fails the moment the beneficiary conventions are read on the identity *service*
    rather than on the rows that changed an authority: target_actor would be "shrike",
    and `user` -- which every consumer groups by -- would file gannet's enumeration of
    shrike under shrike.
    """
    row = _identity_row(event_name, params)

    assert row["actor"] == "gannet"
    assert row["target_actor"] == ""
    assert row["role_ref"] == ""
    assert row["user"] == row["actor"] == "gannet"


@pytest.mark.parametrize("verb_class_name,event_name,params,target,role", [
    ("grant", "AttachQuokkaPolicy",
     {"userName": "pipit", "policyArn": "arn:aws:iam::900000000077:policy/quokka-rw"},
     "pipit", "arn:aws:iam::900000000077:policy/quokka-rw"),
    ("revoke", "DetachQuokkaPolicy",
     {"userName": "avocet", "policyArn": "arn:aws:iam::900000000077:policy/quokka-rw"},
     "avocet", "arn:aws:iam::900000000077:policy/quokka-rw"),
    ("modify", "UpdateLedgerLoginProfile", {"userName": "godwit"}, "godwit", ""),
    # A create that names nobody: the access-key family targets the caller.
    ("create", "IssueAccessKey", {}, "gannet", ""),
    ("delete", "DeleteLedgerUser", {"userName": "bittern"}, "bittern", ""),
])
def test_every_class_of_authority_change_names_the_identity_it_changed(
    verb_class_name, event_name, params, target, role
) -> None:
    """Five verb classes, one column: whose authority moved.

    A revoke, a modify and a delete are not grants, and grading or filling these columns
    on grant-shaped rows alone would leave all three silently empty -- an escalation
    chain that could not see a permission being taken away or a login profile being
    reset. Fails if the predicate narrows back to GRANT, and fails if the access-key
    self-targeting rule is lost (the create case has no userName at all).
    """
    from ath.control_vocab import verb_class

    row = _identity_row(event_name, params)

    assert verb_class(row["verb"]) == verb_class_name
    assert row["target_actor"] == target
    assert row["role_ref"] == role
    # The canonical `user` names the identity the action is about, not the caller.
    assert row["user"] == target


@pytest.mark.parametrize("event_name,params", [
    # `userName` on an EC2 call is whatever the caller put in a tag or a filter; it is
    # never the identity a volume attachment changed the authority of, because a volume
    # attachment changes no identity's authority.
    ("AttachApplianceVolume", {"userName": "sandpiper", "instanceId": "i-0ab7"}),
    ("AuthorizeApplianceFleetIngress",
     {"userName": "sandpiper", "roleName": "fleet-runtime"}),
])
def test_a_grant_shaped_verb_outside_identity_management_names_no_identity(
    event_name, params
) -> None:
    """Grant-shaped is not the same question as changed-an-identity.

    42 of the 132 grant-shaped rows on flaws.cloud attach a storage volume to an
    instance. Fails if the predicate is written on the verb class alone -- these rows
    would claim an identity whose authority nothing changed, from parameters that mean
    something else entirely.
    """
    row = _identity_row(event_name, params, source="ec2.amazonaws.com")

    assert row["resource_type"].startswith("ec2:")
    assert row["target_actor"] == ""
    assert row["role_ref"] == ""
    assert row["user"] == row["actor"] == "gannet"


# ======================================================================================
# The two rules, unchanged in meaning
# ======================================================================================


def test_escalation_chain_fires_through_both_grant_mechanisms(tmp_path) -> None:
    """AWS-001, end to end, for a managed-policy attach and an inline-policy put.

    The inline case used to be a separate resource family with the verb `attach`; the
    family is now the resource the call names and the verb carries the mechanism. Fails
    if either mechanism stops being a grant, or if the finding's text or severity moves.
    """
    records = [
        _record(eventSource="iam.amazonaws.com", eventName="AttachUserPolicy",
                eventID="chain-1", eventTime="2026-03-04T13:00:00Z",
                userIdentity={"type": "IAMUser", "userName": "tapir"},
                requestParameters={"userName": "quokka",
                                   "policyArn": "arn:aws:iam::aws:policy/PowerUserAccess"}),
        _record(eventSource="iam.amazonaws.com", eventName="CreateAccessKey",
                eventID="chain-2", eventTime="2026-03-04T13:04:00Z",
                userIdentity={"type": "IAMUser", "userName": "quokka"},
                requestParameters={"userName": "quokka"}),
        _record(eventSource="iam.amazonaws.com", eventName="PutUserPolicy",
                eventID="chain-3", eventTime="2026-03-04T14:00:00Z",
                userIdentity={"type": "IAMUser", "userName": "tapir"},
                requestParameters={"userName": "vireo", "policyName": "ledger-inline"}),
        _record(eventSource="iam.amazonaws.com", eventName="CreateAccessKey",
                eventID="chain-4", eventTime="2026-03-04T14:02:00Z",
                userIdentity={"type": "IAMUser", "userName": "vireo"},
                requestParameters={}),
    ]
    result = _load(tmp_path, records)
    controls = result.tables[EVENT_CONTROL]

    # The documented value change: an inline put is the same family, a different verb.
    puts = controls[controls["verb"] == "put"]
    assert list(puts["resource_type"]) == ["iam:user-policy"]

    findings = [f for f in run_hunt(_telemetry(result)).findings if f.rule_id == "AWS-001"]
    assert len(findings) == 2
    assert {f.severity for f in findings} == {Severity.HIGH}

    managed = next(f for f in findings if f.user == "quokka")
    assert managed.evidence[0].summary == (
        "tapir attached arn:aws:iam::aws:policy/PowerUserAccess to quokka"
    )
    assert managed.evidence[1].summary == "quokka created an access key"
    assert "created an access key 240s later" in managed.reason

    inline = next(f for f in findings if f.user == "vireo")
    assert inline.evidence[0].summary == "tapir put ledger-inline to vireo"
    assert inline.metadata["grant_resource_type"] == "iam:user-policy"


def test_logging_tampering_fires_on_both_call_shapes(tmp_path) -> None:
    """AWS-002, end to end. Fails if keying on the service loses either call.

    The trail-stop call's resource family is now `logging` rather than `trail` -- the
    noun the call actually names. The rule keys on the `cloudtrail` service, so both it
    and the trail deletion are still the same single detection.
    """
    records = [
        _record(eventSource="cloudtrail.amazonaws.com", eventName="StopLogging",
                eventID="tamper-1", eventTime="2026-03-04T15:00:00Z",
                userIdentity={"type": "IAMUser", "userName": "quokka"},
                requestParameters={"name": "ledger-audit"}),
        _record(eventSource="cloudtrail.amazonaws.com", eventName="DeleteTrail",
                eventID="tamper-2", eventTime="2026-03-04T15:01:00Z",
                userIdentity={"type": "IAMUser", "userName": "quokka"},
                requestParameters={"name": "ledger-audit-2"}),
    ]
    result = _load(tmp_path, records)
    controls = result.tables[EVENT_CONTROL]
    assert set(controls["resource_type"]) == {"cloudtrail:logging", "cloudtrail:trail"}

    findings = [f for f in run_hunt(_telemetry(result)).findings if f.rule_id == "AWS-002"]
    assert len(findings) == 2
    assert {f.severity for f in findings} == {Severity.CRITICAL}
    reasons = sorted(f.reason for f in findings)
    assert reasons[0].startswith("'quokka' deleted CloudTrail trail 'ledger-audit-2'")
    assert reasons[1].startswith("'quokka' stopped CloudTrail trail 'ledger-audit'")


# ======================================================================================
# No allowlist may come back
# ======================================================================================


def _string_literals_outside_docstrings(source: str) -> list[str]:
    """Every string constant in the module except the docstrings."""
    tree = ast.parse(source)
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                docstrings.add(id(body[0].value))
    return [
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
        and id(node) not in docstrings
    ]


def test_the_retired_event_names_appear_nowhere_in_the_adapter() -> None:
    """Fails the moment any of the five names is written into the adapter again.

    Over the whole file, docstrings included: the adapter must not be able to describe
    itself in terms of particular API calls either, because that is how an allowlist
    grows back -- one documented special case at a time.
    """
    source = ADAPTER.read_text(encoding="utf-8")
    present = [name for name in RETIRED_EVENT_NAMES if name in source]
    assert not present, f"the adapter names specific API calls again: {present}"


def test_no_api_name_literal_survives_outside_the_authentication_set() -> None:
    """Fails if a new API name is added as a literal anywhere in the adapter's code.

    A CamelCase token that *starts* a word in a string literal is what an API name
    looks like; the same shape inside a camelCase field name (``recipientAccountId``) is
    not, hence the lookbehind. The four authentication event names are the exception -- they name authentication
    *decisions*, which belong on the logon table and genuinely are a closed set -- and
    the product's own name is not an API call.
    """
    allowed = set(AUTH_EVENTS) | {"CloudTrail"}
    camel_case = re.compile(r"(?<![A-Za-z])[A-Z][a-z]+[A-Z][A-Za-z]*")
    offenders = sorted({
        token
        for literal in _string_literals_outside_docstrings(ADAPTER.read_text(encoding="utf-8"))
        for token in camel_case.findall(literal)
        if token not in allowed
    })
    assert not offenders, f"API-name literals in the adapter: {offenders}"


# ======================================================================================
# The verb vocabulary
# ======================================================================================


def test_verb_class_module_does_not_import_the_hunting_layer() -> None:
    """Fails if the shared vocabulary drags detection into the behavior layer.

    Checked in a fresh interpreter after the module is used, so a lazy import inside
    `verb_class` would be caught too -- the static check in test_behavior.py would not
    see it.
    """
    program = (
        "import sys\n"
        "from ath.behavior.control_plane import verb_class\n"
        "verb_class('describe')\n"
        "print(','.join(m for m in ('ath.hunting', 'ath.triage', 'ath.agent') "
        "if m in sys.modules))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, cwd=str(ROOT),
        env={**__import__("os").environ, "PYTHONPATH": str(ROOT / "src")},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ""


def test_every_token_in_the_vocabulary_maps_to_a_known_class() -> None:
    """Fails if a typo'd class name enters the table and silently groups nothing."""
    unknown = {verb: cls for verb, cls in VERB_CLASSES.items() if cls not in VERB_CLASS_NAMES}
    assert not unknown
    assert all(verb == verb.lower() and verb.isalpha() for verb in VERB_CLASSES)


def test_unknown_verbs_classify_as_other_rather_than_failing() -> None:
    """Fails if an unseen verb raises or is silently dropped.

    AWS ships new API names weekly. An unknown verb must cost the row nothing: it is
    fully represented, and only its *grouping* is unknown.
    """
    assert verb_class("teleport") == "other"
    assert verb_class("") == "other"
    assert verb_class("DESCRIBE") == "read"


def test_kubernetes_audit_verbs_share_the_table() -> None:
    """Fails if the AWS and Kubernetes halves of one column stop agreeing.

    `create` means create on both platforms. A separate table per platform would make a
    cross-platform question ("who created things this week") unanswerable.
    """
    assert verb_class("deletecollection") == "delete"
    assert verb_class("watch") == verb_class("list") == verb_class("get") == "read"
    assert verb_class("patch") == verb_class("update") == "modify"
    assert verb_class("exec") == "execute"


# ======================================================================================
# M18-6: the adapter reports what it could not fill, and why
# ======================================================================================
#
# An empty `target_actor` has two causes and a population fraction reports them
# identically: either the adapter dropped a value the record carried, which is this
# project's blindness, or the record never carried one -- a denied request has no
# `requestParameters` at all, and a policy object names no principal. Only the adapter
# still holds the raw record when the column comes back empty, so only the adapter can
# say which. It counts them, with the reason, on `SourceLoadResult.field_gaps`.


def _gaps(records: list) -> dict:
    """The field gaps one or more records produce, with every row asserted kept."""
    from ath.telemetry.cloudtrail_source import _normalise_control_record

    counter: dict = {}
    for index, record in enumerate(records):
        row, _ = _normalise_control_record(record, "invented.json", index, counter)
        assert row is not None, "a gap must never be counted instead of a row"
    return counter


_GRANT = dict(
    eventSource="iam.amazonaws.com", eventName="AttachQuokkaPolicy",
    userIdentity={"type": "IAMUser", "userName": "gannet", "accountId": "900000000077"},
)
_NOT_GUARANTEED_KEY = (
    "control.target_actor: not guaranteed on this action (filled when derivable)"
)


def test_a_denied_grant_with_no_parameters_is_a_counted_gap() -> None:
    """AccessDenied on a grant: CloudTrail logs no requestParameters at all.

    2,751 of the 2,763 denied authority-changes on flaws.cloud are this shape, and until
    now the only trace of them downstream was a low population fraction that read exactly
    like an adapter which had stopped parsing parameters.

    Fails if the gap is not counted (the reason disappears and the fraction is all that
    is left), if the decision is dropped from the reason (allowed and denied become one
    number, and "the request was refused before it named anyone" stops being visible), or
    if a gap is counted instead of a row -- the helper asserts the row is kept.
    """
    gaps = _gaps([_record(**_GRANT, requestParameters=None,
                          errorCode="AccessDenied", eventID="invented-gap-1")])

    assert gaps == {
        "control.target_actor: request carried no parameters (decision=denied)": 1,
        "control.role_ref: request carried no parameters (decision=denied)": 1,
    }


def test_an_allowed_grant_with_no_parameters_is_a_different_gap() -> None:
    """The same shape, allowed: 315 of the 479 allowed authority-changes on flaws.cloud.

    A denied request that named nobody is the API refusing before it read anything; an
    *allowed* one that named nobody is a record this project should look at. Fails if the
    two are counted under one key.
    """
    gaps = _gaps([_record(**_GRANT, requestParameters={}, eventID="invented-gap-2")])

    assert gaps == {
        "control.target_actor: request carried no parameters (decision=allowed)": 1,
        "control.role_ref: request carried no parameters (decision=allowed)": 1,
    }


def test_a_grant_whose_parameters_name_nobody_is_a_third_gap() -> None:
    """Parameters present, and none of them is a beneficiary or a role.

    This is the one that would be a defect in this adapter rather than in the record, so
    it must not be collapsed into the two above. Fails if "no parameters" and "parameters
    that named nobody" share a reason -- at which point a conventions bug would read as
    an incomplete trail.
    """
    gaps = _gaps([_record(**_GRANT, eventID="invented-gap-3",
                          requestParameters={"tagKeys": ["owner"], "maxItems": 100})])

    assert gaps == {
        "control.target_actor: parameters present but named no beneficiary": 1,
        "control.role_ref: parameters present but named no role": 1,
    }


def test_a_grant_that_names_its_beneficiary_is_no_gap_at_all() -> None:
    """The control: a complete grant counts nothing.

    Fails if the gap counter fires on rows that carry the columns, which would turn the
    ledger's most useful number into a row count.
    """
    gaps = _gaps([_record(
        **_GRANT, eventID="invented-gap-4",
        requestParameters={"userName": "shrike",
                           "policyArn": "arn:aws:iam::900000000077:policy/q"},
    )])

    assert gaps == {}


@pytest.mark.parametrize("event_name,params", [
    ("DeleteQuokkaPolicy", {"policyArn": "arn:aws:iam::900000000077:policy/quokka-rw"}),
    ("CreateQuokkaPolicy", {"policyName": "quokka-rw", "path": "/"}),
    ("GenerateQuokkaReport", {}),
])
def test_an_authority_change_that_names_no_principal_is_informational_only(
    event_name, params
) -> None:
    """A policy created or deleted, a report generated: 146 rows of attack_data_aws.

    These change an authority and act on an object that is not a principal, so an empty
    beneficiary is not a gap in the strong sense and no denominator contains them. They
    are counted anyway, under their own reason, because "this capture changed authority
    146 times and named nobody" is worth seeing -- it is how a reader knows AWS-001's
    "not applicable" is a fact about the corpus and not a rule excusing itself.

    Fails if these are counted as grant gaps (the two populations merge and the
    flaws.cloud decomposition stops meaning anything), and fails if they are counted not
    at all (the M18-5 observation disappears from every artifact).
    """
    gaps = _gaps([_record(eventSource="iam.amazonaws.com", eventName=event_name,
                          requestParameters=params, eventID="invented-gap-5",
                          userIdentity={"type": "IAMUser", "userName": "gannet"})])

    assert gaps == {_NOT_GUARANTEED_KEY: 1}


def test_a_read_about_an_identity_counts_no_gap() -> None:
    """Reads are outside both populations: nothing was changed, so nothing is missing.

    Fails if the informational counter is keyed on the identity *service* rather than on
    an authority change -- at which point 11,388 flaws.cloud reads would be reported as
    fields this project failed to fill.
    """
    assert _gaps([_record(eventSource="iam.amazonaws.com",
                          eventName="DescribeLedgerUserGrants", eventID="invented-gap-6",
                          requestParameters={"userName": "shrike"})]) == {}


def test_gaps_reach_the_load_result_without_touching_the_drop_count(tmp_path) -> None:
    """A whole load: the gaps are on the result, the rows are in the table, none dropped.

    Fails if a gap is ever added to `rows_dropped` (kept rows would be reported as lost,
    which is the over-counting M18-3 flagged), if the counter is not threaded from the
    record loop to the result (every artifact reports an empty dict), or if the summary
    line stops mentioning them.
    """
    result = _load(tmp_path, [
        _record(**_GRANT, requestParameters=None, errorCode="AccessDenied",
                eventID="invented-gap-7"),
        _record(eventSource="iam.amazonaws.com", eventName="DeleteQuokkaPolicy",
                requestParameters={"policyArn": "arn:aws:iam::900000000077:policy/q"},
                eventID="invented-gap-8"),
    ])

    assert len(result.tables[EVENT_CONTROL]) == 2
    assert result.rows_kept == 2
    assert result.rows_dropped == 0
    assert result.field_gaps == {
        "control.target_actor: request carried no parameters (decision=denied)": 1,
        "control.role_ref: request carried no parameters (decision=denied)": 1,
        _NOT_GUARANTEED_KEY: 1,
    }
    assert "3 field gap(s) on kept rows" in result.summary()
    assert "0 dropped" in result.summary()


def test_group_membership_records_the_group_as_what_conferred_the_authority(tmp_path) -> None:
    """AddUserToGroup-shaped: the user is the beneficiary, the group is the role.

    Reads the same two ordered tuples as every other call, and the order is the whole
    convention: `userName` outranks `groupName` as a beneficiary, `groupName` is last
    among the roles. Fails if `groupName` is dropped from the role tuple (putting a user
    into an administrators group records *what* they were given as nothing), and fails if
    it is promoted above `policyArn` (attaching a policy to a group would record the
    group as both the target and the thing conferred).
    """
    rows = {
        row["source_ref"].split(";")[0]: (row["target_actor"], row["role_ref"])
        for _, row in _load(tmp_path, [
            _record(eventSource="iam.amazonaws.com", eventName="AddQuokkaUserToLedgerGroup",
                    eventID="invented-role-1",
                    requestParameters={"userName": "shrike", "groupName": "ledger-admins"}),
            _record(eventSource="iam.amazonaws.com", eventName="AttachLedgerGroupPolicy",
                    eventID="invented-role-2",
                    requestParameters={"groupName": "ledger-admins",
                                       "policyArn": "arn:aws:iam::900000000077:policy/q"}),
            _record(eventSource="iam.amazonaws.com",
                    eventName="AddLedgerRoleToApplianceProfile", eventID="invented-role-3",
                    requestParameters={"roleName": "ledger-operator",
                                       "instanceProfileName": "appliance-fleet"}),
        ]).tables[EVENT_CONTROL].iterrows()
    }

    assert rows["eventID=invented-role-1"] == ("shrike", "ledger-admins")
    assert rows["eventID=invented-role-2"] == (
        "ledger-admins", "arn:aws:iam::900000000077:policy/q",
    )
    assert rows["eventID=invented-role-3"] == ("ledger-operator", "appliance-fleet")
