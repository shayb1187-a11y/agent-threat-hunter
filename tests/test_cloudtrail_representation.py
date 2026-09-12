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
        # userName wins over groupName: the beneficiary is the identity, not the container.
        ("AddUserToGroup", {"userName": "quokka", "groupName": "ledger-admins"},
         "quokka", ""),
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

    None of these five calls is named anywhere in the adapter, and four of them were not
    mapped at all before this change.
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
