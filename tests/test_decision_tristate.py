"""M18-7: "denied" means the platform refused authorization, not that something failed.

The defect these tests guard: ``decision`` was two-valued, and "denied" meant *any*
error. On the public flaws.cloud trail the largest contributor to that value is
``Client.RequestLimitExceeded`` -- 779,330 rows of one account's ``RunInstances`` retry
loop being throttled -- so a count of denials per identity, which is the one question the
column exists to answer, was a count of retries. The split between "the platform refused
your authority" and "the platform rejected your request" is a closed vocabulary of
authorization-error tokens, shared by every adapter, and never a per-API table.

Names below (``quokka``, ``ledger``, ``appliance`` and their relatives) are the invented
vocabulary of ``tests/test_cloudtrail_representation.py``, whose disjointness from the
attack_data_aws capture and the flaws.cloud top-100 is asserted programmatically there.
"""

from __future__ import annotations

import inspect

import pytest

from ath.control_vocab import (
    AUTHORIZATION_ERROR_TOKENS,
    DECISION_ALLOWED,
    DECISION_DENIED,
    DECISION_FAILED,
    DECISIONS,
    classify_error,
)
from ath.environment.channels import FIELD_APPLICABILITY
from ath.hunting import run_hunt
from ath.hunting.base import all_detectors, get_detector
from ath.schema import EVENT_CONTROL
from ath.telemetry.k8s_audit_source import _decision, _normalise_control_record

from tests import _builders as build


# ======================================================================================
# classify_error: the shared definition of denied vs failed
# ======================================================================================


def test_no_error_is_allowed() -> None:
    """Fails if an absent error code is ever read as an outcome other than success."""
    assert classify_error(None) == DECISION_ALLOWED
    assert classify_error("") == DECISION_ALLOWED
    assert classify_error("   ") == DECISION_ALLOWED
    assert classify_error(None, 200) == DECISION_ALLOWED


@pytest.mark.parametrize("token", AUTHORIZATION_ERROR_TOKENS)
@pytest.mark.parametrize("shape", [
    "{token}",              # the bare token
    "Client.{token}",       # EC2's service-class prefix
    "{token}Exception",     # the newer SDK spelling
    "quokka:{token}",       # a service-qualified refusal
    "  {TOKEN}  ",          # upper case, surrounded by whitespace
])
def test_every_authorization_token_is_a_denial_however_it_is_spelled(token, shape) -> None:
    """Each token in the vocabulary, in five spellings, must classify as denied.

    Fails if the match becomes exact rather than a substring (every prefixed and suffixed
    spelling stops being a denial and lands in "failed", which is where 351,760
    ``Client.UnauthorizedOperation`` rows of flaws.cloud would go), or if the comparison
    stops being case-insensitive.
    """
    code = shape.format(token=token, TOKEN=token.upper())
    assert classify_error(code) == DECISION_DENIED, code


@pytest.mark.parametrize("code", [
    # Throttling and capacity -- the three biggest non-authorization codes on flaws.cloud.
    "Client.RequestLimitExceeded",
    "ThrottlingException",
    "Client.InstanceLimitExceeded",
    "Server.InsufficientInstanceCapacity",
    # Validation: the request was malformed, which says nothing about the caller's rights.
    "MalformedPolicyDocumentException",
    "ValidationException",
    "InvalidParameterValue",
    # Absence and conflict.
    "NoSuchBucket",
    "NoSuchEntityException",
    "DeleteConflictException",
    "EntityAlreadyExists",
    # The platform declining the call itself.
    "Client.Unsupported",
    "InternalError",
])
def test_a_rejection_that_is_not_about_authority_is_a_failure(code) -> None:
    """Fails if any of these classifies as denied -- which is the two-valued column.

    ``AccessDenied`` is 120,988 rows of flaws.cloud and ``Client.RequestLimitExceeded`` is
    779,330; a vocabulary that admitted the second would make the column six times larger
    and entirely about retries.
    """
    assert classify_error(code) == DECISION_FAILED, code


@pytest.mark.parametrize("status,expected", [
    (401, DECISION_DENIED),   # not authenticated
    (403, DECISION_DENIED),   # authenticated and not permitted
    (404, DECISION_FAILED),   # the object is not there
    (409, DECISION_FAILED),   # conflict
    (422, DECISION_FAILED),   # unprocessable
    (500, DECISION_FAILED),   # the server broke
    (200, DECISION_ALLOWED),
    (201, DECISION_ALLOWED),
    (101, DECISION_ALLOWED),  # the protocol upgrade a successful exec is answered with
])
def test_http_status_decides_only_401_and_403_as_denial(status, expected) -> None:
    """Fails if any non-2xx status is read as a refusal of authority (the pre-M18-7 rule
    for Kubernetes, under which every 404 on a secret was an access denial) or if 101
    stops being success (every successful container shell becomes a blocked one)."""
    assert classify_error(None, status) == expected


def test_the_order_of_the_tests_is_the_definition() -> None:
    """A source reporting both a code and a status: which one decides, and when.

    The authorization *token* is read first, so a refusal carried in the body of an
    otherwise-successful response is still a refusal; an explicit 401/403 is read next, so
    a platform that answers with the authorization status is believed whatever else it
    said; only then does any remaining code make the row a failure.

    Fails if the status test is moved ahead of the token test (an ``AccessDenied`` body
    returned with a 200 reads as allowed) or if a code is allowed to overrule an explicit
    authorization status.
    """
    assert classify_error("AccessDenied", 200) == DECISION_DENIED
    assert classify_error("NoSuchBucket", 200) == DECISION_FAILED
    assert classify_error("NoSuchBucket", 403) == DECISION_DENIED


def test_every_classification_is_one_of_the_declared_decisions() -> None:
    """Fails if a fourth value is ever returned from anywhere in the function."""
    codes = [None, "", "AccessDenied", "NoSuchBucket", "Unrecognized"]
    statuses = [None, 101, 200, 204, 301, 401, 403, 404, 409, 500]
    for code in codes:
        for status in statuses:
            assert classify_error(code, status) in DECISIONS


def test_the_vocabulary_is_authorization_semantics_and_not_a_corpus_listing() -> None:
    """The tokens name kinds of refusal; the corpora's other error codes must be absent.

    Fails the moment a throttling, validation, absence or conflict code is added to the
    vocabulary to make one corpus come out a particular way -- which is how a measured
    threshold turns into a fitted one.
    """
    forbidden = (
        "requestlimit", "throttl", "malformed", "nosuch", "conflict", "unsupported",
        "capacity", "limitexceeded", "alreadyexists", "validation", "internalerror",
    )
    for token in AUTHORIZATION_ERROR_TOKENS:
        assert not any(word in token for word in forbidden), token
        assert token == token.lower().strip(), token


# ======================================================================================
# The Kubernetes adapter
# ======================================================================================


def _audit_item(code: int | None, *, verb: str = "get") -> dict:
    """One apiserver audit event, named disjointly from the k8s_ci corpus."""
    item = {
        "kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "RequestResponse",
        "auditID": "invented-tristate-1", "stage": "ResponseComplete", "verb": verb,
        "requestURI": "/api/v1/namespaces/quokka/pods/ledger-7/exec?command=sh",
        "user": {"username": "wpaulsen", "groups": ["system:authenticated"]},
        "sourceIPs": ["198.51.100.203"], "userAgent": "kubectl/v1.30.2",
        "objectRef": {
            "resource": "pods", "subresource": "exec",
            "namespace": "quokka", "name": "ledger-7",
        },
        "stageTimestamp": "2026-03-04T11:00:00.000000Z",
    }
    if code is not None:
        item["responseStatus"] = {"metadata": {}, "code": code}
    return item


@pytest.mark.parametrize("code,expected", [
    (403, DECISION_DENIED),
    (404, DECISION_FAILED),
    (200, DECISION_ALLOWED),
])
def test_the_kubernetes_adapter_records_the_three_decisions(code, expected) -> None:
    """A forbidden exec, an exec on a pod that is not there, and one that worked.

    Fails if the adapter goes back to "any non-2xx is denied": the 404 -- a request for an
    object that does not exist, which every reconciliation loop produces -- would be
    recorded as the apiserver refusing an identity.
    """
    row, issue = _normalise_control_record(_audit_item(code), "invented.log", 0, "quokka")
    assert issue is None
    assert row is not None
    assert row["decision"] == expected


def test_an_unreadable_status_is_a_failure_not_a_denial() -> None:
    """Fails if a missing or malformed status code manufactures authorization evidence."""
    assert _decision({}) == DECISION_FAILED
    assert _decision({"responseStatus": {}}) == DECISION_FAILED
    assert _decision({"responseStatus": {"code": "four hundred and three"}}) == DECISION_FAILED
    assert _decision({"responseStatus": "Failure"}) == DECISION_FAILED


# ======================================================================================
# What the tri-state may not change: the rules
# ======================================================================================


# Exactly the rules that are allowed to read `decision`, and what each reads it *for*.
# The point of naming them is that the list is short and deliberate: when M18-7 split the
# column, no rule read it at all, which is what made the split safe to make. M18-8 added
# four rules whose subject *is* the platform's answer, and each of them depends on the
# third value existing -- AWS-004 counts authorization refusals and would otherwise be
# counting a throttled retry loop; AWS-006 counts the rejections that are specifically
# *not* refusals; AWS-005 refuses to call an attempted removal a removal.
DECISION_READERS: dict[str, str] = {
    "AWS-003": "denied fraction grades the burst HIGH or MEDIUM",
    "AWS-004": "the filter IS `decision == denied`",
    "AWS-005": "only `allowed` rows count as a removal that happened",
    "AWS-006": "the filter IS `decision == failed`, the complement of AWS-004's",
}


def test_only_the_declared_rules_read_the_decision_column() -> None:
    """Which detections are capable of noticing the third value, named one by one.

    AWS-002 does *not* read ``decision`` -- it keys on the service prefix and the verb --
    and neither does any Windows rule, which is why splitting "denied" in two could not
    move a finding anywhere when the split was made. Asserted structurally rather than
    claimed in prose: fails the moment a rule starts filtering on the column without the
    tri-state being revisited, which is exactly when "denied means any error" would
    silently become part of a detection's meaning again.
    """
    readers = [
        detector.rule_id for detector in all_detectors()
        # The quoted column name, which is how a rule would address the column
        # (`controls["decision"]`) -- not the bare word, which appears in ATH-005's prose
        # about policy decisions and says nothing about what the rule reads.
        if '"decision"' in inspect.getsource(type(detector))
        or "'decision'" in inspect.getsource(type(detector))
        or "decision" in getattr(detector, "fields_used", ())
        or "decision" in getattr(detector, "optional_fields", frozenset())
    ]
    assert sorted(readers) == sorted(DECISION_READERS), (
        f"rules reading `decision` changed: {sorted(readers)}"
    )


def test_no_decision_reader_treats_failed_as_denied() -> None:
    """The distinction the tri-state exists for, enforced on the rules that use it.

    Failure mode: a rule written as ``decision != "allowed"``. That is the two-valued
    column returning by the back door -- and on the background trail it would put one
    account's throttled retry loop back inside a permission-probe detection.
    """
    for rule_id in DECISION_READERS:
        source = inspect.getsource(type(get_detector(rule_id)))
        assert '!= "allowed"' not in source and "!= DECISION_ALLOWED" not in source, (
            f"{rule_id} treats every non-allowed answer alike"
        )


def _trail_tampering(decision: str) -> list[dict]:
    """A stop and a delete against the audit service, recorded with one decision."""
    return [
        build.ctrl(
            "mriordan", verb, "cloudtrail:quokka-trail", f"quokka-trail-{index}",
            decision=decision, device="aws:519204773311/ap-southeast-2",
            source_ip="198.51.100.203", source="cloudtrail_mgmt",
            when=build.at(minutes=index),
        )
        for index, verb in enumerate(("stop", "delete"))
    ]


@pytest.mark.parametrize("decision", DECISIONS)
def test_aws002_finds_the_same_rows_whatever_the_decision_says(decision) -> None:
    """The same two rows under each of the three values produce the same two findings.

    AWS-002 does not read the column, so this pins the consequence rather than the
    mechanism: fails if the rule ever starts gating on ``decision`` -- in either
    direction. A rule that fired only on allowed rows would miss an attempt; one that
    treated "failed" as "denied" would inherit the defect this milestone removes.
    """
    findings = run_hunt(build.telemetry(ctrls=_trail_tampering(decision))).findings
    aws002 = [f for f in findings if f.rule_id == "AWS-002"]
    assert len(aws002) == 2, [f.rule_id for f in findings]


# ======================================================================================
# The applicability denominator: a refused request carries no guaranteed parameters
# ======================================================================================


def _grant(index: int, *, decision: str, target: str) -> dict:
    return build.ctrl(
        "mriordan", "attach", "iam:quokka-policy", f"quokka-policy-{index}",
        target_actor=target, role_ref="quokka-admin" if target else "",
        decision=decision, device="aws:519204773311/ap-southeast-2",
        source_ip="198.51.100.203", source="cloudtrail_mgmt",
        when=build.at(minutes=index),
    )


def test_a_refused_grant_is_outside_the_denominator() -> None:
    """10 allowed grants that name their beneficiary + 10 denied grants that name nobody.

    CloudTrail logs no ``requestParameters`` at all on a refused call, so a denied grant
    has no beneficiary to record -- the record is empty by construction, not by any loss
    in this project. Applicable rows must therefore be the 10 allowed grants and the
    fraction 1.0.

    Fails if the decision clause is dropped: the denominator becomes 20, the fraction 0.5,
    and AWS-001 is reported DEGRADED on a corpus where every grant the platform actually
    performed names its subject.
    """
    allowed = [_grant(i, decision=DECISION_ALLOWED, target="wpaulsen") for i in range(10)]
    denied = [_grant(10 + i, decision=DECISION_DENIED, target="") for i in range(10)]
    table = build.telemetry(ctrls=allowed + denied).controls

    applies = FIELD_APPLICABILITY[(EVENT_CONTROL, "target_actor")].applies_to(table)
    assert int(applies.sum()) == 10
    populated = table.loc[applies, "target_actor"].astype("string").fillna("")
    assert float((populated.str.len() > 0).mean()) == 1.0


def test_a_failed_grant_is_outside_the_denominator_too() -> None:
    """The same shape with the refusal being a validation error rather than a denial.

    ``MalformedPolicyDocumentException`` is 10 of the attack_data_aws T1580 capture's
    rows. A request the platform rejected for any reason carries no guaranteed parameters,
    so the denominator is the allowed rows and nothing else. Fails if the clause is
    written as ``decision != denied`` instead of ``decision == allowed``, which would put
    the failures back in.
    """
    allowed = [_grant(i, decision=DECISION_ALLOWED, target="wpaulsen") for i in range(10)]
    failed = [_grant(10 + i, decision=DECISION_FAILED, target="") for i in range(10)]
    table = build.telemetry(ctrls=allowed + failed).controls

    applies = FIELD_APPLICABILITY[(EVENT_CONTROL, "target_actor")].applies_to(table)
    assert int(applies.sum()) == 10


def test_the_reason_names_what_the_excluded_rows_have_in_common() -> None:
    """A denominator narrowed without saying why is an excuse. Fails if the reason stops
    naming either the guarantee or the refusal."""
    reason = FIELD_APPLICABILITY[(EVENT_CONTROL, "role_ref")].reason
    assert "identity grant" in reason
    assert "allowed" in reason
    assert "refused" in reason or "failed" in reason
