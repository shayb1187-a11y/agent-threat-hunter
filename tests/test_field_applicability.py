"""A field is measured over the rows it could have carried a value on.

The defect these guard is the mirror image of M17-2, and it arrived with M18-3. Once
every CloudTrail management call became a control row, ``target_actor`` -- a column only
a grant can fill -- read as populated on 0.61% of 1,857,154 rows, and AWS-001 was
reported UNUSABLE on a corpus where every one of its 132 grant rows carried the field.
Reporting blindness that does not exist spends exactly the trust that hiding blindness
spends; a rule called blind on rows its field never applied to is not a conservative
error, it is a wrong one.

Each test below is built so that deleting the applicability check leaves it failing,
*and* so that a check which simply excused an empty field would fail it too. Every test
that asserts a field is not blind has a paired test, on the same shape, that asserts it
is blind when the value is genuinely missing from the rows that should carry it.

Actors, services, accounts and hosts here appear in no other fixture, so nothing can
pass by matching data it was tuned on.
"""

from __future__ import annotations

import ast
import inspect
import os
import subprocess
import sys
from pathlib import Path

import pytest
from tests import _builders as build

from ath.environment import (
    DEGRADED_BELOW,
    UNUSABLE_BELOW,
    RuleSupport,
    RuleVerdict,
    assess_coverage,
    build_environment_model,
)
from ath.environment.channels import FIELD_APPLICABILITY, measure_field_populations
from ath.hunting.base import all_detectors
from ath.schema import REMOTE_LOGON_TYPES, TABLE_COLUMNS
from ath.telemetry.loader import Telemetry


def _rule(telemetry: Telemetry, rule_id: str):
    report = assess_coverage(build_environment_model(telemetry))
    return next(r for r in report.rules if r.rule_id == rule_id)


def _field(runnability, column: str):
    return next(f for f in runnability.fields if f.column == column)


# --------------------------------------------------------------------------------------
# The control table: a trail of reads with a handful of grants in it
# --------------------------------------------------------------------------------------

_READ_CALLS = (
    ("describe", "ec2:volume"),
    ("list", "s3:bucket"),
    ("get", "kms:key-policy"),
    ("describe", "rds:db-instance"),
    ("list", "sqs:queue"),
)


def _reads(count: int) -> list[dict]:
    """Read-shaped control rows across several services, carrying no grant fields."""
    return [
        build.ctrl(
            "mriordan", verb, resource_type, f"{resource_type.split(':')[-1]}-{index}",
            device="aws:519204773311/ap-southeast-2", source_ip="198.51.100.203",
            source="cloudtrail_mgmt", when=build.at(seconds=index),
            actor_groups="system:authenticated",
        )
        for index in range(count)
        for verb, resource_type in [_READ_CALLS[index % len(_READ_CALLS)]]
    ]


def _grants(count: int, *, target: str = "wpaulsen", role: str = "cluster-admin") -> list[dict]:
    """Grant-shaped control rows: half AWS ``attach``, half Kubernetes binding creates.

    Both shapes in one helper on purpose -- ``is_grant`` has two clauses and a test that
    exercised only the verb clause would not notice the resource clause disappearing.
    """
    rows = []
    for index in range(count):
        if index % 2 == 0:
            rows.append(build.ctrl(
                "mriordan", "attach", "iam:user-policy", f"AdminAccess-{index}",
                target_actor=target, role_ref=role,
                device="aws:519204773311/ap-southeast-2", source_ip="198.51.100.203",
                source="cloudtrail_mgmt", when=build.at(minutes=90, seconds=index),
                actor_groups="system:authenticated",
            ))
        else:
            rows.append(build.ctrl(
                "mriordan", "create", "rolebindings", f"binding-{index}",
                target_actor=target, role_ref=role, namespace="payments",
                device="k8s:mercury", source_ip="198.51.100.203",
                source="k8s_audit", when=build.at(minutes=90, seconds=index),
                actor_groups="system:authenticated",
            ))
    return rows


def test_a_grant_field_is_measured_over_grants_not_over_the_whole_trail() -> None:
    """1,000 reads + 10 grants that all carry the grant fields: nobody is blind.

    Fails without applicability: 10/1010 is 0.99%, under UNUSABLE_BELOW, so AWS-001 and
    K8S-001 are both reported UNUSABLE on target_actor and role_ref while every grant in
    the dataset carries both. The raw fraction is asserted too, so the test also fails if
    applicability were implemented by quietly dropping the whole-table measurement.
    """
    telemetry = build.telemetry(ctrls=_reads(1_000) + _grants(10))

    for rule_id in ("AWS-001", "K8S-001"):
        rule = _rule(telemetry, rule_id)
        assert rule.verdict is not RuleVerdict.UNUSABLE, rule.detail
        for column in ("target_actor", "role_ref"):
            field = _field(rule, column)
            assert field.applicable
            assert field.population.applicable_rows == 10
            assert field.fraction == 1.0
            assert field.population.raw_fraction == pytest.approx(10 / 1010)
            assert field.population.raw_fraction < UNUSABLE_BELOW, (
                "the raw fraction must still be under the floor, or this test is not "
                "exercising the defect it was written for"
            )


def test_a_grant_field_missing_from_the_grants_is_still_blindness() -> None:
    """The same 1,000 reads and 10 grants, with target_actor emptied on the grants.

    Applicability narrows the denominator; it must never excuse the numerator. Fails if
    the predicate is written so that "no populated applicable row" reads as "nothing to
    measure" -- which would make every real loss invisible, the exact failure M18-1 was
    built to prevent.
    """
    grants = [dict(row, target_actor="") for row in _grants(10)]
    telemetry = build.telemetry(ctrls=_reads(1_000) + grants)

    aws001 = _rule(telemetry, "AWS-001")
    assert aws001.verdict is RuleVerdict.UNUSABLE
    assert "target_actor" in aws001.unpopulated_fields
    assert "target_actor" in aws001.detail
    field = _field(aws001, "target_actor")
    assert field.population.applicable_rows == 10
    assert field.fraction == 0.0


def test_a_trail_with_no_grant_reports_the_question_as_not_arising() -> None:
    """Reads only: target_actor is not applicable, and it moves no verdict.

    AWS-001 comes back USABLE -- every field it filters on that this data can speak to
    is populated, and the two that only a grant could fill are reported as not
    applicable rather than as empty. That is the honest reading: the corpus contains no
    grant, so it says nothing at all about whether grant beneficiaries are recorded.

    Fails without applicability (UNUSABLE, naming target_actor), and fails if a
    zero-applicable field were graded as 0% (also UNUSABLE) or silently dropped from
    the report (the not_applicable_fields assertion).
    """
    telemetry = build.telemetry(ctrls=_reads(400))

    aws001 = _rule(telemetry, "AWS-001")
    assert aws001.verdict is RuleVerdict.USABLE, aws001.detail
    assert set(aws001.not_applicable_fields) == {"target_actor", "role_ref"}
    assert not aws001.unpopulated_fields
    assert not aws001.sparse_fields
    assert "not applicable in this data" in aws001.detail

    payload = aws001.to_dict()
    assert payload["not_applicable_fields"] == ["role_ref", "target_actor"]
    entry = next(f for f in payload["fields"] if f["column"] == "target_actor")
    assert entry["applicable"] is False and entry["applicable_rows"] == 0
    assert entry["rows"] == 400


# --------------------------------------------------------------------------------------
# The logon table
# --------------------------------------------------------------------------------------

def _successes(count: int) -> list[dict]:
    return [
        build.logon("hbrandt", "TILL-042", logon_type=3, source_ip="203.0.113.61",
                    source_device="TILL-001", action="success",
                    when=build.at(seconds=index * 3))
        for index in range(count)
    ]


def _failures(count: int, *, reason: str) -> list[dict]:
    return [
        build.logon("hbrandt", "TILL-042", logon_type=3, source_ip="203.0.113.61",
                    source_device="TILL-001", action="failure", failure_reason=reason,
                    when=build.at(minutes=200, seconds=index * 3))
        for index in range(count)
    ]


def test_a_failure_reason_is_measured_over_failures() -> None:
    """1,000 successes and 50 failures, every failure carrying a reason.

    Fails without applicability: 50/1050 is 4.8%, under DEGRADED_BELOW, so ATH-005 is
    reported DEGRADED on a field that is complete wherever the schema allows it to
    exist -- an empty failure_reason on a successful logon is the schema working, not a
    gap.
    """
    telemetry = build.telemetry(logons=_successes(1_000) + _failures(50, reason="bad_password"))

    ath005 = _rule(telemetry, "ATH-005")
    field = _field(ath005, "failure_reason")
    assert field.population.applicable_rows == 50
    assert field.fraction == 1.0
    assert field.population.raw_fraction == pytest.approx(50 / 1050)
    assert field.population.raw_fraction < DEGRADED_BELOW
    assert "failure_reason" not in ath005.sparse_fields
    assert ath005.verdict is RuleVerdict.USABLE


def test_a_failure_reason_missing_from_the_failures_is_still_measured_and_reported() -> None:
    """The same shape with every failure's reason empty.

    ATH-005 declares failure_reason optional -- it phrases the evidence and gates
    nothing -- so under the M18-2 definition of optional its emptiness cannot weaken the
    detection, and since M18-5 it does not move the verdict. What it must never do is
    disappear: applicability narrows the denominator and is not allowed to excuse the
    numerator, so the 0-of-50 is measured, and the evidence cost is reported on
    `sparse_optional_fields` and in the detail line.

    Fails if applicability hides a genuine loss (the field would read as not applicable,
    or be missing from both lists), and fails if an optional field grades again.
    """
    telemetry = build.telemetry(logons=_successes(1_000) + _failures(50, reason=""))

    ath005 = _rule(telemetry, "ATH-005")
    field = _field(ath005, "failure_reason")
    assert field.applicable and field.population.applicable_rows == 50
    assert field.fraction == 0.0
    assert not field.required, "ATH-005 reads failure_reason for phrasing only"
    assert "failure_reason" not in ath005.sparse_fields
    assert "failure_reason" not in ath005.unpopulated_fields
    assert "failure_reason" in ath005.sparse_optional_fields
    assert "evidence detail reduced: failure_reason" in ath005.detail


def test_a_console_logon_is_not_missing_the_source_it_cannot_have() -> None:
    """500 interactive logons with no source, 100 network logons with one.

    Interactive (type 2) happens at the keyboard: there is no source host to record.
    Fails without applicability -- 100/600 is 16.7%, under DEGRADED_BELOW, so
    ``source_device`` would be listed among ATH-006's sparse fields while every remote
    logon in the data names its source.

    ATH-006 still grades DEGRADED here, and deliberately so: the *channel* measurement
    is whole-table on purpose, because "does this deployment have source attribution at
    all" is a question about the dataset and not about one rule's rows. The two are
    asserted apart -- no field is sparse, and the DEGRADED comes from the channel -- so
    a future change that narrowed the channel view to applicable rows would fail here
    rather than quietly redefine what a channel means.
    """
    interactive = [
        build.logon("dcassar", "LAB-7", logon_type=2, source_ip="", source_device="",
                    action="success", when=build.at(seconds=index))
        for index in range(500)
    ]
    network = [
        build.logon("dcassar", "LAB-7", logon_type=3, source_ip="203.0.113.88",
                    source_device="LAB-1", action="success",
                    when=build.at(minutes=60, seconds=index))
        for index in range(100)
    ]
    telemetry = build.telemetry(logons=interactive + network)

    ath006 = _rule(telemetry, "ATH-006")
    field = _field(ath006, "source_device")
    assert field.population.applicable_rows == 100
    assert field.fraction == 1.0
    assert field.population.raw_fraction == pytest.approx(100 / 600)
    assert "source_device" not in ath006.sparse_fields
    assert not ath006.unpopulated_fields
    assert ath006.verdict is RuleVerdict.DEGRADED
    assert ath006.support is RuleSupport.DEGRADED
    assert "auth_source_attribution" in ath006.detail, (
        "the remaining DEGRADED must be the channel measurement, not a field one"
    )
    assert set(REMOTE_LOGON_TYPES) == {3, 10}


def test_a_source_that_cannot_supply_a_logon_type_is_still_measured() -> None:
    """The CloudTrail shape: logon_type null everywhere, and no source_device at all.

    An unknown logon type is assumed applicable, in the one direction that cannot
    manufacture reassurance. Fails if the predicate excludes null logon types: every
    row would fall out of the denominator, source_device would report "not applicable",
    and a source with no source attribution whatsoever would read as healthy.
    """
    rows = [
        build.logon("arn:aws:iam::519204773311:user/nvarga", "aws:519204773311/eu-north-1",
                    logon_type=None, source_ip="", source_device="", action="success",
                    when=build.at(seconds=index * 7))
        for index in range(300)
    ]
    telemetry = build.telemetry(logons=rows)

    ath006 = _rule(telemetry, "ATH-006")
    field = _field(ath006, "source_device")
    assert field.applicable
    assert field.population.applicable_rows == 300, "a null logon type stays in the denominator"
    assert field.fraction == 0.0
    assert ath006.verdict is RuleVerdict.UNUSABLE
    assert "source_device" in ath006.unpopulated_fields


# --------------------------------------------------------------------------------------
# Where applicability may and may not be declared
# --------------------------------------------------------------------------------------

def test_applicability_is_declared_in_exactly_one_place() -> None:
    """Every entry names a real (table, column), and nothing else declares one.

    Fails on a typo in the declaration table (a column that does not exist would be
    silently never applied), and fails if a second module grows its own copy.
    """
    for table, column in FIELD_APPLICABILITY:
        assert table in TABLE_COLUMNS, f"unknown table {table!r}"
        assert column in TABLE_COLUMNS[table], f"{table} has no column {column!r}"

    from ath.environment import channels

    source = inspect.getsource(channels)
    assert source.count("FIELD_APPLICABILITY: dict") == 1


def test_no_detector_may_declare_its_own_applicability() -> None:
    """A rule that chose its own denominator could vote itself usable.

    The whole point of measuring population is that the rule does not get to say
    whether it can see. Fails the moment any detector grows an attribute that looks
    like an applicability declaration, however it is spelled.
    """
    forbidden = ("applicab", "denominator", "applies_to", "measured_over")
    for detector in all_detectors():
        for name in dir(detector):
            lowered = name.lower()
            assert not any(word in lowered for word in forbidden), (
                f"{detector.rule_id} declares {name!r}; applicability is a property of "
                "the canonical schema, declared once in ath.environment.channels"
            )


def test_the_kubernetes_adapter_reads_the_leaf_binding_resources() -> None:
    """One declaration of one fact, reached by both layers.

    Until M18-5 ``ath.telemetry`` could not import ``ath.behavior``, so the adapter kept
    its own ``_RBAC_RESOURCES`` and a test held the two sets equal -- a guarded seam
    rather than no seam. The leaf module removes it: the adapter now imports the same
    object. Fails if a second copy is reintroduced anywhere in the adapter, or if the
    adapter stops consulting the shared set (a binding kind would then be either
    invisible to the predicate or invisible to the adapter, with nothing to notice).
    """
    from ath.control_vocab import RBAC_BINDING_RESOURCES
    from ath.telemetry import k8s_audit_source

    assert k8s_audit_source.RBAC_BINDING_RESOURCES is RBAC_BINDING_RESOURCES

    tree = ast.parse(inspect.getsource(k8s_audit_source))
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef))
        and node.body and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    }
    literals = {
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
        and id(node) not in docstrings
    }
    assert not (literals & RBAC_BINDING_RESOURCES), (
        "the adapter names a binding resource of its own again"
    )


def test_the_control_vocabulary_is_a_leaf_every_layer_may_import() -> None:
    """The whole reason the duplicate existed was an import it could not make.

    Checked in a fresh interpreter *after* the predicates are exercised, so a lazy
    import inside one of them would be caught too. Fails the moment the vocabulary grows
    a dependency on telemetry, behavior, environment or hunting -- at which point the
    adapters could not import it and the second copy would come back.
    """
    root = Path(__file__).resolve().parent.parent
    program = (
        "import sys\n"
        "from ath.control_vocab import changes_authority, is_grant, verb_class\n"
        "changes_authority('attach', 'iam:user-policy')\n"
        "is_grant('create', 'rolebindings')\n"
        "verb_class('describe')\n"
        "forbidden = ('telemetry', 'behavior', 'environment', 'hunting')\n"
        "print(','.join(sorted(m for m in sys.modules\n"
        "    if m.split('.')[:1] == ['ath'] and m.split('.')[1:2]\n"
        "    and m.split('.')[1] in forbidden)))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, cwd=str(root),
        env={**os.environ, "PYTHONPATH": str(root / "src")},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "", f"leaf module imported: {result.stdout.strip()}"


# --------------------------------------------------------------------------------------
# changes_authority: the predicate behind target_actor and role_ref
#
# Services, verbs and resource families below exercise the *rule* rather than any
# corpus: ``quokka``, ``ledger`` and ``appliance`` are families invented for
# tests/test_cloudtrail_representation.py, whose disjointness from the attack_data_aws
# capture and the flaws.cloud top-100 is asserted programmatically there.
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("verb_class_name,verb", [
    ("grant", "attach"), ("revoke", "detach"), ("create", "put"),
    ("delete", "delete"), ("modify", "update"),
])
@pytest.mark.parametrize("resource_type", [
    "iam:quokka-policy", "iam:ledger-user", "iam", "rolebindings", "clusterrolebindings",
])
def test_every_changing_class_on_an_identity_object_changes_authority(
    verb_class_name, resource_type, verb
) -> None:
    """Five verb classes against the identity service and both RBAC binding kinds.

    Fails if the predicate narrows back to GRANT (a revoke, a delete and a login-profile
    update stop naming the identity whose authority they moved), and fails if the
    binding clause is dropped (every Kubernetes grant stops naming its subject).
    """
    from ath.control_vocab import changes_authority, verb_class

    assert verb_class(verb) == verb_class_name
    assert changes_authority(verb, resource_type)


@pytest.mark.parametrize("verb,resource_type", [
    # A read on the identity service: names a user, changes nothing about that user.
    ("list", "iam:quokka-policy"),
    ("get", "iam:ledger-user"),
    ("describe", "iam"),
    ("watch", "rolebindings"),
    # A grant-shaped verb somewhere that holds no identities.
    ("attach", "ec2:appliance-volume"),
    ("authorize", "ec2:appliance-fleet-ingress"),
    ("add", "support:communication-to-case"),
    # Neither the verb nor the resource qualifies.
    ("teleport", "iam:quokka-policy"),
    ("", "iam:ledger-user"),
    ("create", "pods"),
    # A malformed resource type with no service prefix, and not a binding.
    ("attach", "quokkapolicy"),
    ("delete", ""),
])
def test_what_does_not_change_an_authority(verb, resource_type) -> None:
    """The near-misses, each of which a looser predicate would let through.

    Fails if the verb clause is dropped (every IAM read claims a beneficiary again --
    the 11,388-row defect), if the service clause is dropped (a volume attachment claims
    one), or if an unknown verb or a colon-less resource type is treated as qualifying.
    """
    from ath.control_vocab import changes_authority

    assert not changes_authority(verb, resource_type)


def test_the_predicate_names_no_resource_family() -> None:
    """A family list would be the allowlist defect M18-3 removed, one layer up.

    ``changes_authority`` may read verb classes, IDENTITY_SERVICES and
    RBAC_BINDING_RESOURCES and nothing else. Fails the moment a family token
    ("user-policy", "role-policy", "login-profile", ...) is written into its body.
    """
    from ath import control_vocab

    source = "".join(
        line for line in inspect.getsource(control_vocab).splitlines(keepends=True)
        if not line.lstrip().startswith("#")
    )
    body = source.split("def changes_authority", 1)[1]
    for family in ("user-policy", "role-policy", "group-policy", "login-profile",
                   "access-key", "instance-profile"):
        assert family not in body, f"changes_authority enumerates {family!r}"


# --------------------------------------------------------------------------------------
# is_identity_grant: the rows the source model *guarantees* a beneficiary on (M18-6)
#
# `changes_authority` answers "may this row name an identity", which is the right
# question for *filling* the column and the wrong one for grading it. A policy is not a
# principal: `CreatePolicy` and `DeletePolicy` change an authority and can name nobody,
# and on the attack_data_aws capture all 146 authority-change rows are of exactly that
# kind -- so grading the column over them reported AWS-001 as blind on a corpus that
# contains no evidence either way.
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("verb,resource_type", [
    # A permission moving to a principal, AWS-style: a grant-class verb on the identity
    # service. Two verbs, because a predicate that read only `attach` would pass with
    # the grant *class* dropped.
    ("attach", "iam:quokka-policy"),
    ("add", "iam:ledger-group"),
    ("associate", "iam:ledger-user"),
    ("ATTACH", " IAM:Quokka-Policy "),
    # ...and the same permission moving back off the same principal. M18-7's ruling:
    # `DetachUserPolicy` and `RemoveUserFromGroup` name the beneficiary in exactly the
    # parameters `AttachUserPolicy` and `AddUserToGroup` name it in, so the guarantee is
    # the same guarantee and the denominator is the same denominator. Until M18-7 these
    # two asserted False, which left every revoke on an identity outside the measurement
    # while the adapter went on filling both columns on them.
    ("detach", "iam:quokka-policy"),
    ("remove", "iam:ledger-group"),
    ("revoke", "iam:ledger-user"),
    ("disassociate", "iam:ledger-user"),
    # ...and Kubernetes-style: granting is creating a binding object.
    ("create", "rolebindings"),
    ("create", "clusterrolebindings"),
])
def test_an_identity_grant_guarantees_a_beneficiary(verb, resource_type) -> None:
    """Fails if either clause is dropped: AWS grants or Kubernetes grants stop counting.

    With the verb clause gone the AWS rows leave the denominator and the column is graded
    over bindings alone; with the binding clause gone every Kubernetes grant leaves it,
    and K8S-001 is graded over nothing at all.
    """
    from ath.control_vocab import is_identity_grant

    assert is_identity_grant(verb, resource_type)


@pytest.mark.parametrize("verb,resource_type", [
    # Grant-shaped, but the thing granted is not authority over an identity.
    ("attach", "ec2:appliance-volume"),
    ("authorize", "ec2:appliance-fleet-ingress"),
    # On the identity service, but the subject is a policy object or a report, which
    # names no principal. These are the 146 rows of the attack_data_aws capture.
    ("delete", "iam:quokka-policy"),
    ("create", "iam:quokka-policy"),
    ("generate", "iam:ledger-report"),
    # Creating a credential for yourself names no beneficiary in the record; the adapter
    # supplies the caller by convention, which is a fill rule and not a guarantee.
    ("create", "iam:access-key"),
    # Changes an authority on an identity object without moving a permission between
    # principals: `UpdateLoginProfile` resets a password. Filled when the record names
    # the subject, and outside the denominator -- MODIFY is neither grant nor revoke.
    ("update", "iam:ledger-login-profile"),
    # `put` is a create-class verb in this vocabulary ("creates or replaces the named
    # resource"), so a PutUserPolicy-shaped row is outside the guaranteed set. Stated
    # here rather than left untested: the alternative is a family list, which is the
    # allowlist defect M18-3 removed.
    ("put", "iam:quokka-policy"),
    # Reads, on the identity service and on a binding.
    ("list", "iam:quokka-policy"),
    ("get", "iam"),
    ("watch", "rolebindings"),
    # A binding deleted, not created: `is_grant`'s literal-token clause is about the
    # audit verb Kubernetes logs for a grant.
    ("delete", "rolebindings"),
    ("", ""),
])
def test_what_guarantees_no_beneficiary(verb, resource_type) -> None:
    """The near-misses, each of which a looser denominator would grade a rule on.

    Fails if the denominator widens back to ``changes_authority`` (policy creates,
    deletes and login-profile updates return), to ``is_grant`` (a storage volume
    attachment returns), or to the identity service alone (every IAM read returns).

    The paired positive test above holds the M18-7 half of the boundary: a *revoke* on an
    identity object is inside the denominator, and a create, delete or modify of one is
    not. ``put`` is listed here for the same reason -- it is a create-class verb in this
    vocabulary -- so that "PutUserPolicy is outside" stays a consequence of the verb
    classes rather than of a family list.
    """
    from ath.control_vocab import is_identity_grant

    assert not is_identity_grant(verb, resource_type)


def test_the_guarantee_is_narrower_than_the_fill_condition() -> None:
    """Every guaranteed row may be filled; not every fillable row is guaranteed.

    The two predicates have one job each and the relation between them is the invariant:
    an adapter fills on ``changes_authority`` and a measurement grades on
    ``is_identity_grant``. Fails if the two are ever made the same function again, in
    either direction -- which is how either a rule gets graded on rows that could not
    carry a value, or a real loss stops being filled at all.
    """
    from ath.control_vocab import changes_authority, is_identity_grant

    pairs = _IDENTITY_GRANT_SHAPES + _OTHER_AUTHORITY_CHANGE_SHAPES + (
        ("list", "iam:quokka-policy"), ("attach", "ec2:appliance-volume"),
    )
    for verb, resource_type in pairs:
        if is_identity_grant(verb, resource_type):
            assert changes_authority(verb, resource_type), (verb, resource_type)
    assert any(
        changes_authority(v, r) and not is_identity_grant(v, r)
        for v, r in _OTHER_AUTHORITY_CHANGE_SHAPES
    ), "the fill condition must stay wider than the guarantee"


# --------------------------------------------------------------------------------------
# The applicability denominator that follows from it
# --------------------------------------------------------------------------------------


def _identity_reads(count: int) -> list[dict]:
    """IAM reads that named a user in the raw record and change nothing about it.

    The canonical shape the adapter now produces for ``ListAttachedUserPolicies`` and
    its relatives: the caller is the actor, and the enumerated user appears nowhere.
    """
    return [
        build.ctrl(
            "mriordan", verb, "iam:quokka-policy", f"quokka-policy-{index}",
            device="aws:519204773311/ap-southeast-2", source_ip="198.51.100.203",
            source="cloudtrail_mgmt", when=build.at(seconds=index),
            actor_groups="system:authenticated",
        )
        for index in range(count)
        for verb in [("list", "get", "describe")[index % 3]]
    ]


def _control_rows(shapes: tuple[tuple[str, str], ...], count: int, *,
                  target: str = "wpaulsen", role: str = "cluster-admin",
                  minutes: int = 90) -> list[dict]:
    """``count`` control rows cycling through ``shapes``, each carrying ``target``/``role``.

    One builder for both populations below, so that the only difference between "the rows
    a beneficiary is guaranteed on" and "the rows it is not" is the ``(verb,
    resource_type)`` pairs -- which is exactly the thing under test.
    """
    rows = []
    for index in range(count):
        verb, resource_type = shapes[index % len(shapes)]
        binding = resource_type in ("rolebindings", "clusterrolebindings")
        rows.append(build.ctrl(
            "mriordan", verb, resource_type, f"{resource_type.split(':')[-1]}-{index}",
            target_actor=target, role_ref=role,
            namespace="payments" if binding else "",
            device="k8s:mercury" if binding else "aws:519204773311/ap-southeast-2",
            source_ip="198.51.100.203",
            source="k8s_audit" if binding else "cloudtrail_mgmt",
            when=build.at(minutes=minutes, seconds=index),
            actor_groups="system:authenticated",
        ))
    return rows


# The rows the source model *guarantees* a beneficiary and a conferred role on: a
# permission moving to a principal, expressed the two ways the two platforms express it.
_IDENTITY_GRANT_SHAPES = (
    ("attach", "iam:quokka-policy"),
    ("add", "iam:ledger-group"),
    ("create", "rolebindings"),
    ("create", "clusterrolebindings"),
)

# Rows that change an authority without acting on a principal, or without being a grant.
# Every one of them may carry a beneficiary and is filled when it does; none of them
# guarantees one, and a denominator that includes them grades a rule on rows where there
# was nothing to record.
_OTHER_AUTHORITY_CHANGE_SHAPES = (
    ("delete", "iam:quokka-policy"),
    ("create", "iam:quokka-policy"),
    ("generate", "iam:ledger-report"),
)


def _identity_grants(count: int, **kwargs) -> list[dict]:
    """Grant-shaped rows on the identity service and on both RBAC binding kinds."""
    return _control_rows(_IDENTITY_GRANT_SHAPES, count, **kwargs)


def _authority_changes(count: int, **kwargs) -> list[dict]:
    """Authority changes whose subject is a policy object or a report, not a principal."""
    return _control_rows(_OTHER_AUTHORITY_CHANGE_SHAPES, count, **kwargs)


def test_identity_reads_are_not_in_the_denominator_of_an_authority_field() -> None:
    """1,000 IAM reads + 20 identity grants that carry their target.

    The reads name a user in the raw record and carry nothing in the canonical row, so
    they cannot dilute a column they could never have filled. Fails if applicability
    returns to the whole identity service (the denominator becomes 1,020 and AWS-001
    reads UNUSABLE at 2%), and fails if the RBAC binding clause is dropped (half of these
    rows leave the denominator).
    """
    telemetry = build.telemetry(ctrls=_identity_reads(1_000) + _identity_grants(20))

    aws001 = _rule(telemetry, "AWS-001")
    for column in ("target_actor", "role_ref"):
        field = _field(aws001, column)
        assert field.applicable
        assert field.population.applicable_rows == 20
        assert field.fraction == 1.0
        assert field.population.raw_fraction == pytest.approx(20 / 1020)
        assert column not in aws001.sparse_fields
    assert aws001.verdict is not RuleVerdict.DEGRADED, aws001.detail


def test_identity_grants_with_no_target_are_still_blindness() -> None:
    """The same shape with the target emptied on all 20.

    Applicability narrows the denominator; it must never excuse the numerator. Fails if
    "no populated applicable row" is read as "nothing to measure".
    """
    changes = [dict(row, target_actor="") for row in _identity_grants(20)]
    telemetry = build.telemetry(ctrls=_identity_reads(1_000) + changes)

    aws001 = _rule(telemetry, "AWS-001")
    assert aws001.verdict is RuleVerdict.UNUSABLE
    assert "target_actor" in aws001.unpopulated_fields
    assert "target_actor" in aws001.detail
    assert _field(aws001, "target_actor").population.applicable_rows == 20


def test_a_volume_attachment_is_grant_shaped_and_names_no_identity() -> None:
    """40 ``attach ec2:volume`` rows + 5 IAM authority changes: the denominator is 5.

    This is the half of the flaws.cloud AWS-001 reading that was measurement error --
    42 of its 132 grant-shaped rows attach a storage volume to an instance. Fails if the
    identity clause is dropped from the denominator: 5 of 45 is 11%, under
    DEGRADED_BELOW, and AWS-001 reads DEGRADED on a corpus where every grant in it names
    its subject.
    """
    volumes = [
        build.ctrl(
            "mriordan", "attach", "ec2:appliance-volume", f"vol-{index:04x}",
            device="aws:519204773311/ap-southeast-2", source_ip="198.51.100.203",
            source="cloudtrail_mgmt", when=build.at(minutes=10, seconds=index),
        )
        for index in range(40)
    ]
    telemetry = build.telemetry(ctrls=volumes + _identity_grants(5))

    aws001 = _rule(telemetry, "AWS-001")
    for column in ("target_actor", "role_ref"):
        field = _field(aws001, column)
        assert field.population.applicable_rows == 5
        assert field.fraction == 1.0
        assert field.population.raw_fraction == pytest.approx(5 / 45)
    assert not aws001.sparse_fields
    assert not aws001.unpopulated_fields


def _attack_capture_shape() -> list[dict]:
    """The attack_data_aws control table in miniature: authority changes, no principals.

    116 policy deletes, 10 policy creates and 20 credential-report generates are that
    capture's entire authority-change population (146 rows), and not one of them names a
    beneficiary -- a policy object has no principal, and a credential report is about the
    account. Scaled down here to 100/10/3 and stripped of both columns, which is what the
    adapter produces from those records.
    """
    return (
        _control_rows((("delete", "iam:quokka-policy"),), 100, target="", role="")
        + _control_rows((("create", "iam:quokka-policy"),), 10, target="", role="",
                        minutes=120)
        + _control_rows((("generate", "iam:ledger-report"),), 3, target="", role="",
                        minutes=150)
    )


def test_a_capture_of_policy_changes_says_nothing_about_beneficiaries() -> None:
    """113 authority changes whose subject is a policy or a report: nobody is blind.

    This is the attack_data_aws reading M18-5 produced and M18-6 corrects: every row
    changes an authority, so every row was in the denominator, none of them could name a
    principal, and AWS-001 was reported UNUSABLE on a corpus that contains no grant at
    all. The honest reading is that the question does not arise here -- and the rows are
    not thereby hidden: the adapter counts them as an informational gap, which the
    adapter-side test asserts.

    Fails if the denominator widens back to ``changes_authority`` (UNUSABLE, naming
    target_actor), and fails if a zero-applicable field were silently dropped from the
    report rather than named as not applicable.
    """
    telemetry = build.telemetry(ctrls=_attack_capture_shape())

    aws001 = _rule(telemetry, "AWS-001")
    assert aws001.verdict is RuleVerdict.USABLE, aws001.detail
    assert set(aws001.not_applicable_fields) == {"target_actor", "role_ref"}
    assert not aws001.unpopulated_fields
    assert "not applicable in this data" in aws001.detail
    for column in ("target_actor", "role_ref"):
        field = _field(aws001, column)
        assert field.applicable is False
        assert field.population.applicable_rows == 0
        assert field.population.rows == 113
        assert "identity grant" in field.population.applicability_reason


def test_one_grant_in_the_same_capture_creates_the_denominator() -> None:
    """The same 113 rows plus 5 identity grants that carry their beneficiary.

    The capture stops being silent the moment it contains a row the model guarantees an
    answer on, and the denominator is those 5 rows and nothing else -- not the 118. Fails
    if the policy changes are counted in (5 of 118 is 4.2%, under DEGRADED_BELOW, and
    AWS-001 reads DEGRADED while every grant in the data names its subject).
    """
    telemetry = build.telemetry(ctrls=_attack_capture_shape() + _identity_grants(5))

    aws001 = _rule(telemetry, "AWS-001")
    assert aws001.verdict is RuleVerdict.USABLE, aws001.detail
    for column in ("target_actor", "role_ref"):
        field = _field(aws001, column)
        assert field.applicable
        assert field.population.applicable_rows == 5
        assert field.fraction == 1.0
        assert field.population.raw_fraction == pytest.approx(5 / 118)


def test_the_same_grants_without_a_beneficiary_are_blindness() -> None:
    """The same 118 rows with the 5 grants' beneficiary emptied.

    The paired test for the one above, and the reason the denominator can be narrowed at
    all: narrowing may never excuse an empty numerator. Fails if a denominator of 5 with
    0 populated were read as "nothing to measure".
    """
    grants = [dict(row, target_actor="") for row in _identity_grants(5)]
    telemetry = build.telemetry(ctrls=_attack_capture_shape() + grants)

    aws001 = _rule(telemetry, "AWS-001")
    assert aws001.verdict is RuleVerdict.UNUSABLE
    assert "target_actor" in aws001.unpopulated_fields
    assert "target_actor" in aws001.detail
    field = _field(aws001, "target_actor")
    assert field.population.applicable_rows == 5
    assert field.fraction == 0.0


def test_is_grant_reads_the_verb_class_and_the_binding_resource_and_nothing_else() -> None:
    """Both clauses, and the near-misses that must not match.

    Fails if the resource clause is dropped (Kubernetes grants stop counting), if the
    verb clause is dropped (AWS grants stop counting), or if ``create`` is treated as a
    grant on any resource at all (every pod creation would become a grant and the
    denominator would swell back towards the whole table).
    """
    from ath.behavior.control_plane import is_grant

    assert is_grant("attach", "iam:user-policy")
    assert is_grant("add", "iam:group")
    assert is_grant("create", "clusterrolebindings")
    assert is_grant("CREATE", " RoleBindings ")

    assert not is_grant("create", "pods")
    assert not is_grant("create", "iam:access-key")
    assert not is_grant("describe", "rolebindings")
    assert not is_grant("delete", "clusterrolebindings")


def test_population_measurement_reports_both_fractions_for_every_column() -> None:
    """The raw fraction never disappears; it is reported beside the applicable one.

    Fails if a future change makes the applicable fraction replace the whole-table one,
    which would leave no way to ask the ingestion question ("how much of this table
    carries the column") at all.
    """
    telemetry = build.telemetry(ctrls=_reads(100) + _grants(4))
    populations = measure_field_populations(telemetry)

    unconditional = populations[("control", "verb")].to_dict()
    assert unconditional["fraction"] == unconditional["raw_fraction"] == 1.0
    assert unconditional["applicable_rows"] == 104

    conditional = populations[("control", "role_ref")].to_dict()
    assert conditional["applicable_rows"] == 4
    assert conditional["fraction"] == 1.0
    assert conditional["raw_fraction"] == pytest.approx(4 / 104, abs=1e-8)
