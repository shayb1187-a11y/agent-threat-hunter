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

import inspect

import pytest

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

from tests import _builders as build


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


def test_a_failure_reason_missing_from_the_failures_still_degrades() -> None:
    """The same shape with every failure's reason empty.

    ATH-005 declares failure_reason optional (it phrases evidence, it does not gate a
    finding), so the verdict is DEGRADED and not UNUSABLE -- stated here rather than
    left to the reader, because "the rule still fires" and "the rule sees nothing" are
    the two answers this whole module exists to keep apart.

    Fails if applicability is allowed to hide a genuine loss.
    """
    telemetry = build.telemetry(logons=_successes(1_000) + _failures(50, reason=""))

    ath005 = _rule(telemetry, "ATH-005")
    field = _field(ath005, "failure_reason")
    assert field.applicable and field.population.applicable_rows == 50
    assert field.fraction == 0.0
    assert not field.required, "ATH-005 reads failure_reason for phrasing only"
    assert ath005.verdict is RuleVerdict.DEGRADED
    assert "failure_reason" in ath005.sparse_fields
    assert "failure_reason" not in ath005.unpopulated_fields


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


def test_the_behavior_binding_resources_match_the_kubernetes_adapter() -> None:
    """Two declarations of one fact, held equal by test because the import is illegal.

    ``ath.telemetry`` may not import ``ath.behavior``, so the adapter's ``_RBAC_RESOURCES``
    and ``control_plane.RBAC_BINDING_RESOURCES`` are separate objects. Fails the moment
    one gains a resource the other does not -- which would make a binding kind either
    invisible to the grant predicate or invisible to the adapter.
    """
    from ath.behavior.control_plane import RBAC_BINDING_RESOURCES
    from ath.telemetry.k8s_audit_source import _RBAC_RESOURCES

    assert RBAC_BINDING_RESOURCES == _RBAC_RESOURCES


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
