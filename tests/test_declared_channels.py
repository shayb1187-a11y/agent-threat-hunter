"""The architectural invariant M18-9 added: a rule's declarations are true of its findings.

What is being protected
-----------------------
``ath.environment.coverage`` tells an operator things like *"AWS-006 is UNUSABLE on this
dataset: the channel it declares is absent."* That sentence is the product -- it is how
this project distinguishes "nothing happened" from "we could not have seen it" -- and it
is only worth printing if the rule cannot then produce a finding anyway. In M18-8 it did:
the pre-registration predicted zero findings on the Kubernetes CI corpus, AWS-006
produced one, and it did so by citing ``k8s_audit`` rows while declaring
``CLOUD_MANAGEMENT_ACTIVITY``. The finding was true; the declaration was not.

So the invariant is: **every evidence row a finding cites belongs to a channel the rule
declares.** The tests below each fail on their own:

* :func:`test_no_registered_rule_cites_a_row_outside_its_declared_channels` runs every
  registered rule on a table holding both platforms' shapes. Against
  ``cloud_behaviour_rules.py`` as it stood at 58b513d this fails with seven violations
  (six AWS-006, one AWS-005); at HEAD the same run is clean.
* the ``channel_of_control_row`` tests fix the mapping's three answers, and
  :func:`test_channel_of_control_row_is_derived_from_the_catalogue` proves the mapping is
  *read from* ``CHANNEL_SPECS`` rather than duplicated beside it, by asking the function
  the same question against an altered copy of the catalogue and requiring a different
  answer.
* :func:`test_every_control_evidence_column_is_a_source_form` guards the assumption
  ``channel_of_control_row`` rests on -- that control rows are separated by provenance --
  so a future catalogue entry that separates them some other way fails here rather than
  being silently unseen by a function whose signature takes only a source.

What this table deliberately does not contain
----------------------------------------------
A Kubernetes authorization-denial burst. AWS-004's predicate is ``decision == "denied"``
with no platform scope, and the Kubernetes adapter does emit ``denied`` (401/403), so
twenty-five refused Kubernetes calls in a window would make AWS-004 cite
``container_audit`` rows while declaring ``cloud_management_activity`` -- the same defect
AWS-006 had, in a rule M18-9 was not scoped to change. That exposure is *recorded, not
fixed*, in ``docs/m18-representation-and-cloud-detection-report.md``. It is written down
here rather than left to be discovered, because a test whose fixture avoids a known
failure without saying so is worse than no test.

Vocabulary is invented (``bandicoot``-numbered services, marsupial identities) for the
reason ``tests/test_cloud_behaviour_rules.py`` gives at length: fixtures that borrow the
corpus a rule was measured against cannot distinguish a rule from a memory. The real
tokens used here are the ones the *predicates are defined by* -- the ``iam:`` identity
prefix, the RBAC binding resource names, ``pods/exec``, ``cluster-admin`` and the logging
service -- because substituting those would exercise different predicates.
"""

from __future__ import annotations

import dataclasses

import pytest

from ath.channels import TelemetryChannel
from ath.environment.channels import (
    CHANNEL_SPECS,
    channel_of_control_row,
    channels_of_row,
)
from ath.environment.coverage import findings_respect_declared_channels
from ath.hunting import HuntConfig, run_hunt
from ath.hunting.base import all_detectors
from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_PROCESS

from _builders import at, ctrl, telemetry

CLOUD_SOURCE = "cloudtrail_mgmt"
K8S_SOURCE = "k8s_audit"

AWS_DEVICE = "aws:519204773311/ap-southeast-2"
K8S_DEVICE = "k8s:c1"

SERVICES = tuple(f"bandicoot{index}" for index in range(20))

CLOUD_ADMIN = "dunnart_admin"
CLOUD_SCANNER = "pademelon_probe"
CLOUD_SCRIPT = "kowari_script"
K8S_ADMIN = "bettong_admin"
K8S_SUBJECT = "antechinus_agent"
K8S_AUTOMATION = "planigale_manager"


# ======================================================================================
# channel_of_control_row -- the mapping, and the proof it is derived
# ======================================================================================


@pytest.mark.parametrize(("source", "expected"), [
    (CLOUD_SOURCE, TelemetryChannel.CLOUD_MANAGEMENT_ACTIVITY),
    (K8S_SOURCE, TelemetryChannel.CONTAINER_AUDIT),
    ("some_adapter_nobody_wrote", None),
    ("", None),
])
def test_channel_of_control_row(source: str, expected: TelemetryChannel | None) -> None:
    """The three answers this function has.

    Failure mode: a control row's channel is decided somewhere by a hand-written source
    table, that table gains an adapter the catalogue does not know about (or loses one it
    does), and the coverage model and the detections disagree about what a row is.
    """
    assert channel_of_control_row(source) is expected


def test_channel_of_control_row_is_derived_from_the_catalogue() -> None:
    """Change the catalogue's source token and the answer changes with it.

    This is the test a second source table cannot survive: a hard-coded
    ``{"cloudtrail_mgmt": CLOUD_MANAGEMENT_ACTIVITY}`` would answer the parametrised
    cases above correctly, and would keep answering them here -- where the catalogue no
    longer says so.

    Failure mode: the function stops reading ``CHANNEL_SPECS`` and starts restating it.
    """
    renamed = tuple(
        dataclasses.replace(
            spec,
            evidence_columns=((EVENT_CONTROL, "source:a_renamed_cloud_source"),),
        )
        if spec.channel is TelemetryChannel.CLOUD_MANAGEMENT_ACTIVITY else spec
        for spec in CHANNEL_SPECS
    )

    assert channel_of_control_row(CLOUD_SOURCE, specs=renamed) is None
    assert (
        channel_of_control_row("a_renamed_cloud_source", specs=renamed)
        is TelemetryChannel.CLOUD_MANAGEMENT_ACTIVITY
    )
    # ...and the real catalogue is untouched by having been copied.
    assert (
        channel_of_control_row(CLOUD_SOURCE)
        is TelemetryChannel.CLOUD_MANAGEMENT_ACTIVITY
    )


def test_every_control_evidence_column_is_a_source_form() -> None:
    """Control rows are separated by provenance, and nothing else, in the catalogue.

    Failure mode: a channel is later evidenced by a control *column* rather than by a
    source value, ``channel_of_control_row`` silently stops being the whole answer for
    control rows, and a row's channel becomes ambiguous without anyone noticing.
    """
    control_columns = [
        column
        for spec in CHANNEL_SPECS
        for event_type, column in spec.evidence_columns
        if event_type == EVENT_CONTROL
    ]
    assert control_columns, "no channel claims the control table at all"
    assert all(c.startswith("source:") for c in control_columns), control_columns


def test_channel_of_control_row_agrees_with_channels_of_row() -> None:
    """One definition, asked two ways, on every source the catalogue names.

    Failure mode: the general row function and the control-row shorthand drift, so a
    checker using one and a script using the other disagree about the same row.
    """
    sources = [
        column.split(":", 1)[1]
        for spec in CHANNEL_SPECS
        for event_type, column in spec.evidence_columns
        if event_type == EVENT_CONTROL
    ]
    for source in [*sources, "unknown_source"]:
        expected = channels_of_row(EVENT_CONTROL, {"source": source})
        got = channel_of_control_row(source)
        assert (frozenset() if got is None else frozenset({got})) == expected


def test_channels_of_row_is_a_set_because_one_row_can_evidence_several() -> None:
    """A CloudTrail console logon is authentication *and* cloud control plane at once.

    Failure mode: the row view collapses to one channel per row, and a rule that
    legitimately declares the authentication channel is reported as citing evidence
    outside its declaration on every cloud logon.
    """
    row = {
        "action": "success", "source_ip": "198.51.100.7", "source_device": "",
        "source": "cloudtrail",
    }
    assert channels_of_row(EVENT_LOGON, row) == frozenset({
        TelemetryChannel.AUTHENTICATION,
        TelemetryChannel.AUTH_SOURCE_ATTRIBUTION,
        TelemetryChannel.CLOUD_CONTROL_PLANE,
    })
    # A row carrying nothing evidences nothing -- a real answer, not an error.
    assert channels_of_row(EVENT_PROCESS, {"process_name": ""}) == frozenset()


# ======================================================================================
# The mixed table, and the invariant over every registered rule
# ======================================================================================


def _cloud(actor: str, verb: str, resource_type: str, name: str, minute: float,
           *, decision: str = "allowed", target: str = "", role: str = "") -> dict:
    return ctrl(
        actor, verb, resource_type, name, target_actor=target, role_ref=role,
        decision=decision, device=AWS_DEVICE, source=CLOUD_SOURCE, when=at(minute),
    )


def _k8s(actor: str, verb: str, resource_type: str, name: str, minute: float,
         *, decision: str = "allowed", target: str = "", role: str = "") -> dict:
    return ctrl(
        actor, verb, resource_type, name, target_actor=target, role_ref=role,
        decision=decision, device=K8S_DEVICE, source=K8S_SOURCE, when=at(minute),
        namespace="marsupial-ns",
    )


def mixed_control_rows() -> list[dict]:
    """Both platforms in one control table, with authority changes present in both.

    The shape of a real EKS-style deployment: a CloudTrail management trail and a
    Kubernetes API audit log landing in the same canonical table, distinguished only by
    ``source``. Every registered control-plane rule has something here to find.
    """
    rows: list[dict] = []

    # -- Kubernetes: authority changes, the half that used to leak into AWS- rules.
    # A binding the apiserver refused with a conflict, six times: AWS-006's exact shape
    # (>= 5 rejected identity-authority writes in a window) on the wrong platform.
    rows += [
        _k8s(K8S_AUTOMATION, "create", "clusterrolebindings", "marsupial-dns-binding",
             0.5 + index * 0.5, decision="failed", target=K8S_SUBJECT, role="view")
        for index in range(6)
    ]
    # A binding removed, and performed: AWS-005's exact shape, likewise.
    rows.append(_k8s(K8S_AUTOMATION, "delete", "rolebindings", "marsupial-old-binding",
                     5.0, target=K8S_SUBJECT, role="view"))
    # K8S-001 then K8S-002: a privileged grant, then the beneficiary opening a shell.
    rows.append(_k8s(K8S_ADMIN, "create", "clusterrolebindings", "marsupial-escalation",
                     6.0, target=K8S_SUBJECT, role="cluster-admin"))
    rows.append(_k8s(K8S_SUBJECT, "exec", "pods/exec", "marsupial-pod-7", 7.0))

    # -- CloudTrail: the same two authority shapes, on the identity service.
    rows += [
        _cloud(CLOUD_SCRIPT, "put", "iam:bandicoot-policy", f"bandicoot-policy-{index}",
               20.5 + index * 0.5, decision="failed")
        for index in range(6)
    ]
    rows.append(_cloud(CLOUD_ADMIN, "delete", "iam:bandicoot-policy",
                       "bandicoot-policy-old", 25.0, target=CLOUD_SCRIPT))

    # -- AWS-001: a policy granted to an identity, which then mints a key for itself.
    rows.append(_cloud(CLOUD_ADMIN, "attach", "iam:user-policy", "bandicoot-power",
                       30.0, target=CLOUD_SCANNER, role="bandicoot-power"))
    rows.append(_cloud(CLOUD_SCANNER, "create", "iam:access-key", "AKIABANDICOOT0001",
                       30.5, target=CLOUD_SCANNER))
    # -- AWS-002: the audit trail switched off.
    rows.append(_cloud(CLOUD_SCANNER, "stop", "cloudtrail:trail", "bandicoot-trail",
                       31.0))
    # -- AWS-003: breadth of reads across many distinct services.
    rows += [
        _cloud(CLOUD_SCANNER, "describe", f"{service}:ledger-fleet", f"ledger-{service}",
               32.0 + index * 0.1)
        for index, service in enumerate(SERVICES)
    ]
    # -- AWS-004: a run of authorization refusals.
    rows += [
        _cloud(CLOUD_SCANNER, "describe", f"bandicoot0:family-{index % 7}",
               f"family-{index % 7}-01", 40.0 + index * 0.1, decision="denied")
        for index in range(30)
    ]
    return rows


def test_mixed_table_exercises_both_platforms_and_every_control_rule() -> None:
    """The invariant test below is only worth running on a table that makes rules fire.

    Failure mode: a fixture edit quietly stops some rule from firing, the violation check
    passes over nothing, and the invariant is asserted about an empty set.
    """
    rows = mixed_control_rows()
    found = run_hunt(telemetry(ctrls=rows), config=HuntConfig()).findings
    fired = {f.rule_id for f in found}
    assert {"AWS-001", "AWS-002", "AWS-003", "AWS-004", "AWS-005", "AWS-006",
            "K8S-001", "K8S-002"} <= fired, sorted(fired)

    cited = {e.event_id for f in found for e in f.evidence}
    by_id = {row["event_id"]: row for row in rows}
    # Both platforms' rows are actually cited by something, so "no violations" is not
    # "one platform was never looked at".
    sources = {by_id[e]["source"] for e in cited if e in by_id}
    assert sources == {CLOUD_SOURCE, K8S_SOURCE}, sources


def test_no_registered_rule_cites_a_row_outside_its_declared_channels() -> None:
    """The invariant, over every registered rule, on a table holding both platforms.

    Failure mode, and the one that was real: a rule's predicate is wider than its
    ``channels`` declaration, so the coverage model reports it unusable on a dataset
    Failure demonstrated, not asserted in prose: restoring
    ``src/ath/hunting/rules/cloud_behaviour_rules.py`` to 58b513d and running this test
    produces seven violations -- six from AWS-006 (the rejected ClusterRoleBinding
    creates below) and one from AWS-005 (the deleted RoleBinding) -- every one of them a
    ``container_audit`` row cited by a rule declaring ``cloud_management_activity``. The
    same check on the real k8s_ci corpus at 58b513d produces twenty, from AWS-006's one
    finding there.
    """
    mixed = telemetry(ctrls=mixed_control_rows())
    findings = run_hunt(mixed, config=HuntConfig()).findings
    assert findings, "no findings, so the invariant would be vacuous"

    violations = findings_respect_declared_channels(findings, mixed, all_detectors())
    assert not violations, "\n".join(str(v) for v in violations)


def test_the_violation_checker_can_fail() -> None:
    """The checker reports a violation when one is constructed, not merely never.

    A clean run proves nothing unless the check has teeth. Here AWS-006's finding is
    re-declared as depending on a channel its rows do not evidence, which is the same
    disagreement the P13 defect was, arrived at from the other side.

    Failure mode: the checker silently returns ``[]`` for everything -- a bug that would
    make every other assertion in this module vacuous.
    """
    mixed = telemetry(ctrls=mixed_control_rows())
    findings = run_hunt(mixed, config=HuntConfig()).findings
    aws006 = [f for f in findings if f.rule_id == "AWS-006"]
    assert aws006

    class _Misdeclared:
        rule_id = "AWS-006"
        channels = frozenset({TelemetryChannel.CONTAINER_AUDIT})
        fields_used = ()

    others = [d for d in all_detectors() if d.rule_id != "AWS-006"]
    violations = findings_respect_declared_channels(
        aws006, mixed, [*others, _Misdeclared()],
    )
    assert violations
    assert {v.reason for v in violations} == {"row is outside the declared channels"}
    assert all(
        v.observed == (TelemetryChannel.CLOUD_MANAGEMENT_ACTIVITY,) for v in violations
    )


def test_a_cited_row_that_is_not_in_the_telemetry_is_a_violation() -> None:
    """The claim layer guarantees this cannot happen; the check does not assume it.

    Failure mode: the row index silently misses a table, every finding from it is
    reported clean, and the invariant is enforced over nothing.
    """
    mixed = telemetry(ctrls=mixed_control_rows())
    findings = run_hunt(mixed, config=HuntConfig()).findings
    empty = telemetry(ctrls=[])
    violations = findings_respect_declared_channels(findings, empty, all_detectors())
    assert violations
    assert {v.reason for v in violations} == {"cited row is not in the telemetry"}
