"""Detections over AWS cloud control-plane activity (``ath.schema.EVENT_CONTROL``).

Both rules here read only ``telemetry.controls`` -- populated by
:mod:`ath.telemetry.cloudtrail_source` from AWS management-API events -- and never
touch process, network or logon telemetry. Neither rule keys on a raw column name that
could equally mean something else on Kubernetes' side of the same table (see
``Detector.channels`` in ``ath.hunting.base`` for why that distinction has to be made
explicitly rather than inferred).
"""

from __future__ import annotations

import pandas as pd

from ath.channels import TelemetryChannel
from ath.hunting.base import Detector, register
from ath.hunting.finding import Evidence, Finding, Severity
from ath.telemetry.loader import Telemetry

# The IAM shapes AWS-001 chains together -- policy grants, and access-key creation.
_GRANT_RESOURCE_TYPES: frozenset[str] = frozenset({"iam:user-policy", "iam:user-inline-policy"})
_ACCESS_KEY_RESOURCE_TYPE = "iam:access-key"
_LOGGING_RESOURCE_TYPE = "cloudtrail:trail"
_PAST_TENSE: dict[str, str] = {"stop": "stopped", "delete": "deleted"}


@register
class IamPrivilegeEscalationChain(Detector):
    """AWS-001 -- A policy grant followed by the beneficiary creating an access key.

    Attacker behaviour
    ------------------
    ``AttachUserPolicy``/``PutUserPolicy`` on its own is not remarkable -- IAM changes
    happen constantly in a working AWS account. What makes it worth an alert is the
    combination: policy granted to identity X, then X immediately mints a long-lived
    credential for itself. That is the shape of "escalate, then persist" -- a stolen
    session token or a compromised low-privilege user attaching an administrator
    policy to themselves and then creating an access key so the access survives the
    original session expiring.

    Detection shape
    ---------------
    1. Find ``AttachUserPolicy``/``PutUserPolicy`` events (``target_actor`` is the
       identity the policy was granted to -- *not* the caller who granted it; see the
       module docstring in ``ath.telemetry.cloudtrail_source`` for why those two are
       tracked separately).
    2. Find a ``CreateAccessKey`` event whose **actor** matches that grant's
       ``target_actor``, within ``HuntConfig.privilege_escalation_window``.
    3. The grantor and the beneficiary can be, and often are, different identities --
       an administrator legitimately attaching a policy to a new hire is the same
       shape as an attacker attaching one to themselves. This rule cannot tell those
       apart from IAM events alone; it surfaces the chain, not a verdict.

    Known false positives
    ----------------------
    Routine onboarding: an administrator grants a new engineer permissions and the
    engineer (or an automated provisioning script acting on their behalf) creates
    their first access key shortly after, as part of normal setup.
    """

    rule_id = "AWS-001"
    title = "IAM policy grant followed by access-key creation for the same identity"
    severity = Severity.HIGH
    description = (
        "Detects a policy attached to an identity, followed shortly by that same "
        "identity creating an access key -- consistent with escalate-then-persist."
    )
    fields_used = (
        "actor", "verb", "resource_type", "target_actor", "role_ref", "timestamp",
    )
    channels = frozenset({TelemetryChannel.CLOUD_MANAGEMENT_ACTIVITY})
    false_positives = (
        "Routine onboarding: an administrator grants a new identity permissions, and "
        "that identity (or a provisioning script) creates its first access key "
        "shortly after as part of normal setup.",
        "Infrastructure-as-code pipelines that both attach policies and rotate access "
        "keys as part of a single automated run.",
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        controls = telemetry.controls
        if controls.empty:
            return []

        grants = controls[
            (controls["verb"] == "attach")
            & (controls["resource_type"].isin(_GRANT_RESOURCE_TYPES))
            & (controls["target_actor"].fillna("") != "")
        ].sort_values("timestamp")
        creates = controls[
            (controls["verb"] == "create")
            & (controls["resource_type"] == _ACCESS_KEY_RESOURCE_TYPE)
        ]
        if grants.empty or creates.empty:
            return []

        window = self.config.privilege_escalation_window
        findings: list[Finding] = []

        for _, grant in grants.iterrows():
            target = grant["target_actor"]
            matches = creates[
                (creates["actor"] == target)
                & (creates["timestamp"] >= grant["timestamp"])
                & (creates["timestamp"] <= grant["timestamp"] + window)
            ].sort_values("timestamp")
            if matches.empty:
                continue

            create = matches.iloc[0]
            evidence = (
                Evidence(
                    event_id=grant["event_id"], timestamp=grant["timestamp"],
                    summary=(
                        f"{grant['actor']} attached {grant['role_ref'] or grant['resource_type']} "
                        f"to {target}"
                    ),
                ),
                Evidence(
                    event_id=create["event_id"], timestamp=create["timestamp"],
                    summary=f"{target} created an access key",
                ),
            )
            delta = int((create["timestamp"] - grant["timestamp"]).total_seconds())

            findings.append(self.make_finding(
                device=create["device"],
                user=target,
                evidence=evidence,
                reason=(
                    f"'{grant['actor']}' attached policy "
                    f"'{grant['role_ref'] or grant['resource_type']}' to '{target}', who "
                    f"created an access key {delta}s later. Escalation granted and "
                    "immediately used to mint a persistent credential is consistent "
                    "with 'escalate, then persist' -- though the grantor and "
                    "beneficiary may simply be an administrator onboarding a new "
                    "identity, which produces the same shape."
                ),
                metadata={
                    "actor": grant["actor"],
                    "target_actor": target,
                    "role_ref": grant["role_ref"],
                    "grant_resource_type": grant["resource_type"],
                    "seconds_between_grant_and_use": delta,
                },
            ))
        return findings


@register
class CloudTrailLoggingDisabled(Detector):
    """AWS-002 -- CloudTrail logging was stopped or the trail deleted.

    Attacker behaviour
    ------------------
    ``StopLogging``/``DeleteTrail`` is a small, high-signal action set: turning off
    the audit trail is not something automation does as part of ordinary operation,
    and it is a step an intruder takes specifically to operate without a record. This
    is a single-event, structural detection -- no history or baseline needed, the same
    directness as ATH-004 reading a command line.

    Detection shape
    ---------------
    Any ``stop``/``delete`` verb against a ``cloudtrail:trail`` resource is CRITICAL:
    there is no ordinary-operations reading of this action that isn't itself a
    significant change-management event.
    """

    rule_id = "AWS-002"
    title = "CloudTrail logging disabled or trail deleted"
    severity = Severity.CRITICAL
    description = "Detects StopLogging/DeleteTrail -- an audit trail being turned off."
    fields_used = ("actor", "verb", "resource_type", "resource_name", "timestamp")
    channels = frozenset({TelemetryChannel.CLOUD_MANAGEMENT_ACTIVITY})
    false_positives = (
        "A deliberate, change-managed decommissioning of a trail being replaced by "
        "another (e.g. during an account-wide logging migration).",
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        controls = telemetry.controls
        if controls.empty:
            return []

        tampering = controls[
            (controls["resource_type"] == _LOGGING_RESOURCE_TYPE)
            & (controls["verb"].isin({"stop", "delete"}))
        ]
        if tampering.empty:
            return []

        findings: list[Finding] = []
        for _, row in tampering.iterrows():
            findings.append(self.make_finding(
                device=row["device"],
                user=row["actor"],
                evidence=(Evidence(
                    event_id=row["event_id"], timestamp=row["timestamp"],
                    summary=f"{row['actor']} {row['verb']} trail {row['resource_name']}",
                ),),
                reason=(
                    f"'{row['actor']}' {_PAST_TENSE.get(row['verb'], row['verb'])} "
                    f"CloudTrail trail '{row['resource_name']}'. Disabling the audit "
                    "trail is not a routine operational action and is consistent with "
                    "an intruder removing the record of subsequent activity."
                ),
                metadata={"actor": row["actor"], "verb": row["verb"]},
            ))
        return findings
