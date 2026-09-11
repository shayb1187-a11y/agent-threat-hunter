"""Detections over Kubernetes control-plane activity (``ath.schema.EVENT_CONTROL``).

Both rules here read only ``telemetry.controls`` -- populated by
:mod:`ath.telemetry.k8s_audit_source` from Kubernetes audit events -- and never touch
process, network or logon telemetry. Structural and single-window, not baseline-
dependent: matching on *what a grant names* (a role, a beneficiary) rather than on
whether an actor's behaviour looks unusual against a short observation window, which
this project's own README flags as a weak signal to build detection on.
"""

from __future__ import annotations

from ath.channels import TelemetryChannel
from ath.hunting.base import Detector, register
from ath.hunting.finding import Evidence, Finding, Severity
from ath.telemetry.loader import Telemetry

_RBAC_RESOURCE_TYPES: frozenset[str] = frozenset({"rolebindings", "clusterrolebindings"})
_EXEC_RESOURCE_TYPE = "pods/exec"

# Cluster roles whose name alone establishes maximal or near-maximal privilege. This is
# a real, stated limitation: a *custom* role named something innocuous can carry
# wildcard rules and would not be caught by a name check. Seeing that would need the
# Role/ClusterRole object's own rule set, which a binding-creation audit event does not
# carry -- the audit log records that a role was bound, not what the role grants.
HIGH_PRIVILEGE_ROLE_NAMES: frozenset[str] = frozenset({"cluster-admin", "admin"})

# Identities the API server allows everything *before* RBAC is consulted. The
# ``system:masters`` group is wired into the apiserver's authorizer chain, not into any
# binding, which has two consequences this module relies on:
#
# * a binding *to* it grants nothing. The apiserver itself creates exactly this one at
#   every start (``cluster-admin -> system:masters``, labelled
#   ``kubernetes.io/bootstrapping=rbac-defaults``); it is a documented no-op.
# * a binding created *by* a member escalates no one relative to the grantor, who could
#   already do everything the grantee now can. That is administration -- a break-glass
#   credential, bootstrap tooling, an e2e harness -- not the compromised low-privilege
#   credential K8S-001 describes.
#
# Ordinary administrators are *not* in this group: a kubeadm ``kubernetes-admin`` holds
# cluster-admin through a binding (``kubeadm:cluster-admins``), a CI deployer through
# whatever it was given, and their grants still fire. This is the feature that separated
# every one of the 55 K8S-001 findings on a real CI apiserver (grantors ``kubecfg`` and
# ``system:apiserver``, both ``system:masters``) from the modelled escalation (a service
# account in ``system:serviceaccounts`` only), and it is read from the audit record
# rather than inferred from how often the grant happens.
SUPERUSER_GROUPS: frozenset[str] = frozenset({"system:masters"})


def _names(joined: object) -> set[str]:
    """Split a comma-joined identity list (``target_actor``, ``actor_groups``)."""
    return {part for part in str(joined or "").split(",") if part}


def _privilege_grants(controls):
    """RBAC bindings that name a high-privilege role and confer it on someone.

    Shared by both rules below. A binding whose every subject is already a superuser
    (the apiserver's own bootstrap ``cluster-admin -> system:masters``) confers
    nothing and is excluded here; a binding that names a superuser group *and* another
    subject still grants that other subject and is kept.
    """
    candidates = controls[
        (controls["verb"] == "create")
        & (controls["resource_type"].isin(_RBAC_RESOURCE_TYPES))
        & (controls["role_ref"].isin(HIGH_PRIVILEGE_ROLE_NAMES))
        & (controls["target_actor"].fillna("") != "")
    ]
    confers = candidates["target_actor"].map(
        lambda t: bool(_names(t) - SUPERUSER_GROUPS)
    ).astype(bool)  # an empty map() is object-typed and would select columns, not rows
    return candidates[confers].sort_values("timestamp")


def _grantor_is_superuser(grant) -> bool:
    return bool(_names(grant.get("actor_groups", "")) & SUPERUSER_GROUPS)


@register
class RbacPrivilegeEscalationGrant(Detector):
    """K8S-001 -- A RoleBinding/ClusterRoleBinding grants a maximally-privileged role.

    Attacker behaviour
    ------------------
    Binding ``cluster-admin`` (or the namespace-scoped ``admin`` ClusterRole) to an
    identity is one of the highest-signal single events available in Kubernetes RBAC:
    almost no legitimate workload needs cluster-admin, and a compromised low-privilege
    credential with just enough RBAC-write access granting itself (or a controlled
    service account) that role is a textbook escalation. Single-event, high-signal, no
    history needed -- the same directness as ATH-004 reading a command line.

    Detection shape
    ---------------
    Any ``create`` on ``rolebindings``/``clusterrolebindings`` whose ``role_ref``
    matches :data:`HIGH_PRIVILEGE_ROLE_NAMES`, **unless the grantor is already a
    superuser** (:data:`SUPERUSER_GROUPS`, read from the audit record's asserted
    groups). An escalation is a grantor conferring standing it did not itself have;
    a ``system:masters`` member conferring cluster-admin is administration, and on a
    real CI apiserver it was every one of 55 findings in 38 minutes (2,070/day, M14).
    A binding to ``system:masters`` itself confers nothing and is excluded in
    :func:`_privilege_grants`, for both rules.

    What this deliberately gives up: a superuser creating a cluster-admin binding as a
    *backdoor* is no longer surfaced by this rule on its own. It is the same event as
    the harness's scaffolding and nothing in a single audit record tells them apart;
    K8S-002 still fires the moment the grantee uses the grant, whoever made it.

    Reports the beneficiary (the binding's ``target_actor``) as the finding's
    ``user``, never the identity that created the binding -- those are frequently
    different, and conflating them would point an analyst at the wrong account. See
    K8S-002 for the follow-on chain, and the module docstring for what this rule
    structurally cannot see (a custom role's actual permissions).
    """

    rule_id = "K8S-001"
    title = "RBAC binding grants a maximally-privileged role"
    severity = Severity.HIGH
    description = "Detects a RoleBinding/ClusterRoleBinding naming cluster-admin or admin."
    fields_used = (
        "actor", "actor_groups", "verb", "resource_type", "resource_name", "target_actor",
        "role_ref", "timestamp",
    )
    channels = frozenset({TelemetryChannel.CONTAINER_AUDIT})
    false_positives = (
        "Legitimate cluster bootstrap or platform-team tooling that binds cluster-admin "
        "to a small, known set of break-glass accounts or operator service accounts.",
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        controls = telemetry.controls
        if controls.empty:
            return []

        grants = _privilege_grants(controls)
        findings: list[Finding] = []
        for _, grant in grants.iterrows():
            if _grantor_is_superuser(grant):
                continue
            target = grant["target_actor"]
            findings.append(self.make_finding(
                device=grant["device"],
                user=target,
                evidence=(Evidence(
                    event_id=grant["event_id"], timestamp=grant["timestamp"],
                    summary=(
                        f"{grant['actor']} bound role '{grant['role_ref']}' to {target} "
                        f"via {grant['resource_type']} '{grant['resource_name']}'"
                    ),
                ),),
                reason=(
                    f"'{grant['actor']}' created {grant['resource_type']} "
                    f"'{grant['resource_name']}', granting the maximally-privileged "
                    f"role '{grant['role_ref']}' to '{target}'. Very few legitimate "
                    "workloads need this level of access, and the grantor is not a "
                    "superuser, so this grant confers standing the grantor did not "
                    "itself hold; it is worth review even when the grantor is an "
                    "ordinary administrative account."
                ),
                metadata={
                    "actor": grant["actor"],
                    "actor_groups": sorted(_names(grant.get("actor_groups", ""))),
                    "target_actor": target,
                    "role_ref": grant["role_ref"],
                    "resource_type": grant["resource_type"],
                    "resource_name": grant["resource_name"],
                },
            ))
        return findings


@register
class ExecShortlyAfterPrivilegeGrant(Detector):
    """K8S-002 -- The identity a privileged role was just granted to used ``pods/exec``.

    Attacker behaviour
    ------------------
    A privilege grant on its own is a single moment; using it is the follow-through
    that turns "someone could" into "someone did". ``pods/exec`` opens an interactive
    shell inside a running container -- the step after which the RBAC grant stops being
    theoretical, and where an attacker with a freshly-escalated service account would
    move next to actually explore or act inside the cluster.

    Detection shape
    ---------------
    Self-contained, like ``ATH-005``: finds a K8S-001-shaped grant (``create`` on
    ``rolebindings``/``clusterrolebindings`` naming a high-privilege role), then looks
    for a later ``pods/exec`` event whose **actor matches that grant's target_actor** --
    i.e. did the identity that *received* the grant go on to use it, never the identity
    that *created* the binding, within ``HuntConfig.privilege_escalation_window``. Does
    not depend on K8S-001 having run first; it recomputes the same grant shape from raw
    telemetry, the same way ATH-006 does not depend on any other rule having tagged
    ownership first.
    """

    rule_id = "K8S-002"
    title = "Pod exec by an identity shortly after receiving a privileged RBAC grant"
    severity = Severity.CRITICAL
    description = (
        "Detects pods/exec by the beneficiary of a K8S-001-shaped privilege grant, "
        "shortly after the grant."
    )
    fields_used = (
        "actor", "verb", "resource_type", "resource_name", "resource_namespace",
        "target_actor", "role_ref", "timestamp",
    )
    channels = frozenset({TelemetryChannel.CONTAINER_AUDIT})
    false_positives = (
        "A platform-team break-glass workflow that grants elevated access and then "
        "immediately uses it for a documented, legitimate operational task.",
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        controls = telemetry.controls
        if controls.empty:
            return []

        grants = _privilege_grants(controls)
        if grants.empty:
            return []
        # ``exec`` is the canonical verb the adapter emits for a shell into a container,
        # whatever HTTP-shaped verb (create/connect/get) the apiserver logged. Matching
        # on ``create`` here missed 100% of the execs in a real 1.37 cluster's audit log.
        execs = controls[
            (controls["verb"] == "exec") & (controls["resource_type"] == _EXEC_RESOURCE_TYPE)
        ]
        if execs.empty:
            return []

        window = self.config.privilege_escalation_window
        findings: list[Finding] = []

        for _, grant in grants.iterrows():
            target = grant["target_actor"]
            matches = execs[
                (execs["actor"] == target)
                & (execs["timestamp"] >= grant["timestamp"])
                & (execs["timestamp"] <= grant["timestamp"] + window)
            ].sort_values("timestamp")
            if matches.empty:
                continue

            pod_exec = matches.iloc[0]
            evidence = (
                Evidence(
                    event_id=grant["event_id"], timestamp=grant["timestamp"],
                    summary=(
                        f"{grant['actor']} bound role '{grant['role_ref']}' to {target}"
                    ),
                ),
                Evidence(
                    event_id=pod_exec["event_id"], timestamp=pod_exec["timestamp"],
                    summary=(
                        f"{target} exec'd into pod '{pod_exec['resource_name']}' "
                        f"in namespace '{pod_exec['resource_namespace']}'"
                    ),
                ),
            )
            delta = int((pod_exec["timestamp"] - grant["timestamp"]).total_seconds())

            findings.append(self.make_finding(
                device=pod_exec["device"],
                user=target,
                evidence=evidence,
                reason=(
                    f"'{target}' was granted the '{grant['role_ref']}' role "
                    f"{delta}s before exec'ing into pod "
                    f"'{pod_exec['resource_name']}' (namespace "
                    f"'{pod_exec['resource_namespace']}'). A freshly-escalated "
                    "identity acting on that escalation shortly after receiving it is "
                    "consistent with the grant being used for exploration or "
                    "post-exploitation access rather than left dormant."
                ),
                metadata={
                    "target_actor": target,
                    "grantor": grant["actor"],
                    "role_ref": grant["role_ref"],
                    "pod": pod_exec["resource_name"],
                    "namespace": pod_exec["resource_namespace"],
                    "seconds_between_grant_and_exec": delta,
                },
            ))
        return findings
