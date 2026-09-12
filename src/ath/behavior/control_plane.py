"""What a control-plane verb *is*, as a closed vocabulary of verbs.

Why this is not in the telemetry layer
---------------------------------------
:mod:`ath.telemetry.cloudtrail_source` derives ``verb`` from an event name's morphology
and nothing else: the first word of ``RunInstances`` is ``run``, the first word of
``DeleteFlowLogs`` is ``delete``, and the adapter does not know or care which of those
two is the interesting one. That ignorance is the point -- the moment an adapter decides
which verbs matter, representation starts depending on an opinion about maliciousness,
and the 99.9% of a cloud trail that nobody wrote an opinion about disappears.

Consumers, though, do need to group verbs: "this identity performed 4,000 reads and then
one grant" is a statement worth making, and making it from 55 distinct verb tokens is
not. So the grouping lives here -- one layer up, in ``ath.behavior``, which is already
the place where telemetry becomes a description of what happened, and which by the
dependency direction ``telemetry -> behavior -> {detection, triage, correlation, agent}``
may not import ``ath.hunting``.

What a class does and does not mean
------------------------------------
A class says what *kind of action* the verb is, and nothing else. ``grant`` is not
"suspicious" -- the overwhelming majority of grants are an administrator doing their job
-- and ``read`` is not "safe": reconnaissance is entirely made of reads. This is the
same discipline :mod:`ath.behavior.models` applies to behaviors: named for what was
observed, never for what it might mean.

Why a vocabulary of verbs, and not of event names
--------------------------------------------------
There are tens of thousands of AWS API names and a new one every week; there are a few
dozen verbs, and the set is stable because it is English. A mapping keyed on event names
would need an entry for every new API before that API could be described at all -- which
is exactly the failure this vocabulary replaces. An unknown verb classifies as ``other``
and stays fully represented; only its grouping is unknown.

Kubernetes' audit verbs (``get``, ``list``, ``watch``, ``create``, ``update``, ``patch``,
``delete``, ``deletecollection``, ``exec``) are in the same table, because they are the
same kind of statement about the same canonical column. Where AWS and Kubernetes share a
token they share a class, which is the useful property: ``create`` means create on both.
"""

from __future__ import annotations

from typing import Final

# The eight classes. Small and closed on purpose: a class per verb would be a rename,
# not an abstraction, and a class nobody can define the boundary of ("privileged") would
# smuggle a judgement in.
READ: Final[str] = "read"
CREATE: Final[str] = "create"
GRANT: Final[str] = "grant"
REVOKE: Final[str] = "revoke"
MODIFY: Final[str] = "modify"
DELETE: Final[str] = "delete"
EXECUTE: Final[str] = "execute"
OTHER: Final[str] = "other"

VERB_CLASS_NAMES: Final[tuple[str, ...]] = (
    READ, CREATE, GRANT, REVOKE, MODIFY, DELETE, EXECUTE, OTHER,
)

# Lowercase verb token -> class. Keys are verbs, never event names.
#
# Judgement calls, stated rather than buried:
#
# * ``run``/``start``/``stop`` are *execute*, not create/delete. "Run" is an execution
#   verb everywhere else in this project (a process runs), and an instance that is run,
#   stopped and run again is one resource being executed, not three resources created.
# * ``put`` is *create*: it creates-or-replaces the named resource. A put that happens to
#   grant a policy is recognised as a grant by the rule that cares about that shape
#   (``AWS-001``), which reads the resource family too -- not by this table, which sees
#   only the verb.
# * ``enable``/``disable``/``deactivate`` are *modify*, not grant/revoke. They change a
#   setting on a resource; they do not move a permission between principals.
# * ``assume`` is *other*: assuming a role is an authentication act, and this vocabulary
#   describes actions on resources. The canonical home for it is the logon table.
VERB_CLASSES: Final[dict[str, str]] = {
    # -- read ---------------------------------------------------------------------
    "get": READ, "list": READ, "describe": READ, "lookup": READ, "search": READ,
    "query": READ, "scan": READ, "check": READ, "view": READ, "discover": READ,
    "simulate": READ, "decode": READ, "validate": READ, "test": READ, "resolve": READ,
    "translate": READ, "estimate": READ, "preview": READ, "head": READ,
    "download": READ, "select": READ, "watch": READ,
    # -- create -------------------------------------------------------------------
    "create": CREATE, "put": CREATE, "generate": CREATE, "copy": CREATE,
    "import": CREATE, "register": CREATE, "allocate": CREATE, "request": CREATE,
    "provision": CREATE, "restore": CREATE, "upload": CREATE, "clone": CREATE,
    "issue": CREATE,
    # -- grant --------------------------------------------------------------------
    "attach": GRANT, "add": GRANT, "authorize": GRANT, "associate": GRANT,
    "grant": GRANT, "share": GRANT, "shared": GRANT, "bind": GRANT, "allow": GRANT,
    # -- revoke -------------------------------------------------------------------
    "detach": REVOKE, "remove": REVOKE, "revoke": REVOKE, "disassociate": REVOKE,
    "deny": REVOKE, "reject": REVOKE, "unshare": REVOKE, "unbind": REVOKE,
    # -- modify -------------------------------------------------------------------
    "modify": MODIFY, "update": MODIFY, "set": MODIFY, "change": MODIFY,
    "replace": MODIFY, "enable": MODIFY, "disable": MODIFY, "activate": MODIFY,
    "deactivate": MODIFY, "rotate": MODIFY, "resize": MODIFY, "tag": MODIFY,
    "untag": MODIFY, "reset": MODIFY, "configure": MODIFY, "move": MODIFY,
    "rename": MODIFY, "monitor": MODIFY, "unmonitor": MODIFY, "patch": MODIFY,
    "apply": MODIFY,
    # -- delete -------------------------------------------------------------------
    "delete": DELETE, "terminate": DELETE, "destroy": DELETE, "purge": DELETE,
    "discard": DELETE, "cancel": DELETE, "release": DELETE, "deregister": DELETE,
    "unregister": DELETE, "deletecollection": DELETE, "expire": DELETE,
    # -- execute ------------------------------------------------------------------
    "run": EXECUTE, "start": EXECUTE, "stop": EXECUTE, "restart": EXECUTE,
    "reboot": EXECUTE, "invoke": EXECUTE, "exec": EXECUTE, "execute": EXECUTE,
    "send": EXECUTE, "publish": EXECUTE, "deliver": EXECUTE, "initiate": EXECUTE,
    "trigger": EXECUTE, "abort": EXECUTE, "connect": EXECUTE, "proxy": EXECUTE,
    # -- other --------------------------------------------------------------------
    # Verbs that are real and common but describe no action on a resource. Listed
    # explicitly, rather than left to the default, so that "we have seen this verb and
    # decided it groups with nothing" is distinguishable from "never seen".
    "assume": OTHER, "batch": OTHER, "git": OTHER, "console": OTHER, "accept": OTHER,
}


def verb_class(verb: str) -> str:
    """Which class of action a canonical ``verb`` names.

    Args:
        verb: A canonical control-row verb -- lowercase, one token (``"describe"``,
            ``"deletecollection"``). Case and surrounding whitespace are tolerated
            because the column is free text and a source could hand up either.

    Returns:
        One of :data:`VERB_CLASS_NAMES`. ``"other"`` for a verb this vocabulary does not
        know, which is a statement about the vocabulary and never about the row: the row
        is represented in full either way.
    """
    return VERB_CLASSES.get(verb.strip().lower(), OTHER)


# The Kubernetes resources whose *creation* is a grant. RBAC has no ``attach`` verb:
# a binding is granted by creating a RoleBinding or ClusterRoleBinding object, so the
# verb alone ("create") classifies as CREATE and says nothing about the permission that
# moved. The resource is what makes it a grant, which is why :func:`is_grant` needs both.
#
# Declared here rather than imported from :mod:`ath.telemetry.k8s_audit_source`, whose
# ``_RBAC_RESOURCES`` is the same set, because the dependency runs
# ``telemetry -> behavior`` and may not be reversed. Two declarations of one fact is a
# drift risk, so a test asserts the two sets are equal; that is the seam, stated.
RBAC_BINDING_RESOURCES: Final[frozenset[str]] = frozenset({
    "rolebindings", "clusterrolebindings",
})


def is_grant(verb: str, resource_type: str) -> bool:
    """Whether a control row is grant-shaped: a permission moved to some identity.

    Two ways a row can be one, because two platforms express the same act differently:

    * the verb itself is a grant verb (:data:`GRANT`) -- AWS' ``attach``, ``add``,
      ``associate``, and their peers;
    * or the row *creates* one of :data:`RBAC_BINDING_RESOURCES` -- Kubernetes, where
      granting is done by creating an object and the verb is therefore ``create``.

    This is a statement about the shape of the action, not about its risk: the
    overwhelming majority of grants are administration. It exists so that a column
    which only a grant can carry -- who the grant targets, which role it names -- is
    measured over the rows that could carry it, instead of over every read in the trail.

    Args:
        verb: The canonical control-row verb.
        resource_type: The canonical resource type the row acted on.

    Returns:
        True when the row grants something to someone.
    """
    if verb_class(verb) == GRANT:
        return True
    # The literal token, not the CREATE *class* constant they happen to share a
    # spelling with: this clause is about the audit verb Kubernetes logs, and a
    # future rename of the class must not silently change which rows are grants.
    return (
        verb.strip().lower() == "create"
        and resource_type.strip().lower() in RBAC_BINDING_RESOURCES
    )
