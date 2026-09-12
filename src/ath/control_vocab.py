"""The control-plane vocabulary: what a verb *is*, and which rows change an authority.

Why this sits at the top level rather than inside :mod:`ath.behavior`
----------------------------------------------------------------------
This module is *vocabulary*, not analysis. It names kinds of action and kinds of
resource, and it needs no telemetry, no rules and no environment model to mean
something. Three layers need it and they sit on different sides of the one-way
dependency ``telemetry -> behavior -> {detection, triage, correlation, agent}``:

* :mod:`ath.telemetry.cloudtrail_source` must know which rows may carry a beneficiary,
  so that a *read about* a user is not attributed to that user;
* :mod:`ath.telemetry.k8s_audit_source` must know which resources are RBAC bindings;
* :mod:`ath.environment.channels` must measure those columns over exactly those rows.

Declaring it in ``ath.behavior`` forced the telemetry layer to keep its own copy of
:data:`RBAC_BINDING_RESOURCES` -- two declarations of one fact, held equal by a test
because the import was illegal. :mod:`ath.channels` already set the precedent for the
fix: a leaf vocabulary module every layer may import, with exactly one definition.
:mod:`ath.behavior.control_plane` re-exports these names, so existing imports keep
working.

This module imports nothing from ``ath.telemetry``, ``ath.behavior``,
``ath.environment`` or ``ath.hunting``, and a test enforces that.

Why the adapter may read this and still not have an opinion
------------------------------------------------------------
:mod:`ath.telemetry.cloudtrail_source` derives ``verb`` from an event name's morphology
and nothing else: the first word of ``RunInstances`` is ``run``, the first word of
``DeleteFlowLogs`` is ``delete``, and the adapter does not know or care which of those
two is the interesting one. That ignorance is the point -- the moment an adapter decides
which verbs *matter*, representation starts depending on an opinion about maliciousness,
and the 99.9% of a cloud trail that nobody wrote an opinion about disappears.

What the adapter reads from here is not an opinion about importance but the canonical
schema's own definition of a column. ``target_actor`` means "the identity whose
authority or credentials this action changed"; a row that changed no authority has no
such identity, on every corpus, forever. Every row is still represented in full either
way -- this decides the contents of two columns, never whether a row exists.

Consumers, too, need to group verbs: "this identity performed 4,000 reads and then one
grant" is a statement worth making, and making it from 55 distinct verb tokens is not.

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
# Declared once, here, because the Kubernetes adapter reads it to decide when to fill
# ``target_actor`` and the predicates below read it for the same reason -- and while
# this lived in ``ath.behavior`` the adapter could not import it, so it kept a second
# copy held equal by a test. A leaf module removes the seam rather than guarding it.
RBAC_BINDING_RESOURCES: Final[frozenset[str]] = frozenset({
    "rolebindings", "clusterrolebindings",
})

# The services whose objects *are* identities, and whose calls therefore move authority
# rather than merely mentioning an identity. A service, not a set of call names: every
# call AWS' identity service has ever shipped names its beneficiary the same way,
# including the ones that do not exist yet. A resource-family list ("user-policy",
# "role-policy", ...) would be the allowlist defect M18-3 removed from the adapter,
# reintroduced one layer up and tuned to whichever trail was open at the time.
IDENTITY_SERVICES: Final[frozenset[str]] = frozenset({"iam"})

# The verb classes that change something about an identity rather than report on it.
# READ is the exclusion this exists for; EXECUTE and OTHER act on no authority either
# (assuming a role is an authentication act, and the logon table is its home).
AUTHORITY_CHANGING_CLASSES: Final[frozenset[str]] = frozenset({
    GRANT, REVOKE, CREATE, DELETE, MODIFY,
})


def service_of(resource_type: str) -> str:
    """The service prefix of a canonical resource type: ``"iam:user-policy"`` -> ``"iam"``.

    A resource type with no ``":"`` is the service alone -- a real canonical value, for
    a call whose name carries no resource noun -- so it is returned as-is rather than
    treated as malformed. A Kubernetes resource (``"rolebindings"``) also has no colon
    and comes back unchanged, which matches no service and is why the binding clause of
    :func:`changes_authority` is a separate test rather than a service name.
    """
    return resource_type.strip().lower().split(":", 1)[0]


def changes_authority(verb: str, resource_type: str) -> bool:
    """Whether a control row changed some identity's authority or credentials.

    This is the predicate behind the ``target_actor`` and ``role_ref`` columns. The
    canonical schema defines those as *the identity whose authority or credentials this
    action changed*, which is a narrower thing than "a row that mentions an identity":
    ``ListAttachedUserPolicies`` names a user in its parameters and changes nothing
    about that user. Filling the column on such a row put 11,388 rows of the public
    flaws.cloud trail -- almost all of them reads -- under the identity they were
    *about* rather than under the caller who read them, because the canonical ``user``
    column is ``target_actor or actor`` (M18-4).

    Two independent ways a row can qualify, because two platforms model identity
    differently, both conjoined with the requirement that something actually changed:

    * the row acts on an :data:`IDENTITY_SERVICES` service -- AWS' IAM, whose every
      object is a user, role, group, policy or credential;
    * or the row acts on one of :data:`RBAC_BINDING_RESOURCES` -- Kubernetes, where a
      permission is granted by creating a binding object.

    ...and :func:`verb_class` is in :data:`AUTHORITY_CHANGING_CLASSES` (``grant``,
    ``revoke``, ``create``, ``delete``, ``modify``). The first clause excludes a grant
    on a storage volume; the second excludes a read on the identity service.

    Built from verb classes and two platform-model vocabularies, and from nothing else.
    No list of resource families appears in it, which is what keeps the predicate from
    being tuned to the trails it was measured on: a service AWS ships next year with an
    identity object in it needs one entry in :data:`IDENTITY_SERVICES`, not an
    enumeration of its calls.

    Args:
        verb: The canonical control-row verb.
        resource_type: The canonical resource type the row acted on.

    Returns:
        True when the row changed an identity's authority or credentials.
    """
    if verb_class(verb) not in AUTHORITY_CHANGING_CLASSES:
        return False
    return (
        service_of(resource_type) in IDENTITY_SERVICES
        or resource_type.strip().lower() in RBAC_BINDING_RESOURCES
    )


def is_grant(verb: str, resource_type: str) -> bool:
    """Whether a control row is grant-shaped: a permission moved to some identity.

    Two ways a row can be one, because two platforms express the same act differently:

    * the verb itself is a grant verb (:data:`GRANT`) -- AWS' ``attach``, ``add``,
      ``associate``, and their peers;
    * or the row *creates* one of :data:`RBAC_BINDING_RESOURCES` -- Kubernetes, where
      granting is done by creating an object and the verb is therefore ``create``.

    This is a statement about the shape of the action, not about its risk: the
    overwhelming majority of grants are administration.

    Crosswise with :func:`changes_authority` rather than narrower or wider than it: a
    ``detach`` changes authority without being a grant, and an ``attach`` of a storage
    volume to an instance is grant-shaped while naming no identity at all (42 of the 132
    grant-shaped rows on flaws.cloud are exactly that). Which is why the columns that
    name an *identity* are measured with :func:`changes_authority`, and this function
    answers the different question of what kind of action a row records.

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
