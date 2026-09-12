"""The control-plane verb vocabulary, re-exported from its leaf module.

The definitions moved to :mod:`ath.control_vocab` in M18-5 and are re-exported here, so
existing imports keep working and there is still exactly one definition -- the same
arrangement :mod:`ath.channels` and :mod:`ath.environment.channels` already use for
:class:`~ath.channels.TelemetryChannel`.

Why the move: :mod:`ath.telemetry.k8s_audit_source` needs
:data:`~ath.control_vocab.RBAC_BINDING_RESOURCES` and the CloudTrail adapter needs
:func:`~ath.control_vocab.changes_authority`, and the dependency direction
``telemetry -> behavior`` forbids either importing this package. The cost of leaving the
vocabulary here was a second declaration of the binding resources inside the adapter,
held equal to this one by a test; a leaf module every layer may import removes the seam
instead of guarding it.

See :mod:`ath.control_vocab` for what a verb class does and does not mean, why the
vocabulary is keyed on verbs rather than event names, and how ``changes_authority``
differs from ``is_grant``.
"""

from __future__ import annotations

from ath.control_vocab import (
    AUTHORITY_CHANGING_CLASSES,
    CREATE,
    DELETE,
    EXECUTE,
    GRANT,
    IDENTITY_SERVICES,
    MODIFY,
    OTHER,
    RBAC_BINDING_RESOURCES,
    READ,
    REVOKE,
    VERB_CLASS_NAMES,
    VERB_CLASSES,
    changes_authority,
    is_grant,
    service_of,
    verb_class,
)

__all__ = [
    "AUTHORITY_CHANGING_CLASSES",
    "CREATE",
    "DELETE",
    "EXECUTE",
    "GRANT",
    "IDENTITY_SERVICES",
    "MODIFY",
    "OTHER",
    "RBAC_BINDING_RESOURCES",
    "READ",
    "REVOKE",
    "VERB_CLASSES",
    "VERB_CLASS_NAMES",
    "changes_authority",
    "is_grant",
    "service_of",
    "verb_class",
]
