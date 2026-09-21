"""Deterministic behaviors and shared features, computed once for every layer.

A :class:`~ath.behavior.models.Behavior` describes *what happened*, carrying no
severity and no suspicion. A :class:`~ath.behavior.features.ConnectionPattern` measures
the timing of one relationship, and is the single implementation of that computation in
the codebase.

Dependency direction is one-way -- ``telemetry -> behavior -> {detection, triage,
correlation, agent}`` -- and enforced by a test. See
:mod:`ath.behavior.models` for why the separation between behavior and suspicion is
load-bearing rather than cosmetic.
"""

from ath.behavior.extractors import (
    RECOVERY_ENUMERATION,
    RECOVERY_PROCEDURES,
    SCRIPT_INTERPRETERS,
    SECURITY_TOOL_PROCEDURES,
    connection_patterns,
    extract_behaviors,
    extract_outbound_relationship_behaviors,
    extract_recovery_behaviors,
    extract_security_tool_behaviors,
)
from ath.behavior.features import (
    MIN_INTERVALS_FOR_REGULARITY,
    MIN_MEANINGFUL_INTERVAL_SECONDS,
    REGULARITY_THRESHOLD,
    RELATION_EMERGING,
    RELATION_ESTABLISHED,
    RELATION_ESTABLISHING,
    RELATION_NEW,
    RELATION_STALE,
    RELATION_UNKNOWN,
    ConnectionPattern,
    compute_connection_pattern,
)
from ath.behavior.models import (
    BEHAVIOR_TYPES,
    FIRST_SEEN_PROCESS_DESTINATION,
    INTERPRETER_EXTERNAL_CONTACT,
    PERIODIC_OUTBOUND_RELATIONSHIP,
    RECOVERY_MECHANISM_DISABLED,
    SECURITY_TOOL_CONFIGURATION_MODIFIED,
    TELEMETRY_HEALTH_CHANGE,
    Behavior,
    BehaviorError,
    make_behavior_id,
)

__all__ = [
    "BEHAVIOR_TYPES",
    "Behavior",
    "BehaviorError",
    "ConnectionPattern",
    "FIRST_SEEN_PROCESS_DESTINATION",
    "INTERPRETER_EXTERNAL_CONTACT",
    "MIN_INTERVALS_FOR_REGULARITY",
    "MIN_MEANINGFUL_INTERVAL_SECONDS",
    "PERIODIC_OUTBOUND_RELATIONSHIP",
    "RECOVERY_ENUMERATION",
    "RECOVERY_MECHANISM_DISABLED",
    "RECOVERY_PROCEDURES",
    "REGULARITY_THRESHOLD",
    "RELATION_EMERGING",
    "RELATION_ESTABLISHED",
    "RELATION_ESTABLISHING",
    "RELATION_NEW",
    "RELATION_STALE",
    "RELATION_UNKNOWN",
    "SCRIPT_INTERPRETERS",
    "SECURITY_TOOL_CONFIGURATION_MODIFIED",
    "SECURITY_TOOL_PROCEDURES",
    "TELEMETRY_HEALTH_CHANGE",
    "compute_connection_pattern",
    "connection_patterns",
    "extract_behaviors",
    "extract_outbound_relationship_behaviors",
    "extract_recovery_behaviors",
    "extract_security_tool_behaviors",
    "make_behavior_id",
]
