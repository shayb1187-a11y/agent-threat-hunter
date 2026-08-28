"""Detection rule modules.

Importing this package registers every rule with the registry in ``ath.hunting.base``.
Rules are grouped by telemetry source, mirroring how public detection repositories
(Sigma, Elastic) organise content by log source rather than one file per rule.

``initial_access_rules`` and ``discovery_rules`` (ATH-009, ATH-010) were promoted from
candidates proposed and measured by ``ath.engineering`` -- see that package and
``docs/detection-engineering.md`` for the propose/evaluate/iterate history.
"""

from ath.hunting.rules import (
    discovery_rules,
    initial_access_rules,
    logon_rules,
    network_rules,
    process_rules,
)

__all__ = [
    "process_rules", "network_rules", "logon_rules",
    "initial_access_rules", "discovery_rules",
]
