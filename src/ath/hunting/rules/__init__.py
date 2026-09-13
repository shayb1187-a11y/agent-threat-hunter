"""Detection rule modules.

Importing this package registers every rule with the registry in ``ath.hunting.base``.
Rules are grouped by telemetry source, mirroring how public detection repositories
(Sigma, Elastic) organise content by log source rather than one file per rule.

``initial_access_rules`` and ``discovery_rules`` (ATH-009, ATH-010) were promoted from
candidates proposed and measured by ``ath.engineering`` -- see that package and
``docs/detection-engineering.md`` for the propose/evaluate/iterate history.

``aws_rules``, ``cloud_behaviour_rules`` and ``k8s_rules`` read
``ath.schema.EVENT_CONTROL`` (cloud/Kubernetes control-plane activity) rather than the
Windows-shaped process/network/logon tables every other module here reads. The split
between the first two is what the rule *names*: ``aws_rules`` keys on particular IAM and
audit-service resource families, ``cloud_behaviour_rules`` (M18-8) names nothing at all
and describes behaviour purely through verb classes, ``decision``, breadth and windows.
"""

from ath.hunting.rules import (
    aws_rules,
    cloud_behaviour_rules,
    defense_impairment_rules,
    discovery_rules,
    impact_rules,
    initial_access_rules,
    k8s_rules,
    logon_rules,
    network_rules,
    process_rules,
)

__all__ = [
    "process_rules", "network_rules", "logon_rules",
    "initial_access_rules", "discovery_rules",
    "impact_rules", "defense_impairment_rules",
    "aws_rules", "cloud_behaviour_rules", "k8s_rules",
]
