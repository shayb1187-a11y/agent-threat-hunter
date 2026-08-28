"""MITRE ATT&CK interpretation layer.

Kept strictly separate from detection: rules decide *what is suspicious*, this layer
decides *what public taxonomy that behaviour matches*. Nothing here can influence
whether a finding is raised.
"""

from ath.mitre.attack import (
    ATTACK_VERSION,
    TECHNIQUES,
    AttackMapping,
    Confidence,
    Tactic,
    Technique,
    UnknownTechniqueError,
    get_technique,
)
from ath.mitre.mapper import (
    MAPPING_RULES,
    MappingRule,
    map_finding,
    map_findings,
    tactics_covered,
    unique_techniques,
)

__all__ = [
    "ATTACK_VERSION", "TECHNIQUES", "AttackMapping", "Confidence", "Tactic",
    "Technique", "UnknownTechniqueError", "get_technique",
    "MAPPING_RULES", "MappingRule", "map_finding", "map_findings",
    "tactics_covered", "unique_techniques",
]
