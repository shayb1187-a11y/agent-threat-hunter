"""Environment-driven capability planning: which specialist crew a case should run with.

Two pieces, deliberately kept separate:

``registry``
    A static, declarative catalogue of capabilities (:class:`CapabilitySpec`) -- what
    telemetry each one needs, and how to build it. Adding a capability means adding a
    tuple entry here, not editing conditional logic anywhere else.

``crew``
    :func:`~ath.capabilities.crew.assemble_crew` turns an
    :class:`~ath.environment.model.EnvironmentModel`'s measured telemetry availability
    into the subset of the registry that can actually do useful work in this
    environment -- the "Security Capability Planning -> Dynamic Security Crew" stage of
    this project's long-term vision. Purely a set-membership computation over
    ``EnvironmentModel.observable_channels``: no LLM, no ranking, deterministic and
    reproducible like every other layer in this project.

This is a separate stage from :meth:`~ath.agent.specialists.Specialist.should_run`,
not a replacement for it. Assembly decides which specialists are *stood up* for an
environment, once, before any case exists; ``should_run`` still decides *per-case*
relevance within whatever crew was assembled.
"""

from ath.capabilities.crew import Crew, assemble_crew, resolve_specialists
from ath.capabilities.registry import CAPABILITY_REGISTRY, CapabilitySpec

__all__ = [
    "CapabilitySpec", "CAPABILITY_REGISTRY", "Crew", "assemble_crew", "resolve_specialists",
]
