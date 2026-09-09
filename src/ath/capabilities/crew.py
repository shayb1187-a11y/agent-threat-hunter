"""Environment-driven crew assembly.

``assemble_crew`` is the "Security Capability Planning -> Dynamic Security Crew" stage
this project's long-term vision describes, built as a thin layer on top of two already-
proven primitives rather than a new mechanism: :attr:`EnvironmentModel.
observable_channels` (what telemetry this environment actually has) and
:class:`~ath.capabilities.registry.CapabilitySpec` (what each capability needs).

It is deliberately **not** where per-case relevance is decided -- that stays
:meth:`~ath.agent.specialists.Specialist.should_run`, unchanged by this milestone.
Assembly answers "does this capability exist in this environment at all", once, before
any case does; ``should_run`` still answers "does *this* case need it", every time one
runs. A capability excluded here never gets the chance to decline per-case, because it
was never stood up -- the same way an organisation that has no cloud team does not run
a per-incident vote on whether to page it.
"""

from __future__ import annotations

from dataclasses import dataclass

from ath.agent.specialists import Specialist, default_specialists
from ath.agent.tools import ToolBox
from ath.capabilities.registry import CAPABILITY_REGISTRY, CapabilitySpec
from ath.environment.model import EnvironmentModel
from ath.logging_setup import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class Crew:
    """The specialists assembled for one environment, and what was left out.

    Attributes:
        specialists: Capabilities whose requirements this environment satisfies,
            instantiated and ready to run.
        excluded: ``(spec, reason)`` for every capability that did *not* stand up --
            kept, not discarded, so "why isn't X investigating this environment" has
            an answer as concrete as the eligibility reasons ``should_run`` already
            gives per case.
    """

    specialists: tuple[Specialist, ...]
    excluded: tuple[tuple[CapabilitySpec, str], ...] = ()

    def to_dict(self) -> dict:
        return {
            "specialists": [s.name for s in self.specialists],
            "excluded": [
                {"id": spec.id, "description": spec.description, "reason": reason}
                for spec, reason in self.excluded
            ],
        }


def _exclusion_reason(spec: CapabilitySpec, observable: set) -> str:
    missing_all = sorted(c.value for c in spec.requires_all - observable)
    parts = []
    if missing_all:
        parts.append(f"missing required channel(s): {', '.join(missing_all)}")
    if spec.requires_any and not (spec.requires_any & observable):
        alternatives = ", ".join(sorted(c.value for c in spec.requires_any))
        parts.append(f"none of its alternative channels are observable: {alternatives}")
    return "; ".join(parts) or "requirements not met"


def assemble_crew(
    environment: EnvironmentModel,
    tools: ToolBox,
    registry: tuple[CapabilitySpec, ...] = CAPABILITY_REGISTRY,
) -> Crew:
    """Build the crew this environment's telemetry can actually support.

    Deterministic and declarative: a pure function of ``environment.
    observable_channels`` and the (static, in-code) registry. No model is consulted --
    see the module docstring in :mod:`ath.capabilities` for why that is a design
    constraint, not a current limitation.

    Args:
        environment: The environment to plan for.
        tools: Passed to each satisfied capability's factory.
        registry: Capabilities to consider; defaults to every registered one.

    Returns:
        The assembled :class:`Crew`.
    """
    observable = environment.observable_channels
    specialists: list[Specialist] = []
    excluded: list[tuple[CapabilitySpec, str]] = []

    for spec in registry:
        if spec.satisfied_by(observable):
            specialists.append(spec.factory(tools))
        else:
            excluded.append((spec, _exclusion_reason(spec, observable)))

    logger.info(
        "Assembled crew for environment (platforms=%s): %s (excluded: %s)",
        sorted(environment.platforms) or ["unknown"],
        [s.name for s in specialists],
        [spec.id for spec, _ in excluded],
    )
    return Crew(specialists=tuple(specialists), excluded=tuple(excluded))


def resolve_specialists(
    specialists: list[Specialist] | None,
    environment: EnvironmentModel | None,
    tools: ToolBox,
) -> list[Specialist]:
    """The specialist roster to use, in one place so runtimes cannot silently diverge.

    Precedence: an explicit ``specialists`` list always wins (tests and callers that
    construct a specific roster keep working exactly as before); otherwise, an
    attached environment gets an assembled crew; otherwise, the fixed
    :func:`~ath.agent.specialists.default_specialists` roster this project shipped
    with before this milestone.

    Both :class:`~ath.agent.orchestrator.InvestigationOrchestrator` and
    :func:`~ath.agent.graph.run_investigation_via_langgraph` call this rather than
    each resolving it independently -- ``ath.agent.graph``'s own docstring already
    documents one bug that exact kind of divergence caused before eligibility was
    threaded through both runtimes identically.
    """
    if specialists is not None:
        return list(specialists)
    if environment is not None:
        return list(assemble_crew(environment, tools).specialists)
    return default_specialists(tools)
