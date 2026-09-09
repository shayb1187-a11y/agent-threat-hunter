"""The capability catalogue: what each investigation capability needs to run at all.

A deliberately small, explicit set. Adding a capability here means declaring its
telemetry requirement honestly, in the same vendor-neutral vocabulary specialists
already use for per-case eligibility (:class:`~ath.agent.specialists.Specialist`) --
this registry does not invent a second vocabulary, it reuses
:class:`~ath.channels.TelemetryChannel` for the same reason ``reads_channels`` does.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ath.agent.specialists import (
    AttackMappingAgent,
    ControlPlaneAgent,
    EndpointAgent,
    IdentityAgent,
    NetworkAgent,
    Specialist,
)
from ath.agent.tools import ToolBox
from ath.channels import TelemetryChannel


@dataclass(frozen=True)
class CapabilitySpec:
    """One capability the platform can potentially stand up for an environment.

    Attributes:
        id: Stable identifier, matching the specialist's own ``name`` (e.g.
            ``"control_plane"``).
        factory: Builds the specialist given a :class:`ToolBox`. Specialist classes
            are directly usable here -- ``Specialist.__init__(self, tools)`` already
            matches this signature.
        requires_all: Every one of these channels must be observable for the
            capability to stand up. Empty means no such requirement.
        requires_any: At least one of these must be observable, when non-empty. Exists
            for capabilities that work from more than one kind of evidence and need
            neither specifically -- ``control_plane`` is the motivating case: it
            should stand up for an AWS-only *or* a Kubernetes-only environment, not
            require both cloud and container telemetry to exist simultaneously.
        description: One line, surfaced in crew listings.
    """

    id: str
    factory: Callable[[ToolBox], Specialist]
    requires_all: frozenset[TelemetryChannel] = frozenset()
    requires_any: frozenset[TelemetryChannel] = frozenset()
    description: str = ""

    def satisfied_by(self, observable: set[TelemetryChannel]) -> bool:
        """Whether this capability's telemetry requirements are met.

        Pure set membership -- no environment object, no side effects, so a crew can
        be recomputed cheaply and the answer is exactly reproducible for the same
        observable-channel set.
        """
        if not self.requires_all <= observable:
            return False
        return not self.requires_any or bool(self.requires_any & observable)


CAPABILITY_REGISTRY: tuple[CapabilitySpec, ...] = (
    CapabilitySpec(
        id="endpoint", factory=EndpointAgent,
        requires_all=frozenset({TelemetryChannel.PROCESS_EXECUTION}),
        description="Process lineage and execution-chain reconstruction.",
    ),
    CapabilitySpec(
        id="identity", factory=IdentityAgent,
        requires_all=frozenset({TelemetryChannel.AUTHENTICATION}),
        description="Authentication and account-behaviour analysis.",
    ),
    CapabilitySpec(
        id="network", factory=NetworkAgent,
        requires_all=frozenset({TelemetryChannel.NETWORK_FLOW}),
        description="Outbound network communication and beacon-timing analysis.",
    ),
    CapabilitySpec(
        id="attack", factory=AttackMappingAgent,
        description=(
            "MITRE ATT&CK technique interpretation and coverage-gap reporting -- "
            "interprets mappings the deterministic layer already produced, so it "
            "needs no telemetry of its own and always stands up."
        ),
    ),
    CapabilitySpec(
        id="control_plane", factory=ControlPlaneAgent,
        requires_any=frozenset({
            TelemetryChannel.CLOUD_MANAGEMENT_ACTIVITY, TelemetryChannel.CONTAINER_AUDIT,
        }),
        description=(
            "Cloud/Kubernetes control-plane privilege-escalation chains -- stands up "
            "for AWS-only, Kubernetes-only, or both."
        ),
    ),
)
