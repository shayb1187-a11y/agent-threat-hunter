"""The telemetry-channel vocabulary: kinds of observation, named vendor-neutrally.

Why this sits at the top level rather than inside :mod:`ath.environment`
------------------------------------------------------------------------
This enum is *vocabulary*, not analysis. It names what kinds of thing can be observed,
and it needs no telemetry, no rules and no environment model to mean something.

It lives here because two packages need it and they sit on opposite sides of a
dependency rule. :mod:`ath.environment` measures channel *availability* against real
data, which requires the hunting layer -- so importing anything from that package pulls
``ath.hunting`` in with it. :mod:`ath.behavior` must be importable and computable
**without** hunting, triage or the agent, because behaviors are an input to those layers
rather than a product of them.

Keeping the enum where both can reach it is what makes the one-way dependency
``telemetry -> behavior -> {detection, triage, correlation, agent}`` actually hold,
instead of holding only until someone needed to name a channel.

:mod:`ath.environment.channels` re-exports this name, so existing imports keep working
and there is still exactly one definition.
"""

from __future__ import annotations

from enum import Enum


class TelemetryChannel(str, Enum):
    """A kind of observation, named independently of any particular product.

    Vendor-neutral on purpose: "process execution" is the same defensive capability
    whether it arrives from Microsoft Defender, auditd, or a Kubernetes audit log.
    A future non-Windows telemetry source should populate these same channels rather
    than introduce a parallel vocabulary.
    """

    PROCESS_EXECUTION = "process_execution"
    PROCESS_COMMAND_LINE = "process_command_line"
    PROCESS_LINEAGE = "process_lineage"
    HANDLE_ACCESS = "handle_access"
    NETWORK_FLOW = "network_flow"
    NETWORK_INBOUND = "network_inbound"
    NETWORK_URL = "network_url"
    DNS_QUERY = "dns_query"
    AUTHENTICATION = "authentication"
    AUTH_SOURCE_ATTRIBUTION = "auth_source_attribution"
    FILE_EVENTS = "file_events"
    REGISTRY = "registry"
    SCRIPT_BLOCK = "script_block"
    EMAIL = "email"
    CLOUD_CONTROL_PLANE = "cloud_control_plane"
    CONTAINER_AUDIT = "container_audit"

    def __str__(self) -> str:
        return self.value
