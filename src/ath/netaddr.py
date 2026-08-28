"""Address classification: whether traffic actually left the network.

Why this sits at the top level
-------------------------------
Deciding "is this address routable on the public internet" is a fact about IP
allocation, not about detection. It needs no rules, no telemetry and no environment
model, and two packages on opposite sides of a dependency rule need it:
:mod:`ath.hunting` (the egress rule), :mod:`ath.environment` (external-destination
profiling), and :mod:`ath.behavior` (outbound relationship extraction), which must stay
computable without the hunting layer.

There must be exactly **one** definition of "external" in this system. Two would be a
bug waiting to be argued about during an incident -- the environment model and the
detection layer disagreeing about whether an address counts as egress is precisely the
kind of quiet inconsistency that erodes trust in every number built on top of it.

:mod:`ath.hunting.indicators` re-exports this name, so existing imports keep working.
"""

from __future__ import annotations

import ipaddress


def is_public_ip(address: str) -> bool:
    """Return True if ``address`` is a routable public IP.

    "External" means *not* private (RFC1918), loopback, link-local, multicast or
    reserved. Getting this right matters: treating 10.x as external would flood the
    egress rule with ordinary internal traffic and make it useless.
    """
    if not address:
        return False
    try:
        ip = ipaddress.ip_address(address.strip())
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )
