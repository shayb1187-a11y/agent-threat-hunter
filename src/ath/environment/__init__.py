"""Environment understanding: what is being defended, and what can be seen of it.

This package answers the two questions every layer before it assumed:

* :mod:`ath.environment.model` -- *what* is this environment? Hosts, identities,
  platform, existing security controls, and an explicit list of what could not be
  determined from telemetry.
* :mod:`ath.environment.channels` -- *what can be seen* of it? Which kinds of
  observation are available, sparse, or entirely absent.
* :mod:`ath.environment.coverage` -- *what does that make defensible*? Every
  assessed technique sorted into detectable, observable-but-undetected,
  unverifiable, or unobservable -- four states with four different remedies.

Everything here is derived deterministically from telemetry. No language model
participates, because this is the ground truth that later reasoning rests on.
"""

from ath.environment.channels import (
    CHANNEL_SPECS,
    ChannelAssessment,
    ChannelSpec,
    ChannelState,
    TelemetryChannel,
    assess_channels,
)
from ath.environment.coverage import (
    FIELD_TO_CHANNEL,
    TECHNIQUE_WATCHLIST,
    CoverageReport,
    CoverageState,
    RuleRunnability,
    RuleSupport,
    TechniqueCoverage,
    WatchlistEntry,
    assess_coverage,
    channels_for_fields,
)
from ath.environment.model import (
    EnvironmentModel,
    Host,
    Identity,
    build_environment_model,
)

__all__ = [
    "CHANNEL_SPECS",
    "FIELD_TO_CHANNEL",
    "TECHNIQUE_WATCHLIST",
    "ChannelAssessment",
    "ChannelSpec",
    "ChannelState",
    "CoverageReport",
    "CoverageState",
    "EnvironmentModel",
    "Host",
    "Identity",
    "RuleRunnability",
    "RuleSupport",
    "TechniqueCoverage",
    "TelemetryChannel",
    "WatchlistEntry",
    "assess_channels",
    "assess_coverage",
    "channels_for_fields",
    "build_environment_model",
]
