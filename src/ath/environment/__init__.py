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
    DEFAULT_PARTIAL_THRESHOLD,
    ChannelAssessment,
    ChannelSpec,
    ChannelState,
    FieldPopulation,
    TelemetryChannel,
    assess_channels,
    channel_of_control_row,
    channels_of_row,
    measure_field_populations,
)
from ath.environment.coverage import (
    DEGRADED_BELOW,
    FIELD_TO_CHANNEL,
    TECHNIQUE_WATCHLIST,
    UNUSABLE_BELOW,
    ChannelViolation,
    CoverageReport,
    CoverageState,
    FieldUsability,
    RuleRunnability,
    RuleSupport,
    RuleVerdict,
    TechniqueCoverage,
    WatchlistEntry,
    assess_coverage,
    assess_rule,
    channels_for_fields,
    findings_respect_declared_channels,
    rule_field_usability,
)
from ath.environment.model import (
    EnvironmentModel,
    Host,
    Identity,
    build_environment_model,
)

__all__ = [
    "CHANNEL_SPECS",
    "DEFAULT_PARTIAL_THRESHOLD",
    "DEGRADED_BELOW",
    "FIELD_TO_CHANNEL",
    "TECHNIQUE_WATCHLIST",
    "UNUSABLE_BELOW",
    "ChannelAssessment",
    "ChannelSpec",
    "ChannelState",
    "ChannelViolation",
    "CoverageReport",
    "CoverageState",
    "EnvironmentModel",
    "FieldPopulation",
    "FieldUsability",
    "Host",
    "Identity",
    "RuleRunnability",
    "RuleSupport",
    "RuleVerdict",
    "TechniqueCoverage",
    "TelemetryChannel",
    "WatchlistEntry",
    "assess_channels",
    "assess_coverage",
    "assess_rule",
    "channel_of_control_row",
    "channels_for_fields",
    "channels_of_row",
    "build_environment_model",
    "findings_respect_declared_channels",
    "measure_field_populations",
    "rule_field_usability",
]
