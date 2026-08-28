"""Telemetry ingestion: sources, normalization, and loading.

    Microsoft Defender export        synthetic generator
            |                                |
     DefenderExportSource         SyntheticTelemetrySource     <- ath.telemetry.source.TelemetrySource
            |________________________________|
                         |
                  Normalization              <- ath.telemetry.normalize.coerce_and_validate
                         |
              Canonical telemetry schema     <- ath.schema
                         |
              write_normalized_telemetry()   <- same CSV layout regardless of source
                         |
                  load_telemetry()           <- what every downstream stage reads

Everything from the detection engine onward reads a `Telemetry` object and does not
know or care which `TelemetrySource` produced it.
"""

from ath.telemetry.defender_source import DefenderExportSource
from ath.telemetry.generator import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import Telemetry, load_ground_truth, load_telemetry
from ath.telemetry.source import (
    NormalizationIssue,
    SourceLoadResult,
    TelemetrySource,
    write_normalized_telemetry,
)
from ath.telemetry.synthetic_source import SyntheticTelemetrySource

__all__ = [
    "GeneratorConfig",
    "generate_telemetry",
    "write_telemetry",
    "Telemetry",
    "load_telemetry",
    "load_ground_truth",
    "TelemetrySource",
    "SourceLoadResult",
    "NormalizationIssue",
    "write_normalized_telemetry",
    "SyntheticTelemetrySource",
    "DefenderExportSource",
]
