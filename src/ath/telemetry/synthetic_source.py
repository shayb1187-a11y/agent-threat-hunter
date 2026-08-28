"""The synthetic generator, exposed as a :class:`~ath.telemetry.source.TelemetrySource`.

Pure adapter: all the generation logic still lives in
:mod:`ath.telemetry.generator`, unchanged. This class exists so the CLI and any other
caller can treat "make up a demo intrusion" and "import a real Defender export" as two
instances of the same interface, rather than as two unrelated code paths.
"""

from __future__ import annotations

from dataclasses import dataclass

from ath.telemetry.generator import GeneratorConfig, generate_telemetry
from ath.telemetry.source import SourceLoadResult, TelemetrySource


@dataclass
class SyntheticTelemetrySource(TelemetrySource):
    """Wraps :func:`ath.telemetry.generator.generate_telemetry`.

    Attributes:
        config: Generator configuration (seed, event counts, start time).
    """

    config: GeneratorConfig | None = None
    name: str = "synthetic"

    def load(self) -> SourceLoadResult:
        tables, ground_truth = generate_telemetry(self.config or GeneratorConfig())
        return SourceLoadResult(
            tables=tables,
            issues=[],  # the generator is trusted; it cannot produce a bad row
            ground_truth=ground_truth,
            rows_read=sum(len(df) for df in tables.values()),
        )
