"""The synthetic generator, exposed as a :class:`~ath.telemetry.source.TelemetrySource`.

Pure adapter: all the generation logic still lives in
:mod:`ath.telemetry.generator`, unchanged. This class exists so the CLI and any other
caller can treat "make up a demo intrusion" and "import a real Defender export" as two
instances of the same interface, rather than as two unrelated code paths.
"""

from __future__ import annotations

from dataclasses import dataclass

from ath.telemetry.generator import GeneratorConfig, generate_telemetry
from ath.telemetry.normalize import quarantine_implausible_timestamps
from ath.telemetry.source import NormalizationIssue, SourceLoadResult, TelemetrySource


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

        # The generator is trusted and produces no bad rows -- so this must find nothing,
        # which is exactly why it runs here. The synthetic path is the one telemetry whose
        # timestamps this project controls end to end; if quarantine ever fired on it, the
        # bound would be wrong rather than the data, and a bound tested only against
        # corpora it was written for is not a bound at all.
        issues: list[NormalizationIssue] = []
        for event_type, table in list(tables.items()):
            kept, quarantined = quarantine_implausible_timestamps(table, event_type)
            tables[event_type] = kept
            issues.extend(quarantined)

        return SourceLoadResult(
            tables=tables,
            issues=issues,
            ground_truth=ground_truth,
            rows_read=sum(len(df) for df in tables.values()) + len(issues),
        )
