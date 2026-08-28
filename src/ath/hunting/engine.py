"""The hunt engine: runs detectors over telemetry and collects findings.

Error isolation is the point of this module. If one rule raises -- a bad regex, an
unexpected null -- the remaining rules must still run. A hunting platform that goes
silent because a single detection crashed is worse than one that reports the failure
and continues, because silence looks identical to "nothing found".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ath.hunting.base import Detector, HuntConfig, all_detectors, get_detector
from ath.hunting.finding import Finding, Severity
from ath.logging_setup import get_logger
from ath.telemetry.loader import Telemetry

logger = get_logger(__name__)


@dataclass
class HuntResult:
    """The outcome of a hunt across one or more detectors.

    Attributes:
        findings: All findings produced, sorted by severity then time.
        rules_run: Rule ids that executed successfully.
        errors: Mapping of rule id -> error message for rules that failed.
        started_at: When the hunt began (UTC).
    """

    findings: list[Finding] = field(default_factory=list)
    rules_run: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def by_rule(self, rule_id: str) -> list[Finding]:
        """Return only the findings produced by ``rule_id``."""
        return [f for f in self.findings if f.rule_id == rule_id.upper()]

    def by_device(self, device: str) -> list[Finding]:
        """Return only the findings affecting ``device``."""
        return [f for f in self.findings if f.device == device]

    def severity_counts(self) -> dict[str, int]:
        """Count findings per severity, highest first."""
        counts: dict[str, int] = {}
        for f in sorted(self.findings, key=lambda x: -x.severity.rank):
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """Serialise the whole result to JSON-safe types."""
        return {
            "started_at": self.started_at.isoformat(),
            "rules_run": self.rules_run,
            "errors": self.errors,
            "finding_count": self.finding_count,
            "severity_counts": self.severity_counts(),
            "findings": [f.to_dict() for f in self.findings],
        }


def run_hunt(
    telemetry: Telemetry,
    *,
    rule_ids: list[str] | None = None,
    config: HuntConfig | None = None,
    min_severity: Severity | None = None,
) -> HuntResult:
    """Run detectors over ``telemetry`` and return the collected findings.

    Args:
        telemetry: The loaded telemetry set.
        rule_ids: Specific rules to run. ``None`` runs every registered rule.
        config: Threshold overrides. ``None`` uses defaults.
        min_severity: Drop findings below this severity.

    Returns:
        A :class:`HuntResult`.

    Raises:
        KeyError: if an explicitly requested rule id is unknown. Unknown rules are a
            caller error and must not be silently skipped -- a typo in a scheduled hunt
            would otherwise mean a detection quietly stops running.
    """
    detectors: list[Detector] = (
        [get_detector(rid, config) for rid in rule_ids]
        if rule_ids
        else all_detectors(config)
    )

    result = HuntResult()
    for detector in detectors:
        try:
            found = detector.run(telemetry)
        except Exception as exc:  # noqa: BLE001 -- isolate one rule's failure
            logger.exception("Rule %s failed", detector.rule_id)
            result.errors[detector.rule_id] = f"{type(exc).__name__}: {exc}"
            continue

        result.rules_run.append(detector.rule_id)
        result.findings.extend(found)
        logger.info(
            "%s (%s): %d finding(s)", detector.rule_id, detector.title, len(found)
        )

    if min_severity is not None:
        result.findings = [
            f for f in result.findings if f.severity.rank >= min_severity.rank
        ]

    # Highest severity first, then chronological within a severity band -- the order an
    # analyst wants to triage in.
    result.findings.sort(key=lambda f: (-f.severity.rank, f.first_seen))

    logger.info(
        "Hunt complete: %d findings from %d rules (%d errors)",
        result.finding_count, len(result.rules_run), len(result.errors),
    )
    return result
