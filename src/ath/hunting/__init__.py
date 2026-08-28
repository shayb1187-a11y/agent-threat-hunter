"""Deterministic threat-hunting layer.

Public surface:

    Finding, Evidence, Severity  -- the structured detection output
    HuntConfig                   -- tunable thresholds
    run_hunt(), HuntResult       -- execution
    all_detectors(), get_detector(), registered_rule_ids()

Nothing in this package reads ``ground_truth.json``. Detections must stand on the
telemetry alone; labels are for measuring them afterwards.
"""

from ath.hunting.base import (
    Detector,
    HuntConfig,
    all_detectors,
    get_detector,
    registered_rule_ids,
)
from ath.hunting.engine import HuntResult, run_hunt
from ath.hunting.finding import Evidence, Finding, Severity, findings_to_frame

__all__ = [
    "Detector",
    "HuntConfig",
    "all_detectors",
    "get_detector",
    "registered_rule_ids",
    "HuntResult",
    "run_hunt",
    "Evidence",
    "Finding",
    "Severity",
    "findings_to_frame",
]
