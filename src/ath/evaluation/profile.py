"""What the pipeline does to a dataset that has no answer key.

Most real telemetry has no labels, and the questions that can still be asked of it are
exactly the ones a SOC would ask before trusting an automation: how many findings per
day, how many of them become cases, how many of those an analyst would actually have to
open, and how long the machinery takes as the data grows. None of that needs ground
truth. This module measures it, so an unlabelled dataset gets a row in the M14
evaluation table with its label-dependent columns honestly blank rather than no row.

Everything here is a measurement of existing layers; it adds no detection, no triage
signal and no agent. The timings are the E8 scaling experiment: they are taken per stage
so the pairwise correlator can be told apart from the linear stages when the event
count grows.
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from ath.correlation import correlate
from ath.environment import build_environment_model
from ath.hunting import HuntConfig, run_hunt
from ath.telemetry.loader import Telemetry
from ath.triage import assess_findings


@dataclass
class DatasetProfile:
    """Label-free measurements of one telemetry set through hunt, triage and correlation."""

    # -- what was there -------------------------------------------------------------
    events: int = 0
    events_by_table: dict[str, int] = field(default_factory=dict)
    window_hours: float = 0.0
    hosts: int = 0
    identities: int = 0
    platforms: tuple[str, ...] = ()

    # -- what the rules said --------------------------------------------------------
    findings: int = 0
    findings_by_rule: dict[str, int] = field(default_factory=dict)
    findings_by_severity: dict[str, int] = field(default_factory=dict)

    # -- what triage could do -------------------------------------------------------
    dispositions: dict[str, int] = field(default_factory=dict)
    findings_after_triage: int = 0
    """Findings not dispositioned ``likely_benign``: what an analyst still has to look at."""

    # -- what correlation made of it ------------------------------------------------
    cases: int = 0
    singleton_cases: int = 0
    links: int = 0

    # -- cost (E8) ------------------------------------------------------------------
    seconds_hunt: float = 0.0
    seconds_environment: float = 0.0
    seconds_triage: float = 0.0
    seconds_correlate: float = 0.0

    @property
    def window_days(self) -> float:
        return self.window_hours / 24.0

    @property
    def findings_per_day(self) -> float:
        return self.findings / self.window_days if self.window_days else 0.0

    @property
    def cases_per_day(self) -> float:
        return self.cases / self.window_days if self.window_days else 0.0

    @property
    def findings_per_host_day(self) -> float:
        denominator = self.window_days * self.hosts
        return self.findings / denominator if denominator else 0.0

    @property
    def triage_load_reduction(self) -> float:
        if not self.findings:
            return 0.0
        return 1.0 - (self.findings_after_triage / self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "telemetry": {
                "events": self.events,
                "events_by_table": dict(self.events_by_table),
                "window_hours": round(self.window_hours, 2),
                "window_days": round(self.window_days, 2),
                "hosts": self.hosts,
                "identities": self.identities,
                "platforms": list(self.platforms),
            },
            "detection": {
                "findings": self.findings,
                "by_rule": dict(self.findings_by_rule),
                "by_severity": dict(self.findings_by_severity),
                "findings_per_day": round(self.findings_per_day, 4),
                "findings_per_host_day": round(self.findings_per_host_day, 4),
            },
            "triage": {
                "dispositions": dict(self.dispositions),
                "findings_after_triage": self.findings_after_triage,
                "triage_load_reduction": round(self.triage_load_reduction, 4),
            },
            "correlation": {
                "cases": self.cases,
                "singleton_cases": self.singleton_cases,
                "links": self.links,
                "cases_per_day": round(self.cases_per_day, 4),
            },
            "cost_seconds": {
                "hunt": round(self.seconds_hunt, 3),
                "environment": round(self.seconds_environment, 3),
                "triage": round(self.seconds_triage, 3),
                "correlate": round(self.seconds_correlate, 3),
            },
        }


def profile_telemetry(telemetry: Telemetry, config: HuntConfig | None = None) -> DatasetProfile:
    """Run hunt, environment, triage and correlation over ``telemetry`` and measure."""
    profile = DatasetProfile()
    profile.events = telemetry.event_count
    profile.events_by_table = {
        "process": len(telemetry.processes), "network": len(telemetry.network),
        "logon": len(telemetry.logons), "control": len(telemetry.controls),
    }
    if profile.events:
        start, end = telemetry.time_range
        profile.window_hours = float((end - start).total_seconds()) / 3600.0

    t0 = time.perf_counter()
    hunt = run_hunt(telemetry, config=config or HuntConfig())
    profile.seconds_hunt = time.perf_counter() - t0
    profile.findings = len(hunt.findings)
    profile.findings_by_rule = dict(Counter(f.rule_id for f in hunt.findings))
    profile.findings_by_severity = dict(Counter(f.severity.value for f in hunt.findings))

    t0 = time.perf_counter()
    environment = build_environment_model(telemetry)
    profile.seconds_environment = time.perf_counter() - t0
    profile.hosts = len(environment.hosts)
    profile.identities = len(environment.identities)
    profile.platforms = tuple(sorted(str(p) for p in environment.platforms))

    t0 = time.perf_counter()
    assessments = assess_findings(hunt.findings, environment)
    profile.seconds_triage = time.perf_counter() - t0
    dispositions = Counter(a.disposition.value for a in assessments.values())
    profile.dispositions = dict(dispositions)
    profile.findings_after_triage = profile.findings - dispositions.get("likely_benign", 0)

    t0 = time.perf_counter()
    cases = correlate(hunt.findings, telemetry)
    profile.seconds_correlate = time.perf_counter() - t0
    profile.cases = len(cases)
    profile.singleton_cases = sum(1 for c in cases if len(c.findings) == 1)
    profile.links = sum(len(c.findings) - 1 for c in cases)
    return profile
