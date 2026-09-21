"""One corpus through the deterministic layer, and the footing every row must match.

These are the M19-era helpers the runner used to import from ``scripts/m19_ablation.py``,
``scripts/m19b_ablation.py``, ``scripts/m19b_manifest.py`` and
``scripts/m19b_necessity_audit.py``. They are copied here rather than imported so the
package has no dependency on script module bodies; ``tests/test_experiments_frozen_parity.py``
holds every copy to its original on the fixture corpus. None of the originals is
hash-pinned, but they are the frozen milestones' code and are not edited.
"""

from __future__ import annotations

import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ath.correlation import correlate
from ath.correlation.chain import InvestigationCase
from ath.environment import build_environment_model
from ath.evaluation.ablation import STEP_BUDGET, TOOL_CALL_CAP, ArmConfig
from ath.evaluation.ablation.environment import sha256_text
from ath.evaluation.incidents import Incident, score_labels
from ath.hunting import HuntConfig, run_hunt
from ath.hunting.finding import Finding
from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS
from ath.telemetry.loader import Telemetry
from ath.triage import assess_findings, set_aside_ids

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_EXTERNAL = ROOT / "data" / "external"


@dataclass
class Bundle:
    """One corpus: its telemetry, everything the deterministic layer made of it."""

    name: str
    telemetry: Telemetry
    findings: list[Finding]
    cases: list[InvestigationCase]
    environment: Any
    assessments: dict[str, Any] = field(default_factory=dict)
    """The triage assessment per finding id -- part of the deterministic layer, and an
    input to the label scores, which are graded per finding rather than per case."""
    labels: dict[str, dict[str, Any]] = field(default_factory=dict)
    incident: Incident | None = None
    load_seconds: float = 0.0
    pipeline_seconds: float = 0.0


def pipeline(
    telemetry: Telemetry,
) -> tuple[list[Finding], list[InvestigationCase], Any, dict[str, Any]]:
    """Hunt, triage, correlate -- exactly as ``run_incident`` and the M18 scripts do.

    Returns the assessments as well as the cases: they are what the label scores grade
    benign discrimination against, and re-deriving them beside the row would be a second
    copy of the triage layer for the scoring path to drift from.
    """
    hunt = run_hunt(telemetry, config=HuntConfig())
    environment = build_environment_model(telemetry)
    assessments = assess_findings(hunt.findings, environment)
    cases = correlate(
        hunt.findings, telemetry, set_aside=set_aside_ids(assessments)
    )
    return list(hunt.findings), list(cases), environment, dict(assessments)


def label_scorer(bundle: Any):
    """Grade this corpus's rows against its answer key, or nothing if it has none.

    The closure carries the answer key and the corpus's deterministic layer -- the
    incident, its findings, its triage assessments -- and is handed the row's own
    investigation state by the runner. One investigation per row, graded where it ran.
    """
    incident = getattr(bundle, "incident", None)
    if incident is None:
        return None

    def scorer(state: Any) -> dict[str, Any]:
        return score_labels(
            incident, bundle.findings, bundle.assessments, state,
        ).to_dict()

    return scorer


def required_footing_for(
    arm: ArmConfig, telemetry_digest: str, surface: Sequence[str],
) -> dict[str, Any]:
    """The footing every row of this corpus must match, in T6's own shape.

    Built from the **frozen** tool surface and the **pinned** telemetry hash, so the
    per-row assertion compares what the run is doing against what the freeze and the
    manifest said -- rather than against itself.
    """
    return {
        "tool_surface_sha256": sha256_text("\n".join(surface)),
        "tools": len(surface),
        "tool_call_cap": TOOL_CALL_CAP,
        "max_steps": STEP_BUDGET,
        "telemetry_hash": telemetry_digest,
        "requires_model": arm.requires_model,
        "generalist": arm.generalist,
    }


# -- loading ------------------------------------------------------------------------------


def telemetry_of(tables: dict[str, Any]) -> Telemetry:
    """Canonical telemetry from an adapter's tables, tolerating the ones it omits."""
    import pandas as pd

    from ath.schema import TABLE_COLUMNS

    def table(event_type: str) -> Any:
        frame = tables.get(event_type)
        if frame is None:
            return pd.DataFrame(columns=list(TABLE_COLUMNS[event_type]))
        return frame

    return Telemetry(
        processes=table(EVENT_PROCESS), network=table(EVENT_NETWORK),
        logons=table(EVENT_LOGON), controls=table(EVENT_CONTROL),
    )


def winlogbeat_telemetry(directory: Path) -> Telemetry:
    from ath.telemetry.winlogbeat_source import WinlogbeatSource

    return telemetry_of(WinlogbeatSource(directory).load().tables)


def cloudtrail_telemetry(directory: Path) -> Telemetry:
    from ath.telemetry.cloudtrail_source import CloudTrailSource

    return telemetry_of(CloudTrailSource(directory).load().tables)


def bundle_from_telemetry(name: str, telemetry: Telemetry, *, load_seconds: float = 0.0) -> Bundle:
    started = time.perf_counter()
    findings, cases, environment, assessments = pipeline(telemetry)
    return Bundle(
        name=name, telemetry=telemetry, findings=findings, cases=cases,
        environment=environment, assessments=assessments, load_seconds=load_seconds,
        pipeline_seconds=time.perf_counter() - started,
    )


def flaws_bundle(external: Path = DEFAULT_EXTERNAL) -> Bundle:
    """flaws.cloud through the same CloudTrail adapter ``scripts/m18_cloud_detection`` used."""
    started = time.perf_counter()
    telemetry = cloudtrail_telemetry(Path(external) / "flaws_cloud" / "raw")
    return bundle_from_telemetry(
        "flaws_cloud", telemetry, load_seconds=time.perf_counter() - started,
    )


def winlogbeat_bundle(name: str, directory: Path) -> Bundle:
    started = time.perf_counter()
    telemetry = winlogbeat_telemetry(directory)
    return bundle_from_telemetry(name, telemetry, load_seconds=time.perf_counter() - started)


def synthetic_bundles() -> Iterator[Bundle]:
    """Every standard-suite incident, each through the pipeline, as M19 loaded them."""
    from ath.evaluation.suite import standard_suite

    for incident in standard_suite(
        ROOT / "data" / "raw",
        ROOT / "tests" / "fixtures" / "cloudtrail",
        ROOT / "tests" / "fixtures" / "k8s_audit",
    ):
        started = time.perf_counter()
        findings, cases, environment, assessments = pipeline(incident.telemetry)
        yield Bundle(
            name=f"synthetic:{incident.incident_id}",
            telemetry=incident.telemetry,
            findings=findings, cases=cases, environment=environment,
            assessments=assessments,
            incident=incident,
            labels={c.case_id: {"incident_id": incident.incident_id} for c in cases},
            pipeline_seconds=time.perf_counter() - started,
        )


def select_synthetic(bundle: Bundle) -> tuple[list[InvestigationCase], str, dict[str, Any]]:
    """Which of a synthetic corpus's cases go in a manifest, and why (M19's rule)."""
    incident = bundle.incident
    assert incident is not None
    if not bundle.cases:
        return [], "no case was raised for this incident", {}
    malicious = set(incident.malicious_event_ids)
    target = (
        max(bundle.cases, key=lambda c: len(set(c.event_ids) & malicious))
        if malicious else max(bundle.cases, key=lambda c: len(c.findings))
    )
    return (
        [target],
        "the case run_incident investigates for this incident",
        {"cases_in_corpus": len(bundle.cases)},
    )
