"""Triage must be tested at the severities the rules actually emit.

RC5 in docs/test-quality-root-causes.md: the benign layer defers to the rule at HIGH and
above, the existing triage tests exercise LOW and MEDIUM, and every cloud and Kubernetes
rule plus ATH-004 emit HIGH+. On four real sources the layer cleared 0 of 124 findings.
These tests pin that boundary explicitly, per emitted severity, so the design decision
behind it (M15-4) is a visible line in the suite rather than an implicit one.

M15-4 determination: the boundary stays. Of the 124 vetoed findings, 115 were
detection-precision false positives that no longer exist (M15-1, M15-3) and the rest were
ATH-005 bursts graded HIGH without meeting the rule's own success condition (M15-2, now
MEDIUM). With those fixed, no finding on a benign real-shaped corpus is HIGH+, so the veto
blocks nothing there; tests/test_real_shaped_corpus.py pins that per corpus. What the
layer still lacks is benign evidence of a logon shape, which is a signal gap, not a
boundary problem.
"""

from __future__ import annotations

import dataclasses

import pytest

from ath.environment import build_environment_model
from ath.hunting import run_hunt
from ath.hunting.base import all_detectors
from ath.hunting.finding import Severity
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import load_telemetry
from ath.triage import Disposition, assess_findings

EMITTED = sorted({det.severity for det in all_detectors()}, key=lambda s: list(Severity).index(s))


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    out = tmp_path_factory.mktemp("triage_sev")
    tables, gt = generate_telemetry(GeneratorConfig(seed=5))
    write_telemetry(tables, gt, out)
    telemetry = load_telemetry(out)
    return telemetry, run_hunt(telemetry).findings, build_environment_model(telemetry)


def test_rules_emit_severities_the_triage_layer_must_be_tested_at() -> None:
    """The set is the contract: add a severity here only with a test below."""
    assert set(EMITTED) == {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}


@pytest.fixture(scope="module")
def benign_lookalike(world):
    """The shipped benign look-alike: the IT administrator's encoded PowerShell (ATH-002,
    MEDIUM), which triage clears today. Used as the probe at every emitted severity."""
    telemetry, findings, environment = world
    assessments = assess_findings(findings, environment)
    cleared = [f for f in findings if assessments[f.finding_id].disposition is Disposition.LIKELY_BENIGN]
    assert cleared, "the generator's benign look-alike is no longer cleared; this probe needs it"
    return cleared[0]


@pytest.mark.parametrize("severity", EMITTED, ids=[s.value for s in EMITTED])
def test_pinned_veto_boundary_per_emitted_severity(world, benign_lookalike, severity) -> None:
    """The identical benign evidence, re-graded: cleared at MEDIUM, vetoed at HIGH+.

    This pins the boundary as it stands. Whether the layer *should* defer at HIGH is the
    M15-4 decision; the strict xfail in tests/test_real_shaped_corpus.py states the target."""
    telemetry, findings, environment = world
    probe = dataclasses.replace(benign_lookalike, severity=severity)
    assessment = assess_findings([probe], environment)[probe.finding_id]
    if severity in (Severity.HIGH, Severity.CRITICAL):
        assert assessment.disposition is Disposition.LIKELY_MALICIOUS
        assert any(v.name == "graded_high_by_detection" for v in assessment.vetoes)
    else:
        assert assessment.disposition is Disposition.LIKELY_BENIGN


def test_every_high_plus_rule_is_therefore_untriageable_today() -> None:
    """Names the rules whose findings the benign layer can never explain as things stand."""
    untriageable = sorted(d.rule_id for d in all_detectors() if d.severity in (Severity.HIGH, Severity.CRITICAL))
    assert untriageable == [
        "ATH-001", "ATH-004", "ATH-005", "ATH-006", "ATH-007", "ATH-011", "ATH-012",
        "AWS-001", "AWS-002", "K8S-001", "K8S-002",
    ]
