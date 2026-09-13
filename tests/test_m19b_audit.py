"""M19b T4: the necessity audit must describe the pipeline, not a model of it.

Three things are asserted, and each of them is a way the audit could be wrong while
still looking right.

*The simulation could be describing a different pipeline.* ``reports/m19b/necessity/
AUDIT.json`` reports, per case, the specialists that were eligible over a whole
deterministic run. M19's arm A recorded exactly that number, months and several commits
earlier, under the name ``specialists_eligible``. If the two disagree on any case then
either the audit is not running what arm A ran or the pipeline has drifted since -- and
both of those make every other number in the audit unreadable, so the disagreement must
fail loudly rather than be discovered by a reader comparing two files by eye.

*The audit could be silently incomplete.* A corpus that fails to load returns an
``UNAVAILABLE`` row rather than raising, which is right for a script and dangerous for a
report: an audit missing half its cases still renders. So every case M19 pinned in its
manifest must appear.

*The test itself could be circular.* The qualification rule is asserted twice: once as a
property of the committed artifact, and once by building a one-domain case in memory and
putting it through :func:`ath.evaluation.necessity.audit_case`, so the rule is checked
against the code and not only against the code's output.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from _builders import failures
from _builders import telemetry as telemetry_of
from ath.correlation.chain import InvestigationCase
from ath.environment import build_environment_model
from ath.evaluation.necessity import (
    DOMAIN_SPECIALISTS,
    STEP_BUDGET,
    audit_case,
    channel_domains,
)
from ath.hunting import HuntConfig, run_hunt
from ath.telemetry.loader import Telemetry

ROOT = Path(__file__).resolve().parent.parent
AUDIT_PATH = ROOT / "reports" / "m19b" / "necessity" / "AUDIT.json"
ARM_A_PATH = ROOT / "reports" / "m19" / "ablation" / "arm_A.json"
MANIFEST_PATH = ROOT / "reports" / "m19" / "ablation" / "MANIFEST.json"


def _load(path: Path) -> dict:
    if not path.is_file():
        pytest.skip(f"{path.relative_to(ROOT)} has not been generated in this checkout")
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def audit() -> dict:
    return _load(AUDIT_PATH)


@pytest.fixture(scope="module")
def audited_cases(audit: dict) -> dict[tuple[str, str], dict]:
    return {
        (corpus["corpus"], case["case_id"]): case
        for corpus in audit["corpora"]
        for case in corpus["cases_detail"]
    }


def test_step_budget_matches_the_arm_it_claims_to_reproduce() -> None:
    """The audit's walk is arm A's walk, or it is not arm A's number."""
    from ath.evaluation.ablation.arms import STEP_BUDGET as ARM_STEP_BUDGET

    assert STEP_BUDGET == ARM_STEP_BUDGET


def test_eligibility_simulation_agrees_with_arm_a(audited_cases: dict) -> None:
    """Every M19 case's ``specialists_eligible``, as arm A recorded it."""
    arm_a = _load(ARM_A_PATH)
    mismatches = []
    missing = []
    for row in arm_a["cases"]:
        key = (row["corpus"], row["case_id"])
        recorded = row["scores"]["completeness"]["specialists_eligible"]
        case = audited_cases.get(key)
        if case is None:
            missing.append(key)
            continue
        if case["whole_run_specialists_eligible"] != recorded:
            mismatches.append(
                f"{key}: audit says {case['whole_run_specialists_eligible']} "
                f"({', '.join(case['whole_run_eligible'])}), arm A recorded {recorded}"
            )
    assert not missing, f"arm A cases absent from the audit: {missing}"
    assert not mismatches, "\n".join(mismatches)


def test_audit_covers_every_m19_manifest_case(audited_cases: dict) -> None:
    manifest = _load(MANIFEST_PATH)
    absent = [
        (entry["corpus"], entry["case_id"])
        for entry in manifest["cases"]
        if (entry["corpus"], entry["case_id"]) not in audited_cases
    ]
    assert not absent, f"manifest cases with no audit entry: {absent}"


def test_one_domain_case_is_never_qualifying(audited_cases: dict) -> None:
    """The rule the whole audit rests on, checked over every case it produced."""
    offenders = [
        key for key, case in audited_cases.items()
        if case["qualifies"] and len(case["domains"]) < 2
    ]
    assert not offenders, f"cases marked qualifying with fewer than two domains: {offenders}"

    # The same rule expressed against the orchestrator's own eligibility, which is the
    # fact M19 measured: a case offering the planner one domain specialist is a case
    # where there was nothing to plan.
    offenders = [
        key for key, case in audited_cases.items()
        if case["qualifies"] and case["first_step_domain_specialists"] < 2
    ]
    assert not offenders, (
        "cases marked qualifying while only one domain specialist was eligible at the "
        f"first step: {offenders}"
    )


def test_qualifying_cases_satisfy_all_three_conditions(audited_cases: dict) -> None:
    for key, case in audited_cases.items():
        if not case["qualifies"]:
            assert case["failure_reason"], f"{key} fails the test without saying why"
            continue
        assert case["two_domains"], key
        assert case["non_redundant"], key
        assert case["synthesis_could_change"], key
        assert case["independent_evidence_sources"] >= 1, key


def _one_domain_case() -> tuple[InvestigationCase, Telemetry, list]:
    """A case whose every finding is authentication evidence.

    Built from a real rule firing on real-shaped rows rather than from a hand-written
    ``Finding``: the audit reads ``fields_used`` and ``channels``, which are precisely
    the fields a fabricated finding would get to choose for itself.
    """
    data = telemetry_of(logons=failures("alice", "SRV01", "203.0.113.9", 12))
    findings = list(run_hunt(data, config=HuntConfig()).findings)
    assert findings, "the authentication rule did not fire on this fixture"
    case = InvestigationCase(case_id="CASE-ONE-DOMAIN", findings=tuple(findings))
    return case, data, findings


def test_audit_case_refuses_to_qualify_a_single_domain_case() -> None:
    """The rule, checked against the code rather than against the code's output."""
    case, data, findings = _one_domain_case()
    environment = build_environment_model(data)
    result = audit_case(
        case, corpus="unit", provenance="synthetic (generated by this repository)",
        telemetry=data, findings=findings, cases=[case], environment=environment,
    )
    assert result.domains == ("identity",)
    assert result.first_step_domain_specialists == 1
    assert not result.qualifies
    assert not result.two_domains
    assert "one domain only" in result.failure_reason
    assert result.synthesis_statement.startswith("It could not")


def test_channel_domains_reads_the_specialists_own_declarations() -> None:
    """The domain map is derived, so a new channel on a specialist cannot go stale."""
    from ath.agent.specialists import EndpointAgent, IdentityAgent

    assert channel_domains(EndpointAgent.triggered_by_channels) == {"endpoint"}
    assert "identity" in channel_domains(IdentityAgent.triggered_by_channels)
    assert set(DOMAIN_SPECIALISTS) == {
        "endpoint", "identity", "network", "control_plane",
    }
    assert "attack" not in DOMAIN_SPECIALISTS
