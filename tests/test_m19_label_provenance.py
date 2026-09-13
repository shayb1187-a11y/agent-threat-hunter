"""A row's label-based scores must describe the row's own investigation.

The failure this file is about
-------------------------------
The M19 ablation obtained its synthetic rows' ``label_scores`` by calling
``ath.evaluation.incidents.run_incident`` a second time, inside ``cmd_run``, after the
arm had already investigated the case. That second call ran a *different* investigation:
its own :class:`~ath.agent.tools.ToolBox`, uncapped, with the environment-assembled
specialist crew rather than the arm's. For arm B -- one generalist under a 40-call cap --
the label scores were therefore arm C's architecture wearing arm B's label, and the
tokens the second investigation spent appeared in no cost column at all.

For arm A the two investigations happen to be the same run, which is exactly why the
defect was invisible: every published number was right, and would have stayed right until
the first model arm ran.

How each fails
---------------
*Equality under arm A.* :func:`score_labels` on an arm-A row's own state must equal what
``run_incident`` reports for the same incident, field by field, on all four synthetic
incidents. Fails if the shared function is not in fact the definition the benchmark uses
-- which would make the ablation's rows incomparable with every benchmark row this
project has published.

*No second investigation.* ``cmd_run`` must not import or call ``run_incident``. Fails
if the convenience is ever restored; the prose in the module still names it, so the
assertion is on the module's namespace and on ``cmd_run``'s own source.

*The row says whose scores these are.* A scripted arm B row's ``label_scores`` must name
arm B. Fails if the identity is taken from anything other than the row -- as it was when
it came from a separate client built for a separate run, where B and C produced the same
string.
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

from ath.agent.claims import ClaimVerifier
from ath.agent.tools import ToolBox
from ath.correlation import correlate
from ath.environment import build_environment_model
from ath.evaluation.ablation import CaseResult, arm_a, arm_b, build_manifest, run_arm
from ath.evaluation.incidents import run_incident, score_labels
from ath.evaluation.suite import standard_suite
from ath.hunting import HuntConfig, run_hunt
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.triage import assess_findings, set_aside_ids

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import m19_ablation  # noqa: E402
from m19_ablation import ScriptedArmLLM  # noqa: E402

CLOUDTRAIL = Path(__file__).parent / "fixtures" / "cloudtrail"
K8S_AUDIT = Path(__file__).parent / "fixtures" / "k8s_audit"


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory):
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("label_provenance")
    write_telemetry(tables, gt, out)
    return out


@pytest.fixture(scope="module")
def incidents(data_dir):
    return standard_suite(data_dir, CLOUDTRAIL, K8S_AUDIT)


def _pipeline(telemetry):
    """The deterministic layer, as both the ablation and ``run_incident`` run it."""
    hunt = run_hunt(telemetry, config=HuntConfig())
    environment = build_environment_model(telemetry)
    assessments = assess_findings(hunt.findings, environment)
    cases = correlate(
        hunt.findings, telemetry, set_aside=set_aside_ids(assessments)
    )
    return list(hunt.findings), list(cases), environment, dict(assessments)


def _arm_a_row(incident) -> CaseResult:
    """One arm-A row for the case ``run_incident`` investigates for this incident."""
    findings, cases, environment, assessments = _pipeline(incident.telemetry)
    malicious = set(incident.malicious_event_ids)
    target = (
        max(cases, key=lambda c: len(set(c.event_ids) & malicious)) if malicious
        else max(cases, key=lambda c: len(c.findings))
    )
    manifest = build_manifest(
        f"synthetic:{incident.incident_id}", incident.telemetry, [target],
    )
    rows = run_arm(
        arm_a(), manifest, incident.telemetry, cases,
        findings=findings, environment=environment,
        label_scorer=lambda state: score_labels(
            incident, findings, assessments, state,
        ).to_dict(),
    )
    return rows[0]


# --------------------------------------------------------------------------------------
# One definition, two callers
# --------------------------------------------------------------------------------------


def test_arm_a_label_scores_equal_the_benchmark_outcome(incidents) -> None:
    """The shared function, on the row's own state, is the benchmark's own verdict."""
    graded = 0
    for incident in incidents:
        outcome = run_incident(incident)
        if not outcome.cases:
            continue  # no case, no row: this incident is not in the manifest
        row = _arm_a_row(incident)
        labels = row.label_scores
        assert labels["incident_id"] == incident.incident_id
        assert labels["passed"] is outcome.passed
        assert labels["event_recall"] == round(outcome.event_recall, 4)
        assert labels["trustworthy"] is outcome.trustworthy
        assert labels["hallucinated_citations"] == outcome.hallucinated_citations
        assert labels["calibration_warnings"] == outcome.calibration_warnings
        assert labels["overclaimed_as_fact"] == list(outcome.overclaimed_as_fact)
        assert labels["techniques_missing"] == list(outcome.techniques_missing)
        assert labels["conclusions_missed"] == list(outcome.conclusions_missed)
        graded += 1
    assert graded == 4, f"expected the four manifest incidents, graded {graded}"


def test_the_label_scores_say_where_they_came_from(incidents) -> None:
    """Provenance is in the record: an older file's figures came from another run."""
    row = _arm_a_row(incidents[0])
    assert row.label_scores["computed_from"] == "this row's own investigation state"
    assert row.label_scores["investigated"] is True


def test_an_unlabelled_corpus_carries_no_label_column(incidents) -> None:
    """No answer key, no column -- never a false zero."""
    findings, cases, environment, _assessments = _pipeline(incidents[0].telemetry)
    manifest = build_manifest("unlabelled", incidents[0].telemetry, cases[:1])
    rows = run_arm(
        arm_a(), manifest, incidents[0].telemetry, cases,
        findings=findings, environment=environment, label_scorer=None,
    )
    assert rows[0].label_scores == {}


# --------------------------------------------------------------------------------------
# The second investigation is gone
# --------------------------------------------------------------------------------------


def test_cmd_run_neither_imports_nor_calls_run_incident() -> None:
    assert not hasattr(m19_ablation, "run_incident"), (
        "the ablation imported run_incident again: a second investigation of the same "
        "incident, with its own toolbox and its own crew, graded as if it were the row"
    )
    source = inspect.getsource(m19_ablation.cmd_run)
    assert "run_incident" not in source
    assert "label_scorer" in source


def test_the_label_scorer_is_none_for_a_corpus_without_an_incident() -> None:
    bundle = m19_ablation.Bundle(
        name="flaws_cloud", telemetry=None, findings=[], cases=[], environment=None,
    )
    assert m19_ablation._label_scorer(bundle) is None


# --------------------------------------------------------------------------------------
# The row names its own arm
# --------------------------------------------------------------------------------------


def test_a_scripted_arm_b_row_names_arm_b_not_the_crew(incidents) -> None:
    incident = incidents[0]
    findings, cases, environment, assessments = _pipeline(incident.telemetry)
    malicious = set(incident.malicious_event_ids)
    target = max(cases, key=lambda c: len(set(c.event_ids) & malicious))
    manifest = build_manifest(
        f"synthetic:{incident.incident_id}", incident.telemetry, [target],
    )

    rows = run_arm(
        arm_b(), manifest, incident.telemetry, cases,
        findings=findings, environment=environment,
        llm=ScriptedArmLLM(), scripted=True,
        label_scorer=lambda state: score_labels(
            incident, findings, assessments, state,
        ).to_dict(),
    )

    labels = rows[0].label_scores
    assert labels["arm"] == "B_single_llm_SCRIPTED"
    assert "C_crew" not in labels["arm"]
    assert labels["configuration"] == "scripted-harness"
    assert labels["llm_degraded"] is rows[0].llm_degraded
    # And the figures are this row's: one generalist under the 40-call cap, not the
    # crew's uncapped walk.
    assert rows[0].budgets["tool_call_cap"] == 40
