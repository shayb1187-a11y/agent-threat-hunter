"""The generalist investigator -- arm B's agent, and the properties that make it fair.

What each group is for, and how it fails
-----------------------------------------
*Claims.* The generalist authors FACTs and nothing else, each citing evidence that the
verifier recognises. These fail if it starts inferring (which would make arm B's
inference count a mix of agent and model, destroying the only thing arm B measures) or
if it cites an id no telemetry carries.

*Resumption.* The step budget only means anything if the agent actually resumes. This
fails if ``investigate`` restarts the walk each step (in which case two steps cover no
more than one) or if it walks everything in one step (in which case the step budget is
not a budget).

*Determinism.* Arm B must be comparable with arm A, which is reproducible by
construction. This fails the moment a set is iterated or a dict ordered by one.

*Identity.* A finding that names a process instance must be walked by that instance
(M18b-2). This fails if the generalist falls back to the pid slot -- which would lose
the comparison for a reason that says nothing about single-agent versus crew.

*Budgets.* At a cap of zero the agent claims nothing and crashes nothing.
"""

from __future__ import annotations

import pytest

from _builders import at, proc, telemetry as build_telemetry
from ath.agent.claims import ClaimType, ClaimVerifier
from ath.agent.generalist import GeneralistAgent
from ath.agent.llm import NullLLM
from ath.agent.orchestrator import InvestigationConfig, InvestigationOrchestrator
from ath.agent.state import InvestigationState
from ath.agent.tools import ToolBox
from ath.correlation import correlate
from ath.correlation.chain import InvestigationCase
from ath.hunting import Evidence, Finding, Severity, run_hunt
from ath.instance_identity import start_identity
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import load_telemetry


@pytest.fixture(scope="module")
def telemetry(tmp_path_factory):
    """The synthetic Windows intrusion -- the corpus behind INC-001."""
    tables, ground_truth = generate_telemetry(GeneratorConfig())
    directory = tmp_path_factory.mktemp("generalist")
    write_telemetry(tables, ground_truth, directory)
    return load_telemetry(directory)


@pytest.fixture(scope="module")
def pipeline(telemetry):
    hunt = run_hunt(telemetry)
    cases = correlate(hunt.findings, telemetry)
    return list(hunt.findings), list(cases)


@pytest.fixture(scope="module")
def intrusion_case(pipeline):
    _findings, cases = pipeline
    return max(cases, key=lambda c: len(c.findings))


def _agent(telemetry, pipeline, budget=None, items_per_step=5):
    findings, cases = pipeline
    tools = ToolBox(telemetry, findings, cases, tool_call_budget=budget)
    return GeneralistAgent(tools, items_per_step=items_per_step), tools


def _run_to_exhaustion(agent, state, max_steps=8):
    results = []
    for _ in range(max_steps):
        should, _reason = agent.should_run(state)
        if not should:
            break
        results.append(agent.investigate(state))
        state.step += 1
        state.agents_run.append(agent.name)
    return results


# --------------------------------------------------------------------------------------
# Claims
# --------------------------------------------------------------------------------------


def test_it_emits_facts_and_only_facts(telemetry, pipeline, intrusion_case) -> None:
    """Inference in arm B comes from the model. Without one, arm B infers nothing.

    Fails if the generalist ever authors an INFERENCE or HYPOTHESIS of its own, which
    would put agent-authored inferences in the same column as model-authored ones.
    """
    agent, _tools = _agent(telemetry, pipeline)
    state = InvestigationState(case=intrusion_case)

    results = _run_to_exhaustion(agent, state)

    claims = [c for r in results for c in r.claims]
    assert claims, "the generalist must produce something on a 13-finding case"
    assert {c.claim_type for c in claims} == {ClaimType.FACT}


def test_every_claim_it_makes_verifies(telemetry, pipeline, intrusion_case) -> None:
    """Fails if a claim cites an id the telemetry does not contain."""
    agent, _tools = _agent(telemetry, pipeline)
    state = InvestigationState(case=intrusion_case)
    verifier = ClaimVerifier(telemetry)

    results = _run_to_exhaustion(agent, state)

    for claim in (c for r in results for c in r.claims):
        assert verifier.check(claim) is None, claim.statement
        assert claim.evidence_ids, "a FACT without evidence cannot exist"


def test_it_uses_the_whole_tool_surface(telemetry, pipeline, intrusion_case) -> None:
    """A generalist that calls two tools would lose the comparison for the wrong reason."""
    agent, tools = _agent(telemetry, pipeline)
    state = InvestigationState(case=intrusion_case)

    _run_to_exhaustion(agent, state)

    used = {call.tool for call in tools.calls_by("generalist")}
    assert {"get_case", "get_finding", "get_events", "process_tree"} <= used


def test_a_step_reports_only_its_own_tool_calls(
    telemetry, pipeline, intrusion_case
) -> None:
    """The cumulative-count defect M19-2 corrected in the M18 script, in miniature.

    ``Specialist._result`` attaches every call the agent has ever made, which is correct
    for an agent that runs once and wrong for one that resumes. Fails if the generalist
    uses it: step two would re-report step one's calls and the arm's tool-call column
    would be a triangular number.
    """
    agent, tools = _agent(telemetry, pipeline, items_per_step=2)
    state = InvestigationState(case=intrusion_case)

    results = _run_to_exhaustion(agent, state)

    reported = sum(len(r.tool_calls) for r in results)
    assert reported == len(tools.calls_by("generalist")) == tools.call_count
    assert len(results) > 1, "this case must take more than one step to be a test"


# --------------------------------------------------------------------------------------
# Resumption and determinism
# --------------------------------------------------------------------------------------


def test_two_steps_cover_more_entities_than_one(
    telemetry, pipeline, intrusion_case
) -> None:
    """Fails if the walk restarts each step, or if it finishes in one."""
    agent, tools = _agent(telemetry, pipeline, items_per_step=3)
    state = InvestigationState(case=intrusion_case)

    agent.investigate(state)
    after_one = len(tools.calls_by("generalist"))
    agent.investigate(state)
    after_two = len(tools.calls_by("generalist"))

    assert 0 < after_one < after_two
    assert after_two <= 6, "a step must not walk more than items_per_step entities"


def test_it_stops_when_the_case_is_walked_out(
    telemetry, pipeline, intrusion_case
) -> None:
    """The stopping rule is the queue, not the step budget."""
    agent, _tools = _agent(telemetry, pipeline)
    state = InvestigationState(case=intrusion_case)

    _run_to_exhaustion(agent, state, max_steps=40)

    should, reason = agent.should_run(state)
    assert should is False
    assert "walked" in reason


def test_two_runs_of_the_same_case_are_identical(
    telemetry, pipeline, intrusion_case
) -> None:
    """Fails on any set iteration in the walk order or in a claim's evidence."""
    def transcript():
        agent, tools = _agent(telemetry, pipeline)
        state = InvestigationState(case=intrusion_case)
        results = _run_to_exhaustion(agent, state)
        return (
            [(c.claim_type.value, c.statement, c.evidence_ids)
             for r in results for c in r.claims],
            [(call.tool, sorted(call.arguments)) for call in tools.calls],
        )

    assert transcript() == transcript()


# --------------------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------------------


def test_a_finding_that_names_an_instance_is_walked_by_that_instance() -> None:
    """M18b-2: the identity, not the slot.

    Fails if the generalist hands ``process_tree`` a pid when the finding carried a
    ``process_guid`` -- on a corpus where one pid was held by several processes, that is
    the difference between one run's lineage and a chain assembled from strangers.
    """
    device, pid = "PC09", 4444
    identity = start_identity(device, pid, at(0))
    rows = [
        proc("cmd.exe", "cmd.exe /c one", "explorer.exe", device=device, user="operator",
             when=at(0), pid=pid, ppid=1000, guid=identity),
        proc("powershell.exe", "powershell -enc AAA", "cmd.exe", device=device,
             user="operator", when=at(1), pid=5555, ppid=pid, parent_guid=identity),
    ]
    data = build_telemetry(procs=rows)
    finding = Finding(
        rule_id="ATH-002", title="t", severity=Severity.HIGH, device=device,
        user="operator", evidence=(Evidence(rows[0]["event_id"], at(0), "s"),),
        reason="r", fields_used=("process_name", "process_id"),
        metadata={"process_guid": identity, "process_id": pid},
    )
    case = InvestigationCase(case_id="CASE-001", findings=(finding,))
    tools = ToolBox(data, [finding], [case])
    agent = GeneralistAgent(tools)
    state = InvestigationState(case=case)

    results = _run_to_exhaustion(agent, state)

    walks = [c for c in tools.calls if c.tool == "process_tree"]
    assert walks, "the finding names a process; the generalist must walk it"
    assert walks[0].arguments["process_guid"] == identity
    lineage = [
        c for r in results for c in r.claims if c.statement.startswith(f"On {device},")
    ]
    assert lineage, "the walk resolved an instance; it must be published"
    assert "Resolution: identity" in lineage[0].statement


# --------------------------------------------------------------------------------------
# Budgets
# --------------------------------------------------------------------------------------


def test_at_a_cap_of_zero_it_claims_nothing_and_crashes_nothing(
    telemetry, pipeline, intrusion_case
) -> None:
    """Every tool refuses, so the generalist -- whose every claim is a tool result -- has
    nothing to say, and says so in notes rather than in claims."""
    findings, cases = pipeline
    tools = ToolBox(telemetry, findings, cases, tool_call_budget=0)
    orchestrator = InvestigationOrchestrator(
        tools, ClaimVerifier(telemetry), llm=NullLLM(),
        config=InvestigationConfig(use_llm_planner=False, use_llm_synthesis=False),
        specialists=[GeneralistAgent(tools)],
    )

    state = orchestrator.investigate(intrusion_case)

    assert state.claims == []
    assert tools.budget_hits > 0
    assert all(call.refused for call in state.tool_calls)
    assert any("budget" in note for result in state.results for note in result.notes)


def test_the_step_budget_stops_a_case_it_cannot_finish(
    telemetry, pipeline, intrusion_case
) -> None:
    """A case with more entities than steps ends at the budget, visibly.

    Fails if the generalist is allowed to keep walking past ``max_steps`` -- the runaway
    guard the orchestrator owns and no agent may override.
    """
    findings, cases = pipeline
    tools = ToolBox(telemetry, findings, cases)
    orchestrator = InvestigationOrchestrator(
        tools, ClaimVerifier(telemetry), llm=NullLLM(),
        config=InvestigationConfig(
            max_steps=2, use_llm_planner=False, use_llm_synthesis=False,
        ),
        specialists=[GeneralistAgent(tools, items_per_step=1)],
    )

    state = orchestrator.investigate(intrusion_case)

    assert state.step == 2
    assert state.status.value == "step_limit"
