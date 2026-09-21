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

*Facets (M19-3).* Arm B's planner must have a choice to make, so the tool surface is
seven facets of one agent sharing one walk. These fail if a kind loses its facet (that
kind is then never walked and arm B silently shrinks), if two facets can take the same
entity (arm B's tool-call column would double-count), if the split changes what is
walked (the refactor would have moved the measurement, not the menu), if the planner
stops being consulted (which is the defect this milestone exists to fix), or if a
keyless run stops being deterministic.
"""

from __future__ import annotations

import json

import pytest

from _builders import at, proc
from _builders import telemetry as build_telemetry
from ath.agent.claims import ClaimType, ClaimVerifier
from ath.agent.generalist import (
    FACET_DOMAINS,
    KIND_ORDER,
    GeneralistAgent,
    GeneralistFacet,
    build_generalist_crew,
    plan_walk,
)
from ath.agent.llm import NullLLM, ScriptedLLM
from ath.agent.orchestrator import (
    PLANNER_SYSTEM,
    InvestigationConfig,
    InvestigationOrchestrator,
)
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


# --------------------------------------------------------------------------------------
# Facets -- M19-3
# --------------------------------------------------------------------------------------


def _crew(telemetry, pipeline, budget=None, items_per_step=5):
    findings, cases = pipeline
    tools = ToolBox(telemetry, findings, cases, tool_call_budget=budget)
    return build_generalist_crew(tools, items_per_step=items_per_step), tools


def _run_crew_to_exhaustion(crew, state, max_steps=200):
    """Drive the crew the way the orchestrator's deterministic fallback does.

    First eligible facet in crew order, every step -- exactly what ``plan`` falls back
    to when no model answers, so this loop is the fallback order rather than a
    test-local ordering of its own.
    """
    results = []
    for _ in range(max_steps):
        for facet in crew:
            should, _reason = facet.should_run(state)
            if should:
                results.append(facet.investigate(state))
                state.step += 1
                state.agents_run.append(facet.name)
                break
        else:
            return results
    raise AssertionError("the crew never ran out of work")


def _transcript(results, tools):
    """What was claimed and what was called, as sets: order is allowed to differ."""
    claims = {
        (c.claim_type.value, c.statement, c.evidence_ids)
        for r in results for c in r.claims
    }
    calls = {
        (c.tool, json.dumps(c.arguments, sort_keys=True, default=str))
        for c in tools.calls
    }
    return claims, calls


def test_there_is_one_facet_per_kind_and_no_kind_without_a_facet(
    telemetry, pipeline, intrusion_case
) -> None:
    """The crew is exactly the seven kinds a walk can contain.

    Fails if a kind is added to ``plan_walk`` without a facet -- those entities would
    never be eligible for anyone, so arm B's tool surface would shrink with no error and
    no visible gap -- or if a facet is built for a kind nothing plans.
    """
    crew, _tools = _crew(telemetry, pipeline)

    assert [facet.kind for facet in crew] == list(KIND_ORDER)
    assert [facet.name for facet in crew] == [f"generalist:{k}" for k in KIND_ORDER]
    assert {facet.domain for facet in crew} == set(FACET_DOMAINS.values()), (
        "seven facets need seven domains: the domain is what the planner reads"
    )

    state = InvestigationState(case=intrusion_case)
    assert {item.kind for item in plan_walk(state)} <= set(KIND_ORDER)

    with pytest.raises(ValueError, match="unknown generalist facet"):
        GeneralistFacet(crew[0].tools, kind="kubernetes")


def test_a_facet_declines_once_its_own_kind_is_walked_out(
    telemetry, pipeline, intrusion_case
) -> None:
    """Eligibility is per kind, and the refusal says which kind is finished.

    Fails if a facet stays eligible after its kind is exhausted (it would burn steps
    doing nothing) or declines while entities of its kind remain (they would never be
    walked).
    """
    crew, _tools = _crew(telemetry, pipeline, items_per_step=100)
    state = InvestigationState(case=intrusion_case)
    case_facet = crew[0]

    assert case_facet.should_run(state)[0] is True
    case_facet.investigate(state)

    should, reason = case_facet.should_run(state)
    assert should is False
    assert reason == "every case entity has been walked"
    assert crew[1].should_run(state)[0] is True, "the other facets are untouched"


def test_no_entity_is_walked_twice_across_the_facets(
    telemetry, pipeline, intrusion_case
) -> None:
    """The shared-state property, stated three ways.

    Fails the moment each facet gets its own copy of the plan: the identity assertion
    goes first, then the cross-facet visibility one -- an entity taken by the ``case``
    facet must be gone from every other facet's view of the walk, not merely from its
    own. Facets happen to partition the plan by kind today, so a per-facet copy would
    not double-count *yet*; it would the moment two facets can see one entity, and the
    walk is the only place that invariant can be stated.
    """
    crew, tools = _crew(telemetry, pipeline, items_per_step=2)
    state = InvestigationState(case=intrusion_case)

    case_facet, finding_facet = crew[0], crew[1]
    assert case_facet.walk is finding_facet.walk, "one walk, not seven"
    before = len(finding_facet.walk.remaining(state))
    case_facet.investigate(state)
    after = finding_facet.walk.remaining(state)
    assert len(after) == before - 1, "a sibling's view of the walk must have shrunk"
    assert all(item.kind != "case" for _index, item in after)

    _run_crew_to_exhaustion(crew, state)

    walk = crew[0].walk
    assert all(facet.walk is walk for facet in crew), "one walk, not seven"
    assert walk.walked == [True] * len(walk.plan), "every planned entity was walked"
    assert len(walk.walked_items()) == len(plan_walk(state))
    calls = [
        (c.tool, json.dumps(c.arguments, sort_keys=True, default=str))
        for c in tools.calls
    ]
    assert len(calls) == len(set(calls)), "a repeated call means two facets took one item"


def test_the_facets_together_walk_exactly_what_the_single_agent_walked(
    telemetry, pipeline, intrusion_case
) -> None:
    """M19-3 changed the menu, not the meal.

    The union of the seven facets' work must equal the M19-2 single agent's work on
    INC-001: the same tool calls with the same arguments, and the same FACTs. Order is
    allowed to differ -- the facets batch per kind and the single agent batched across
    kinds -- so both sides are compared as sets.

    Fails if the split drops an entity (a kind with no facet, or an item lost between
    two), duplicates one, or changes what any handler asserts.
    """
    single, single_tools = _agent(telemetry, pipeline)
    single_state = InvestigationState(case=intrusion_case)
    single_results = _run_to_exhaustion(single, single_state, max_steps=200)

    crew, crew_tools = _crew(telemetry, pipeline)
    crew_state = InvestigationState(case=intrusion_case)
    crew_results = _run_crew_to_exhaustion(crew, crew_state)

    single_claims, single_calls = _transcript(single_results, single_tools)
    crew_claims, crew_calls = _transcript(crew_results, crew_tools)

    assert crew_calls == single_calls
    assert crew_claims == single_claims
    assert single_claims, "a 13-finding case must produce something to compare"
    assert {a.split(":", 1)[0] for a in crew_state.agents_run} == {"generalist"}


def test_the_planner_is_consulted_once_more_than_one_facet_is_eligible(
    telemetry, pipeline, intrusion_case
) -> None:
    """The whole point of M19-3, asserted on the orchestrator rather than on the agent.

    Fails if arm B's crew goes back to being a crew of one: ``plan`` short-circuits to
    "only eligible specialist" with a single candidate, the model is never asked, and
    arm B measures synthesis over a fixed walk -- which is exactly what M19-2 measured
    and reported as 0 planner-chosen steps.
    """
    findings, cases = pipeline
    tools = ToolBox(telemetry, findings, cases)
    llm = ScriptedLLM(
        responses=[
            json.dumps({
                "next_agent": f"generalist:{kind}",
                "reason": f"scripted: the {kind} surface",
            })
            for kind in reversed(KIND_ORDER)
        ] * 4,
        name="scripted-model",
    )
    orchestrator = InvestigationOrchestrator(
        tools, ClaimVerifier(telemetry), llm=llm,
        config=InvestigationConfig(
            max_steps=8, use_llm_planner=True, use_llm_synthesis=False,
        ),
        specialists=build_generalist_crew(tools),
    )

    state = orchestrator.investigate(intrusion_case)

    planner_steps = [line for line in state.plan_log if " -- planner:" in line]
    assert planner_steps, state.plan_log
    assert planner_steps[0].startswith("step 1: generalist:technique -- planner:"), (
        "the model's choice must steer the run, not coincide with the fallback"
    )
    planner_prompts = [p for system, p in llm.calls if system == PLANNER_SYSTEM]
    assert planner_prompts, "the planner stage was never reached"
    candidates = [
        line for line in planner_prompts[0].splitlines()
        if line.startswith("  generalist:")
    ]
    assert len(candidates) > 1, "a menu of one is not a choice"
    assert not state.llm_degraded


def test_without_a_model_the_fallback_is_the_fixed_kind_order_and_repeats(
    telemetry, pipeline, intrusion_case
) -> None:
    """A keyless arm B is still deterministic, and walks in :data:`KIND_ORDER`.

    Fails if the crew is handed to the orchestrator in any order but ``KIND_ORDER`` (the
    fallback takes the first eligible candidate in crew order), or if anything in the
    walk starts depending on set iteration.
    """
    def run():
        findings, cases = pipeline
        tools = ToolBox(telemetry, findings, cases)
        orchestrator = InvestigationOrchestrator(
            tools, ClaimVerifier(telemetry), llm=NullLLM(),
            config=InvestigationConfig(
                max_steps=100, use_llm_planner=True, use_llm_synthesis=True,
            ),
            specialists=build_generalist_crew(tools),
        )
        state = orchestrator.investigate(intrusion_case)
        return (
            list(state.agents_run),
            [(c.claim_type.value, c.statement, c.evidence_ids) for c in state.claims],
            [(call.tool, sorted(call.arguments)) for call in state.tool_calls],
        )

    first = run()
    assert first == run()

    agents_run = first[0]
    positions = [KIND_ORDER.index(name.split(":", 1)[1]) for name in agents_run]
    assert positions == sorted(positions), agents_run
    assert agents_run[0] == "generalist:case"
    assert set(agents_run) == {f"generalist:{k}" for k in KIND_ORDER}
