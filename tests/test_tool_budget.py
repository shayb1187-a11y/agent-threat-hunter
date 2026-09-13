"""The per-case tool budget: a spent budget is data, and never an exception.

What each group here is for, and how it fails
----------------------------------------------
*The cap itself.* A budget that can be exceeded is not a budget, and one that raises
turns an expensive arm into a crashed run -- which an ablation would score as "no
result" rather than "too expensive". These fail if the 41st call is served, if it is not
recorded, if it is not counted, or if anything propagates out of the toolbox.

*The refusal's shape.* Every caller of a tool already branches on that tool's own result
shape. A refusal that arrived as some new shape would be read by existing code as "the
telemetry says nothing", which is the exact confusion between absence and invisibility
this project refuses everywhere else. The parametrised test walks **every** public tool,
and a tool added later without a budget guard fails it rather than silently becoming the
one unbounded route.

*What a specialist does with a refusal.* A refusal must never become a FACT. The
strongest available statement of that is a real investigation run at a cap of zero: no
tool answers anything, and no claim sourced from a tool may exist afterwards.
"""

from __future__ import annotations

import pytest

from ath.agent.claims import ClaimVerifier
from ath.agent.llm import NullLLM
from ath.agent.orchestrator import InvestigationConfig, InvestigationOrchestrator
from ath.agent.tools import ToolBox
from ath.correlation import correlate
from ath.hunting import run_hunt
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import load_telemetry


@pytest.fixture(scope="module")
def telemetry(tmp_path_factory):
    tables, ground_truth = generate_telemetry(GeneratorConfig())
    directory = tmp_path_factory.mktemp("tool-budget")
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


def _toolbox(telemetry, pipeline, budget):
    findings, cases = pipeline
    return ToolBox(telemetry, findings, cases, tool_call_budget=budget)


# --------------------------------------------------------------------------------------
# The cap
# --------------------------------------------------------------------------------------


def test_no_budget_means_no_cap(telemetry, pipeline) -> None:
    """The default is unlimited -- every caller written before budgets is unchanged."""
    tools = _toolbox(telemetry, pipeline, None)
    for _ in range(50):
        tools.lookup_technique("T1059.001", agent="attack")
    assert tools.calls_served == 50
    assert tools.budget_hits == 0
    assert not any(call.refused for call in tools.calls)


def test_the_forty_first_call_is_refused_recorded_and_counted(telemetry, pipeline) -> None:
    """Fails if the cap is off by one, silent, unrecorded, or raises."""
    tools = _toolbox(telemetry, pipeline, 40)
    for _ in range(40):
        assert tools.lookup_technique("T1059.001", agent="attack").get("refused") is None

    refused = tools.lookup_technique("T1059.001", agent="attack")

    assert refused["refused"] is True
    assert "tool budget exhausted (40 calls)" in refused["reason"]
    assert tools.budget_hits == 1
    assert tools.calls_served == 40
    assert tools.call_count == 41, "the refusal is recorded as a call, not swallowed"
    assert tools.calls[-1].refused is True
    assert tools.calls[-1].to_dict()["refused"] is True


def test_a_refusal_does_not_itself_spend_budget(telemetry, pipeline) -> None:
    """Otherwise the cap would mean a smaller number than it says."""
    tools = _toolbox(telemetry, pipeline, 2)
    for _ in range(5):
        tools.lookup_technique("T1059.001", agent="attack")
    assert tools.calls_served == 2
    assert tools.budget_hits == 3


def test_an_unrefused_call_serialises_exactly_as_it_did_before_budgets(
    telemetry, pipeline
) -> None:
    """``refused`` appears in the payload only when true.

    Fails if the field is always emitted -- which would change every already-published
    arm A row in ``reports/m19/ablation/arm_A.json`` without a single behaviour moving.
    """
    tools = _toolbox(telemetry, pipeline, None)
    tools.lookup_technique("T1059.001", agent="attack")
    assert "refused" not in tools.calls[0].to_dict()


# --------------------------------------------------------------------------------------
# Every tool, not just the convenient ones
# --------------------------------------------------------------------------------------


TOOL_ARGUMENTS = {
    "get_case": {"case_id": "CASE-001"},
    "get_events": {"event_ids": ["evt-000001"]},
    "process_tree": {"device": "PC01", "pid": 1234},
    "user_auth_history": {"user": "jdoe"},
    "host_network_activity": {"device": "PC01"},
    "analyse_beacon": {"device": "PC01", "remote_ip": "185.220.101.47"},
    "search_processes": {"device": "PC01"},
    "get_finding": {"finding_id": "ATH-001-0001"},
    "lookup_technique": {"technique_id": "T1059.001"},
}


def test_the_argument_table_covers_every_public_tool(telemetry, pipeline) -> None:
    """A tool added without a budget guard must fail a test, not pass silently."""
    tools = _toolbox(telemetry, pipeline, None)
    public = {
        name for name in dir(tools)
        if not name.startswith("_")
        and callable(getattr(tools, name))
        and name not in {"calls_by"}
    }
    assert public == set(TOOL_ARGUMENTS), (
        "every public tool must be exercised against the budget; "
        f"unlisted: {sorted(public - set(TOOL_ARGUMENTS))}"
    )


@pytest.mark.parametrize("tool_name", sorted(TOOL_ARGUMENTS))
def test_every_tool_refuses_rather_than_raising_when_the_budget_is_spent(
    telemetry, pipeline, tool_name
) -> None:
    tools = _toolbox(telemetry, pipeline, 0)
    result = getattr(tools, tool_name)(**TOOL_ARGUMENTS[tool_name])
    assert result["refused"] is True
    assert tools.budget_hits == 1
    assert tools.calls[-1].tool == tool_name


# The key each tool's callers branch on when it has nothing for them. For the three
# lookup-shaped tools that is ``error``, which is the branch an unknown id already
# takes -- a refusal must travel a path that exists, not a new one nobody handles.
REFUSAL_KEYS = {
    "get_case": {"error"},
    "get_events": {"events", "not_found"},
    "process_tree": {"resolution", "ancestry", "children", "candidates"},
    "user_auth_history": {"summary", "events"},
    "host_network_activity": {"destinations", "event_ids", "total"},
    "analyse_beacon": {"regular", "samples", "event_ids"},
    "search_processes": {"results", "count"},
    "get_finding": {"error"},
    "lookup_technique": {"error"},
}


@pytest.mark.parametrize("tool_name", sorted(TOOL_ARGUMENTS))
def test_a_refusal_carries_the_shape_its_callers_branch_on(
    telemetry, pipeline, tool_name
) -> None:
    """Fails if a refusal arrives as a shape existing code does not know how to read."""
    refused = getattr(_toolbox(telemetry, pipeline, 0), tool_name)(
        **TOOL_ARGUMENTS[tool_name]
    )
    expected = REFUSAL_KEYS[tool_name] | {"refused", "reason"}
    assert expected <= set(refused), (
        f"{tool_name} refusal omits {sorted(expected - set(refused))}"
    )


# --------------------------------------------------------------------------------------
# What a specialist does with a refusal
# --------------------------------------------------------------------------------------


def test_a_crew_at_a_cap_of_zero_authors_no_fact_from_a_tool(
    telemetry, pipeline, intrusion_case
) -> None:
    """No tool answered anything, so no tool may have authored anything.

    The surviving FACTs are the ones the *detector* authored from a finding's own
    metadata (ATH-006's cross-host credential use), which never consulted a tool and is
    therefore unaffected by the budget. The assertion is deliberately about the source
    rather than about the count: a refusal must not produce a claim, and a finding that
    was already evidence does not stop being evidence because a budget ran out.

    Fails if any specialist reads a refused payload as data.
    """
    findings, cases = pipeline
    tools = ToolBox(telemetry, findings, cases, tool_call_budget=0)
    orchestrator = InvestigationOrchestrator(
        tools, ClaimVerifier(telemetry), llm=NullLLM(),
        config=InvestigationConfig(use_llm_planner=False, use_llm_synthesis=False),
    )

    state = orchestrator.investigate(intrusion_case)

    assert [c for c in state.facts if c.source == "tool"] == []
    assert tools.budget_hits > 0
    assert sum(1 for call in state.tool_calls if call.refused) == tools.budget_hits, (
        "the state must record the budget hits, not merely the toolbox"
    )
    assert not state.rejected_claims
    assert state.status.value in {"complete", "exhausted"}


def test_a_crew_with_budget_produces_the_facts_the_refusal_suppressed(
    telemetry, pipeline, intrusion_case
) -> None:
    """The contrast that makes the previous test mean something."""
    findings, cases = pipeline
    tools = ToolBox(telemetry, findings, cases)
    orchestrator = InvestigationOrchestrator(
        tools, ClaimVerifier(telemetry), llm=NullLLM(),
        config=InvestigationConfig(use_llm_planner=False, use_llm_synthesis=False),
    )

    state = orchestrator.investigate(intrusion_case)

    assert [c for c in state.facts if c.source == "tool"], (
        "the uncapped run must produce tool-authored facts, or the cap-zero assertion "
        "above is vacuous"
    )
    assert tools.budget_hits == 0
