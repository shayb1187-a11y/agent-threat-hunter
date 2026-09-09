"""Optional LangGraph runtime for the investigation orchestrator.

This module is a thin adapter, not a reimplementation. All investigation logic --
planning, specialist execution, verification, synthesis, stopping conditions -- lives in
:class:`~ath.agent.orchestrator.InvestigationOrchestrator` and is fully testable without
this file or the ``langgraph`` package installed. What this module adds is a
``langgraph.graph.StateGraph`` whose nodes call straight into that orchestrator, so the
same logic can run as a LangGraph app (with its visualisation, checkpointing, and
streaming) when that runtime is wanted.

Why build it this way round
----------------------------
The tempting shortcut is to write the investigation loop *as* LangGraph nodes directly.
That would work, but it would mean the core logic could only be tested by instantiating
a graph, and the project's design principle -- deterministic logic first, framework
second -- would be inverted. Here, if ``langgraph`` were uninstalled or changed its API
tomorrow, only this file would need to change; every test in ``tests/test_agent.py``
would keep passing unmodified because none of them import this module.

Import is deferred
-------------------
``langgraph`` is an optional dependency (see ``requirements.txt``). Importing it at
module load time would make the entire ``ath.agent`` package fail to import in an
environment that only wants the deterministic pipeline. So the import happens inside
:func:`build_graph`, and callers who never call that function never pay for it.
"""

from __future__ import annotations

from typing import Any, TypedDict

from ath.agent.claims import ClaimVerifier
from ath.agent.llm import LLMClient, NullLLM
from ath.agent.orchestrator import InvestigationConfig, InvestigationOrchestrator
from ath.agent.specialists import Specialist
from ath.agent.state import InvestigationState
from ath.agent.tools import ToolBox
from ath.capabilities.crew import resolve_specialists
from ath.correlation.chain import InvestigationCase
from ath.environment.model import EnvironmentModel
from ath.logging_setup import get_logger

logger = get_logger(__name__)


class GraphState(TypedDict):
    """The dict-shaped state LangGraph threads between nodes.

    LangGraph's ``StateGraph`` operates on plain dicts (or ``TypedDict``s) rather than
    arbitrary objects, so this wraps our real :class:`InvestigationState` in a single
    key. Nodes unwrap it, delegate to the orchestrator, and rewrap the result --
    LangGraph never sees or touches the investigation logic itself.
    """

    investigation: InvestigationState
    orchestrator: InvestigationOrchestrator
    done: bool


def _plan_and_act_node(state: GraphState) -> GraphState:
    """One planning + acting + verification cycle, delegated to the orchestrator."""
    orch = state["orchestrator"]
    inv = state["investigation"]

    if inv.step >= inv.max_steps:
        inv.plan_log.append(f"stopped at the {inv.max_steps}-step budget")
        from ath.agent.state import InvestigationStatus
        inv.status = InvestigationStatus.STEP_LIMIT
        return {**state, "done": True}

    specialist, reason = orch.plan(inv)
    if specialist is None:
        inv.plan_log.append(f"step {inv.step + 1}: stop -- {reason}")
        from ath.agent.state import InvestigationStatus
        inv.status = (
            InvestigationStatus.COMPLETE if inv.agents_run else InvestigationStatus.EXHAUSTED
        )
        return {**state, "done": True}

    inv.plan_log.append(f"step {inv.step + 1}: {specialist.name} -- {reason}")
    result = orch.act(inv, specialist, reason)
    orch.verify(inv, result)
    return {**state, "investigation": inv, "done": False}


def _should_continue(state: GraphState) -> str:
    """LangGraph conditional edge: loop back to planning, or proceed to synthesis."""
    return "synthesise" if state["done"] else "plan_and_act"


def _synthesise_node(state: GraphState) -> GraphState:
    """Terminal node: model-assisted synthesis over verified claims, then stop."""
    orch = state["orchestrator"]
    orch.synthesise(state["investigation"])
    return state


def build_graph() -> Any:
    """Construct the compiled LangGraph app.

    Returns:
        A compiled ``langgraph.graph.StateGraph``. Import of ``langgraph`` happens here,
        not at module level, so this package remains importable without it installed.

    Raises:
        ImportError: if ``langgraph`` is not installed. The caller (see
            :func:`run_investigation_via_langgraph`) catches this and falls back to
            calling the orchestrator directly -- LangGraph is a convenience runtime,
            never a requirement for the investigation to run.
    """
    from langgraph.graph import END, StateGraph

    graph = StateGraph(GraphState)
    graph.add_node("plan_and_act", _plan_and_act_node)
    graph.add_node("synthesise", _synthesise_node)
    graph.set_entry_point("plan_and_act")
    graph.add_conditional_edges(
        "plan_and_act", _should_continue,
        {"plan_and_act": "plan_and_act", "synthesise": "synthesise"},
    )
    graph.add_edge("synthesise", END)
    return graph.compile()


def run_investigation_via_langgraph(
    case: InvestigationCase,
    tools: ToolBox,
    verifier: ClaimVerifier,
    llm: LLMClient | None = None,
    specialists: list[Specialist] | None = None,
    config: InvestigationConfig | None = None,
    environment: EnvironmentModel | None = None,
) -> InvestigationState:
    """Run an investigation through the LangGraph runtime.

    Falls back to calling :meth:`InvestigationOrchestrator.investigate` directly -- with
    identical results, since it is the same underlying logic -- when ``langgraph`` is
    not installed. This means switching runtimes never changes investigation behaviour,
    only how the loop is executed and observed.
    """
    # Resolved once, the same way the orchestrator itself resolves it, so an explicit
    # specialists list, an environment-assembled crew, and the fixed default roster
    # all mean the same thing here as they do calling the orchestrator directly.
    resolved = resolve_specialists(specialists, environment, tools)
    orchestrator = InvestigationOrchestrator(
        tools, verifier, llm or NullLLM(), resolved, config, environment,
    )

    try:
        app = build_graph()
    except ImportError:
        logger.info("langgraph not installed; running the orchestrator loop directly")
        return orchestrator.investigate(case)

    # This node builds its own initial state rather than reusing
    # `orchestrator.investigate`, so every field that affects planning has to be
    # threaded through here too. Specialist eligibility now consults the environment,
    # so omitting it would make the LangGraph runtime plan differently from the direct
    # one -- exactly the divergence `test_langgraph_run_matches_direct_orchestrator_call`
    # exists to catch.
    initial = InvestigationState(
        case=case,
        max_steps=orchestrator.config.max_steps,
        environment=orchestrator.environment,
    )
    from ath.agent.state import InvestigationStatus

    initial.status = InvestigationStatus.IN_PROGRESS
    result: GraphState = app.invoke(
        {"investigation": initial, "orchestrator": orchestrator, "done": False},
        config={"recursion_limit": orchestrator.config.max_steps * 4 + 10},
    )
    return result["investigation"]
