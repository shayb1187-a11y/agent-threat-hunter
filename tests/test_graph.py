"""Tests for the LangGraph runtime adapter.

The property under test is equivalence: running through LangGraph must produce exactly
the same investigation as calling the orchestrator directly, and the system must degrade
gracefully -- not fail -- when ``langgraph`` is unavailable. If either test failed, the
project's claim that "LangGraph is a runtime choice, not the design" would be false.
"""

from __future__ import annotations

import pytest

from ath.agent.claims import ClaimVerifier
from ath.agent.orchestrator import InvestigationConfig, InvestigationOrchestrator
from ath.agent.tools import ToolBox
from ath.correlation import correlate
from ath.hunting import run_hunt
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import load_telemetry

langgraph = pytest.importorskip("langgraph", reason="langgraph is an optional dependency")


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory):
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("graph_data")
    write_telemetry(tables, gt, out)
    return out


@pytest.fixture(scope="module")
def telemetry(data_dir):
    return load_telemetry(data_dir)


@pytest.fixture(scope="module")
def hunt_result(telemetry):
    return run_hunt(telemetry)


@pytest.fixture(scope="module")
def cases(hunt_result, telemetry):
    return correlate(hunt_result.findings, telemetry)


@pytest.fixture(scope="module")
def intrusion_case(cases):
    return max(cases, key=lambda c: len(c.findings))


def _config():
    return InvestigationConfig(use_llm_planner=False, use_llm_synthesis=False)


def test_build_graph_compiles() -> None:
    from ath.agent.graph import build_graph

    app = build_graph()
    assert app is not None


def test_langgraph_run_matches_direct_orchestrator_call(
    telemetry, hunt_result, cases, intrusion_case
) -> None:
    from ath.agent.graph import run_investigation_via_langgraph

    tb_direct = ToolBox(telemetry, hunt_result.findings, cases)
    verifier = ClaimVerifier(telemetry)
    direct = InvestigationOrchestrator(tb_direct, verifier, config=_config())
    direct_state = direct.investigate(intrusion_case)

    tb_graph = ToolBox(telemetry, hunt_result.findings, cases)
    graph_state = run_investigation_via_langgraph(
        intrusion_case, tb_graph, ClaimVerifier(telemetry), config=_config()
    )

    assert graph_state.status == direct_state.status
    assert graph_state.agents_run == direct_state.agents_run
    assert [c.statement for c in graph_state.claims] == [c.statement for c in direct_state.claims]


def test_langgraph_respects_the_step_budget(telemetry, hunt_result, cases, intrusion_case) -> None:
    from ath.agent.graph import run_investigation_via_langgraph

    tb = ToolBox(telemetry, hunt_result.findings, cases)
    state = run_investigation_via_langgraph(
        intrusion_case, tb, ClaimVerifier(telemetry),
        config=InvestigationConfig(max_steps=1, use_llm_planner=False, use_llm_synthesis=False),
    )
    assert state.step <= 1


def test_falls_back_to_direct_orchestrator_when_langgraph_unavailable(
    telemetry, hunt_result, cases, intrusion_case, monkeypatch
) -> None:
    """Simulates langgraph being uninstalled: behaviour must be unaffected."""
    from ath.agent import graph as graph_module

    def _boom() -> None:
        raise ImportError("simulated: langgraph not installed")

    monkeypatch.setattr(graph_module, "build_graph", _boom)

    tb = ToolBox(telemetry, hunt_result.findings, cases)
    state = graph_module.run_investigation_via_langgraph(
        intrusion_case, tb, ClaimVerifier(telemetry), config=_config()
    )
    assert state.status.value == "complete"
    assert state.agents_run  # the investigation still ran to completion


def test_agent_package_does_not_require_langgraph_to_import(monkeypatch) -> None:
    """ath.agent must import cleanly even if langgraph is absent from the environment.

    We cannot literally uninstall the package mid-test-run, so this asserts the
    structural guarantee instead: importing ath.agent.graph's module-level code makes
    no reference to langgraph outside function bodies.
    """
    import ast
    from pathlib import Path

    source = Path(__import__("ath.agent.graph", fromlist=["x"]).__file__).read_text()
    tree = ast.parse(source)
    module_level_imports = [
        node for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
    ]
    for node in module_level_imports:
        names = (
            [node.module] if isinstance(node, ast.ImportFrom) else [a.name for a in node.names]
        )
        assert not any(n and "langgraph" in n for n in names), (
            "langgraph must only be imported inside function bodies (build_graph), "
            "not at module level"
        )
