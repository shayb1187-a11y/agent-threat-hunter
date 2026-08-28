"""Autonomous investigation layer.

Everything in this package is optional: with no LLM configured, the orchestrator still
runs to completion using its deterministic planner and produces evidence-backed claims
from the specialists alone (see :class:`~ath.agent.llm.NullLLM`). A model, when
available, adds planning judgement and cross-claim synthesis -- it never becomes a
requirement for the investigation to work, and it never gets write access to anything.

Core guarantees, each enforced in code rather than by convention:

* The agent never receives raw telemetry -- only tool results (:mod:`ath.agent.tools`).
* A model can never author a FACT (:mod:`ath.agent.claims`).
* Every claim's evidence is checked against real telemetry before acceptance.
* The investigation path is decided by evidence-driven gates
  (:meth:`~ath.agent.specialists.Specialist.should_run`), not by a fixed script.
* Stopping is deterministic: no eligible specialist, or a hard step budget --
  never "the model decided it was done".
"""

from ath.agent.claims import (
    Claim,
    ClaimType,
    ClaimVerifier,
    RejectedClaim,
    VerificationResult,
)
from ath.agent.llm import AnthropicLLM, LLMClient, LLMResponse, NullLLM, ScriptedLLM, build_llm
from ath.agent.orchestrator import (
    DEFAULT_PRIORITY,
    InvestigationConfig,
    InvestigationOrchestrator,
)
from ath.agent.specialists import (
    AttackMappingAgent,
    EndpointAgent,
    IdentityAgent,
    NetworkAgent,
    Specialist,
    default_specialists,
)
from ath.agent.state import AgentResult, InvestigationState, InvestigationStatus
from ath.agent.tools import ToolBox, ToolCall

__all__ = [
    "Claim", "ClaimType", "ClaimVerifier", "RejectedClaim", "VerificationResult",
    "LLMClient", "LLMResponse", "NullLLM", "ScriptedLLM", "AnthropicLLM", "build_llm",
    "InvestigationOrchestrator", "InvestigationConfig", "DEFAULT_PRIORITY",
    "Specialist", "EndpointAgent", "IdentityAgent", "NetworkAgent", "AttackMappingAgent",
    "default_specialists",
    "InvestigationState", "InvestigationStatus", "AgentResult",
    "ToolBox", "ToolCall",
]
