"""Versioned operational policy beside, never inside, the frozen experiment arms.

This composes existing tools and investigators. It does not prove that a cited event
supports an interpretation; ClaimVerifier still checks references, not entailment.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from dataclasses import asdict, dataclass, replace
from typing import ClassVar
from uuid import uuid4

from ath.agent.claims import ClaimVerifier
from ath.agent.investigator import RESPONSE_SCHEMA, D1Investigator, InvestigatorConfig
from ath.agent.llm import LLMClient, LLMResponse, NullLLM
from ath.agent.orchestrator import InvestigationConfig, InvestigationOrchestrator
from ath.agent.state import InvestigationState, InvestigationStatus
from ath.agent.tools import ToolBox
from ath.correlation.chain import InvestigationCase
from ath.environment.model import EnvironmentModel
from ath.hunting.finding import Finding
from ath.telemetry.loader import Telemetry


@dataclass(frozen=True)
class OperationalProfile:
    """Finite per-case limits; effective values and their hash accompany every run.

    Timeouts are cooperative, not process preemption. Token usage is checked between
    calls and after the final reply; an in-flight request can exceed the token budget.
    Missing usage stops the model path instead of silently treating it as free.
    """

    version: ClassVar[str] = "operational-v1"
    max_steps: int = 8
    max_probes: int = 2
    tool_call_budget: int = 64
    tool_max_rows: int = 100
    tool_max_chars: int = 2048
    time_budget_seconds: float = 120.0
    token_budget: int = 24000
    max_output_tokens: int = 768
    max_prompt_bytes: int = 65536

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if name == "time_budget_seconds":
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                    raise ValueError(f"{name} must be finite and positive")
            elif isinstance(value, bool) or not isinstance(value, int) or value < (0 if name == "max_probes" else 1):
                raise ValueError(f"{name} must be a {'nonnegative' if name == 'max_probes' else 'positive'} integer")
        # D1 records a seed and a conclusion in addition to each probe.
        if self.max_steps < self.max_probes + 2:
            raise ValueError("max_steps must accommodate seed, probes, and conclusion")

    def to_dict(self) -> dict:
        return {
            "version": self.version, **asdict(self),
            "reject_unretrieved": True, "prompt_contract": True, "ledger": True,
        }

    def sha256(self) -> str:
        body = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(body.encode("utf-8")).hexdigest()


class _OperationalLLM:
    """Per-investigation accounting and bounded calls around an existing client."""

    def __init__(self, client: LLMClient, profile: OperationalProfile, started: float):
        self.client = client
        self.profile = profile
        self.started = started
        self.name = client.name
        self.available = client.available
        self.tokens_used = 0
        self.usage_unknown = False

    def complete(self, system, prompt, max_tokens=1024, timeout_seconds=None) -> LLMResponse:
        remaining = self.profile.time_budget_seconds - (time.perf_counter() - self.started)
        if remaining <= 0:
            return LLMResponse(error="time budget exhausted", model=self.name)
        if self.tokens_used >= self.profile.token_budget or self.usage_unknown:
            return LLMResponse(error="token budget exhausted or usage unavailable", model=self.name)
        if len(system.encode("utf-8")) + len(prompt.encode("utf-8")) > self.profile.max_prompt_bytes:
            return LLMResponse(error="prompt byte budget exceeded", model=self.name)
        timeout = min(remaining, timeout_seconds) if timeout_seconds is not None else remaining
        try:
            response = self.client.complete(
                system, prompt,
                max_tokens=min(max_tokens, self.profile.max_output_tokens,
                               self.profile.token_budget - self.tokens_used),
                timeout_seconds=timeout,
            )
        except Exception as exc:
            # Do not persist arbitrary transport exception text, which can contain secrets.
            self.usage_unknown = True
            return LLMResponse(error=f"model client raised {type(exc).__name__}", model=self.name)
        self.tokens_used += response.total_tokens or 0
        self.usage_unknown |= response.input_tokens is None or response.output_tokens is None
        if response.ok and response.truncated:
            return replace(response, error="model reply truncated")
        if response.ok and self.usage_unknown:
            return replace(response, error="model token usage unavailable")
        # The frozen parser deliberately tolerates missing fields. Operational replies
        # must at least carry the required shape before that parser is invoked.
        if response.ok and not _reply_shape_valid(response.parsed):
            return replace(response, error="invalid investigation response shape")
        return response


def _reply_shape_valid(payload: object) -> bool:
    if not isinstance(payload, dict) or not set(RESPONSE_SCHEMA["required"]) <= payload.keys():
        return False
    if any(not isinstance(payload[key], str) for key in (
        "evidence_gap", "next_probe", "probe_reason", "disposition",
    )):
        return False
    explanations = payload["explanations"]
    probe = payload["next_probe"].strip().lower()
    if probe != "none" and re.fullmatch(r"p[1-9][0-9]*", probe) is None:
        return False
    return isinstance(explanations, list) and all(
        isinstance(item, dict)
        and isinstance(item.get("label"), str)
        and isinstance(item.get("statement"), str)
        and isinstance(item.get("evidence"), list)
        and all(isinstance(event_id, str) for event_id in item["evidence"])
        for item in explanations
    )


def investigate_operational(
    case: InvestigationCase,
    telemetry: Telemetry,
    findings: list[Finding],
    *,
    llm: LLMClient | None = None,
    profile: OperationalProfile | None = None,
    environment: EnvironmentModel | None = None,
) -> InvestigationState:
    """Run D1 with a model, or deterministic specialists when none is requested.

    Each invocation owns its tools, counters and run ID, even if a caller reuses the
    model client. A configured but unavailable model produces an incomplete result.
    Partial model conclusions remain in the audit results, but are withheld from the
    reportable claims and final disposition when execution cannot complete reliably.
    """
    profile = profile or OperationalProfile()
    started = time.perf_counter()
    tools = ToolBox(
        telemetry, findings, [case], tool_call_budget=profile.tool_call_budget,
        max_rows=profile.tool_max_rows, max_chars=profile.tool_max_chars, ledger=True,
    )
    verifier = ClaimVerifier(telemetry)
    model_requested = llm is not None and not isinstance(llm, NullLLM)
    guarded = _OperationalLLM(llm, profile, started) if model_requested else None
    if guarded is not None:
        engine = D1Investigator(
            tools, verifier, llm=guarded,
            config=InvestigatorConfig(
                max_steps=profile.max_steps, max_probes=profile.max_probes,
                max_tokens=profile.max_output_tokens,
                time_budget_seconds=profile.time_budget_seconds,
                token_budget=profile.token_budget, reject_unretrieved=True, prompt_contract=True,
            ),
        )
    else:
        engine = InvestigationOrchestrator(
            tools, verifier, llm=NullLLM(), environment=environment,
            config=InvestigationConfig(
                max_steps=profile.max_steps, use_llm_planner=False, use_llm_synthesis=False,
                tool_output_budget=4096, time_budget_seconds=profile.time_budget_seconds,
                token_budget=profile.token_budget, reject_unretrieved=True, prompt_contract=True,
            ),
        )
    state = engine.investigate(case)
    state.environment = environment
    state.run_id = str(uuid4())
    state.llm_requested = model_requested
    elapsed = time.perf_counter() - started
    reasons = list(state.llm_errors)
    if model_requested and not guarded.available:
        reasons.append("configured model unavailable")
        state.llm_errors.append("configured model unavailable")
    if state.llm_unparseable_responses:
        reasons.append("unparseable model reply")
    if state.status in (InvestigationStatus.STEP_LIMIT, InvestigationStatus.BUDGET_LIMIT):
        reasons.append(state.status.value)
    stop = state.investigation.get("stop_reason", "")
    if model_requested and stop != "model chose no probe":
        reasons.append(stop or "model investigation did not conclude")
    if tools.budget_hits:
        reasons.append("tool budget exhausted")
    if elapsed >= profile.time_budget_seconds:
        reasons.append("time budget exhausted")
    if guarded is not None and guarded.tokens_used >= profile.token_budget:
        reasons.append("token budget exhausted")
    if state.rejected_claims:
        reasons.append("claims failed evidence verification")
    rounds = state.investigation.get("rounds", [])
    if any(r.get("invalid_probe") or any(r.get("dropped", {}).values()) for r in rounds):
        reasons.append("model reply contained invalid or over-limit decisions")
    if model_requested and state.investigation.get("final_disposition") in ("benign", "malicious"):
        if not any(c.source == "llm" and c.evidence_ids for c in state.claims):
            reasons.append("model disposition has no accepted cited explanation")
    reasons = list(dict.fromkeys(reasons))
    original_status = state.status.value
    original_disposition = state.investigation.get("final_disposition")
    if reasons:
        state.status = InvestigationStatus.INCOMPLETE
        state.claims = [claim for claim in state.claims if claim.source != "llm"]
        if model_requested:
            state.investigation["final_disposition"] = "abstain"
            state.investigation["abstained"] = True
            # Keep provisional results for audit, explicitly labelled when the report
            # builder incorporates their notes into its limitations.
            state.results = [
                replace(result, notes=tuple("Provisional model output (incomplete): " + n for n in result.notes))
                if result.agent == "investigator:conclude" else result
                for result in state.results
            ]
        state.plan_log.append("operational result incomplete: " + "; ".join(reasons))
    state.investigation["operational"] = {
        "profile": profile.to_dict(), "profile_sha256": profile.sha256(),
        "engine": "d1" if model_requested else "deterministic",
        "outcome": "incomplete" if reasons else "complete", "reasons": reasons,
        "engine_status": original_status, "model_disposition": original_disposition,
        "elapsed_seconds": elapsed,
        "tokens_used": guarded.tokens_used if guarded is not None and not guarded.usage_unknown else None,
        "tool_calls_served": tools.calls_served, "tool_calls_refused": tools.budget_hits,
        "tool_results_truncated": tools.truncations,
    }
    return state
