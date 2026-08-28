"""The language-model boundary.

Everything model-related is behind :class:`LLMClient`, for one reason: **the pipeline
must be fully testable and fully runnable without an API key.** A security tool that
cannot be evaluated offline cannot be evaluated at all -- you would be measuring the
model's mood rather than your system.

Three implementations:

``NullLLM``
    No model. The orchestrator falls back to its deterministic planner and produces
    evidence-backed claims from the specialists alone. This is the **default**, and the
    whole investigation still works -- which is the point. The model is an enhancement,
    not a load-bearing component.

``ScriptedLLM``
    Returns canned responses in order. Used in tests to drive specific paths, including
    deliberately malicious ones: a scripted response that cites a fabricated event id
    is how we prove the verifier actually rejects hallucinations.

``AnthropicLLM``
    The real client. Used only when an API key is configured.

Note what the model is *not* allowed to do, enforced structurally elsewhere:
it cannot create findings, assign ATT&CK techniques, link findings into cases, author a
FACT, or invoke any tool that changes state. It plans and it synthesises. Everything it
says passes through :class:`~ath.agent.claims.ClaimVerifier`.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from ath.config import DEFAULT_MODEL
from ath.logging_setup import get_logger

logger = get_logger(__name__)


@dataclass
class LLMResponse:
    """A model response, plus the bookkeeping needed to audit it.

    Attributes:
        text: Raw response text.
        model: Model identifier that produced it.
        parsed: Parsed JSON payload when the response was expected to be structured.
        error: Populated when the call or the parse failed. Callers must degrade
            gracefully rather than propagate -- a model outage should downgrade the
            investigation to deterministic mode, not break it.
    """

    text: str = ""
    model: str = ""
    parsed: dict[str, Any] | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


@runtime_checkable
class LLMClient(Protocol):
    """Minimal interface the orchestrator depends on."""

    name: str
    available: bool

    def complete(self, system: str, prompt: str, max_tokens: int = 1024) -> LLMResponse:
        """Return a completion for ``prompt``."""
        ...


class NullLLM:
    """No model available. The orchestrator uses its deterministic planner."""

    name = "none"
    available = False

    def complete(self, system: str, prompt: str, max_tokens: int = 1024) -> LLMResponse:
        return LLMResponse(error="no LLM configured", model=self.name)


@dataclass
class ScriptedLLM:
    """Returns pre-set responses in order. For tests only.

    Attributes:
        responses: Response strings, consumed in order.
        calls: Every (system, prompt) pair received, so tests can assert on what the
            orchestrator actually asked -- including that raw telemetry was never sent.
    """

    responses: list[str] = field(default_factory=list)
    name: str = "scripted"
    available: bool = True
    calls: list[tuple[str, str]] = field(default_factory=list)
    _index: int = 0

    def complete(self, system: str, prompt: str, max_tokens: int = 1024) -> LLMResponse:
        self.calls.append((system, prompt))
        if self._index >= len(self.responses):
            return LLMResponse(error="scripted responses exhausted", model=self.name)
        text = self.responses[self._index]
        self._index += 1
        return LLMResponse(text=text, model=self.name, parsed=_parse_json(text))


# HTTP statuses worth retrying. Everything else (401 bad key, 403 no access, 404
# unknown model, 400 malformed request) is a configuration error that will reproduce
# identically on every attempt.
_RETRYABLE_STATUS: frozenset[int] = frozenset({408, 409, 429, 500, 502, 503, 504, 529})


def _describe_http_error(exc: Any) -> str:
    """Turn an HTTPError into something an operator can act on.

    ``HTTPError: HTTP Error 401: Unauthorized`` tells you what happened but not what to
    do about it. Since the whole point of surfacing this is that a misconfigured key
    must not masquerade as "deterministic mode by choice", the hint matters.
    """
    hints = {
        400: "the request was rejected as malformed",
        401: "ATH_LLM_API_KEY is missing or invalid",
        403: "this API key is not permitted to use that model",
        404: f"unknown model -- check ATH_LLM_MODEL",
        429: "rate limited",
    }
    hint = hints.get(getattr(exc, "code", None), "")
    suffix = f" ({hint})" if hint else ""
    return f"HTTP {getattr(exc, 'code', '?')}{suffix}"


class AnthropicLLM:
    """Calls the Anthropic Messages API.

    Deliberately dependency-free (``urllib``) so the project's core requirements do not
    grow an SDK for one HTTP call. The cost of that choice is that retry and error
    classification are ours to implement rather than the SDK's -- so they are
    implemented here rather than left absent.
    """

    name = "anthropic"

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        max_attempts: int = 3,
        backoff_seconds: float = 1.0,
    ) -> None:
        self._api_key = api_key
        self.model = model
        self.available = bool(api_key)
        self.max_attempts = max(1, max_attempts)
        self.backoff_seconds = backoff_seconds

    def complete(self, system: str, prompt: str, max_tokens: int = 1024) -> LLMResponse:
        import urllib.error
        import urllib.request

        payload = json.dumps({
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }).encode("utf-8")

        last_error = "no attempt made"
        for attempt in range(self.max_attempts):
            request = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=payload,
                headers={
                    "content-type": "application/json",
                    "x-api-key": self._api_key,
                    "anthropic-version": "2023-06-01",
                },
            )
            try:
                with urllib.request.urlopen(request, timeout=60) as response:
                    body = json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                last_error = _describe_http_error(exc)
                if exc.code not in _RETRYABLE_STATUS:
                    # 401/403/404/400 will fail identically forever. Retrying wastes
                    # time and, worse, buries a misconfiguration under transient-
                    # looking noise. Fail immediately with an actionable message.
                    logger.error(
                        "LLM call failed permanently (%s); continuing deterministically",
                        last_error,
                    )
                    return LLMResponse(error=last_error, model=self.model)
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
            else:
                text = "".join(
                    block.get("text", "") for block in body.get("content", [])
                    if block.get("type") == "text"
                )
                return LLMResponse(text=text, model=self.model, parsed=_parse_json(text))

            if attempt + 1 < self.max_attempts:
                delay = self.backoff_seconds * (2**attempt)
                logger.warning(
                    "LLM call failed (%s); retrying in %.1fs (attempt %d/%d)",
                    last_error, delay, attempt + 2, self.max_attempts,
                )
                time.sleep(delay)

        logger.error(
            "LLM call failed after %d attempt(s) (%s); continuing deterministically",
            self.max_attempts, last_error,
        )
        return LLMResponse(error=last_error, model=self.model)


def _parse_json(text: str) -> dict[str, Any] | None:
    """Best-effort JSON extraction from a model response.

    Models wrap JSON in prose or fences no matter how firmly you ask them not to, so we
    strip fences and fall back to the outermost brace pair. Returning ``None`` on
    failure is fine: the caller degrades to the deterministic path.
    """
    candidate = text.strip()
    if candidate.startswith("```"):
        lines = [ln for ln in candidate.splitlines() if not ln.strip().startswith("```")]
        candidate = "\n".join(lines).strip()
    try:
        parsed = json.loads(candidate)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass

    start, end = candidate.find("{"), candidate.rfind("}")
    if start != -1 and end > start:
        try:
            parsed = json.loads(candidate[start : end + 1])
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None
    return None


def build_llm(api_key: str | None = None, model: str = DEFAULT_MODEL) -> LLMClient:
    """Return a real client when a key is configured, otherwise :class:`NullLLM`."""
    key = api_key or os.getenv("ATH_LLM_API_KEY")
    if not key:
        logger.info("No LLM API key configured; investigating in deterministic mode")
        return NullLLM()
    return AnthropicLLM(key, model)
