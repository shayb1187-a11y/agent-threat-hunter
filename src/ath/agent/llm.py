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

Cost is measured, never estimated
----------------------------------
Every client reports what the *provider* said it spent, not what this codebase guessed.
:class:`LLMResponse` carries ``input_tokens`` / ``output_tokens`` read from the Messages
API's ``usage`` object, and a client accumulates them into ``tokens_used`` with a
per-call log. A response that reports no usage records ``None``, never ``0``: "the model
spent nothing" and "nobody told us what it spent" are different facts, and an ablation
whose cost column silently contains the second wearing the first's clothes is not a cost
column at all.

A reply that was cut off, or that contains no text, is an error
--------------------------------------------------------------
Thinking tokens count against ``max_tokens``. A response that hits the cap comes back
with ``stop_reason == "max_tokens"`` and may carry no text block at all; a response that
thought and then stopped can carry only thinking blocks. Both parse to ``None``, and a
caller that treats ``None`` as "the model had nothing useful to say" would fall back to
its deterministic path while still reporting itself as a model arm. So both are returned
as :attr:`LLMResponse.error`, which is what makes them land in ``state.llm_errors`` and
degrade the row. The distinction this preserves is the one the whole class exists for:
*the model answered and the answer was unusable* is a different fact from *the model
never answered*, and neither is *the model was not asked*.

Note what the model is *not* allowed to do, enforced structurally elsewhere:
it cannot create findings, assign ATT&CK techniques, link findings into cases, author a
FACT, or invoke any tool that changes state. It plans and it synthesises. Everything it
says passes through :class:`~ath.agent.claims.ClaimVerifier`.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Protocol, runtime_checkable

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
        input_tokens: Prompt tokens the provider reported for this call, summed over
            every attempt that reported any. ``None`` when nothing was reported.
        output_tokens: Completion tokens, same rule.
        stop_reason: What the provider said ended the response (``end_turn``,
            ``max_tokens``, ``refusal``, ...), or ``None`` when it said nothing. Recorded
            rather than inspected-and-discarded: a row that degraded must be able to say
            which of the several ways a call can be useless actually happened.
        truncated: ``stop_reason == "max_tokens"`` -- the cap ended the response, so
            whatever text arrived is a fragment of an answer rather than an answer.
    """

    text: str = ""
    model: str = ""
    parsed: dict[str, Any] | None = None
    error: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    stop_reason: str | None = None
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def total_tokens(self) -> int | None:
        """Input plus output, or ``None`` when the provider reported neither."""
        if self.input_tokens is None and self.output_tokens is None:
            return None
        return (self.input_tokens or 0) + (self.output_tokens or 0)


API_ENDPOINT = "https://api.anthropic.com/v1/messages"
"""The Messages API endpoint. Named so the environment freeze records what is sent."""

ANTHROPIC_VERSION = "2023-06-01"
"""The ``anthropic-version`` header value this client pins."""

REQUEST_TIMEOUT_SECONDS = 60
"""Per-attempt socket timeout. The retry policy sits on top of it."""

ADAPTIVE_THINKING: dict[str, str] = {"type": "adaptive"}
"""The ``thinking`` block sent by default.

Sent explicitly rather than omitted. On the current models omitting it runs adaptive
thinking anyway, so the two are equivalent *today* -- but an experiment whose request
body depends on a provider default cannot say what it ran under, and the default is not
the same on every model in the family. No sampling parameter accompanies it:
``temperature``, ``top_p`` and ``top_k`` are rejected with a 400 by the models this
project targets, and sending one would fail every call rather than vary any output.
"""

NO_TEXT_BLOCK = "response contained no text block"
"""The reply completed and contained nothing to parse -- thinking only, or empty."""


def truncation_error(max_tokens: int, has_text: bool) -> str:
    """The error string for a reply the ``max_tokens`` cap ended.

    Names the cap because that is the actionable part: the fix for a truncated planner
    answer is a larger budget, and an error that says only "truncated" sends the reader
    looking for a model problem instead.
    """
    suffix = "" if has_text else " with no text"
    return f"response truncated at max_tokens={max_tokens}{suffix}"


@runtime_checkable
class LLMClient(Protocol):
    """Minimal interface the orchestrator depends on."""

    name: str
    available: bool

    def complete(self, system: str, prompt: str, max_tokens: int = 1024) -> LLMResponse:
        """Return a completion for ``prompt``."""
        ...


class TokenAccounting:
    """Per-call usage, kept by any client that can report it.

    Two things live here rather than in each client, so the ablation cannot read one
    number from one client and a differently-defined number from another:

    ``tokens_used``
        Running total, ``None`` until a provider reports something. The distinction is
        load-bearing: a case whose client reported nothing must appear as ``null`` in the
        results and never as ``0``, or the cost column quietly credits the most
        expensive arm with being free.
    ``token_log``
        One entry per call, so a per-case total can be checked against the calls that
        made it rather than trusted.
    """

    def __init__(self) -> None:
        self.tokens_used: int | None = None
        self.token_log: list[dict[str, Any]] = []

    def reset_token_accounting(self) -> None:
        """Start a new accounting period -- one case, in the ablation harness."""
        self.tokens_used = None
        self.token_log = []

    def _record_usage(
        self, input_tokens: int | None, output_tokens: int | None, **extra: Any
    ) -> None:
        entry: dict[str, Any] = {
            "input_tokens": input_tokens, "output_tokens": output_tokens, **extra,
        }
        self.token_log.append(entry)
        if input_tokens is None and output_tokens is None:
            return
        self.tokens_used = (self.tokens_used or 0) + (input_tokens or 0) + (
            output_tokens or 0
        )


class NullLLM:
    """No model available. The orchestrator uses its deterministic planner.

    Reports no ``tokens_used`` attribute at all, deliberately: a client that never spoke
    to a provider has nothing to say about cost, and ``0`` would be a claim.
    """

    name = "none"
    available = False

    def complete(self, system: str, prompt: str, max_tokens: int = 1024) -> LLMResponse:
        return LLMResponse(error="no LLM configured", model=self.name)


@dataclass
class ScriptedLLM(TokenAccounting):
    """Returns pre-set responses in order. For tests only.

    Reports *deterministic fake usage* -- a fixed input and output count per answered
    call -- so the plumbing from a provider's usage object to a per-case cost column can
    be asserted without a network. A call that returns an error reports no usage, because
    a failed call is not a cheap call.

    An entry may also be a ready-made :class:`LLMResponse`, which is how a test drives
    the failures that have no text to script: a reply truncated at the cap, or one that
    completed with no text block. Without that, the only model failure a test could
    stage was a transport error, and the two failures this milestone is about are
    neither transport errors nor parse failures.

    Attributes:
        responses: Response strings -- or whole :class:`LLMResponse` objects -- consumed
            in order.
        calls: Every (system, prompt) pair received, so tests can assert on what the
            orchestrator actually asked -- including that raw telemetry was never sent.
        fake_input_tokens: Prompt tokens claimed per answered call.
        fake_output_tokens: Completion tokens claimed per answered call.
    """

    responses: list[Any] = field(default_factory=list)
    name: str = "scripted"
    available: bool = True
    calls: list[tuple[str, str]] = field(default_factory=list)
    fake_input_tokens: int = 100
    fake_output_tokens: int = 50
    _index: int = 0

    def __post_init__(self) -> None:
        TokenAccounting.__init__(self)

    def complete(self, system: str, prompt: str, max_tokens: int = 1024) -> LLMResponse:
        self.calls.append((system, prompt))
        if self._index >= len(self.responses):
            self._record_usage(None, None, model=self.name, error="exhausted")
            return LLMResponse(error="scripted responses exhausted", model=self.name)
        item = self.responses[self._index]
        self._index += 1
        if isinstance(item, LLMResponse):
            reply = replace(item, model=item.model or self.name)
            if reply.ok and reply.parsed is None:
                reply = replace(reply, parsed=_parse_json(reply.text))
            self._record_usage(
                reply.input_tokens, reply.output_tokens, model=self.name,
                stop_reason=reply.stop_reason, has_text=bool(reply.text),
                error=reply.error,
            )
            return reply
        text = str(item)
        self._record_usage(
            self.fake_input_tokens, self.fake_output_tokens, model=self.name,
            stop_reason="end_turn", has_text=bool(text),
        )
        return LLMResponse(
            text=text, model=self.name, parsed=_parse_json(text),
            input_tokens=self.fake_input_tokens,
            output_tokens=self.fake_output_tokens,
            stop_reason="end_turn",
        )


def truncated_reply(
    max_tokens: int, *, text: str = "", model: str = "scripted"
) -> LLMResponse:
    """A reply the cap ended, as the client would return it. For tests and doubles."""
    return LLMResponse(
        text=text, model=model, error=truncation_error(max_tokens, bool(text)),
        stop_reason="max_tokens", truncated=True,
    )


def textless_reply(*, model: str = "scripted") -> LLMResponse:
    """A completed reply carrying no text block, as the client would return it."""
    return LLMResponse(
        model=model, error=NO_TEXT_BLOCK, stop_reason="end_turn",
    )


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


def build_request_body(
    *,
    model: str,
    max_tokens: int,
    system: str,
    prompt: str,
    adaptive_thinking: bool = True,
) -> dict[str, Any]:
    """The Messages API body :meth:`AnthropicLLM.complete` sends, as a dict.

    Extracted so a measurement can construct **the same bytes the client would send**
    without sending them. M19b-T2 had to answer "how large was the request that came
    back 413", and the only honest answer is one computed by the code that builds the
    request rather than by a second, similar-looking builder in a script: a
    reconstruction that differs by a field ordering differs by bytes, and bytes are the
    quantity under investigation.

    Key ordering is load-bearing and therefore fixed here: ``json.dumps`` preserves
    insertion order, so ``thinking`` is appended last exactly as it was when it was
    added conditionally at the call site.
    """
    body: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": prompt}],
    }
    if adaptive_thinking:
        body["thinking"] = dict(ADAPTIVE_THINKING)
    return body


def encode_request_body(body: dict[str, Any]) -> bytes:
    """The exact payload bytes for a body from :func:`build_request_body`."""
    return json.dumps(body).encode("utf-8")


def request_measurement(
    body: dict[str, Any], payload: bytes | None = None
) -> dict[str, Any]:
    """Sizes of one request, in the units the provider's limits are stated in.

    Characters and bytes are reported separately rather than one standing in for the
    other: an id list is ASCII and the two coincide, a hostname in another script is
    not, and the whole question M19b-T2 asks is whether the limit that rejected a
    request counts bytes or tokens. Reporting only ``len(text)`` would make that
    question unanswerable from the artifact.

    ``envelope_bytes`` is the payload minus the raw UTF-8 size of the system and user
    text, so it carries the JSON scaffolding *and* whatever escaping those two strings
    needed. It is a residual, not a constant, and the artifact treats it as one.
    """
    if payload is None:
        payload = encode_request_body(body)
    system = str(body.get("system", ""))
    messages = body.get("messages") or []
    user = "".join(
        str(message.get("content", "")) for message in messages
        if isinstance(message, dict)
    )
    return {
        "model": body.get("model"),
        "max_tokens": body.get("max_tokens"),
        "request_bytes": len(payload),
        "system_chars": len(system),
        "system_bytes": len(system.encode("utf-8")),
        "user_chars": len(user),
        "user_bytes": len(user.encode("utf-8")),
        "messages": len(messages),
        "envelope_bytes": len(payload) - len(system.encode("utf-8")) - len(
            user.encode("utf-8")
        ),
    }


class AnthropicLLM(TokenAccounting):
    """Calls the Anthropic Messages API.

    Deliberately dependency-free (``urllib``) so the project's core requirements do not
    grow an SDK for one HTTP call. The cost of that choice is that retry and error
    classification are ours to implement rather than the SDK's -- so they are
    implemented here rather than left absent.

    Usage is read from the response, not estimated
    -----------------------------------------------
    The Messages API returns a ``usage`` object (``input_tokens``, ``output_tokens``) on
    every completed response. It is read from the parsed body and summed **across every
    attempt of one call that reported any** -- a retried call really did spend what the
    failed attempt spent, and a cost column that counts only the attempt that succeeded
    under-reports exactly the calls that were most expensive. A body without ``usage``
    is not an error and does not fail the call: it records ``None``, which is what the
    results file then says.

    What is sent, and what is deliberately not
    -------------------------------------------
    ``{model, max_tokens, thinking, system, messages}``. ``thinking`` is
    :data:`ADAPTIVE_THINKING` unless the caller turns it off. No sampling parameter is
    sent: ``temperature``, ``top_p`` and ``top_k`` are rejected outright by the models
    this project targets, and an ablation that varied one would be measuring the sampler
    rather than the architecture.

    What comes back is *inspected*, not merely parsed
    --------------------------------------------------
    Thinking tokens count against ``max_tokens``, so a cap that is too small ends the
    response before any text block is emitted. That reply parses to ``None`` exactly
    like a model answering in prose -- and the two must not be treated alike, because
    one is a run that lost its model and the other is a run whose model was unhelpful.
    ``stop_reason`` and the presence of a text block are therefore read on every call,
    recorded in the token log, and turned into an ``error`` when either says the answer
    is unusable.
    """

    name = "anthropic"

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        max_attempts: int = 3,
        backoff_seconds: float = 1.0,
        adaptive_thinking: bool = True,
        request_observer: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        super().__init__()
        self._api_key = api_key
        self.model = model
        self.available = bool(api_key)
        self.max_attempts = max(1, max_attempts)
        self.backoff_seconds = backoff_seconds
        self.adaptive_thinking = adaptive_thinking
        """Send ``thinking`` explicitly. Off only for a provider that rejects it."""
        self.request_observer = request_observer
        """Measurement-only callback, handed :func:`request_measurement` per call.

        Called once per :meth:`complete`, before the first attempt, and never consulted
        afterwards: it cannot alter the payload, the headers, the retry policy or the
        response. It exists because "what did we send" is a question this project had
        no way to answer without either sending the request or re-deriving it in a
        script that could be wrong. Exceptions raised by an observer are deliberately
        **not** caught -- a measurement hook that can silently fail measures nothing --
        so production code leaves it ``None``, which is the default.
        """

    def complete(self, system: str, prompt: str, max_tokens: int = 1024) -> LLMResponse:
        import urllib.error
        import urllib.request

        body_sent = build_request_body(
            model=self.model, max_tokens=max_tokens, system=system, prompt=prompt,
            adaptive_thinking=self.adaptive_thinking,
        )
        payload = encode_request_body(body_sent)
        if self.request_observer is not None:
            self.request_observer(request_measurement(body_sent, payload))

        last_error = "no attempt made"
        # Accumulated over the attempts of this one call, not over the client's life.
        spent_in: int | None = None
        spent_out: int | None = None
        attempts_with_usage = 0
        for attempt in range(self.max_attempts):
            request = urllib.request.Request(
                API_ENDPOINT,
                data=payload,
                headers={
                    "content-type": "application/json",
                    "x-api-key": self._api_key,
                    "anthropic-version": ANTHROPIC_VERSION,
                },
            )
            try:
                with urllib.request.urlopen(
                    request, timeout=REQUEST_TIMEOUT_SECONDS
                ) as response:
                    body = json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                last_error = _describe_http_error(exc)
                # A rejected attempt can still have cost tokens, and some errors carry
                # the usage that was spent before the failure. Reading it is best-effort
                # -- an unreadable error body must never turn a model outage into an
                # exception -- but ignoring it would make retries look free.
                used_in, used_out = _usage_of(_error_body(exc))
                if used_in is not None or used_out is not None:
                    attempts_with_usage += 1
                    spent_in = (spent_in or 0) + (used_in or 0)
                    spent_out = (spent_out or 0) + (used_out or 0)
                if exc.code not in _RETRYABLE_STATUS:
                    # 401/403/404/400 will fail identically forever. Retrying wastes
                    # time and, worse, buries a misconfiguration under transient-
                    # looking noise. Fail immediately with an actionable message.
                    logger.error(
                        "LLM call failed permanently (%s); continuing deterministically",
                        last_error,
                    )
                    self._record_usage(
                        spent_in, spent_out, model=self.model,
                        attempts=attempt + 1, error=last_error,
                    )
                    return LLMResponse(
                        error=last_error, model=self.model,
                        input_tokens=spent_in, output_tokens=spent_out,
                    )
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
            else:
                blocks = body.get("content", []) if isinstance(body, dict) else []
                text = "".join(
                    block.get("text", "") for block in blocks
                    if isinstance(block, dict) and block.get("type") == "text"
                )
                stop_reason = body.get("stop_reason") if isinstance(body, dict) else None
                stop_reason = stop_reason if isinstance(stop_reason, str) else None
                truncated = stop_reason == "max_tokens"
                has_text = bool(text.strip())
                used_in, used_out = _usage_of(body)
                if used_in is not None or used_out is not None:
                    attempts_with_usage += 1
                    spent_in = (spent_in or 0) + (used_in or 0)
                    spent_out = (spent_out or 0) + (used_out or 0)
                # An unusable reply still cost what it cost: usage is recorded before
                # the answer is judged, or the calls that spent a whole budget on
                # thinking and returned nothing would be the cheapest in the file.
                if truncated:
                    error = truncation_error(max_tokens, has_text)
                elif not has_text:
                    error = NO_TEXT_BLOCK
                else:
                    error = None
                self._record_usage(
                    spent_in, spent_out, model=self.model,
                    attempts=attempt + 1, attempts_with_usage=attempts_with_usage,
                    stop_reason=stop_reason, has_text=has_text,
                    output_tokens_reported=used_out, error=error,
                )
                if error is not None:
                    logger.warning(
                        "LLM call unusable (%s); continuing deterministically", error,
                    )
                return LLMResponse(
                    text=text, model=self.model,
                    parsed=_parse_json(text) if error is None else None,
                    error=error,
                    input_tokens=spent_in, output_tokens=spent_out,
                    stop_reason=stop_reason, truncated=truncated,
                )

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
        self._record_usage(
            spent_in, spent_out, model=self.model,
            attempts=self.max_attempts, error=last_error,
        )
        return LLMResponse(
            error=last_error, model=self.model,
            input_tokens=spent_in, output_tokens=spent_out,
        )


def _usage_of(body: Any) -> tuple[int | None, int | None]:
    """``(input_tokens, output_tokens)`` from a Messages API body, or ``(None, None)``.

    Tolerant by design. The API shape may grow fields, a proxy may strip them, and an
    error body may carry none at all -- none of which is a reason to fail a call that
    otherwise succeeded. What it will not do is invent a number: anything not present as
    an integer comes back as ``None``.
    """
    if not isinstance(body, dict):
        return None, None
    usage = body.get("usage")
    if not isinstance(usage, dict):
        return None, None

    def _count(key: str) -> int | None:
        value = usage.get(key)
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    return _count("input_tokens"), _count("output_tokens")


def _error_body(exc: Any) -> Any:
    """The JSON body of an HTTPError, or ``None``. Never raises."""
    try:
        raw = exc.read()
    except Exception:  # noqa: BLE001 -- reading an error body is strictly best-effort
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None


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
