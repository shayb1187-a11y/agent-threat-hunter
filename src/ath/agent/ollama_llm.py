"""A local model behind the same boundary as the hosted one.

Why a second module rather than a second branch in :mod:`ath.agent.llm`
-------------------------------------------------------------------------
``ath.agent.llm`` holds constants the M19/M19b environment freeze reads by name -- the
endpoint, the version header, the retry set, the ``AnthropicLLM`` defaults -- and the
freeze is the thing that lets a reader say what a published row ran under. Editing that
module to add a provider would move a frozen surface for a change that has nothing to do
with the frozen experiment. So the local client lives here and *imports* what it shares:
the response type, the token accounting, the JSON extraction and the retry set. The
orchestrator sees an :class:`~ath.agent.llm.LLMClient` and cannot tell the difference,
which is the point.

What is the same
-----------------
* ``complete(system, prompt, max_tokens)`` and nothing else. Sampling (temperature,
  seed), the context window, thinking and the output format are *construction*
  attributes: an experiment that varies them builds a different client, and the row
  header says which.
* Usage is what the daemon reported (``prompt_eval_count`` / ``eval_count``), never an
  estimate; a body without counts records ``None``, never ``0``.
* A reply cut off by the generation cap is an error naming the cap; a reply with no text
  is an error; a reply in prose is *not* an error -- it parses to ``None`` and the
  orchestrator counts it, exactly as the pre-registration fixed for the hosted arms.
* Permanent HTTP failures (400, 404) fail at once with an actionable message; transient
  ones retry with exponential backoff; a daemon that is not running is a transport error
  that names the URL it tried.

What is different, and why it is refused rather than tolerated
----------------------------------------------------------------
Ollama truncates a prompt that does not fit ``num_ctx`` by dropping its *beginning*,
silently. A synthesis prompt that lost its first claims would produce a confident answer
about half the case and a row that looked healthy. So the client estimates the prompt
before sending and refuses -- as an :attr:`LLMResponse.error`, so the row degrades
visibly -- when the estimate plus the generation cap would not fit. The estimate is
deliberately conservative (:data:`CHARS_PER_TOKEN`); the measured ``prompt_eval_count``
is recorded beside it on every call so the estimator can be calibrated from the rows
rather than argued about.

Per-call telemetry the hosted client has no source for -- load, prefill and generation
durations, and tokens per second derived from them -- goes into the token log. A local
run is bounded by the laptop, and a row that cannot say whether its 15-minute call was
generation or paging cannot be diagnosed.
"""

from __future__ import annotations

import hashlib
import json
import math
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from ath.agent.llm import (
    ERROR_MESSAGE_CHARS,
    NO_TEXT_BLOCK,
    LLMResponse,
    TokenAccounting,
    _parse_json,
    _RETRYABLE_STATUS,
)
from ath.logging_setup import get_logger

logger = get_logger(__name__)

PROVIDER = "ollama"
"""The value ``LLMClient.name`` carries, and therefore ``CaseResult.configuration``."""

DEFAULT_BASE_URL = "http://127.0.0.1:11434"
CHAT_PATH = "/api/chat"
SHOW_PATH = "/api/show"
TAGS_PATH = "/api/tags"
VERSION_PATH = "/api/version"
PS_PATH = "/api/ps"

DEFAULT_NUM_CTX = 10240
"""Context window sent as ``options.num_ctx``: the V1 compaction budget (6-8K) plus tool
output and the reply. Sent on every call rather than left to the model file, because a
row must be able to say what window it ran under."""

DEFAULT_NUM_PREDICT_CAP = 2048
"""Largest ``num_predict`` this client sends, whatever ``max_tokens`` a caller asks for.

The orchestrator asks for 8192 because hosted thinking tokens count against the cap. A
local model with thinking off answers a planner prompt in well under a hundred tokens and
a synthesis prompt in a few hundred; letting the cap take 8192 of a 10240 window would
leave 2048 for the prompt and refuse nearly every synthesis call. The cap actually sent
is recorded per call so a truncation names the number that truncated it.
"""

DEFAULT_KEEP_ALIVE = -1
"""Keep the weights loaded between calls. A 9B that reloads per call spends longer
loading than answering."""

DEFAULT_TIMEOUT_SECONDS = 900
"""Per-attempt socket timeout. CPU prefill of an 8K prompt on a 9B is minutes, not
seconds; the hosted client's 60 s would time out every scored call."""

CHARS_PER_TOKEN = 3.0
"""The pre-send estimator's ratio. English prose runs near 4; evidence ids such as
``evt-000123`` and JSON scaffolding run nearer 2.5-3. Three over-estimates prose and is
about right for what these prompts mostly contain, so a refusal errs toward refusing a
prompt that would have fit rather than sending one that would have been cut."""

NS_PER_SECOND = 1_000_000_000

_TRANSPORT_ERRORS = (urllib.error.URLError, TimeoutError, socket.timeout, OSError)


@dataclass(frozen=True)
class Sampling:
    """The two sampling parameters V1 pre-registers, and no others.

    D1 (single pass) runs ``temperature=0`` with a fixed seed. D2-D4 run ``0.7`` with a
    seed list, one client per seed. Both are recorded in the freeze and on every row.
    """

    temperature: float = 0.0
    seed: int | None = 0

    def to_dict(self) -> dict[str, Any]:
        return {"temperature": self.temperature, "seed": self.seed}


D1_SAMPLING = Sampling(temperature=0.0, seed=0)
"""The V1 D1 policy: greedy, seeded, so two runs of one arm differ only where the daemon
itself is nondeterministic (and a difference is then a finding about the daemon)."""


class OllamaUnavailable(RuntimeError):
    """The daemon or the model could not be described. Raised by :meth:`OllamaLLM.describe`
    only -- :meth:`OllamaLLM.complete` never raises, it degrades."""


def estimate_tokens(text: str) -> int:
    """A conservative token estimate for the pre-send context check."""
    return int(math.ceil(len(text) / CHARS_PER_TOKEN))


def context_budget_error(estimated: int, num_predict: int, num_ctx: int) -> str:
    return (
        f"prompt (~{estimated} tokens estimated) plus num_predict={num_predict} exceeds "
        f"num_ctx={num_ctx}; refused before sending, because Ollama would have dropped "
        "the start of the prompt silently"
    )


def generation_cap_error(num_predict: int, has_text: bool) -> str:
    suffix = "" if has_text else " with no text"
    return f"response truncated at num_predict={num_predict}{suffix}"


def _error_detail(body: Any) -> str:
    """Ollama's error body is ``{"error": "<message>"}``. Bounded like the hosted one."""
    if not isinstance(body, dict):
        return ""
    message = body.get("error")
    if not isinstance(message, str) or not message:
        return ""
    if len(message) > ERROR_MESSAGE_CHARS:
        message = message[:ERROR_MESSAGE_CHARS] + "..."
    return message


def _count(body: dict[str, Any], key: str) -> int | None:
    value = body.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _seconds(body: dict[str, Any], key: str) -> float | None:
    value = _count(body, key)
    return None if value is None else round(value / NS_PER_SECOND, 3)


def _rate(tokens: int | None, seconds: float | None) -> float | None:
    """Tokens per second, or ``None`` when either side was not reported or is zero.

    A rate computed from a zero duration would be infinite, and one computed from a
    missing count would be a guess; both would be read as a measurement."""
    if tokens is None or seconds is None or seconds <= 0 or tokens <= 0:
        return None
    return round(tokens / seconds, 1)


def _read_json(request: urllib.request.Request, timeout: float) -> Any:
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _error_body(exc: Any) -> Any:
    try:
        return json.loads(exc.read().decode("utf-8"))
    except Exception:  # noqa: BLE001 -- reading an error body is strictly best-effort
        return None


class OllamaLLM(TokenAccounting):
    """The local client. See the module docstring for what it shares and what it refuses."""

    name = PROVIDER

    def __init__(
        self,
        model: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        sampling: Sampling = D1_SAMPLING,
        num_ctx: int = DEFAULT_NUM_CTX,
        num_predict_cap: int = DEFAULT_NUM_PREDICT_CAP,
        think: bool | None = False,
        format: str | dict[str, Any] | None = "json",
        keep_alive: int | str = DEFAULT_KEEP_ALIVE,
        max_attempts: int = 3,
        backoff_seconds: float = 1.0,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        request_observer: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        super().__init__()
        if not model:
            raise ValueError("an Ollama client needs a model tag, e.g. 'qwen3.5:4b'")
        if num_ctx <= 0 or num_predict_cap <= 0:
            raise ValueError("num_ctx and num_predict_cap must be positive")
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.sampling = sampling
        self.num_ctx = num_ctx
        self.num_predict_cap = num_predict_cap
        self.think = think
        self.format = format
        self.keep_alive = keep_alive
        self.max_attempts = max(1, max_attempts)
        self.backoff_seconds = backoff_seconds
        self.timeout_seconds = timeout_seconds
        self.request_observer = request_observer
        """Measurement-only hook, same contract as the hosted client's: called once per
        :meth:`complete` before anything is sent, return value ignored, exceptions not
        caught. Exactly one call per ``complete`` so it pairs by position with the token
        log, including on the calls the context check refuses."""
        self.available = True
        """No credential exists to be missing. Whether the daemon and the model exist is a
        preflight question -- :meth:`describe` -- not an availability flag, because a
        client that flipped to unavailable mid-run would turn a model arm into arm A."""

    # -- what is frozen -----------------------------------------------------------------

    def configuration(self) -> dict[str, Any]:
        """Everything about this client a freeze must record. No credential, none exists."""
        return {
            "provider": self.name,
            "model": self.model,
            "base_url": self.base_url,
            "endpoint": CHAT_PATH,
            "sampling": self.sampling.to_dict(),
            "num_ctx": self.num_ctx,
            "num_predict_cap": self.num_predict_cap,
            "think": self.think,
            "format": self.format if isinstance(self.format, str) or self.format is None else "schema",
            # A schema is not dumped into the freeze, but *which* schema is gated: two
            # runs under different output grammars are different experiments.
            "format_schema_sha256": (
                None if isinstance(self.format, str) or self.format is None
                else hashlib.sha256(
                    json.dumps(self.format, sort_keys=True).encode("utf-8")
                ).hexdigest()
            ),
            "keep_alive": self.keep_alive,
            "timeout_seconds_per_attempt": self.timeout_seconds,
            "max_attempts": self.max_attempts,
            "backoff_seconds": self.backoff_seconds,
            "retryable_statuses": sorted(_RETRYABLE_STATUS),
            "chars_per_token_estimate": CHARS_PER_TOKEN,
            "transport": "urllib (stdlib); no SDK, by project choice",
        }

    # -- the request ----------------------------------------------------------------------

    def num_predict_for(self, max_tokens: int) -> int:
        return max(1, min(int(max_tokens), self.num_predict_cap))

    def build_request_body(self, system: str, prompt: str, max_tokens: int) -> dict[str, Any]:
        """The ``/api/chat`` body, as a dict. Key order fixed: bytes are measured."""
        options: dict[str, Any] = {
            "temperature": self.sampling.temperature,
            "num_ctx": self.num_ctx,
            "num_predict": self.num_predict_for(max_tokens),
        }
        if self.sampling.seed is not None:
            options["seed"] = self.sampling.seed
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "keep_alive": self.keep_alive,
            "options": options,
        }
        if self.format is not None:
            body["format"] = self.format
        if self.think is not None:
            body["think"] = self.think
        return body

    def _measurement(
        self, body: dict[str, Any], payload: bytes, estimated: int,
    ) -> dict[str, Any]:
        """Same keys as :func:`ath.agent.llm.request_measurement`, plus the local ones."""
        system = str(body["messages"][0]["content"])
        user = str(body["messages"][1]["content"])
        system_bytes = len(system.encode("utf-8"))
        user_bytes = len(user.encode("utf-8"))
        return {
            "model": body["model"],
            "max_tokens": body["options"]["num_predict"],
            "request_bytes": len(payload),
            "system_chars": len(system),
            "system_bytes": system_bytes,
            "user_chars": len(user),
            "user_bytes": user_bytes,
            "messages": len(body["messages"]),
            "envelope_bytes": len(payload) - system_bytes - user_bytes,
            "provider": self.name,
            "num_ctx": self.num_ctx,
            "estimated_prompt_tokens": estimated,
        }

    def _describe_http_error(self, exc: Any, body: Any) -> str:
        code = getattr(exc, "code", None)
        hints = {
            400: "the request was rejected (an unsupported option or field for this model)",
            404: (
                f"model {self.model!r} is not present on {self.base_url}; "
                f"run `ollama pull {self.model}`"
            ),
            500: "the daemon failed (out of memory, or the model failed to load)",
            503: "the daemon is busy or still loading the model",
        }
        hint = hints.get(code, "")
        detail = _error_detail(body)
        text = f"HTTP {code if code is not None else '?'}"
        if hint:
            text += f" ({hint})"
        if detail:
            text += f"; {detail}"
        return text

    # -- the call -------------------------------------------------------------------------

    def complete(self, system: str, prompt: str, max_tokens: int = 1024) -> LLMResponse:
        body_sent = self.build_request_body(system, prompt, max_tokens)
        payload = json.dumps(body_sent).encode("utf-8")
        num_predict = body_sent["options"]["num_predict"]
        estimated = estimate_tokens(system) + estimate_tokens(prompt)
        if self.request_observer is not None:
            self.request_observer(self._measurement(body_sent, payload, estimated))

        if estimated + num_predict > self.num_ctx:
            error = context_budget_error(estimated, num_predict, self.num_ctx)
            logger.warning("Ollama call refused (%s); continuing deterministically", error)
            self._record_usage(
                None, None, model=self.model, attempts=0, error=error,
                estimated_prompt_tokens=estimated, num_predict=num_predict, sent=False,
            )
            return LLMResponse(error=error, model=self.model)

        last_error = "no attempt made"
        for attempt in range(self.max_attempts):
            request = urllib.request.Request(
                self.base_url + CHAT_PATH, data=payload,
                headers={"content-type": "application/json"},
            )
            try:
                body = _read_json(request, self.timeout_seconds)
            except urllib.error.HTTPError as exc:
                last_error = self._describe_http_error(exc, _error_body(exc))
                if exc.code not in _RETRYABLE_STATUS:
                    logger.error(
                        "Ollama call failed permanently (%s); continuing deterministically",
                        last_error,
                    )
                    self._record_usage(
                        None, None, model=self.model, attempts=attempt + 1,
                        error=last_error, estimated_prompt_tokens=estimated,
                        num_predict=num_predict, sent=True,
                    )
                    return LLMResponse(error=last_error, model=self.model)
            except json.JSONDecodeError as exc:
                last_error = f"JSONDecodeError: {exc} (the daemon answered with a non-JSON body)"
            except _TRANSPORT_ERRORS as exc:
                last_error = (
                    f"{type(exc).__name__}: {exc} (is the Ollama daemon running at "
                    f"{self.base_url}?)"
                )
            else:
                return self._finish(body, estimated, num_predict, attempt + 1)

            if attempt + 1 < self.max_attempts:
                delay = self.backoff_seconds * (2 ** attempt)
                logger.warning(
                    "Ollama call failed (%s); retrying in %.1fs (attempt %d/%d)",
                    last_error, delay, attempt + 2, self.max_attempts,
                )
                time.sleep(delay)

        logger.error(
            "Ollama call failed after %d attempt(s) (%s); continuing deterministically",
            self.max_attempts, last_error,
        )
        self._record_usage(
            None, None, model=self.model, attempts=self.max_attempts, error=last_error,
            estimated_prompt_tokens=estimated, num_predict=num_predict, sent=True,
        )
        return LLMResponse(error=last_error, model=self.model)

    def _finish(
        self, body: Any, estimated: int, num_predict: int, attempts: int,
    ) -> LLMResponse:
        if not isinstance(body, dict):
            body = {}
        message = body.get("message") if isinstance(body.get("message"), dict) else {}
        content = message.get("content")
        text = content if isinstance(content, str) else ""
        done_reason = body.get("done_reason")
        done_reason = done_reason if isinstance(done_reason, str) else None
        truncated = done_reason == "length"
        has_text = bool(text.strip())
        used_in, used_out = _count(body, "prompt_eval_count"), _count(body, "eval_count")
        prompt_seconds = _seconds(body, "prompt_eval_duration")
        eval_seconds = _seconds(body, "eval_duration")

        if truncated:
            error: str | None = generation_cap_error(num_predict, has_text)
        elif not has_text:
            error = NO_TEXT_BLOCK
        else:
            error = None

        self._record_usage(
            used_in, used_out, model=self.model, attempts=attempts,
            stop_reason=done_reason, has_text=has_text, error=error,
            estimated_prompt_tokens=estimated, num_predict=num_predict, sent=True,
            load_seconds=_seconds(body, "load_duration"),
            prompt_eval_seconds=prompt_seconds,
            eval_seconds=eval_seconds,
            total_seconds=_seconds(body, "total_duration"),
            prompt_tokens_per_second=_rate(used_in, prompt_seconds),
            eval_tokens_per_second=_rate(used_out, eval_seconds),
        )
        if error is not None:
            logger.warning("Ollama call unusable (%s); continuing deterministically", error)
        return LLMResponse(
            text=text, model=self.model,
            parsed=_parse_json(text) if error is None else None,
            error=error, input_tokens=used_in, output_tokens=used_out,
            stop_reason=done_reason, truncated=truncated,
        )

    # -- preflight ------------------------------------------------------------------------

    def loaded(self, timeout: float = 10.0) -> dict[str, dict[str, Any]]:
        """Models the daemon currently holds in memory, by tag: ``{size, size_vram, digest}``.

        Never raises: a guard that cannot read ``/api/ps`` must answer "nothing resident",
        which is the conservative answer, not an exception that ends the run.
        """
        try:
            payload = _read_json(urllib.request.Request(self.base_url + PS_PATH), timeout)
        except (*_TRANSPORT_ERRORS, json.JSONDecodeError):
            return {}
        models = payload.get("models", []) if isinstance(payload, dict) else []
        loaded: dict[str, dict[str, Any]] = {}
        for entry in models:
            if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                continue
            loaded[entry["name"]] = {
                "size": _count(entry, "size"),
                "size_vram": _count(entry, "size_vram"),
                "digest": entry.get("digest"),
            }
        return loaded

    def resident_bytes(self, timeout: float = 10.0) -> int:
        """Bytes of *system* memory this client's model already occupies, or ``0``.

        A model the daemon has kept alive does not need its floor a second time; the RAM
        guard credits this figure. Only the part not in VRAM counts, because VRAM is not
        the memory the OS would page.
        """
        entry = self.loaded(timeout).get(self.model)
        if not entry or entry.get("size") is None:
            return 0
        return max(0, int(entry["size"]) - int(entry.get("size_vram") or 0))

    def describe(self, timeout: float = 10.0) -> dict[str, Any]:
        """What the daemon says it is and what the model is. For freezes and probes.

        Raises :class:`OllamaUnavailable` with the action to take, because a freeze that
        recorded "unknown" for the model digest would freeze nothing.
        """
        try:
            version = _read_json(urllib.request.Request(self.base_url + VERSION_PATH), timeout)
            tags = _read_json(urllib.request.Request(self.base_url + TAGS_PATH), timeout)
        except _TRANSPORT_ERRORS as exc:
            raise OllamaUnavailable(
                f"no Ollama daemon answered at {self.base_url} "
                f"({type(exc).__name__}: {exc}); start it with `ollama serve` or point "
                "base_url at the right host"
            ) from exc
        models = tags.get("models", []) if isinstance(tags, dict) else []
        entry = next(
            (m for m in models if isinstance(m, dict) and m.get("name") == self.model),
            None,
        )
        if entry is None:
            present = sorted(str(m.get("name")) for m in models if isinstance(m, dict))
            raise OllamaUnavailable(
                f"model {self.model!r} is not present on {self.base_url} (present: "
                f"{present or 'none'}); run `ollama pull {self.model}`"
            )
        try:
            show = _read_json(
                urllib.request.Request(
                    self.base_url + SHOW_PATH,
                    data=json.dumps({"model": self.model}).encode("utf-8"),
                    headers={"content-type": "application/json"},
                ),
                timeout,
            )
        except _TRANSPORT_ERRORS as exc:
            raise OllamaUnavailable(
                f"{self.base_url}{SHOW_PATH} failed for {self.model!r}: {exc}"
            ) from exc
        details = entry.get("details") if isinstance(entry.get("details"), dict) else {}
        info = (
            show.get("model_info")
            if isinstance(show, dict) and isinstance(show.get("model_info"), dict)
            else {}
        )
        context_length = next(
            (v for k, v in info.items() if k.endswith(".context_length") and isinstance(v, int)),
            None,
        )
        return {
            "provider": self.name,
            "base_url": self.base_url,
            "daemon_version": version.get("version") if isinstance(version, dict) else None,
            "model": self.model,
            "digest": entry.get("digest"),
            "size_bytes": entry.get("size"),
            "modified_at": entry.get("modified_at"),
            "family": details.get("family"),
            "parameter_size": details.get("parameter_size"),
            "quantization_level": details.get("quantization_level"),
            "format": details.get("format"),
            "capabilities": list(show.get("capabilities", [])) if isinstance(show, dict) else [],
            "model_context_length": context_length,
            "configuration": self.configuration(),
        }
