"""The local client: what it sends, what it reads, and what it refuses to call an answer.

Why these tests exist
----------------------
Every scored local run in V1 goes through this client with nobody watching, and every
failure mode below is shaped like a success from the orchestrator's side: a prompt that
Ollama silently cut, a reply the generation cap ended mid-JSON, a daemon that was not
running, a model that was never pulled. In each case the planner would fall back to the
deterministic order and the row would be labelled a model arm. These tests pin the
client's answer to each, without a daemon, by faking ``urllib.request.urlopen`` exactly
as the hosted client's tests do.

How each fails
---------------
*Body shape.* Fails if a sampling parameter, the context window, the cap, ``think`` or
``format`` stops being sent -- the freeze would then record a setting the daemon never saw.

*Usage.* Fails if ``None`` becomes ``0``, if durations stop being recorded, or if a
tokens-per-second figure is invented from a zero duration.

*Refusals.* Fails if a too-long prompt is sent anyway (Ollama would truncate it), if a
missing model is retried (it will be missing on every attempt), or if a stopped daemon
is reported as anything but a transport error naming the URL.

*Semantics kept from the hosted client.* Fails if a prose reply becomes an error (the
pre-registration counts it, it does not retry it), or if the observer and the token log
stop pairing one-to-one.
"""

from __future__ import annotations

import io
import json
import urllib.error

import pytest

from ath.agent.llm import NO_TEXT_BLOCK, LLMClient
from ath.agent.ollama_llm import (
    CHARS_PER_TOKEN,
    CHAT_PATH,
    D1_SAMPLING,
    DEFAULT_NUM_CTX,
    DEFAULT_NUM_PREDICT_CAP,
    OllamaLLM,
    OllamaUnavailable,
    Sampling,
    estimate_tokens,
)


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _transport(monkeypatch, outcomes):
    """Serve ``outcomes`` in order (a dict body or an exception); keep every request."""
    served: list = []
    requests: list = []

    def fake_urlopen(request, timeout=60):
        requests.append(request)
        outcome = outcomes[len(served)]
        served.append(outcome)
        if isinstance(outcome, Exception):
            raise outcome
        return _Response(json.dumps(outcome).encode("utf-8"))

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    monkeypatch.setattr("time.sleep", lambda _seconds: None)
    return requests


def _http_error(code: int, body: dict | None = None) -> urllib.error.HTTPError:
    payload = json.dumps(body or {}).encode("utf-8")
    return urllib.error.HTTPError(
        "http://127.0.0.1:11434/api/chat", code, "err", {}, io.BytesIO(payload),
    )


def _body(
    content: str = '{"next_agent": "endpoint"}', *, done_reason: str = "stop",
    prompt_eval_count: int | None = 900, eval_count: int | None = 40, **extra,
) -> dict:
    body = {
        "model": "qwen3.5:4b",
        "message": {"role": "assistant", "content": content},
        "done": True,
        "done_reason": done_reason,
        **extra,
    }
    if prompt_eval_count is not None:
        body["prompt_eval_count"] = prompt_eval_count
    if eval_count is not None:
        body["eval_count"] = eval_count
    return body


def _sent(request) -> dict:
    return json.loads(request.data.decode("utf-8"))


# --------------------------------------------------------------------------------------
# The request
# --------------------------------------------------------------------------------------


def test_the_client_is_an_llm_client_and_is_available_without_a_key() -> None:
    client = OllamaLLM("qwen3.5:4b")
    assert isinstance(client, LLMClient)
    assert client.available is True
    assert client.name == "ollama"


def test_the_body_carries_every_setting_the_freeze_records(monkeypatch) -> None:
    requests = _transport(monkeypatch, [_body()])
    client = OllamaLLM(
        "qwen3.5:4b", sampling=Sampling(temperature=0.7, seed=11), num_ctx=8192,
        num_predict_cap=1024, think=False, format="json", keep_alive=-1,
    )
    client.complete("SYS", "USER", max_tokens=8192)

    assert requests[0].full_url == "http://127.0.0.1:11434" + CHAT_PATH
    body = _sent(requests[0])
    assert body["model"] == "qwen3.5:4b"
    assert body["messages"] == [
        {"role": "system", "content": "SYS"}, {"role": "user", "content": "USER"},
    ]
    assert body["stream"] is False
    assert body["format"] == "json"
    assert body["think"] is False
    assert body["keep_alive"] == -1
    assert body["options"] == {
        "temperature": 0.7, "num_ctx": 8192, "num_predict": 1024, "seed": 11,
    }
    assert "authorization" not in {k.lower() for k in requests[0].headers}
    assert "x-api-key" not in {k.lower() for k in requests[0].headers}


def test_num_predict_is_the_smaller_of_max_tokens_and_the_cap(monkeypatch) -> None:
    """The orchestrator asks for 8192; a 10240 window cannot give it that and a prompt."""
    requests = _transport(monkeypatch, [_body(), _body()])
    client = OllamaLLM("qwen3.5:4b")
    client.complete("s", "p", max_tokens=8192)
    client.complete("s", "p", max_tokens=256)
    assert _sent(requests[0])["options"]["num_predict"] == DEFAULT_NUM_PREDICT_CAP
    assert _sent(requests[1])["options"]["num_predict"] == 256


def test_a_seedless_sampling_omits_the_seed_and_a_none_think_omits_think(monkeypatch) -> None:
    requests = _transport(monkeypatch, [_body()])
    OllamaLLM(
        "qwen3.5:4b", sampling=Sampling(temperature=0.7, seed=None), think=None, format=None,
    ).complete("s", "p")
    body = _sent(requests[0])
    assert "seed" not in body["options"]
    assert "think" not in body
    assert "format" not in body


def test_the_base_url_is_configurable_and_trailing_slashes_do_not_double(monkeypatch) -> None:
    requests = _transport(monkeypatch, [_body()])
    OllamaLLM("qwen3.5:4b", base_url="http://gpu-box:11434/").complete("s", "p")
    assert requests[0].full_url == "http://gpu-box:11434/api/chat"


def test_configuration_records_what_is_sent_and_no_credential() -> None:
    config = OllamaLLM("qwen3.5:4b").configuration()
    assert config["provider"] == "ollama"
    assert config["model"] == "qwen3.5:4b"
    assert config["sampling"] == D1_SAMPLING.to_dict() == {"temperature": 0.0, "seed": 0}
    assert config["num_ctx"] == DEFAULT_NUM_CTX
    assert config["num_predict_cap"] == DEFAULT_NUM_PREDICT_CAP
    assert config["think"] is False
    assert config["format"] == "json"
    assert "api_key" not in json.dumps(config).lower()


def test_a_schema_format_is_recorded_as_schema_not_dumped_into_the_freeze() -> None:
    config = OllamaLLM("qwen3.5:4b", format={"type": "object"}).configuration()
    assert config["format"] == "schema"


# --------------------------------------------------------------------------------------
# Usage and telemetry
# --------------------------------------------------------------------------------------


def test_usage_is_the_daemons_counts_and_durations_become_seconds(monkeypatch) -> None:
    _transport(monkeypatch, [_body(
        prompt_eval_count=1200, eval_count=60,
        load_duration=2_000_000_000, prompt_eval_duration=30_000_000_000,
        eval_duration=6_000_000_000, total_duration=38_000_000_000,
    )])
    client = OllamaLLM("qwen3.5:4b")
    reply = client.complete("s", "p")

    assert reply.ok and reply.parsed == {"next_agent": "endpoint"}
    assert (reply.input_tokens, reply.output_tokens) == (1200, 60)
    assert client.tokens_used == 1260
    entry = client.token_log[-1]
    assert entry["load_seconds"] == 2.0
    assert entry["prompt_eval_seconds"] == 30.0
    assert entry["eval_seconds"] == 6.0
    assert entry["total_seconds"] == 38.0
    assert entry["prompt_tokens_per_second"] == 40.0
    assert entry["eval_tokens_per_second"] == 10.0
    assert entry["stop_reason"] == "stop"
    assert entry["sent"] is True


def test_missing_counts_are_none_never_zero(monkeypatch) -> None:
    _transport(monkeypatch, [_body(prompt_eval_count=None, eval_count=None)])
    client = OllamaLLM("qwen3.5:4b")
    reply = client.complete("s", "p")
    assert reply.ok
    assert reply.input_tokens is None and reply.output_tokens is None
    assert reply.total_tokens is None
    assert client.tokens_used is None


def test_a_rate_is_never_invented_from_a_zero_or_missing_duration(monkeypatch) -> None:
    _transport(monkeypatch, [_body(eval_count=50, eval_duration=0)])
    client = OllamaLLM("qwen3.5:4b")
    client.complete("s", "p")
    entry = client.token_log[-1]
    assert entry["eval_tokens_per_second"] is None
    assert entry["prompt_tokens_per_second"] is None  # no prompt_eval_duration reported


def test_the_estimate_is_recorded_beside_the_measured_prompt_tokens(monkeypatch) -> None:
    """So the estimator is calibrated from rows, not argued about."""
    _transport(monkeypatch, [_body(prompt_eval_count=333)])
    client = OllamaLLM("qwen3.5:4b")
    system, prompt = "a" * 300, "b" * 600
    client.complete(system, prompt)
    entry = client.token_log[-1]
    assert entry["estimated_prompt_tokens"] == estimate_tokens(system) + estimate_tokens(prompt)
    assert entry["estimated_prompt_tokens"] == 300
    assert entry["input_tokens"] == 333


def test_estimate_tokens_is_conservative_and_rounds_up() -> None:
    assert estimate_tokens("") == 0
    assert estimate_tokens("x") == 1
    assert estimate_tokens("x" * 3000) == 3000 / CHARS_PER_TOKEN


# --------------------------------------------------------------------------------------
# Replies that are not answers
# --------------------------------------------------------------------------------------


def test_a_reply_ended_by_the_generation_cap_is_an_error_naming_the_cap(monkeypatch) -> None:
    _transport(monkeypatch, [_body('{"claims": [', done_reason="length")])
    reply = OllamaLLM("qwen3.5:4b", num_predict_cap=512).complete("s", "p", max_tokens=8192)
    assert not reply.ok
    assert reply.truncated is True
    assert "num_predict=512" in reply.error
    assert reply.parsed is None
    assert reply.input_tokens == 900, "an unusable reply still cost what it cost"


def test_a_reply_with_no_text_is_an_error(monkeypatch) -> None:
    _transport(monkeypatch, [_body("")])
    reply = OllamaLLM("qwen3.5:4b").complete("s", "p")
    assert reply.error == NO_TEXT_BLOCK


def test_a_prose_reply_is_not_an_error_it_is_counted_by_the_caller(monkeypatch) -> None:
    """The pre-registered semantics: unparseable is counted, never retried."""
    _transport(monkeypatch, [_body("I think the endpoint specialist should go next.")])
    reply = OllamaLLM("qwen3.5:4b").complete("s", "p")
    assert reply.ok
    assert reply.parsed is None
    assert reply.text.startswith("I think")


def test_a_fenced_json_reply_still_parses(monkeypatch) -> None:
    _transport(monkeypatch, [_body('```json\n{"next_agent": "identity"}\n```')])
    reply = OllamaLLM("qwen3.5:4b").complete("s", "p")
    assert reply.parsed == {"next_agent": "identity"}


# --------------------------------------------------------------------------------------
# Refusals and failures
# --------------------------------------------------------------------------------------


def test_a_prompt_that_would_not_fit_is_refused_before_anything_is_sent(monkeypatch) -> None:
    requests = _transport(monkeypatch, [_body()])
    client = OllamaLLM("qwen3.5:4b", num_ctx=1000, num_predict_cap=200)
    measurements: list = []
    client.request_observer = measurements.append
    prompt = "x" * 3000  # ~1000 tokens estimated; 1000 + 200 > 1000

    reply = client.complete("s", prompt, max_tokens=200)

    assert requests == [], "Ollama would have dropped the start of the prompt silently"
    assert not reply.ok
    assert "exceeds num_ctx=1000" in reply.error
    assert "num_predict=200" in reply.error
    entry = client.token_log[-1]
    assert entry["sent"] is False
    assert entry["input_tokens"] is None
    assert len(measurements) == 1 == len(client.token_log), (
        "observer and token log must pair by position even on a refused call"
    )


def test_a_prompt_that_just_fits_is_sent(monkeypatch) -> None:
    requests = _transport(monkeypatch, [_body()])
    client = OllamaLLM("qwen3.5:4b", num_ctx=1000, num_predict_cap=200)
    client.complete("", "x" * 2400, max_tokens=200)  # 800 + 200 == 1000
    assert len(requests) == 1


def test_a_missing_model_fails_at_once_and_says_how_to_fix_it(monkeypatch) -> None:
    requests = _transport(monkeypatch, [
        _http_error(404, {"error": "model 'qwen3.5:9b' not found"}), _body(),
    ])
    reply = OllamaLLM("qwen3.5:9b").complete("s", "p")
    assert not reply.ok
    assert len(requests) == 1, "a 404 reproduces identically; retrying buries it"
    assert "ollama pull qwen3.5:9b" in reply.error
    assert "model 'qwen3.5:9b' not found" in reply.error
    assert reply.error.startswith("HTTP 404")


def test_a_bad_request_fails_at_once_with_the_daemons_message(monkeypatch) -> None:
    requests = _transport(monkeypatch, [
        _http_error(400, {"error": "model does not support thinking"}),
    ])
    reply = OllamaLLM("qwen3.5:4b", think=True).complete("s", "p")
    assert len(requests) == 1
    assert "does not support thinking" in reply.error


def test_a_transient_failure_is_retried_and_then_answered(monkeypatch) -> None:
    requests = _transport(monkeypatch, [_http_error(503, {"error": "loading"}), _body()])
    client = OllamaLLM("qwen3.5:4b", max_attempts=3)
    reply = client.complete("s", "p")
    assert reply.ok
    assert len(requests) == 2
    assert client.token_log[-1]["attempts"] == 2


def test_a_stopped_daemon_is_a_transport_error_naming_the_url(monkeypatch) -> None:
    requests = _transport(monkeypatch, [
        urllib.error.URLError(ConnectionRefusedError(111, "refused")),
        urllib.error.URLError(ConnectionRefusedError(111, "refused")),
    ])
    client = OllamaLLM("qwen3.5:4b", base_url="http://127.0.0.1:11434", max_attempts=2)
    reply = client.complete("s", "p")
    assert not reply.ok
    assert len(requests) == 2
    assert "URLError" in reply.error
    assert "http://127.0.0.1:11434" in reply.error
    assert client.token_log[-1]["attempts"] == 2
    assert client.token_log[-1]["input_tokens"] is None


def test_every_complete_writes_exactly_one_token_log_entry(monkeypatch) -> None:
    """The row's request records pair measurements to log entries by position."""
    _transport(monkeypatch, [
        _body(), _http_error(404), urllib.error.URLError("down"), _body(""),
    ])
    client = OllamaLLM("qwen3.5:4b", max_attempts=1)
    measurements: list = []
    client.request_observer = measurements.append
    for _ in range(4):
        client.complete("s", "p")
    assert len(client.token_log) == 4 == len(measurements)


# --------------------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------------------


def _tags(*names: str) -> dict:
    return {"models": [
        {"name": n, "digest": f"digest-{n}", "size": 3_000_000_000,
         "modified_at": "2026-09-14T20:37:31Z",
         "details": {"family": "qwen35", "parameter_size": "4.7B",
                     "quantization_level": "Q4_K_M", "format": "gguf"}}
        for n in names
    ]}


def test_describe_records_daemon_version_digest_and_quantisation(monkeypatch) -> None:
    _transport(monkeypatch, [
        {"version": "0.33.3"}, _tags("qwen3.5:4b"),
        {"capabilities": ["completion", "tools", "thinking"],
         "model_info": {"qwen35.context_length": 262144}},
    ])
    described = OllamaLLM("qwen3.5:4b").describe()
    assert described["daemon_version"] == "0.33.3"
    assert described["digest"] == "digest-qwen3.5:4b"
    assert described["quantization_level"] == "Q4_K_M"
    assert described["parameter_size"] == "4.7B"
    assert described["capabilities"] == ["completion", "tools", "thinking"]
    assert described["model_context_length"] == 262144
    assert described["configuration"]["num_ctx"] == DEFAULT_NUM_CTX


def test_describe_refuses_when_the_model_is_not_pulled(monkeypatch) -> None:
    _transport(monkeypatch, [{"version": "0.33.3"}, _tags("qwen3.5:4b")])
    with pytest.raises(OllamaUnavailable, match="ollama pull qwen3.5:9b"):
        OllamaLLM("qwen3.5:9b").describe()


def test_describe_refuses_when_the_daemon_is_down(monkeypatch) -> None:
    _transport(monkeypatch, [urllib.error.URLError("refused")])
    with pytest.raises(OllamaUnavailable, match="ollama serve"):
        OllamaLLM("qwen3.5:4b").describe()


def test_construction_refuses_nonsense() -> None:
    with pytest.raises(ValueError):
        OllamaLLM("")
    with pytest.raises(ValueError):
        OllamaLLM("qwen3.5:4b", num_ctx=0)


def test_loaded_reads_the_daemons_resident_models_and_never_raises(monkeypatch) -> None:
    body = {"models": [
        {"name": "qwen3.5:4b", "size": 3_424_754_072, "size_vram": 0, "digest": "abc"},
        {"name": "other", "size": 10, "size_vram": 10, "digest": "def"},
    ]}
    _transport(monkeypatch, [body, body])
    client = OllamaLLM("qwen3.5:4b")
    assert client.loaded()["qwen3.5:4b"] == {"size": 3_424_754_072, "size_vram": 0, "digest": "abc"}
    assert client.resident_bytes() == 3_424_754_072


def test_resident_bytes_credits_every_loaded_byte_and_is_zero_when_unknown(monkeypatch) -> None:
    """A loaded model needs no floor a second time, wherever its bytes live. The first
    version credited only the non-VRAM part and refused a GPU run whose weights were
    entirely in VRAM (Colab, 2026-09-20)."""
    _transport(monkeypatch, [
        {"models": [{"name": "qwen3.5:4b", "size": 1000, "size_vram": 600}]},
        {"models": [{"name": "qwen3.5:4b", "size": 1000, "size_vram": 1000}]},
        {"models": [{"name": "qwen3.5:4b", "size": 1000, "size_vram": 0}]},
        urllib.error.URLError("down"),
        {"models": []},
        {"models": [{"name": "qwen3.5:4b", "size": 1000, "size_vram": 1000}]},
        {"models": []},
    ])
    client = OllamaLLM("qwen3.5:4b")
    assert client.resident_bytes() == 1000, "partly offloaded: every loaded byte is spent"
    assert client.resident_bytes() == 1000, "fully in VRAM: the same credit"
    assert client.resident_bytes() == 1000, "fully in system memory: the same credit"
    assert client.resident_bytes() == 0, "an unreadable /api/ps is the conservative answer"
    assert client.resident_bytes() == 0
    assert client.residency() == {"size": 1000, "size_vram": 1000}
    assert client.residency() == {"size": None, "size_vram": None}
