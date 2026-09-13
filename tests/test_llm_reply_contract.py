"""What the client sends, and what it refuses to call an answer.

Why these tests exist
----------------------
No API key exists in this environment, so every one of these paths would first execute
on the day the frozen run starts -- with nobody watching, and with the failure shaped
exactly like a success. Thinking tokens count against ``max_tokens``: a cap set too low
ends the response before a single text block is emitted, the body comes back with
``stop_reason == "max_tokens"``, and the text is empty. Empty text parses to ``None``,
``None`` is precisely what a model answering in prose produces, and the orchestrator's
answer to prose is to plan deterministically and carry on. A whole model arm could
therefore have run as the deterministic arm while every row described itself as a model
arm. That is not a weak result; it is a false one, and it is invisible in the output.

How each fails
---------------
*Truncation.* A ``max_tokens`` body must produce ``ok False``, ``truncated True`` and an
error naming the cap. Fails if ``stop_reason`` goes unread -- which is how the client
behaved before M19 Phase 0.5.

*No text block.* A completed reply carrying only thinking blocks must be an error too.
Fails if "parsed to None" is treated as the only way a reply can be useless.

*A good reply.* ``end_turn`` with text must still be ``ok``, with its JSON parsed. Fails
if the new checks are too eager and degrade every run.

*The request body.* Asserted on the captured payload: ``thinking`` is adaptive, and no
sampling parameter is present. Fails if ``temperature``/``top_p``/``top_k`` are ever
added back -- the current models reject them with a 400, so every call in the experiment
would fail -- or if ``thinking`` silently stops being sent, which would leave the run
depending on a provider default that the freeze claims to have pinned.
"""

from __future__ import annotations

import io
import json

import pytest

from ath.agent.llm import (
    ADAPTIVE_THINKING,
    ANTHROPIC_VERSION,
    API_ENDPOINT,
    NO_TEXT_BLOCK,
    AnthropicLLM,
    ScriptedLLM,
    textless_reply,
    truncated_reply,
)


class _Response(io.BytesIO):
    """Enough of urlopen's context-manager result for the client under test."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _transport(monkeypatch, body: dict) -> list:
    """Serve one body, and keep every request object the client built."""
    sent: list = []

    def fake_urlopen(request, timeout=60):
        sent.append(request)
        return _Response(json.dumps(body).encode("utf-8"))

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    return sent


def _text_block(text: str) -> dict:
    return {"type": "text", "text": text}


def _thinking_block() -> dict:
    return {"type": "thinking", "thinking": ""}


# --------------------------------------------------------------------------------------
# What counts as an answer
# --------------------------------------------------------------------------------------


def test_a_reply_cut_off_at_the_cap_is_an_error_that_names_the_cap(monkeypatch) -> None:
    _transport(monkeypatch, {
        "stop_reason": "max_tokens",
        "content": [_thinking_block()],
        "usage": {"input_tokens": 900, "output_tokens": 8192},
    })
    client = AnthropicLLM("test-key")

    response = client.complete("system", "prompt", max_tokens=8192)

    assert response.ok is False
    assert response.truncated is True
    assert response.stop_reason == "max_tokens"
    assert "max_tokens=8192" in (response.error or "")
    assert "no text" in (response.error or "")
    assert response.parsed is None
    # It cost what it cost: a call that spent a whole output budget on thinking and
    # returned nothing is the most expensive kind of failure, not a free one.
    assert client.tokens_used == 9092


def test_a_completed_reply_with_no_text_block_is_an_error(monkeypatch) -> None:
    _transport(monkeypatch, {
        "stop_reason": "end_turn",
        "content": [_thinking_block()],
        "usage": {"input_tokens": 10, "output_tokens": 20},
    })
    client = AnthropicLLM("test-key")

    response = client.complete("system", "prompt")

    assert response.ok is False
    assert response.error == NO_TEXT_BLOCK
    assert response.truncated is False
    assert response.stop_reason == "end_turn"


def test_a_completed_reply_with_text_is_usable(monkeypatch) -> None:
    _transport(monkeypatch, {
        "stop_reason": "end_turn",
        "content": [_thinking_block(), _text_block('{"next_agent": "identity"}')],
        "usage": {"input_tokens": 10, "output_tokens": 20},
    })
    client = AnthropicLLM("test-key")

    response = client.complete("system", "prompt")

    assert response.ok is True
    assert response.truncated is False
    assert response.parsed == {"next_agent": "identity"}
    assert response.stop_reason == "end_turn"


def test_the_call_records_stop_reason_and_whether_text_came_back(monkeypatch) -> None:
    """The token log is the only per-call record; it must carry the diagnosis."""
    _transport(monkeypatch, {
        "stop_reason": "max_tokens", "content": [],
        "usage": {"input_tokens": 1, "output_tokens": 2},
    })
    client = AnthropicLLM("test-key")

    client.complete("system", "prompt", max_tokens=512)

    entry = client.token_log[-1]
    assert entry["stop_reason"] == "max_tokens"
    assert entry["has_text"] is False
    assert entry["output_tokens"] == 2
    assert "max_tokens=512" in entry["error"]


# --------------------------------------------------------------------------------------
# What is sent
# --------------------------------------------------------------------------------------


def _sent_body(request) -> dict:
    return json.loads(request.data.decode("utf-8"))


def test_the_request_sends_adaptive_thinking_and_no_sampling_parameters(
    monkeypatch,
) -> None:
    sent = _transport(monkeypatch, {
        "stop_reason": "end_turn", "content": [_text_block("{}")],
    })
    client = AnthropicLLM("test-key", model="claude-opus-5")

    client.complete("sys", "prompt", max_tokens=8192)

    body = _sent_body(sent[0])
    assert body["thinking"] == ADAPTIVE_THINKING == {"type": "adaptive"}
    assert body["model"] == "claude-opus-5"
    assert body["max_tokens"] == 8192
    assert body["system"] == "sys"
    assert body["messages"] == [{"role": "user", "content": "prompt"}]
    for rejected in ("temperature", "top_p", "top_k"):
        assert rejected not in body, f"{rejected} is rejected with a 400 by this model"
    assert set(body) == {"model", "max_tokens", "system", "messages", "thinking"}
    assert sent[0].full_url == API_ENDPOINT
    assert sent[0].headers["Anthropic-version"] == ANTHROPIC_VERSION


def test_thinking_can_be_turned_off_for_a_provider_that_rejects_it(monkeypatch) -> None:
    sent = _transport(monkeypatch, {
        "stop_reason": "end_turn", "content": [_text_block("{}")],
    })
    client = AnthropicLLM("test-key", adaptive_thinking=False)

    client.complete("sys", "prompt")

    assert "thinking" not in _sent_body(sent[0])


def test_the_api_key_is_never_in_the_request_body(monkeypatch) -> None:
    """It belongs in a header, and nothing that gets logged or dumped may carry it."""
    sent = _transport(monkeypatch, {
        "stop_reason": "end_turn", "content": [_text_block("{}")],
    })
    AnthropicLLM("sk-ant-secret-value").complete("sys", "prompt")

    assert "sk-ant-secret-value" not in sent[0].data.decode("utf-8")


# --------------------------------------------------------------------------------------
# The same two failures, scriptable without a network
# --------------------------------------------------------------------------------------


def test_the_scripted_client_can_stage_a_truncated_reply() -> None:
    client = ScriptedLLM(responses=[truncated_reply(8192)])

    response = client.complete("sys", "prompt")

    assert response.ok is False
    assert response.truncated is True
    assert "max_tokens=8192" in (response.error or "")


def test_the_scripted_client_can_stage_a_textless_reply() -> None:
    client = ScriptedLLM(responses=[textless_reply()])

    response = client.complete("sys", "prompt")

    assert response.ok is False
    assert response.error == NO_TEXT_BLOCK


def test_a_scripted_string_is_still_an_ordinary_answer() -> None:
    client = ScriptedLLM(responses=['{"claims": []}'])

    response = client.complete("sys", "prompt")

    assert response.ok is True
    assert response.parsed == {"claims": []}
    assert response.stop_reason == "end_turn"


@pytest.mark.parametrize("has_text", [True, False])
def test_the_truncation_error_names_the_cap_either_way(has_text: bool) -> None:
    from ath.agent.llm import truncation_error

    message = truncation_error(4096, has_text)
    assert "max_tokens=4096" in message
    assert ("with no text" in message) is (not has_text)
