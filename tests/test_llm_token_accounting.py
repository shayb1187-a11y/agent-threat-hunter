"""Cost is read from the provider, summed per call, and reset per case.

Why this is tested with fakes rather than left to the first real run
--------------------------------------------------------------------
The cost column is the one number in the ablation that nobody can sanity-check by
reading the output: a wrong fact is visible, a wrong token count is not. It also cannot
be exercised here -- no key exists in this environment -- so the whole path from an HTTP
body's ``usage`` object to ``CaseResult.tokens`` is asserted against fake bodies. If the
API shape is read wrongly, these fail now rather than on the day a key appears and one
number quietly means something else.

How each fails
---------------
*Reading usage.* A body with usage must produce the two counts; a body without must
produce ``None`` and must not fail the call. Fails if ``usage`` is assumed present, or
if a missing one becomes ``0`` -- which would report the most expensive arm as free.

*Retries.* A retried call spent what every attempt spent. Fails if only the successful
attempt is counted.

*Per case.* ``CaseResult.tokens`` is per case. Fails if the client's running total
leaks across cases, which would charge the last case of a 22-case manifest for the whole
manifest.
"""

from __future__ import annotations

import io
import json
import urllib.error

import pytest

from _builders import at, ctrl, logon, telemetry as build_telemetry
from ath.agent.llm import AnthropicLLM, LLMResponse, NullLLM, ScriptedLLM
from ath.evaluation.ablation import (
    arm_a,
    arm_c,
    begin_token_accounting,
    build_manifest,
    run_arm,
    tokens_spent,
)


# --------------------------------------------------------------------------------------
# A fake transport: the Messages API shape, and nothing else
# --------------------------------------------------------------------------------------


def _body(text: str = "{}", usage: dict | None = None) -> dict:
    payload = {"content": [{"type": "text", "text": text}]}
    if usage is not None:
        payload["usage"] = usage
    return payload


class _Response(io.BytesIO):
    """Enough of urlopen's context-manager result for the client under test."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _transport(monkeypatch, outcomes):
    """Serve ``outcomes`` in order: a dict body, or an exception to raise."""
    served = []

    def fake_urlopen(request, timeout=60):
        outcome = outcomes[len(served)]
        served.append(outcome)
        if isinstance(outcome, Exception):
            raise outcome
        return _Response(json.dumps(outcome).encode("utf-8"))

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    monkeypatch.setattr("time.sleep", lambda _seconds: None)
    return served


def _http_error(code: int, body: dict | None = None) -> urllib.error.HTTPError:
    payload = json.dumps(body or {}).encode("utf-8")
    return urllib.error.HTTPError(
        "https://api.anthropic.com/v1/messages", code, "err", {},
        io.BytesIO(payload),
    )


# --------------------------------------------------------------------------------------
# Reading usage off a response
# --------------------------------------------------------------------------------------


def test_usage_is_read_from_the_response_body(monkeypatch) -> None:
    _transport(monkeypatch, [_body(usage={"input_tokens": 1200, "output_tokens": 340})])
    client = AnthropicLLM("test-key")

    response = client.complete("system", "prompt")

    assert (response.input_tokens, response.output_tokens) == (1200, 340)
    assert response.total_tokens == 1540
    assert client.tokens_used == 1540


def test_two_calls_sum_into_the_running_total(monkeypatch) -> None:
    _transport(monkeypatch, [
        _body(usage={"input_tokens": 100, "output_tokens": 20}),
        _body(usage={"input_tokens": 300, "output_tokens": 40}),
    ])
    client = AnthropicLLM("test-key")

    client.complete("system", "one")
    client.complete("system", "two")

    assert client.tokens_used == 460
    assert [entry["input_tokens"] for entry in client.token_log] == [100, 300]


def test_a_body_without_usage_reports_none_and_still_returns_the_text(
    monkeypatch
) -> None:
    """Fails if a missing ``usage`` becomes 0, or breaks the call."""
    _transport(monkeypatch, [_body(text='{"next_agent": "endpoint"}')])
    client = AnthropicLLM("test-key")

    response = client.complete("system", "prompt")

    assert response.ok
    assert response.parsed == {"next_agent": "endpoint"}
    assert (response.input_tokens, response.output_tokens) == (None, None)
    assert response.total_tokens is None
    assert client.tokens_used is None, "nothing reported must not become zero"


def test_a_malformed_usage_object_is_ignored_rather_than_trusted(monkeypatch) -> None:
    _transport(monkeypatch, [_body(usage={"input_tokens": "lots", "output_tokens": None})])
    client = AnthropicLLM("test-key")

    response = client.complete("system", "prompt")

    assert (response.input_tokens, response.output_tokens) == (None, None)
    assert client.tokens_used is None


# --------------------------------------------------------------------------------------
# Retries
# --------------------------------------------------------------------------------------


def test_a_retried_call_sums_every_attempt_that_reported_usage(monkeypatch) -> None:
    """One retry: the 429 spent 90 tokens before failing, the retry spent 130.

    Fails if only the successful attempt is counted -- which under-reports precisely the
    calls that cost the most.
    """
    _transport(monkeypatch, [
        _http_error(429, {"usage": {"input_tokens": 90, "output_tokens": 0}}),
        _body(usage={"input_tokens": 100, "output_tokens": 30}),
    ])
    client = AnthropicLLM("test-key", backoff_seconds=0)

    response = client.complete("system", "prompt")

    assert response.ok
    assert (response.input_tokens, response.output_tokens) == (190, 30)
    assert client.tokens_used == 220
    assert client.token_log[-1]["attempts"] == 2


def test_a_retryable_error_without_usage_costs_nothing_extra(monkeypatch) -> None:
    _transport(monkeypatch, [
        _http_error(503),
        _body(usage={"input_tokens": 10, "output_tokens": 5}),
    ])
    client = AnthropicLLM("test-key", backoff_seconds=0)

    response = client.complete("system", "prompt")

    assert (response.input_tokens, response.output_tokens) == (10, 5)


def test_a_permanent_failure_reports_what_it_spent_and_no_more(monkeypatch) -> None:
    """A 401 is a configuration error, not a cost -- and it still must not raise."""
    _transport(monkeypatch, [_http_error(401)])
    client = AnthropicLLM("bad-key", backoff_seconds=0)

    response = client.complete("system", "prompt")

    assert response.ok is False
    assert response.total_tokens is None
    assert client.tokens_used is None


# --------------------------------------------------------------------------------------
# ScriptedLLM's fake usage, and per-case accounting
# --------------------------------------------------------------------------------------


def test_the_scripted_double_reports_deterministic_fake_usage() -> None:
    client = ScriptedLLM(responses=["{}", "{}"])

    first = client.complete("system", "one")
    client.complete("system", "two")

    assert (first.input_tokens, first.output_tokens) == (100, 50)
    assert client.tokens_used == 300


def test_an_exhausted_scripted_call_reports_no_usage() -> None:
    """A failed call is not a cheap call; it is a call that reported nothing."""
    client = ScriptedLLM(responses=[])

    response = client.complete("system", "one")

    assert response.ok is False
    assert response.total_tokens is None
    assert client.tokens_used is None


def test_accounting_resets_between_cases() -> None:
    client = ScriptedLLM(responses=["{}"] * 4)
    client.complete("s", "case one")

    baseline = begin_token_accounting(client)
    client.complete("s", "case two")

    assert tokens_spent(client, baseline) == 150


def test_a_client_that_cannot_reset_is_snapshotted_instead() -> None:
    """A double exposing only a running total still yields a per-case figure."""

    class _Cumulative:
        name = "cumulative"
        available = True
        tokens_used = 500

        def complete(self, system, prompt, max_tokens=1024):
            self.tokens_used += 25
            return LLMResponse(text="{}", model=self.name)

    client = _Cumulative()
    baseline = begin_token_accounting(client)
    client.complete("s", "p")

    assert baseline == 500
    assert tokens_spent(client, baseline) == 25


def test_a_client_that_reports_nothing_yields_null_not_zero() -> None:
    baseline = begin_token_accounting(NullLLM())
    assert tokens_spent(NullLLM(), baseline) is None


# --------------------------------------------------------------------------------------
# End to end: the number reaches the row, per case
# --------------------------------------------------------------------------------------


def _two_case_corpus():
    """Two unrelated Kubernetes-shaped escalations, so the manifest has two rows."""
    from ath.correlation import correlate
    from ath.environment import build_environment_model
    from ath.hunting import run_hunt

    rows = []
    for index, actor in enumerate(("alice", "bob")):
        rows += [
            ctrl(actor, "create", "clusterrolebindings", f"binding-{actor}",
                 target_actor=f"svc-{actor}", role_ref="cluster-admin",
                 device=f"k8s:cluster-{index}", when=at(index * 600)),
            ctrl(f"svc-{actor}", "exec", "pods/exec", f"pod-{actor}",
                 namespace="prod", device=f"k8s:cluster-{index}",
                 when=at(index * 600 + 3)),
        ]
    telemetry = build_telemetry(ctrls=rows, logons=[logon("alice", "k8s:cluster-0")])
    hunt = run_hunt(telemetry)
    environment = build_environment_model(telemetry)
    cases = correlate(hunt.findings, telemetry)
    return telemetry, list(hunt.findings), list(cases), environment


def test_tokens_reach_the_row_and_do_not_accumulate_across_cases() -> None:
    """Fails if case two is charged for case one -- the cumulative defect, in the cost
    column instead of the tool-call column."""
    telemetry, findings, cases, environment = _two_case_corpus()
    if len(cases) < 2:
        pytest.skip("this fixture no longer produces two cases")
    manifest = build_manifest("fixture", telemetry, cases, selection="every case")
    client = ScriptedLLM(responses=['{"claims": []}'] * 40, name="scripted-model")

    results = run_arm(
        arm_c(), manifest, telemetry, cases, findings=findings,
        environment=environment, llm=client,
    )

    assert len(results) == 2
    assert all(r.tokens is not None for r in results)
    assert all(r.tokens % 150 == 0 for r in results), "150 fake tokens per answered call"
    assert sum(r.tokens for r in results) == (client.tokens_used or 0) + results[0].tokens
    assert results[1].tokens < sum(r.tokens for r in results)


def test_arm_a_still_reports_no_tokens() -> None:
    """The deterministic arm has no cost column, and must not grow a zero."""
    telemetry, findings, cases, environment = _two_case_corpus()
    manifest = build_manifest("fixture", telemetry, cases, selection="every case")

    results = run_arm(
        arm_a(), manifest, telemetry, cases, findings=findings,
        environment=environment,
    )

    assert all(r.tokens is None for r in results)
