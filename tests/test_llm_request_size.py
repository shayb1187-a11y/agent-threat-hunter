"""The size of the request the orchestrator builds, and the one bound that fixes it.

M19 arm B degraded on ``comiset/CASE-001`` and ``comiset/CASE-002`` with
``HTTP 413``. M19b-T2 measured why: the synthesis request was **36,827,172 bytes**, of
which 36,547,510 -- 99.24% -- were the evidence ids of a single claim, which are the
verbatim output of a single ``host_network_activity`` call over a corpus with 589,476
network rows. The API's limit, found by binary search against the frozen endpoint, is
**33,554,432 bytes exactly** (``reports/m19b/http413/probe_boundary.json``: 33,554,432
answers 400, 33,554,433 answers 413).

These tests rebuild that request offline, from the claim shapes the committed M19 row
records, and hold three things:

* the request really does exceed the measured limit -- the regression, reproducible
  with no key and no network;
* with :attr:`~ath.agent.orchestrator.InvestigationConfig.tool_output_budget` unset,
  every prompt is **byte-identical** to what M19 sent, because a mitigation that changes
  the frozen behaviour when it is switched off is not switched off;
* with it set, the same request falls under the limit while every evidence id that arm
  C cited on those cases, and that arm B's prompt contained, is still in the prompt.

One test needs the network. It is skipped unless ``ATH_LLM_API_KEY`` **and**
``ATH_NETWORK_TESTS=1`` are both set, so the default suite never sends anything.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from ath.agent.claims import Claim, ClaimType
from ath.agent.llm import build_request_body, encode_request_body
from ath.agent.orchestrator import (
    SYNTHESIS_MAX_TOKENS,
    SYNTHESIS_SYSTEM,
    SYNTHESIS_USER_TEMPLATE,
    InvestigationConfig,
    render_synthesis_claims,
)
from ath.evaluation.ablation.arms import ABLATION_MODEL

ROOT = Path(__file__).resolve().parent.parent
M19_ARM_B = ROOT / "reports" / "m19" / "ablation" / "arm_B.json"
M19_ARM_C = ROOT / "reports" / "m19" / "ablation" / "arm_C.json"
PROBE_BOUNDARY = ROOT / "reports" / "m19b" / "http413" / "probe_boundary.json"

MEASURED_REQUEST_LIMIT_BYTES = 33_554_432
"""The provider's request-size limit, measured, not looked up.

32 MiB to the byte: with the frozen endpoint, headers, model and ``max_tokens=1``, a
33,554,432-byte body is answered (400 -- the prompt exceeds the context window, which is
a rejection that happened *after* the body was accepted) and a 33,554,433-byte body is
answered 413. The same flip happens at the same byte count with a multi-byte filler
carrying six times fewer characters, so the limit counts bytes of the HTTP body rather
than characters or tokens. Probe log: ``reports/m19b/http413/probe_log.json`` and
``probe_boundary.json``.
"""

MEASURED_CASE_001_REQUEST_BYTES = 36_827_172
"""What arm B's synthesis call on ``comiset/CASE-001`` weighed, reconstructed offline.

``reports/m19b/http413/measurements.json``, whose reconstruction is checked claim by
claim against the committed M19 row before any byte of it is reported.
"""

TOOL_OUTPUT_BUDGET = 4096
"""The budget these tests exercise, and the one the mitigated run used.

Large enough for 66 of these 60-byte ids per claim -- more identifiers than an analyst
reads out of a list -- and small enough that eight such claims cannot approach the
limit. It is a test constant and a run parameter, never a default.
"""


# --------------------------------------------------------------------------------------
# Rebuilding the oversized request from what M19 committed
# --------------------------------------------------------------------------------------


def _row(path: Path, corpus: str, case_id: str) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    for row in payload["cases"]:
        if row["corpus"] == corpus and row["case_id"] == case_id:
            return row
    raise AssertionError(f"{corpus}/{case_id} is not in {path}")


def _claims_of(row: dict[str, Any]) -> list[Claim]:
    """The row's specialist claims, with their id lists restored to full length.

    The committed file caps each id list at
    :data:`~ath.evaluation.ablation.arms.MAX_SERIALISED_IDS` and records how many it
    dropped beside it, so the row says *how many* ids the claim carried but not what
    they all were. The ids past the cap are therefore regenerated at exactly the length
    of the ones that were kept -- which is what makes the reconstruction faithful in the
    only dimension these tests measure, bytes. They are not evidence and nothing here
    verifies them; the real ones are in the telemetry, and
    ``scripts/m19b_http413.py measure`` re-derives them from it.
    """
    claims: list[Claim] = []
    for raw in row["state"]["claims"]:
        if raw.get("agent") == "synthesis":
            continue
        kept = list(raw["evidence_ids"])
        omitted = int(raw.get("evidence_ids_omitted") or 0)
        width = len(kept[0]) if kept else 60
        padding = [f"{i:0{width}d}"[-width:] for i in range(omitted)]
        claims.append(Claim(
            claim_type=ClaimType(raw["type"]),
            statement=raw["statement"],
            evidence_ids=tuple(kept + padding),
            source=raw.get("source", "tool"),
            agent=raw.get("agent", "unknown"),
        ))
    return claims


def _request_bytes(case_id: str, claims: list[Claim], budget: int | None) -> int:
    """Exactly what :meth:`InvestigationOrchestrator.synthesise` would put on the wire."""
    body = build_request_body(
        model=ABLATION_MODEL,
        max_tokens=SYNTHESIS_MAX_TOKENS,
        system=SYNTHESIS_SYSTEM,
        prompt=SYNTHESIS_USER_TEMPLATE.format(
            case_id=case_id, claims=render_synthesis_claims(claims, budget=budget),
        ),
    )
    return len(encode_request_body(body))


@pytest.fixture(scope="module")
def comiset_case_001() -> list[Claim]:
    return _claims_of(_row(M19_ARM_B, "comiset", "CASE-001"))


@pytest.fixture(scope="module")
def comiset_case_002() -> list[Claim]:
    return _claims_of(_row(M19_ARM_B, "comiset", "CASE-002"))


# --------------------------------------------------------------------------------------
# The regression
# --------------------------------------------------------------------------------------


def test_the_unbounded_comiset_request_exceeds_the_measured_limit(comiset_case_001):
    """The 413, reproduced offline: the request is larger than the API will accept.

    The exact byte count is asserted, not merely "too large". A regression test that
    only says "still over the limit" would pass just as happily if the request grew a
    hundredfold for a different reason, and the number is the finding.
    """
    size = _request_bytes("CASE-001", comiset_case_001, budget=None)
    assert size == MEASURED_CASE_001_REQUEST_BYTES
    assert size > MEASURED_REQUEST_LIMIT_BYTES
    assert size - MEASURED_REQUEST_LIMIT_BYTES == 3_272_740


def test_the_oversize_is_one_tool_result_and_not_accumulated_context(comiset_case_001):
    """Where the bytes are: one claim, fed by one tool call, not a growing history.

    This is the measurement that chooses between two diagnoses that would get different
    fixes. Trimming a conversation history would save nothing here -- there is no
    conversation: every request this system makes carries one freshly built user
    message.
    """
    per_claim = sorted(
        (len(", ".join(c.evidence_ids).encode("utf-8")), c.agent)
        for c in comiset_case_001
    )
    largest, agent = per_claim[-1]
    total = sum(size for size, _ in per_claim)
    assert agent == "generalist:host"
    assert largest == 36_547_510
    assert largest / total > 0.99
    statements = sum(len(c.statement.encode("utf-8")) for c in comiset_case_001)
    assert statements < 2_000


# --------------------------------------------------------------------------------------
# The flag, off
# --------------------------------------------------------------------------------------


def test_the_budget_is_off_by_default():
    """The frozen M19 behaviour is the default, and an M19b run has to ask for the fix."""
    assert InvestigationConfig().tool_output_budget is None


@pytest.mark.parametrize(
    "path,corpus,case_id",
    [
        (M19_ARM_B, "comiset", "CASE-001"),
        (M19_ARM_B, "comiset", "CASE-002"),
        (M19_ARM_B, "flaws_cloud", "CASE-018"),
        (M19_ARM_C, "comiset", "CASE-001"),
        (M19_ARM_C, "attack_data_aws", "CASE-001"),
    ],
)
def test_with_the_flag_off_the_prompt_is_byte_identical(path, corpus, case_id):
    """Unset, the new renderer emits what the old expression emitted, character for
    character, on every case reconstructed for M19b-T2 and on two more besides."""
    claims = _claims_of(_row(path, corpus, case_id))
    legacy = "\n".join(
        f"- [{c.claim_type.value}] {c.statement} (evidence: {', '.join(c.evidence_ids)})"
        for c in claims
    )
    assert render_synthesis_claims(claims, budget=None) == legacy


# --------------------------------------------------------------------------------------
# The flag, on
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("case_id", ["CASE-001", "CASE-002"])
def test_a_bounded_request_falls_under_the_measured_limit(
    case_id, comiset_case_001, comiset_case_002,
):
    """With the budget set, the request that was rejected is 0.1% of what is allowed."""
    claims = comiset_case_001 if case_id == "CASE-001" else comiset_case_002
    size = _request_bytes(case_id, claims, budget=TOOL_OUTPUT_BUDGET)
    assert size < MEASURED_REQUEST_LIMIT_BYTES
    assert size < MEASURED_REQUEST_LIMIT_BYTES / 100
    assert size < 40_000


def test_every_id_arm_c_cited_and_arm_b_saw_survives_the_bound():
    """The bound may shorten a list; it may not lose evidence another arm found decisive.

    The comparison is against the ids arm C's *verified* claims cite on the same two
    cases, intersected with the ids arm B's unbounded prompt actually contained -- arm
    B never walked the process facet on these cases, so four of arm C's six ids were
    never in arm B's prompt to begin with, and a test that demanded them would be
    asserting that a size bound can add evidence.
    """
    for case_id in ("CASE-001", "CASE-002"):
        claims = _claims_of(_row(M19_ARM_B, "comiset", case_id))
        cited: set[str] = set()
        for raw in _row(M19_ARM_C, "comiset", case_id)["state"]["claims"]:
            cited.update(raw["evidence_ids"])
        unbounded = render_synthesis_claims(claims, budget=None)
        bounded = render_synthesis_claims(claims, budget=TOOL_OUTPUT_BUDGET)
        shared = {e for e in cited if e in unbounded}
        assert shared, f"arm C cited nothing arm B's prompt contained on {case_id}"
        missing = sorted(e for e in shared if e not in bounded)
        assert not missing, f"{case_id}: the bound dropped {missing}"


def test_the_bound_says_how_much_it_left_out(comiset_case_001):
    """A truncated list carries the full count, so the model is not told a smaller story."""
    bounded = render_synthesis_claims(comiset_case_001, budget=TOOL_OUTPUT_BUDGET)
    assert "+589410 more of 589476 not shown" in bounded
    assert "+4392 more of 4458 not shown" in bounded


def test_an_id_two_claims_share_is_never_the_one_dropped():
    """Cross-claim ids come first: they are the only ones a *relationship* can rest on."""
    wide = Claim(
        claim_type=ClaimType.FACT, statement="wide", source="tool", agent="host",
        evidence_ids=tuple(f"evt-{i:06d}" for i in range(10_000)),
    )
    narrow = Claim(
        claim_type=ClaimType.FACT, statement="narrow", source="tool", agent="endpoint",
        evidence_ids=("evt-009999",),
    )
    bounded = render_synthesis_claims([wide, narrow], budget=200)
    assert bounded.count("evt-009999") == 2
    assert "+" in bounded and "more of 10000 not shown" in bounded


def test_a_bounded_claim_never_renders_more_ids_than_the_budget_allows(comiset_case_001):
    """Per claim, not per prompt: the evidence of one claim is bounded by the budget."""
    bounded = render_synthesis_claims(comiset_case_001, budget=TOOL_OUTPUT_BUDGET)
    for line in bounded.splitlines():
        evidence = line.rsplit("(evidence: ", 1)[1].rstrip(")")
        ids = [part for part in evidence.split(", ") if not part.startswith("+")]
        assert len(", ".join(ids).encode("utf-8")) <= TOOL_OUTPUT_BUDGET


def test_a_non_positive_budget_is_refused(comiset_case_001):
    """Zero is not "no bound" and it is not "cite nothing"; it is a configuration error."""
    with pytest.raises(ValueError):
        render_synthesis_claims(comiset_case_001, budget=0)


def test_the_measured_limit_matches_the_committed_probe_log():
    """The constant these tests assert against is the one the probe actually found."""
    if not PROBE_BOUNDARY.exists():  # pragma: no cover -- artifact not checked out
        pytest.skip(f"{PROBE_BOUNDARY} is not present")
    attempts = json.loads(PROBE_BOUNDARY.read_text(encoding="utf-8"))["attempts"]
    accepted = [a for a in attempts if a["status"] != 413]
    rejected = [a for a in attempts if a["status"] == 413]
    assert max(a["request_bytes"] for a in accepted) == MEASURED_REQUEST_LIMIT_BYTES
    assert min(a["request_bytes"] for a in rejected) == MEASURED_REQUEST_LIMIT_BYTES + 1


# --------------------------------------------------------------------------------------
# The one test that sends anything
# --------------------------------------------------------------------------------------


@pytest.mark.skipif(
    not (os.getenv("ATH_LLM_API_KEY") and os.getenv("ATH_NETWORK_TESTS") == "1"),
    reason="needs ATH_LLM_API_KEY and an explicit ATH_NETWORK_TESTS=1 opt-in",
)
def test_the_api_rejects_one_byte_over_the_measured_limit():  # pragma: no cover
    """Re-measures the boundary against the live endpoint. Never in the default suite.

    Both attempts are rejections and neither is billed: under the limit the request is
    refused for exceeding the context window, over it for exceeding the body size.
    """
    import scripts.m19b_http413 as probe  # noqa: PLC0415 -- optional, network only

    key = os.environ["ATH_LLM_API_KEY"]
    under = probe.probe_once(MEASURED_REQUEST_LIMIT_BYTES, key, ABLATION_MODEL)
    over = probe.probe_once(MEASURED_REQUEST_LIMIT_BYTES + 1, key, ABLATION_MODEL)
    assert under["status"] != 413
    assert over["status"] == 413
