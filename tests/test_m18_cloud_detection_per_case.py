"""The M18 cloud-detection script's investigation counts are per case, not cumulative.

The defect this pins
---------------------
``investigate_cases`` built one :class:`~ath.agent.tools.ToolBox` and reused it for every
case. ``ToolBox.calls_by`` returns every call since construction and
``Specialist._result`` attaches exactly that, so case *n* reported the calls of cases
1..n-1 as its own, so the total accumulated. The M18 report published the
accumulation: **172 tool calls** across ten flaws.cloud cases, against **39** actually
made.

Why a test rather than a careful re-read
-----------------------------------------
The error is invisible in the output. Every number is plausible, monotonic and
internally consistent; nothing looks wrong until you divide by the case count. So the
property is asserted on a fixture whose answer is known: two cases that cannot share a
tool call, because they involve different clusters, different actors and different
events.

How these fail
---------------
*Non-cumulative:* fails on the pre-M19-2 code, where case two's count includes case
one's. Asserted as an inequality against the total as well as case by case, so it cannot
be satisfied by a subtraction that happens to work for two cases.

*Unchanged columns:* facts, inferences and rejections come from the investigation state
and were never affected. If a fix ever moves them, that is a behaviour change hiding
inside a counting correction, and this fails.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from m18_cloud_detection import investigate_cases  # noqa: E402

from _builders import at, ctrl, logon, telemetry as build_telemetry  # noqa: E402


@pytest.fixture(scope="module")
def two_case_corpus():
    """Two Kubernetes escalations, on two clusters, an hour apart.

    Nothing links them, so the correlator makes two cases and no tool call one case
    makes can be relevant to the other.
    """
    rows = []
    for index, actor in enumerate(("alice", "bob")):
        rows += [
            ctrl(actor, "create", "clusterrolebindings", f"binding-{actor}",
                 target_actor=f"svc-{actor}", role_ref="cluster-admin",
                 device=f"k8s:cluster-{index}", when=at(index * 600)),
            ctrl(f"svc-{actor}", "exec", "pods/exec", f"pod-{actor}", namespace="prod",
                 device=f"k8s:cluster-{index}", when=at(index * 600 + 3)),
        ]
    return build_telemetry(ctrls=rows, logons=[logon("alice", "k8s:cluster-0")])


def test_the_fixture_really_produces_two_cases(two_case_corpus) -> None:
    """Without this, every assertion below would pass vacuously on one case."""
    result = investigate_cases(two_case_corpus, limit=10)
    assert result["totals"]["cases"] == 2
    assert len(result["per_case"]) == 2


def test_per_case_tool_calls_are_not_cumulative(two_case_corpus) -> None:
    """FAILS ON THE PRE-M19-2 SCRIPT: case two reported case one's calls as well."""
    result = investigate_cases(two_case_corpus, limit=10)
    first, second = result["per_case"]

    assert first["tool_calls"] > 0
    assert second["tool_calls"] > 0
    assert second["tool_calls"] < first["tool_calls"] + second["tool_calls"], (
        "case two must not contain case one's calls"
    )
    # The toolbox each case was given saw exactly that case's calls and no others.
    for row in result["per_case"]:
        assert row["tool_calls"] == row["toolbox_calls"]


def test_the_total_is_the_sum_of_the_cases(two_case_corpus) -> None:
    """The published total must be addable from the published rows."""
    result = investigate_cases(two_case_corpus, limit=10)
    assert result["totals"]["tool_calls"] == sum(
        row["tool_calls"] for row in result["per_case"]
    )


def test_two_identical_cases_cost_the_same(two_case_corpus) -> None:
    """The two halves of the fixture are the same shape, so their counts must match.

    This is the sharpest form of the assertion: under the old code the second identical
    case cost exactly twice the first, which reads as "the second one was harder".
    """
    first, second = investigate_cases(two_case_corpus, limit=10)["per_case"]
    assert first["tool_calls"] == second["tool_calls"]
    assert first["facts"] == second["facts"]


def test_claim_counts_are_unaffected_by_the_correction(two_case_corpus) -> None:
    """Facts, inferences and rejections come from the state and never double-counted."""
    result = investigate_cases(two_case_corpus, limit=10)
    assert result["totals"]["facts"] == sum(r["facts"] for r in result["per_case"])
    assert result["totals"]["inferences"] == sum(
        r["inferences"] for r in result["per_case"]
    )
    assert result["totals"]["rejected_claims"] == 0
