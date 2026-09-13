"""M19b T6: the necessity metrics, the fair-comparison instrumentation, two defect fixes.

What each group of tests is for, and how it fails
--------------------------------------------------
*The defects.* Both were found by another task and are fixed here because they apply to
every arm identically -- a fix landing between two arms' runs would be a difference
between the arms. ``NetworkAgent`` indexed a key the beacon tool does not write at
exactly three connections; the test fails if the agent goes back to reading a count that
only implies the key. ``AnthropicLLM`` discarded the HTTP error body, so a 400 for an
exhausted balance was indistinguishable from a malformed request; the test fails if the
body stops being read, if the retry classification moves, or if the request or the
credential ever reaches the recorded error.

*The metrics.* Each is a pure function over a finished investigation plus a
pre-registered rubric, and each test states the answer it expects rather than asserting
that a number exists. The uniqueness test is the one that matters most: UCC is a
*comparative* metric, so a contribution two arms both produced must be unique to
neither, and the comparison must be by cited ids and domain pair rather than by prose --
two arms wording the same link differently have still both produced it.

*The reproduction.* M19b's freeze can no longer hash-match ``scoring.py``, because this
task adds metrics to it. What replaces the hash is this: the M19 metrics, recomputed by
the new code over the committed ``arm_{A,B,C}.json``, must reproduce ``GRADING.json``
exactly. It fails the moment an edit to ``scoring.py`` changes any already-published
number, which is the property the hash was standing in for.

*The equal footing.* An ablation's claim is that the arms differed in one thing. The
row-level assertion fails if a run is ever handed a different tool surface, a different
budget or a different corpus than the one it is being compared against.
"""

from __future__ import annotations

import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest

from _builders import at, ctrl, logon, net, proc, telemetry as build_telemetry
from ath.agent.claims import Claim, ClaimType, ClaimVerifier
from ath.agent.llm import (
    AnthropicLLM,
    ScriptedLLM,
    build_request_body,
    encode_request_body,
)
from ath.agent.orchestrator import InvestigationConfig, InvestigationOrchestrator
from ath.agent.specialists import NetworkAgent
from ath.agent.state import AgentResult, InvestigationState
from ath.agent.tools import ToolBox, ToolCall
from ath.correlation import correlate
from ath.correlation.chain import InvestigationCase
from ath.evaluation.ablation import (
    UnequalFooting,
    arm_a,
    arm_b,
    build_manifest,
    run_arm,
)
from ath.evaluation.ablation import scoring
from ath.hunting import run_hunt
from ath.hunting.finding import Evidence, Finding, Severity

ROOT = Path(__file__).resolve().parent.parent
M19 = ROOT / "reports" / "m19" / "ablation"


# ======================================================================================
# Defect 1: NetworkAgent raised KeyError('robust_cv') at exactly three connections
# ======================================================================================


def _beacon_case(connections: int) -> tuple[ToolBox, InvestigationState]:
    """A case whose single finding names a destination with ``connections`` rows."""
    rows = [
        net("powershell.exe", "45.155.204.10", when=at(minutes=5 * i))
        for i in range(connections)
    ]
    telemetry = build_telemetry(
        procs=[proc("powershell.exe", "powershell.exe -enc AAA", "WINWORD.EXE")],
        nets=rows,
        logons=[logon("jdoe", "PC01")],
    )
    finding = Finding(
        rule_id="ATH-003",
        title="Outbound connection to a flagged destination",
        severity=Severity.HIGH,
        device="PC01",
        user="jdoe",
        evidence=tuple(
            Evidence(event_id=str(r["event_id"]), timestamp=r["timestamp"],
                     summary="connection")
            for r in rows
        ),
        reason="test",
        metadata={"remote_ip": "45.155.204.10"},
    )
    case = InvestigationCase(case_id="CASE-001", findings=(finding,))
    tools = ToolBox(telemetry, [finding], [case])
    return tools, InvestigationState(case=case)


@pytest.mark.parametrize("connections", [1, 2, 3, 4, 5])
def test_the_network_specialist_survives_every_connection_count(connections) -> None:
    """Three connections satisfied the agent's guard and not the tool's.

    ``analyse_beacon`` writes ``robust_cv`` only when ``interarrival_count >= 3`` --
    four connections -- and the agent's irregular-timing branch fired at
    ``samples >= 3``. Fails if the branch goes back to gating on a count rather than on
    the key it reads.
    """
    tools, state = _beacon_case(connections)
    result = NetworkAgent(tools).investigate(state)
    assert isinstance(result, AgentResult)
    assert all("Specialist failed" not in note for note in result.notes)


def test_three_connections_report_too_few_rather_than_a_statistic() -> None:
    """The fix must not invent a figure the tool declined to compute."""
    tools, state = _beacon_case(3)
    notes = NetworkAgent(tools).investigate(state).notes
    assert any("to assess timing" in note for note in notes), notes
    assert not any("robust cv" in note for note in notes), notes


def test_four_connections_still_report_the_statistic_they_always_did() -> None:
    """The fix is narrow: where the tool computed a figure, the note still quotes it."""
    tools, state = _beacon_case(4)
    notes = NetworkAgent(tools).investigate(state).notes
    beacon = tools.analyse_beacon("PC01", "45.155.204.10")
    assert "robust_cv" in beacon
    if not beacon["regular"]:
        assert any("robust cv" in note for note in notes), notes


def test_the_defender_export_fixture_no_longer_loses_its_network_specialist() -> None:
    """The reproduction T4 recorded: the orchestrator caught the KeyError and the
    network specialist contributed nothing while the run reported ``complete``."""
    from ath.telemetry import DefenderExportSource
    from ath.telemetry.loader import Telemetry

    tables = DefenderExportSource(
        directory=ROOT / "tests" / "fixtures" / "defender_export"
    ).load().tables
    telemetry = Telemetry(
        processes=tables["process"], network=tables["network"], logons=tables["logon"],
    )
    hunt = run_hunt(telemetry)
    cases = correlate(hunt.findings, telemetry)
    assert cases, "the fixture must still produce a case for this test to mean anything"

    from ath.environment import build_environment_model

    environment = build_environment_model(telemetry)
    orchestrator = InvestigationOrchestrator(
        ToolBox(telemetry, list(hunt.findings), list(cases)),
        ClaimVerifier(telemetry),
        config=InvestigationConfig(use_llm_planner=False, use_llm_synthesis=False),
        environment=environment,
    )
    state = orchestrator.investigate(cases[0])

    failures = [
        note for result in state.results for note in result.notes
        if "Specialist failed" in note
    ]
    assert failures == []
    assert "network" in state.agents_run


# ======================================================================================
# Defect 2: AnthropicLLM discarded the HTTP error body
# ======================================================================================


CREDIT_BODY = {
    "type": "error",
    "error": {
        "type": "invalid_request_error",
        "message": (
            "Your credit balance is too low to access the Anthropic API. Please go to "
            "Plans & Billing to upgrade or purchase credits."
        ),
    },
}


def _http_error(status: int, body: dict) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://api.anthropic.com/v1/messages", status, "Bad Request", {},
        io.BytesIO(json.dumps(body).encode("utf-8")),
    )


def _raising_urlopen(monkeypatch, status: int, body: dict) -> list[int]:
    """Patch the transport to fail with ``status``; returns the attempt counter."""
    import urllib.request

    attempts: list[int] = []

    def _fake(request, timeout=None):  # noqa: ANN001 -- a stdlib signature
        attempts.append(1)
        raise _http_error(status, body)

    monkeypatch.setattr(urllib.request, "urlopen", _fake)
    return attempts


def test_an_exhausted_balance_says_so_instead_of_saying_http_400(monkeypatch) -> None:
    """A 400 for an exhausted balance was indistinguishable from a malformed request.

    Fails if the error body is discarded again, which is what sent this project to an
    external probe to find out why every model call was failing.
    """
    _raising_urlopen(monkeypatch, 400, CREDIT_BODY)
    response = AnthropicLLM("sk-ant-test-key", model="claude-opus-5").complete(
        "system", "prompt",
    )
    assert response.error is not None
    assert "HTTP 400" in response.error
    assert "invalid_request_error" in response.error
    assert "credit balance is too low" in response.error


def test_the_recorded_error_carries_neither_the_request_nor_the_credential(
    monkeypatch,
) -> None:
    """What is recorded is the API's own two fields, and nothing else."""
    _raising_urlopen(monkeypatch, 400, CREDIT_BODY)
    client = AnthropicLLM("sk-ant-secret-value", model="claude-opus-5")
    response = client.complete("the system prompt", "the user prompt with evidence ids")
    assert "sk-ant-secret-value" not in (response.error or "")
    assert "the user prompt" not in (response.error or "")
    assert "the system prompt" not in (response.error or "")
    assert "x-api-key" not in (response.error or "")
    assert "anthropic-version" not in (response.error or "")


def test_an_error_body_that_is_not_json_still_yields_the_status(monkeypatch) -> None:
    """Reading the body is best effort: an unreadable one must not raise."""
    import urllib.request

    def _fake(request, timeout=None):  # noqa: ANN001
        raise urllib.error.HTTPError(
            "https://api.anthropic.com/v1/messages", 401, "Unauthorized", {},
            io.BytesIO(b"<html>gateway</html>"),
        )

    monkeypatch.setattr(urllib.request, "urlopen", _fake)
    response = AnthropicLLM("sk-ant-test-key").complete("s", "p")
    assert response.error is not None
    assert response.error.startswith("HTTP 401")
    assert "ATH_LLM_API_KEY" in response.error


def test_the_retry_classification_is_unchanged(monkeypatch) -> None:
    """A 400 fails immediately; a 429 is still retried. Recording the body is not a
    licence to retry a configuration error."""
    attempts = _raising_urlopen(monkeypatch, 400, CREDIT_BODY)
    AnthropicLLM("k", max_attempts=3, backoff_seconds=0).complete("s", "p")
    assert len(attempts) == 1

    attempts = _raising_urlopen(monkeypatch, 429, {"error": {"type": "rate_limit_error",
                                                            "message": "slow down"}})
    AnthropicLLM("k", max_attempts=3, backoff_seconds=0).complete("s", "p")
    assert len(attempts) == 3


def test_the_degraded_row_says_what_the_api_said(monkeypatch) -> None:
    """End to end: the API's two fields reach ``llm_errors`` and ``llm_status``."""
    _raising_urlopen(monkeypatch, 400, CREDIT_BODY)
    telemetry = build_telemetry(
        procs=[proc("powershell.exe", "powershell.exe -enc AAA", "WINWORD.EXE")],
    )
    event_id = str(telemetry.processes.iloc[0]["event_id"])
    finding = Finding(
        rule_id="ATH-002", title="Encoded command", severity=Severity.HIGH,
        device="PC01", user="jdoe",
        evidence=(Evidence(event_id=event_id, timestamp=at(), summary="x"),),
        reason="test",
    )
    case = InvestigationCase(case_id="CASE-001", findings=(finding,))
    state = InvestigationState(case=case)
    state.llm_requested = True
    state.claims.append(Claim(
        claim_type=ClaimType.FACT, statement="a fact", evidence_ids=(event_id,),
        source="tool", agent="endpoint",
    ))
    orchestrator = InvestigationOrchestrator(
        ToolBox(telemetry, [finding], [case]),
        ClaimVerifier(telemetry),
        llm=AnthropicLLM("sk-ant-test-key", model="claude-opus-5"),
    )

    orchestrator.synthesise(state)

    assert state.llm_degraded
    assert any("credit balance is too low" in e for e in state.llm_errors)
    assert "credit balance is too low" in state.llm_status


# ======================================================================================
# The cross-domain metrics, on constructed states
# ======================================================================================


@pytest.fixture(scope="module")
def four_domains():
    """One small corpus carrying all four domains, and the ids each domain owns."""
    process = proc("powershell.exe", "powershell.exe -enc AAA", "WINWORD.EXE")
    connection = net("powershell.exe", "45.155.204.10")
    authentication = logon("svc_backup", "FS01", source_device="PC01")
    control = ctrl("svc_backup", "create", "ClusterRoleBinding", "cluster-admin-binding")
    telemetry = build_telemetry(
        procs=[process], nets=[connection], logons=[authentication], ctrls=[control],
    )
    ids = {
        "endpoint": str(process["event_id"]),
        "network": str(connection["event_id"]),
        "identity": str(authentication["event_id"]),
        "control_plane": str(control["event_id"]),
    }
    return telemetry, ids, scoring.domain_of_telemetry(telemetry)


def _state(claims: list) -> InvestigationState:
    """A finished-looking investigation carrying exactly ``claims``."""
    finding = Finding(
        rule_id="ATH-002", title="Encoded command", severity=Severity.HIGH,
        device="PC01", user="jdoe",
        evidence=(Evidence(event_id="evt-x", timestamp=at(), summary="x"),),
        reason="test",
    )
    state = InvestigationState(case=InvestigationCase(case_id="CASE-001", findings=(finding,)))
    state.claims.extend(claims)
    return state


def _claim(claim_type: ClaimType, ids: tuple, statement: str = "linked") -> Claim:
    return Claim(
        claim_type=claim_type, statement=statement, evidence_ids=ids,
        source="tool" if claim_type is ClaimType.FACT else "analysis", agent="test",
    )


def test_domains_come_from_the_registry_and_the_channel_table() -> None:
    """Not typed out here: a specialist added to the registry appears without an edit."""
    assert scoring.domain_tables() == {
        "endpoint": frozenset({"process"}),
        "identity": frozenset({"logon"}),
        "network": frozenset({"network"}),
        "control_plane": frozenset({"control"}),
    }
    assert "attack" not in scoring.domain_tables(), (
        "the ATT&CK mapper reads no telemetry of its own and is not a domain"
    )


def test_an_evidence_id_knows_which_domain_it_belongs_to(four_domains) -> None:
    _telemetry, ids, domain_of = four_domains
    for domain, event_id in ids.items():
        assert domain_of(event_id) == domain
    assert domain_of("evt-does-not-exist") is None


def test_cder_counts_a_link_recovered_only_when_one_claim_cites_both(four_domains) -> None:
    """Two claims that each mention one end assert no connection between them."""
    _telemetry, ids, domain_of = four_domains
    links = [
        (ids["identity"], ids["endpoint"]),   # recovered by one INFERENCE
        (ids["endpoint"], ids["network"]),    # recovered by one FACT
        (ids["identity"], ids["network"]),    # missed: cited by two separate claims
    ]
    state = _state([
        _claim(ClaimType.INFERENCE, (ids["identity"], ids["endpoint"])),
        _claim(ClaimType.FACT, (ids["endpoint"], ids["network"])),
        _claim(ClaimType.FACT, (ids["identity"],), "one end"),
        _claim(ClaimType.FACT, (ids["network"],), "the other end"),
    ])

    result = scoring.cross_domain_evidence_recovery(state, links, domain_of)

    assert result["defined"] == 3
    assert result["recovered"] == 2
    assert result["recovery"] == pytest.approx(2 / 3)
    assert [link["evidence_ids"] for link in result["missed_links"]] == [
        sorted([ids["identity"], ids["network"]])
    ]


def test_a_hypothesis_does_not_recover_a_link(four_domains) -> None:
    """The claim type this project allows to stand unsupported cannot do the one thing
    CDER measures. Fails if HYPOTHESIS is ever folded into the recovering types."""
    _telemetry, ids, domain_of = four_domains
    link = (ids["identity"], ids["endpoint"])
    guess = _state([
        Claim(
            claim_type=ClaimType.HYPOTHESIS,
            statement="these may be the same hop",
            evidence_ids=(ids["identity"], ids["endpoint"]),
            source="llm", agent="synthesis",
        ),
    ])
    stated = _state([_claim(ClaimType.INFERENCE, (ids["identity"], ids["endpoint"]))])

    assert scoring.cross_domain_evidence_recovery(guess, [link], domain_of)["recovered"] == 0
    assert scoring.cross_domain_evidence_recovery(stated, [link], domain_of)["recovered"] == 1


@pytest.mark.parametrize("bad,match", [
    (("a",), "pair of two different"),
    (("same", "same"), "pair of two different"),
    (("missing-id", "other-missing"), "no canonical telemetry table"),
])
def test_a_mis_registered_link_raises_rather_than_scoring_zero(
    four_domains, bad, match,
) -> None:
    """A pre-registration that cannot be right must not look like an arm that failed."""
    _telemetry, _ids, domain_of = four_domains
    with pytest.raises(scoring.UnknownRubric, match=match):
        scoring.cross_domain_evidence_recovery(_state([]), [bad], domain_of)


def test_a_link_inside_one_domain_is_refused() -> None:
    """"Two ids from two different domains" is the definition, not a preference."""
    first = proc("powershell.exe", "powershell.exe -enc AAA", "WINWORD.EXE")
    second = proc("cmd.exe", "cmd.exe /c whoami", "powershell.exe")
    telemetry = build_telemetry(procs=[first, second])
    domain_of = scoring.domain_of_telemetry(telemetry)
    with pytest.raises(scoring.UnknownRubric, match="not cross-domain"):
        scoring.cross_domain_evidence_recovery(
            _state([]),
            [(str(first["event_id"]), str(second["event_id"]))],
            domain_of,
        )


def test_no_registered_link_reports_none_rather_than_zero(four_domains) -> None:
    """A case with no links is not a case this metric failed."""
    _telemetry, _ids, domain_of = four_domains
    result = scoring.cross_domain_evidence_recovery(_state([]), [], domain_of)
    assert result == {
        "defined": 0, "recovered": 0, "recovery": None,
        "recovered_links": [], "missed_links": [],
    }


def test_cross_domain_claims_report_the_pairs_and_keep_the_types_apart(
    four_domains,
) -> None:
    _telemetry, ids, domain_of = four_domains
    state = _state([
        _claim(ClaimType.FACT, (ids["endpoint"], ids["network"])),
        _claim(ClaimType.INFERENCE, (ids["identity"], ids["endpoint"], ids["control_plane"])),
        _claim(ClaimType.FACT, (ids["endpoint"],), "one domain only"),
        Claim(
            claim_type=ClaimType.HYPOTHESIS, statement="maybe",
            evidence_ids=(ids["identity"], ids["network"]),
            source="llm", agent="synthesis",
        ),
    ])

    result = scoring.cross_domain_claims(state, domain_of)

    assert result["count"] == 3
    assert result["verified_count"] == 2
    assert result["by_type"] == {"FACT": 1, "HYPOTHESIS": 1, "INFERENCE": 1}
    assert result["domain_pairs"] == {
        "control_plane|endpoint": 1,
        "control_plane|identity": 1,
        "endpoint|identity": 1,
        "endpoint|network": 1,
        "identity|network": 1,
    }
    assert all("evidence_ids" not in entry for entry in result["claims"]), (
        "a metric that embeds every cited id rebuilds the 36 MB artifact T2 characterised"
    )


def test_cross_domain_claims_ignore_a_claim_citing_one_domain_twice(four_domains) -> None:
    """Two ids from the same table are one domain, however many of them there are."""
    telemetry, ids, domain_of = four_domains
    other = str(telemetry.processes.iloc[0]["event_id"])
    state = _state([_claim(ClaimType.FACT, (ids["endpoint"], other))])
    assert scoring.cross_domain_claims(state, domain_of)["count"] == 0


# --------------------------------------------------------------------------------------
# UCC
# --------------------------------------------------------------------------------------


@pytest.fixture
def rubric(four_domains):
    _telemetry, ids, domain_of = four_domains
    return scoring.CaseRubric.from_dict(
        {
            "case_id": "CASE-001",
            "links": [[ids["identity"], ids["endpoint"]]],
            "matters": [
                {
                    "name": "lateral movement",
                    "kind": "stage",
                    "evidence_ids": [ids["identity"], ids["endpoint"]],
                },
                {
                    "name": "verdict",
                    "kind": "verdict",
                    "evidence_ids": [ids["endpoint"], ids["network"]],
                },
            ],
        },
        domain_of,
    )


def test_ucc_credits_the_only_arm_that_produced_a_contribution(four_domains, rubric) -> None:
    """And credits neither when two arms produced the same one.

    The case that decides whether this metric is honest: arm B and arm C both link the
    logon to the process, in different words. The link is unique to neither, and a
    comparison by prose would have called both unique.
    """
    _telemetry, ids, domain_of = four_domains
    shared = (ids["identity"], ids["endpoint"])
    rows = {
        "A_deterministic": _state([]),
        "B_single_llm": _state([
            _claim(ClaimType.INFERENCE, shared, "the logon and the process are one hop"),
        ]),
        "C_crew_llm": _state([
            _claim(ClaimType.INFERENCE, shared, "one hop: this logon started this process"),
            _claim(ClaimType.FACT, (ids["endpoint"], ids["network"]), "and it dialled out"),
        ]),
    }

    result = scoring.unique_cross_domain_contribution(rows, rubric)

    assert result["A_deterministic"]["contributions"] == 0
    assert result["A_deterministic"]["unique"] == 0

    # Both model arms recovered the pre-registered link, and both stated it -- with
    # different words and the same cited ids, so neither owns it.
    assert result["B_single_llm"]["links_recovered"] == 1
    assert result["C_crew_llm"]["links_recovered"] == 1
    assert result["B_single_llm"]["unique"] == 0
    assert result["B_single_llm"]["shared"] == 2

    # C's second claim joins endpoint to network evidence, which no other arm cited.
    assert result["C_crew_llm"]["unique"] == 1
    assert result["C_crew_llm"]["unique_claims"] == 1
    assert result["C_crew_llm"]["unique_and_matters"] == 1
    assert result["C_crew_llm"]["entries"][0]["matters"] == ["verdict"]


def test_ucc_drops_a_unique_contribution_that_matters_to_nothing(four_domains, rubric) -> None:
    """Unique is not the same as useful: the plan requires a rubric item too."""
    _telemetry, ids, domain_of = four_domains
    rows = {
        "A_deterministic": _state([]),
        "C_crew_llm": _state([
            _claim(ClaimType.INFERENCE, (ids["identity"], ids["control_plane"]), "unregistered"),
        ]),
    }
    result = scoring.unique_cross_domain_contribution(rows, rubric)
    assert result["C_crew_llm"]["unique"] == 1
    assert result["C_crew_llm"]["unique_and_matters"] == 0
    assert result["C_crew_llm"]["unique_without_matters"][0]["domains"] == [
        "control_plane", "identity",
    ]


def test_ucc_is_computed_for_every_arm_not_only_the_crew(four_domains, rubric) -> None:
    """Symmetric by construction -- the milestone's question is comparative."""
    _telemetry, ids, _domain_of = four_domains
    rows = {
        "A_deterministic": _state([
            _claim(ClaimType.FACT, (ids["endpoint"], ids["network"]), "A found it"),
        ]),
        "B_single_llm": _state([]),
        "C_crew_llm": _state([]),
    }
    result = scoring.unique_cross_domain_contribution(rows, rubric)
    assert set(result) == {"A_deterministic", "B_single_llm", "C_crew_llm"}
    assert result["A_deterministic"]["unique_and_matters"] == 1


def test_a_rubric_item_of_an_unknown_kind_is_refused(four_domains) -> None:
    _telemetry, ids, domain_of = four_domains
    with pytest.raises(scoring.UnknownRubric, match="kind"):
        scoring.CaseRubric.from_dict(
            {"case_id": "x", "matters": [{"name": "n", "kind": "priority"}]}, domain_of,
        )


# ======================================================================================
# Planner activation, duplicate calls, context size
# ======================================================================================


def _m19_row(arm: str, corpus: str = "synthetic:INC-001", case_id: str = "CASE-001"):
    rows = json.loads((M19 / f"arm_{arm}.json").read_text(encoding="utf-8"))["cases"]
    return next(
        row for row in rows if row["corpus"] == corpus and row["case_id"] == case_id
    )


def test_planner_activation_on_the_one_m19_case_that_offered_a_choice() -> None:
    """INC-001 is the case the M19 report is about: the only one of 22 where more than
    one specialist was eligible at a step.

    The numbers are read from the committed rows, and two of them correct the reading
    the task brief carried. Arm A has three multi-candidate steps too -- the choice
    existed and the planner was *not consulted*, which is a different fact from no
    choice existing -- and arm B has eight, because M19-3 split its generalist into
    seven facets precisely so its planner would have something to choose between. What
    is 3-and-0 is arm C's ``chosen_by_model`` against arm A's.
    """
    activation = {
        arm: scoring.planner_activation(_m19_row(arm)) for arm in ("A", "B", "C")
    }

    assert activation["C"]["multi_candidate_steps"] == 3
    assert activation["C"]["chosen_by_model"] == 3
    assert activation["C"]["specialists_selected"] == [
        "endpoint", "identity", "network", "attack",
    ]
    assert activation["C"]["domain_specialists_selected"] == [
        "endpoint", "identity", "network",
    ]
    assert activation["C"]["handoffs"] == [
        "endpoint->identity", "identity->network", "network->attack",
    ]

    assert activation["A"]["multi_candidate_steps"] == 3
    assert activation["A"]["chosen_by_model"] == 0
    assert activation["A"]["decisions"] == {"only-eligible": 1, "planner-not-consulted": 3}

    assert activation["B"]["multi_candidate_steps"] == 8
    assert activation["B"]["chosen_by_model"] == 8
    assert activation["B"]["domain_specialists_selected"] == []
    assert activation["B"]["handoffs"] == [], (
        "seven facets of one generalist are one agent; a handoff between them is not one"
    )


def test_planner_activation_reads_a_live_state_and_a_row_alike(four_domains) -> None:
    state = _state([])
    state.note_planner_decision("only-eligible")
    state.record(AgentResult(agent="endpoint", ran_because="x"), [], [])
    live = scoring.planner_activation(state)
    assert live == scoring.planner_activation(state.to_dict())
    assert live["specialists_selected"] == ["endpoint"]
    assert live["multi_candidate_share"] == 0.0


def test_duplicate_tool_calls_on_a_recorded_m19_row() -> None:
    """What the metric is for, on real rows: arm C spent 7 of its 43 calls on INC-001
    asking a read-only tool something it had already been told.

    Six of the seven are ``lookup_technique`` on a technique id the ATT&CK mapper had
    already retrieved -- it looks one up per mapping rather than per distinct id -- and
    the case then hit the 40-call cap with three refusals, one of them ``T1074.001``,
    a technique no call ever retrieved. So on this row the duplicates are not only a
    cost: they displaced a technique out of ``techniques_asserted``.
    """
    duplicates = scoring.duplicate_tool_calls(_m19_row("C"))
    assert duplicates["tool_calls"] == 43
    assert duplicates["distinct_calls"] == 36
    assert duplicates["duplicate_calls"] == 7
    assert duplicates["refused_calls"] == 3
    repeated = {
        entry["calls"] for entry in duplicates["repeated"]
    }
    assert repeated == {2}
    assert sum(1 for e in duplicates["repeated"] if e["tool"] == "lookup_technique") == 6


def test_duplicate_tool_calls_ignore_the_order_arguments_were_passed_in() -> None:
    state = _state([])
    state.record(
        AgentResult(
            agent="endpoint", ran_because="x",
            tool_calls=(
                ToolCall(tool="process_tree", arguments={"device": "PC01", "pid": 4},
                         agent="endpoint", result_summary=""),
                ToolCall(tool="process_tree", arguments={"pid": 4, "device": "PC01"},
                         agent="endpoint", result_summary=""),
                ToolCall(tool="process_tree", arguments={"pid": 5, "device": "PC01"},
                         agent="endpoint", result_summary=""),
            ),
        ),
        [], [],
    )
    result = scoring.duplicate_tool_calls(state)
    assert result["tool_calls"] == 3
    assert result["distinct_calls"] == 2
    assert result["duplicate_calls"] == 1


# ======================================================================================
# The harness: context size, and the equal-footing refusal
# ======================================================================================


@pytest.fixture(scope="module")
def corpus():
    from ath.telemetry.k8s_audit_source import K8sAuditSource
    from ath.telemetry.loader import Telemetry

    tables = K8sAuditSource(
        ROOT / "tests" / "fixtures" / "k8s_audit", cluster="test-cluster",
    ).load().tables
    return Telemetry(
        processes=tables["process"], network=tables["network"],
        logons=tables["logon"], controls=tables["control"],
    )


@pytest.fixture(scope="module")
def pipeline(corpus):
    from ath.environment import build_environment_model
    from ath.triage import assess_findings, set_aside_ids

    hunt = run_hunt(corpus)
    environment = build_environment_model(corpus)
    assessments = assess_findings(hunt.findings, environment)
    cases = correlate(hunt.findings, corpus, set_aside=set_aside_ids(assessments))
    assert cases
    return list(hunt.findings), list(cases), environment


@pytest.fixture(scope="module")
def manifest(corpus, pipeline):
    _findings, cases, _environment = pipeline
    return build_manifest("fixture", corpus, cases, selection="every case")


def test_a_scripted_run_records_what_each_request_weighed(manifest, corpus, pipeline):
    """End to end through ``run_arm``: the observer, the state, the row.

    The bytes are checked against :func:`build_request_body` over the prompts the
    orchestrator actually assembled, so this fails if the recorded number ever stops
    being the number that would go on the wire -- which is the only property that made
    T2's 413 characterisation answerable.
    """
    findings, cases, environment = pipeline
    client = ScriptedLLM(responses=['{"claims": []}'] * 12, name="scripted-harness")

    rows = run_arm(
        arm_b(), manifest, corpus, cases, findings=findings,
        environment=environment, llm=client, scripted=True,
    )

    row = rows[0]
    requests = row.to_dict()["state"]["llm"]["requests"]
    assert requests, "a scripted model arm sent requests and must have recorded them"
    expected = [
        len(encode_request_body(build_request_body(
            model=client.name, max_tokens=8192, system=system, prompt=prompt,
        )))
        for system, prompt in client.calls[: len(requests)]
    ]
    assert [r["request_bytes"] for r in requests] == expected

    assert row.context["model_calls"] == len(requests)
    assert row.context["largest_request_bytes"] == max(expected)
    assert row.context["total_request_bytes"] == sum(expected)
    assert row.context["total_input_tokens"] == (
        client.fake_input_tokens * row.context["calls_with_input_tokens"]
    )
    assert scoring.context_size(row.to_dict()) == row.context


def test_the_deterministic_arm_records_zeros(manifest, corpus, pipeline) -> None:
    """Arm A sends nothing, so its context column is zero rather than absent."""
    findings, cases, environment = pipeline
    row = run_arm(
        arm_a(), manifest, corpus, cases, findings=findings, environment=environment,
    )[0]
    assert row.context == {
        "model_calls": 0, "largest_request_bytes": 0, "total_request_bytes": 0,
        "calls_with_input_tokens": 0, "largest_input_tokens": None,
        "total_input_tokens": None,
    }
    assert "requests" not in row.to_dict()["state"]["llm"], (
        "a run with no measurements must serialise exactly as it did before the hook "
        "existed"
    )


def test_one_case_records_only_its_own_requests(manifest, corpus, pipeline) -> None:
    """The client is shared across cases; the measurements must not be."""
    findings, cases, environment = pipeline
    client = ScriptedLLM(responses=['{"claims": []}'] * 40, name="scripted-harness")
    rows = run_arm(
        arm_b(), list(manifest) * 2, corpus, cases, findings=findings,
        environment=environment, llm=client, scripted=True,
    )
    assert len(rows) == 2
    first, second = (row.to_dict()["state"]["llm"]["requests"] for row in rows)
    assert len(first) == len(second)
    assert client.request_observer is None, "the hook is detached when the case ends"


def test_the_row_says_what_it_was_allowed_to_see_and_spend(manifest, corpus, pipeline):
    findings, cases, environment = pipeline
    row = run_arm(
        arm_a(), manifest, corpus, cases, findings=findings, environment=environment,
    )[0]
    assert row.footing["tool_call_cap"] is None
    assert row.footing["max_steps"] == 8
    assert row.footing["telemetry_hash"] == row.telemetry_hash
    assert len(row.footing["tool_surface_sha256"]) == 64
    assert row.footing["tools"] > 1


def test_a_row_on_a_different_footing_is_refused(manifest, corpus, pipeline) -> None:
    """The assertion has to fire while the run happens: afterwards a row run on another
    corpus is indistinguishable from a row that simply did worse."""
    findings, cases, environment = pipeline
    row = run_arm(
        arm_a(), manifest, corpus, cases, findings=findings, environment=environment,
    )[0]

    with pytest.raises(UnequalFooting, match="tool_surface_sha256"):
        run_arm(
            arm_a(), manifest, corpus, cases, findings=findings,
            environment=environment,
            required_footing={**row.footing, "tool_surface_sha256": "0" * 64},
        )
    with pytest.raises(UnequalFooting, match="telemetry_hash"):
        run_arm(
            arm_a(), manifest, corpus, cases, findings=findings,
            environment=environment,
            required_footing={**row.footing, "telemetry_hash": "0" * 64},
        )


def test_a_model_arm_may_run_on_the_deterministic_arm_s_footing(
    manifest, corpus, pipeline,
) -> None:
    """Arm A is uncapped by design, and that pre-registered difference must not refuse
    every run: budgets are compared between the arms that run a model."""
    findings, cases, environment = pipeline
    reference = run_arm(
        arm_a(), manifest, corpus, cases, findings=findings, environment=environment,
    )[0]
    rows = run_arm(
        arm_b(), manifest, corpus, cases, findings=findings, environment=environment,
        llm=ScriptedLLM(responses=['{"claims": []}'] * 12), scripted=True,
        required_footing=reference.footing,
    )
    assert rows and rows[0].footing["tool_call_cap"] == 40


def test_two_model_arms_on_different_budgets_are_not_on_equal_footing() -> None:
    footings = {
        "B_single_llm": {
            "tool_surface_sha256": "a" * 64, "telemetry_hash": "b" * 64,
            "tool_call_cap": 40, "max_steps": 8, "requires_model": True,
        },
        "C_crew_llm": {
            "tool_surface_sha256": "a" * 64, "telemetry_hash": "b" * 64,
            "tool_call_cap": 80, "max_steps": 8, "requires_model": True,
        },
    }
    differences = scoring.footing_differences(footings)
    assert differences and "tool_call_cap" in differences[0]

    footings["C_crew_llm"]["tool_call_cap"] = 40
    assert scoring.footing_differences(footings) == []


# ======================================================================================
# The scoring reproduction that replaces the frozen hash
# ======================================================================================


sys.path.insert(0, str(ROOT / "scripts"))

from m19b_env import (  # noqa: E402
    m19_equality_differences,
    recompute_m19_metrics,
    reproduces_grading,
)


def test_the_new_scoring_code_reproduces_grading_json_exactly() -> None:
    """M19b's freeze can no longer hash-match ``scoring.py``; this is what replaces it.

    Fails the moment an edit to the scoring code moves any number M19 published --
    which is the property the hash was standing in for, and a stronger one, because a
    hash would also have failed for an edit that moved nothing.
    """
    reproduces, differences = reproduces_grading()
    assert differences == []
    assert reproduces


def test_every_published_row_survives_the_new_code_unchanged() -> None:
    """The per-row half: no metric field dropped, renamed or re-rounded."""
    recomputed = recompute_m19_metrics()
    assert recomputed["rows"] == 66
    assert recomputed["round_trip_failures"] == []


def test_the_reproduction_notices_a_changed_number(tmp_path) -> None:
    """Fails if the check is vacuous -- the failure mode of every comparison test."""
    for name in ("arm_A.json", "arm_B.json", "arm_C.json", "GRADING.json"):
        (tmp_path / name).write_text(
            (M19 / name).read_text(encoding="utf-8"), encoding="utf-8",
        )
    payload = json.loads((tmp_path / "arm_A.json").read_text(encoding="utf-8"))
    payload["cases"][0]["scores"]["completeness"]["facts"] += 1
    (tmp_path / "arm_A.json").write_text(json.dumps(payload), encoding="utf-8")

    reproduces, differences = reproduces_grading(tmp_path)
    assert not reproduces
    assert any("round trip" in d or "arms." in d for d in differences)


def test_the_m19b_environment_still_equals_m19_where_it_must() -> None:
    """Prompts, request configuration, retry policy, budgets, model ids, tool surface.

    The two defect fixes touch none of them, which is the claim this asserts rather
    than assumes.
    """
    from ath.evaluation.ablation import environment as ablation_env

    live = ablation_env.capture_environment(ROOT, manifest_hash="m19b")
    m19 = json.loads(
        (M19 / ablation_env.ENVIRONMENT_JSON).read_text(encoding="utf-8")
    )
    assert m19_equality_differences(live, m19) == []


def test_the_m19_equality_check_notices_a_changed_prompt() -> None:
    from ath.evaluation.ablation import environment as ablation_env

    live = ablation_env.capture_environment(ROOT, manifest_hash="m19b")
    m19 = json.loads(
        (M19 / ablation_env.ENVIRONMENT_JSON).read_text(encoding="utf-8")
    )
    live["prompts"]["planner_system"] = "0" * 64
    differences = m19_equality_differences(live, m19)
    assert differences and "planner_system" in differences[0]


# ======================================================================================
# The defect fixes change no claim the M19 manifest already published
# ======================================================================================


def _strip_call_times(state: dict) -> list:
    return [
        {k: v for k, v in call.items() if k != "called_at"}
        for result in state["results"] for call in result["tool_calls"]
    ]


def test_arm_a_on_the_m19_manifest_is_unchanged_by_the_defect_fixes() -> None:
    """Re-run arm A on the M19 manifest cases this repository can load, and require
    every claim, every tool call and every score to equal the committed row.

    This is the assertion the two defect fixes rest on: they apply to every arm
    identically, so they may not move a number M19 published. Wall time is excluded and
    nothing else is.

    **Coverage.** Four of the 22 manifest cases -- the synthetic incidents, whose
    corpora are generated from ``data/raw`` and the two fixture directories. The other
    eighteen (``attack_data_aws``, ``comiset``, ``flaws_cloud``) need corpora that are
    not in the repository; all 22 were checked once by hand at the commit that made the
    fixes, with zero differences, and this keeps the reproducible four as a standing
    guard rather than claiming the eighteen.
    """
    from ath.environment import build_environment_model
    from ath.evaluation.ablation import load_manifest
    from ath.evaluation.suite import standard_suite
    from ath.triage import assess_findings, set_aside_ids

    manifest_payload = json.loads((M19 / "MANIFEST.json").read_text(encoding="utf-8"))
    committed = {
        (row["corpus"], row["case_id"]): row
        for row in json.loads((M19 / "arm_A.json").read_text(encoding="utf-8"))["cases"]
    }
    entries: dict[str, list] = {}
    for entry in load_manifest(manifest_payload):
        entries.setdefault(entry.corpus, []).append(entry)

    checked = 0
    for incident in standard_suite(
        ROOT / "data" / "raw",
        ROOT / "tests" / "fixtures" / "cloudtrail",
        ROOT / "tests" / "fixtures" / "k8s_audit",
    ):
        corpus_entries = entries.get(f"synthetic:{incident.incident_id}")
        if not corpus_entries:
            continue
        telemetry = incident.telemetry
        hunt = run_hunt(telemetry)
        environment = build_environment_model(telemetry)
        assessments = assess_findings(hunt.findings, environment)
        cases = correlate(
            hunt.findings, telemetry, set_aside=set_aside_ids(assessments),
        )
        for row in run_arm(
            arm_a(), corpus_entries, telemetry, cases,
            manifest_digest=manifest_payload["manifest_hash"],
            findings=list(hunt.findings), environment=environment,
        ):
            before, now = committed[(row.corpus, row.case_id)], row.to_dict()
            key = f"{row.corpus}/{row.case_id}"
            assert now["state"]["claims"] == before["state"]["claims"], key
            assert _strip_call_times(now["state"]) == _strip_call_times(before["state"]), key
            assert now["state"]["agents_run"] == before["state"]["agents_run"], key
            assert now["state"]["plan_log"] == before["state"]["plan_log"], key
            assert now["state"]["evidence_ids"] == before["state"]["evidence_ids"], key
            for scores in (now["scores"], before["scores"]):
                scores["completeness"].pop("wall_seconds", None)
            assert now["scores"] == before["scores"], key
            checked += 1

    assert checked == 4, (
        "the guard is vacuous if it re-ran nothing; the M19 manifest pins four "
        "synthetic cases"
    )
