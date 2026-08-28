"""Tests for specialist agents and the investigation orchestrator.

These tests check three things that matter most for an "autonomous agent" claim to be
credible: (1) the path taken is genuinely conditional on the case's evidence, not fixed;
(2) unnecessary agents are skipped, not run and then ignored; (3) the loop always stops,
deterministically, regardless of what a model says.
"""

from __future__ import annotations

import json

import pytest

from ath.agent.claims import ClaimType, ClaimVerifier
from ath.agent.llm import NullLLM, ScriptedLLM
from ath.agent.orchestrator import InvestigationConfig, InvestigationOrchestrator
from ath.agent.specialists import (
    AttackMappingAgent,
    EndpointAgent,
    IdentityAgent,
    NetworkAgent,
    default_specialists,
)
from ath.agent.state import InvestigationState, InvestigationStatus
from ath.agent.tools import ToolBox
from ath.correlation import correlate
from ath.hunting import run_hunt
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import load_ground_truth, load_telemetry


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory):
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("agent_data")
    write_telemetry(tables, gt, out)
    return out


@pytest.fixture(scope="module")
def telemetry(data_dir):
    return load_telemetry(data_dir)


@pytest.fixture(scope="module")
def hunt_result(telemetry):
    return run_hunt(telemetry)


@pytest.fixture(scope="module")
def cases(hunt_result, telemetry):
    return correlate(hunt_result.findings, telemetry)


@pytest.fixture(scope="module")
def intrusion_case(cases):
    return max(cases, key=lambda c: len(c.findings))


@pytest.fixture(scope="module")
def benign_case(cases, intrusion_case):
    return next(c for c in cases if c is not intrusion_case)


@pytest.fixture
def toolbox(telemetry, hunt_result, cases):
    return ToolBox(telemetry, hunt_result.findings, cases)


@pytest.fixture
def verifier(telemetry):
    return ClaimVerifier(telemetry)


def deterministic_orchestrator(toolbox, verifier, max_steps: int = 8):
    return InvestigationOrchestrator(
        toolbox, verifier,
        config=InvestigationConfig(
            max_steps=max_steps, use_llm_planner=False, use_llm_synthesis=False
        ),
    )


# ======================================================================================
# Specialist should_run gates
# ======================================================================================


def test_endpoint_runs_when_process_findings_present(toolbox, intrusion_case) -> None:
    state = InvestigationState(case=intrusion_case)
    agent = EndpointAgent(toolbox)
    should, reason = agent.should_run(state)
    assert should
    assert "process" in reason.lower()


def test_endpoint_skips_when_already_run(toolbox, intrusion_case) -> None:
    state = InvestigationState(case=intrusion_case)
    state.agents_run.append("endpoint")
    should, reason = EndpointAgent(toolbox).should_run(state)
    assert not should
    assert "already" in reason.lower()


def test_identity_requires_auth_or_credential_findings(toolbox, intrusion_case) -> None:
    should, reason = IdentityAgent(toolbox).should_run(InvestigationState(case=intrusion_case))
    assert should


def test_network_requires_ath003_or_a_follow_up_request(toolbox, intrusion_case) -> None:
    should, _ = NetworkAgent(toolbox).should_run(InvestigationState(case=intrusion_case))
    assert should  # the intrusion case has ATH-003


def test_attack_agent_is_deferred_until_after_step_zero(toolbox, intrusion_case) -> None:
    """ATT&CK synthesis is most useful once evidence exists -- so it must not go first."""
    fresh_state = InvestigationState(case=intrusion_case)  # step == 0
    should, reason = AttackMappingAgent(toolbox).should_run(fresh_state)
    assert not should
    assert "deferred" in reason.lower()

    fresh_state.step = 1
    should, _ = AttackMappingAgent(toolbox).should_run(fresh_state)
    assert should


def test_case_with_no_process_findings_skips_endpoint(toolbox) -> None:
    """A pure auth-only case should never trigger process-tree analysis.

    The refusal must be justified by the *telemetry the case rests on*, not by which
    rule ids it happens to contain -- that is the whole point of declaring eligibility
    as a capability. Asserting the old wording would have pinned the mechanism this
    refactor replaced.
    """
    from ath.correlation.chain import InvestigationCase

    auth_only = [f for f in toolbox._findings.values() if f.rule_id in ("ATH-005", "ATH-006")]
    if len(auth_only) < 1:
        pytest.skip("no auth-only findings available in this generation")
    fake_case = InvestigationCase(case_id="CASE-TEST", findings=tuple(auth_only[:1]))
    should, reason = EndpointAgent(toolbox).should_run(InvestigationState(case=fake_case))
    assert not should
    assert "telemetry" in reason
    assert not any(rule in reason for rule in ("ATH-001", "ATH-002", "ATH-004"))


# ======================================================================================
# Specialists produce well-formed, evidence-backed claims
# ======================================================================================


def test_endpoint_agent_reconstructs_macro_execution_chain(toolbox, intrusion_case) -> None:
    state = InvestigationState(case=intrusion_case)
    result = EndpointAgent(toolbox).investigate(state)
    chain_claims = [c for c in result.claims if "Execution chain" in c.statement]
    assert any("WINWORD.EXE" in c.statement and "powershell.exe" in c.statement
               for c in chain_claims)


def test_endpoint_agent_does_not_duplicate_claims_for_shared_evidence(
    toolbox, intrusion_case
) -> None:
    """ATH-001 and ATH-002 both cite the same execution; it must be analysed once."""
    state = InvestigationState(case=intrusion_case)
    result = EndpointAgent(toolbox).investigate(state)
    statements = [c.statement for c in result.claims]
    assert len(statements) == len(set(statements)), "duplicate claims were produced"


def test_identity_agent_flags_bruteforce_as_inference_not_fact(toolbox, intrusion_case) -> None:
    state = InvestigationState(case=intrusion_case)
    result = IdentityAgent(toolbox).investigate(state)
    guess_claims = [c for c in result.claims if "guessed" in c.statement.lower()]
    assert guess_claims
    assert all(c.claim_type is ClaimType.INFERENCE for c in guess_claims)


def test_identity_agent_marks_credential_source_as_hypothesis(toolbox, intrusion_case) -> None:
    """We never observed which account's memory was dumped -- must stay a hypothesis."""
    state = InvestigationState(case=intrusion_case)
    result = IdentityAgent(toolbox).investigate(state)
    hyps = [c for c in result.claims if c.claim_type is ClaimType.HYPOTHESIS]
    assert any("may have been obtained" in c.statement for c in hyps)


def test_network_agent_detects_the_c2_beacon(toolbox, intrusion_case) -> None:
    state = InvestigationState(case=intrusion_case)
    result = NetworkAgent(toolbox).investigate(state)
    assert any("automated" in c.statement.lower() for c in result.claims)
    assert any(c.claim_type is ClaimType.FACT and "coefficient of variation" in c.statement
               for c in result.claims)


def test_network_agent_notes_shared_infrastructure_across_hosts(
    toolbox, intrusion_case
) -> None:
    state = InvestigationState(case=intrusion_case)
    result = NetworkAgent(toolbox).investigate(state)
    assert any("more than one host" in c.statement for c in result.claims)


def test_attack_agent_never_claims_exfiltration_as_fact(toolbox, intrusion_case) -> None:
    state = InvestigationState(case=intrusion_case)
    state.step = 1
    result = AttackMappingAgent(toolbox).investigate(state)
    exfil_claims = [c for c in result.claims if "exfiltrat" in c.statement.lower()
                    or "transferred" in c.statement.lower()]
    assert all(c.claim_type is ClaimType.HYPOTHESIS for c in exfil_claims)


def test_attack_agent_names_missing_tactics_in_notes(toolbox, benign_case) -> None:
    state = InvestigationState(case=benign_case)
    state.step = 1
    result = AttackMappingAgent(toolbox).investigate(state)
    assert any("no evidence was found" in n.lower() for n in result.notes)


def test_all_specialist_claims_pass_verification(toolbox, verifier, intrusion_case) -> None:
    """Every claim a specialist produces must independently survive the verifier --
    specialists must not rely on the orchestrator to clean up after them."""
    state = InvestigationState(case=intrusion_case)
    for specialist in default_specialists(toolbox):
        should, _ = specialist.should_run(state)
        if not should:
            continue
        result = specialist.investigate(state)
        verification = verifier.verify(list(result.claims))
        assert not verification.rejected, (
            f"{specialist.name} produced unverifiable claims: "
            f"{[(r.claim.statement, r.reason) for r in verification.rejected]}"
        )
        state.agents_run.append(specialist.name)
        state.claims.extend(result.claims)
        state.step += 1


# ======================================================================================
# Orchestrator: path is conditional on evidence
# ======================================================================================


def test_investigation_completes_and_runs_all_applicable_agents(toolbox, verifier, intrusion_case) -> None:
    orch = deterministic_orchestrator(toolbox, verifier)
    state = orch.investigate(intrusion_case)
    assert state.status is InvestigationStatus.COMPLETE
    assert set(state.agents_run) == {"endpoint", "identity", "network", "attack"}


def test_benign_case_skips_identity_agent(toolbox, verifier, benign_case) -> None:
    """The benign case has no auth/credential findings -- identity has nothing to do."""
    orch = deterministic_orchestrator(toolbox, verifier)
    state = orch.investigate(benign_case)
    assert "identity" not in state.agents_run


def test_attack_agent_runs_last_by_default(toolbox, verifier, intrusion_case) -> None:
    orch = deterministic_orchestrator(toolbox, verifier)
    state = orch.investigate(intrusion_case)
    assert state.agents_run[-1] == "attack"


def test_plan_log_explains_every_decision(toolbox, verifier, intrusion_case) -> None:
    orch = deterministic_orchestrator(toolbox, verifier)
    state = orch.investigate(intrusion_case)
    assert len(state.plan_log) == len(state.agents_run) + 1  # + the final stop entry
    assert "stop" in state.plan_log[-1]


def test_no_agent_runs_twice(toolbox, verifier, intrusion_case) -> None:
    orch = deterministic_orchestrator(toolbox, verifier)
    state = orch.investigate(intrusion_case)
    assert len(state.agents_run) == len(set(state.agents_run))


# ======================================================================================
# Stopping conditions are deterministic
# ======================================================================================


def test_step_budget_is_enforced_regardless_of_available_work(
    toolbox, verifier, intrusion_case
) -> None:
    """Even with more eligible work, the loop must obey a low step cap."""
    orch = deterministic_orchestrator(toolbox, verifier, max_steps=2)
    state = orch.investigate(intrusion_case)
    assert state.step <= 2
    assert state.status is InvestigationStatus.STEP_LIMIT


def test_step_limit_status_is_distinguishable_from_success(
    toolbox, verifier, intrusion_case
) -> None:
    """STEP_LIMIT must never be reported as COMPLETE -- it is a budget cutoff, not success."""
    orch = deterministic_orchestrator(toolbox, verifier, max_steps=1)
    state = orch.investigate(intrusion_case)
    assert state.status is not InvestigationStatus.COMPLETE


def test_investigation_of_a_trivial_case_reaches_exhausted_or_complete(
    telemetry, hunt_result
) -> None:
    """A case with findings no specialist targets must still terminate cleanly."""
    from ath.correlation.chain import InvestigationCase

    non_actionable = [f for f in hunt_result.findings if f.rule_id == "ATH-008"]
    if not non_actionable:
        pytest.skip("no ATH-008 finding available")
    case = InvestigationCase(case_id="CASE-TRIVIAL", findings=tuple(non_actionable[:1]))
    tb = ToolBox(telemetry, hunt_result.findings, [case])
    orch = deterministic_orchestrator(tb, ClaimVerifier(telemetry))
    state = orch.investigate(case)
    assert state.status in (InvestigationStatus.COMPLETE, InvestigationStatus.EXHAUSTED)


def test_model_cannot_extend_the_investigation_past_its_budget(
    toolbox, verifier, intrusion_case
) -> None:
    """A model that always says 'keep going' must still be capped by max_steps."""
    from ath.agent.orchestrator import InvestigationOrchestrator

    # Always propose a valid-looking but never-run agent name to try to prolong things.
    scripted = ScriptedLLM(responses=[
        json.dumps({"next_agent": "endpoint", "reason": "x"}),
    ] * 20)
    orch = InvestigationOrchestrator(
        toolbox, verifier, llm=scripted,
        config=InvestigationConfig(max_steps=2, use_llm_synthesis=False),
    )
    state = orch.investigate(intrusion_case)
    assert state.step <= 2


# ======================================================================================
# Planner: model chooses from a menu, never invents an action
# ======================================================================================


def test_planner_rejects_a_name_outside_the_candidate_list(toolbox, verifier, intrusion_case) -> None:
    scripted = ScriptedLLM(responses=[
        json.dumps({"next_agent": "exfiltration_agent", "reason": "nice try"}),
    ])
    orch = InvestigationOrchestrator(
        toolbox, verifier, llm=scripted,
        config=InvestigationConfig(use_llm_synthesis=False),
    )
    specialist, reason = orch.plan(InvestigationState(case=intrusion_case))
    assert specialist is not None
    assert specialist.name != "exfiltration_agent"
    assert "deterministic priority order" in reason


def test_planner_falls_back_on_unparseable_response(toolbox, verifier, intrusion_case) -> None:
    scripted = ScriptedLLM(responses=["not json at all, sorry"])
    orch = InvestigationOrchestrator(
        toolbox, verifier, llm=scripted,
        config=InvestigationConfig(use_llm_synthesis=False),
    )
    specialist, reason = orch.plan(InvestigationState(case=intrusion_case))
    assert specialist is not None
    assert "deterministic" in reason


def test_planner_uses_model_choice_when_valid(toolbox, verifier, intrusion_case) -> None:
    scripted = ScriptedLLM(responses=[
        json.dumps({"next_agent": "identity", "reason": "credentials matter most here"}),
    ])
    orch = InvestigationOrchestrator(
        toolbox, verifier, llm=scripted,
        config=InvestigationConfig(use_llm_synthesis=False),
    )
    specialist, reason = orch.plan(InvestigationState(case=intrusion_case))
    assert specialist.name == "identity"
    assert "planner:" in reason


def test_planner_is_not_consulted_when_only_one_candidate(toolbox, verifier, intrusion_case) -> None:
    """No LLM call should be spent when the decision is not actually a decision."""
    scripted = ScriptedLLM(responses=[])  # would raise if consumed
    orch = InvestigationOrchestrator(
        toolbox, verifier, llm=scripted,
        config=InvestigationConfig(use_llm_synthesis=False),
    )
    state = InvestigationState(case=intrusion_case)
    state.agents_run = ["endpoint", "identity", "network"]
    state.step = 3
    specialist, reason = orch.plan(state)
    assert specialist.name == "attack"
    assert scripted.calls == []  # never consulted


def test_deterministic_mode_produces_identical_results_across_runs(
    toolbox, verifier, intrusion_case
) -> None:
    orch1 = deterministic_orchestrator(toolbox, verifier)
    orch2 = deterministic_orchestrator(ToolBox(
        toolbox.telemetry, list(toolbox._findings.values()), list(toolbox._cases.values())
    ), verifier)
    state1 = orch1.investigate(intrusion_case)
    state2 = orch2.investigate(intrusion_case)
    assert state1.agents_run == state2.agents_run
    assert [c.statement for c in state1.claims] == [c.statement for c in state2.claims]


# ======================================================================================
# The model never receives raw telemetry
# ======================================================================================


def test_planner_prompt_contains_no_raw_telemetry(toolbox, verifier, intrusion_case) -> None:
    scripted = ScriptedLLM(responses=[
        json.dumps({"next_agent": "endpoint", "reason": "x"}),
        json.dumps({"next_agent": "identity", "reason": "x"}),
        json.dumps({"next_agent": "network", "reason": "x"}),
    ])
    orch = InvestigationOrchestrator(
        toolbox, verifier, llm=scripted, config=InvestigationConfig(use_llm_synthesis=False)
    )
    orch.investigate(intrusion_case)
    for _system, prompt in scripted.calls:
        assert "-EncodedCommand" not in prompt
        assert "comsvcs.dll" not in prompt
        assert "185.220.101.47" not in prompt  # no raw IOCs, only structural summary


def test_synthesis_prompt_contains_only_verified_claim_text(
    toolbox, verifier, intrusion_case
) -> None:
    """Synthesis sees claim statements (already vetted), never raw telemetry rows."""
    responses = [json.dumps({"next_agent": a, "reason": "x"})
                 for a in ("endpoint", "identity", "network")]
    responses.append(json.dumps({"claims": []}))
    scripted = ScriptedLLM(responses=responses)
    orch = InvestigationOrchestrator(toolbox, verifier, llm=scripted)
    orch.investigate(intrusion_case)
    synthesis_prompt = scripted.calls[-1][1]
    assert "process_id" not in synthesis_prompt  # no raw field names / rows
    assert "[FACT]" in synthesis_prompt or "[INFERENCE]" in synthesis_prompt


# ======================================================================================
# Serialisation
# ======================================================================================


def test_investigation_state_serialises_to_json(toolbox, verifier, intrusion_case) -> None:
    orch = deterministic_orchestrator(toolbox, verifier)
    state = orch.investigate(intrusion_case)
    payload = json.loads(json.dumps(state.to_dict()))
    assert payload["case_id"] == intrusion_case.case_id
    assert payload["status"] == "complete"
    assert len(payload["claims"]) == len(state.claims)


# ======================================================================================
# Degraded-model reporting
#
# A run that lost the model it was configured to use must not be indistinguishable
# from a run that was deliberately deterministic. Both complete; only one of them is
# reporting less than it was asked to.
# ======================================================================================


class _FailingLLM:
    """A configured-and-available model whose every call fails.

    Stands in for the realistic failure that motivated this: a typo'd API key, an
    unknown model id, or an expired credential -- all of which return an HTTP error
    that the client turns into `LLMResponse(error=...)` while the run continues.
    """

    name = "failing"
    available = True

    def __init__(self, error: str = "HTTP 401 (ATH_LLM_API_KEY is missing or invalid)"):
        self._error = error
        self.call_count = 0

    def complete(self, system: str, prompt: str, max_tokens: int = 1024):
        from ath.agent.llm import LLMResponse

        self.call_count += 1
        return LLMResponse(error=self._error, model=self.name)


def test_failing_llm_still_completes_the_investigation(
    toolbox, verifier, intrusion_case
) -> None:
    """Degradation must not become an outage: the deterministic path still runs."""
    orch = InvestigationOrchestrator(toolbox, verifier, llm=_FailingLLM())
    state = orch.investigate(intrusion_case)
    assert state.status is InvestigationStatus.COMPLETE
    assert state.facts, "deterministic specialists should still have produced facts"


def test_failing_llm_is_reported_as_degraded(toolbox, verifier, intrusion_case) -> None:
    """The run must say it lost the model, and say why."""
    llm = _FailingLLM()
    orch = InvestigationOrchestrator(toolbox, verifier, llm=llm)
    state = orch.investigate(intrusion_case)

    assert llm.call_count > 0, "test is vacuous if the model was never called"
    assert state.llm_requested is True
    assert state.llm_degraded is True
    assert state.llm_errors, "failures were swallowed instead of recorded"
    assert "401" in state.llm_status
    assert "DEGRADED" in state.llm_status
    # And it must survive serialisation -- the JSON output is what a downstream
    # consumer or a report reads, not the Python object.
    payload = json.loads(json.dumps(state.to_dict()))
    assert payload["llm"]["degraded"] is True


def test_deterministic_run_is_not_reported_as_degraded(
    toolbox, verifier, intrusion_case
) -> None:
    """`--no-llm` is a choice, not a failure, and must not be flagged as one."""
    orch = deterministic_orchestrator(toolbox, verifier)
    state = orch.investigate(intrusion_case)
    assert state.llm_requested is False
    assert state.llm_degraded is False
    assert state.llm_errors == []
    assert "no model requested" in state.llm_status


def test_unparseable_response_is_not_a_model_failure(
    toolbox, verifier, intrusion_case
) -> None:
    """A model that answers with prose is working; it is just unhelpful.

    Recording that as an error would inflate the degraded signal and train a reader
    to ignore it -- the same reason ATH-002 does not grade all encoded PowerShell as
    HIGH.
    """
    scripted = ScriptedLLM(responses=["not json at all, sorry"] * 20)
    orch = InvestigationOrchestrator(toolbox, verifier, llm=scripted)
    state = orch.investigate(intrusion_case)
    assert state.llm_requested is True
    assert state.llm_degraded is False, "a parseable-but-useless answer is not an outage"


# ======================================================================================
# Capability-based eligibility
#
# Specialists declare the telemetry they need and respond to, rather than matching
# literal rule ids. These tests cover the two failures the allowlist actually had.
# ======================================================================================


def _finding(rule_id: str, fields: tuple[str, ...], device: str = "HOST", user: str = "u"):
    """A finding from an arbitrary rule catalogue, declaring its telemetry fields."""
    from datetime import datetime, timezone

    from ath.hunting.finding import Evidence, Finding, Severity

    return Finding(
        rule_id=rule_id, title="t", severity=Severity.HIGH, device=device, user=user,
        evidence=(Evidence("evt-000001", datetime.now(timezone.utc), "s"),),
        reason="r", fields_used=fields,
    )


def _case(*findings):
    from ath.correlation.chain import InvestigationCase

    return InvestigationCase(case_id="CASE-TEST", findings=tuple(findings))


def test_specialists_activate_on_an_unknown_rule_catalogue(toolbox) -> None:
    """The failure that motivated this design.

    Before: eligibility matched literal ``ATH-0xx`` ids, so a case built from any other
    catalogue matched nothing, *every* specialist declined, and the investigation
    completed as EXHAUSTED having done no work. The specialists' logic was never
    Windows-specific -- only the allowlist was.
    """
    from ath.agent.specialists import EndpointAgent, IdentityAgent

    case = _case(
        _finding("AWS-001", ("action", "logon_type", "source_ip")),
        _finding("K8S-001", ("process_name", "command_line", "parent_process_name")),
    )
    state = InvestigationState(case=case)

    endpoint_ok, endpoint_why = EndpointAgent(toolbox).should_run(state)
    identity_ok, identity_why = IdentityAgent(toolbox).should_run(state)

    assert endpoint_ok, f"endpoint declined a process-evidenced case: {endpoint_why}"
    assert identity_ok, f"identity declined an auth-evidenced case: {identity_why}"


def test_specialist_declines_when_the_case_lacks_its_telemetry(toolbox) -> None:
    """Capability matching must still discriminate, or it is just 'always run'."""
    from ath.agent.specialists import NetworkAgent

    case = _case(_finding("AWS-001", ("action", "logon_type", "source_ip")))
    should, reason = NetworkAgent(toolbox).should_run(InvestigationState(case=case))
    assert not should
    assert "network" in reason


def test_rules_added_later_are_picked_up_without_editing_a_list(toolbox, hunt_result) -> None:
    """The allowlist's other failure: it went stale silently.

    ATH-009 and ATH-010 were added in Milestone 6. Both are process rules. Neither was
    added to the endpoint specialist's hardcoded set, so lineage analysis quietly
    stopped applying to them -- no error, no failing test, and a plausible-sounding
    "case contains no process-based findings" recorded as the reason. Declared
    capabilities cannot drift this way: the rule states its fields, and eligibility
    follows.
    """
    from ath.agent.specialists import EndpointAgent

    for rule_id in ("ATH-009", "ATH-010"):
        findings = [f for f in hunt_result.findings if f.rule_id == rule_id]
        if not findings:
            pytest.skip(f"{rule_id} produced no findings in this generation")
        state = InvestigationState(case=_case(findings[0]))
        should, reason = EndpointAgent(toolbox).should_run(state)
        assert should, f"{rule_id} is a process rule but endpoint declined it: {reason}"


def test_credential_access_triggers_identity_via_tactic_not_rule_id(toolbox) -> None:
    """The ATH-004 special case, re-expressed as the intent behind it.

    The old gate named one rule id to mean "credentials were touched, so check where
    those accounts were used next". That intent is a tactic. Any rule mapping to
    Credential Access should now trigger the same follow-up, including rules that do
    not exist yet.
    """
    from unittest.mock import MagicMock

    from ath.agent.specialists import IdentityAgent

    case = MagicMock()
    case.findings = (_finding("NEW-999", ("command_line", "process_name")),)
    case.rule_ids = ("NEW-999",)
    case.tactics = ("Credential Access",)

    should, reason = IdentityAgent(toolbox).should_run(InvestigationState(case=case))
    assert should
    assert "Credential Access" in reason


# ======================================================================================
# Environment-aware refusal
# ======================================================================================


def _environment_without_processes(telemetry):
    """An environment whose process telemetry is entirely absent."""
    from ath.environment import build_environment_model
    from ath.telemetry.loader import Telemetry

    return build_environment_model(Telemetry(
        processes=telemetry.processes.iloc[0:0],
        network=telemetry.network,
        logons=telemetry.logons,
    ))


def test_specialist_declines_when_the_environment_cannot_see(toolbox, telemetry) -> None:
    """Missing telemetry is a different refusal from "nothing to investigate".

    A specialist whose channel is absent should say so, rather than run, find nothing,
    and leave a reader to conclude nothing happened -- the same distinction the
    visibility model draws at the detection layer.
    """
    from ath.agent.specialists import EndpointAgent

    case = _case(_finding("K8S-001", ("process_name", "parent_process_name")))
    state = InvestigationState(
        case=case, environment=_environment_without_processes(telemetry)
    )
    should, reason = EndpointAgent(toolbox).should_run(state)

    assert not should
    assert "unavailable" in reason
    assert "process_execution" in reason
    assert "regardless of what occurred" in reason


def test_absent_environment_does_not_block_anything(toolbox) -> None:
    """No visibility assessment is not evidence that telemetry is missing.

    Declining on an absent environment model would be exactly the inference this
    project forbids everywhere else: treating "we did not check" as "it is not there".
    """
    from ath.agent.specialists import EndpointAgent

    case = _case(_finding("K8S-001", ("process_name", "parent_process_name")))
    should, _ = EndpointAgent(toolbox).should_run(
        InvestigationState(case=case, environment=None)
    )
    assert should


def test_environment_aware_run_still_completes(toolbox, verifier, intrusion_case, telemetry) -> None:
    """Attaching an environment must not break a normal investigation."""
    from ath.environment import build_environment_model

    orch = InvestigationOrchestrator(
        toolbox, verifier, llm=NullLLM(),
        environment=build_environment_model(telemetry),
    )
    state = orch.investigate(intrusion_case)
    assert state.status is InvestigationStatus.COMPLETE
    assert state.facts
    assert state.environment is not None
