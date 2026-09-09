"""Integration test: the full pipeline, unchanged, on real-shaped imported telemetry.

This is the capstone test for the `TelemetrySource` architecture:

    Microsoft Defender export
            |
      DefenderExportSource        (adapter)
            |
      Normalization                (column rename + value remap)
            |
    Canonical telemetry schema     (validated Telemetry)
            |
    Existing detection engine      (run_hunt -- the same 10 ATH-* rules, ZERO changes)
            |
      Correlation                  (correlate -- ZERO changes)
            |
    Investigation agent            (InvestigationOrchestrator -- ZERO changes)
            |
    Evidence verification          (ClaimVerifier -- ZERO changes)
            |
      Report                       (build_report/render_markdown -- ZERO changes)

No detection rule, correlator, agent, or report module was modified to make this test
pass -- every assertion below exercises code paths that were already fully tested
against synthetic telemetry in earlier test files. What's new here is only the input:
a fixture shaped like a genuine Defender advanced-hunting export
(``tests/fixtures/defender_export/``), containing a real mini-intrusion (macro
attachment -> encoded PowerShell -> external C2) plus two deliberately malformed rows
to prove those are handled gracefully rather than corrupting the run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ath.agent.claims import ClaimVerifier
from ath.agent.orchestrator import InvestigationConfig, InvestigationOrchestrator
from ath.agent.state import InvestigationStatus
from ath.agent.tools import ToolBox
from ath.correlation import correlate
from ath.hunting import run_hunt
from ath.hunting.finding import Severity
from ath.reporting import audit_calibration, build_report, render_markdown
from ath.telemetry import DefenderExportSource, write_normalized_telemetry
from ath.telemetry.loader import load_telemetry

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "defender_export"


@pytest.fixture(scope="module")
def import_result():
    return DefenderExportSource(directory=FIXTURES).load()


@pytest.fixture(scope="module")
def telemetry(import_result):
    from ath.telemetry.loader import Telemetry

    return Telemetry(
        processes=import_result.tables["process"],
        network=import_result.tables["network"],
        logons=import_result.tables["logon"],
    )


@pytest.fixture(scope="module")
def hunt_result(telemetry):
    return run_hunt(telemetry)


@pytest.fixture(scope="module")
def cases(hunt_result, telemetry):
    return correlate(hunt_result.findings, telemetry)


# ======================================================================================
# Stage 1-3: adapter -> normalization -> canonical schema
# ======================================================================================


def test_import_produces_canonical_telemetry(telemetry) -> None:
    assert telemetry.event_count == 7  # 3 process + 3 network + 1 logon (2 dropped)


def test_canonical_telemetry_carries_defender_provenance(telemetry) -> None:
    unified = telemetry.unified()
    assert (unified["source"] == "defender_export").all()


# ======================================================================================
# Stage 4: existing detection engine, run UNCHANGED
# ======================================================================================


def test_existing_rules_fire_on_imported_telemetry(hunt_result) -> None:
    """The same ATH-001/002/003/009 that fire on synthetic data fire here too --
    no rule was touched to make this pass."""
    fired = {f.rule_id for f in hunt_result.findings}
    assert fired == {"ATH-001", "ATH-002", "ATH-003", "ATH-009"}


def test_all_registered_rules_run_without_error(hunt_result) -> None:
    assert hunt_result.errors == {}
    assert len(hunt_result.rules_run) == 16


def test_office_macro_attachment_detected(hunt_result) -> None:
    finding = hunt_result.by_rule("ATH-009")[0]
    assert finding.device == "CORP-WKS01"
    assert finding.user == "rsmith"
    assert ".docm" in finding.metadata["command_line"].lower()


def test_encoded_powershell_decoded_correctly(hunt_result) -> None:
    """The base64 blob in the fixture is real -EncodedCommand-shaped input; the
    decoder must handle it exactly as it does for synthetic data."""
    finding = hunt_result.by_rule("ATH-002")[0]
    assert finding.severity is Severity.HIGH  # decoded payload downloads remote code
    assert "45.155.204.10" in finding.metadata["decoded_command"]


def test_c2_beacon_detected_across_three_connections(hunt_result) -> None:
    finding = hunt_result.by_rule("ATH-003")[0]
    assert finding.event_count == 3
    assert finding.metadata["remote_ip"] == "45.155.204.10"


def test_every_finding_cites_only_real_imported_event_ids(hunt_result, telemetry) -> None:
    """The core traceability guarantee, now exercised on imported data."""
    known = set(
        telemetry.processes["event_id"].tolist()
        + telemetry.network["event_id"].tolist()
        + telemetry.logons["event_id"].tolist()
    )
    for finding in hunt_result.findings:
        assert set(finding.event_ids) <= known


def test_dropped_malformed_logon_rows_produce_no_findings_about_them(hunt_result) -> None:
    """svc_report / CORP-FS01 (the two malformed rows) must not appear anywhere --
    they were dropped at import, before detection ever ran."""
    for finding in hunt_result.findings:
        assert finding.user != "svc_report"
        assert finding.device != "CORP-FS01"


# ======================================================================================
# Stage 5: correlation, run UNCHANGED
# ======================================================================================


def test_findings_correlate_into_one_case(cases) -> None:
    assert len(cases) == 1
    assert len(cases[0].findings) == 4


def test_case_spans_the_expected_tactics(cases) -> None:
    case = cases[0]
    assert "Execution" in case.tactics
    assert "Command and Control" in case.tactics


def test_case_links_are_structural(cases) -> None:
    case = cases[0]
    assert case.links
    assert all(link.structural for link in case.links)


# ======================================================================================
# Stage 6-7: investigation agent + evidence verification, run UNCHANGED
# ======================================================================================


def test_investigation_completes_on_imported_telemetry(telemetry, hunt_result, cases) -> None:
    tools = ToolBox(telemetry, hunt_result.findings, cases)
    verifier = ClaimVerifier(telemetry)
    orchestrator = InvestigationOrchestrator(
        tools, verifier,
        config=InvestigationConfig(use_llm_planner=False, use_llm_synthesis=False),
    )
    state = orchestrator.investigate(cases[0])

    assert state.status is InvestigationStatus.COMPLETE
    assert state.facts
    assert state.rejected_claims == []  # every claim traces to a real imported event


def test_endpoint_agent_reconstructs_the_real_execution_chain(telemetry, hunt_result, cases) -> None:
    """Process lineage reconstruction (Office -> PowerShell) must work identically on
    imported data -- this exercises the exact same code path proven on synthetic data
    in test_orchestrator.py, now against Defender-shaped input."""
    tools = ToolBox(telemetry, hunt_result.findings, cases)
    verifier = ClaimVerifier(telemetry)
    orchestrator = InvestigationOrchestrator(
        tools, verifier,
        config=InvestigationConfig(use_llm_planner=False, use_llm_synthesis=False),
    )
    state = orchestrator.investigate(cases[0])
    chain_claims = [c for c in state.facts if "Execution chain" in c.statement]
    assert any("OUTLOOK.EXE" in c.statement and "powershell.exe" in c.statement
               for c in chain_claims)


# ======================================================================================
# Stage 8: report, run UNCHANGED
# ======================================================================================


def test_report_builds_and_renders_on_imported_telemetry(telemetry, hunt_result, cases) -> None:
    tools = ToolBox(telemetry, hunt_result.findings, cases)
    verifier = ClaimVerifier(telemetry)
    orchestrator = InvestigationOrchestrator(
        tools, verifier,
        config=InvestigationConfig(use_llm_planner=False, use_llm_synthesis=False),
    )
    state = orchestrator.investigate(cases[0])
    report = build_report(state, telemetry)

    assert report.data_sources == ("defender_export",)
    assert audit_calibration(list(report.all_claims)) == {}

    markdown = render_markdown(report)
    assert "defender_export" in markdown
    assert "synthetic" not in markdown.lower()  # the old hardcoded-disclaimer bug
    assert "CORP-WKS01" in markdown

    limitations_text = " ".join(report.limitations).lower()
    assert "synthetic" not in limitations_text  # the paired hardcoded-limitations bug
    assert "defender_export" in limitations_text


def test_every_evidence_appendix_event_is_traceable_to_the_original_export(
    telemetry, hunt_result, cases
) -> None:
    tools = ToolBox(telemetry, hunt_result.findings, cases)
    verifier = ClaimVerifier(telemetry)
    orchestrator = InvestigationOrchestrator(
        tools, verifier,
        config=InvestigationConfig(use_llm_planner=False, use_llm_synthesis=False),
    )
    state = orchestrator.investigate(cases[0])
    report = build_report(state, telemetry)

    assert report.evidence_appendix
    for entry in report.evidence_appendix:
        assert entry.source == "defender_export"


# ======================================================================================
# Round trip: write normalized output to disk, reload via the standard loader
# ======================================================================================


def test_write_then_reload_round_trips_through_the_standard_loader(
    import_result, tmp_path
) -> None:
    """Proves the drop-in point: `load_telemetry` -- used by every CLI command --
    reads Defender-imported data exactly as it reads synthetic data, with no branching
    on source anywhere in the loader."""
    written = write_normalized_telemetry(import_result, tmp_path)
    assert len(written) == 3  # no ground truth for a real import -- no 4th file

    reloaded = load_telemetry(tmp_path)
    assert reloaded.event_count == 7
    assert reloaded.unified()["source"].unique().tolist() == ["defender_export"]


def test_evaluate_command_fails_informatively_without_ground_truth(tmp_path, import_result) -> None:
    """A real import has no labels; `evaluate` must fail with a clear, specific
    message rather than the generic 'run generate first' text that would mislead
    someone who imported real data instead."""
    from ath.telemetry.loader import load_ground_truth

    write_normalized_telemetry(import_result, tmp_path)
    with pytest.raises(FileNotFoundError, match="no labels by design"):
        load_ground_truth(tmp_path)


def test_hunt_chains_investigate_report_all_work_without_ground_truth(
    import_result, tmp_path
) -> None:
    """The four commands that do NOT need labels must all still succeed end to end
    when pointed at a directory with no ground_truth.json."""
    write_normalized_telemetry(import_result, tmp_path)
    assert not (tmp_path / "ground_truth.json").exists()

    telemetry = load_telemetry(tmp_path)
    result = run_hunt(telemetry)
    assert result.findings
    found_cases = correlate(result.findings, telemetry)
    assert found_cases

    tools = ToolBox(telemetry, result.findings, found_cases)
    verifier = ClaimVerifier(telemetry)
    orchestrator = InvestigationOrchestrator(
        tools, verifier,
        config=InvestigationConfig(use_llm_planner=False, use_llm_synthesis=False),
    )
    state = orchestrator.investigate(found_cases[0])
    report = build_report(state, telemetry)
    assert render_markdown(report)
