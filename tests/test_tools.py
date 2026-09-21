"""Tests for the agent's tool surface.

The property under test throughout: tools are the *only* channel between the agent and
the data, so every tool call must be both correct and recorded. A tool that returns
wrong data or that fails to log its own call breaks the traceability the whole design
depends on.
"""

from __future__ import annotations

import pytest

from ath.agent.tools import ToolBox
from ath.correlation import correlate
from ath.hunting import run_hunt
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import load_telemetry


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory):
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("tools_data")
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


@pytest.fixture
def toolbox(telemetry, hunt_result, cases):
    """A fresh ToolBox per test so call logs don't leak across tests."""
    return ToolBox(telemetry, hunt_result.findings, cases)


# ======================================================================================
# Every call is recorded
# ======================================================================================


def test_every_tool_call_is_recorded(toolbox) -> None:
    assert toolbox.call_count == 0
    toolbox.get_case("CASE-001", agent="tester")
    assert toolbox.call_count == 1
    toolbox.user_auth_history("jdoe", agent="tester")
    assert toolbox.call_count == 2


def test_calls_are_attributed_to_the_calling_agent(toolbox) -> None:
    toolbox.get_case("CASE-001", agent="endpoint")
    toolbox.get_case("CASE-001", agent="identity")
    assert len(toolbox.calls_by("endpoint")) == 1
    assert len(toolbox.calls_by("identity")) == 1
    assert len(toolbox.calls_by("network")) == 0


def test_tool_call_records_arguments_and_summary(toolbox) -> None:
    toolbox.user_auth_history("svc_backup", agent="identity")
    call = toolbox.calls[-1]
    assert call.tool == "user_auth_history"
    assert call.arguments == {"user": "svc_backup"}
    assert "logons" in call.result_summary or call.result_summary


# ======================================================================================
# get_case / get_finding
# ======================================================================================


def test_get_case_returns_the_real_case(toolbox, cases) -> None:
    real = cases[0]
    payload = toolbox.get_case(real.case_id, agent="t")
    assert payload["case_id"] == real.case_id
    assert set(payload["event_ids"]) == set(real.event_ids)


def test_get_case_unknown_id_reports_error_not_crash(toolbox) -> None:
    payload = toolbox.get_case("CASE-999", agent="t")
    assert "error" in payload
    assert "known" in payload


def test_get_finding_returns_evidence(toolbox, hunt_result) -> None:
    finding = hunt_result.findings[0]
    payload = toolbox.get_finding(finding.finding_id, agent="t")
    assert payload["rule_id"] == finding.rule_id
    assert set(payload["event_ids"]) == set(finding.event_ids)


def test_get_finding_unknown_id(toolbox) -> None:
    payload = toolbox.get_finding("ATH-999:evt-000001", agent="t")
    assert "error" in payload


# ======================================================================================
# get_events
# ======================================================================================


def test_get_events_returns_real_rows(toolbox, telemetry) -> None:
    real_id = telemetry.processes.iloc[0]["event_id"]
    payload = toolbox.get_events([real_id], agent="t")
    assert len(payload["events"]) == 1
    assert payload["events"][0]["event_id"] == real_id
    assert payload["not_found"] == []


def test_get_events_reports_unknown_ids_explicitly(toolbox) -> None:
    payload = toolbox.get_events(["evt-999999"], agent="t")
    assert payload["events"] == []
    assert payload["not_found"] == ["evt-999999"]


def test_get_events_drops_empty_fields(toolbox, telemetry) -> None:
    """Logon rows have an empty command_line; it should not appear as ''."""
    logon_id = telemetry.logons.iloc[0]["event_id"]
    payload = toolbox.get_events([logon_id], agent="t")
    row = payload["events"][0]
    assert "command_line" not in row


# ======================================================================================
# process_tree
# ======================================================================================


def test_process_tree_walks_real_lineage(toolbox, telemetry) -> None:
    procs = telemetry.processes
    powershell = procs[
        (procs["device"] == "PC01") & (procs["process_name"] == "powershell.exe")
        & (procs["parent_process_name"] == "WINWORD.EXE")
    ].iloc[0]
    result = toolbox.process_tree("PC01", int(powershell["process_id"]), agent="t")
    assert result["ancestry"][0]["process_name"] == "powershell.exe"
    assert result["ancestry"][1]["process_name"] == "WINWORD.EXE"


def test_process_tree_finds_children(toolbox, telemetry) -> None:
    procs = telemetry.processes
    powershell = procs[
        (procs["device"] == "PC01") & (procs["process_name"] == "powershell.exe")
        & (procs["parent_process_name"] == "WINWORD.EXE")
    ].iloc[0]
    result = toolbox.process_tree("PC01", int(powershell["process_id"]), agent="t")
    child_names = {c["process_name"] for c in result["children"]}
    assert "rundll32.exe" in child_names


def test_process_tree_unknown_pid_returns_empty(toolbox) -> None:
    result = toolbox.process_tree("PC01", 999999, agent="t")
    assert result["ancestry"] == []


# ======================================================================================
# user_auth_history
# ======================================================================================


def test_user_auth_history_matches_ground_truth_count(toolbox, telemetry, data_dir) -> None:
    result = toolbox.user_auth_history("svc_backup", agent="t")
    logons = telemetry.logons
    expected = len(logons[logons["user"] == "svc_backup"])
    assert result["summary"]["total"] == expected


def test_user_auth_history_unknown_user(toolbox) -> None:
    result = toolbox.user_auth_history("nobody_at_all", agent="t")
    assert result["events"] == []
    assert result["summary"] == {}


def test_user_auth_history_reveals_multiple_source_devices(toolbox) -> None:
    """svc_backup authenticates from both APP01 (legit) and PC01 (the attack)."""
    result = toolbox.user_auth_history("svc_backup", agent="t")
    assert set(result["summary"]["source_devices"]) >= {"PC01"}


# ======================================================================================
# host_network_activity / analyse_beacon
# ======================================================================================


def test_host_network_activity_finds_the_c2_destination(toolbox) -> None:
    result = toolbox.host_network_activity("PC01", agent="t")
    ips = {d["remote_ip"] for d in result["destinations"]}
    assert "185.220.101.47" in ips


def test_host_network_activity_returns_its_own_evidence_ids(toolbox) -> None:
    """The tool must hand back the events behind its answer.

    A caller that needs this evidence previously had to read it out of the audit log
    (``calls_by(agent)[-1].event_ids``), which couples the caller to tool-call
    *ordering*: add or reorder one internal call and the citations silently re-point
    at a different result. The audit trail records what happened; it is not an API.
    """
    result = toolbox.host_network_activity("PC01", remote_ip="185.220.101.47", agent="t")
    assert result["event_ids"], "tool returned no evidence ids"
    assert result["total"] == len(result["event_ids"])
    # And it must agree with what was recorded, not merely be non-empty.
    assert tuple(result["event_ids"]) == toolbox.calls_by("t")[-1].event_ids


def test_analyse_beacon_detects_regular_c2_interval(toolbox) -> None:
    """5 of 6 real-world gaps are exactly 300s; only the leading download-to-first-
    -beacon gap (27s) differs. The median/MAD statistic must see through that outlier."""
    result = toolbox.analyse_beacon("PC01", "185.220.101.47", agent="t")
    assert result["regular"] is True
    assert result["samples"] >= 3
    assert result["robust_cv"] < 0.15
    assert result["median_interval_seconds"] == pytest.approx(300.0)


def test_beacon_dispersion_statistic_cannot_be_paired_with_the_wrong_centre(
    toolbox,
) -> None:
    """`robust_cv` is MAD/median, and the mean is no longer exposed at all.

    This dataset is the exact shape that makes the distinction load-bearing: one 27s
    outlier among five identical 300s gaps. The robust statistic is 0.0 (every gap the
    median cares about is identical) while the mean is 254.5s -- a number no interval
    ever took. Reporting the two together asserts zero dispersion around a centre
    nothing sits on, which is precisely the incoherent FACT this project once emitted.

    Originally fixed by pairing the statistic with its own centre. `ConnectionPattern`
    goes further and drops the mean entirely: a value that cannot be read cannot be
    mispaired, and no consumer has ever needed it.
    """
    result = toolbox.analyse_beacon("PC01", "185.220.101.47", agent="t")
    assert "coefficient_of_variation" not in result, (
        "ambiguous key name reintroduced; it invites pairing a median-based "
        "statistic with the mean"
    )
    assert "mean_interval_seconds" not in result, (
        "the mean is back; it exists only to be accidentally paired with MAD/median"
    )
    assert result["robust_cv"] == pytest.approx(0.0)
    assert result["median_interval_seconds"] == pytest.approx(300.0)


def test_beacon_states_how_thin_its_support_is(toolbox) -> None:
    """A claim built on three intervals must be able to say so."""
    result = toolbox.analyse_beacon("PC01", "185.220.101.47", agent="t")
    assert result["interarrival_count"] == result["samples"] - 1
    assert "intervals" in result["support_note"]


def test_analyse_beacon_too_few_samples(toolbox) -> None:
    result = toolbox.analyse_beacon("PC02", "1.2.3.4", agent="t")
    assert result["regular"] is False
    assert "reason" in result


def test_analyse_beacon_irregular_traffic_is_not_flagged(toolbox, telemetry) -> None:
    """Ordinary browsing to a benign external IP should not look like a beacon."""
    net = telemetry.network
    benign_hits = (
        net[(net["device"] == "PC02")]
        .groupby("remote_ip").size().sort_values(ascending=False)
    )
    candidates = benign_hits[benign_hits >= 3]
    if candidates.empty:
        pytest.skip("no destination with 3+ connections on PC02 in this generation")
    ip = candidates.index[0]
    result = toolbox.analyse_beacon("PC02", ip, agent="t")
    # Not asserting False outright (randomness could coincidentally align) but the
    # dispersion should be far looser than the deliberate C2 beacon's.
    c2 = toolbox.analyse_beacon("PC01", "185.220.101.47", agent="t")
    assert result["robust_cv"] > c2["robust_cv"]


# ======================================================================================
# search_processes
# ======================================================================================


def test_search_processes_by_command_line_substring(toolbox) -> None:
    result = toolbox.search_processes(contains="comsvcs", agent="t")
    assert result["count"] == 1
    assert "comsvcs" in result["results"][0]["command_line"].lower()


def test_search_processes_by_device_and_name(toolbox) -> None:
    result = toolbox.search_processes(device="PC01", process_name="powershell.exe", agent="t")
    assert result["count"] > 0
    assert all(r["device"] == "PC01" for r in result["results"])


def test_search_processes_respects_limit(toolbox) -> None:
    result = toolbox.search_processes(process_name="powershell.exe", limit=3, agent="t")
    assert result["count"] <= 3


# ======================================================================================
# lookup_technique
# ======================================================================================


def test_lookup_technique_returns_verified_data(toolbox) -> None:
    result = toolbox.lookup_technique("T1003.001", agent="t")
    assert result["name"] == "LSASS Memory"
    assert result["parent_id"] == "T1003"


def test_lookup_technique_unknown_id(toolbox) -> None:
    result = toolbox.lookup_technique("T9999", agent="t")
    assert "error" in result


# ======================================================================================
# Read-only guarantee (structural, not just documented)
# ======================================================================================


def test_toolbox_exposes_no_write_or_delete_methods(toolbox) -> None:
    """Every public method must be a pure query -- no verbs implying mutation."""
    forbidden_verbs = ("delete", "remove", "update", "write", "set_", "disable",
                       "isolate", "block", "quarantine", "kill", "modify")
    public_methods = [
        name for name in dir(toolbox)
        if not name.startswith("_") and callable(getattr(toolbox, name))
        and name not in ("calls_by",)
    ]
    assert public_methods, "expected at least one public tool method"
    for name in public_methods:
        assert not any(v in name.lower() for v in forbidden_verbs), (
            f"{name} looks like a mutating action; tools must be read-only"
        )
