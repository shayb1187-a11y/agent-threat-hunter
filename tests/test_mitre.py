"""Tests for the MITRE ATT&CK interpretation layer.

The property that matters most here is negative: the system must be *unable* to emit a
technique ID it has not verified, and must *not* assert techniques it has no evidence
for. Both are tested directly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ath.hunting import Evidence, Finding, Severity, run_hunt
from ath.mitre import (
    MAPPING_RULES,
    TECHNIQUES,
    AttackMapping,
    Confidence,
    Tactic,
    UnknownTechniqueError,
    get_technique,
    map_finding,
    map_findings,
    tactics_covered,
    unique_techniques,
)
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import load_telemetry


@pytest.fixture(scope="module")
def telemetry(tmp_path_factory):
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("mitre_data")
    write_telemetry(tables, gt, out)
    return load_telemetry(out)


@pytest.fixture(scope="module")
def hunt(telemetry):
    return run_hunt(telemetry)


def _finding(rule_id: str, **metadata) -> Finding:
    """Minimal synthetic finding for gate testing."""
    import pandas as pd

    return Finding(
        rule_id=rule_id, title="t", severity=Severity.MEDIUM,
        device="PC01", user="jdoe",
        evidence=(Evidence("evt-000001", pd.Timestamp("2026-08-17 09:00", tz="UTC"), "s"),),
        reason="r", metadata=metadata,
    )


# ======================================================================================
# Catalogue integrity
# ======================================================================================


def test_catalogue_is_internally_consistent() -> None:
    for tid, technique in TECHNIQUES.items():
        assert technique.technique_id == tid
        assert technique.name and technique.tactics
        assert technique.url.startswith("https://attack.mitre.org/techniques/")


def test_sub_technique_parents_exist_and_share_a_tactic() -> None:
    """A sub-technique that names a parent not in the catalogue is a data error."""
    for technique in TECHNIQUES.values():
        if not technique.is_sub_technique:
            continue
        parent = get_technique(technique.parent_id)
        assert not parent.is_sub_technique, f"{technique.technique_id} parent is a sub"
        assert set(technique.tactics) & set(parent.tactics), (
            f"{technique.technique_id} shares no tactic with {parent.technique_id}"
        )


def test_sub_technique_ids_are_well_formed() -> None:
    for tid, technique in TECHNIQUES.items():
        if technique.is_sub_technique:
            assert tid.startswith(technique.parent_id + ".")
            assert len(tid.split(".")[1]) == 3  # ATT&CK sub-ids are 3 digits


def test_defense_evasion_is_recorded_as_stealth() -> None:
    """ATT&CK v19 retired 'Defense Evasion'; TA0005 is now 'Stealth'.

    Guards against reverting to the pre-v19 name out of habit.
    """
    assert Tactic.STEALTH.tactic_id == "TA0005"
    assert Tactic.STEALTH.display_name == "Stealth"
    assert not any(t.display_name == "Defense Evasion" for t in Tactic)
    assert Tactic.DEFENSE_IMPAIRMENT.tactic_id == "TA0112"


def test_known_techniques_have_correct_names() -> None:
    """Spot-check verified names against attack.mitre.org."""
    expected = {
        "T1059.001": "PowerShell",
        "T1027.010": "Command Obfuscation",
        "T1003.001": "LSASS Memory",
        "T1110.001": "Password Guessing",
        "T1021.002": "SMB/Windows Admin Shares",
        "T1569.002": "Service Execution",
        "T1560.001": "Archive via Utility",
        "T1218.011": "Rundll32",
        "T1105": "Ingress Tool Transfer",
        "T1078": "Valid Accounts",
        "T1033": "System Owner/User Discovery",
        "T1069.002": "Domain Groups",
        "T1482": "Domain Trust Discovery",
    }
    for tid, name in expected.items():
        assert get_technique(tid).name == name


def test_discovery_techniques_have_no_sub_techniques_where_expected() -> None:
    """T1033 and T1482 have no sub-techniques in ATT&CK; T1069 does (.002 is one)."""
    assert not get_technique("T1033").is_sub_technique
    assert not get_technique("T1482").is_sub_technique
    assert get_technique("T1069.002").is_sub_technique
    assert get_technique("T1069.002").parent_id == "T1069"


def test_discovery_techniques_are_all_tactic_discovery() -> None:
    for tid in ("T1033", "T1069", "T1069.002", "T1482"):
        assert get_technique(tid).primary_tactic is Tactic.DISCOVERY


# ======================================================================================
# Invented IDs are structurally impossible
# ======================================================================================


def test_unknown_technique_id_raises() -> None:
    with pytest.raises(UnknownTechniqueError, match="not in the verified"):
        get_technique("T9999.999")


def test_attack_mapping_rejects_invented_technique() -> None:
    """The core guarantee: no code path can emit a made-up technique ID."""
    with pytest.raises(UnknownTechniqueError):
        AttackMapping(
            technique_id="T1337", rule_id="ATH-001",
            confidence=Confidence.HIGH, reason="r", evidence_ids=("evt-000001",),
        )


def test_attack_mapping_requires_evidence() -> None:
    with pytest.raises(ValueError, match="must cite telemetry evidence"):
        AttackMapping(
            technique_id="T1059.001", rule_id="ATH-002",
            confidence=Confidence.HIGH, reason="r", evidence_ids=(),
        )


def test_every_mapping_rule_references_a_real_rule_and_technique() -> None:
    from ath.hunting import registered_rule_ids

    known_rules = set(registered_rule_ids())
    for rule in MAPPING_RULES:
        assert rule.rule_id in known_rules, f"{rule.rule_id} is not a registered rule"
        get_technique(rule.technique_id)


# ======================================================================================
# Evidence gating -- the design's whole point
# ======================================================================================


def test_ingress_tool_transfer_requires_download_evidence() -> None:
    """T1105 must NOT be asserted for encoded PowerShell that downloads nothing."""
    downloader = _finding("ATH-002", download_indicators=["downloadstring", "iex"])
    inventory = _finding("ATH-002", download_indicators=[])

    assert "T1105" in unique_techniques(map_finding(downloader))
    assert "T1105" not in unique_techniques(map_finding(inventory))
    # Both still legitimately obfuscate a command.
    assert "T1027.010" in unique_techniques(map_finding(inventory))


def test_lateral_movement_technique_follows_logon_type() -> None:
    """Type 3 is SMB (T1021.002); type 10 is RDP (T1021.001). Not interchangeable."""
    smb = map_finding(_finding("ATH-006", logon_types=[3]))
    rdp = map_finding(_finding("ATH-006", logon_types=[10]))
    assert "T1021.002" in unique_techniques(smb)
    assert "T1021.001" not in unique_techniques(smb)
    assert "T1021.001" in unique_techniques(rdp)


def test_valid_accounts_only_when_bruteforce_succeeded() -> None:
    assert "T1078" in unique_techniques(map_finding(_finding("ATH-005", succeeded=True)))
    assert "T1078" not in unique_techniques(map_finding(_finding("ATH-005", succeeded=False)))


def test_rundll32_proxy_requires_rundll32_evidence() -> None:
    via_rundll = _finding(
        "ATH-004", indicators=["comsvcs.dll MiniDump"],
        command_line=r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 x full",
    )
    via_procdump = _finding(
        "ATH-004", indicators=["procdump against lsass"],
        command_line="procdump64.exe -ma lsass.exe out.dmp",
    )
    assert "T1218.011" in unique_techniques(map_finding(via_rundll))
    assert "T1218.011" not in unique_techniques(map_finding(via_procdump))
    assert "T1003.001" in unique_techniques(map_finding(via_procdump))


def test_unrelated_findings_get_no_mapping() -> None:
    """A rule with no mapping table entry must produce nothing, not a guess."""
    assert map_finding(_finding("ATH-999")) == []


def test_no_exfiltration_technique_is_ever_asserted(hunt) -> None:
    """We observe staging and, separately, egress -- never data actually leaving.

    Asserting Exfiltration would be inferring the conclusion we most want to be true.
    """
    all_mappings = [m for f in hunt.findings for m in map_finding(f)]
    exfil = [m for m in all_mappings if m.tactic is Tactic.EXFILTRATION]
    assert exfil == []


def test_no_phishing_technique_without_email_telemetry(hunt) -> None:
    """T1566 would require delivery evidence the dataset does not contain."""
    ids = {m.technique_id for f in hunt.findings for m in map_finding(f)}
    assert not any(t.startswith("T1566") for t in ids)


# ======================================================================================
# Behaviour on the real dataset
# ======================================================================================


def test_mappings_preserve_evidence_ids(hunt) -> None:
    for finding in hunt.findings:
        for mapping in map_finding(finding):
            assert mapping.evidence_ids == finding.event_ids
            assert mapping.rule_id == finding.rule_id


def test_attacker_and_admin_encoded_powershell_map_differently(hunt) -> None:
    """The headline demonstration: identical rule, different evidence, different ATT&CK."""
    attacker = [f for f in hunt.by_rule("ATH-002") if f.device == "PC01"][0]
    admin = [f for f in hunt.by_rule("ATH-002") if f.device == "PC07"][0]

    attacker_ids = set(unique_techniques(map_finding(attacker)))
    admin_ids = set(unique_techniques(map_finding(admin)))

    assert attacker_ids == {"T1059.001", "T1027.010", "T1105"}
    assert admin_ids == {"T1059.001", "T1027.010"}
    assert "T1105" in attacker_ids - admin_ids


def test_lsass_finding_maps_to_credential_access(hunt) -> None:
    finding = hunt.by_rule("ATH-004")[0]
    mappings = map_finding(finding)
    lsass = [m for m in mappings if m.technique_id == "T1003.001"][0]
    assert lsass.tactic is Tactic.CREDENTIAL_ACCESS
    assert lsass.confidence is Confidence.HIGH
    assert lsass.sub_technique_of == "T1003"
    assert lsass.display == "T1003.001 OS Credential Dumping: LSASS Memory"


def test_discovery_finding_maps_to_all_three_matched_techniques(hunt) -> None:
    """ATH-010's finding matched whoami/net/nltest, so all three Discovery techniques
    should be mapped -- each gated on its own binary having actually been matched."""
    finding = hunt.by_rule("ATH-010")[0]
    ids = set(unique_techniques(map_finding(finding)))
    assert ids == {"T1033", "T1069.002", "T1482"}
    for mapping in map_finding(finding):
        assert mapping.tactic is Tactic.DISCOVERY


def test_discovery_mapping_gate_excludes_unmatched_techniques() -> None:
    """A finding that only matched whoami.exe must not get net/nltest's mappings."""
    import pandas as pd

    from ath.hunting.finding import Evidence, Finding, Severity

    only_whoami = Finding(
        rule_id="ATH-010", title="t", severity=Severity.MEDIUM,
        device="PC01", user="jdoe",
        evidence=(Evidence("evt-000001", pd.Timestamp("2026-01-01", tz="UTC"), "s"),),
        reason="r", metadata={"candidate_techniques": ["T1033"]},
    )
    ids = set(unique_techniques(map_finding(only_whoami)))
    assert ids == {"T1033"}


def test_tactics_covered_is_in_kill_chain_order(hunt) -> None:
    mappings = [m for f in hunt.findings for m in map_finding(f)]
    tactics = tactics_covered(mappings)
    assert "Execution" in tactics and "Credential Access" in tactics
    assert tactics.index("Execution") < tactics.index("Credential Access")
    assert tactics.index("Credential Access") < tactics.index("Lateral Movement")


def test_map_findings_keys_by_finding_id(hunt) -> None:
    mapped = map_findings(hunt.findings)
    assert set(mapped) == {f.finding_id for f in hunt.findings}


def test_mapping_serialises_to_json(hunt) -> None:
    import json

    for finding in hunt.findings:
        for mapping in map_finding(finding):
            payload = json.loads(json.dumps(mapping.to_dict()))
            assert payload["technique_id"] and payload["tactic"]
            assert payload["url"].startswith("https://attack.mitre.org/")


def test_mitre_layer_never_reads_ground_truth() -> None:
    import ast

    for path in (Path(__file__).resolve().parents[1] / "src" / "ath" / "mitre").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {
            n.id for n in ast.walk(tree) if isinstance(n, ast.Name)
        } | {
            n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
        }
        assert not any("ground_truth" in n.lower() for n in names)
