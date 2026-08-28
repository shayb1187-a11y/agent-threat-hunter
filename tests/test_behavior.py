"""Tests for the deterministic behavior and feature layer.

Three claims this layer makes, each tested directly because each is easy to erode:

1. A behavior describes what happened and carries no judgement.
2. The dependency direction is one-way -- behavior is an *input* to detection, triage
   and the agent, never a product of them.
3. The timing computation exists exactly once in the codebase.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ath.behavior import (
    MIN_INTERVALS_FOR_REGULARITY,
    RECOVERY_PROCEDURES,
    SCRIPT_INTERPRETERS,
    Behavior,
    BehaviorError,
    ConnectionPattern,
    compute_connection_pattern,
    connection_patterns,
    extract_behaviors,
    extract_recovery_behaviors,
    extract_security_tool_behaviors,
)
from ath.behavior.models import (
    INTERPRETER_EXTERNAL_CONTACT,
    PERIODIC_OUTBOUND_RELATIONSHIP,
    RECOVERY_MECHANISM_DISABLED,
)
from ath.channels import TelemetryChannel
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import load_telemetry

SRC = Path(__file__).resolve().parents[1] / "src" / "ath"
NOW = datetime(2026, 8, 17, 9, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def telemetry(tmp_path_factory):
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("behavior_data")
    write_telemetry(tables, gt, out)
    return load_telemetry(out)


@pytest.fixture(scope="module")
def behaviors(telemetry):
    return extract_behaviors(telemetry)


def _times(*offsets_seconds: float) -> list[datetime]:
    return [NOW + timedelta(seconds=offset) for offset in offsets_seconds]


# ======================================================================================
# A behavior is a description, not a judgement
# ======================================================================================


def test_behavior_carries_no_severity_or_suspicion() -> None:
    """The load-bearing separation, asserted structurally rather than by convention.

    `remote_interactive_logon` is usually an administrator doing their job. A layer
    that only emitted alarming things would be a rule engine with a new name -- and
    could never support benign explanation, which is half of what hypothesis reasoning
    needs.
    """
    forbidden = {
        "severity", "is_suspicious", "suspicious", "risk", "score", "confidence",
        "malicious", "disposition",
    }
    fields = set(Behavior.__dataclass_fields__)
    assert not (fields & forbidden), f"Behavior gained a judgement field: {fields & forbidden}"
    assert not any(hasattr(Behavior, name) for name in forbidden)


def test_behavior_requires_real_evidence() -> None:
    """No code path to an unevidenced behavior, exactly as with Finding."""
    with pytest.raises(BehaviorError, match="must cite at least one event"):
        Behavior(
            behavior_id="b", behavior_type=RECOVERY_MECHANISM_DISABLED,
            start_time=NOW, end_time=NOW, evidence_ids=(),
        )


def test_behavior_rejects_an_unknown_type() -> None:
    with pytest.raises(BehaviorError, match="Unknown behavior_type"):
        Behavior(
            behavior_id="b", behavior_type="something_invented",
            start_time=NOW, end_time=NOW, evidence_ids=("evt-1",),
        )


def test_behavior_rejects_an_inverted_window() -> None:
    with pytest.raises(BehaviorError, match="precedes start_time"):
        Behavior(
            behavior_id="b", behavior_type=RECOVERY_MECHANISM_DISABLED,
            start_time=NOW, end_time=NOW - timedelta(seconds=1), evidence_ids=("evt-1",),
        )


# ======================================================================================
# Dependency direction
# ======================================================================================


def test_behavior_is_importable_and_computable_without_upper_layers() -> None:
    """Behaviors are an input to detection, triage and the agent, never a product.

    Run in a *subprocess* so it cannot pass by accident on modules another test already
    imported. Checks after computation, not merely after import -- a lazy import inside
    an extractor would satisfy the weaker check while breaking the rule.
    """
    program = """
import sys
from ath.behavior import extract_behaviors
from ath.telemetry import GeneratorConfig, generate_telemetry
from ath.telemetry.loader import Telemetry
from ath.telemetry.normalize import coerce_and_validate

tables, _ = generate_telemetry(GeneratorConfig())
telemetry = Telemetry(
    processes=coerce_and_validate(tables["process"], "process"),
    network=coerce_and_validate(tables["network"], "network"),
    logons=coerce_and_validate(tables["logon"], "logon"),
)
extract_behaviors(telemetry)

leaked = [m for m in ("ath.hunting", "ath.triage", "ath.agent", "ath.correlation")
          if m in sys.modules]
print(",".join(leaked))
"""
    result = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True, text=True,
        cwd=str(SRC.parents[1]),
        env={**__import__("os").environ, "PYTHONPATH": str(SRC.parent)},
    )
    assert result.returncode == 0, result.stderr
    leaked = [name for name in result.stdout.strip().split(",") if name]
    assert not leaked, f"ath.behavior pulled in upper layers: {leaked}"


def test_behavior_modules_never_import_upper_layers() -> None:
    """Static counterpart to the runtime check, so a new lazy import is caught too."""
    forbidden = ("ath.hunting", "ath.triage", "ath.agent", "ath.correlation",
                 "ath.environment", "ath.reporting", "ath.evaluation")
    offences: list[str] = []
    for path in (SRC / "behavior").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if any(node.module.startswith(bad) for bad in forbidden):
                    offences.append(f"{path.name}: {node.module}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if any(alias.name.startswith(bad) for bad in forbidden):
                        offences.append(f"{path.name}: {alias.name}")
    assert not offences, f"behavior imports upper layers: {offences}"


def test_interpreter_list_agrees_with_the_hunting_layer() -> None:
    """The one deliberate duplication, guarded so it cannot silently drift."""
    from ath.hunting.base import SCRIPT_INTERPRETERS as HUNTING_INTERPRETERS

    assert SCRIPT_INTERPRETERS == HUNTING_INTERPRETERS


# ======================================================================================
# ConnectionPattern: statistical honesty
# ======================================================================================


def test_pattern_sees_through_a_leading_outlier() -> None:
    """One payload fetch then a steady heartbeat: the shape median/MAD exists for.

    Mean-based CV scores this irregular; the robust statistic reports it correctly.
    """
    pattern = compute_connection_pattern(
        "powershell.exe", "185.220.101.47", _times(0, 27, 327, 627, 927, 1227, 1527),
    )
    assert pattern.median_interval == timedelta(seconds=300)
    assert pattern.robust_cv == pytest.approx(0.0)
    assert pattern.is_regular


def test_robust_cv_is_none_when_support_is_too_thin() -> None:
    """Two connections give one interval, which is regular by definition and meaningless.

    `None` rather than `0.0`: a zero would read as "perfectly regular" to every
    consumer, which is precisely the false reassurance this layer exists to prevent.
    """
    pattern = compute_connection_pattern("powershell.exe", "1.2.3.4", _times(0, 300))
    assert pattern.interarrival_count == 1
    assert pattern.robust_cv is None
    assert pattern.median_interval is None
    assert not pattern.has_measurable_regularity
    assert not pattern.is_regular


def test_robust_cv_is_none_rather_than_infinite_on_a_zero_median() -> None:
    """The old implementation returned inf, which compares above every threshold.

    That silently reads as "irregular" when the honest answer is "not measurable".
    """
    pattern = compute_connection_pattern("cmd.exe", "1.2.3.4", _times(0, 0, 0, 0))
    assert pattern.robust_cv is None
    assert not pattern.is_regular


def test_pattern_exposes_how_thin_its_support_is() -> None:
    """Four connections give three intervals, and consumers must be able to see that."""
    pattern = compute_connection_pattern(
        "powershell.exe", "1.2.3.4", _times(0, 600, 1200, 1800),
    )
    assert pattern.connection_count == 4
    assert pattern.interarrival_count == 3
    assert "3 intervals" in pattern.support_note


def test_single_connection_states_it_has_no_interval() -> None:
    pattern = compute_connection_pattern("chrome.exe", "1.2.3.4", _times(0))
    assert pattern.interarrival_count == 0
    assert "no interval" in pattern.support_note


def test_pattern_has_no_beacon_verdict() -> None:
    """Whether a pattern warrants suspicion is a judgement, and belongs to consumers."""
    assert "is_beacon" not in ConnectionPattern.__dataclass_fields__
    assert not hasattr(ConnectionPattern, "is_beacon")


def test_pattern_refuses_to_measure_nothing() -> None:
    """Returning a zero-valued pattern would be a fabricated observation."""
    with pytest.raises(ValueError, match="no timestamps"):
        compute_connection_pattern("cmd.exe", "1.2.3.4", [])


def test_timing_statistics_are_computed_in_exactly_one_place() -> None:
    """The whole reason this package exists.

    The median/MAD computation previously lived in `analyse_beacon`, inside the
    investigation layer, where triage could not reach it. If a second implementation
    appears, the layers can disagree again.
    """
    implementations = [
        path.relative_to(SRC).as_posix()
        for path in SRC.rglob("*.py")
        if "statistics.median" in path.read_text(encoding="utf-8")
    ]
    assert implementations == ["behavior/features.py"], (
        f"median/MAD computed in more than one place: {implementations}"
    )


# ======================================================================================
# Extraction
# ======================================================================================


def test_behaviors_are_extracted_from_the_synthetic_dataset(behaviors) -> None:
    assert behaviors
    assert all(b.evidence_ids for b in behaviors)


def test_extraction_is_deterministic(telemetry) -> None:
    first = [b.to_dict() for b in extract_behaviors(telemetry)]
    second = [b.to_dict() for b in extract_behaviors(telemetry)]
    assert first == second


def test_interpreter_contact_is_recognised(behaviors) -> None:
    interpreter = [
        b for b in behaviors if b.behavior_type == INTERPRETER_EXTERNAL_CONTACT
    ]
    assert interpreter
    assert any(b.entity("destination") == "185.220.101.47" for b in interpreter)


def test_every_outbound_relationship_carries_a_pattern(behaviors) -> None:
    """Attached even when irregular: a consumer must tell "irregular" from "not measured"."""
    relationships = [
        b for b in behaviors if b.behavior_type == PERIODIC_OUTBOUND_RELATIONSHIP
    ]
    assert relationships
    for behavior in relationships:
        assert isinstance(behavior.observations["connection_pattern"], ConnectionPattern)


def test_connection_patterns_index_is_keyed_by_host_and_destination(behaviors) -> None:
    index = connection_patterns(behaviors)
    assert ("PC01", "185.220.101.47") in index
    assert index[("PC01", "185.220.101.47")].is_regular


def test_behaviors_serialise(behaviors) -> None:
    import json

    payload = json.loads(json.dumps([b.to_dict() for b in behaviors]))
    assert len(payload) == len(behaviors)


# ======================================================================================
# Argument semantics, not binary names
# ======================================================================================


def _process_telemetry(telemetry, command_line: str, process_name: str = "vssadmin.exe"):
    """One synthetic process row carrying the given command line."""
    import pandas as pd

    from ath.telemetry.loader import Telemetry

    row = telemetry.processes.iloc[0].copy()
    row["event_id"] = "evt-SYNTH"
    row["process_name"] = process_name
    row["command_line"] = command_line
    return Telemetry(
        processes=pd.DataFrame([row]), network=telemetry.network, logons=telemetry.logons,
    )


def test_destructive_recovery_command_is_extracted(telemetry) -> None:
    behaviors = extract_recovery_behaviors(
        _process_telemetry(telemetry, "vssadmin.exe delete shadows /all /quiet")
    )
    assert len(behaviors) == 1
    assert behaviors[0].observations["is_destructive"] is True


def test_recovery_enumeration_is_extracted_but_not_destructive(telemetry) -> None:
    """`vssadmin list shadows` is a backup administrator checking their backups.

    Emitted, because the behavior layer describes what happened -- but flagged
    non-destructive, so no consumer can treat the binary name as the signal.
    """
    behaviors = extract_recovery_behaviors(
        _process_telemetry(telemetry, "vssadmin.exe list shadows")
    )
    assert len(behaviors) == 1
    assert behaviors[0].observations["is_destructive"] is False
    assert behaviors[0].observations["enumeration_procedures"] == [
        "shadow_copy_enumeration"
    ]


def test_renamed_binary_still_matches_on_argument_semantics(telemetry) -> None:
    """`process_name == "vssadmin.exe"` is not a rule.

    An attacker who renames the binary keeps the destructive arguments, because the
    arguments are what the operating system acts on.
    """
    behaviors = extract_recovery_behaviors(_process_telemetry(
        telemetry, "svc-helper.exe delete shadows /all /quiet",
        process_name="svc-helper.exe",
    ))
    assert len(behaviors) == 1
    assert behaviors[0].observations["is_destructive"] is True


def test_security_tool_tampering_is_extracted(telemetry) -> None:
    behaviors = extract_security_tool_behaviors(_process_telemetry(
        telemetry, "taskkill.exe /F /IM MsMpEng.exe", process_name="taskkill.exe",
    ))
    assert len(behaviors) == 1
    assert "security_process_killed" in behaviors[0].observations["procedures"]


def test_defender_exclusion_is_extracted(telemetry) -> None:
    behaviors = extract_security_tool_behaviors(_process_telemetry(
        telemetry,
        "powershell.exe Add-MpPreference -ExclusionPath C:\\Users\\Public",
        process_name="powershell.exe",
    ))
    assert len(behaviors) == 1
    assert "defender_exclusion_added" in behaviors[0].observations["procedures"]


def test_ordinary_commands_produce_no_recovery_behavior(telemetry) -> None:
    """The guard against a pattern so loose it matches everyday activity."""
    for command in (
        "notepad.exe C:\\Users\\jdoe\\notes.txt",
        "powershell.exe Get-ChildItem C:\\Backups",
        "cmd.exe /c del C:\\temp\\old.log",
    ):
        assert not extract_recovery_behaviors(_process_telemetry(telemetry, command))
        assert not extract_security_tool_behaviors(_process_telemetry(telemetry, command))


# ======================================================================================
# Cloud telemetry
# ======================================================================================


def test_cloud_telemetry_yields_no_network_behaviors_without_erroring() -> None:
    """CloudTrail carries no process or network events; that must be a quiet zero."""
    from ath.telemetry.cloudtrail_source import CloudTrailSource
    from ath.telemetry.loader import Telemetry

    fixture = Path(__file__).parent / "fixtures" / "cloudtrail"
    result = CloudTrailSource(fixture).load()
    behaviors = extract_behaviors(Telemetry(
        processes=result.tables["process"],
        network=result.tables["network"],
        logons=result.tables["logon"],
    ))
    assert behaviors == []
