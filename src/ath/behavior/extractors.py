"""Deterministic behavior extraction from canonical telemetry.

Every extractor here is label-blind, side-effect free, and reproducible: the same
telemetry produces the same behaviors, every time. No extractor may consult ground
truth, and none may reach into the hunting, triage or agent layers -- behaviors are an
input to those, not a product of them.

What these deliberately do *not* do
------------------------------------
They do not decide whether anything is suspicious. ``recovery_mechanism_disabled`` fires
on a genuine restore operation exactly as it fires on ransomware preparation, because
from telemetry alone those are the same observation. The difference is context, and
context belongs to the layers above.

Extractors also fire on **benign** activity by design. An extractor that only emitted
alarming things would leave the hypothesis layer unable to construct an innocent
explanation, which is half of what it is for.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

import pandas as pd

from ath.behavior.features import (
    RELATION_UNKNOWN,
    ConnectionPattern,
    compute_connection_pattern,
)
from ath.behavior.models import (
    INTERPRETER_EXTERNAL_CONTACT,
    PERIODIC_OUTBOUND_RELATIONSHIP,
    RECOVERY_MECHANISM_DISABLED,
    SECURITY_TOOL_CONFIGURATION_MODIFIED,
    Behavior,
    make_behavior_id,
)
from ath.channels import TelemetryChannel
from ath.logging_setup import get_logger
from ath.netaddr import is_public_ip
from ath.telemetry.loader import Telemetry

logger = get_logger(__name__)

# Interpreters and LOLBins capable of executing attacker-supplied code. Duplicated
# intentionally rather than imported from ath.hunting: importing it would invert the
# dependency direction this package exists to establish. A test asserts the two lists
# stay in agreement, so the duplication cannot silently drift.
SCRIPT_INTERPRETERS: frozenset[str] = frozenset({
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "bitsadmin.exe",
    "certutil.exe", "msbuild.exe", "installutil.exe",
})

# Recovery-inhibition procedures, keyed on *destructive argument semantics* and nothing
# else. `vssadmin.exe` is not a signal -- deleting shadow copies is.
#
# No pattern here requires a binary name, because the name is the one part an attacker
# controls for free. `svc-helper.exe delete shadows /all` does the same damage as
# `vssadmin.exe delete shadows /all`: the arguments are what the operating system acts
# on, so the arguments are what these match. `vssadmin list shadows` deliberately does
# not match, despite naming the same tool.
#
# `reagentc /disable` is the one honest exception. `/disable` alone appears in far too
# many unrelated command lines to key on, so that pattern names the tool -- and is
# therefore evadable by rename. Stated here rather than hidden, because a reader
# deserves to know which of these an attacker can sidestep.
RECOVERY_PROCEDURES: tuple[tuple[str, str, str], ...] = (
    ("shadow_copy_deletion", r"\bdelete\b[^|;&]{0,40}?\bshadows?\b",
     "volume shadow copies deleted"),
    ("shadow_copy_deletion_wmi", r"\bshadowcopy\b[^|;&]{0,40}?\bdelete\b",
     "volume shadow copies deleted via WMI"),
    ("backup_catalog_deletion", r"\bdelete\b[^|;&]{0,40}?\bcatalog\b",
     "Windows backup catalog deleted"),
    ("backup_deletion", r"\bdelete\b[^|;&]{0,40}?\bsystemstatebackup\b",
     "Windows system state backups deleted"),
    ("recovery_environment_disabled", r"\breagentc(\.exe)?\b[^|;&]{0,40}?/disable\b",
     "Windows Recovery Environment disabled"),
    ("boot_recovery_disabled", r"\brecoveryenabled\b\s+no\b",
     "boot-time recovery disabled"),
    ("boot_failure_policy_ignored", r"\bbootstatuspolicy\b\s+ignoreallfailures\b",
     "boot failure policy set to ignore all failures"),
)

# Recovery *enumeration*: read-only inspection of the same subsystems. Extracted so a
# consumer can tell "looked at the backups" from "destroyed the backups", instead of
# treating the tool as the signal in either direction.
RECOVERY_ENUMERATION: tuple[tuple[str, str], ...] = (
    ("shadow_copy_enumeration", r"\blist\b[^|;&]{0,40}?\bshadows?\b"),
    ("backup_enumeration", r"\bwbadmin(\.exe)?\b[^|;&]{0,40}?\bget\b[^|;&]{0,40}?\b(versions|status)\b"),
)

# Security-tool tampering, on the same principle. The *target* of the action is the
# discriminating part -- a security product's process name, service name or preference
# -- rather than the utility used to reach it, so a renamed taskkill still matches.
SECURITY_TOOL_PROCEDURES: tuple[tuple[str, str, str], ...] = (
    ("security_process_killed",
     r"/im\s+\"?(msmpeng|mssense|senseir|csfalconservice|xagt|sentinelagent|"
     r"carbonblack|wazuh-agent)\w*\.exe",
     "a security product process was terminated"),
    ("security_service_stopped",
     r"\bstop\b\s+\"?(windefend|sense|wdnissvc|mpssvc|csagent|sentinelagent|wazuh)\b",
     "a security service was stopped"),
    ("defender_realtime_disabled",
     r"-disablerealtimemonitoring\s+\$?true",
     "Defender real-time monitoring disabled"),
    ("defender_exclusion_added",
     r"-exclusion(path|extension|process)\b",
     "a Defender scanning exclusion was added"),
    ("security_service_disabled_registry",
     r"\\(windefend|sense|sentinelagent)\b[^|;&]{0,60}?\bstart\b[^|;&]{0,20}?\b4\b",
     "a security service was disabled via the registry"),
    ("firewall_disabled",
     r"\bfirewall\b[^|;&]{0,60}?\bstate\s+off\b",
     "the host firewall was turned off"),
)


def _rows(frame: pd.DataFrame) -> Iterable[dict[str, Any]]:
    return frame.to_dict("records") if not frame.empty else ()


def _matched_procedures(
    command_line: str, table: tuple[tuple[str, str, str], ...]
) -> list[tuple[str, str]]:
    """Return ``(procedure_name, description)`` for every pattern the command matches."""
    lowered = (command_line or "").lower()
    return [
        (name, description)
        for name, pattern, description in table
        if re.search(pattern, lowered, re.IGNORECASE)
    ]


def extract_recovery_behaviors(telemetry: Telemetry) -> list[Behavior]:
    """Recovery mechanisms being disabled, or merely enumerated.

    Both are emitted. Enumeration is overwhelmingly a backup administrator checking
    their backups, and the behavior layer says what happened rather than what it means.
    """
    behaviors: list[Behavior] = []
    for row in _rows(telemetry.processes):
        command_line = str(row.get("command_line") or "")
        destructive = _matched_procedures(command_line, RECOVERY_PROCEDURES)
        enumeration = [
            name for name, pattern in RECOVERY_ENUMERATION
            if re.search(pattern, command_line.lower(), re.IGNORECASE)
        ]
        if not destructive and not enumeration:
            continue

        evidence = (str(row["event_id"]),)
        behaviors.append(Behavior(
            behavior_id=make_behavior_id(RECOVERY_MECHANISM_DISABLED, evidence),
            behavior_type=RECOVERY_MECHANISM_DISABLED,
            start_time=row["timestamp"],
            end_time=row["timestamp"],
            entities={
                "host": str(row.get("device") or ""),
                "user": str(row.get("user") or ""),
                "process": str(row.get("process_name") or ""),
            },
            evidence_ids=evidence,
            fields_used=("command_line", "process_name", "device", "user", "timestamp"),
            required_channels=frozenset({TelemetryChannel.PROCESS_COMMAND_LINE}),
            observations={
                "destructive_procedures": [name for name, _ in destructive],
                "descriptions": [text for _, text in destructive],
                "enumeration_procedures": enumeration,
                "is_destructive": bool(destructive),
                "distinct_controls_affected": len({name for name, _ in destructive}),
                "command_line": command_line[:400],
            },
        ))
    return behaviors


def extract_security_tool_behaviors(telemetry: Telemetry) -> list[Behavior]:
    """Security tooling being disabled, stopped, excluded from, or reconfigured."""
    behaviors: list[Behavior] = []
    for row in _rows(telemetry.processes):
        command_line = str(row.get("command_line") or "")
        matched = _matched_procedures(command_line, SECURITY_TOOL_PROCEDURES)
        if not matched:
            continue

        evidence = (str(row["event_id"]),)
        behaviors.append(Behavior(
            behavior_id=make_behavior_id(SECURITY_TOOL_CONFIGURATION_MODIFIED, evidence),
            behavior_type=SECURITY_TOOL_CONFIGURATION_MODIFIED,
            start_time=row["timestamp"],
            end_time=row["timestamp"],
            entities={
                "host": str(row.get("device") or ""),
                "user": str(row.get("user") or ""),
                "process": str(row.get("process_name") or ""),
            },
            evidence_ids=evidence,
            fields_used=("command_line", "process_name", "device", "user", "timestamp"),
            required_channels=frozenset({TelemetryChannel.PROCESS_COMMAND_LINE}),
            observations={
                "procedures": [name for name, _ in matched],
                "descriptions": [text for _, text in matched],
                "distinct_controls_affected": len({name for name, _ in matched}),
                "command_line": command_line[:400],
            },
        ))
    return behaviors


def extract_outbound_relationship_behaviors(telemetry: Telemetry) -> list[Behavior]:
    """One behavior per (host, process, destination) relationship observed.

    Emits ``interpreter_external_contact`` when the process is a script interpreter, and
    ``periodic_outbound_relationship`` carrying a :class:`ConnectionPattern` whenever the
    timing is measurable at all. The pattern is attached regardless of whether it looks
    regular -- a consumer needs to distinguish "irregular" from "not measured", and only
    attaching it when it looked interesting would destroy that distinction.
    """
    network = telemetry.network
    if network.empty:
        return []

    external = network[network["remote_ip"].map(is_public_ip)]
    if external.empty:
        return []

    behaviors: list[Behavior] = []
    grouped = external.groupby(["device", "process_name", "remote_ip"], dropna=False)
    for (device, process_name, remote_ip), group in grouped:
        ordered = group.sort_values("timestamp")
        evidence = tuple(str(e) for e in ordered["event_id"])
        timestamps = list(ordered["timestamp"])
        entities = {
            "host": str(device or ""),
            "user": str(ordered.iloc[0].get("user") or ""),
            "process": str(process_name or ""),
            "destination": str(remote_ip or ""),
        }
        pattern = compute_connection_pattern(
            source_process=str(process_name or ""),
            destination=str(remote_ip or ""),
            timestamps=timestamps,
            evidence_ids=evidence,
            baseline_relation_status=RELATION_UNKNOWN,
        )

        if str(process_name or "").lower() in SCRIPT_INTERPRETERS:
            behaviors.append(Behavior(
                behavior_id=make_behavior_id(INTERPRETER_EXTERNAL_CONTACT, evidence),
                behavior_type=INTERPRETER_EXTERNAL_CONTACT,
                start_time=timestamps[0],
                end_time=timestamps[-1],
                entities=entities,
                evidence_ids=evidence,
                fields_used=(
                    "process_name", "remote_ip", "remote_port", "device", "user",
                    "timestamp",
                ),
                required_channels=frozenset({
                    TelemetryChannel.NETWORK_FLOW, TelemetryChannel.PROCESS_EXECUTION,
                }),
                observations={
                    "connection_count": pattern.connection_count,
                    "ports": sorted({int(p) for p in ordered["remote_port"] if pd.notna(p)}),
                    "connection_pattern": pattern,
                },
            ))

        behaviors.append(Behavior(
            behavior_id=make_behavior_id(PERIODIC_OUTBOUND_RELATIONSHIP, evidence),
            behavior_type=PERIODIC_OUTBOUND_RELATIONSHIP,
            start_time=timestamps[0],
            end_time=timestamps[-1],
            entities=entities,
            evidence_ids=evidence,
            fields_used=("process_name", "remote_ip", "device", "user", "timestamp"),
            required_channels=frozenset({TelemetryChannel.NETWORK_FLOW}),
            observations={"connection_pattern": pattern},
        ))
    return behaviors


def extract_behaviors(telemetry: Telemetry) -> list[Behavior]:
    """Run every extractor over one telemetry set.

    Ordered by start time so downstream consumers see a coherent sequence rather than
    an artefact of extractor registration order.
    """
    behaviors: list[Behavior] = []
    for extractor in (
        extract_outbound_relationship_behaviors,
        extract_recovery_behaviors,
        extract_security_tool_behaviors,
    ):
        behaviors.extend(extractor(telemetry))

    logger.info("extracted %d behavior(s)", len(behaviors))
    return sorted(behaviors, key=lambda b: (b.start_time, b.behavior_type))


def connection_patterns(behaviors: Iterable[Behavior]) -> dict[tuple[str, str], ConnectionPattern]:
    """Index every measured relationship by ``(host, destination)``.

    The lookup triage uses. Built from behaviors rather than recomputed, so there is
    still exactly one place the statistics are produced.
    """
    index: dict[tuple[str, str], ConnectionPattern] = {}
    for behavior in behaviors:
        pattern = behavior.observations.get("connection_pattern")
        if isinstance(pattern, ConnectionPattern):
            index[(behavior.entity("host"), pattern.destination)] = pattern
    return index
