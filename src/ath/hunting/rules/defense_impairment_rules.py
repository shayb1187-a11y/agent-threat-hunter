"""Detections targeting the Defense Impairment tactic (TA0112, new in ATT&CK v19).

The tactic exists because "hiding within legitimate activity" and "attacking the
defences directly" are different adversary goals that were previously both filed under
Defense Evasion. ATH-012 addresses the second.
"""

from __future__ import annotations

from ath.behavior import extract_security_tool_behaviors
from ath.hunting.base import Detector, register
from ath.hunting.finding import Evidence, Finding, Severity
from ath.hunting.indicators import truncate
from ath.telemetry.loader import Telemetry


@register
class SecurityToolTampering(Detector):
    """ATH-012 -- A security product was disabled, stopped or reconfigured.

    Attacker behaviour
    ------------------
    Turning off real-time protection, adding a staging directory to the exclusion list,
    killing the AV process, or stopping the sensor service. All four buy the same
    thing: the next action will not be seen.

    Why the target is the signal, not the tool
    -------------------------------------------
    ``taskkill.exe`` is an ordinary administrative utility, and keying on it would
    alert on routine work while missing the same action taken through any other means.
    What is distinctive is *what was acted upon* -- a security product's process name,
    service name, or preference -- so that is what the patterns match. A renamed
    ``taskkill`` still fires.

    Why this rule is severity-capped below CRITICAL on its own
    -----------------------------------------------------------
    A single security-tool change is genuinely ambiguous: administrators disable
    real-time protection to install software, and exclusions are added for legitimate
    line-of-business applications every day. Several distinct controls modified in one
    window is a different claim, and only that earns CRITICAL.

    What this rule cannot see, and where that is handled
    ------------------------------------------------------
    Registry-based tampering and ETW patching leave no command line, so this rule is
    blind to them -- the visibility layer reports that honestly rather than letting
    command-line coverage stand in for the technique. The complementary signal is the
    *disappearance of expected telemetry*, which is a separate behavior
    (``telemetry_health_change``) rather than something this rule can observe.
    """

    rule_id = "ATH-012"
    title = "Security product disabled or reconfigured"
    severity = Severity.HIGH
    description = (
        "A security product's protection was disabled, its process killed, its service "
        "stopped, or a scanning exclusion added. Keys on the security product being "
        "acted upon rather than on the utility used."
    )
    fields_used = ("command_line", "process_name", "device", "user", "timestamp")
    false_positives = (
        "An administrator disabling real-time protection to install or troubleshoot "
        "software -- common, and the single largest source of noise for this rule.",
        "Exclusions added for legitimate line-of-business applications with known "
        "scanner conflicts.",
        "Endpoint agent upgrades that stop the service as part of a normal upgrade.",
        "Security products restarting their own components during definition updates.",
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        behaviors = extract_security_tool_behaviors(telemetry)
        if not behaviors:
            return []

        by_target: dict[tuple[str, str], list] = {}
        for behavior in behaviors:
            key = (behavior.entity("host"), behavior.entity("user"))
            by_target.setdefault(key, []).append(behavior)

        findings: list[Finding] = []
        for (device, user), group in by_target.items():
            procedures = sorted({
                procedure
                for behavior in group
                for procedure in behavior.observations.get("procedures", [])
            })
            descriptions = sorted({
                description
                for behavior in group
                for description in behavior.observations.get("descriptions", [])
            })
            evidence = tuple(
                Evidence(
                    event_id=event_id,
                    timestamp=behavior.start_time,
                    summary=truncate(behavior.observations.get("command_line", ""), 140),
                )
                for behavior in group
                for event_id in behavior.evidence_ids
            )

            severity = Severity.CRITICAL if len(procedures) >= 3 else Severity.HIGH
            findings.append(self.make_finding(
                device=device, user=user, evidence=evidence, severity=severity,
                reason=(
                    f"{len(procedures)} distinct security-control change(s) on {device} "
                    f"by '{user}': {'; '.join(descriptions)}. A single change is often "
                    "administrative; several in one window is the shape of an attacker "
                    "clearing the way for what comes next."
                ),
                metadata={
                    "procedures": procedures,
                    "distinct_controls_affected": len(procedures),
                    "descriptions": descriptions,
                    "process_name": group[0].entity("process"),
                    "behavior_ids": [b.behavior_id for b in group],
                },
            ))
        return findings
