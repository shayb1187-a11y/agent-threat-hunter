"""Detections targeting the Impact stage of an intrusion.

Built on behaviors, not on raw events
--------------------------------------
ATH-011 reads :func:`ath.behavior.extract_recovery_behaviors` rather than scanning
command lines itself. The behavior layer decides *what was observed*; this rule decides
*whether it is worth an analyst's attention*. Keeping those apart is what lets the same
observation feed benign explanation later, and it is why the behavior carries no
severity of its own.
"""

from __future__ import annotations

from ath.behavior import extract_recovery_behaviors
from ath.hunting.base import Detector, register
from ath.hunting.finding import Evidence, Finding, Severity
from ath.hunting.indicators import truncate
from ath.schema import EVENT_PROCESS
from ath.telemetry.loader import Telemetry


@register
class RecoveryInhibition(Detector):
    """ATH-011 -- Windows recovery mechanisms were destroyed or disabled.

    Attacker behaviour
    ------------------
    Deleting shadow copies, backup catalogues and boot-time recovery is the step that
    turns an intrusion into an extortion event: it removes the victim's ability to
    roll back, and it almost always happens minutes before encryption starts. It is
    also one of the few pre-encryption actions with essentially no legitimate
    equivalent at scale.

    Why the binary name is not the signal
    -------------------------------------
    ``process_name == "vssadmin.exe"`` is not a rule. The image name is the one part an
    attacker controls for free -- a renamed copy does identical damage -- while the
    arguments are what the operating system actually acts on. Detection therefore keys
    on destructive argument semantics, and a renamed binary still fires.

    The same choice makes the rule quiet where it should be. ``vssadmin list shadows``
    names the same tool and is a backup administrator checking their backups; it
    produces a behavior but no finding.

    Severity ladder
    ---------------
    Graded by how much recovery capability was actually removed, not by how many
    patterns matched:

    ==================================== ==========
    Observation                          Severity
    ==================================== ==========
    enumeration only                     no finding
    one recovery control destroyed       HIGH
    two or more distinct controls        CRITICAL
    ==================================== ==========

    Two independent controls destroyed within one window is the shape of a deliberate
    sequence rather than a single administrative action, which is the only thing here
    that justifies CRITICAL.
    """

    rule_id = "ATH-011"
    title = "Windows recovery mechanisms destroyed"
    severity = Severity.HIGH
    description = (
        "Shadow copies, backup catalogues or boot-time recovery were deleted or "
        "disabled. Keys on destructive argument semantics, so a renamed binary still "
        "matches and read-only enumeration does not."
    )
    fields_used = ("command_line", "process_name", "device", "user", "timestamp")
    tables = frozenset({EVENT_PROCESS})
    false_positives = (
        "Backup software legitimately rotating or pruning old shadow copies.",
        "An administrator clearing space on a volume that has run out of shadow storage.",
        "Disk imaging or migration tooling that resets boot configuration.",
        "Note that read-only enumeration (`vssadmin list shadows`) is deliberately "
        "excluded and never produces a finding.",
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        behaviors = [
            behavior for behavior in extract_recovery_behaviors(telemetry)
            if behavior.observations.get("is_destructive")
        ]
        if not behaviors:
            return []

        findings: list[Finding] = []
        # Group by (host, user) so a sequence of distinct controls on one host reads as
        # one incident rather than three separate alerts -- alert volume is a real cost.
        by_target: dict[tuple[str, str], list] = {}
        for behavior in behaviors:
            key = (behavior.entity("host"), behavior.entity("user"))
            by_target.setdefault(key, []).append(behavior)

        for (device, user), group in by_target.items():
            procedures = sorted({
                procedure
                for behavior in group
                for procedure in behavior.observations.get("destructive_procedures", [])
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

            severity = Severity.CRITICAL if len(procedures) >= 2 else Severity.HIGH
            findings.append(self.make_finding(
                device=device, user=user, evidence=evidence, severity=severity,
                reason=(
                    f"{len(procedures)} distinct recovery control(s) were destroyed on "
                    f"{device} by '{user}': {'; '.join(descriptions)}. Destroying "
                    "recovery paths removes the ability to roll back and commonly "
                    "immediately precedes encryption."
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
