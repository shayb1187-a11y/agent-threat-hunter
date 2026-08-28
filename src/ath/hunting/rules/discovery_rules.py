"""Detections targeting the Discovery stage of an intrusion.

Provenance
----------
ATH-010, like ATH-009, began as a proposal from the detection-engineering harness
(``ath.engineering.candidates.DiscoveryCommandSequenceV1``) and was tightened once after
measurement showed it was far too broad. See
``ath.engineering.candidates.DiscoveryCommandSequenceV2`` for the candidate this rule
was promoted from, and ``docs/detection-engineering.md`` for the numbers.
"""

from __future__ import annotations

from datetime import timedelta

import pandas as pd

from ath.hunting.base import Detector, register
from ath.hunting.finding import Evidence, Finding, Severity
from ath.hunting.indicators import truncate
from ath.telemetry.loader import Telemetry

# Each discovery binary mapped to the ATT&CK technique its use corresponds to. Used by
# the MITRE mapping layer (ath.mitre.mapper) to interpret which specific technique(s)
# a given finding's matched binaries support -- see the gates on ATH-010 there.
DISCOVERY_BINARIES: dict[str, str] = {
    "whoami.exe": "T1033",       # System Owner/User Discovery
    "net.exe": "T1069.002",      # Permission Groups Discovery: Domain Groups
    "nltest.exe": "T1482",       # Domain Trust Discovery
    "systeminfo.exe": "T1033",
    "hostname.exe": "T1033",
    "quser.exe": "T1033",
}


@register
class DiscoveryCommandSequence(Detector):
    """ATH-010 -- A sequence of distinct discovery commands ran from one parent process.

    Attacker behaviour
    ------------------
    After landing on a host, an operator systematically maps the environment before
    deciding what to do next: who am I, what domain groups exist, what other domains
    does this one trust. ``whoami``, ``net group ... /domain``, and ``nltest
    /domain_trusts`` are the textbook Windows commands for exactly that, and they
    typically run in a burst, from the same interactive shell, within a few minutes of
    each other.

    Why sequence-and-shared-parentage, not a binary blocklist
    -----------------------------------------------------------
    Every one of these binaries is also a completely ordinary IT support tool --
    ``whoami`` and ``systeminfo`` in particular are run constantly during routine
    troubleshooting, one at a time, by hand, from Explorer. A rule that fires on any of
    them individually is measuring "did IT do their job today", not "is this
    reconnaissance". The pattern that is actually distinctive is **two or more
    different** discovery binaries launched from the **same parent process** in a
    **short window** -- that specific shape describes an operator methodically working
    through a checklist from one shell, and it does not describe a technician running
    one command by hand.

    Detection shape
    ---------------
    Group process events by ``(device, parent_process_id)``. Within a group, if at
    least ``min_distinct_binaries`` (default 2) different discovery binaries appear
    within ``window`` (default 5 minutes) of each other, raise one finding covering all
    of them.

    History
    -------
    v1 (any discovery binary running anywhere) scored 0.07 precision on this project's
    telemetry -- 39 false positives, the majority of them the single ``ipconfig /all``
    calls this project's own benign IT-support template generates, against 3 true
    positives (matched per-row, before grouping). Requiring >=2 distinct binaries
    sharing a parent within 5 minutes brought precision to 1.00 with the same stage
    coverage. See ``ath.engineering.candidates`` and ``docs/detection-engineering.md``.
    """

    rule_id = "ATH-010"
    title = "Sequence of discovery commands from one parent process"
    severity = Severity.MEDIUM
    description = "Detects >=2 distinct discovery binaries sharing a parent process in a short window."
    fields_used = ("process_name", "parent_process_id", "device", "user", "timestamp")
    false_positives = (
        "IT support running a single discovery command (e.g. ipconfig /all, whoami) "
        "during routine troubleshooting -- excluded by design, since a lone command "
        "cannot meet the >=2-distinct-binaries condition.",
        "Automated inventory or compliance scripts that legitimately run several "
        "discovery commands in sequence from one scheduled task.",
        "A single administrator manually running a short checklist of commands "
        "during planned environment documentation.",
    )

    min_distinct_binaries: int = 2
    window: timedelta = timedelta(minutes=5)

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        procs = telemetry.processes
        if procs.empty:
            return []

        is_discovery = procs["process_name"].str.lower().isin(DISCOVERY_BINARIES)
        candidates = procs[is_discovery]
        if candidates.empty:
            return []

        findings: list[Finding] = []
        for (device, parent_pid), group in candidates.groupby(
            ["device", "parent_process_id"], dropna=False
        ):
            if pd.isna(parent_pid):
                continue
            group = group.sort_values("timestamp")
            span = group["timestamp"].max() - group["timestamp"].min()
            distinct = sorted({name.lower() for name in group["process_name"]})
            if len(distinct) < self.min_distinct_binaries or span > self.window:
                continue

            evidence = tuple(
                Evidence(
                    event_id=row["event_id"], timestamp=row["timestamp"],
                    summary=f"{row['parent_process_name']} -> {row['process_name']}: "
                            f"{truncate(row['command_line'], 120)}",
                )
                for _, row in group.iterrows()
            )
            techniques = sorted({DISCOVERY_BINARIES[b] for b in distinct if b in DISCOVERY_BINARIES})
            findings.append(self.make_finding(
                device=str(device), user=str(group.iloc[0]["user"]), evidence=evidence,
                reason=(
                    f"{len(distinct)} distinct discovery commands "
                    f"({', '.join(distinct)}) ran from the same parent process "
                    f"(PID {int(parent_pid)}) within "
                    f"{int(span.total_seconds())}s, consistent with systematic "
                    "reconnaissance of the local environment and domain."
                ),
                metadata={
                    "matched_binaries": distinct,
                    "candidate_techniques": techniques,
                    "parent_process_id": int(parent_pid),
                    "span_seconds": int(span.total_seconds()),
                },
            ))
        return findings
