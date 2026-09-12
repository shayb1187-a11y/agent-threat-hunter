"""Detections over network connection telemetry."""

from __future__ import annotations

import pandas as pd

from ath.hunting.base import SCRIPT_INTERPRETERS, Detector, register
from ath.hunting.finding import Evidence, Finding, Severity
from ath.hunting.indicators import is_public_ip, truncate
from ath.schema import EVENT_NETWORK
from ath.telemetry.loader import Telemetry


@register
class InterpreterExternalConnection(Detector):
    """ATH-003 -- A script interpreter connected to an external host.

    Attacker behaviour
    ------------------
    After code execution is achieved, the implant needs to talk to its operator: to
    download a second stage, to receive commands, and to send results back. When the
    implant *is* a PowerShell session, that traffic originates from
    ``powershell.exe`` itself.

    Why the process matters more than the destination
    -------------------------------------------------
    ``chrome.exe`` connecting to an unfamiliar IP on 443 is a Tuesday. ``powershell.exe``
    doing the same thing is a question worth asking. Threat intelligence feeds go stale
    within days -- attacker infrastructure is cheap and disposable -- so anchoring the
    rule on *which process is talking* rather than *which IP it talks to* produces a
    detection that survives infrastructure rotation.

    This rule also groups by (device, process id) so that a beacon producing dozens of
    connections yields **one finding with many evidence items**, rather than dozens of
    near-identical alerts. Alert volume is a real operational cost.

    Cleartext HTTP raises severity: an interpreter pulling a script over port 80 is
    both more suspicious and more likely to be a first-stage downloader.
    """

    rule_id = "ATH-003"
    title = "Script interpreter connected to an external host"
    severity = Severity.MEDIUM
    description = "Detects PowerShell and similar interpreters making outbound external connections."
    fields_used = (
        "process_name", "process_id", "remote_ip", "remote_port", "direction",
        "protocol", "remote_url", "device", "user", "timestamp",
    )
    tables = frozenset({EVENT_NETWORK})
    optional_fields = frozenset({"protocol", "remote_url"})
    """Both appear in the evidence summary only, never in the detection mask:
    ``f"{row['remote_ip']}:{row['remote_port']}/{row['protocol']}"`` and the
    ``url=`` clause after it. ``remote_port`` is *not* optional -- it decides the
    cleartext-HTTP severity grade and is the field an analyst pivots on, so losing
    it is a real loss of detection quality, not a cosmetic one."""
    false_positives = (
        "PowerShell installing modules from the PowerShell Gallery.",
        "Scripts calling cloud management APIs (Azure, AWS, Microsoft Graph).",
        "Package managers such as Chocolatey or winget invoked through PowerShell.",
        "Telemetry, licensing or update checks made by vendor scripts.",
        "Administrators running ad-hoc scripts that query internet resources.",
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        network = telemetry.network
        if network.empty:
            return []

        is_interpreter = (
            network["process_name"].fillna("").astype(str).str.lower().isin(SCRIPT_INTERPRETERS)
        )
        is_outbound = network["direction"].fillna("").astype(str).str.lower() == "outbound"
        is_external = network["remote_ip"].fillna("").astype(str).map(is_public_ip)
        not_allowed = ~network["remote_ip"].isin(self.config.allowed_external_destinations)

        hits = network[is_interpreter & is_outbound & is_external & not_allowed]
        if hits.empty:
            return []

        findings: list[Finding] = []
        # One finding per (device, process instance, destination): this is the natural
        # unit an analyst investigates.
        for (device, pid, process_name, remote_ip), group in hits.groupby(
            ["device", "process_id", "process_name", "remote_ip"], dropna=False
        ):
            group = group.sort_values("timestamp")
            ports = sorted({int(p) for p in group["remote_port"].dropna()})
            urls = sorted({u for u in group["remote_url"].fillna("") if u})
            cleartext = 80 in ports

            evidence = tuple(
                Evidence(
                    event_id=row["event_id"],
                    timestamp=row["timestamp"],
                    summary=(
                        f"{row['process_name']} (PID {row['process_id']}) -> "
                        f"{row['remote_ip']}:{row['remote_port']}/{row['protocol']}"
                        + (f" url={truncate(row['remote_url'], 80)}" if row["remote_url"] else "")
                    ),
                )
                for _, row in group.iterrows()
            )

            severity = Severity.HIGH if cleartext else Severity.MEDIUM
            cleartext_note = (
                " The connection to port 80 indicates cleartext HTTP, which is "
                "commonly used to retrieve a second-stage script."
                if cleartext
                else ""
            )

            findings.append(
                self.make_finding(
                    device=device,
                    user=str(group.iloc[0]["user"]),
                    evidence=evidence,
                    severity=severity,
                    reason=(
                        f"{process_name} made {len(group)} outbound connection(s) to the "
                        f"external address {remote_ip} on port(s) "
                        f"{', '.join(map(str, ports))}. Script interpreters do not "
                        "normally initiate direct internet connections; this may "
                        "indicate payload retrieval or command-and-control."
                        + cleartext_note
                    ),
                    metadata={
                        "remote_ip": remote_ip,
                        "ports": ports,
                        "connection_count": len(group),
                        "process_id": int(pid) if pd.notna(pid) else None,
                        "urls": urls,
                        "cleartext_http": cleartext,
                    },
                )
            )
        return findings
