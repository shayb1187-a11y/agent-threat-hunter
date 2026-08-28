"""Read-only tools -- the agent's *only* route to data.

The single most important architectural decision in this layer
--------------------------------------------------------------
The agent never receives the dataset. Not a sample of it, not a summary of it, not
"here are the 40 most relevant rows" pasted into a prompt. It receives a *case* and a
list of tools, and it must ask for everything else.

Three things follow from that, and they are the reasons to do it:

1. **Traceability.** Every piece of data that reached the model arrived through a
   recorded :class:`ToolCall`. When a conclusion looks wrong you can replay exactly what
   the model saw, which is impossible when context was assembled by string concatenation.
2. **Hallucination becomes detectable.** If a claim cites an event the model never
   retrieved, that is visible. When the whole dataset is in the prompt, a fabricated
   citation is indistinguishable from a real one.
3. **It scales past the context window.** A real SOC has billions of events. Any design
   that depends on fitting telemetry into a prompt is a demo, not a system.

Every tool here is **read-only**. There is no tool that disables an account, isolates a
host, or writes to the telemetry. Response actions are a later milestone and will be
gated behind human approval; giving an autonomous loop destructive capability because it
was convenient is how these systems cause incidents rather than resolve them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import pandas as pd

from ath.behavior import compute_connection_pattern
from ath.correlation.chain import InvestigationCase
from ath.hunting.finding import Finding
from ath.logging_setup import get_logger
from ath.mitre.attack import get_technique
from ath.schema import describe_logon_type
from ath.telemetry.loader import Telemetry

logger = get_logger(__name__)


@dataclass(frozen=True)
class ToolCall:
    """A recorded invocation of a tool -- the audit trail of what the agent saw."""

    tool: str
    arguments: dict[str, Any]
    agent: str
    result_summary: str
    event_ids: tuple[str, ...] = ()
    called_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "arguments": self.arguments,
            "agent": self.agent,
            "result_summary": self.result_summary,
            "event_ids": list(self.event_ids),
            "called_at": self.called_at.isoformat(),
        }

    def __str__(self) -> str:
        args = ", ".join(f"{k}={v!r}" for k, v in self.arguments.items())
        return f"{self.agent}::{self.tool}({args}) -> {self.result_summary}"


class ToolBox:
    """The read-only tool surface available during an investigation.

    Args:
        telemetry: Source telemetry.
        findings: All findings from the hunt.
        cases: All correlated investigation cases.
    """

    def __init__(
        self,
        telemetry: Telemetry,
        findings: list[Finding],
        cases: list[InvestigationCase],
    ) -> None:
        self.telemetry = telemetry
        self._findings = {f.finding_id: f for f in findings}
        self._cases = {c.case_id: c for c in cases}
        self.calls: list[ToolCall] = []

    # -- bookkeeping ----------------------------------------------------------------

    def _record(
        self, tool: str, arguments: dict[str, Any], agent: str,
        summary: str, event_ids: tuple[str, ...] = (),
    ) -> None:
        call = ToolCall(
            tool=tool, arguments=arguments, agent=agent,
            result_summary=summary, event_ids=event_ids,
        )
        self.calls.append(call)
        logger.debug("tool call: %s", call)

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def calls_by(self, agent: str) -> list[ToolCall]:
        return [c for c in self.calls if c.agent == agent]

    # -- tools ----------------------------------------------------------------------

    def get_case(self, case_id: str, agent: str = "orchestrator") -> dict[str, Any]:
        """Return one correlated case, including its timeline and ATT&CK mappings."""
        case = self._cases.get(case_id.upper())
        if case is None:
            self._record("get_case", {"case_id": case_id}, agent, "not found")
            return {"error": f"No such case {case_id!r}", "known": sorted(self._cases)}
        payload = case.to_dict()
        self._record(
            "get_case", {"case_id": case_id}, agent,
            f"{len(case.findings)} findings, {len(case.devices)} host(s)",
            tuple(case.event_ids),
        )
        return payload

    def get_events(self, event_ids: list[str], agent: str = "orchestrator") -> dict[str, Any]:
        """Return raw telemetry rows for specific event ids.

        The lowest-level tool: how an agent checks the actual data rather than trusting
        a summary. Unknown ids are reported back explicitly rather than dropped, so an
        agent asking for a non-existent event learns that it does not exist.
        """
        wanted = set(event_ids)
        rows: list[dict[str, Any]] = []
        for df in (self.telemetry.processes, self.telemetry.network, self.telemetry.logons):
            match = df[df["event_id"].isin(wanted)]
            for row in match.to_dict("records"):
                rows.append({k: _jsonable(v) for k, v in row.items() if _present(v)})

        found = {r["event_id"] for r in rows}
        rows.sort(key=lambda r: r["timestamp"])
        self._record(
            "get_events", {"event_ids": event_ids[:10]}, agent,
            f"{len(found)}/{len(wanted)} found", tuple(sorted(found)),
        )
        return {"events": rows, "not_found": sorted(wanted - found)}

    def process_tree(
        self, device: str, pid: int, depth: int = 3, agent: str = "endpoint"
    ) -> dict[str, Any]:
        """Walk a process's ancestry on one host.

        Answers the question that decides most endpoint investigations: *what started
        this?* A PowerShell process is unremarkable until you learn its parent was Word.
        """
        procs = self.telemetry.processes
        host = procs[procs["device"] == device]
        chain: list[dict[str, Any]] = []
        current = pid

        for _ in range(depth):
            match = host[host["process_id"] == current]
            if match.empty:
                break
            row = match.iloc[0]
            chain.append({
                "event_id": row["event_id"],
                "timestamp": _jsonable(row["timestamp"]),
                "process_name": row["process_name"],
                "process_id": int(row["process_id"]),
                "parent_process_name": row["parent_process_name"],
                "parent_process_id": _jsonable(row["parent_process_id"]),
                "command_line": row["command_line"],
                "user": row["user"],
            })
            if pd.isna(row["parent_process_id"]):
                break
            current = int(row["parent_process_id"])

        # Direct children, so an agent can walk downward as well as upward.
        children = host[host["parent_process_id"] == pid]
        child_rows = [
            {
                "event_id": r["event_id"],
                "timestamp": _jsonable(r["timestamp"]),
                "process_name": r["process_name"],
                "process_id": int(r["process_id"]),
                "command_line": r["command_line"],
            }
            for r in children.to_dict("records")
        ]

        ids = tuple(c["event_id"] for c in chain) + tuple(c["event_id"] for c in child_rows)
        self._record(
            "process_tree", {"device": device, "pid": pid}, agent,
            f"{len(chain)} ancestor(s), {len(child_rows)} child(ren)", ids,
        )
        return {"device": device, "pid": pid, "ancestry": chain, "children": child_rows}

    def user_auth_history(self, user: str, agent: str = "identity") -> dict[str, Any]:
        """All authentication activity for one account.

        The identity question: where does this account normally operate, and did that
        change?
        """
        logons = self.telemetry.logons
        rows = logons[logons["user"] == user].sort_values("timestamp")
        if rows.empty:
            self._record("user_auth_history", {"user": user}, agent, "no activity")
            return {"user": user, "events": [], "summary": {}}

        failures = rows[rows["action"] == "failure"]
        successes = rows[rows["action"] == "success"]
        summary = {
            "total": int(len(rows)),
            "failures": int(len(failures)),
            "successes": int(len(successes)),
            "source_devices": sorted({s for s in rows["source_device"] if s}),
            "target_devices": sorted(set(rows["device"])),
            "logon_types": sorted({describe_logon_type(t) for t in rows["logon_type"]}),
            "first_seen": _jsonable(rows["timestamp"].min()),
            "last_seen": _jsonable(rows["timestamp"].max()),
        }
        events = [
            {
                "event_id": r["event_id"],
                "timestamp": _jsonable(r["timestamp"]),
                "device": r["device"],
                "action": r["action"],
                "logon_type": describe_logon_type(r["logon_type"]),
                "source_device": r["source_device"],
                "source_ip": r["source_ip"],
            }
            for r in rows.to_dict("records")
        ]
        self._record(
            "user_auth_history", {"user": user}, agent,
            f"{summary['total']} logons ({summary['failures']} failed)",
            tuple(rows["event_id"]),
        )
        return {"user": user, "summary": summary, "events": events}

    def host_network_activity(
        self, device: str, remote_ip: str | None = None, agent: str = "network"
    ) -> dict[str, Any]:
        """Outbound connections from a host, optionally filtered to one destination."""
        net = self.telemetry.network
        rows = net[net["device"] == device]
        if remote_ip:
            rows = rows[rows["remote_ip"] == remote_ip]
        rows = rows.sort_values("timestamp")

        by_destination = (
            rows.groupby(["remote_ip", "process_name"])
            .agg(connections=("event_id", "count"), first=("timestamp", "min"))
            .reset_index()
            .sort_values("connections", ascending=False)
        )
        destinations = [
            {
                "remote_ip": r["remote_ip"],
                "process_name": r["process_name"],
                "connections": int(r["connections"]),
                "first_seen": _jsonable(r["first"]),
            }
            for r in by_destination.head(15).to_dict("records")
        ]
        event_ids = tuple(rows["event_id"])
        self._record(
            "host_network_activity", {"device": device, "remote_ip": remote_ip}, agent,
            f"{len(rows)} connections to {len(by_destination)} destination(s)",
            event_ids,
        )
        # event_ids is returned, not just recorded. A caller that needs the evidence
        # behind this result must not have to reach into the audit log for it --
        # `calls_by(agent)[-1]` couples the caller to tool-call *ordering*, so any
        # added or reordered internal call would silently re-point its citations.
        # The audit trail records what happened; it is not a data channel.
        return {
            "device": device,
            "destinations": destinations,
            "total": int(len(rows)),
            "event_ids": list(event_ids),
        }

    def analyse_beacon(
        self, device: str, remote_ip: str, agent: str = "network"
    ) -> dict[str, Any]:
        """Interpret the measured timing of one host-to-destination relationship.

        This tool **computes no statistics**. It reads the
        :class:`~ath.behavior.features.ConnectionPattern` produced once by
        :mod:`ath.behavior`, and interprets it.

        That split is the whole point. The median/MAD computation used to live here, in
        the investigation layer, which only runs after a case has been formed -- so
        triage, the layer that decides whether to reassure an analyst, could not reach
        it. Four regular TLS connections to a popular destination were returned as
        ``likely_benign``. One deterministic computation existed in exactly one place,
        and the layer that most needed it was not that place.

        Interpretation, not measurement, is what remains here: what the numbers mean for
        this case, including how thin their support is.

        The honest limit is unchanged: implants add *jitter* precisely to defeat
        interval analysis, so an irregular result is weak evidence of absence.
        """
        net = self.telemetry.network
        rows = net[(net["device"] == device) & (net["remote_ip"] == remote_ip)]
        rows = rows.sort_values("timestamp")

        if rows.empty:
            self._record(
                "analyse_beacon", {"device": device, "remote_ip": remote_ip}, agent,
                "no connections to this destination",
            )
            return {
                "regular": False, "reason": "no connections observed", "samples": 0,
                "interarrival_count": 0,
            }

        pattern = compute_connection_pattern(
            source_process=str(rows.iloc[0].get("process_name") or ""),
            destination=remote_ip,
            timestamps=list(rows["timestamp"]),
            evidence_ids=tuple(str(e) for e in rows["event_id"]),
        )

        if not pattern.has_measurable_regularity:
            self._record(
                "analyse_beacon", {"device": device, "remote_ip": remote_ip}, agent,
                pattern.support_note, tuple(pattern.evidence_ids),
            )
            return {
                "regular": False,
                "reason": pattern.support_note,
                "samples": pattern.connection_count,
                "interarrival_count": pattern.interarrival_count,
                "event_ids": list(pattern.evidence_ids),
            }

        median_seconds = pattern.median_interval.total_seconds()
        self._record(
            "analyse_beacon", {"device": device, "remote_ip": remote_ip}, agent,
            f"{pattern.interarrival_count} intervals, median {median_seconds:.0f}s, "
            f"robust cv {pattern.robust_cv:.3f}, "
            f"{'regular' if pattern.is_regular else 'irregular'}",
            tuple(pattern.evidence_ids),
        )
        return {
            "regular": pattern.is_regular,
            "samples": pattern.connection_count,
            # Exposed so a claim can state how much support the figures have. Four
            # connections give three intervals, and a reader deserves to see that
            # rather than infer it from a confident-looking ratio.
            "interarrival_count": pattern.interarrival_count,
            "median_interval_seconds": round(median_seconds, 1),
            # Named for what it is: MAD / median, NOT stdev / mean. The old name was
            # `coefficient_of_variation`, which invited callers to pair it with the
            # mean -- and one did, producing a FACT asserting zero dispersion around a
            # mean no interval ever equalled. A statistic and its centre travel together.
            "robust_cv": round(pattern.robust_cv, 4),
            "support_note": pattern.support_note,
            "event_ids": list(pattern.evidence_ids),
        }

    def search_processes(
        self, device: str | None = None, contains: str | None = None,
        process_name: str | None = None, limit: int = 25, agent: str = "endpoint",
    ) -> dict[str, Any]:
        """Search process telemetry by host, image name, or command-line substring."""
        rows = self.telemetry.processes
        if device:
            rows = rows[rows["device"] == device]
        if process_name:
            rows = rows[rows["process_name"].str.lower() == process_name.lower()]
        if contains:
            rows = rows[rows["command_line"].str.contains(contains, case=False, na=False)]
        rows = rows.sort_values("timestamp").head(limit)

        results = [
            {
                "event_id": r["event_id"],
                "timestamp": _jsonable(r["timestamp"]),
                "device": r["device"],
                "user": r["user"],
                "process_name": r["process_name"],
                "process_id": int(r["process_id"]) if pd.notna(r["process_id"]) else None,
                "parent_process_name": r["parent_process_name"],
                "command_line": r["command_line"],
            }
            for r in rows.to_dict("records")
        ]
        self._record(
            "search_processes",
            {"device": device, "contains": contains, "process_name": process_name},
            agent, f"{len(results)} match(es)", tuple(r["event_id"] for r in results),
        )
        return {"results": results, "count": len(results)}

    def get_finding(self, finding_id: str, agent: str = "orchestrator") -> dict[str, Any]:
        """Return one detection finding with its evidence and declared caveats."""
        finding = self._findings.get(finding_id)
        if finding is None:
            self._record("get_finding", {"finding_id": finding_id}, agent, "not found")
            return {"error": f"No such finding {finding_id!r}"}
        self._record(
            "get_finding", {"finding_id": finding_id}, agent,
            f"{finding.rule_id} {finding.severity}", finding.event_ids,
        )
        return finding.to_dict()

    def lookup_technique(self, technique_id: str, agent: str = "attack") -> dict[str, Any]:
        """Look up an ATT&CK technique in the verified catalogue."""
        try:
            technique = get_technique(technique_id)
        except KeyError:
            self._record("lookup_technique", {"technique_id": technique_id}, agent, "unknown")
            return {"error": f"{technique_id} is not in the verified catalogue"}
        self._record(
            "lookup_technique", {"technique_id": technique_id}, agent, technique.name
        )
        return {
            "technique_id": technique.technique_id,
            "name": technique.name,
            "tactics": [t.display_name for t in technique.tactics],
            "parent_id": technique.parent_id,
            "url": technique.url,
        }


def _present(value: Any) -> bool:
    """Drop empty/missing fields so tool output stays compact."""
    if value is None:
        return False
    if isinstance(value, float) and pd.isna(value):
        return False
    return not (isinstance(value, str) and value == "")


def _jsonable(value: Any) -> Any:
    if isinstance(value, (pd.Timestamp, datetime)):
        return value.isoformat()
    if pd.isna(value) if not isinstance(value, (list, tuple, dict, str)) else False:
        return None
    if hasattr(value, "item") and not isinstance(value, (str, bytes)):
        try:
            return value.item()
        except (AttributeError, ValueError):
            return str(value)
    return value
