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

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import pandas as pd

from ath.behavior import compute_connection_pattern
from ath.correlation.chain import InvestigationCase
from ath.hunting.finding import Finding
from ath.instance_identity import (
    INFERRED_FROM_PID,
    RESOLVED_BY_IDENTITY,
    instance_key,
)
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
    refused: bool = False
    """The call was refused because the per-case tool budget was spent.

    A refusal is *recorded as a call*, not swallowed: an arm that ran out of budget
    asked for that data and did not get it, and a cost column that omits the asking
    would under-report exactly the arm that was too expensive.
    """
    truncated: bool = False
    """The result handed to the caller was cut at the toolbox's ``max_rows`` or
    ``max_chars``. ``event_ids`` still records the *full* retrieval, because the scorer's
    "touched" set is about what the tool found; ``shown_event_ids`` records what the
    caller was actually given, because a claim may only cite what it saw."""
    shown_event_ids: tuple[str, ...] = ()
    args_sha256: str = ""
    result_sha256: str = ""
    """Canonical-JSON digests of the arguments and the returned payload, recorded when
    the toolbox's ``ledger`` is on. Two runs of one case produce one hash sequence."""

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "tool": self.tool,
            "arguments": self.arguments,
            "agent": self.agent,
            "result_summary": self.result_summary,
            "event_ids": list(self.event_ids),
            "called_at": self.called_at.isoformat(),
        }
        # Every addition below is emitted only when set, so a run made under no budget,
        # no cap and no ledger serialises exactly as it did before they existed -- the
        # published arm A rows and the pending D1 v3 rows stay comparable.
        if self.refused:
            payload["refused"] = True
        if self.truncated:
            payload["truncated"] = True
            payload["shown_event_ids"] = list(self.shown_event_ids)
        if self.args_sha256:
            payload["args_sha256"] = self.args_sha256
        if self.result_sha256:
            payload["result_sha256"] = self.result_sha256
        return payload

    def __str__(self) -> str:
        args = ", ".join(f"{k}={v!r}" for k, v in self.arguments.items())
        prefix = "REFUSED " if self.refused else ""
        return f"{prefix}{self.agent}::{self.tool}({args}) -> {self.result_summary}"


class ToolBox:
    """The read-only tool surface available during an investigation.

    The tool budget
    ----------------
    ``tool_call_budget`` caps how many tools one case may actually consume. It exists
    because an agent that decides for itself what to look at is unbounded by
    construction: a generalist walking every entity of a forty-finding cloud case will
    keep asking, and an arm that runs out of wall clock has measured its own exhaustion
    rather than anything about agent design.

    A spent budget is **data, not an exception**. Every further call returns a structured
    refusal -- the tool's own empty shape plus ``refused: True`` and a reason -- and is
    recorded as a :class:`ToolCall` with ``refused=True``. Nothing raises, the
    investigation continues, and the hit is counted in :attr:`budget_hits`. Callers get a
    result they already know how to read, which is what keeps a refusal from being
    mistaken for "the telemetry says nothing" -- the distinction this codebase draws
    everywhere else between absence and invisibility.

    Refused calls do not consume budget themselves; only calls that returned data do.
    Otherwise the refusal of the 41st call would spend the budget of the 42nd and the
    cap would not mean the number it says.

    Args:
        telemetry: Source telemetry.
        findings: All findings from the hunt.
        cases: All correlated investigation cases.
        tool_call_budget: Maximum tool calls that may return data for this case.
            ``None`` (the default) is unlimited -- the behaviour every caller written
            before budgets existed keeps.
        max_rows: Longest list of rows, events, children, destinations or ids a tool
            hands back. ``None`` is unbounded. When a cap fires the payload carries
            ``truncated: True`` and ``total``, so the model knows it saw a sample, and
            the :class:`ToolCall` records what was shown next to what was found. This
            is the fix for the M19 HTTP 413: one ``host_network_activity`` call
            returned 589,476 ids into a prompt.
        max_chars: Longest string (a command line) a tool hands back; cut with a marker.
        ledger: Record canonical-JSON digests of every call's arguments and result on
            the :class:`ToolCall`. Off by default; hashing a 589k-id payload per call
            is not free.

    These are constructor state on purpose: the tool *methods* are the frozen surface
    (``ath.evaluation.ablation.environment.tool_surface`` hashes their signatures), and
    a new public method would be a new tool.
    """

    TRUNCATION_MARKER = " ...[truncated]"

    def __init__(
        self,
        telemetry: Telemetry,
        findings: list[Finding],
        cases: list[InvestigationCase],
        tool_call_budget: int | None = None,
        max_rows: int | None = None,
        max_chars: int | None = None,
        ledger: bool = False,
    ) -> None:
        self.telemetry = telemetry
        self._findings = {f.finding_id: f for f in findings}
        self._cases = {c.case_id: c for c in cases}
        self.calls: list[ToolCall] = []
        self.tool_call_budget = tool_call_budget
        self.budget_hits = 0
        """How many calls this toolbox refused for want of budget."""
        if max_rows is not None and max_rows < 1:
            raise ValueError("max_rows must be positive or None")
        if max_chars is not None and max_chars < 1:
            raise ValueError("max_chars must be positive or None")
        self.max_rows = max_rows
        self.max_chars = max_chars
        self.ledger = ledger
        self.truncations = 0
        """How many results this toolbox cut at ``max_rows`` or ``max_chars``."""

    # -- bookkeeping ----------------------------------------------------------------

    def _record(
        self, tool: str, arguments: dict[str, Any], agent: str,
        summary: str, event_ids: tuple[str, ...] = (), refused: bool = False,
        *, result: Any = None, shown_event_ids: tuple[str, ...] | None = None,
        truncated: bool = False,
    ) -> None:
        if truncated:
            self.truncations += 1
            summary = f"{summary}; truncated to {len(shown_event_ids or ())} shown"
        call = ToolCall(
            tool=tool, arguments=arguments, agent=agent,
            result_summary=summary, event_ids=event_ids, refused=refused,
            truncated=truncated,
            shown_event_ids=tuple(shown_event_ids or ()) if truncated else (),
            args_sha256=_sha256_json(arguments) if self.ledger else "",
            result_sha256=_sha256_json(result) if self.ledger and result is not None else "",
        )
        self.calls.append(call)
        logger.debug("tool call: %s", call)

    def _cap(self, items: list[Any]) -> tuple[list[Any], bool]:
        """``items`` cut at ``max_rows``; whether the cut happened."""
        if self.max_rows is None or len(items) <= self.max_rows:
            return items, False
        return items[: self.max_rows], True

    def _cap_text(self, value: Any) -> tuple[Any, bool]:
        if self.max_chars is None or not isinstance(value, str) or len(value) <= self.max_chars:
            return value, False
        return value[: self.max_chars] + self.TRUNCATION_MARKER, True

    @property
    def call_count(self) -> int:
        return len(self.calls)

    @property
    def calls_served(self) -> int:
        """Calls that returned data -- what the budget is actually spent on."""
        return sum(1 for c in self.calls if not c.refused)

    @property
    def budget_exhausted(self) -> bool:
        return (
            self.tool_call_budget is not None
            and self.calls_served >= self.tool_call_budget
        )

    def _refuse(
        self, tool: str, arguments: dict[str, Any], agent: str, shape: dict[str, Any],
    ) -> dict[str, Any]:
        """Record a refused call and return the tool's empty shape, marked as refused."""
        reason = f"tool budget exhausted ({self.tool_call_budget} calls)"
        self.budget_hits += 1
        payload = {**shape, "refused": True, "reason": reason}
        self._record(tool, arguments, agent, reason, refused=True, result=payload)
        return payload

    def calls_by(self, agent: str) -> list[ToolCall]:
        return [c for c in self.calls if c.agent == agent]

    # -- tools ----------------------------------------------------------------------

    def get_case(self, case_id: str, agent: str = "orchestrator") -> dict[str, Any]:
        """Return one correlated case, including its timeline and ATT&CK mappings."""
        if self.budget_exhausted:
            return self._refuse(
                "get_case", {"case_id": case_id}, agent,
                {"error": "not retrieved", "known": []},
            )
        case = self._cases.get(case_id.upper())
        if case is None:
            payload = {"error": f"No such case {case_id!r}", "known": sorted(self._cases)}
            self._record("get_case", {"case_id": case_id}, agent, "not found", result=payload)
            return payload
        payload = case.to_dict()
        self._record(
            "get_case", {"case_id": case_id}, agent,
            f"{len(case.findings)} findings, {len(case.devices)} host(s)",
            tuple(case.event_ids), result=payload,
        )
        return payload

    def get_events(self, event_ids: list[str], agent: str = "orchestrator") -> dict[str, Any]:
        """Return raw telemetry rows for specific event ids.

        The lowest-level tool: how an agent checks the actual data rather than trusting
        a summary. Unknown ids are reported back explicitly rather than dropped, so an
        agent asking for a non-existent event learns that it does not exist.
        """
        if self.budget_exhausted:
            return self._refuse(
                "get_events", {"event_ids": event_ids if self.ledger else event_ids[:10]}, agent,
                {"events": [], "not_found": sorted(set(event_ids))},
            )
        wanted = set(event_ids)
        rows: list[dict[str, Any]] = []
        for df in (
            self.telemetry.processes, self.telemetry.network, self.telemetry.logons,
            self.telemetry.controls,
        ):
            match = df[df["event_id"].isin(wanted)]
            for row in match.to_dict("records"):
                rows.append({k: _jsonable(v) for k, v in row.items() if _present(v)})

        found = {r["event_id"] for r in rows}
        rows.sort(key=lambda r: r["timestamp"])
        shown, truncated = self._cap(rows)
        cut = False
        for row in shown:
            if "command_line" in row:
                row["command_line"], text_cut = self._cap_text(row["command_line"])
                cut = cut or text_cut
        payload: dict[str, Any] = {"events": shown, "not_found": sorted(wanted - found)}
        if truncated:
            payload["truncated"] = True
            payload["total"] = len(rows)
        self._record(
            "get_events", {"event_ids": event_ids if self.ledger else event_ids[:10]}, agent,
            f"{len(found)}/{len(wanted)} found", tuple(sorted(found)),
            result=payload, truncated=truncated or cut,
            shown_event_ids=tuple(r["event_id"] for r in shown),
        )
        return payload

    def process_tree(
        self, device: str, pid: int | None = None, depth: int = 3,
        agent: str = "endpoint", process_guid: str = "",
    ) -> dict[str, Any]:
        """Walk a process instance's ancestry and children on one host.

        Answers the question that decides most endpoint investigations: *what started
        this?* A PowerShell process is unremarkable until you learn its parent was Word.

        What identifies the process
        ----------------------------
        A PID does not. The operating system reissues it, so ``(device, pid)`` names a
        slot that several runs pass through -- on the COMISET slice, the worst slot on
        one host covered 27 distinct instances. This tool therefore takes either:

        * ``process_guid`` -- the instance's
          :mod:`identity <ath.instance_identity>`, which names exactly one run; or
        * ``pid`` -- a slot, which is resolved to an instance **only when exactly one
          instance held it**. When more than one did, the result is
          ``resolution="ambiguous_pid"`` carrying every candidate with its identity and
          timestamp, and no ancestry. The previous implementation took ``iloc[0]``: the
          first row in file order, silently, and then walked *its* ancestors, so a chain
          could be assembled from three unrelated processes and returned as a fact.

        How each hop was made is part of the answer
        --------------------------------------------
        Every entry carries ``resolved_by``: ``"identity"`` when the instance is named
        by the telemetry, ``"inferred from pid"`` when the join to it could only be made
        on ``(device, pid)`` -- because the row asserted no identity, or because the two
        identities came from authorities that cannot confirm each other. Those hops are
        still walked; a corpus that records no identity would otherwise return nothing.
        Each entry also carries ``parent_resolution``, which says the same thing about
        the row's *named* parent, so a caller can label a "started by X" statement
        without re-deriving the rule.

        Args:
            device: Host to walk on. Also the fallback's other half.
            pid: The slot, when that is what the caller has.
            depth: Maximum ancestors to walk.
            agent: Recorded on the tool call.
            process_guid: The instance identity, when the caller has one. Takes
                precedence over ``pid``.

        Returns:
            ``device``, ``pid``, ``process_guid``, ``resolution``, ``ambiguous_pid``
            (the number of instances that held the slot, ``0`` when it was not
            ambiguous), ``candidates`` (populated only when it was), ``ancestry``
            (leaf first), ``children``, and ``notes`` for anything the walk had to stop
            on.
        """
        procs = self.telemetry.processes
        arguments = {"device": device, "pid": pid, "process_guid": process_guid}
        if self.ledger:
            arguments["depth"] = depth
        result: dict[str, Any] = {
            "device": device, "pid": pid, "process_guid": process_guid,
            "resolution": "not_found", "ambiguous_pid": 0, "candidates": [],
            "ancestry": [], "children": [], "notes": [],
        }
        if self.budget_exhausted:
            return self._refuse("process_tree", arguments, agent, result)
        if procs.empty or (pid is None and not process_guid):
            self._record("process_tree", arguments, agent, "no process telemetry", result=result)
            return result

        host = procs[procs["device"] == device]
        if process_guid:
            rows = procs[procs["process_guid"].astype("string").fillna("") == process_guid]
            if rows.empty:
                self._record(
                    "process_tree", arguments, agent, "no row carries that identity", result=result,
                )
                return result
            start_row = rows.sort_values("timestamp").iloc[0]
            result["resolution"] = RESOLVED_BY_IDENTITY
        else:
            instances = _instances_of(host, "process_id", int(pid))
            if not instances:
                self._record("process_tree", arguments, agent, "unknown pid", result=result)
                return result
            if len(instances) > 1:
                # Never an arbitrary pick. The candidates are the answer: a caller that
                # knows which instance it meant can come back with its identity, and one
                # that does not now knows it cannot name a single process here.
                result["resolution"] = "ambiguous_pid"
                result["ambiguous_pid"] = len(instances)
                result["candidates"] = [_candidate(row) for row in instances]
                self._record(
                    "process_tree", arguments, agent,
                    f"pid {pid} on {device} was held by {len(instances)} process "
                    "instance(s); no single ancestry can be attributed",
                    tuple(c["event_id"] for c in result["candidates"]), result=result,
                )
                return result
            start_row = instances[0]
            result["resolution"] = "pid_unique"
            result["process_guid"] = _identity_of(start_row)

        # -- upward ------------------------------------------------------------------
        chain: list[dict[str, Any]] = []
        row = start_row
        resolved_by = (
            RESOLVED_BY_IDENTITY if _identity_of(row) else INFERRED_FROM_PID
        )
        seen: set[str] = set()
        for _ in range(depth):
            if row["event_id"] in seen:
                result["notes"].append(
                    "ancestry stopped: the walk returned to a row it had already "
                    "visited, which means the telemetry describes a cycle"
                )
                break
            seen.add(row["event_id"])
            chain.append(_ancestry_entry(row, resolved_by))
            parent, resolved_by, note = _resolve_parent(procs, host, row)
            if note:
                result["notes"].append(note)
            if parent is None:
                break
            row = parent

        # -- downward ----------------------------------------------------------------
        children = _children_of(host, start_row)

        shown_children, truncated = self._cap(children)
        result["ancestry"] = chain
        result["children"] = shown_children
        if truncated:
            result["truncated"] = True
            result["total"] = len(children)
        if result["pid"] is None and chain:
            result["pid"] = chain[0]["process_id"]
        inferred_hops = sum(1 for c in chain if c["resolved_by"] == INFERRED_FROM_PID)
        ids = tuple(c["event_id"] for c in chain) + tuple(c["event_id"] for c in children)
        self._record(
            "process_tree", arguments, agent,
            f"{len(chain)} ancestor(s), {len(children)} child(ren)"
            + (f", {inferred_hops} {INFERRED_FROM_PID}" if inferred_hops else ""),
            ids, result=result, truncated=truncated,
            shown_event_ids=tuple(c["event_id"] for c in chain) + tuple(c["event_id"] for c in shown_children),
        )
        return result

    def user_auth_history(self, user: str, agent: str = "identity") -> dict[str, Any]:
        """All authentication activity for one account.

        The identity question: where does this account normally operate, and did that
        change?
        """
        if self.budget_exhausted:
            return self._refuse(
                "user_auth_history", {"user": user}, agent,
                {"user": user, "events": [], "summary": {}},
            )
        logons = self.telemetry.logons
        rows = logons[logons["user"] == user].sort_values("timestamp")
        if rows.empty:
            payload = {"user": user, "events": [], "summary": {}}
            self._record("user_auth_history", {"user": user}, agent, "no activity", result=payload)
            return payload

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
        shown, truncated = self._cap(events)
        payload: dict[str, Any] = {"user": user, "summary": summary, "events": shown}
        if truncated:
            payload["truncated"] = True
            payload["total"] = len(events)
        self._record(
            "user_auth_history", {"user": user}, agent,
            f"{summary['total']} logons ({summary['failures']} failed)",
            tuple(rows["event_id"]), result=payload, truncated=truncated,
            shown_event_ids=tuple(e["event_id"] for e in shown),
        )
        return payload

    def host_network_activity(
        self, device: str, remote_ip: str | None = None, agent: str = "network"
    ) -> dict[str, Any]:
        """Outbound connections from a host, optionally filtered to one destination."""
        if self.budget_exhausted:
            return self._refuse(
                "host_network_activity", {"device": device, "remote_ip": remote_ip},
                agent,
                {"device": device, "destinations": [], "total": 0, "event_ids": []},
            )
        net = self.telemetry.network
        rows = net[net["device"] == device]
        if remote_ip:
            rows = rows[rows["remote_ip"] == remote_ip]
        rows = rows.sort_values("timestamp")

        # Grouped by image name, as before -- the question this tool answers is "what
        # did this host talk to". The *instance* is reported alongside: one identity
        # when every connection in the group came from one process, and the count when
        # it did not, because "chrome.exe contacted X 400 times" is a different fact
        # depending on whether that was one browser or forty.
        identities = "process_guid" in rows.columns
        by_destination = (
            rows.groupby(["remote_ip", "process_name"])
            .agg(connections=("event_id", "count"), first=("timestamp", "min"))
            .reset_index()
            .sort_values("connections", ascending=False)
        )
        destinations = []
        for r in by_destination.head(15).to_dict("records"):
            group = rows[
                (rows["remote_ip"] == r["remote_ip"])
                & (rows["process_name"] == r["process_name"])
            ]
            observed = (
                sorted({g for g in group["process_guid"].astype("string").fillna("") if g})
                if identities else []
            )
            destinations.append({
                "remote_ip": r["remote_ip"],
                "process_name": r["process_name"],
                "connections": int(r["connections"]),
                "first_seen": _jsonable(r["first"]),
                "process_guid": observed[0] if len(observed) == 1 else "",
                "process_instances": len(observed),
            })
        event_ids = tuple(rows["event_id"])
        shown_destinations, cut_destinations = self._cap(destinations)
        shown_ids, cut_ids = self._cap(list(event_ids))
        truncated = cut_destinations or cut_ids
        # event_ids is returned, not just recorded. A caller that needs the evidence
        # behind this result must not have to reach into the audit log for it --
        # `calls_by(agent)[-1]` couples the caller to tool-call *ordering*, so any
        # added or reordered internal call would silently re-point its citations.
        # The audit trail records what happened; it is not a data channel. Under a
        # cap the returned list is the *shown* ids and ``total`` says how many exist.
        payload: dict[str, Any] = {
            "device": device,
            "destinations": shown_destinations,
            "total": int(len(rows)),
            "event_ids": shown_ids,
        }
        if truncated:
            payload["truncated"] = True
        self._record(
            "host_network_activity", {"device": device, "remote_ip": remote_ip}, agent,
            f"{len(rows)} connections to {len(by_destination)} destination(s)",
            event_ids, result=payload, truncated=truncated, shown_event_ids=tuple(shown_ids),
        )
        return payload

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
        if self.budget_exhausted:
            return self._refuse(
                "analyse_beacon", {"device": device, "remote_ip": remote_ip}, agent,
                {
                    "regular": False, "samples": 0, "interarrival_count": 0,
                    "event_ids": [],
                },
            )
        net = self.telemetry.network
        rows = net[(net["device"] == device) & (net["remote_ip"] == remote_ip)]
        rows = rows.sort_values("timestamp")

        if rows.empty:
            payload = {
                "regular": False, "reason": "no connections observed", "samples": 0,
                "interarrival_count": 0,
            }
            self._record(
                "analyse_beacon", {"device": device, "remote_ip": remote_ip}, agent,
                "no connections to this destination", result=payload,
            )
            return payload

        pattern = compute_connection_pattern(
            source_process=str(rows.iloc[0].get("process_name") or ""),
            destination=remote_ip,
            timestamps=list(rows["timestamp"]),
            evidence_ids=tuple(str(e) for e in rows["event_id"]),
        )

        if not pattern.has_measurable_regularity:
            shown_ids, truncated = self._cap(list(pattern.evidence_ids))
            payload: dict[str, Any] = {
                "regular": False,
                "reason": pattern.support_note,
                "samples": pattern.connection_count,
                "interarrival_count": pattern.interarrival_count,
                "event_ids": shown_ids,
            }
            if truncated:
                payload["truncated"] = True
                payload["total"] = len(pattern.evidence_ids)
            self._record(
                "analyse_beacon", {"device": device, "remote_ip": remote_ip}, agent,
                pattern.support_note, tuple(pattern.evidence_ids),
                result=payload, truncated=truncated, shown_event_ids=tuple(shown_ids),
            )
            return payload

        median_seconds = pattern.median_interval.total_seconds()
        shown_ids, truncated = self._cap(list(pattern.evidence_ids))
        payload = {
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
            "event_ids": shown_ids,
        }
        if truncated:
            payload["truncated"] = True
            payload["total"] = len(pattern.evidence_ids)
        self._record(
            "analyse_beacon", {"device": device, "remote_ip": remote_ip}, agent,
            f"{pattern.interarrival_count} intervals, median {median_seconds:.0f}s, "
            f"robust cv {pattern.robust_cv:.3f}, "
            f"{'regular' if pattern.is_regular else 'irregular'}",
            tuple(pattern.evidence_ids),
            result=payload, truncated=truncated, shown_event_ids=tuple(shown_ids),
        )
        return payload

    def search_processes(
        self, device: str | None = None, contains: str | None = None,
        process_name: str | None = None, limit: int = 25, agent: str = "endpoint",
    ) -> dict[str, Any]:
        """Search process telemetry by host, image name, or command-line substring."""
        if self.budget_exhausted:
            return self._refuse(
                "search_processes",
                {"device": device, "contains": contains, "process_name": process_name,
                 **({"limit": limit} if self.ledger else {})},
                agent, {"results": [], "count": 0},
            )
        rows = self.telemetry.processes
        if device:
            rows = rows[rows["device"] == device]
        if process_name:
            rows = rows[rows["process_name"].str.lower() == process_name.lower()]
        if contains:
            rows = rows[rows["command_line"].str.contains(contains, case=False, na=False)]
        rows = rows.sort_values("timestamp")
        total = int(len(rows))
        rows = rows.head(limit)

        results = [
            {
                "event_id": r["event_id"],
                "timestamp": _jsonable(r["timestamp"]),
                "device": r["device"],
                "user": r["user"],
                "process_name": r["process_name"],
                "process_id": int(r["process_id"]) if pd.notna(r["process_id"]) else None,
                # The instance, next to the slot. Without it a caller reading two rows
                # with the same pid cannot tell one process from two.
                "process_guid": _identity_of(r),
                "parent_process_name": r["parent_process_name"],
                "command_line": r["command_line"],
            }
            for r in rows.to_dict("records")
        ]
        shown, truncated = self._cap(results)
        cut = False
        for entry in shown:
            entry["command_line"], text_cut = self._cap_text(entry["command_line"])
            cut = cut or text_cut
        payload: dict[str, Any] = {"results": shown, "count": len(shown)}
        if truncated or total > len(shown):
            payload["total"] = total
        if truncated:
            payload["truncated"] = True
        self._record(
            "search_processes",
            {"device": device, "contains": contains, "process_name": process_name,
             **({"limit": limit} if self.ledger else {})},
            agent, f"{len(results)} match(es)", tuple(r["event_id"] for r in results),
            result=payload, truncated=truncated or cut,
            shown_event_ids=tuple(r["event_id"] for r in shown),
        )
        return payload

    def get_finding(self, finding_id: str, agent: str = "orchestrator") -> dict[str, Any]:
        """Return one detection finding with its evidence and declared caveats."""
        if self.budget_exhausted:
            return self._refuse(
                "get_finding", {"finding_id": finding_id}, agent,
                {"error": "not retrieved"},
            )
        finding = self._findings.get(finding_id)
        if finding is None:
            payload = {"error": f"No such finding {finding_id!r}"}
            self._record("get_finding", {"finding_id": finding_id}, agent, "not found", result=payload)
            return payload
        payload = finding.to_dict()
        self._record(
            "get_finding", {"finding_id": finding_id}, agent,
            f"{finding.rule_id} {finding.severity}", finding.event_ids, result=payload,
        )
        return payload

    def lookup_technique(self, technique_id: str, agent: str = "attack") -> dict[str, Any]:
        """Look up an ATT&CK technique in the verified catalogue."""
        if self.budget_exhausted:
            # The refusal carries ``error`` as well, because that is the key every
            # caller of this tool already branches on: a budget refusal must travel
            # the path an unknown technique already travels, not a new one nobody
            # handles.
            return self._refuse(
                "lookup_technique", {"technique_id": technique_id}, agent,
                {"error": "not retrieved"},
            )
        try:
            technique = get_technique(technique_id)
        except KeyError:
            payload = {"error": f"{technique_id} is not in the verified catalogue"}
            self._record("lookup_technique", {"technique_id": technique_id}, agent, "unknown", result=payload)
            return payload
        payload = {
            "technique_id": technique.technique_id,
            "name": technique.name,
            "tactics": [t.display_name for t in technique.tactics],
            "parent_id": technique.parent_id,
            "url": technique.url,
        }
        self._record(
            "lookup_technique", {"technique_id": technique_id}, agent, technique.name, result=payload,
        )
        return payload


def _sha256_json(payload: Any) -> str:
    """One canonical serialisation -- sorted keys, no spaces -- so two runs of one case
    hash their tool calls identically whatever order a dict was built in."""
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _identity_of(row: Any) -> str:
    """The instance identity a row asserts, or ``""``. Never a guess."""
    value = row.get("process_guid") if hasattr(row, "get") else None
    return "" if value is None or pd.isna(value) else str(value)


def _parent_identity_of(row: Any) -> str:
    value = row.get("parent_process_guid") if hasattr(row, "get") else None
    return "" if value is None or pd.isna(value) else str(value)


def _instances_of(frame: pd.DataFrame, column: str, value: int) -> list[Any]:
    """The distinct process *instances* whose ``column`` holds ``value``.

    Rows that assert the same identity are one instance observed more than once, so they
    collapse; rows that assert different identities are different processes and stay
    apart. Rows that assert nothing cannot be collapsed at all -- two creation events on
    one slot are two runs, and the source simply did not say which is which -- so each
    is its own candidate. Returned earliest first.
    """
    rows = frame[frame[column] == value].sort_values("timestamp")
    if rows.empty:
        return []
    instances: list[Any] = []
    seen_identities: set[str] = set()
    for row in rows.to_dict("records"):
        identity = _identity_of(row)
        if identity:
            if identity in seen_identities:
                continue
            seen_identities.add(identity)
        instances.append(row)
    return instances


def _candidate(row: Any) -> dict[str, Any]:
    """One instance that held an ambiguous slot, with what distinguishes it."""
    return {
        "event_id": row["event_id"],
        "timestamp": _jsonable(row["timestamp"]),
        "process_name": row["process_name"],
        "process_id": int(row["process_id"]) if pd.notna(row["process_id"]) else None,
        "process_guid": _identity_of(row),
        "parent_process_name": row["parent_process_name"],
        "command_line": row["command_line"],
    }


def _ancestry_entry(row: Any, resolved_by: str) -> dict[str, Any]:
    parent_identity = _parent_identity_of(row)
    return {
        "event_id": row["event_id"],
        "timestamp": _jsonable(row["timestamp"]),
        "process_name": row["process_name"],
        "process_id": int(row["process_id"]) if pd.notna(row["process_id"]) else None,
        "process_guid": _identity_of(row),
        "parent_process_name": row["parent_process_name"],
        "parent_process_id": _jsonable(row["parent_process_id"]),
        "parent_process_guid": parent_identity,
        # Whether *naming this row's parent instance* rests on an identity or on the
        # slot. A caller writing "X was started by Y" needs exactly this, and computing
        # it here keeps one rule in one place.
        "parent_resolution": (
            RESOLVED_BY_IDENTITY if parent_identity else INFERRED_FROM_PID
        ),
        "command_line": row["command_line"],
        "user": row["user"],
        "resolved_by": resolved_by,
    }


def _resolve_parent(
    procs: pd.DataFrame, host: pd.DataFrame, row: Any
) -> tuple[Any | None, str, str]:
    """The row of this row's parent instance, how it was found, and what stopped us.

    The identity is tried first and, when the row names one, it is the *only* thing
    tried: a row that says which instance created it has answered the question, and
    picking some other process that holds the parent's number would be inventing an
    answer it did not give. When no row carries that identity the parent simply started
    before the capture did, which is a gap and is reported as one.
    """
    wanted = _parent_identity_of(row)
    if wanted:
        exact = procs[procs["process_guid"].astype("string").fillna("") == wanted]
        if not exact.empty:
            return exact.sort_values("timestamp").iloc[0].to_dict(), RESOLVED_BY_IDENTITY, ""
        return None, "", (
            f"ancestry stopped: {row['process_name']} names a parent instance no row "
            "in this telemetry describes -- it was created before the capture began"
        )

    parent_pid = row["parent_process_id"]
    if pd.isna(parent_pid):
        return None, "", ""
    candidates = _instances_of(host, "process_id", int(parent_pid))
    if not candidates:
        return None, "", ""
    if len(candidates) > 1:
        return None, "", (
            f"ancestry stopped: pid {int(parent_pid)} on {row['device']} was held by "
            f"{len(candidates)} process instances and this row names none of them"
        )
    return candidates[0], INFERRED_FROM_PID, ""


def _children_of(host: pd.DataFrame, row: Any) -> list[dict[str, Any]]:
    """Rows this instance started, each saying how it was attributed to it.

    A child that names its parent instance is matched on that identity. A child that
    names none is matched on ``(device, parent_pid)`` and labelled -- which is most of
    them on most corpora, and all of them on any source that does not write a parent
    GUID.
    """
    identity = _identity_of(row)
    pid = row["process_id"]
    by_identity = host["parent_process_guid"].astype("string").fillna("") == identity
    if not identity:
        by_identity = by_identity & False
    by_pid = host["parent_process_id"] == pid
    rows = host[by_identity | by_pid]

    node = instance_key(identity, row["device"], pid)
    children: list[dict[str, Any]] = []
    for child in rows.sort_values("timestamp").to_dict("records"):
        parent_key = instance_key(
            _parent_identity_of(child), child["device"], child["parent_process_id"]
        )
        if node is None or parent_key is None:
            continue
        joined, inferred = node.joins(parent_key)
        if not joined:
            continue
        children.append({
            "event_id": child["event_id"],
            "timestamp": _jsonable(child["timestamp"]),
            "process_name": child["process_name"],
            "process_id": int(child["process_id"]) if pd.notna(child["process_id"]) else None,
            "process_guid": _identity_of(child),
            "command_line": child["command_line"],
            "resolved_by": INFERRED_FROM_PID if inferred else RESOLVED_BY_IDENTITY,
        })
    return children


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
