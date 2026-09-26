"""Operational-v7's structural benign guard: no benign clearance of a process without its ancestry.

Why this exists
---------------
On the pre-registered holdout (``docs/holdout-v1-windows-results.md``) qwen3.5:9b on
operational-v6 cleared three of six malicious Windows cases as benign. Two were cleared on
the seed command alone, with no probe: deleting a temporary directory and killing a
process look like maintenance in isolation, and the malicious context was in the process
ancestry, which was never requested. A prompt can ask for ancestry; this module makes it
a condition the application enforces, whatever the model was told or answered.

The rule
--------
When a case's seed contains a process-creation record and the model concludes
``benign``, the benign stands only if the investigation retrieved that process's parent.
Otherwise the disposition becomes ``abstain`` and the reason is recorded. The run stays
complete: the model did answer, and the system refused a clearance the evidence it
gathered cannot support. Malicious and abstain are never touched. Seeds with no process
record (control-plane actions, logons) are not guarded, and say so.

What counts as the parent, and as retrieved
-------------------------------------------
* **The parent** is identified by the same rule ``ToolBox.process_tree`` walks with
  (``tools._resolve_parent``). When the seed row names its creator's instance identity,
  every process or network row carrying that identity is the parent -- each records the
  parent's image. When it names none, the parent is the single process instance that
  held the parent pid on that device; an ambiguous pid names no parent.
* **Retrieved** means a tool call that was not refused showed one of those rows during
  the run: its ``shown_event_ids`` when the result was cut, its ``event_ids`` otherwise --
  the same set as :func:`ath.agent.state.shown_ids`. ``process_tree`` returns the
  ancestry, so running it on the seed retrieves the parent when the parent is recorded.
* **The seed row itself never counts**, although it records the parent's name. That name
  is exactly what the seed alone showed in the two cases cleared without a probe.
* A parent with **no record in the telemetry** (it started before the capture) cannot be
  retrieved; the benign is withheld with that reason, stated separately from "no tool
  showed it", so a reader can tell a skipped probe from a gap in the data.

:func:`benign_guard_decision` is pure: the live path (``investigate_operational``) and the
offline replay (``scripts/replay_benign_guard.py``) both call it, so they cannot diverge.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

import pandas as pd

from ath.agent.tools import _identity_of, _parent_identity_of, _resolve_parent
from ath.telemetry.loader import Telemetry

GUARD_VERSION = "benign-guard-v1"
NOT_PROCESS_SEED = "not a process seed"


def seed_ancestry(telemetry: Telemetry, seed_event_ids: Iterable[str]) -> list[dict[str, Any]]:
    """For each process-creation record in the seed: the ids of its parent's records.

    Reads recorded telemetry only -- no labels, no model output. An empty list means the
    seed holds no process record, so the guard does not apply.
    """
    procs = telemetry.processes
    wanted = {str(e) for e in seed_event_ids}
    if procs.empty or not wanted:
        return []
    seeds = procs[procs["event_id"].astype(str).isin(wanted)].sort_values(["timestamp", "event_id"])
    out = []
    for row in seeds.to_dict("records"):
        identity = _parent_identity_of(row)
        host = procs[procs["device"] == row["device"]]
        parent, _, _ = _resolve_parent(procs, host, row)
        parents: set[str] = set()
        if identity:
            parents |= _ids_with_identity(procs, identity)
            parents |= _ids_with_identity(telemetry.network, identity)
        elif parent is not None:
            parents.add(str(parent["event_id"]))
        parents.discard(str(row["event_id"]))
        out.append({
            "event_id": str(row["event_id"]),
            "process_name": _text(row.get("process_name")),
            "parent_process_name": _text(row.get("parent_process_name")),
            "parent_identified_by": "identity" if identity else ("pid" if parent is not None else "none"),
            "parent_event_ids": sorted(parents),
        })
    return out


def _ids_with_identity(frame: pd.DataFrame, identity: str) -> set[str]:
    if frame.empty or "process_guid" not in frame:
        return set()
    return {str(r["event_id"]) for r in frame.to_dict("records") if _identity_of(r) == identity}


def _text(value: Any) -> str:
    return "" if value is None or (not isinstance(value, str) and pd.isna(value)) else str(value)


def retrieved_event_ids(tool_calls: Iterable[Any]) -> frozenset[str]:
    """Ids a tool showed during the run, from ``ToolCall`` objects or their ``to_dict()``.

    The same rule as :func:`ath.agent.state.shown_ids`, readable from a sealed row too.
    """
    ids: set[str] = set()
    for call in tool_calls:
        get = call.get if isinstance(call, Mapping) else lambda k, d=None, c=call: getattr(c, k, d)
        if get("refused", False):
            continue
        ids.update(str(e) for e in (get("shown_event_ids", ()) if get("truncated", False) else get("event_ids", ())))
    return frozenset(ids)


def benign_guard_decision(
    model_disposition: str | None,
    ancestry: Sequence[Mapping[str, Any]],
    retrieved: Iterable[str],
    *,
    complete: bool = True,
) -> dict[str, Any]:
    """Whether to withhold a benign disposition, and why. Pure; records every outcome.

    Args:
        model_disposition: The model's final disposition before any downgrade.
        ancestry: :func:`seed_ancestry` of the case's seed.
        retrieved: :func:`retrieved_event_ids` of the run's tool calls.
        complete: Whether the operational run otherwise completed. An incomplete run is
            already withheld as abstain; the guard then records that and changes nothing.
    """
    if not ancestry:
        return {"version": GUARD_VERSION, "applied": False, "reason": NOT_PROCESS_SEED}
    shown = frozenset(retrieved)
    seeds = [{**dict(s), "parent_retrieved": bool(set(s["parent_event_ids"]) & shown)} for s in ancestry]
    decision: dict[str, Any] = {"version": GUARD_VERSION, "applied": False,
                                "model_disposition": model_disposition, "seeds": seeds}
    if model_disposition != "benign":
        decision["reason"] = (f"model disposition is {model_disposition or 'none'}; "
                              "the guard reviews only benign conclusions")
        return decision
    if not complete:
        decision["reason"] = "run incomplete; the disposition is already withheld as abstain"
        return decision
    missing = [s for s in seeds if not s["parent_retrieved"]]
    if not missing:
        decision["reason"] = "the parent of every seed process was retrieved: " + "; ".join(
            f"{s['process_name'] or '?'} [{s['event_id']}] <- {s['parent_process_name'] or '?'}" for s in seeds)
        return decision
    parts = []
    for s in missing:
        what = f"seed process {s['process_name'] or '?'} [{s['event_id']}]"
        parent = s["parent_process_name"] or "unnamed parent"
        if s["parent_event_ids"]:
            parts.append(f"{what}: no tool showed its parent {parent} during the investigation")
        else:
            parts.append(f"{what}: its parent {parent} has no record in this telemetry, "
                         "so its ancestry could not be established")
    decision.update({"applied": True, "reason": "benign withheld, ancestry not retrieved -- " + "; ".join(parts)})
    return decision


def guard_from_row(state: Mapping[str, Any], telemetry: Telemetry,
                   seed_event_ids: Iterable[str]) -> dict[str, Any]:
    """The guard's decision for a recorded run, from a sealed row's ``state`` dict.

    Uses the row's model disposition, operational outcome and every recorded tool call,
    and the case's own telemetry for the ancestry: the same inputs the live path reads,
    through the same :func:`benign_guard_decision`.
    """
    operational = state["investigation"]["operational"]
    calls = [call for result in state.get("results", ()) for call in result.get("tool_calls", ())]
    return benign_guard_decision(
        operational.get("model_disposition") if operational.get("engine") == "d1" else None,
        seed_ancestry(telemetry, seed_event_ids), retrieved_event_ids(calls),
        complete=operational.get("outcome") == "complete",
    )
