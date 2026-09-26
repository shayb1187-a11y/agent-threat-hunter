"""Read-only control-plane tools for operational-v6 investigations.

The first real-data assessment offered D1 only Windows probes on Kubernetes cases
(``user_auth_history``, ``host_network_activity``), which cannot see control-plane
activity; its abstentions there measured missing tools, not reasoning. These tools read
the canonical ``control`` table (Kubernetes audit, CloudTrail management events).

They are deliberately **not** :class:`~ath.agent.tools.ToolBox` methods: the ToolBox
method set is the frozen M19 tool surface (``tool_surface`` hashes it). This class wraps
a ToolBox by composition and uses its bookkeeping, so every call shares the same budget,
row and character caps, refusals and ledger digests, and lands in the same
``ToolBox.calls`` audit trail.

Payload keys use plain words (``namespace``, ``subject``, ``role``, ``result``) rather
than canonical column names, because rendered prompts must keep the prompt contract
(:mod:`ath.agent.contract`).
"""

from __future__ import annotations

from collections import Counter
from typing import Any

import pandas as pd

from ath.agent.tools import ToolBox, _jsonable
from ath.control_vocab import is_grant

TOOL_NAMES = ("actor_control_history", "resource_control_history", "identity_grants")
USE_RESOURCES = frozenset({"pods/exec", "pods/attach", "secrets", "serviceaccounts/token"})


def _text(value: Any) -> str:
    return "" if value is None or (not isinstance(value, str) and pd.isna(value)) else str(value).strip()


class ControlPlaneTools:
    """Three read-only views of control-plane activity, recorded in the ToolBox ledger."""

    def __init__(self, toolbox: ToolBox) -> None:
        self.box = toolbox

    # -- helpers --------------------------------------------------------------------

    def _controls(self) -> pd.DataFrame:
        return self.box.telemetry.controls

    def _event(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "event_id": str(row["event_id"]),
            "timestamp": _jsonable(row["timestamp"]),
            "actor": _text(row.get("actor")),
            "verb": _text(row.get("verb")),
            "resource_type": _text(row.get("resource_type")),
            "resource_name": _text(row.get("resource_name")),
            "namespace": _text(row.get("resource_namespace")),
            "subject": _text(row.get("target_actor")),
            "role": _text(row.get("role_ref")),
            "result": _text(row.get("decision")),
            "source_ip": _text(row.get("source_ip")),
        }

    def _finish(self, tool: str, arguments: dict[str, Any], agent: str, frame: pd.DataFrame,
                summary: dict[str, Any], empty_note: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        rows = frame.sort_values(["timestamp", "event_id"]).to_dict("records")
        events = [self._event(r) for r in rows]
        if not events:
            payload = {**arguments, "events": [], "summary": {}, **(extra or {})}
            self.box._record(tool, arguments, agent, empty_note, result=payload)
            return payload
        shown, truncated = self.box._cap(events)
        payload = {**arguments, "summary": summary, "events": shown, **(extra or {})}
        if truncated:
            payload["truncated"] = True
            payload["total"] = len(events)
        self.box._record(
            tool, arguments, agent, f"{len(events)} control events",
            tuple(e["event_id"] for e in events), result=payload, truncated=truncated,
            shown_event_ids=tuple(e["event_id"] for e in shown),
        )
        return payload

    @staticmethod
    def _counts(frame: pd.DataFrame, column: str) -> dict[str, int]:
        return dict(sorted(Counter(_text(v) or "?" for v in frame[column]).items()))

    def _span(self, frame: pd.DataFrame) -> dict[str, Any]:
        return {"total": int(len(frame)), "first_seen": _jsonable(frame["timestamp"].min()),
                "last_seen": _jsonable(frame["timestamp"].max())}

    # -- tools ----------------------------------------------------------------------

    def actor_control_history(self, actor: str, agent: str = "control_plane") -> dict[str, Any]:
        """Every control-plane action this identity performed: what, on what, and the result."""
        arguments = {"actor": actor}
        if self.box.budget_exhausted:
            return self.box._refuse("actor_control_history", arguments, agent, {**arguments, "events": [], "summary": {}})
        controls = self._controls()
        frame = controls[controls["actor"].astype(str) == actor] if not controls.empty else controls
        summary = {} if frame.empty else {
            **self._span(frame), "verbs": self._counts(frame, "verb"),
            "resources": self._counts(frame, "resource_type"), "results": self._counts(frame, "decision"),
            "source_ips": sorted({_text(v) for v in frame["source_ip"] if _text(v)}),
        }
        return self._finish("actor_control_history", arguments, agent, frame, summary,
                            "no control-plane activity for this identity")

    def resource_control_history(self, resource_type: str, name: str, namespace: str = "",
                                 agent: str = "control_plane") -> dict[str, Any]:
        """Every control-plane action on one object, by any identity."""
        arguments = {"resource_type": resource_type, "name": name, "namespace": namespace}
        if self.box.budget_exhausted:
            return self.box._refuse("resource_control_history", arguments, agent, {**arguments, "events": [], "summary": {}})
        controls = self._controls()
        frame = controls
        if not controls.empty:
            keep = (controls["resource_type"].astype(str) == resource_type) & (controls["resource_name"].astype(str) == name)
            if namespace:
                keep &= controls["resource_namespace"].astype(str) == namespace
            frame = controls[keep]
        summary = {} if frame.empty else {
            **self._span(frame), "actors": self._counts(frame, "actor"), "verbs": self._counts(frame, "verb"),
            "results": self._counts(frame, "decision"),
        }
        return self._finish("resource_control_history", arguments, agent, frame, summary,
                            "no control-plane activity on this object")

    def identity_grants(self, identity: str, agent: str = "control_plane") -> dict[str, Any]:
        """Permissions granted to an identity, and that identity's later exec or secret use."""
        arguments = {"identity": identity}
        if self.box.budget_exhausted:
            return self.box._refuse("identity_grants", arguments, agent,
                                    {**arguments, "events": [], "summary": {}, "grants": 0, "later_use": 0})
        controls = self._controls()
        if controls.empty:
            return self._finish("identity_grants", arguments, agent, controls, {},
                                "no control-plane telemetry", {"grants": 0, "later_use": 0})
        grant_shaped = [is_grant(_text(v), _text(r)) for v, r in zip(controls["verb"], controls["resource_type"])]
        grants = controls[pd.Series(grant_shaped, index=controls.index) & (controls["target_actor"].astype(str) == identity)]
        use = controls[(controls["actor"].astype(str) == identity)
                       & controls["resource_type"].astype(str).isin(USE_RESOURCES)]
        if not grants.empty:
            use = use[pd.to_datetime(use["timestamp"], utc=True) >= pd.to_datetime(grants["timestamp"], utc=True).min()]
        frame = pd.concat([grants, use]).drop_duplicates("event_id")
        summary = {} if frame.empty else {
            **self._span(frame), "roles_granted": sorted({_text(v) for v in grants["role_ref"] if _text(v)}),
            "granted_by": sorted({_text(v) for v in grants["actor"] if _text(v)}),
            "later_use_resources": self._counts(use, "resource_type") if not use.empty else {},
        }
        return self._finish("identity_grants", arguments, agent, frame, summary,
                            "no grants to this identity and no later use",
                            {"grants": int(len(grants)), "later_use": int(len(use))})
