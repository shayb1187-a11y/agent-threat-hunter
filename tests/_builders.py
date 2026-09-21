"""Row builders for constructing small canonical telemetry sets in tests.

Every builder writes the *canonical* schema (what an adapter emits), so a test that uses
them is testing a rule against rows it could really receive. Tests that need the adapter
path itself use the real-shaped fixtures under ``tests/fixtures/real_shaped`` instead.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pandas as pd

from ath.schema import (
    EVENT_CONTROL,
    EVENT_LOGON,
    EVENT_NETWORK,
    EVENT_PROCESS,
    SIG_UNKNOWN,
    TABLE_COLUMNS,
)
from ath.telemetry.loader import Telemetry
from ath.telemetry.normalize import coerce_and_validate

T0 = datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc)


def at(minutes: float = 0, seconds: float = 0) -> datetime:
    return T0 + timedelta(minutes=minutes, seconds=seconds)


_counter = {"n": 0}


def _eid(prefix: str) -> str:
    _counter["n"] += 1
    return f"{prefix}-{_counter['n']:06d}"


def proc(name: str, cmd: str, parent: str, *, device: str = "PC01", user: str = "jdoe",
         when: datetime | None = None, pid: int | None = None, ppid: int = 1000,
         path: str | None = None, sha256: str = "", signer: str = "",
         signature_status: str = SIG_UNKNOWN, source: str = "test",
         guid: str = "", parent_guid: str = "") -> dict[str, Any]:
    """One canonical process row.

    ``guid`` / ``parent_guid`` are this instance's and its creator's
    :mod:`process-instance identities <ath.instance_identity>`, already minted (by
    ``start_identity`` or ``sysmon_identity``) so a test can say exactly which authority
    asserted them. They default to ``""`` -- the honest default, because most sources
    assert nothing, and because it keeps every test written before identities existed
    exercising the same pid fallback it always did.
    """
    pid = pid if pid is not None else 4000 + _counter["n"]
    return {
        "event_id": _eid("p"), "timestamp": when or at(), "event_type": EVENT_PROCESS,
        "device": device, "user": user, "source": source, "source_ref": "",
        "process_name": name, "process_id": pid, "command_line": cmd,
        "parent_process_name": parent, "parent_process_id": ppid,
        "file_path": path or f"C:\\Windows\\System32\\{name}", "sha256": sha256,
        "signer": signer, "signature_status": signature_status,
        "process_guid": guid, "parent_process_guid": parent_guid,
    }


def net(process: str, remote_ip: str, port: int = 443, *, device: str = "PC01",
        user: str = "jdoe", when: datetime | None = None, pid: int = 4000,
        protocol: str = "tcp", direction: str = "outbound", url: str = "",
        guid: str = "") -> dict[str, Any]:
    """One canonical network row.

    ``guid`` is the identity of the instance that opened the connection, where the
    source asserted one (Sysmon writes ``ProcessGuid`` on event 3 as well as event 1).
    Never derived here from the row's own timestamp: a connection's time is when the
    socket opened, not when the process started.
    """
    return {
        "event_id": _eid("n"), "timestamp": when or at(), "event_type": EVENT_NETWORK,
        "device": device, "user": user, "source": "test", "source_ref": "",
        "process_name": process, "process_id": pid, "remote_ip": remote_ip,
        "remote_port": port, "protocol": protocol, "direction": direction,
        "remote_url": url, "process_guid": guid,
    }


def logon(user: str, device: str, *, logon_type: int | None = 3, source_ip: str = "",
          source_device: str = "", action: str = "success", failure_reason: str = "",
          when: datetime | None = None) -> dict[str, Any]:
    return {
        "event_id": _eid("l"), "timestamp": when or at(), "event_type": EVENT_LOGON,
        "device": device, "user": user, "source": "test", "source_ref": "",
        "logon_type": logon_type if logon_type is not None else pd.NA,
        "source_ip": source_ip, "source_device": source_device, "action": action,
        "failure_reason": failure_reason,
    }


def ctrl(actor: str, verb: str, resource_type: str, resource_name: str, *,
         target_actor: str = "", role_ref: str = "", namespace: str = "",
         decision: str = "allowed", device: str = "k8s:c1", source_ip: str = "10.0.0.1",
         when: datetime | None = None, source: str = "k8s_audit",
         actor_groups: str = "") -> dict[str, Any]:
    return {
        "event_id": _eid("c"), "timestamp": when or at(), "event_type": EVENT_CONTROL,
        "device": device, "user": target_actor or actor, "source": source, "source_ref": "",
        "actor": actor, "actor_groups": actor_groups, "verb": verb, "resource_type": resource_type,
        "resource_name": resource_name, "resource_namespace": namespace,
        "target_actor": target_actor, "role_ref": role_ref, "decision": decision,
        "source_ip": source_ip,
    }


def _frame(rows: list[dict[str, Any]], event_type: str) -> pd.DataFrame:
    return coerce_and_validate(
        pd.DataFrame(rows, columns=list(TABLE_COLUMNS[event_type])), event_type,
    )


def telemetry(procs: list[dict] = (), nets: list[dict] = (), logons: list[dict] = (),
              ctrls: list[dict] = ()) -> Telemetry:
    return Telemetry(
        processes=_frame(list(procs), EVENT_PROCESS),
        network=_frame(list(nets), EVENT_NETWORK),
        logons=_frame(list(logons), EVENT_LOGON),
        controls=_frame(list(ctrls), EVENT_CONTROL),
    )


def failures(user: str, device: str, source_ip: str, count: int, *, start_minute: float = 0,
             spacing_seconds: float = 20, reason: str = "bad_password") -> list[dict]:
    return [
        logon(user, device, logon_type=3, source_ip=source_ip, action="failure",
              failure_reason=reason, when=at(start_minute, i * spacing_seconds))
        for i in range(count)
    ]
