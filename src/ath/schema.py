"""Canonical telemetry schema for Agentic Threat Hunter.

Why this module exists
----------------------
Everything downstream -- hunting queries, MITRE mapping, agent tools, the report --
reads columns by name. If those names are only defined implicitly inside a CSV file,
then a typo in the data generator silently breaks a detection and produces a
*false negative*, which is the worst failure mode in security engineering.

So the schema is declared once, here, and validated on load.

Table design
------------
We deliberately mirror the Microsoft Defender for Endpoint / Microsoft Sentinel
"advanced hunting" schema, which splits telemetry by event type:

    DeviceProcessEvents   ->  process events   (what ran, and what spawned it)
    DeviceNetworkEvents   ->  network events   (who talked to what)
    DeviceLogonEvents     ->  logon events     (who authenticated where)

Keeping the tables separate (rather than one giant flat table) is closer to how real
SIEM data is shaped, and it is what forces us to learn `join` and `union` in KQL.
`unified_columns()` gives us a thin cross-table view for building timelines.
"""

from __future__ import annotations

from typing import Final

import pandas as pd

# --------------------------------------------------------------------------------------
# Event type values (kept as constants so a typo becomes an ImportError, not a bad query)
# --------------------------------------------------------------------------------------

EVENT_PROCESS: Final[str] = "process"
EVENT_NETWORK: Final[str] = "network"
EVENT_LOGON: Final[str] = "logon"
EVENT_CONTROL: Final[str] = "control"

EVENT_TYPES: Final[tuple[str, ...]] = (
    EVENT_PROCESS, EVENT_NETWORK, EVENT_LOGON, EVENT_CONTROL,
)

# --------------------------------------------------------------------------------------
# Core columns: present on EVERY event, regardless of table.
# --------------------------------------------------------------------------------------

CORE_COLUMNS: Final[tuple[str, ...]] = (
    "event_id",    # stable unique id, e.g. "evt-000123". Used for evidence traceability.
    "timestamp",   # UTC, timezone-aware. All correlation is time-based, so this is critical.
    "event_type",  # one of EVENT_TYPES
    "device",      # hostname the event was observed ON (e.g. "PC01")
    "user",        # account context the event ran under (e.g. "jdoe")
    "source",      # which TelemetrySource produced this event, e.g. "synthetic" or
                   # "defender_export". Lets a report or an analyst tell a real,
                   # imported finding apart from a demo/synthetic one at a glance.
    "source_ref",  # free-text pointer back to the original record: for an imported
                   # event, the source file and the vendor's own row identifier (e.g.
                   # Defender's ReportId), so a real investigation can go back to the
                   # raw export. Empty for synthetic data, which has no "original".
)

PROCESS_COLUMNS: Final[tuple[str, ...]] = CORE_COLUMNS + (
    "process_name",         # image name, e.g. "powershell.exe"
    "process_id",           # OS PID
    "command_line",         # full command line -- the single richest detection field
    "parent_process_name",  # what spawned it, e.g. "WINWORD.EXE"
    "parent_process_id",    # parent PID
    "file_path",            # full path on disk of the executed image
    # -- identity, as opposed to name ------------------------------------------------
    # A process name is a *claim* a file makes about itself, and anyone can copy a
    # binary to malware.exe and rename it MsMpEng.exe. Reasoning about trust from the
    # name alone means an attacker inherits the reputation of whatever they imitate.
    # These three columns are what distinguishes a file from its filename.
    "sha256",               # content hash: the only truly stable identifier
    "signer",               # signing organisation, e.g. "Microsoft Corporation"
    "signature_status",     # see SIGNATURE_STATUSES
)

# Authenticode-style signature outcomes, kept as constants so a typo is an ImportError.
#
# `unknown` is not a synonym for `unsigned`, and conflating them is the classic mistake:
# "we did not check" and "we checked and there was no signature" support completely
# different conclusions, and only the latter is evidence about the file.
SIG_VALID: Final[str] = "signed_valid"
SIG_INVALID: Final[str] = "signed_invalid"   # signature present but broken/untrusted
SIG_UNSIGNED: Final[str] = "unsigned"
SIG_UNKNOWN: Final[str] = "unknown"          # not evaluated by this telemetry source

SIGNATURE_STATUSES: Final[tuple[str, ...]] = (
    SIG_VALID, SIG_INVALID, SIG_UNSIGNED, SIG_UNKNOWN,
)

NETWORK_COLUMNS: Final[tuple[str, ...]] = CORE_COLUMNS + (
    "process_name",  # process that opened the connection -- lets us join network -> process
    "process_id",
    "remote_ip",
    "remote_port",
    "protocol",      # "tcp" / "udp"
    "direction",     # "outbound" / "inbound"
    "remote_url",    # populated when the URL was observed; may be empty
)

LOGON_COLUMNS: Final[tuple[str, ...]] = CORE_COLUMNS + (
    "logon_type",      # Windows logon type: 2=interactive, 3=network, 10=RemoteInteractive(RDP)
    "source_ip",       # where the auth attempt came from
    "source_device",   # resolved hostname of source_ip, may be empty
    "action",          # "success" / "failure"
    "failure_reason",  # e.g. "bad_password", empty on success
)

# Cloud/Kubernetes control-plane audit events: an actor performs a verb on a resource,
# allowed or denied. AWS management-API calls (CreateAccessKey, AttachUserPolicy,
# StopLogging, ...) and Kubernetes audit log entries (create/delete/get on pods, secrets,
# RBAC objects, pods/exec, ...) are the same shape at this level of abstraction, which is
# what lets one table -- and one specialist -- serve both. See
# ath.telemetry.cloudtrail_source and ath.telemetry.k8s_audit_source for what maps here.
CONTROL_COLUMNS: Final[tuple[str, ...]] = CORE_COLUMNS + (
    "actor",               # principal that made the call, e.g. an IAM user or k8s user/SA
    # Group memberships the platform asserted for the caller, comma-joined, e.g.
    # "system:masters,system:authenticated" from a Kubernetes audit event's
    # `user.groups`. Carried because a grant's meaning depends on what the grantor
    # already held: `system:masters` is allowed everything before RBAC is consulted,
    # so a cluster-admin binding it creates is administration, not escalation
    # (Kubernetes CI, M14: 55 of 55 K8S-001 findings). Empty when the source asserts
    # no groups (CloudTrail).
    "actor_groups",
    "verb",                # e.g. "create", "delete", "get", "attach", "exec"
    "resource_type",       # e.g. "iam:policy", "rolebindings", "pods/exec"
    "resource_name",       # the specific resource acted upon
    "resource_namespace",  # Kubernetes namespace; empty for cloud (not a cloud concept)
    # -- who a grant targets, as distinct from who performed it ----------------------
    # A grant-shaped action (a Kubernetes RoleBinding, an AWS AttachUserPolicy call)
    # names a *beneficiary* that is frequently a different identity from the caller who
    # created it. Conflating `actor` (the caller) with the beneficiary is the mistake
    # that would make a privilege-escalation chain match the wrong identity's later
    # activity. Left empty for actions with no target identity (StopLogging, pods/exec).
    "target_actor",
    "role_ref",             # the specific role/policy granted, e.g. "cluster-admin" or a
                            # policy ARN. Empty when the action does not grant a role.
    "decision",             # "allowed" / "denied"
    "source_ip",            # caller's address
)

# Columns kept when we `union` all four tables into a single chronological view.
UNIFIED_COLUMNS: Final[tuple[str, ...]] = CORE_COLUMNS + ("summary",)

TABLE_COLUMNS: Final[dict[str, tuple[str, ...]]] = {
    EVENT_PROCESS: PROCESS_COLUMNS,
    EVENT_NETWORK: NETWORK_COLUMNS,
    EVENT_LOGON: LOGON_COLUMNS,
    EVENT_CONTROL: CONTROL_COLUMNS,
}

# Filenames on disk, keyed by event type.
TABLE_FILES: Final[dict[str, str]] = {
    EVENT_PROCESS: "process_events.csv",
    EVENT_NETWORK: "network_events.csv",
    EVENT_LOGON: "logon_events.csv",
    EVENT_CONTROL: "control_events.csv",
}

# Human-readable meaning of Windows logon types. Used by detections and by the
# report writer, because "logon_type 3" means nothing to a reader.
LOGON_TYPE_NAMES: Final[dict[int, str]] = {
    2: "Interactive (console)",
    3: "Network (SMB / share access)",
    4: "Batch (scheduled task)",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials (runas /netonly)",
    10: "RemoteInteractive (RDP)",
    11: "CachedInteractive",
}

# The logon types that arrive from somewhere else. An interactive console logon (2) or
# an unlock (7) happens at the keyboard: there is no source host and no source address
# to record, and a source column empty on such a row is correct rather than missing.
# A network (3) or RemoteInteractive/RDP (10) logon came over the wire, and a source
# column empty on one of those is a real loss of attribution.
#
# Declared here, beside LOGON_TYPE_NAMES, because it is a statement about what the
# canonical `logon_type` codes *mean* -- the same reason the names live here -- and not
# about any rule, source or dataset that reads them.
REMOTE_LOGON_TYPES: Final[frozenset[int]] = frozenset({3, 10})


class SchemaError(ValueError):
    """Raised when a telemetry table does not match the declared schema."""


def validate_frame(df: pd.DataFrame, event_type: str) -> None:
    """Validate that ``df`` conforms to the schema for ``event_type``.

    Fails loudly and early. A detection that silently returns zero rows because a
    column was renamed is far more dangerous than a crash at load time.

    Raises:
        SchemaError: if the event type is unknown, columns are missing, or the
            ``event_type`` column contains unexpected values.
    """
    if event_type not in TABLE_COLUMNS:
        raise SchemaError(f"Unknown event_type {event_type!r}; expected one of {EVENT_TYPES}")

    expected = set(TABLE_COLUMNS[event_type])
    actual = set(df.columns)

    missing = expected - actual
    if missing:
        raise SchemaError(
            f"{event_type} table is missing required columns: {sorted(missing)}"
        )

    unexpected = actual - expected
    if unexpected:
        raise SchemaError(
            f"{event_type} table has unexpected columns: {sorted(unexpected)}"
        )

    if not df.empty:
        bad_types = set(df["event_type"].unique()) - {event_type}
        if bad_types:
            raise SchemaError(
                f"{event_type} table contains foreign event_type values: {sorted(bad_types)}"
            )

        if df["event_id"].duplicated().any():
            dupes = df.loc[df["event_id"].duplicated(), "event_id"].tolist()[:5]
            raise SchemaError(f"{event_type} table has duplicate event_ids, e.g. {dupes}")


def describe_logon_type(logon_type: int | float | None) -> str:
    """Return a human-readable name for a Windows logon type code."""
    if logon_type is None or pd.isna(logon_type):
        return "Unknown"
    return LOGON_TYPE_NAMES.get(int(logon_type), f"Type {int(logon_type)}")
