"""Telemetry channels: what this deployment can and cannot see.

Why this module exists
----------------------
Every layer built so far answers "what happened?". None of them can answer "what
could we not have seen?" -- and in security those are different questions with very
different consequences::

    "No suspicious DNS activity was detected."
    "There is no DNS telemetry, so whether suspicious DNS activity occurred is unknown."

The first is a finding. The second is a gap. A system that renders the second as the
first is not merely incomplete, it is misleading -- it converts blindness into
reassurance, which is the most expensive mistake a detection platform can make.

A :class:`TelemetryChannel` is a *kind* of observation, named independently of any
vendor: process execution, authentication, DNS, cloud control plane. The canonical
schema (:mod:`ath.schema`) implements some of them and has no representation at all
for others. Both facts are worth reporting, and they are different:

``ABSENT_BY_SCHEMA``
    This project's canonical schema cannot carry this channel. No import, however
    complete, would populate it. Closing this gap is a schema change.

``ABSENT_IN_DATA``
    The schema can carry it, but this particular dataset contains none of it. Closing
    this gap is an ingestion or configuration change, not a code change.

``PARTIAL``
    Present but sparsely populated -- the most dangerous state, because a rule
    reading the field will run, produce few findings, and look like it worked. This
    dataset's ``remote_url`` is populated on well under 1% of network events; a
    URL-based detection would silently be near-blind rather than obviously broken.

``AVAILABLE``
    Populated well enough to build on.

Nothing here infers, guesses, or asks a model. Channel state is counted directly off
the loaded tables, which is what makes it usable as ground truth for the coverage
analysis in :mod:`ath.environment.coverage`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

# Re-exported so existing imports keep working; the single definition lives in
# ath.channels, which ath.behavior can reach without pulling in the hunting layer.
from ath.channels import TelemetryChannel
from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS
from ath.telemetry.loader import Telemetry


class ChannelState(str, Enum):
    """How well a channel is covered in a given dataset."""

    AVAILABLE = "available"
    PARTIAL = "partial"
    ABSENT_IN_DATA = "absent_in_data"
    ABSENT_BY_SCHEMA = "absent_by_schema"

    @property
    def usable(self) -> bool:
        """Whether a detection may depend on this channel and be trusted."""
        return self is ChannelState.AVAILABLE

    @property
    def observable(self) -> bool:
        """Whether any signal at all exists -- partial counts, absent does not."""
        return self in (ChannelState.AVAILABLE, ChannelState.PARTIAL)


@dataclass(frozen=True)
class ChannelSpec:
    """What a channel means, and how its presence is measured.

    Attributes:
        channel: The channel being described.
        description: What an analyst gets from having it.
        evidence_columns: ``(event_type, column)`` pairs in the canonical schema whose
            population evidences this channel. **Empty means the canonical schema has
            no representation for this channel at all** -- the channel is then
            ``ABSENT_BY_SCHEMA`` regardless of what any dataset contains.
        closes_gap_by: How this gap would actually be closed, in operational terms.
            Recorded because "you lack DNS telemetry" is only actionable alongside
            "onboard a DNS resolver log source".
        partial_threshold: Fraction of rows that must carry a value before the channel
            counts as ``AVAILABLE`` rather than ``PARTIAL``.
    """

    channel: TelemetryChannel
    description: str
    evidence_columns: tuple[tuple[str, str], ...] = ()
    closes_gap_by: str = ""
    partial_threshold: float = 0.5


# --------------------------------------------------------------------------------------
# The channel catalogue.
#
# Channels with no `evidence_columns` are here *precisely because* this project cannot
# see them. Listing only what we have would make the visibility report a restatement of
# the schema; the absences are the informative half.
# --------------------------------------------------------------------------------------

CHANNEL_SPECS: tuple[ChannelSpec, ...] = (
    ChannelSpec(
        channel=TelemetryChannel.PROCESS_EXECUTION,
        description="Which executables ran, on which host, under which account.",
        evidence_columns=((EVENT_PROCESS, "process_name"),),
        closes_gap_by="onboard endpoint process telemetry (EDR or Sysmon event 1)",
    ),
    ChannelSpec(
        channel=TelemetryChannel.PROCESS_COMMAND_LINE,
        description="Full command lines -- the single richest endpoint detection field.",
        evidence_columns=((EVENT_PROCESS, "command_line"),),
        closes_gap_by="enable command-line auditing (Windows 4688 with command line, or EDR)",
    ),
    ChannelSpec(
        channel=TelemetryChannel.PROCESS_LINEAGE,
        description="Parent/child relationships, which turn isolated executions into chains.",
        evidence_columns=((EVENT_PROCESS, "parent_process_name"),),
        closes_gap_by="ensure the process source records parent image and PID",
    ),
    ChannelSpec(
        channel=TelemetryChannel.HANDLE_ACCESS,
        description=(
            "Process-to-process handle requests, e.g. opening LSASS with memory-read "
            "rights. Catches credential dumping that produces no suspicious command line."
        ),
        closes_gap_by="onboard Sysmon event 10 (ProcessAccess) or equivalent EDR telemetry",
    ),
    ChannelSpec(
        channel=TelemetryChannel.NETWORK_FLOW,
        description="Connections between a host process and a remote address.",
        evidence_columns=((EVENT_NETWORK, "remote_ip"),),
        closes_gap_by="onboard endpoint or firewall network telemetry",
    ),
    ChannelSpec(
        channel=TelemetryChannel.NETWORK_INBOUND,
        description=(
            "Connections *toward* monitored hosts. Required to reason about externally "
            "exposed services and inbound exploitation."
        ),
        # Deliberately measured by a value, not a column: `direction` is always
        # populated, so column-presence alone would wrongly report this as available.
        evidence_columns=((EVENT_NETWORK, "direction:inbound"),),
        closes_gap_by="collect inbound flows (firewall, load balancer, or NSG logs)",
        partial_threshold=0.01,
    ),
    ChannelSpec(
        channel=TelemetryChannel.NETWORK_URL,
        description="The requested URL, not merely the destination address.",
        evidence_columns=((EVENT_NETWORK, "remote_url"),),
        closes_gap_by="onboard web proxy or TLS-inspecting gateway logs",
    ),
    ChannelSpec(
        channel=TelemetryChannel.DNS_QUERY,
        description=(
            "Name resolution requests. Without it, DNS tunnelling and domain-based C2 "
            "are not merely undetected -- they are unobservable."
        ),
        closes_gap_by="onboard DNS resolver logs or Sysmon event 22",
    ),
    ChannelSpec(
        channel=TelemetryChannel.AUTHENTICATION,
        description="Logon successes and failures, with logon type.",
        evidence_columns=((EVENT_LOGON, "action"),),
        closes_gap_by="onboard domain controller and endpoint authentication logs",
    ),
    ChannelSpec(
        channel=TelemetryChannel.AUTH_SOURCE_ATTRIBUTION,
        description=(
            "Where an authentication came *from*. This is what makes lateral movement "
            "visible as movement rather than as unrelated logons."
        ),
        # Two alternatives, not two requirements. A resolved source hostname is richer,
        # but a source IP is genuine attribution too -- and CloudTrail records only the
        # latter. Requiring `source_device` alone declared this channel absent for
        # cloud telemetry, which then declared ATH-005 unsupported... while ATH-005 was
        # in fact firing correctly on that very data. A visibility model that
        # contradicts observed behaviour is worse than none.
        evidence_columns=((EVENT_LOGON, "source_device"), (EVENT_LOGON, "source_ip")),
        closes_gap_by="ensure the authentication source records originating host or IP",
    ),
    ChannelSpec(
        channel=TelemetryChannel.FILE_EVENTS,
        description="File creation, modification and deletion.",
        closes_gap_by="onboard file system telemetry (Sysmon events 11/23, or EDR)",
    ),
    ChannelSpec(
        channel=TelemetryChannel.REGISTRY,
        description="Registry key and value changes -- most Windows persistence lives here.",
        closes_gap_by="onboard registry telemetry (Sysmon events 12-14, or EDR)",
    ),
    ChannelSpec(
        channel=TelemetryChannel.SCRIPT_BLOCK,
        description=(
            "Deobfuscated script content as executed. Sees through encoding that a "
            "command line only hints at, including multi-stage and in-memory payloads."
        ),
        closes_gap_by="enable PowerShell script block logging (event 4104)",
    ),
    ChannelSpec(
        channel=TelemetryChannel.EMAIL,
        description="Message delivery metadata -- sender, recipient, attachment, verdict.",
        closes_gap_by="onboard email gateway telemetry",
    ),
    ChannelSpec(
        channel=TelemetryChannel.CLOUD_CONTROL_PLANE,
        description=(
            "Cloud control-plane authentication: console logins, role assumption, "
            "session tokens. NOTE this channel covers the authentication subset only. "
            "Management API activity (CreateAccessKey, AttachUserPolicy, StopLogging) "
            "is a separate channel -- see CLOUD_MANAGEMENT_ACTIVITY below -- because "
            "forcing it into the process table would manufacture endpoint visibility "
            "that does not exist; see ath.telemetry.cloudtrail_source."
        ),
        # Evidenced by provenance rather than by a column: cloud authentication lands
        # in the ordinary logon table, so only the `source` value distinguishes it from
        # a Windows logon. This reuses the same "column:value" measurement the inbound
        # network channel needs, for the same reason -- presence of the column proves
        # nothing about presence of the signal.
        evidence_columns=((EVENT_LOGON, "source:cloudtrail"),),
        closes_gap_by="onboard AWS CloudTrail, Azure Activity, or GCP Audit Logs",
        partial_threshold=0.01,
    ),
    ChannelSpec(
        channel=TelemetryChannel.CLOUD_MANAGEMENT_ACTIVITY,
        description=(
            "Cloud management-plane API activity: IAM policy changes, access key "
            "creation, logging configuration changes, and similar account/resource "
            "mutations -- as distinct from authentication (CLOUD_CONTROL_PLANE above). "
            "This is what closes the gap ath.telemetry.cloudtrail_source used to "
            "document as unmappable."
        ),
        evidence_columns=((EVENT_CONTROL, "source:cloudtrail_mgmt"),),
        closes_gap_by="onboard AWS CloudTrail (management events), Azure Activity, or GCP Audit Logs",
        partial_threshold=0.01,
    ),
    ChannelSpec(
        channel=TelemetryChannel.CONTAINER_AUDIT,
        description="Kubernetes API server audit events and container runtime activity.",
        evidence_columns=((EVENT_CONTROL, "source:k8s_audit"),),
        closes_gap_by="onboard Kubernetes audit logs and a container runtime sensor",
        partial_threshold=0.01,
    ),
)

CHANNEL_SPEC_BY_NAME: dict[TelemetryChannel, ChannelSpec] = {
    spec.channel: spec for spec in CHANNEL_SPECS
}


@dataclass(frozen=True)
class ChannelAssessment:
    """The measured state of one channel in one dataset.

    Attributes:
        spec: The channel definition this assesses.
        state: Measured availability.
        populated_rows: Rows carrying a usable value.
        total_rows: Rows in the underlying table(s).
        detail: One-line explanation of the measurement.
    """

    spec: ChannelSpec
    state: ChannelState
    populated_rows: int = 0
    total_rows: int = 0
    detail: str = ""

    @property
    def channel(self) -> TelemetryChannel:
        return self.spec.channel

    @property
    def coverage(self) -> float:
        """Fraction of rows carrying a value; 0.0 when nothing was measurable."""
        return 0.0 if not self.total_rows else self.populated_rows / self.total_rows

    def to_dict(self) -> dict[str, Any]:
        return {
            "channel": self.channel.value,
            "state": self.state.value,
            "description": self.spec.description,
            "populated_rows": self.populated_rows,
            "total_rows": self.total_rows,
            "coverage": round(self.coverage, 4),
            "detail": self.detail,
            "closes_gap_by": self.spec.closes_gap_by,
        }

    def __str__(self) -> str:
        return f"{self.channel.value}: {self.state.value} -- {self.detail}"


def _count_populated(telemetry: Telemetry, event_type: str, column: str) -> tuple[int, int]:
    """Count rows carrying a usable value for one canonical column.

    Supports a ``"column:value"`` form so a channel can be evidenced by a specific
    *value* rather than by mere column presence -- ``direction:inbound`` is the case
    that forces this: the column is always populated, so counting non-empty cells
    would report inbound visibility as complete when there is none.
    """
    df = telemetry.table(event_type)
    total = len(df)
    if total == 0:
        return 0, 0

    if ":" in column:
        column, required_value = column.split(":", 1)
        if column not in df.columns:
            return 0, total
        return int((df[column].astype("string") == required_value).sum()), total

    if column not in df.columns:
        return 0, total

    series = df[column]
    if series.dtype.name in ("Int64", "int64", "float64"):
        return int(series.notna().sum()), total
    filled = series.astype("string").fillna("")
    return int((filled.str.len() > 0).sum()), total


def assess_channel(telemetry: Telemetry, spec: ChannelSpec) -> ChannelAssessment:
    """Measure one channel against loaded telemetry."""
    if not spec.evidence_columns:
        return ChannelAssessment(
            spec=spec,
            state=ChannelState.ABSENT_BY_SCHEMA,
            detail=(
                "the canonical schema has no representation for this channel; "
                f"{spec.closes_gap_by}"
            ),
        )

    # Multiple evidence columns are ALTERNATIVES, not requirements -- the channel is as
    # available as its best available source. Summing them would penalise a source that
    # populates one of two equivalent fields: with `source_device` empty and `source_ip`
    # complete, a sum reports 50% coverage and grades genuine attribution as "partial".
    populated = 0
    total = 0
    best_coverage = -1.0
    for event_type, column in spec.evidence_columns:
        got, rows = _count_populated(telemetry, event_type, column)
        coverage = (got / rows) if rows else 0.0
        if coverage > best_coverage:
            best_coverage, populated, total = coverage, got, rows

    if total == 0:
        return ChannelAssessment(
            spec=spec, state=ChannelState.ABSENT_IN_DATA, total_rows=0,
            detail="the supporting table is empty in this dataset",
        )

    coverage = populated / total
    if populated == 0:
        state = ChannelState.ABSENT_IN_DATA
        detail = (
            f"the schema supports this channel but no row carries a value "
            f"(0 of {total}); {spec.closes_gap_by}"
        )
    elif coverage < spec.partial_threshold:
        state = ChannelState.PARTIAL
        detail = (
            f"only {populated} of {total} rows ({coverage:.1%}) carry a value -- "
            "a detection reading this field would run but see very little"
        )
    else:
        state = ChannelState.AVAILABLE
        detail = f"{populated} of {total} rows ({coverage:.1%}) carry a value"

    return ChannelAssessment(
        spec=spec, state=state, populated_rows=populated, total_rows=total, detail=detail,
    )


def assess_channels(telemetry: Telemetry) -> dict[TelemetryChannel, ChannelAssessment]:
    """Measure every known channel against loaded telemetry."""
    return {spec.channel: assess_channel(telemetry, spec) for spec in CHANNEL_SPECS}
