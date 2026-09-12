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

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

import pandas as pd

# Re-exported so existing imports keep working; the single definition lives in
# ath.channels, which ath.behavior can reach without pulling in the hunting layer.
from ath.channels import TelemetryChannel
from ath.control_vocab import is_identity_grant
from ath.schema import (
    EVENT_CONTROL,
    EVENT_LOGON,
    EVENT_NETWORK,
    EVENT_PROCESS,
    REMOTE_LOGON_TYPES,
    TABLE_COLUMNS,
)
from ath.telemetry.loader import Telemetry

DEFAULT_PARTIAL_THRESHOLD: float = 0.5
"""Fraction of rows that must carry a value before a measurement counts as complete.

Declared once, here, because it is the boundary between "present" and "present but
too sparse to rely on" for *both* measurements built on it: a channel's
``PARTIAL``/``AVAILABLE`` split (:class:`ChannelSpec.partial_threshold`, whose default
this is) and a rule's ``DEGRADED`` verdict over individual fields
(:mod:`ath.environment.coverage`). Two copies of the same threshold would let the
channel view and the field view disagree about the same column.
"""


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
    partial_threshold: float = DEFAULT_PARTIAL_THRESHOLD


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


def _populated_in(df: pd.DataFrame, column: str) -> tuple[int, int]:
    """``(populated, rows)`` for one column of one frame.

    Split out from :func:`_count_populated` so the same definition of "carries a usable
    value" applies whether the frame is a whole table or the subset of it a column
    applies to (:data:`FIELD_APPLICABILITY`). Two definitions would let the raw fraction
    and the applicable fraction disagree about the same cell.

    Supports a ``"column:value"`` form so a channel can be evidenced by a specific
    *value* rather than by mere column presence -- ``direction:inbound`` is the case
    that forces this: the column is always populated, so counting non-empty cells
    would report inbound visibility as complete when there is none.
    """
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


def _count_populated(telemetry: Telemetry, event_type: str, column: str) -> tuple[int, int]:
    """Count rows of a whole canonical table carrying a usable value for one column.

    Whole-table on purpose: this is what the *channel* view needs. "Is there any
    authentication telemetry here" is a question about the dataset, and narrowing it to
    the rows some column applies to would answer a different question.
    """
    return _populated_in(telemetry.table(event_type), column)


# --------------------------------------------------------------------------------------
# Applicability: the rows a column can legitimately carry a value on.
#
# The defect this exists for is the mirror image of the one per-field population was
# built to catch. M18-3 made every CloudTrail management call a control row, and
# `target_actor` -- a column only a grant can fill -- went from 0.6% of 96 rows to 0.6%
# of 1,857,154. The measurement was correct and the conclusion ("AWS-001 is blind on
# flaws.cloud") was false: among the 132 grant-shaped rows in that trail, target_actor
# and role_ref are populated. Reporting blindness that does not exist spends the same
# trust as hiding blindness that does.
#
# WHERE THIS LIVES, AND WHY HERE
# -------------------------------
# Applicability is a property of the canonical schema -- failure_reason is empty on a
# successful logon by the schema's own definition of the column, not because of anything
# a rule does. The natural home is therefore ath.schema, and the piece of it that needs
# no other module does live there (REMOTE_LOGON_TYPES, beside LOGON_TYPE_NAMES).
#
# The predicates themselves cannot. Deciding whether a control row granted authority to
# an identity needs ath.control_vocab.is_identity_grant, and ath.schema may import nothing
# of the sort without inverting the dependency direction
# schema -> telemetry -> behavior -> environment. So the table is declared here, in the
# module that performs the population measurement -- one declaration, immediately above
# its only consumer -- and reads the same leaf vocabulary the *adapters* read when they
# populate those columns. That shared predicate is the point: a column filled on one set
# of rows and graded over another is a measurement of nothing.
#
# What it may never be is a property of a detector. A rule that chose its own denominator
# could make itself look usable by narrowing the rows it is judged on, which is precisely
# the reassurance this project exists to refuse. Detector has no applicability attribute,
# and a test asserts that none appears.
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class FieldApplicability:
    """Which rows a canonical column can legitimately carry a value on.

    Attributes:
        applies_to: Given the table, a boolean mask of the rows the column applies to.
            Vectorised, because it runs over every row of a multi-million-row table.
        reason: What those rows have in common, in one clause, for the line a reader
            sees when a dataset contains none of them.
    """

    applies_to: Callable[[pd.DataFrame], "pd.Series"]
    reason: str


_PAIR_SEPARATOR = "\x1f"
"""Joins two canonical column values into one key.

ASCII unit separator: the character whose job this is, it cannot occur in a verb or a
resource type, and so two distinct pairs cannot collide into one key. NUL would be the
other obvious choice and is unusable -- pandas' string concatenation silently drops it,
which would collide every pair into one."""


def _identity_grants(df: pd.DataFrame) -> pd.Series:
    """Control rows on which the source model *guarantees* a beneficiary and a role.

    Decided by :func:`ath.control_vocab.is_identity_grant`, evaluated once per distinct
    ``(verb, resource_type)`` pair rather than once per row: a real trail carries 1.9M
    rows and a few hundred distinct pairs.

    A denominator is a claim about what must exist, and only a guarantee can support one.
    Every call by which the identity service moves a permission names the principal it
    moves it to and what was moved; every RBAC binding creation names its subjects and
    its ``roleRef``. An empty column on such a row is therefore a loss, and grading it is
    fair.

    Neither of the two wider predicates can be that denominator:

    * ``is_grant`` alone admits attaching a storage volume to an instance -- 42 of the
      132 grant-shaped rows on flaws.cloud -- which names no identity at all.
    * ``changes_authority``, which this was between M18-5 and M18-6, admits every create
      and delete of a policy object. On the attack_data_aws capture that is 146 of the
      146 rows in the denominator (116 policy deletes, 20 credential-report generates, 10
      policy creates) and not one of them can name a principal, because a policy is not a
      principal. AWS-001 was reported UNUSABLE there on a corpus that contains no
      evidence either way -- the same false report of blindness M18-4 removed, arriving
      one predicate later.

    The rows this excludes are still *filled* by the adapters, whose fill condition
    remains ``changes_authority``: a ``DeleteUser`` still records the user it deleted.
    What the excluded rows never do again is grade a rule. Their emptiness is not
    inferred from this measurement either -- the adapter counts it directly, with a
    reason, on :attr:`ath.telemetry.source.SourceLoadResult.field_gaps`.
    """
    verbs = df["verb"].astype("string").fillna("")
    resources = df["resource_type"].astype("string").fillna("")
    keys = (verbs + _PAIR_SEPARATOR + resources).astype("string")
    decisions = {
        key: is_identity_grant(*key.split(_PAIR_SEPARATOR, 1))
        for key in keys.dropna().unique()
    }
    return keys.map(decisions).fillna(False).astype(bool)


def _failed_logon(df: pd.DataFrame) -> pd.Series:
    """Logon rows that record a failure -- the only rows a failure reason belongs on."""
    return df["action"].astype("string").fillna("") == "failure"


def _logon_from_elsewhere(df: pd.DataFrame) -> pd.Series:
    """Logon rows that could name where they came from.

    A console logon has no source host and no source address: the person was at the
    keyboard. A remote type (:data:`ath.schema.REMOTE_LOGON_TYPES`) did come from
    somewhere, and a missing source on one of those is real lost attribution.

    An *unknown* logon type counts as applicable. A source that cannot supply
    ``logon_type`` at all -- CloudTrail is exactly this -- must still be measured on its
    source attribution, and assuming those rows away would turn a source's blindness
    into a clean bill of health. The assumption points in the one direction that cannot
    manufacture reassurance.
    """
    logon_type = pd.to_numeric(df["logon_type"], errors="coerce")
    return logon_type.isna() | logon_type.isin(REMOTE_LOGON_TYPES)


FIELD_APPLICABILITY: dict[tuple[str, str], FieldApplicability] = {
    (EVENT_CONTROL, "target_actor"): FieldApplicability(
        applies_to=_identity_grants,
        reason=(
            "the source model guarantees a beneficiary/conferred role only on an "
            "identity grant; other authority changes may name one and are filled when "
            "they do"
        ),
    ),
    (EVENT_CONTROL, "role_ref"): FieldApplicability(
        applies_to=_identity_grants,
        reason=(
            "the source model guarantees a beneficiary/conferred role only on an "
            "identity grant; other authority changes may name one and are filled when "
            "they do"
        ),
    ),
    (EVENT_LOGON, "failure_reason"): FieldApplicability(
        applies_to=_failed_logon,
        reason="a successful logon has no failure reason",
    ),
    (EVENT_LOGON, "source_device"): FieldApplicability(
        applies_to=_logon_from_elsewhere,
        reason="an interactive console logon has no source host",
    ),
    (EVENT_LOGON, "source_ip"): FieldApplicability(
        applies_to=_logon_from_elsewhere,
        reason="an interactive console logon has no source address",
    ),
}
"""``(table, column)`` -> the rows that column applies to. Absent means *every* row.

Deliberately short. A column belongs here only when the canonical schema says a value on
the excluded rows would be wrong -- never when a dataset merely happens not to populate
it. That distinction is the whole difference between this table and an excuse:
``resource_name`` is empty on 91.9% of the flaws.cloud trail -- 1.32M of those rows are
``RunInstances`` calls that name their subject only inside a nested structure, and 159K
carry no request parameters at all -- which is a real gap in representation and stays
measured as one. It is a *smaller* gap than the 99.9% M18-5 reported, because M18-6
derives the column from the request's own parameters instead of from the identity
columns; what it is not is excused.
"""


@dataclass(frozen=True)
class FieldPopulation:
    """How well one canonical column is populated in one dataset.

    The channel view measures a *kind* of observation through a single nominated
    evidence column, which is enough to answer "is there any network telemetry here"
    and structurally unable to answer "does the field this rule filters on carry a
    value". COMISET is the case that proves the difference: ``remote_ip`` populated on
    100% of 589,477 network rows, ``remote_port``/``protocol``/``direction`` populated
    on 1 -- one channel reported AVAILABLE, and every rule reading the other three
    returned zero findings that read as clean data.

    Two fractions, never merged. ``raw_fraction`` is over the whole table and answers
    "how much of this dataset carries the column"; ``fraction`` is over the rows the
    column *applies* to (:data:`FIELD_APPLICABILITY`) and answers "where the column
    could have carried a value, did it". Only the second can grade a rule: measuring
    ``target_actor`` over 1.86M CloudTrail reads reports a working rule as blind, and
    measuring it over nothing at all would report a blind one as working.

    Attributes:
        table: Canonical event type the column belongs to.
        column: Canonical column name.
        rows: Rows in that table. Zero means the table is absent from this dataset, in
            which case the column was not measured rather than measured as empty.
        populated: Rows carrying a usable value, by the same definition the channel
            measurement uses (see :func:`_populated_in`).
        applicable_rows: Rows the column applies to. ``None`` when no applicability is
            declared for this column, which means it applies to every row.
        applicable_populated: Of those, the rows carrying a usable value.
        applicability_reason: What the applicable rows have in common, carried from the
            declaration so a report can say *why* a column was not measured instead of
            leaving the reader to guess. Empty for an unconditional column.
    """

    table: str
    column: str
    rows: int
    populated: int
    applicable_rows: int | None = None
    applicable_populated: int | None = None
    applicability_reason: str = ""

    @property
    def measured_rows(self) -> int:
        """The denominator the verdict uses: applicable rows, or every row."""
        return self.rows if self.applicable_rows is None else self.applicable_rows

    @property
    def measured_populated(self) -> int:
        """The numerator that goes with :attr:`measured_rows`."""
        return (
            self.populated if self.applicable_populated is None
            else self.applicable_populated
        )

    @property
    def applicable(self) -> bool:
        """Whether this dataset contains any row the column applies to at all.

        False only when a declared predicate matched nothing -- a trail of pure reads
        has no grant for ``target_actor`` to be missing from. Such a column is reported
        as not applicable in this data and grades nothing, in either direction.
        """
        return self.measured_rows > 0

    @property
    def fraction(self) -> float:
        """Populated among applicable -- the fraction every verdict reads."""
        return 0.0 if not self.measured_rows else self.measured_populated / self.measured_rows

    @property
    def raw_fraction(self) -> float:
        """Populated over the whole table, reported beside :attr:`fraction`, never instead.

        Kept because it is the number an ingestion question is asked in: "1.8% of the
        control table carries a role reference" is the right sentence about the import,
        and the wrong one about the rule.
        """
        return 0.0 if not self.rows else self.populated / self.rows

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "column": self.column,
            "rows": self.rows,
            "populated": self.populated,
            # Eight places, not the usual four: the fractions this exists to report
            # are of the order 1/589,477, and rounding one of those to 0.0 would hide
            # exactly the measurement it was built to surface.
            "fraction": round(self.fraction, 8),
            "raw_fraction": round(self.raw_fraction, 8),
            "applicable_rows": self.measured_rows,
            "applicable_populated": self.measured_populated,
            "applicable": self.applicable,
            "applicability_reason": self.applicability_reason,
        }

    def __str__(self) -> str:
        if not self.applicable:
            return (
                f"{self.table}.{self.column}: not applicable in this data -- "
                f"{self.applicability_reason}, and no row of {self.rows} is one"
            )
        if self.applicable_rows is None:
            return (
                f"{self.table}.{self.column}: {self.populated}/{self.rows} "
                f"({self.fraction:.1%})"
            )
        return (
            f"{self.table}.{self.column}: {self.measured_populated}/"
            f"{self.measured_rows} applicable ({self.fraction:.1%}); "
            f"{self.populated}/{self.rows} of all rows ({self.raw_fraction:.1%})"
        )


def measure_field_population(
    telemetry: Telemetry, table: str, column: str
) -> FieldPopulation:
    """Measure one canonical column against loaded telemetry.

    Both fractions are computed here, in one place, so no consumer can choose which
    denominator it prefers: the applicable one is what :mod:`ath.environment.coverage`
    grades on, the whole-table one is carried beside it, and a column with no declared
    applicability has them equal by construction.
    """
    populated, rows = _count_populated(telemetry, table, column)
    applicability = FIELD_APPLICABILITY.get((table, column))
    if applicability is None or rows == 0:
        return FieldPopulation(
            table=table, column=column, rows=rows, populated=populated
        )

    df = telemetry.table(table)
    applicable = df[applicability.applies_to(df)]
    applicable_populated, applicable_rows = _populated_in(applicable, column)
    return FieldPopulation(
        table=table, column=column, rows=rows, populated=populated,
        applicable_rows=applicable_rows, applicable_populated=applicable_populated,
        applicability_reason=applicability.reason,
    )


def measure_field_populations(
    telemetry: Telemetry,
) -> dict[tuple[str, str], FieldPopulation]:
    """Measure every column of every canonical table, keyed by ``(table, column)``.

    Deliberately exhaustive and rule-agnostic: this is a property of the *telemetry*,
    measured once, and any consumer -- a rule verdict, a report, a future specialist --
    looks up the columns it cares about. Measuring only the columns some rule happens
    to declare today would make the measurement move whenever the rule set moves.
    """
    return {
        (table, column): measure_field_population(telemetry, table, column)
        for table, columns in TABLE_COLUMNS.items()
        for column in columns
    }


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
