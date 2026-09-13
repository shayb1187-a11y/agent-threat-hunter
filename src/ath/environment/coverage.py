"""Defensive coverage: what is detectable, what is merely visible, what is invisible.

Why the three-way split matters
--------------------------------
Coverage is usually reported as a binary -- a technique is covered by a rule or it is
not. That collapses two failures with completely different remedies::

    DETECTABLE            a rule exists and the telemetry it needs is present
    OBSERVABLE_UNDETECTED the telemetry is present; nobody has written the rule
                            -> fix: detection engineering
    UNOBSERVABLE          the telemetry does not exist
                            -> fix: onboard a log source; no rule can help
    UNVERIFIABLE          a rule exists but its telemetry is missing or too sparse
                            -> fix: the most dangerous state -- the rule *runs*,
                               finds nothing, and looks healthy

The fourth state is the one this analysis exists to surface. A rule that reads a
field populated on 0.5% of rows does not fail; it returns no findings, and a
dashboard renders that identically to "no attacks occurred". Every layer of this
project is built to keep an absence of evidence from being read as evidence of
absence, and a silently under-fed detection is exactly that failure in rule form.

Scope of the watchlist
----------------------
:data:`TECHNIQUE_WATCHLIST` is deliberately *not* :data:`ath.mitre.attack.TECHNIQUES`.
That catalogue holds only techniques this project can evidence -- by design, so an
``AttackMapping`` can never name a technique we cannot support. But a coverage report
whose scope is "things we can already see" can never report a blind spot: it would
grade the exam it wrote. The watchlist therefore includes techniques this project
*cannot* observe at all, because those are the findings.

Entries that also exist in the ATT&CK catalogue must agree with it on name, which a
test enforces, so the two cannot drift apart.

Rules are graded on fields, not only on channels
------------------------------------------------
The technique split above rests on per-rule verdicts, and a rule is only as usable as
the individual fields it filters on. Channel availability cannot see that: a channel is
evidenced by one nominated column, so a dataset carrying ``remote_ip`` on every network
row and ``remote_port``/``protocol``/``direction`` on one row reports NETWORK_FLOW as
AVAILABLE (COMISET, M17-2). :class:`RuleVerdict` therefore separates three questions
that a single "supported" collapses:

    NOT_ELIGIBLE  the tables this rule reads are empty -- it had no input
    UNUSABLE      a field it *filters on* is populated on < UNUSABLE_BELOW of the rows
                    that field applies to
    DEGRADED      everything it filters on is present; a field it filters on is sparse
    USABLE        every field it filters on is populated

Only a required field moves the verdict
----------------------------------------
Required and optional mean something precise here (M18-2): a *required* field affects
whether a finding exists or how it is graded; an *optional* field affects the evidence
text or the metadata alone. An optional field that is empty therefore cannot weaken
detection -- the rule fires on exactly the same rows and grades them exactly the same
way -- so it may not move the verdict, and since M18-5 it does not. It is reported
instead, on `RuleRunnability.sparse_optional_fields` and as "evidence detail reduced" in
the detail line, because a thinner evidence paragraph is a real cost and hiding it would
be its own kind of dishonesty.

The rule this replaces graded required and optional alike, which produced two verdicts
that said "this detection is weakened" about detections nothing had weakened: AWS-002
was DEGRADED on flaws.cloud solely because `resource_name` is populated on 2.4% of the
trail, and ATH-005 solely because CloudTrail carries no `logon_type` or `source_device`.
Both found everything they were going to find. A DEGRADED that a reader cannot act on
spends the same trust an unreported gap does.

A field's denominator is the rows it could legitimately carry a value on, declared once
in `ath.environment.channels.FIELD_APPLICABILITY` and never by a rule. Measuring
`target_actor` over 1.86M CloudTrail reads reported AWS-001 blind on a corpus where
every one of its grants carried the field (M18-3); a field with no applicable row in a
dataset is reported as not applicable there and moves no verdict in either direction.

Eligibility, usability and detection are reported side by side and never merged, which
is what keeps "0 findings" from meaning three different things at once.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ath.environment.channels import (
    DEFAULT_PARTIAL_THRESHOLD,
    ChannelAssessment,
    ChannelState,
    FieldPopulation,
    TelemetryChannel,
    channels_of_row,
)
from ath.environment.model import EnvironmentModel
from ath.hunting.base import Detector, all_detectors
from ath.mitre.attack import TECHNIQUES, Tactic
from ath.mitre.mapper import MAPPING_RULES
from ath.schema import (
    EVENT_CONTROL,
    EVENT_LOGON,
    EVENT_NETWORK,
    EVENT_PROCESS,
    TABLE_COLUMNS,
)

# --------------------------------------------------------------------------------------
# Where the line between blind, weakened and working is drawn, for a single field.
#
# Two thresholds, because a field can fail a rule in two different ways. A field
# populated on almost nothing is not sparse data, it is a missing field wearing a
# column's name: the rule runs, filters everything out, and reports zero. A field
# populated on some but not most rows leaves the rule working on what it can see.
# --------------------------------------------------------------------------------------

UNUSABLE_BELOW: float = 0.01
"""Below this fraction a required field is treated as absent, not as sparse.

Set from measurement, not taste: COMISET carried ``remote_port``, ``protocol`` and
``direction`` on 1 of 589,477 network rows (0.00017%), ATH-003 filtered on
``direction``, returned zero findings, and the zero was read as clean data. Anything
this starved cannot support a detection, and saying so is the whole point of this
module -- a rule reported as supported while its filter field is empty converts
blindness into reassurance.
"""

DEGRADED_BELOW: float = DEFAULT_PARTIAL_THRESHOLD
"""Below this fraction a field is present but too sparse to rely on.

Deliberately *the same* number the channel measurement uses for its
``PARTIAL``/``AVAILABLE`` split (:data:`ath.environment.channels.DEFAULT_PARTIAL_THRESHOLD`),
imported rather than repeated so the channel view and the field view can never
disagree about the same column.
"""

# Which canonical schema field belongs to which telemetry channel. This is the join
# that makes rule runnability computable: a rule declares `fields_used`, and this maps
# those fields onto the channels whose availability was measured against real data.
FIELD_TO_CHANNEL: dict[str, TelemetryChannel] = {
    "process_name": TelemetryChannel.PROCESS_EXECUTION,
    "process_id": TelemetryChannel.PROCESS_EXECUTION,
    "file_path": TelemetryChannel.PROCESS_EXECUTION,
    "command_line": TelemetryChannel.PROCESS_COMMAND_LINE,
    "parent_process_name": TelemetryChannel.PROCESS_LINEAGE,
    "parent_process_id": TelemetryChannel.PROCESS_LINEAGE,
    # Process-*instance* identity (`ath.instance_identity`). No new channel: knowing
    # *which run* of a program this row is about is a property of the process-execution
    # observation itself, so `process_guid` maps where `process_id` already does -- on
    # the network table as well, exactly as `process_id` does, since the column means the
    # same thing there. `parent_process_guid` maps to lineage for the same reason
    # `parent_process_id` does: it is only ever read to tie a child to its creator, and a
    # source that records execution without recording parentage populates one and not the
    # other. Deliberately absent from `CHANNEL_SPECS`' evidence columns: a channel's
    # AVAILABLE/PARTIAL state is measured over those, and an empty identity column is a
    # gap in identity, not evidence that process execution was not observed.
    "process_guid": TelemetryChannel.PROCESS_EXECUTION,
    "parent_process_guid": TelemetryChannel.PROCESS_LINEAGE,
    "remote_ip": TelemetryChannel.NETWORK_FLOW,
    "remote_port": TelemetryChannel.NETWORK_FLOW,
    "protocol": TelemetryChannel.NETWORK_FLOW,
    "direction": TelemetryChannel.NETWORK_FLOW,
    "remote_url": TelemetryChannel.NETWORK_URL,
    "action": TelemetryChannel.AUTHENTICATION,
    "logon_type": TelemetryChannel.AUTHENTICATION,
    "failure_reason": TelemetryChannel.AUTHENTICATION,
    "source_ip": TelemetryChannel.AUTH_SOURCE_ATTRIBUTION,
    "source_device": TelemetryChannel.AUTH_SOURCE_ATTRIBUTION,
    # `device`, `user`, `timestamp`, `event_id` are core columns present on every
    # event in the canonical schema, so they carry no channel requirement.
}


class CoverageState(str, Enum):
    """How well one technique is covered in this environment."""

    DETECTABLE = "detectable"
    OBSERVABLE_UNDETECTED = "observable_undetected"
    UNVERIFIABLE = "unverifiable"
    UNOBSERVABLE = "unobservable"

    @property
    def remedy(self) -> str:
        return {
            "detectable": "none -- covered",
            "observable_undetected": "detection engineering: the data is already here",
            "unverifiable": "restore the telemetry this rule depends on, or retire the rule",
            "unobservable": "onboard a new telemetry source; no rule can close this",
        }[self.value]


@dataclass(frozen=True)
class WatchlistEntry:
    """A technique assessed for coverage, and the telemetry it would require.

    Attributes:
        technique_id: ATT&CK id.
        name: Technique name. Must match the ATT&CK catalogue when present there.
        tactic: Primary tactic, used to group the report.
        required_channels: Channels needed to observe this technique *at all*. If any
            is unavailable, the technique is unobservable regardless of rule coverage.
        note: Why these channels, when it is not obvious.
    """

    technique_id: str
    name: str
    tactic: Tactic
    required_channels: tuple[TelemetryChannel, ...]
    note: str = ""


_C = TelemetryChannel

# The assessment scope. Techniques marked with channels this project does not have are
# included on purpose -- they are how the report says "we would not see this".
TECHNIQUE_WATCHLIST: tuple[WatchlistEntry, ...] = (
    # -- covered today, to prove the analysis agrees with reality -------------------
    WatchlistEntry(
        "T1059.001", "PowerShell", Tactic.EXECUTION,
        (_C.PROCESS_EXECUTION, _C.PROCESS_COMMAND_LINE),
    ),
    WatchlistEntry(
        "T1204.002", "Malicious File", Tactic.EXECUTION,
        (_C.PROCESS_EXECUTION, _C.PROCESS_LINEAGE),
    ),
    WatchlistEntry(
        "T1027.010", "Command Obfuscation", Tactic.STEALTH,
        (_C.PROCESS_COMMAND_LINE,),
    ),
    WatchlistEntry(
        "T1003.001", "LSASS Memory", Tactic.CREDENTIAL_ACCESS,
        (_C.PROCESS_COMMAND_LINE,),
        note=(
            "Command-line visibility catches only the tooling-based variants. An "
            "implant calling MiniDumpWriteDump() directly produces no command line "
            "and needs HANDLE_ACCESS -- see T1003.001-handle below."
        ),
    ),
    WatchlistEntry(
        "T1110.001", "Password Guessing", Tactic.CREDENTIAL_ACCESS,
        (_C.AUTHENTICATION,),
    ),
    WatchlistEntry(
        "T1021.002", "SMB/Windows Admin Shares", Tactic.LATERAL_MOVEMENT,
        (_C.AUTHENTICATION, _C.AUTH_SOURCE_ATTRIBUTION),
    ),
    WatchlistEntry(
        "T1071.001", "Web Protocols", Tactic.COMMAND_AND_CONTROL,
        (_C.NETWORK_FLOW,),
    ),
    WatchlistEntry(
        "T1560.001", "Archive via Utility", Tactic.COLLECTION,
        (_C.PROCESS_COMMAND_LINE,),
    ),
    WatchlistEntry(
        "T1569.002", "Service Execution", Tactic.EXECUTION,
        (_C.PROCESS_EXECUTION, _C.PROCESS_COMMAND_LINE),
    ),
    WatchlistEntry(
        "T1033", "System Owner/User Discovery", Tactic.DISCOVERY,
        (_C.PROCESS_EXECUTION, _C.PROCESS_LINEAGE),
    ),

    # -- observable here, but no rule exists ---------------------------------------
    WatchlistEntry(
        "T1053.005", "Scheduled Task", Tactic.PERSISTENCE,
        (_C.PROCESS_COMMAND_LINE,),
        note="schtasks.exe invocations are visible in command lines; no rule reads them.",
    ),
    WatchlistEntry(
        "T1490", "Inhibit System Recovery", Tactic.IMPACT,
        (_C.PROCESS_COMMAND_LINE,),
        note="vssadmin/wbadmin deletion is command-line visible and commonly precedes ransomware.",
    ),
    WatchlistEntry(
        "T1685", "Disable or Modify Tools", Tactic.DEFENSE_IMPAIRMENT,
        (_C.PROCESS_COMMAND_LINE,),
        note=(
            "Defender-tampering commands are visible; registry-based tampering is not. "
            "Previously filed here as the retired T1562.001 -- the name was right and "
            "the id was two versions stale."
        ),
    ),
    WatchlistEntry(
        "T1136.001", "Create Account: Local Account", Tactic.PERSISTENCE,
        (_C.PROCESS_COMMAND_LINE,),
        note="`net user /add` is command-line visible.",
    ),
    WatchlistEntry(
        "T1021.001", "Remote Desktop Protocol", Tactic.LATERAL_MOVEMENT,
        (_C.AUTHENTICATION, _C.AUTH_SOURCE_ATTRIBUTION),
        note="Logon type 10 is representable in the schema; no RDP-specific rule exists.",
    ),

    # -- structurally invisible: the findings that motivate this module -------------
    WatchlistEntry(
        "T1003.001-handle", "LSASS Memory (handle-based)", Tactic.CREDENTIAL_ACCESS,
        (_C.HANDLE_ACCESS,),
        note=(
            "The variant ATH-004 documents as its own blind spot. Needs process-handle "
            "telemetry, which the canonical schema cannot carry at all."
        ),
    ),
    WatchlistEntry(
        "T1071.004", "DNS", Tactic.COMMAND_AND_CONTROL,
        (_C.DNS_QUERY,),
        note="DNS-tunnelled C2. With no resolver telemetry this is not detectable at any threshold.",
    ),
    WatchlistEntry(
        "T1566.001", "Spearphishing Attachment", Tactic.INITIAL_ACCESS,
        (_C.EMAIL,),
        note=(
            "ATH-009 observes a macro document being *opened*, never its delivery. "
            "This is why no mapping in this project reaches for Initial Access."
        ),
    ),
    WatchlistEntry(
        "T1547.001", "Registry Run Keys / Startup Folder", Tactic.PERSISTENCE,
        (_C.REGISTRY,),
        note="The most common Windows persistence mechanism, entirely invisible here.",
    ),
    WatchlistEntry(
        # Moved to Defense Impairment in v19 -- present in the TA0112 listing, absent
        # from TA0005. Filed under Stealth here until the migration caught it.
        "T1112", "Modify Registry", Tactic.DEFENSE_IMPAIRMENT,
        (_C.REGISTRY,),
    ),
    WatchlistEntry(
        "T1486", "Data Encrypted for Impact", Tactic.IMPACT,
        (_C.FILE_EVENTS,),
        note="Ransomware encryption is a file-event pattern; process telemetry sees only the launcher.",
    ),
    WatchlistEntry(
        "T1041", "Exfiltration Over C2 Channel", Tactic.EXFILTRATION,
        (_C.NETWORK_FLOW, _C.NETWORK_URL),
        note=(
            "Flow records show a connection occurred, not what left. Confirming "
            "exfiltration needs volume or content visibility."
        ),
    ),
    WatchlistEntry(
        "T1059.001-scriptblock", "PowerShell (in-memory / multi-stage)", Tactic.EXECUTION,
        (_C.SCRIPT_BLOCK,),
        note=(
            "A downloader's *second* stage never appears on a command line. ATH-002 "
            "decodes the launcher; what it fetched is unobservable without script "
            "block logging."
        ),
    ),
    WatchlistEntry(
        "T1078.004", "Valid Accounts: Cloud Accounts", Tactic.INITIAL_ACCESS,
        (_C.CLOUD_CONTROL_PLANE, _C.AUTH_FACTOR),
        note=(
            "ATH sees the login and not the factor. The console login itself is "
            "represented -- actor, source address, success or failure -- but what "
            "separates an administrator signing in from a stolen credential being used "
            "is whether a second factor was presented, and the canonical logon table has "
            "no column for it. The attack_data_aws capture for this technique is two "
            "root ConsoleLogins whose entire signal is "
            "`additionalEventData.MFAUsed`, which reaches no canonical column: this "
            "technique is unobservable here even on a corpus collected to demonstrate it."
        ),
    ),
    WatchlistEntry(
        "T1610", "Deploy Container", Tactic.EXECUTION,
        (_C.CONTAINER_AUDIT,),
    ),

    # -- cloud management activity: observable wherever a management trail is loaded,
    # and unobservable on every endpoint corpus. Added in M18-7 because the five
    # attack_data_aws captures are one technique each and three of them were techniques
    # this watchlist had no opinion about at all -- which made the report silent about
    # the corpus rather than wrong about it.
    WatchlistEntry(
        "T1098", "Account Manipulation", Tactic.PERSISTENCE,
        (_C.CLOUD_MANAGEMENT_ACTIVITY,),
        note=(
            "Policy attach/detach, group membership, access-key creation and their "
            "deletions are represented in full on the control table, with the "
            "beneficiary named. No rule reads them as manipulation on its own: AWS-001 "
            "fires on a grant *followed by* the beneficiary creating a key, so a grant "
            "that is never used, and every revoke, is visible and uncredited."
        ),
    ),
    WatchlistEntry(
        "T1526", "Cloud Service Discovery", Tactic.DISCOVERY,
        (_C.CLOUD_MANAGEMENT_ACTIVITY,),
        note=(
            "Enumerating which services an account runs is made of ordinary read calls, "
            "each of them individually unremarkable; what names it is the breadth and "
            "the rate. The rows are all here -- the attack_data_aws capture is 1,071 "
            "calls across 19 services in three minutes by one actor -- and no rule "
            "reads them. The statistics this needs are measured in "
            "reports/m18/cloud_behaviour; no threshold is chosen here."
        ),
    ),
    WatchlistEntry(
        "T1580", "Cloud Infrastructure Discovery", Tactic.DISCOVERY,
        (_C.CLOUD_MANAGEMENT_ACTIVITY,),
        note=(
            "The same shape aimed at infrastructure rather than services, and the "
            "variant a refused caller produces: 1,150 AccessDenied responses across 45 "
            "services in two hours is one attack_data_aws capture, and a permission "
            "brute-force against a role trust policy is another. Both are fully "
            "represented and uncredited -- and both are only separable from a broken "
            "script by `decision`, which is why that column had to stop meaning "
            "\"any error\" first."
        ),
    ),
)


class RuleSupport(str, Enum):
    """How well a rule's telemetry dependencies are met.

    Three states, not a boolean, because "missing" and "sparse" have different
    consequences. A rule whose core channel is absent produces nothing and is
    actively misleading. A rule whose *enrichment* field is sparse still fires
    correctly on its main signal and merely grades less precisely -- ATH-003 is
    exactly this: it detects on ``remote_ip``/``remote_port`` and reads
    ``remote_url`` only to sharpen severity. Collapsing the two would report a
    working detection as broken, which spends the reader's trust for nothing.
    """

    SUPPORTED = "supported"
    DEGRADED = "degraded"
    UNSUPPORTED = "unsupported"


class RuleVerdict(str, Enum):
    """Whether a rule can work here, measured field by field rather than channel by channel.

    The channel measurement asks "is there network telemetry", which a single nominated
    evidence column can answer. It cannot ask "does the column this rule filters on
    carry a value", and that is a different question with the same consequence as a
    missing rule. COMISET is the measured case: ``NETWORK_FLOW`` came back AVAILABLE
    (``remote_ip`` on 100% of 589,477 rows) while ATH-003's ``direction`` and
    ``remote_port`` filters saw 1 populated row each. The channel view did grade
    ATH-003 unsupported there -- but for an unrelated reason, the absent ``remote_url``
    enrichment channel, which the rule does not filter on at all. Right verdict,
    wrong cause, and an operator sent to onboard a web proxy instead of fixing the
    adapter that dropped the port.

    Four outcomes, because three different things are being separated -- and each has a
    different remedy:

    ``NOT_ELIGIBLE``
        Every table this rule reads is empty. Nothing about the rule is in question;
        there was no input. Remedy: onboard that telemetry, or accept that this rule
        does not apply to this dataset.
    ``UNUSABLE``
        There was input, and a field the rule *filters on* is populated on less than
        :data:`UNUSABLE_BELOW` of it (or the channel it needs is absent outright). The
        rule runs, finds nothing, and looks healthy. Remedy: fix the ingestion of that
        field -- no threshold change and no rule edit can recover it.
    ``DEGRADED``
        Every required field is present; something the rule reads is sparse. The rule
        fires on its remaining fields and grades or explains less precisely.
    ``USABLE``
        Every declared field is populated above the threshold.
    """

    NOT_ELIGIBLE = "not_eligible"
    UNUSABLE = "unusable"
    DEGRADED = "degraded"
    USABLE = "usable"

    @property
    def runnable(self) -> bool:
        """Whether this rule's findings -- or its silence -- can be believed."""
        return self in (RuleVerdict.USABLE, RuleVerdict.DEGRADED)

    @property
    def remedy(self) -> str:
        return {
            "not_eligible": "none -- this rule's input table is absent from this dataset",
            "unusable": "restore the named field(s) in ingestion; the rule cannot see without them",
            "degraded": "improve population of the named field(s) to sharpen grading",
            "usable": "none -- every field this rule filters on is populated",
        }[self.value]


@dataclass(frozen=True)
class FieldUsability:
    """One field a rule declares, measured on one table the rule declares it reads.

    Attributes:
        population: The measurement (table, column, rows, populated, fraction).
        required: True when this field affects whether a finding exists or how it is
            graded. False when the rule declared it in ``optional_fields`` -- read to
            phrase the evidence or carry metadata, never to decide or grade a finding.

            This is the distinction that decides whether the field may move a verdict.
            A required field that is empty blinds the rule; an optional one that is
            empty leaves it finding exactly what it would have found, described in
            fewer words. Only the first is a detection problem, so only the first is
            graded -- the second is reported on
            :attr:`RuleRunnability.sparse_optional_fields` instead.
    """

    population: FieldPopulation
    required: bool = True

    @property
    def column(self) -> str:
        return self.population.column

    @property
    def table(self) -> str:
        return self.population.table

    @property
    def fraction(self) -> float:
        """Populated among the rows the field applies to -- the graded fraction."""
        return self.population.fraction

    @property
    def applicable(self) -> bool:
        """False when this dataset holds no row the field could carry a value on.

        Such a field grades nothing. It cannot make a rule UNUSABLE (there is no loss
        to report) and it cannot make one DEGRADED (there is no sparseness either):
        the honest statement is that the question does not arise in this data, and
        that statement is what gets printed.
        """
        return self.population.applicable

    def to_dict(self) -> dict[str, Any]:
        return {**self.population.to_dict(), "required": self.required}

    def __str__(self) -> str:
        requirement = "required" if self.required else "optional"
        if not self.applicable:
            return (
                f"{self.column} not applicable in this data -- "
                f"{self.population.applicability_reason}, and no row of "
                f"{self.population.rows} {self.table} rows is one ({requirement})"
            )
        measured = (
            f"{self.population.measured_populated} of "
            f"{self.population.measured_rows} applicable {self.table} rows "
            f"({self.fraction:.2%}"
        )
        if self.population.applicable_rows is not None:
            measured += f"; {self.population.raw_fraction:.2%} of all {self.population.rows}"
        return f"{self.column} {measured}, {requirement})"


@dataclass(frozen=True)
class RuleRunnability:
    """Whether a registered detection can actually be trusted in this environment.

    Carries two measurements of the same rule, deliberately not merged. ``support`` is
    the channel-level verdict -- "does this deployment have authentication telemetry at
    all" -- and ``verdict`` is the field-level one -- "is the column this rule filters
    on populated". A rule can pass the first and fail the second, which is exactly the
    failure this class exists to make visible; merging them would hide whichever one
    happened to be reported second.

    Attributes:
        rule_id: The rule assessed.
        title: Its human-readable title.
        support: Measured channel-level support.
        verdict: Measured field-level verdict, including table eligibility.
        missing_channels: Channels the rule needs that are absent entirely.
        degraded_channels: Channels present but too sparse to rely on.
        fields: Per-field population for every field the rule declares on a table it
            declares. Empty when no field populations were supplied, in which case
            ``verdict`` falls back to what the channel measurement alone can say.
        tables: Row count per declared table, so eligibility is readable directly.
        detail: One-line summary.
    """

    rule_id: str
    title: str
    support: RuleSupport
    verdict: RuleVerdict = RuleVerdict.USABLE
    missing_channels: tuple[TelemetryChannel, ...] = ()
    degraded_channels: tuple[TelemetryChannel, ...] = ()
    fields: tuple[FieldUsability, ...] = ()
    tables: tuple[tuple[str, int], ...] = ()
    detail: str = ""

    @property
    def runnable(self) -> bool:
        """True when the rule will produce trustworthy findings at all."""
        return self.verdict.runnable

    @property
    def unpopulated_fields(self) -> tuple[str, ...]:
        """Required fields starved below :data:`UNUSABLE_BELOW` -- the blinding ones."""
        return tuple(
            f.column for f in self.fields
            if f.applicable and f.required and f.fraction < UNUSABLE_BELOW
        )

    @property
    def sparse_fields(self) -> tuple[str, ...]:
        """Required fields below :data:`DEGRADED_BELOW` -- the weakening ones.

        Required only, since M18-5. These are the fields whose sparseness costs the rule
        findings or grading accuracy, which is what DEGRADED is a statement about; an
        optional field that is empty costs a sentence of evidence and is listed on
        :attr:`sparse_optional_fields` instead.
        """
        return tuple(
            f.column for f in self.fields
            if f.applicable and f.required and f.fraction < DEGRADED_BELOW
        )

    @property
    def sparse_optional_fields(self) -> tuple[str, ...]:
        """Optional fields below :data:`DEGRADED_BELOW` -- thinner evidence, same findings.

        Reported and never graded. The rule fires on the same rows and assigns the same
        severities whether these carry a value or not (that is what made them optional),
        so a verdict that moved on them would be telling a reader their detection is
        weakened when nothing about it is. What *is* true is that its evidence paragraph
        will say less, and that is worth a line of its own -- suppressing it entirely
        would trade one misreading for another.
        """
        return tuple(
            f.column for f in self.fields
            if f.applicable and not f.required and f.fraction < DEGRADED_BELOW
        )

    @property
    def not_applicable_fields(self) -> tuple[str, ...]:
        """Declared fields no row in this dataset could have carried a value on.

        Reported as its own list rather than folded into either of the two above,
        because it is a third fact: not blind, not sparse, simply not asked. A trail of
        pure reads contains no grant, so nothing about ``target_actor`` is known from it
        -- and saying so is different from saying the column is empty.
        """
        return tuple(f.column for f in self.fields if not f.applicable)

    @property
    def eligible_rows(self) -> int:
        """Rows available to this rule across the tables it declares."""
        return sum(rows for _, rows in self.tables)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "support": self.support.value,
            "verdict": self.verdict.value,
            "verdict_remedy": self.verdict.remedy,
            "runnable": self.runnable,
            "missing_channels": [c.value for c in self.missing_channels],
            "degraded_channels": [c.value for c in self.degraded_channels],
            "tables": {table: rows for table, rows in self.tables},
            "eligible_rows": self.eligible_rows,
            "fields": [f.to_dict() for f in self.fields],
            "unpopulated_fields": list(self.unpopulated_fields),
            "sparse_fields": list(self.sparse_fields),
            "sparse_optional_fields": list(self.sparse_optional_fields),
            "not_applicable_fields": list(self.not_applicable_fields),
            "detail": self.detail,
        }


@dataclass(frozen=True)
class TechniqueCoverage:
    """The coverage verdict for one watchlist technique."""

    entry: WatchlistEntry
    state: CoverageState
    covering_rules: tuple[str, ...] = ()
    missing_channels: tuple[TelemetryChannel, ...] = ()
    degraded_channels: tuple[TelemetryChannel, ...] = ()
    degraded_rules: tuple[str, ...] = ()
    """Covering rules that fire but read at least one sparsely populated field.

    Detectable, with a caveat -- worth surfacing separately so "covered" does not
    quietly mean "covered less well than it looks"."""

    @property
    def technique_id(self) -> str:
        return self.entry.technique_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.entry.technique_id,
            "name": self.entry.name,
            "tactic": self.entry.tactic.display_name,
            "state": self.state.value,
            "remedy": self.state.remedy,
            "covering_rules": list(self.covering_rules),
            "degraded_rules": list(self.degraded_rules),
            "missing_channels": [c.value for c in self.missing_channels],
            "degraded_channels": [c.value for c in self.degraded_channels],
            "note": self.entry.note,
        }


@dataclass
class CoverageReport:
    """Defensive posture for one environment.

    Attributes:
        techniques: Per-technique verdicts.
        rules: Per-rule runnability.
        environment: The model this was assessed against.
    """

    techniques: tuple[TechniqueCoverage, ...]
    rules: tuple[RuleRunnability, ...]
    environment: EnvironmentModel

    def in_state(self, state: CoverageState) -> list[TechniqueCoverage]:
        return [t for t in self.techniques if t.state is state]

    @property
    def counts(self) -> dict[str, int]:
        return {s.value: len(self.in_state(s)) for s in CoverageState}

    @property
    def detectable_fraction(self) -> float:
        return 0.0 if not self.techniques else (
            len(self.in_state(CoverageState.DETECTABLE)) / len(self.techniques)
        )

    @property
    def unrunnable_rules(self) -> list[RuleRunnability]:
        return [r for r in self.rules if not r.runnable]

    @property
    def provenance(self) -> dict[str, Any]:
        """What this assessment describes, and what it was derived from.

        A coverage report is the artifact someone acts on -- and a posture verdict is
        meaningless without knowing which environment produced it, from which telemetry,
        over what window. "8 of 25 techniques unobservable" is a different statement
        about a four-hour synthetic sample than about a month of production data.

        The investigation report already carries its data sources for exactly this
        reason ("This report was produced by an automated investigation over telemetry
        from: defender_export"); without this the coverage report was the one output
        that could not say what it was about.
        """
        environment = self.environment
        window = (
            [t.isoformat() for t in environment.observation_window]
            if environment.observation_window else None
        )
        return {
            "data_sources": list(environment.data_sources),
            "platform": environment.platform,
            "hosts": len(environment.hosts),
            "identities": len(environment.identities),
            "event_count": environment.event_count,
            "observation_window": window,
            "observation_hours": round(environment.observation_hours, 2),
            "rules_assessed": len(self.rules),
            "techniques_assessed": len(self.techniques),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "provenance": self.provenance,
            "counts": self.counts,
            "detectable_fraction": round(self.detectable_fraction, 4),
            "techniques": [t.to_dict() for t in self.techniques],
            "rules": [r.to_dict() for r in self.rules],
        }


def channels_for_fields(fields: Iterable[str]) -> set[TelemetryChannel]:
    """Map declared telemetry field names onto the channels they belong to.

    The join that makes telemetry dependency computable anywhere it is declared.
    Rules declare ``fields_used`` and so do the findings they produce, which means a
    *case* can be asked what kinds of telemetry its evidence actually rests on --
    without anyone naming a rule id. That is what lets the investigation layer decide
    which specialist is relevant by capability rather than by allowlist.

    Fields with no mapping (``device``, ``user``, ``timestamp`` -- core columns present
    on every event) contribute no requirement and are skipped.
    """
    return {FIELD_TO_CHANNEL[f] for f in fields if f in FIELD_TO_CHANNEL}


def _channels_for_rule(detector: Detector) -> set[TelemetryChannel]:
    """The channels a rule depends on.

    Uses the rule's explicit `channels` declaration when it has one -- required for
    rules where `fields_used` column names alone are ambiguous (see `Detector.channels`)
    -- and falls back to mapping `fields_used` through `channels_for_fields()`, which is
    the entire behaviour for every rule that does not set `channels` explicitly.
    """
    if detector.channels:
        return set(detector.channels)
    return channels_for_fields(detector.fields_used)


def rule_field_usability(
    detector: Detector,
    populations: dict[tuple[str, str], FieldPopulation],
) -> tuple[FieldUsability, ...]:
    """Look up each field a rule declares, on each table the rule declares.

    Reads nothing but the detector's own declarations and the measured populations --
    no rule id, table name or column name appears here, so a new rule is covered the
    moment it declares ``tables`` and ``fields_used``.

    A declared field is skipped for a table that does not carry that column: rules read
    one table each today, and a field belongs to whichever of its declared tables has
    it. That a field belongs to *no* declared table is a declaration error rather than
    a measurement result, and is caught by the static declaration test instead of being
    silently reported as 0% here.

    A table with no rows contributes no field measurements at all. The fraction of
    nothing is not zero, it is unmeasured -- and reporting it as zero would grade a rule
    with no input as blind rather than as not applicable.
    """
    if not populations:
        return ()

    results: list[FieldUsability] = []
    for table in sorted(detector.tables):
        columns = set(TABLE_COLUMNS.get(table, ()))
        for name in sorted(detector.fields_used):
            if name not in columns:
                continue
            population = populations.get((table, name))
            if population is None or population.rows == 0:
                continue
            results.append(FieldUsability(
                population=population, required=name not in detector.optional_fields,
            ))
    return tuple(results)


def _table_rows(
    detector: Detector, populations: dict[tuple[str, str], FieldPopulation]
) -> tuple[tuple[str, int], ...]:
    """Row count for each table the rule declares, read off the measured populations.

    Every canonical column is measured, so any column of the table answers how many
    rows it has; ``event_id`` is present on every table by construction.
    """
    rows: list[tuple[str, int]] = []
    for table in sorted(detector.tables):
        measured = [p for (t, _), p in populations.items() if t == table]
        rows.append((table, measured[0].rows if measured else 0))
    return tuple(rows)


def _gating_channels_for_rule(detector: Detector) -> set[TelemetryChannel]:
    """The channels a rule's *detection* depends on, optional enrichment excluded.

    ``_channels_for_rule`` answers "what telemetry does this rule touch", which is the
    right question for the channel-level `support` grade and is left untouched. It is
    the wrong question for a verdict, because it cannot tell a filter field from an
    evidence field: ATH-003 declares ``remote_url``, so a dataset with no URLs makes
    NETWORK_URL absent and the rule "depends on absent telemetry" -- while it detects
    on ``remote_ip``/``direction`` and fires perfectly well. Rules that declare
    `channels` explicitly are unaffected: an explicit declaration is a statement that
    those channels *are* the dependency.
    """
    if detector.channels:
        return set(detector.channels)
    return channels_for_fields(
        name for name in detector.fields_used if name not in detector.optional_fields
    )


def _field_verdict(
    fields: tuple[FieldUsability, ...],
    tables: tuple[tuple[str, int], ...],
    missing_gating: tuple[TelemetryChannel, ...],
    support: RuleSupport,
) -> tuple[RuleVerdict, str]:
    """Grade a rule on its declared tables and fields, then on its gating channels.

    Precedence, worst first, and each step answers a question the next one cannot:
    no input at all; then a filter field that carries no value, or a gating channel
    that is absent outright; then a weakened field; then working.

    Fields are checked *before* channels because they say more. "``direction`` is
    populated on 1 of 589,477 network rows" names the column to fix; "depends on absent
    telemetry (network_flow)" names a category, and on the COMISET shape it is not even
    true -- the channel was AVAILABLE. The channel reasoning still decides the verdict
    when no field measurement is available (an absent-by-schema channel has no column to
    count), and is carried verbatim either way on ``support`` and ``missing_channels``.

    Only *required* fields are graded. An optional field is read to phrase evidence or
    carry metadata and changes neither whether a finding exists nor how it is graded, so
    its sparseness cannot weaken a detection and may not move this verdict; it is
    reported by :func:`_evidence_detail_reduced`, appended to whichever detail line
    wins, and on :attr:`RuleRunnability.sparse_optional_fields`.
    """
    if tables and all(rows == 0 for _, rows in tables):
        named = ", ".join(table for table, _ in tables)
        return RuleVerdict.NOT_ELIGIBLE, (
            f"no input: every table this rule reads is empty ({named}); "
            "its silence says nothing about what occurred"
        )

    # Fields the dataset holds no applicable row for are set aside before either
    # threshold is applied. Neither verdict has anything to say about them: there is no
    # value missing from a row that could not have carried one, and pretending there is
    # reports blindness that does not exist -- the defect this whole branch exists to
    # remove. They are still carried on `not_applicable_fields`, so the reader sees the
    # field was declared and why it was not graded.
    graded = [f for f in fields if f.applicable]
    skipped = [f for f in fields if not f.applicable]

    # Required only, in both thresholds: see the module docstring. An optional field
    # at 0% leaves the rule finding exactly what it would have found.
    starved = [f for f in graded if f.required and f.fraction < UNUSABLE_BELOW]
    if starved:
        return RuleVerdict.UNUSABLE, (
            "required field(s) effectively unpopulated: "
            + "; ".join(str(f) for f in sorted(starved, key=lambda f: f.column))
            + " -- this rule filters on them, so it runs, matches nothing, and its "
            "zero must not be read as clean data"
        )

    if missing_gating:
        return RuleVerdict.UNUSABLE, (
            "depends on absent telemetry "
            f"({', '.join(c.value for c in missing_gating)}); this rule will run and "
            "find nothing regardless of what occurred"
        )

    sparse = [f for f in graded if f.required and f.fraction < DEGRADED_BELOW]
    if sparse:
        return RuleVerdict.DEGRADED, (
            "reads sparsely populated field(s): "
            + "; ".join(str(f) for f in sorted(sparse, key=lambda f: f.column))
            + " -- the rule still fires on its remaining fields"
        )

    if support is not RuleSupport.SUPPORTED:
        return RuleVerdict.DEGRADED, ""  # detail comes from the channel reasoning

    if not graded:
        return RuleVerdict.USABLE, (
            "no declared field applies to any row of its input table(s): "
            + "; ".join(str(f) for f in sorted(skipped, key=lambda f: f.column))
            if skipped else ""
        )

    detail = (
        f"every field this rule filters on is populated on the {len(graded)} measured "
        "column(s) of its input table(s)"
    )
    if skipped:
        detail += (
            "; not applicable in this data: "
            + ", ".join(sorted(f.column for f in skipped))
        )
    return RuleVerdict.USABLE, detail


def _evidence_detail_reduced(fields: tuple[FieldUsability, ...]) -> str:
    """The clause naming optional fields too sparse to phrase evidence with, if any.

    Appended to whichever detail line the verdict produced, rather than folded into it,
    because it is a different kind of statement: the verdict says what this rule can and
    cannot detect here, and this says how much the finding it does produce will be able
    to explain. A reader who sees "usable" needs to know the second without being told
    the first is in doubt.
    """
    reduced = sorted(
        (f for f in fields
         if f.applicable and not f.required and f.fraction < DEGRADED_BELOW),
        key=lambda f: f.column,
    )
    if not reduced:
        return ""
    return (
        "; evidence detail reduced: "
        + "; ".join(str(f) for f in reduced)
        + " -- read to phrase or annotate a finding and not to decide or grade one, so "
        "every finding this rule would make it still makes"
    )


def assess_rule(
    detector: Detector,
    channels: dict[TelemetryChannel, ChannelAssessment],
    populations: dict[tuple[str, str], FieldPopulation] | None = None,
) -> RuleRunnability:
    """Decide whether one rule's telemetry dependencies are actually satisfied.

    Args:
        detector: The rule to assess.
        channels: Measured channel availability.
        populations: Measured per-column population, keyed by ``(table, column)``. When
            omitted the verdict is whatever the channel measurement alone can say --
            which is the pre-M18 behaviour, and is why a model built without telemetry
            still assesses.
    """
    populations = populations or {}
    required = _channels_for_rule(detector)
    missing = tuple(sorted(
        (c for c in required if not channels[c].state.observable), key=lambda c: c.value
    ))
    degraded = tuple(sorted(
        (c for c in required
         if channels[c].state is ChannelState.PARTIAL),
        key=lambda c: c.value,
    ))

    if missing:
        support = RuleSupport.UNSUPPORTED
        detail = (
            f"depends on absent telemetry ({', '.join(c.value for c in missing)}); "
            "this rule will run and find nothing regardless of what occurred"
        )
    elif degraded:
        support = RuleSupport.DEGRADED
        detail = (
            f"reads sparsely populated telemetry "
            f"({', '.join(c.value for c in degraded)}); it still fires on its "
            "remaining fields, but any grading that depends on these is weakened"
        )
    else:
        support = RuleSupport.SUPPORTED
        detail = "all required telemetry channels are available"

    fields = rule_field_usability(detector, populations)
    tables = _table_rows(detector, populations) if populations else ()
    missing_gating = tuple(
        c for c in missing if c in _gating_channels_for_rule(detector)
    )
    verdict, field_detail = _field_verdict(fields, tables, missing_gating, support)
    # Appended after the two details compete, so it survives whichever one won: a rule
    # that is DEGRADED on its channels and thin on its evidence fields is both things.
    detail = (field_detail or detail) + _evidence_detail_reduced(fields)

    return RuleRunnability(
        rule_id=detector.rule_id,
        title=detector.title,
        support=support,
        verdict=verdict,
        missing_channels=missing,
        degraded_channels=degraded,
        fields=fields,
        tables=tables,
        detail=detail,
    )


def _rules_covering(technique_id: str) -> tuple[str, ...]:
    """Registered rules whose ATT&CK mapping table names this technique.

    Reads :data:`ath.mitre.mapper.MAPPING_RULES` -- the authoritative declaration --
    rather than running a hunt and inspecting findings. Coverage must be a property
    of the *rule set*, not of whether an attack happened to occur in the dataset
    currently on disk: a rule that would catch T1110 still covers T1110 on a quiet
    day, and a coverage report that said otherwise would swing with the telemetry.

    Note this credits a rule even when its mapping is gated on evidence that may not
    be present. The gate decides whether a *particular finding* asserts the technique;
    coverage asks whether the rule set addresses it at all.
    """
    covering = {
        mapping.rule_id for mapping in MAPPING_RULES
        if mapping.technique_id == technique_id
    }
    return tuple(sorted(covering))


def assess_coverage(
    environment: EnvironmentModel, detectors: list[Detector] | None = None
) -> CoverageReport:
    """Produce the three-way (four-state) coverage verdict for an environment.

    Args:
        environment: The model to assess, carrying measured channel availability.
        detectors: Rule set to credit. Defaults to every registered rule.
    """
    detectors = detectors if detectors is not None else all_detectors()
    channels = environment.channels
    # Measured once when the model was built from telemetry, for the same reason
    # `channels` is: coverage assesses a *model*, and re-deriving either here would
    # mean two places counting the same rows.
    populations = environment.field_populations

    rules = tuple(assess_rule(d, channels, populations) for d in detectors)
    # A degraded rule still fires; only an unsupported one cannot be credited.
    trustworthy_rules = {r.rule_id for r in rules if r.runnable}
    degraded_rules = {
        r.rule_id for r in rules if r.support is RuleSupport.DEGRADED
    }

    verdicts: list[TechniqueCoverage] = []
    for entry in TECHNIQUE_WATCHLIST:
        missing = tuple(
            c for c in entry.required_channels if not channels[c].state.observable
        )
        degraded = tuple(
            c for c in entry.required_channels
            if channels[c].state is ChannelState.PARTIAL
        )
        covering = _rules_covering(entry.technique_id)

        if missing:
            # Unobservable dominates: a rule cannot help, so this is not a detection
            # engineering problem even when a rule nominally names the technique.
            state = CoverageState.UNOBSERVABLE
        elif not covering:
            state = CoverageState.OBSERVABLE_UNDETECTED
        elif any(r in trustworthy_rules for r in covering):
            state = CoverageState.DETECTABLE
        else:
            state = CoverageState.UNVERIFIABLE

        verdicts.append(TechniqueCoverage(
            entry=entry,
            state=state,
            covering_rules=covering,
            missing_channels=missing,
            degraded_channels=degraded,
            degraded_rules=tuple(sorted(set(covering) & degraded_rules)),
        ))

    return CoverageReport(
        techniques=tuple(verdicts), rules=rules, environment=environment
    )


# --------------------------------------------------------------------------------------
# The declaration-truth check: a rule's findings stay inside the channels it declares.
#
# Everything above turns a rule's `channels` declaration into advice for an operator:
# "AWS-006 is UNUSABLE here, the channel it needs is absent." That sentence is only worth
# printing if it cannot be contradicted by the rule itself, and in M18-8 it was. AWS-006
# declares CLOUD_MANAGEMENT_ACTIVITY; its predicate `changes_authority` is deliberately
# cross-platform and its second clause is Kubernetes RBAC; so on a Kubernetes-only corpus
# the coverage model said "cannot fire" and the rule fired, citing rows from a channel it
# had never declared. Nothing was wrong with the finding -- the rows were real and the
# behaviour was as documented -- and the coverage model was still lying.
#
# This is the check that makes that impossible to reintroduce. It compares, per cited
# evidence row, the channels the row *evidences* (from the catalogue, via
# `channels_of_row`) against the channels the rule *declares* (via the same
# `_channels_for_rule` the runnability verdict uses). Disjoint is a violation.
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ChannelViolation:
    """One evidence row a finding cites from outside its rule's declared channels.

    Attributes:
        rule_id: The rule that produced the finding.
        event_id: The cited row.
        event_type: The canonical table the row was found in, or ``""`` when the row was
            not found at all.
        declared: Channels the rule declares.
        observed: Channels the row evidences.
        reason: Which of the three ways this row broke the invariant.
    """

    rule_id: str
    event_id: str
    event_type: str
    declared: tuple[TelemetryChannel, ...]
    observed: tuple[TelemetryChannel, ...]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "declared": [c.value for c in self.declared],
            "observed": [c.value for c in self.observed],
            "reason": self.reason,
        }

    def __str__(self) -> str:
        return (
            f"{self.rule_id} cites {self.event_id} ({self.event_type or 'not found'}): "
            f"declared {[c.value for c in self.declared]}, "
            f"row evidences {[c.value for c in self.observed]} -- {self.reason}"
        )


def findings_respect_declared_channels(
    findings: Iterable[Any],
    telemetry: Any,
    detectors: Iterable[Detector] | None = None,
) -> list[ChannelViolation]:
    """Check the architectural invariant: every cited row is in a declared channel.

    Runs over findings that already exist, so it is usable in three places with one
    definition -- a test over every registered rule on a synthetic mixed table, and the
    two measurement scripts, on every corpus they touch.

    Three ways a finding breaks the invariant, reported as three distinct reasons rather
    than collapsed, because they have different remedies:

    * ``"rule declares no channels"`` -- the rule made no claim at all, so the coverage
      model has nothing to gate it on. Vacuous today (every registered rule declares or
      derives at least one channel) and kept strict so it stays that way.
    * ``"row evidences no known channel"`` -- the row carries a value for no evidence
      column in the catalogue. Usually an adapter gap, occasionally a genuinely empty
      row; either way the finding cannot show that its declared channel is behind it.
    * ``"row is outside the declared channels"`` -- the P13 case. The row belongs to a
      channel, and the rule did not declare it.

    A row whose ``event_id`` is not in the telemetry at all is reported too: the
    claim-verification layer guarantees it cannot happen, and a check that assumed the
    guarantee would be resting on the thing it is meant to test.

    Args:
        findings: The findings to check.
        telemetry: The telemetry they were produced from.
        detectors: The detectors whose declarations to read; defaults to every
            registered rule.

    Returns:
        One :class:`ChannelViolation` per offending (finding, cited row), ordered by
        rule id then event id. Empty is the passing result.
    """
    findings = list(findings)
    if not findings:
        return []

    declared_by_rule = {
        detector.rule_id: tuple(sorted(
            _channels_for_rule(detector), key=lambda c: c.value,
        ))
        for detector in (all_detectors() if detectors is None else detectors)
    }

    cited = {event_id for finding in findings for event_id in finding.event_ids}
    # One vectorised pass per table over the cited ids, rather than an index over every
    # row: flaws.cloud is 1.86M control rows and the findings cite tens of thousands.
    located: dict[str, tuple[str, dict[str, Any]]] = {}
    for event_type in (EVENT_PROCESS, EVENT_NETWORK, EVENT_LOGON, EVENT_CONTROL):
        table = telemetry.table(event_type)
        if table.empty:
            continue
        matched = table[table["event_id"].astype("string").isin(cited)]
        for record in matched.to_dict("records"):
            located[str(record["event_id"])] = (event_type, record)

    violations: list[ChannelViolation] = []
    for finding in findings:
        declared = declared_by_rule.get(finding.rule_id, ())
        for event_id in finding.event_ids:
            found = located.get(str(event_id))
            if found is None:
                violations.append(ChannelViolation(
                    rule_id=finding.rule_id, event_id=str(event_id), event_type="",
                    declared=declared, observed=(),
                    reason="cited row is not in the telemetry",
                ))
                continue
            event_type, record = found
            observed = tuple(sorted(
                channels_of_row(event_type, record), key=lambda c: c.value,
            ))
            if not declared:
                reason = "rule declares no channels"
            elif not observed:
                reason = "row evidences no known channel"
            elif set(observed) & set(declared):
                continue
            else:
                reason = "row is outside the declared channels"
            violations.append(ChannelViolation(
                rule_id=finding.rule_id, event_id=str(event_id),
                event_type=event_type, declared=declared, observed=observed,
                reason=reason,
            ))

    return sorted(violations, key=lambda v: (v.rule_id, v.event_id))
