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
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ath.environment.channels import (
    ChannelAssessment,
    ChannelState,
    TelemetryChannel,
)
from ath.environment.model import EnvironmentModel
from ath.hunting.base import Detector, all_detectors
from ath.mitre.attack import TECHNIQUES, Tactic
from ath.mitre.mapper import MAPPING_RULES

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
        (_C.CLOUD_CONTROL_PLANE,),
    ),
    WatchlistEntry(
        "T1610", "Deploy Container", Tactic.EXECUTION,
        (_C.CONTAINER_AUDIT,),
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


@dataclass(frozen=True)
class RuleRunnability:
    """Whether a registered detection can actually be trusted in this environment.

    Attributes:
        rule_id: The rule assessed.
        title: Its human-readable title.
        support: Measured support level.
        missing_channels: Channels the rule needs that are absent entirely.
        degraded_channels: Channels present but too sparse to rely on.
        detail: One-line summary.
    """

    rule_id: str
    title: str
    support: RuleSupport
    missing_channels: tuple[TelemetryChannel, ...] = ()
    degraded_channels: tuple[TelemetryChannel, ...] = ()
    detail: str = ""

    @property
    def runnable(self) -> bool:
        """True when the rule will produce trustworthy findings at all."""
        return self.support is not RuleSupport.UNSUPPORTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "support": self.support.value,
            "runnable": self.runnable,
            "missing_channels": [c.value for c in self.missing_channels],
            "degraded_channels": [c.value for c in self.degraded_channels],
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


def assess_rule(
    detector: Detector, channels: dict[TelemetryChannel, ChannelAssessment]
) -> RuleRunnability:
    """Decide whether one rule's telemetry dependencies are actually satisfied."""
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

    return RuleRunnability(
        rule_id=detector.rule_id,
        title=detector.title,
        support=support,
        missing_channels=missing,
        degraded_channels=degraded,
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

    rules = tuple(assess_rule(d, channels) for d in detectors)
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
