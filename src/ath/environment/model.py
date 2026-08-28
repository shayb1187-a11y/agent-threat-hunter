"""The Environment Model: a structured picture of what is being defended.

Why this module exists
----------------------
Everything before this milestone reasons about *events*. Nothing reasons about the
*environment* those events came from -- yet almost every real defensive decision
depends on the latter. Whether "svc_backup authenticated to three servers" is alarming
depends on whether svc_backup is a service account, whether those hosts are servers,
and whether that is how the account normally behaves.

This model is the system's internal representation of the world it is protecting. It
is the input to capability planning: you cannot decide *which* defensive capabilities
an environment needs until you can describe the environment.

What this deliberately does not do
-----------------------------------
**It does not guess.** Every attribute is either counted directly from telemetry or
marked as underivable. Two temptations are refused explicitly:

*Naming conventions.* ``FS02`` looks like a file server and ``PC01`` looks like a
workstation, and in this dataset that even happens to be right. Encoding it would
produce a model that is confidently wrong in any environment with different naming --
and would be untestable, because it would agree with the fixture for the wrong reason.
Host roles here are inferred from *behaviour* (what authenticates to them, and how),
which is weaker but honest, and which carries a confidence the reader can see.

*Criticality.* Which assets matter is a business fact, not a telemetry fact. No amount
of event data reveals that a host holds regulated data. The model therefore exposes
:attr:`EnvironmentModel.undetermined` -- the list of things it knows it cannot know --
rather than inventing a plausible answer. That list is an input to the analyst, and
eventually to a declarative environment description the operator supplies.

The model is derived deterministically. Run it twice on the same telemetry and it is
identical; no model is consulted at any point.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from statistics import median
from typing import Any

import pandas as pd

from ath.environment.channels import (
    ChannelAssessment,
    ChannelState,
    TelemetryChannel,
    assess_channels,
)
from ath.netaddr import is_public_ip
from ath.schema import SIG_VALID, describe_logon_type
from ath.telemetry.loader import Telemetry

# Logon types indicating someone is working *at* a machine, which is what makes it
# look like a workstation rather than a service target.
_INTERACTIVE_LOGON_TYPES: frozenset[int] = frozenset({2, 7, 10, 11})
# Logon types indicating a machine is being *reached* -- the shape of a server.
_REMOTE_LOGON_TYPES: frozenset[int] = frozenset({3, 10})

# Process images that indicate a security or management product is present. Detecting
# existing controls matters because a capability plan should not propose building what
# the environment already has.
_SECURITY_PRODUCT_PROCESSES: dict[str, str] = {
    "msmpeng.exe": "Microsoft Defender Antivirus",
    "mssense.exe": "Microsoft Defender for Endpoint sensor",
    "senseir.exe": "Microsoft Defender for Endpoint response",
    "ccmexec.exe": "Microsoft Configuration Manager (patch management)",
    "sysmon.exe": "Sysinternals Sysmon",
    "sysmon64.exe": "Sysinternals Sysmon",
    "carbonblack.exe": "VMware Carbon Black",
    "csfalconservice.exe": "CrowdStrike Falcon",
    "xagt.exe": "Trellix/FireEye HX",
    "sentinelagent.exe": "SentinelOne",
    "wazuh-agent.exe": "Wazuh",
    "splunkd.exe": "Splunk forwarder",
}

# Windows-only signals, used to state an OS conclusion with its evidence rather than
# assuming the platform. A non-Windows telemetry source would leave these unmatched,
# and the model would correctly decline to claim Windows.
_WINDOWS_PROCESS_MARKERS: frozenset[str] = frozenset(
    {"svchost.exe", "lsass.exe", "services.exe", "explorer.exe", "winlogon.exe"}
)


@dataclass(frozen=True)
class Host:
    """One machine observed in telemetry.

    Attributes:
        name: Hostname as it appears in telemetry.
        role: ``"workstation"``, ``"server"`` or ``"unknown"`` -- inferred from
            authentication behaviour, never from the name.
        role_reason: Why that role was assigned, so the inference can be checked.
        interactive_users: Accounts observed logging on interactively -- the closest
            available notion of "who owns this machine".
        remote_auth_sources: Hosts observed authenticating *to* this one.
        process_count / network_count / logon_count: Observed event volumes.
        external_destinations: Distinct **public, routable** addresses contacted --
            this host's outbound attack surface.
        internal_peers: Distinct **private** addresses contacted. Kept separate rather
            than merged: conflating them makes an ordinary file-server mount look like
            egress to the internet, and hides real egress inside a list of noise. The
            two answer different questions -- internal peers describe the environment's
            shape, external destinations describe its exposure.
    """

    name: str
    role: str
    role_reason: str
    interactive_users: tuple[str, ...] = ()
    remote_auth_sources: tuple[str, ...] = ()
    process_count: int = 0
    network_count: int = 0
    logon_count: int = 0
    external_destinations: tuple[str, ...] = ()
    internal_peers: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "role": self.role,
            "role_reason": self.role_reason,
            "interactive_users": list(self.interactive_users),
            "remote_auth_sources": list(self.remote_auth_sources),
            "event_counts": {
                "process": self.process_count,
                "network": self.network_count,
                "logon": self.logon_count,
            },
            "external_destinations": list(self.external_destinations),
            "internal_peers": list(self.internal_peers),
        }


@dataclass(frozen=True)
class WindowedPrevalence:
    """Prevalence measured over a recent slice as well as the whole observation.

    Why one number is not enough
    -----------------------------
    A single prevalence figure conflates two opposite situations. Something contacted
    by 10% of hosts might be:

    * **newly deployed** -- absent for most of the window, then suddenly everywhere.
      Rare *because it is new*, and about to become normal.
    * **anomalous** -- present all along at a trickle, or appearing on one host only.
      Rare *because it does not belong*.

    Comparing a recent slice against the full window separates them. Something whose
    recent reach far exceeds its overall reach is spreading; something flat is
    established; something that has stopped appearing is receding. None of these is by
    itself good or bad -- rollout of a new agent and a worm propagating look identical
    on this axis -- which is exactly why the shape is reported rather than scored.

    Attributes:
        overall_hosts: Distinct hosts across the entire observation window.
        recent_hosts: Distinct hosts within the recent slice.
        first_seen / last_seen: Bounds of observed activity.
        window_hours: Length of the full observation window.
        recent_hours: Length of the recent slice.
    """

    overall_hosts: int = 0
    recent_hosts: int = 0
    first_seen: pd.Timestamp | None = None
    last_seen: pd.Timestamp | None = None
    window_hours: float = 0.0
    recent_hours: float = 0.0

    @property
    def is_emerging(self) -> bool:
        """Present in the recent slice on more hosts than its overall footprint implies.

        The signature of something spreading -- a rollout, or a worm. Requires at least
        two hosts so a single machine cannot look like propagation.
        """
        if self.recent_hosts < 2 or not self.overall_hosts:
            return False
        return self.recent_hosts > self.overall_hosts * 0.75

    @property
    def is_established(self) -> bool:
        """Observed across most of the window rather than confined to part of it."""
        if self.first_seen is None or self.last_seen is None or not self.window_hours:
            return False
        span = (self.last_seen - self.first_seen).total_seconds() / 3600.0
        return span >= self.window_hours * 0.5

    @property
    def confidence_note(self) -> str:
        """How much weight this prevalence figure can bear.

        A four-hour window cannot establish that anything is normal. Saying so beside
        the number stops a short sample being read as a baseline.
        """
        if self.window_hours < 24:
            return (
                f"observation window is only {self.window_hours:.1f}h, far short of the "
                "weeks needed to establish what is normal; treat prevalence as a weak "
                "signal here"
            )
        if self.window_hours < 168:
            return (
                f"observation window is {self.window_hours / 24:.1f} days; prevalence is "
                "indicative but has not seen a full weekly cycle"
            )
        return f"observation window is {self.window_hours / 24:.1f} days"

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_hosts": self.overall_hosts,
            "recent_hosts": self.recent_hosts,
            "is_emerging": self.is_emerging,
            "is_established": self.is_established,
            "first_seen": self.first_seen.isoformat() if self.first_seen is not None else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen is not None else None,
            "window_hours": round(self.window_hours, 2),
            "recent_hours": round(self.recent_hours, 2),
            "confidence_note": self.confidence_note,
        }


@dataclass(frozen=True)
class DestinationProfile:
    """How widely one external address is contacted across the environment.

    Prevalence is the strongest benign signal available without threat intelligence,
    and it is computable from telemetry alone. Shared infrastructure looks like shared
    infrastructure: many hosts, many accounts, and -- most tellingly -- many *different*
    processes, including ones nobody would attribute to an intruder. Adversary
    infrastructure is narrow: few hosts, and usually a single process reaching it.

    Attributes:
        remote_ip: The address profiled.
        hosts: Distinct hosts that contacted it.
        users: Distinct accounts.
        processes: Distinct process images -- the most discriminating of the three.
        connections: Total connection events.
    """

    remote_ip: str
    hosts: tuple[str, ...] = ()
    users: tuple[str, ...] = ()
    processes: tuple[str, ...] = ()
    connections: int = 0
    windowed: WindowedPrevalence = field(default_factory=WindowedPrevalence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "remote_ip": self.remote_ip,
            "hosts": list(self.hosts),
            "users": list(self.users),
            "processes": list(self.processes),
            "connections": self.connections,
            "windowed": self.windowed.to_dict(),
        }


@dataclass(frozen=True)
class ProcessProfile:
    """How established one process image is in the environment.

    A binary running on most hosts, repeatedly, is part of how the estate operates.
    One seen once on one host is not. This does not make either safe or unsafe -- it
    is the base rate an interpretation can rest on.
    """

    process_name: str
    hosts: tuple[str, ...] = ()
    executions: int = 0
    spawned_children: int = 0
    windowed: WindowedPrevalence = field(default_factory=WindowedPrevalence)
    signers: tuple[str, ...] = ()
    """Distinct signing organisations observed for this image name.

    More than one is itself a finding: a name that is sometimes Microsoft-signed and
    sometimes not is either an impersonation or a genuinely ambiguous binary, and
    either way it must not inherit the trusted variant's standing."""
    hashes: tuple[str, ...] = ()
    signature_statuses: tuple[str, ...] = ()

    @property
    def consistently_signed(self) -> bool:
        """Every observation of this image was validly signed by one organisation.

        The property that lets a name be trusted at all. A single unsigned copy
        anywhere means the name is not a reliable identifier in this environment.
        """
        return (
            len(self.signers) == 1
            and bool(self.signers[0])
            and tuple(self.signature_statuses) == (SIG_VALID,)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "process_name": self.process_name,
            "hosts": list(self.hosts),
            "executions": self.executions,
            "spawned_children": self.spawned_children,
            "windowed": self.windowed.to_dict(),
            "signers": list(self.signers),
            "hashes": list(self.hashes),
            "signature_statuses": list(self.signature_statuses),
            "consistently_signed": self.consistently_signed,
        }


@dataclass(frozen=True)
class Identity:
    """One account observed in telemetry.

    Attributes:
        name: Account name.
        kind: ``"service"``, ``"interactive"`` or ``"unknown"`` -- from logon types.
        kind_reason: Why that classification was made.
        hosts_authenticated_to: Hosts this account reached.
        hosts_run_on: Hosts where this account ran processes.
        privileged_signals: Observations suggesting elevated reach. Named *signals*,
            not "is_admin": no telemetry here reads group membership, so this is
            evidence of privileged *behaviour*, which is a weaker claim.
        failed_logons / successful_logons: Observed authentication outcomes.
    """

    name: str
    kind: str
    kind_reason: str
    hosts_authenticated_to: tuple[str, ...] = ()
    hosts_run_on: tuple[str, ...] = ()
    privileged_signals: tuple[str, ...] = ()
    failed_logons: int = 0
    successful_logons: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "kind_reason": self.kind_reason,
            "hosts_authenticated_to": list(self.hosts_authenticated_to),
            "hosts_run_on": list(self.hosts_run_on),
            "privileged_signals": list(self.privileged_signals),
            "failed_logons": self.failed_logons,
            "successful_logons": self.successful_logons,
        }


@dataclass
class EnvironmentModel:
    """A structured description of the environment, derived from telemetry alone.

    Attributes:
        hosts: Every machine observed, keyed by name.
        identities: Every account observed, keyed by name.
        platform: Inferred operating-system family, with evidence.
        platform_reason: What the platform conclusion rests on.
        security_controls: Security/management products observed running.
        channels: Measured telemetry availability (see :mod:`ath.environment.channels`).
        data_sources: Which telemetry sources contributed (``synthetic``, ``defender_export``).
        observation_window: ``(first, last)`` timestamps observed.
        event_count: Total events the model was derived from.
        undetermined: Things the model explicitly cannot establish from telemetry.
    """

    hosts: dict[str, Host] = field(default_factory=dict)
    identities: dict[str, Identity] = field(default_factory=dict)
    destinations: dict[str, DestinationProfile] = field(default_factory=dict)
    processes: dict[str, ProcessProfile] = field(default_factory=dict)
    connection_patterns: dict[tuple[str, str], Any] = field(default_factory=dict)
    """Measured relationship timing, keyed by ``(host, destination)``.

    Carried on the environment model because triage reads it and triage has no other
    route to it. Computed by :mod:`ath.behavior`, never here -- there is exactly one
    implementation of the statistic in the codebase and a test enforces that."""
    platform: str = "unknown"
    platform_reason: str = ""
    security_controls: dict[str, str] = field(default_factory=dict)
    channels: dict[TelemetryChannel, ChannelAssessment] = field(default_factory=dict)
    data_sources: tuple[str, ...] = ()
    observation_window: tuple[pd.Timestamp, pd.Timestamp] | None = None
    event_count: int = 0
    undetermined: tuple[str, ...] = ()

    # -- derived views ---------------------------------------------------------------

    @property
    def servers(self) -> list[Host]:
        return [h for h in self.hosts.values() if h.role == "server"]

    @property
    def workstations(self) -> list[Host]:
        return [h for h in self.hosts.values() if h.role == "workstation"]

    @property
    def service_accounts(self) -> list[Identity]:
        return [i for i in self.identities.values() if i.kind == "service"]

    @property
    def privileged_identities(self) -> list[Identity]:
        return [i for i in self.identities.values() if i.privileged_signals]

    @property
    def available_channels(self) -> set[TelemetryChannel]:
        """Channels a detection may rely on and be trusted."""
        return {c for c, a in self.channels.items() if a.state.usable}

    @property
    def observable_channels(self) -> set[TelemetryChannel]:
        """Channels carrying any signal at all, including sparse ones."""
        return {c for c, a in self.channels.items() if a.state.observable}

    def connection_pattern(self, host: str, remote_ip: str) -> Any | None:
        """Measured timing for one host-to-destination relationship, if any.

        Read from behaviors computed once by :mod:`ath.behavior`, never recomputed.
        This is what lets triage see inter-arrival regularity at all: the statistic
        used to exist only inside the investigation layer, which runs after a case has
        formed, so the layer deciding whether to reassure an analyst was blind to it.
        """
        return self.connection_patterns.get((host, remote_ip))

    def destination_reach(self, remote_ip: str) -> float:
        """Fraction of the environment's hosts that contacted ``remote_ip``.

        Expressed as a fraction rather than a count so the same threshold means the
        same thing in an eight-host lab and a thousand-host estate.
        """
        profile = self.destinations.get(remote_ip)
        if profile is None or not self.hosts:
            return 0.0
        return len(profile.hosts) / len(self.hosts)

    def process_reach(self, process_name: str) -> float:
        """Fraction of the environment's hosts that ran ``process_name``."""
        profile = self.processes.get(process_name.lower())
        if profile is None or not self.hosts:
            return 0.0
        return len(profile.hosts) / len(self.hosts)

    def is_known_security_tool(self, process_name: str) -> str | None:
        """Return the product name if this image is a *verifiably* recognised tool.

        Recognition requires two things, not one: the name must match a known product
        **and** every observation of that name in this environment must have been
        validly signed by a single organisation.

        The second condition is the whole point. This method previously matched on name
        alone, which meant a payload dropped as ``MsMpEng.exe`` inherited Microsoft
        Defender's standing and contributed the largest single benign signal toward
        being dismissed as legitimate. A name is a claim a file makes about itself; a
        signature is an assertion by a named organisation that an attacker cannot forge.

        Note what this still cannot do: ``powershell.exe`` is genuinely Microsoft-signed
        while running an attacker's payload. Signature answers "is this file what it
        claims to be", never "is what it is doing legitimate" -- which is why the triage
        layer's vetoes remain the load-bearing control.
        """
        product = self.security_controls.get(process_name.lower())
        if product is None:
            return None
        profile = self.processes.get(process_name.lower())
        if profile is None or not profile.consistently_signed:
            return None
        return product

    def identity_conflict(self, process_name: str) -> str | None:
        """Describe an image name whose observations disagree about what it is.

        One name, several signers or several hashes, is the signature of impersonation
        -- and it is a fact about the *environment*, visible only because prevalence is
        computed across every host rather than per event.
        """
        profile = self.processes.get(process_name.lower())
        if profile is None:
            return None
        if len(profile.signers) > 1:
            return (
                f"{process_name} appears under {len(profile.signers)} different signing "
                f"organisations here ({', '.join(profile.signers)})"
            )
        unsigned = {s for s in profile.signature_statuses if s != SIG_VALID}
        if profile.signers and unsigned:
            return (
                f"{process_name} is validly signed by {profile.signers[0]} in some "
                f"observations and {', '.join(sorted(unsigned))} in others"
            )
        return None

    @property
    def observation_hours(self) -> float:
        if self.observation_window is None:
            return 0.0
        start, end = self.observation_window
        return (end - start).total_seconds() / 3600.0

    def to_dict(self) -> dict[str, Any]:
        window = (
            [t.isoformat() for t in self.observation_window]
            if self.observation_window else None
        )
        return {
            "platform": self.platform,
            "platform_reason": self.platform_reason,
            "data_sources": list(self.data_sources),
            "observation_window": window,
            "observation_hours": round(self.observation_hours, 2),
            "event_count": self.event_count,
            "hosts": [h.to_dict() for h in self.hosts.values()],
            "identities": [i.to_dict() for i in self.identities.values()],
            "security_controls": dict(self.security_controls),
            "channels": [a.to_dict() for a in self.channels.values()],
            "undetermined": list(self.undetermined),
        }


# --------------------------------------------------------------------------------------
# Derivation
# --------------------------------------------------------------------------------------


def _infer_platform(telemetry: Telemetry) -> tuple[str, str]:
    """Infer the OS family from observed process images, with a stated basis."""
    if telemetry.processes.empty:
        return "unknown", "no process telemetry to infer a platform from"

    names = telemetry.processes["process_name"].astype("string").str.lower()
    markers = sorted(set(names) & _WINDOWS_PROCESS_MARKERS)
    if markers:
        return "windows", f"observed Windows system processes: {', '.join(markers)}"

    exe_share = float(names.str.endswith(".exe").mean())
    if exe_share > 0.5:
        return "windows", (
            f"{exe_share:.0%} of observed process images end in .exe, but no Windows "
            "system process was seen -- platform inferred from naming alone"
        )
    return "unknown", (
        "no Windows system processes observed and image names are not .exe-dominated"
    )


def _host_role(
    name: str,
    interactive_users: set[str],
    remote_sources: set[str],
    remote_logons: int,
    logon_events: int = 0,
) -> tuple[str, str]:
    """Classify a host from authentication behaviour, never from its name.

    A machine that many hosts authenticate *to*, without anyone working *at* it, is
    behaving like a server. A machine someone logs into interactively is behaving
    like a workstation. Both conclusions are stated with the evidence, because both
    are wrong for a terminal server -- the case this method cannot distinguish.

    ``logon_events`` separates two very different unknowns. Both classifications above
    are driven by *logon type*, so a source that records no logon type (CloudTrail has
    no Windows equivalent) leaves both empty -- and the fallback used to report "no
    authentication activity observed" for a host with fifteen authentications on it.
    Stating a false negative as fact is precisely the failure this project exists to
    avoid, so the two cases are now distinguished.
    """
    if remote_sources and not interactive_users:
        return "server", (
            f"reached by remote authentication from {len(remote_sources)} host(s) "
            f"({', '.join(sorted(remote_sources))}) with no interactive logon observed"
        )
    if interactive_users and not remote_sources:
        return "workstation", (
            f"interactive logon(s) by {', '.join(sorted(interactive_users))} and no "
            "inbound remote authentication observed"
        )
    if interactive_users and remote_sources:
        return "workstation", (
            f"interactive logon(s) by {', '.join(sorted(interactive_users))}, but also "
            f"{remote_logons} inbound remote authentication(s) -- could equally be a "
            "jump host or terminal server, which this telemetry cannot distinguish"
        )
    if logon_events:
        return "unknown", (
            f"{logon_events} authentication event(s) observed, but none carry a logon "
            "type or originating host, so the host's function cannot be classified "
            "from them"
        )
    return "unknown", "no authentication activity observed for this host"


def _identity_kind(logon_types: set[int], interactive: int, service: int) -> tuple[str, str]:
    """Classify an account from the logon types observed for it.

    ``-1`` is the sentinel for "this source recorded no logon type" -- which is the
    normal case for cloud control-plane telemetry, where the Windows concept does not
    exist. It must not be rendered as a logon type named "Type -1"; the honest
    statement is that the field was absent, not that it held an odd value.
    """
    known = {t for t in logon_types if t >= 0}
    unclassified = -1 in logon_types

    if not logon_types:
        return "unknown", "no authentication events observed for this account"
    if service and not interactive:
        return "service", (
            f"{service} service-type logon(s) and no interactive logon observed"
        )
    if interactive:
        return "interactive", f"{interactive} interactive logon(s) observed"
    if not known and unclassified:
        return "unknown", (
            "authentication observed, but this telemetry source records no logon type, "
            "so interactive and non-interactive use cannot be told apart"
        )
    names = ", ".join(sorted(describe_logon_type(t) for t in known))
    return "unknown", f"only non-interactive, non-service logon types observed: {names}"


def _privileged_signals(
    hosts_reached: set[str],
    admin_share_hits: int,
    interactive_server_logons: tuple[str, ...],
    median_reach: float,
) -> tuple[str, ...]:
    """Collect evidence of privileged *behaviour*.

    Not "is this an admin" -- no telemetry here reads group membership. These are
    observations that an account has reach a normal account does not, which is the
    strongest claim the available data supports.

    Why reach is measured against the environment, not a fixed number
    -----------------------------------------------------------------
    The obvious signal -- "authenticated to N or more hosts" -- is the same mistake
    ATH-006 exists to avoid, and it fails here for the same reason: every account in
    a normal office reaches the file server and the app server, so an absolute
    threshold of three flags almost everyone and distinguishes nothing. (Measured on
    this project's own dataset, ``>= 3 hosts`` marked 7 of 8 accounts as privileged,
    which is a heuristic that has stopped carrying information.)

    Reach is therefore compared against the *environment's own* median. Distinctive
    breadth is evidence; ordinary breadth is the baseline. The other two signals are
    structural rather than statistical, and stay regardless of environment size.
    """
    signals: list[str] = []

    if admin_share_hits:
        signals.append(
            f"{admin_share_hits} process event(s) referencing an administrative share "
            "(ADMIN$/C$/IPC$), which requires local administrator rights"
        )
    if interactive_server_logons:
        signals.append(
            "interactive logon at the console of server-role host(s): "
            + ", ".join(sorted(interactive_server_logons))
        )
    # Only flag reach that stands out against this environment's own norm.
    if median_reach > 0 and len(hosts_reached) > max(2.0 * median_reach, median_reach + 1):
        signals.append(
            f"authenticated to {len(hosts_reached)} hosts "
            f"({', '.join(sorted(hosts_reached))}), against an environment median of "
            f"{median_reach:.0f}"
        )
    return tuple(signals)


def build_environment_model(telemetry: Telemetry) -> EnvironmentModel:
    """Derive an :class:`EnvironmentModel` from loaded telemetry.

    Deterministic and side-effect free: same telemetry in, same model out. No language
    model participates, because this is the ground truth later reasoning rests on.
    """
    processes, network, logons = telemetry.processes, telemetry.network, telemetry.logons

    interactive_by_host: dict[str, set[str]] = defaultdict(set)
    remote_sources_by_host: dict[str, set[str]] = defaultdict(set)
    remote_logons_by_host: Counter = Counter()

    logon_types_by_user: dict[str, set[int]] = defaultdict(set)
    interactive_hosts_by_user: dict[str, set[str]] = defaultdict(set)
    interactive_by_user: Counter = Counter()
    service_by_user: Counter = Counter()
    hosts_reached_by_user: dict[str, set[str]] = defaultdict(set)
    failures_by_user: Counter = Counter()
    successes_by_user: Counter = Counter()

    for row in logons.to_dict("records"):
        host, user, action = row["device"], row["user"], row["action"]
        raw_type = row["logon_type"]
        logon_type = int(raw_type) if pd.notna(raw_type) else -1

        logon_types_by_user[user].add(logon_type)
        hosts_reached_by_user[user].add(host)
        if action == "success":
            successes_by_user[user] += 1
        else:
            failures_by_user[user] += 1

        if logon_type in _INTERACTIVE_LOGON_TYPES:
            interactive_by_user[user] += 1
            if action == "success":
                interactive_by_host[host].add(user)
                interactive_hosts_by_user[user].add(host)
        if logon_type == 5:
            service_by_user[user] += 1
        if logon_type in _REMOTE_LOGON_TYPES and action == "success":
            remote_logons_by_host[host] += 1
            origin = row.get("source_device") or ""
            if origin and origin != host:
                remote_sources_by_host[host].add(origin)

    # Administrative-share references are a privilege signal available from command
    # lines alone -- a rare case where the richest field pays off outside detection.
    admin_share_by_user: Counter = Counter()
    if not processes.empty:
        command_lines = processes["command_line"].astype("string").fillna("")
        admin_share = command_lines.str.contains(
            r"\\\\[^\\\s]+\\(?:ADMIN\$|C\$|IPC\$)", case=False, regex=True, na=False
        )
        for user in processes.loc[admin_share, "user"]:
            admin_share_by_user[user] += 1

    hosts_run_on_by_user: dict[str, set[str]] = defaultdict(set)
    for row in processes[["device", "user"]].to_dict("records"):
        hosts_run_on_by_user[row["user"]].add(row["device"])

    process_counts = Counter(processes["device"])
    network_counts = Counter(network["device"])
    logon_counts = Counter(logons["device"])

    # Split public from private rather than calling everything "external". The same
    # `is_public_ip` the egress rule (ATH-003) uses decides it, so the environment
    # model and the detection layer cannot disagree about what "external" means --
    # two definitions of that word in one system is a bug waiting to be argued about.
    external_by_host: dict[str, set[str]] = defaultdict(set)
    internal_by_host: dict[str, set[str]] = defaultdict(set)
    for row in network[["device", "remote_ip"]].to_dict("records"):
        remote_ip = row["remote_ip"]
        if not remote_ip:
            continue
        bucket = external_by_host if is_public_ip(remote_ip) else internal_by_host
        bucket[row["device"]].add(remote_ip)

    every_host = sorted(
        set(process_counts) | set(network_counts) | set(logon_counts)
        | set(remote_sources_by_host)
    )
    hosts: dict[str, Host] = {}
    for name in every_host:
        interactive_users = interactive_by_host.get(name, set())
        remote_sources = remote_sources_by_host.get(name, set())
        role, reason = _host_role(
            name, interactive_users, remote_sources, remote_logons_by_host[name],
            logon_counts[name],
        )
        hosts[name] = Host(
            name=name,
            role=role,
            role_reason=reason,
            interactive_users=tuple(sorted(interactive_users)),
            remote_auth_sources=tuple(sorted(remote_sources)),
            process_count=process_counts[name],
            network_count=network_counts[name],
            logon_count=logon_counts[name],
            external_destinations=tuple(sorted(external_by_host.get(name, set()))),
            internal_peers=tuple(sorted(internal_by_host.get(name, set()))),
        )

    every_user = sorted(
        set(logon_types_by_user) | set(hosts_run_on_by_user) | set(admin_share_by_user)
    )

    # The environment's own norm for how many hosts an account touches. Computed here,
    # from this dataset, rather than hardcoded -- see _privileged_signals for why.
    reach_counts = [len(hosts_reached_by_user.get(u, set())) for u in every_user]
    reach_counts = [c for c in reach_counts if c]
    median_reach = float(median(reach_counts)) if reach_counts else 0.0

    server_names = {n for n, h in hosts.items() if h.role == "server"}

    identities: dict[str, Identity] = {}
    for name in every_user:
        kind, reason = _identity_kind(
            logon_types_by_user.get(name, set()),
            interactive_by_user[name],
            service_by_user[name],
        )
        hosts_reached = hosts_reached_by_user.get(name, set())
        interactive_on_servers = tuple(
            h for h in interactive_hosts_by_user.get(name, set()) if h in server_names
        )
        identities[name] = Identity(
            name=name,
            kind=kind,
            kind_reason=reason,
            hosts_authenticated_to=tuple(sorted(hosts_reached)),
            hosts_run_on=tuple(sorted(hosts_run_on_by_user.get(name, set()))),
            privileged_signals=_privileged_signals(
                hosts_reached,
                admin_share_by_user[name],
                interactive_on_servers,
                median_reach,
            ),
            failed_logons=failures_by_user[name],
            successful_logons=successes_by_user[name],
        )

    controls: dict[str, str] = {}
    if not processes.empty:
        observed = set(processes["process_name"].astype("string").str.lower())
        for image, product in _SECURITY_PRODUCT_PROCESSES.items():
            if image in observed:
                controls[image] = product

    destinations = _profile_destinations(network)
    process_profiles = _profile_processes(processes)
    # Behaviors are computed once and read here; the environment does not recompute
    # timing. Imported at call time so the module-level dependency graph stays
    # telemetry -> behavior -> environment rather than becoming circular.
    from ath.behavior import connection_patterns, extract_outbound_relationship_behaviors

    patterns = connection_patterns(extract_outbound_relationship_behaviors(telemetry))

    platform, platform_reason = _infer_platform(telemetry)
    channels = assess_channels(telemetry)

    sources: set[str] = set()
    for df in (processes, network, logons):
        if not df.empty and "source" in df.columns:
            sources.update(s for s in df["source"].astype("string") if s)

    model = EnvironmentModel(
        hosts=hosts,
        identities=identities,
        destinations=destinations,
        processes=process_profiles,
        connection_patterns=patterns,
        platform=platform,
        platform_reason=platform_reason,
        security_controls=controls,
        channels=channels,
        data_sources=tuple(sorted(sources)),
        observation_window=telemetry.time_range if telemetry.event_count else None,
        event_count=telemetry.event_count,
        undetermined=_undetermined(telemetry, channels, hosts),
    )
    return model


def _windowed(
    group: pd.DataFrame, window_start: pd.Timestamp, window_end: pd.Timestamp,
    recent_start: pd.Timestamp,
) -> WindowedPrevalence:
    """Measure one entity's reach over the full window and over a recent slice."""
    recent = group[group["timestamp"] >= recent_start]
    window_hours = (window_end - window_start).total_seconds() / 3600.0
    return WindowedPrevalence(
        overall_hosts=int(group["device"].nunique()),
        recent_hosts=int(recent["device"].nunique()),
        first_seen=group["timestamp"].min(),
        last_seen=group["timestamp"].max(),
        window_hours=window_hours,
        recent_hours=(window_end - recent_start).total_seconds() / 3600.0,
    )


def _recent_boundary(
    window_start: pd.Timestamp, window_end: pd.Timestamp
) -> pd.Timestamp:
    """Where the recent slice begins.

    The final quarter of whatever observation exists, rather than a fixed duration.
    A fixed "last 24 hours" would cover the entire sample on a four-hour dataset and
    make the comparison vacuous; a proportional slice keeps the two figures distinct
    at any window length, and the accompanying `confidence_note` is what stops a short
    window being read as a baseline.
    """
    span = window_end - window_start
    return window_end - (span / 4)


def _profile_destinations(network: pd.DataFrame) -> dict[str, DestinationProfile]:
    """Build a prevalence profile for every external address contacted.

    Only public addresses are profiled: internal peers are a description of the
    network's shape, not of what leaves it, and mixing them in would drown the
    handful of external destinations that matter.
    """
    profiles: dict[str, DestinationProfile] = {}
    if network.empty:
        return profiles

    external = network[network["remote_ip"].map(is_public_ip)]
    if external.empty:
        return profiles

    window_start, window_end = external["timestamp"].min(), external["timestamp"].max()
    recent_start = _recent_boundary(window_start, window_end)

    for remote_ip, group in external.groupby("remote_ip"):
        profiles[str(remote_ip)] = DestinationProfile(
            remote_ip=str(remote_ip),
            hosts=tuple(sorted({d for d in group["device"] if d})),
            users=tuple(sorted({u for u in group["user"] if u})),
            processes=tuple(sorted({p.lower() for p in group["process_name"] if p})),
            connections=int(len(group)),
            windowed=_windowed(group, window_start, window_end, recent_start),
        )
    return profiles


def _profile_processes(processes: pd.DataFrame) -> dict[str, ProcessProfile]:
    """Build a prevalence profile for every process image observed, keyed lower-case."""
    profiles: dict[str, ProcessProfile] = {}
    if processes.empty:
        return profiles

    children = Counter(
        str(p).lower() for p in processes["parent_process_name"] if p
    )
    window_start, window_end = processes["timestamp"].min(), processes["timestamp"].max()
    recent_start = _recent_boundary(window_start, window_end)

    lowered = processes.assign(_image=processes["process_name"].str.lower())
    for image, group in lowered.groupby("_image"):
        name = str(image)
        profiles[name] = ProcessProfile(
            process_name=name,
            hosts=tuple(sorted({d for d in group["device"] if d})),
            executions=int(len(group)),
            spawned_children=int(children.get(name, 0)),
            windowed=_windowed(group, window_start, window_end, recent_start),
            signers=tuple(sorted({s for s in group.get("signer", []) if s})),
            hashes=tuple(sorted({h for h in group.get("sha256", []) if h})),
            signature_statuses=tuple(sorted({
                s for s in group.get("signature_status", []) if s
            })),
        )
    return profiles


def _undetermined(
    telemetry: Telemetry,
    channels: dict[TelemetryChannel, ChannelAssessment],
    hosts: dict[str, Host],
) -> tuple[str, ...]:
    """Enumerate what this model knows it cannot establish.

    The most important field on the model. A description of an environment that lists
    only what it found reads as complete; listing what it could not determine is what
    keeps a downstream capability plan from treating silence as absence.
    """
    unknowns: list[str] = [
        "Asset criticality: which hosts or accounts matter most is a business fact, "
        "not a telemetry fact, and must be supplied rather than inferred.",
        "Group membership and actual privilege: no directory or IAM telemetry is "
        "ingested, so privilege is inferred from observed behaviour only.",
        "Software inventory: only processes that *executed* during the observation "
        "window are visible; installed-but-unused software is invisible.",
    ]

    window_hours = (
        (telemetry.time_range[1] - telemetry.time_range[0]).total_seconds() / 3600.0
        if telemetry.event_count else 0.0
    )
    if window_hours < 168:
        unknowns.append(
            f"Baseline normality: the observation window is {window_hours:.1f} hours. "
            "Distinguishing unusual from merely unfamiliar needs weeks of history, so "
            "any 'normal for this environment' claim is out of reach here."
        )

    if not channels[TelemetryChannel.NETWORK_INBOUND].state.observable:
        unknowns.append(
            "Externally exposed services: no inbound network telemetry is present, so "
            "which services accept connections from outside cannot be determined."
        )

    if not channels[TelemetryChannel.CLOUD_CONTROL_PLANE].state.observable:
        unknowns.append(
            "Cloud infrastructure: no cloud control-plane telemetry is ingested. The "
            "environment may have cloud assets that are entirely invisible here."
        )

    ambiguous = [h.name for h in hosts.values() if h.role == "unknown"]
    if ambiguous:
        unknowns.append(
            f"Role of {len(ambiguous)} host(s) ({', '.join(sorted(ambiguous)[:5])}): no "
            "authentication activity was observed, so their function is unclassified."
        )

    return tuple(unknowns)
