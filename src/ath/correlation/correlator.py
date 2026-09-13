"""Deterministic correlation of findings into attack chains.

The naive approach and why it fails
-----------------------------------
The tempting implementation is::

    if abs(a.time - b.time) < timedelta(minutes=30):
        same_case(a, b)

On this dataset that produces one enormous case containing the intrusion *and* the IT
administrator's legitimate work, because everything happened during the same morning.
In a real SOC it is worse: on a busy host, time proximity groups essentially
everything, and the "attack chain" becomes a list of everything that happened today.
Time is the weakest possible correlation signal, and using it alone is the single most
common mistake in home-grown correlation engines.

What this module does instead
-----------------------------
Two findings are linked when they clear **both** bars:

1. their combined signal score reaches ``min_score``, and
2. at least one **structural** signal is present.

Structural signals describe a concrete relationship recorded in the telemetry:

===================== ====== ===========================================================
Signal                Weight Meaning
===================== ====== ===========================================================
shared_evidence         +3   The same telemetry event supports both findings.
same_process            +3   Both cite activity by the same process *instance*.
process_lineage         +3   A process in one finding is the parent of one in the other.
sibling_lineage         +2   Both findings' processes were started by the *same parent
                             instance*, and that parent looks like a single session
                             rather than a launcher. The weakest structural signal --
                             see below -- and deliberately worth less than the others.
host_movement           +3   One finding's host is the other's authentication source or
                             target -- a directed host-to-host relationship.
auth_then_exec          +3   An authentication landing on a host, followed shortly by
                             execution on that same host -- the named special case of
                             the cross-channel link below.
shared_principal        +3   Two findings resting on *different kinds* of telemetry
                             whose evidence names the same principal, inside
                             ``cross_domain_window``. The only signal that can put two
                             specialist domains in one case on evidence neither of them
                             shares.
===================== ====== ===========================================================

and circumstantial signals, which can support a link but never create one:

===================== ====== ===========================================================
same_device             +2   Same host.
same_user               +2   Same account.
temporal_close          +2   Within ``tight_window`` (default 10 min).
temporal_near           +1   Within ``max_gap`` (default 60 min).
===================== ====== ===========================================================

The weights are not arbitrary, and the shape matters more than the numbers: structural
signals are worth more than circumstantial ones, and no combination of circumstantial
signals alone can reach a link, because of rule (2). Same-host + same-user + close-in-
time sums to 6, which clears ``min_score`` -- and is still refused, because on a single
workstation those three facts are true of almost every pair of alerts.

Why ``sibling_lineage`` is worth 2 and not 3
--------------------------------------------
``process_lineage`` requires that a process in one finding *is* the parent of a process
in the other: the two findings are directly connected in the process tree. Sibling
findings are not. They are connected only by a third process that neither finding
mentions, and which may itself be entirely innocent -- a shell is a shell.

That is a real relationship but a weaker one, so it is priced lower. The weight is
honest labelling rather than a safeguard, and it is worth being precise about which,
because it would be easy to imply otherwise: **the weights do not gate this signal at
all.** Two findings that share a parent necessarily share a device (+2), and the sibling
window is the same ten minutes as ``tight_window``, so ``temporal_close`` (+2) always
comes with it. The floor is therefore 2 + 2 + 2 = 6, which is already over
``min_score``. Whenever the sibling predicate holds, the link is made.

So the entire guard lives in the predicate -- in :meth:`_ProcessIndex.session_parents` --
and not in the arithmetic. The +2 exists so that a reader of the output can see this was
the weakest reason two findings were joined, which matters when a case is being argued
with. It is not a second line of defence, and treating it as one would be a mistake.

What stops every process on a workstation being everyone's sibling
-------------------------------------------------------------------
Naively, "same parent process" links far too much: ``explorer.exe`` is the parent of
everything a user launches all day, and ``services.exe`` of everything the machine runs.
A rule keying on shared parentage alone would merge a morning's unrelated alerts into
one case and call it an attack chain.

The guard is not a list of parent names to ignore. Name lists are wrong in both
directions -- they miss the launcher you did not think of, and an attacker who renames a
shell walks through them. Instead, two properties are measured **from the telemetry
itself**, and a parent has to satisfy both:

``fan-out``      how many distinct children it started. An operator's shell session
                 starts a handful; an installer or a service host starts hundreds.
``spawn span``   the wall-clock time between its first and last child. This is the
                 discriminating one. A shell an operator is typing into spawns its
                 children over seconds or minutes. A desktop shell spawns them across
                 the whole working day.

On this project's own dataset the separation is stark, and both sides of it are real
rather than constructed::

    PC03/7419    6 children over  3m40s   the ransomware operator's shell
    PC01/6612    4 children over  3m19s   the intrusion's discovery burst
    PC05/631     4 children over  2h45m   a user's desktop shell -- OUTLOOK, WINWORD,
                                          chrome, powershell, spread over a morning

``PC05/631`` is the case that matters. It has a *small* fan-out, so fan-out alone would
have admitted it; its two-and-three-quarter-hour span is what rules it out. This is why
the span bound carries the weight and the fan-out bound is defence in depth.

**Honest limit on the fan-out bound.** The largest fan-out anywhere in this dataset is
6, so ``max_session_fan_out`` is never the binding constraint here and this dataset
cannot validate its value. It is exercised only by a synthetic unit test. The span bound
is the one measured against real generated telemetry.

What stops unrelated findings from grouping
-------------------------------------------
* The structural requirement. The two false-positive findings on PC07 link to *each
  other* (same process, PID 5150) but to nothing on PC01: different host, different
  user, no shared process, no authentication path. Score 1, no structural signal.
* ``max_gap``. Findings further apart than this are never compared, which stops a chain
  growing indefinitely through transitive links across a whole day.
* Directionality. ``host_movement`` is asserted only where an authentication actually
  connects two hosts, not merely because two hosts appear in the same case.

How two domains are joined at all
----------------------------------
Four of the signals above (``shared_evidence``, ``same_process``, ``process_lineage``,
``sibling_lineage``) need the two findings to cite one telemetry event or one process
instance, which rows in two different canonical tables cannot do. ``host_movement`` needs
a directed host relationship, which no cloud or cluster finding carries. So the only
signals that can put an *identity* finding and a *control-plane* finding -- or an
endpoint and a network finding -- in one case are the last two, and until M19b they were
one signal gated by a list of three rule ids::

    _AUTH_RULES = frozenset({"ATH-005", "ATH-006"})
    _REMOTE_EXEC_RULES = frozenset({"ATH-007"})

``reports/m19b/necessity/AUDIT.md`` measured the consequence: on flaws.cloud, 79,424
authentication rows and 1,857,154 control-plane rows produced 280 control-plane cases and
one identity case, and never a case containing both -- not because the evidence was
absent but because no pair of rule ids outside that product could produce a link. The
same failure mode ``ath.agent.specialists.Specialist`` documents removing from the
specialist gates, one layer down.

What replaced it is a property of the *findings*, not of their rule ids. Every finding
declares the telemetry channels it rests on (``Finding.channels``, else its
``fields_used``), every channel belongs to one domain family
(:data:`CHANNEL_FAMILY`, exhaustive over ``ath.channels.TelemetryChannel``), and two
findings are candidates for a cross-channel link when their families are **disjoint** --
different kinds of telemetry, not two readings of one kind. A candidate pair links when
either

* it names the same principal (:data:`PRINCIPAL_COLUMNS`, compared as the adapters
  canonicalised it) inside ``cross_domain_window`` -- ``shared_principal``; or
* the identity half landed on the host the endpoint half then ran on, inside
  ``auth_exec_window`` -- ``auth_then_exec``, which keeps its name and its meaning and
  loses only the rule ids. It stays a separate case because it is the one cross-family
  relationship that does *not* need a shared principal name: a service-launched shell
  runs as the service account, not as the account that authenticated.

A rule written tomorrow is classified the moment it declares its fields. Nothing in this
module names a rule.

``shared_principal`` is worth 3 and ``min_score`` is 5, so the principal alone never
makes a link: something circumstantial -- the same host, the same account, or ten minutes
-- has to agree with it. That is the same arithmetic that stops ``same_device`` +
``same_user`` + ``temporal_close`` from linking on their own, applied from the other side.

What the triage verdict does here
---------------------------------
Nothing to the links. A finding the benign layer set aside (``likely_benign``, with cited
evidence) still links, still joins a case that has an unexplained finding in it, and is
never dropped from the output. What it cannot do is *raise* a case by itself: a component
whose every member was set aside is not turned into an investigation, because each member
already carries the counter-case an investigation would produce, and raising it cost an
analyst a case for nothing (the benign look-alike's second case in INC-001 and the quiet
day's only case, M15-4). The correlator does not decide which findings are benign; it is
told, by finding id, in ``set_aside``.

What could still cause false correlation -- stated honestly
------------------------------------------------------------
* **Shared infrastructure.** A jump box or terminal server legitimately produces
  ``host_movement`` and ``auth_then_exec`` signals between unrelated sessions. Without
  an exclusion list this correlator would chain them.
* **PID reuse, where the telemetry cannot see past it.** Every process signal here
  keys on :class:`~ath.instance_identity.InstanceKey`, so where both rows carry an
  instance identity from the same authority the join *is* the identity comparison and
  PID reuse cannot produce a link at all. Where a row asserts no identity -- or the two
  identities come from different authorities, which cannot confirm each other -- the
  comparison falls back to ``(device, pid)``, which names a slot the operating system
  reissues. Those links are still made, because refusing them would discard every
  attribution on a corpus that records no identity, and they are labelled
  ``inferred from pid`` in the signal text and counted in
  :class:`CorrelationStats`. A labelled fallback is bounded by ``max_gap`` exactly as
  before; what has changed is that it is no longer indistinguishable, in the output,
  from an observation.
* **Transitive drift.** Cases are connected components, so A-B and B-C put A and C in
  one case even if A and C share nothing. That is usually correct for intrusions --
  which are chains -- but it means one bad link can merge two cases.
* **Busy service accounts.** An account used by automation across many hosts generates
  ``same_user`` plus ``host_movement`` broadly, and would over-group.
* **A principal that is not a person.** ``shared_principal`` joins two domains' findings
  that name one principal, and ``SYSTEM``, a CI service account or an AWS service
  principal names itself on unrelated activity all day. ``cross_domain_window`` and the
  score bar are the only bounds on that; what it actually did to each corpus in this
  repository is measured in ``reports/m19b/link/BEFORE_AFTER.md`` rather than asserted
  here.
* **A shell used for two unrelated things.** ``sibling_lineage`` cannot tell an operator
  who ran two stages of one attack from an administrator who ran two unrelated commands
  in one ``cmd.exe`` inside ten minutes. Both are genuinely "one session", and the
  correlator groups them. That is a deliberate trade: the session is the unit of human
  intent, and separating them would need intent, which the telemetry does not carry.
* **A parent nobody identified.** The sibling relation keys on the parent's
  :class:`~ath.instance_identity.InstanceKey`, which is the parent's identity when the
  child row names one and ``(device, parent_pid)`` when it does not. Sources differ
  sharply here: Sysmon writes ``ParentProcessGuid`` on every process-creation event,
  while this project's own generated corpus names a parent instance on 7 of 462 rows,
  so on that corpus nearly every sibling relation is a slot comparison and says so.
  Where it is a slot comparison, two runs that reused one parent PID inside
  ``sibling_window`` are indistinguishable, and the fan-out and span bounds are measured
  over the pooled children of both -- which can only make the pair *less* likely to read
  as one session, so the fallback errs towards refusing the link.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass
from datetime import timedelta
from functools import lru_cache
from typing import Any

import pandas as pd

from ath.channels import TelemetryChannel
from ath.correlation.chain import FindingLink, InvestigationCase
from ath.hunting.finding import Finding, Severity
from ath.instance_identity import (
    INFERRED_FROM_PID,
    InstanceKey,
    instance_key,
    match_keys,
)
from ath.logging_setup import get_logger
from ath.mitre.mapper import map_finding
from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS
from ath.telemetry.loader import Telemetry

logger = get_logger(__name__)

# Signal weights. Structural signals are worth strictly more than circumstantial ones.
W_SHARED_EVIDENCE = 3
W_SAME_PROCESS = 3
W_PROCESS_LINEAGE = 3
W_SIBLING_LINEAGE = 2
W_HOST_MOVEMENT = 3
W_AUTH_THEN_EXEC = 3
W_SHARED_PRINCIPAL = 3
W_SAME_DEVICE = 2
W_SAME_USER = 2
W_TEMPORAL_CLOSE = 2
W_TEMPORAL_NEAR = 1

STRUCTURAL_SIGNALS = frozenset(
    {
        "shared_evidence",
        "same_process",
        "process_lineage",
        "sibling_lineage",
        "host_movement",
        "auth_then_exec",
        "shared_principal",
    }
)

# --------------------------------------------------------------------------------------
# Cross-channel linking: which *kind* of telemetry a finding rests on.
#
# This table is what replaced the rule-id allowlist described above. It is keyed on the
# channel vocabulary every rule already declares, so a rule written tomorrow is
# classified the moment it declares its fields and nothing here has to be kept current.
# It is exhaustive over ``TelemetryChannel`` and
# ``tests/test_correlation_cross_domain.py`` asserts that it stays so: a channel nobody
# classified is then a failing test rather than a link that quietly stops firing, which
# is the failure mode the allowlist had.
# --------------------------------------------------------------------------------------

FAMILY_ENDPOINT = "endpoint"
FAMILY_IDENTITY = "identity"
FAMILY_NETWORK = "network"
FAMILY_CONTROL_PLANE = "control_plane"

CHANNEL_FAMILY: dict[TelemetryChannel, str] = {
    # Endpoint: what ran on a host, and what started it.
    TelemetryChannel.PROCESS_EXECUTION: FAMILY_ENDPOINT,
    TelemetryChannel.PROCESS_COMMAND_LINE: FAMILY_ENDPOINT,
    TelemetryChannel.PROCESS_LINEAGE: FAMILY_ENDPOINT,
    TelemetryChannel.HANDLE_ACCESS: FAMILY_ENDPOINT,
    TelemetryChannel.FILE_EVENTS: FAMILY_ENDPOINT,
    TelemetryChannel.REGISTRY: FAMILY_ENDPOINT,
    TelemetryChannel.SCRIPT_BLOCK: FAMILY_ENDPOINT,
    # Identity: who authenticated, from where, and how it was proven.
    TelemetryChannel.AUTHENTICATION: FAMILY_IDENTITY,
    TelemetryChannel.AUTH_SOURCE_ATTRIBUTION: FAMILY_IDENTITY,
    TelemetryChannel.AUTH_FACTOR: FAMILY_IDENTITY,
    # Network: who a host talked to.
    TelemetryChannel.NETWORK_FLOW: FAMILY_NETWORK,
    TelemetryChannel.NETWORK_INBOUND: FAMILY_NETWORK,
    TelemetryChannel.NETWORK_URL: FAMILY_NETWORK,
    TelemetryChannel.DNS_QUERY: FAMILY_NETWORK,
    # Control plane: what an identity did to a cloud or cluster resource. Cloud
    # *authentication* sits here rather than under identity because a console login is
    # an action on the control plane; no rule in this repository declares that channel
    # today, so the placement changes no measurement, and it is stated rather than
    # omitted so this table stays total over the vocabulary.
    TelemetryChannel.CLOUD_CONTROL_PLANE: FAMILY_CONTROL_PLANE,
    TelemetryChannel.CLOUD_MANAGEMENT_ACTIVITY: FAMILY_CONTROL_PLANE,
    TelemetryChannel.CONTAINER_AUDIT: FAMILY_CONTROL_PLANE,
}

CHANNELS_WITHOUT_FAMILY: frozenset[TelemetryChannel] = frozenset({
    # Message delivery metadata belongs to none of the four domain specialists, so a
    # finding resting only on it has no family and forms no cross-channel link. Listed
    # rather than left out, so "unclassified" is a decision and not an oversight.
    TelemetryChannel.EMAIL,
})

PRINCIPAL_COLUMNS: dict[str, tuple[str, ...]] = {
    EVENT_PROCESS: ("user",),
    EVENT_NETWORK: ("user",),
    EVENT_LOGON: ("user",),
    # Both columns, deliberately. ``actor`` is who called; ``target_actor`` is whose
    # authority the call changed, and an escalation chain is exactly the case where they
    # differ -- the principal a grant created is the principal whose later activity
    # belongs in the same case. ``ath.schema`` documents why conflating them is the
    # mistake that would match the wrong identity.
    EVENT_CONTROL: ("actor", "target_actor"),
}

CROSS_DOMAIN_WINDOW = timedelta(minutes=15)
"""Default :attr:`CorrelationConfig.cross_domain_window`: how far apart two findings from
different channel families may be and still be read as one principal's activity.

Chosen from the windows already in this file rather than invented, so a pre-registration
can quote it by name. ``tight_window``, ``sibling_window`` and ``max_session_span`` are
all ten minutes and all describe activity *within* one host or one process tree, which is
a tighter question than this one. ``max_gap`` (sixty minutes) is not a causal claim at
all -- it is the horizon beyond which :func:`correlate` does not compare two findings, so
it bounds this window rather than supplying it. That leaves ``auth_exec_window``, fifteen
minutes, the one existing window that already answers "did A plausibly cause B *across
two different kinds of telemetry*". This window answers the same question for every other
pair of families, so it takes the same value.
"""


@dataclass(frozen=True)
class CorrelationConfig:
    """Tunable correlation parameters.

    Attributes:
        min_score: Combined weight required to link two findings.
        require_structural: Refuse links supported only by circumstantial signals.
            Turning this off reproduces the naive behaviour and is useful in tests to
            demonstrate what it prevents.
        max_gap: Findings further apart than this are never compared.
        tight_window: Gap qualifying for the stronger temporal signal.
        auth_exec_window: How long after an authentication a remote execution on the
            same host still counts as caused by it.
        cross_domain_window: How far apart two findings resting on *different* channel
            families may be and still be linked by ``shared_principal``. Bounded by
            ``max_gap``, which is the horizon beyond which no pair is compared at all;
            see :data:`CROSS_DOMAIN_WINDOW` for why it takes the value it does.
        sibling_window: How far apart two findings sharing a parent process may be and
            still be treated as siblings. Separate from ``tight_window`` so the sibling
            relation can be tightened without changing what ``temporal_close`` means.
        max_session_fan_out: The most distinct children a parent may have started and
            still be read as one session rather than a launcher. Defence in depth: the
            largest fan-out in this project's dataset is 6, so this bound is never the
            binding constraint there and only a synthetic test exercises it.
        max_session_span: The longest a parent's children may be spread over and still
            be read as one session. This is the bound that does the real work -- a
            desktop shell has a small fan-out but spawns across the whole day.
        min_case_size: Cases smaller than this are discarded as isolated findings,
            unless the finding clears ``singleton_min_severity``.
        singleton_min_severity: A finding that linked to nothing still becomes a
            one-finding case at or above this severity.

            Isolated findings used to be dropped outright, on the reasoning that "an
            isolated finding is an alert, not a chain". That is right about naming and
            wrong about consequences: the investigation layer only ever runs on cases,
            so dropping singletons meant a lone CRITICAL detection produced no
            investigation at all -- measured as INC-002 in the incident benchmark,
            where a cloud credential-stuffing attack was detected and then generated
            zero facts and zero tool calls.

            The threshold is HIGH deliberately, and it lines up with the triage layer's
            ``MAX_SEVERITY_FOR_BENIGN``: findings that benign assessment is never
            allowed to clear are exactly the ones that warrant investigation without
            corroboration. Below it, a lone finding stays an alert, so this does not
            reopen the "every finding is a case" behaviour that would make the
            triage-reduction metric meaningless.
    """

    min_score: int = 5
    require_structural: bool = True
    max_gap: timedelta = timedelta(minutes=60)
    tight_window: timedelta = timedelta(minutes=10)
    singleton_min_severity: Severity = Severity.HIGH
    auth_exec_window: timedelta = timedelta(minutes=15)
    cross_domain_window: timedelta = CROSS_DOMAIN_WINDOW
    sibling_window: timedelta = timedelta(minutes=10)
    max_session_fan_out: int = 12
    max_session_span: timedelta = timedelta(minutes=10)
    min_case_size: int = 2

    def __post_init__(self) -> None:
        """Refuse a cross-domain window that could not mean what it says.

        :func:`correlate` skips any pair further apart than ``max_gap`` before scoring
        it, so a ``cross_domain_window`` beyond that silently collapses to ``max_gap``.
        A setting that is quietly ignored is worse than one that is refused.
        """
        if self.cross_domain_window > self.max_gap:
            raise ValueError(
                f"cross_domain_window ({self.cross_domain_window}) exceeds max_gap "
                f"({self.max_gap}): pairs further apart than max_gap are never "
                "compared, so the wider window would silently mean max_gap."
            )


class _ProcessIndex:
    """Look-ups from telemetry needed for process-level correlation.

    Built once per correlation run. Maps each telemetry event id to the process
    *instance* it was produced by -- an :class:`~ath.instance_identity.InstanceKey` --
    and to the instance that started it, which is what lets us assert process lineage
    between two findings.

    Why a key object and not ``(device, pid)``
    ------------------------------------------
    A PID is a slot the operating system reissues, so ``(device, pid)`` names a slot and
    not a process. Keyed that way, a lineage link between two findings can rest on two
    *different* runs that happened to hold the same number, and nothing in the output
    says so. :class:`~ath.instance_identity.InstanceKey` carries the source's own
    instance identity when there is one and falls back to the slot when there is not,
    and :meth:`~ath.instance_identity.InstanceKey.joins` reports which of the two
    answered -- so a link that rested on the slot is labelled rather than silent.

    It also records, for every parent instance observed, how many distinct children it
    started and over what span. Those two numbers are what separate a shell an operator
    is typing into from a launcher that starts things all day -- see
    :meth:`session_parents`.
    """

    def __init__(self, telemetry: Telemetry) -> None:
        self.key_of: dict[str, InstanceKey] = {}
        self.parent_key_of: dict[str, InstanceKey] = {}
        self._children: dict[InstanceKey, set[InstanceKey]] = {}
        self._spawned_at: dict[InstanceKey, list[Any]] = {}

        procs = telemetry.processes
        has_identity = "process_guid" in procs.columns
        has_parent_identity = "parent_process_guid" in procs.columns
        for row in procs.itertuples(index=False):
            identity = getattr(row, "process_guid", "") if has_identity else ""
            key = instance_key(identity, row.device, row.process_id)
            if key is not None:
                self.key_of[row.event_id] = key
            parent_identity = (
                getattr(row, "parent_process_guid", "") if has_parent_identity else ""
            )
            parent = instance_key(parent_identity, row.device, row.parent_process_id)
            if parent is None:
                continue
            self.parent_key_of[row.event_id] = parent
            if key is not None:
                self._children.setdefault(parent, set()).add(key)
            self._spawned_at.setdefault(parent, []).append(row.timestamp)

        # Network events inherit the identity of the process that opened the connection,
        # which is what links a PowerShell execution to its own outbound traffic. Where
        # the source wrote no identity on the connection -- a Sysmon 3 without a
        # ProcessGuid -- the key falls back to the slot, and every link built on it is
        # labelled, because that attribution is the one M18b-1 measured as 94.8%
        # ambiguous on real telemetry.
        net = telemetry.network
        net_has_identity = "process_guid" in net.columns
        for row in net.itertuples(index=False):
            identity = getattr(row, "process_guid", "") if net_has_identity else ""
            key = instance_key(identity, row.device, row.process_id)
            if key is not None:
                self.key_of[row.event_id] = key

    def keys(self, finding: Finding) -> set[InstanceKey]:
        """The process instances this finding's evidence was produced by."""
        return {self.key_of[e] for e in finding.event_ids if e in self.key_of}

    def parent_keys(self, finding: Finding) -> set[InstanceKey]:
        """The instances that started this finding's processes."""
        return {
            self.parent_key_of[e] for e in finding.event_ids if e in self.parent_key_of
        }

    def fan_out(self, parent: InstanceKey) -> int:
        """How many distinct child instances this parent was observed to start."""
        return len(self._children.get(parent, ()))

    def spawn_span(self, parent: InstanceKey) -> timedelta:
        """Wall-clock time between this parent's first and last observed child."""
        times = self._spawned_at.get(parent)
        if not times:
            return timedelta(0)
        return max(times) - min(times)

    def session_parents(
        self, finding: Finding, config: CorrelationConfig
    ) -> set[InstanceKey]:
        """Those of the finding's parents that look like a single session.

        A parent qualifies when it started few enough children, closely enough
        together, to read as one burst of activity rather than a launcher that starts
        things all day. Both bounds come off the telemetry, so no process is named here
        and there is no allow-list to keep up to date -- a renamed shell is measured
        exactly like any other.

        The bounds are measured per *key*, which is per instance where the rows carry
        identities and per slot where they do not. Pooling two runs of one slot can only
        raise the fan-out and lengthen the span, so the fallback errs towards refusing
        the sibling relation rather than towards asserting it.
        """
        return {
            parent
            for parent in self.parent_keys(finding)
            if self.fan_out(parent) <= config.max_session_fan_out
            and self.spawn_span(parent) <= config.max_session_span
        }


def _signal(name: str, weight: int, inferred: bool) -> str:
    """One signal's rendering, carrying its weight and how the join was made.

    ``process_lineage(+3)`` is an observation about two process instances;
    ``process_lineage(+3, inferred from pid)`` is an observation about two PID slots
    that may or may not be the same instances. An analyst arguing with a case needs to
    see which one they are reading, so the distinction is in the text and not only in a
    counter.
    """
    suffix = f", {INFERRED_FROM_PID}" if inferred else ""
    return f"{name}(+{weight}{suffix})"


def _stronger(left: tuple[bool, bool], right: tuple[bool, bool]) -> tuple[bool, bool]:
    """Combine two answers to one question, preferring the identity-backed one.

    A lineage relation is asked in both directions. If either direction can evidence it
    by identity, the relation is evidenced by identity; reporting it as inferred because
    the other direction could only reach a slot would understate what was actually seen.
    """
    joined = left[0] or right[0]
    identity_backed = (left[0] and not left[1]) or (right[0] and not right[1])
    return joined, joined and not identity_backed


def _hosts_of(finding: Finding) -> set[str]:
    """Every host a finding touches, including movement sources and targets."""
    hosts = {finding.device}
    source = finding.metadata.get("source_device")
    if source:
        hosts.add(str(source))
    hosts.update(str(d) for d in finding.metadata.get("target_devices", []) or [])
    return hosts


def _time_gap(a: Finding, b: Finding) -> timedelta:
    """Gap between two findings' time windows; zero when they overlap."""
    if a.last_seen >= b.first_seen and b.last_seen >= a.first_seen:
        return timedelta(0)
    return (
        b.first_seen - a.last_seen if b.first_seen > a.last_seen else a.first_seen - b.last_seen
    )


@lru_cache(maxsize=None)
def _declared_channels_of_rule(rule_id: str) -> frozenset[TelemetryChannel]:
    """The channels a rule declares, for a finding that declares none of its own.

    Every finding a detector in this repository emits carries that detector's
    ``fields_used``, so this path is reached only by a :class:`Finding` assembled by
    hand -- in a test, or by a caller building one from an external alert. The rule's own
    declaration is then the last *declared* answer available, and it is read off the rule
    exactly as ``ath.environment.coverage`` reads it, never from a table of rule ids kept
    in this module. An unknown rule id classifies as nothing rather than raising: a
    finding this repository did not produce is not a reason to refuse to correlate.
    """
    from ath.environment.coverage import channels_for_fields  # noqa: PLC0415
    from ath.hunting.base import get_detector  # noqa: PLC0415

    try:
        detector = get_detector(rule_id)
    except KeyError:
        return frozenset()
    return frozenset(detector.channels or channels_for_fields(detector.fields_used))


def channel_families(finding: Finding) -> frozenset[str]:
    """Which domain families this finding's telemetry belongs to.

    Usually one. A finding naming process execution, command line and lineage is three
    views of one endpoint observation, and they are one family. ``ATH-003`` is the single
    rule that spans two families on its own (network flow *and* process execution), and
    it is why :func:`_cross_channel_link` requires the two findings' families to be
    **disjoint** rather than merely different: a finding the endpoint specialist also
    reads is not a second domain's stage, which is the same judgement
    ``ath.evaluation.necessity`` makes when it calls such a case redundant.
    """
    from ath.environment.coverage import channels_for_fields  # noqa: PLC0415

    channels = set(finding.channels) or channels_for_fields(finding.fields_used)
    if not channels:
        channels = set(_declared_channels_of_rule(finding.rule_id))
    return frozenset(CHANNEL_FAMILY[c] for c in channels if c in CHANNEL_FAMILY)


def _principal_name(value: Any) -> str:
    """One identity column's value, as the adapters already canonicalised it.

    No case folding, no stripping of domain prefixes, no shortening of
    ``system:serviceaccount:<ns>:<name>``. The adapters decided what a principal's
    canonical name is (``cloudtrail_source._principal``, ``k8s_audit_source._principal``)
    and a second opinion here would be an identity rule nothing else in the pipeline
    applies -- which is how two systems come to disagree about whether two rows are the
    same person. Only whitespace and pandas' spellings of "missing" are removed, because
    those are absence rather than a name.
    """
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.lower() in {"", "nan", "none", "<na>", "nat"} else text


class _CrossChannelIndex:
    """What a run needs to ask whether two findings are one principal's activity.

    Two look-ups, both built once per correlation run and both keyed by ``finding_id``:

    ``families``
        the channel families a finding rests on. Cached because
        :func:`channel_families` is asked once per *pair*, and a corpus with 1,476
        findings is a million pairs.
    ``principals``
        the principals a finding's evidence rows name. Built by one vectorised pass per
        table over the ids the findings actually cite -- not an index over every row,
        because flaws.cloud is 1.86M control rows and the cases cite tens of thousands.

    An index built with no telemetry answers "no principals", which is what a caller of
    :func:`score_pair` that supplies none gets: ``auth_then_exec`` still fires, because
    it rests on channel families and a device that the findings themselves carry, and
    ``shared_principal`` cannot, because it rests on rows this index was not given.
    """

    def __init__(
        self,
        telemetry: Telemetry | None = None,
        findings: Sequence[Finding] = (),
    ) -> None:
        self._families: dict[str, frozenset[str]] = {}
        self._principals: dict[str, frozenset[str]] = {}
        self._by_event: dict[str, frozenset[str]] = {}
        if telemetry is None or not findings:
            return
        cited = {str(e) for f in findings for e in f.event_ids}
        if not cited:
            return
        for event_type, columns in PRINCIPAL_COLUMNS.items():
            frame = telemetry.table(event_type)
            if frame.empty or "event_id" not in frame.columns:
                continue
            present = [c for c in columns if c in frame.columns]
            if not present:
                continue
            matched = frame[frame["event_id"].astype("string").isin(cited)]
            if matched.empty:
                continue
            for record in matched[["event_id", *present]].to_dict("records"):
                names = frozenset(
                    _principal_name(record[c]) for c in present
                ) - {""}
                if names:
                    self._by_event[str(record["event_id"])] = names

    def families(self, finding: Finding) -> frozenset[str]:
        cached = self._families.get(finding.finding_id)
        if cached is None:
            cached = channel_families(finding)
            self._families[finding.finding_id] = cached
        return cached

    def principals(self, finding: Finding) -> frozenset[str]:
        cached = self._principals.get(finding.finding_id)
        if cached is None:
            names: set[str] = set()
            for event_id in finding.event_ids:
                names |= self._by_event.get(str(event_id), frozenset())
            cached = frozenset(names)
            self._principals[finding.finding_id] = cached
        return cached


def score_pair(
    a: Finding,
    b: Finding,
    index: _ProcessIndex,
    config: CorrelationConfig,
    cross: _CrossChannelIndex | None = None,
) -> tuple[int, list[str], bool]:
    """Score the relationship between two findings.

    Args:
        a: One finding.
        b: The other.
        index: The run's process-instance look-ups.
        config: Correlation parameters.
        cross: The run's cross-channel look-ups. Omitting it does not change any signal
            the findings themselves can evidence -- ``auth_then_exec`` included -- but
            ``shared_principal`` needs telemetry rows and cannot fire without one.
            :func:`correlate_with_stats` always supplies one.

    Returns:
        ``(score, signal_names, has_structural_signal)``. Signal names carry their
        weight so the reasoning is legible in output, e.g. ``"same_process(+3)"``.
    """
    cross = cross if cross is not None else _CrossChannelIndex()
    signals: list[str] = []
    score = 0

    # -- structural ------------------------------------------------------------------
    if set(a.event_ids) & set(b.event_ids):
        score += W_SHARED_EVIDENCE
        signals.append(f"shared_evidence(+{W_SHARED_EVIDENCE})")

    keys_a, keys_b = index.keys(a), index.keys(b)
    same_process, same_process_inferred = match_keys(keys_a, keys_b)
    if same_process:
        score += W_SAME_PROCESS
        signals.append(_signal("same_process", W_SAME_PROCESS, same_process_inferred))

    # Lineage in either direction: a process in one finding is the parent of one in the
    # other. Both directions are asked and the stronger answer wins, so a relationship
    # one direction evidences by identity is not reported as inferred because the other
    # direction could only reach a slot.
    lineage, lineage_inferred = _stronger(
        match_keys(keys_a, index.parent_keys(b)),
        match_keys(keys_b, index.parent_keys(a)),
    )
    if lineage:
        score += W_PROCESS_LINEAGE
        signals.append(_signal("process_lineage", W_PROCESS_LINEAGE, lineage_inferred))

    # Siblings: neither finding is the other's parent, but the same parent instance
    # started both, and that parent reads as one session rather than a launcher.
    sibling, sibling_inferred = False, False
    if _time_gap(a, b) <= config.sibling_window:
        sibling, sibling_inferred = match_keys(
            index.session_parents(a, config), index.session_parents(b, config)
        )
    if sibling:
        score += W_SIBLING_LINEAGE
        signals.append(_signal("sibling_lineage", W_SIBLING_LINEAGE, sibling_inferred))

    # Directed host relationship: one finding's host is the other's auth source/target.
    hosts_a, hosts_b = _hosts_of(a), _hosts_of(b)
    if a.device != b.device and (a.device in hosts_b or b.device in hosts_a):
        score += W_HOST_MOVEMENT
        signals.append(f"host_movement(+{W_HOST_MOVEMENT})")

    # The only signal that can put two *different* specialist domains in one case.
    link = _cross_channel_link(a, b, config, cross)
    if link is not None:
        signal, weight = link
        score += weight
        signals.append(signal)

    structural = any(s.split("(")[0] in STRUCTURAL_SIGNALS for s in signals)

    # -- circumstantial --------------------------------------------------------------
    if a.device == b.device:
        score += W_SAME_DEVICE
        signals.append(f"same_device(+{W_SAME_DEVICE})")

    if a.user == b.user:
        score += W_SAME_USER
        signals.append(f"same_user(+{W_SAME_USER})")

    gap = _time_gap(a, b)
    if gap <= config.tight_window:
        score += W_TEMPORAL_CLOSE
        signals.append(f"temporal_close(+{W_TEMPORAL_CLOSE})")
    elif gap <= config.max_gap:
        score += W_TEMPORAL_NEAR
        signals.append(f"temporal_near(+{W_TEMPORAL_NEAR})")

    return score, signals, structural


def _cross_channel_link(
    a: Finding,
    b: Finding,
    config: CorrelationConfig,
    cross: _CrossChannelIndex,
) -> tuple[str, int] | None:
    """The structural link between two findings resting on different kinds of telemetry.

    Eligibility is symmetric and has nothing to do with which rule fired: the two
    findings' channel families must be **disjoint** and non-empty. Disjoint rather than
    merely different, because a finding both specialists read (``ATH-003``, which
    declares network flow and process execution at once) is one stage described twice,
    and joining it to an endpoint finding on that basis would manufacture a second domain
    out of one observation.

    Two relationships qualify, and order decides only how they read:

    ``auth_then_exec``
        the identity half landed on the host the endpoint half then ran on, inside
        ``auth_exec_window``. This is the link the rule-id allowlist used to express,
        with the rule ids replaced by what they stood for. It is kept distinct because it
        is the one cross-family relationship that does *not* need a shared principal
        name -- a service-launched shell runs as the service account, not as the account
        that authenticated -- so folding it into ``shared_principal`` would drop links
        this correlator already makes.

    ``shared_principal``
        the two findings' evidence names one principal, inside ``cross_domain_window``.
        Asked of every qualifying pair of families, which is what makes an identity
        finding and a control-plane finding about one AWS principal correlatable at all.

    Returns:
        ``(signal_text, weight)``, or ``None``. The signal text carries the principal and
        the direction ("identity then control_plane"), because an analyst arguing with a
        case needs to see *which* name joined it and in what order, not only that
        something did.
    """
    families_a, families_b = cross.families(a), cross.families(b)
    if not families_a or not families_b or (families_a & families_b):
        return None

    # Asked in both directions, exactly as before: whichever finding is the
    # authentication, the execution has to follow it rather than precede it.
    if _auth_then_exec(a, b, cross, config) or _auth_then_exec(b, a, cross, config):
        return f"auth_then_exec(+{W_AUTH_THEN_EXEC})", W_AUTH_THEN_EXEC

    if _time_gap(a, b) > config.cross_domain_window:
        return None
    shared = cross.principals(a) & cross.principals(b)
    if not shared:
        return None

    earlier, later = (
        (a, b) if (a.first_seen, a.rule_id) <= (b.first_seen, b.rule_id) else (b, a)
    )
    return (
        "shared_principal(+{}, {}, {} then {})".format(
            W_SHARED_PRINCIPAL,
            ", ".join(sorted(shared)),
            "/".join(sorted(cross.families(earlier))),
            "/".join(sorted(cross.families(later))),
        ),
        W_SHARED_PRINCIPAL,
    )


def _auth_then_exec(
    auth: Finding,
    exec_: Finding,
    cross: _CrossChannelIndex,
    config: CorrelationConfig,
) -> bool:
    """True if ``auth`` is an authentication that ``exec_`` plausibly followed.

    Unchanged in meaning; changed in what decides it. It used to ask whether the two
    findings' *rule ids* were drawn from ``{ATH-005, ATH-006}`` and ``{ATH-007}``, which
    made "the identity-to-endpoint link this project can form" a statement about three
    named rules rather than about telemetry. It now asks what those ids stood for: one
    finding rests on identity telemetry, the other on endpoint telemetry, and they name
    the same host inside ``auth_exec_window``.
    """
    if FAMILY_IDENTITY not in cross.families(auth):
        return False
    if FAMILY_ENDPOINT not in cross.families(exec_):
        return False
    if auth.device != exec_.device:
        return False
    delta = exec_.first_seen - auth.last_seen
    return timedelta(0) <= delta <= config.auth_exec_window


@dataclass(frozen=True)
class CorrelationStats:
    """What one correlation run did, and how much of it rested on a PID slot.

    Why this is reported at the run and not only on the case
    --------------------------------------------------------
    A case carries the links between its own members, so a link inside a component that
    was never raised -- too small, or entirely set aside by triage -- is invisible from
    the cases alone. "How many of this run's attributions rested on a slot" is a
    property of the run, and answering it from the cases would quietly exclude exactly
    the links nobody looked at.

    Attributes:
        findings: Findings offered to this run.
        cases: Cases raised.
        links: Links made, including those inside components no case was raised for.
        links_by_signal: How many links carried each signal.
        inferred_links_by_signal: How many of those rested on ``(device, pid)`` rather
            than on an instance identity. Only process signals can appear here; a
            ``host_movement`` link has no process join to infer.
    """

    findings: int
    cases: int
    links: int
    links_by_signal: dict[str, int]
    inferred_links_by_signal: dict[str, int]

    @property
    def inferred_links(self) -> int:
        """Links with at least one process signal that rested on a PID slot."""
        return self.inferred_links_by_signal.get("any", 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": self.findings,
            "cases": self.cases,
            "links": self.links,
            "links_by_signal": dict(sorted(self.links_by_signal.items())),
            "inferred_links_by_signal": dict(
                sorted(self.inferred_links_by_signal.items())
            ),
        }


def _signal_name(signal: str) -> str:
    """``"process_lineage(+3, inferred from pid)"`` -> ``"process_lineage"``."""
    return signal.split("(")[0]


def _is_inferred(signal: str) -> bool:
    return INFERRED_FROM_PID in signal


class _UnionFind:
    """Minimal disjoint-set structure for grouping linked findings."""

    def __init__(self, items: Iterable[str]) -> None:
        self._parent = {item: item for item in items}

    def find(self, item: str) -> str:
        while self._parent[item] != item:
            self._parent[item] = self._parent[self._parent[item]]  # path compression
            item = self._parent[item]
        return item

    def union(self, a: str, b: str) -> None:
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            self._parent[root_b] = root_a


def _warrants_singleton(
    members: list[Finding], config: CorrelationConfig
) -> bool:
    """Whether a finding that linked to nothing still deserves investigation.

    Severity is the only admissible basis here. Anything else -- rule identity, host,
    account -- would smuggle a judgement about *which* detections matter into the
    correlator, which is the coupling the specialist gates were just refactored to
    remove.
    """
    if len(members) != 1:
        return False
    return members[0].severity.rank >= config.singleton_min_severity.rank


def correlate(
    findings: Sequence[Finding],
    telemetry: Telemetry,
    config: CorrelationConfig | None = None,
    *,
    set_aside: Collection[str] = (),
) -> list[InvestigationCase]:
    """Group findings into investigation cases using deterministic evidence.

    The cases half of :func:`correlate_with_stats`, kept as the name every caller
    already uses. Callers that need to report how much of a run rested on a PID slot
    call that function instead.
    """
    return correlate_with_stats(
        findings, telemetry, config, set_aside=set_aside
    )[0]


def correlate_with_stats(
    findings: Sequence[Finding],
    telemetry: Telemetry,
    config: CorrelationConfig | None = None,
    *,
    set_aside: Collection[str] = (),
) -> tuple[list[InvestigationCase], CorrelationStats]:
    """Group findings into investigation cases, and report what the run rested on.

    Args:
        findings: Findings to correlate.
        telemetry: Source telemetry, needed for process-lineage look-ups.
        config: Correlation parameters.
        set_aside: Finding ids the triage layer dispositioned ``likely_benign`` with
            cited evidence (``ath.triage.set_aside_ids``). A connected component made
            up entirely of set-aside findings is not raised as a case; a set-aside
            finding that links to an unexplained one still joins that case. Links and
            findings are never affected, only whether a case is raised.

    Returns:
        ``(cases, stats)``. Cases of at least ``config.min_case_size`` findings, ordered
        by start time; findings that link to nothing are omitted -- an isolated finding
        is an alert, not a chain, and inventing single-finding "chains" would overstate
        the output. :class:`CorrelationStats` covers every link the run made, including
        links inside components no case was raised for.
    """
    config = config or CorrelationConfig()
    if not findings:
        return [], CorrelationStats(0, 0, 0, {}, {})

    ordered = sorted(findings, key=lambda f: (f.first_seen, f.rule_id))

    # finding_id is the graph key. Two distinct findings sharing one would be merged
    # silently by the union-find below, producing a case that never existed. Fail loudly
    # instead: a silent grouping error is invisible in the output and impossible to
    # debug from a timeline.
    ids = [f.finding_id for f in ordered]
    if len(ids) != len(set(ids)):
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        raise ValueError(
            f"Duplicate finding_id(s) {duplicates}: correlation keys must be unique, "
            "otherwise unrelated findings are merged without any link being recorded."
        )

    index = _ProcessIndex(telemetry)
    cross = _CrossChannelIndex(telemetry, ordered)
    union = _UnionFind(f.finding_id for f in ordered)
    links: list[FindingLink] = []

    for i, left in enumerate(ordered):
        for right in ordered[i + 1 :]:
            if _time_gap(left, right) > config.max_gap:
                continue  # too far apart to be compared at all

            score, signals, structural = score_pair(
                left, right, index, config, cross
            )
            if score < config.min_score:
                continue
            if config.require_structural and not structural:
                logger.debug(
                    "Refused link %s -> %s: score %d but no structural signal (%s)",
                    left.finding_id, right.finding_id, score, ", ".join(signals),
                )
                continue

            links.append(
                FindingLink(
                    left_id=left.finding_id,
                    right_id=right.finding_id,
                    score=score,
                    signals=tuple(signals),
                    structural=structural,
                    inferred_from_pid=any(_is_inferred(s) for s in signals),
                )
            )
            union.union(left.finding_id, right.finding_id)

    # Connected components become cases.
    groups: dict[str, list[Finding]] = {}
    for finding in ordered:
        groups.setdefault(union.find(finding.finding_id), []).append(finding)

    cases: list[InvestigationCase] = []
    for members in groups.values():
        if set_aside and all(f.finding_id in set_aside for f in members):
            logger.debug(
                "No case for %s: every finding in the group was set aside by triage",
                ", ".join(f.finding_id for f in members),
            )
            continue
        if len(members) < config.min_case_size and not _warrants_singleton(
            members, config
        ):
            continue
        member_ids = {f.finding_id for f in members}
        case_links = tuple(
            link for link in links
            if link.left_id in member_ids and link.right_id in member_ids
        )
        mappings = tuple(m for f in members for m in map_finding(f))
        cases.append(
            InvestigationCase(
                case_id="",  # assigned below, after ordering
                findings=tuple(sorted(members, key=lambda f: (f.first_seen, f.rule_id))),
                links=case_links,
                mappings=mappings,
            )
        )

    cases.sort(key=lambda c: c.start_time)
    for number, case in enumerate(cases, start=1):
        case.case_id = f"CASE-{number:03d}"

    by_signal: dict[str, int] = {}
    inferred_by_signal: dict[str, int] = {}
    for link in links:
        for signal in link.signals:
            name = _signal_name(signal)
            by_signal[name] = by_signal.get(name, 0) + 1
            if _is_inferred(signal):
                inferred_by_signal[name] = inferred_by_signal.get(name, 0) + 1
        if link.inferred_from_pid:
            inferred_by_signal["any"] = inferred_by_signal.get("any", 0) + 1

    stats = CorrelationStats(
        findings=len(findings), cases=len(cases), links=len(links),
        links_by_signal=by_signal, inferred_links_by_signal=inferred_by_signal,
    )
    logger.info(
        "Correlated %d findings into %d case(s) via %d link(s); "
        "%d link(s) rested on a PID slot rather than a process identity",
        len(findings), len(cases), len(links), stats.inferred_links,
    )
    return cases, stats
