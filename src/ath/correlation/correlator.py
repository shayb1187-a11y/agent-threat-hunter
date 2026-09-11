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
same_process            +3   Both cite activity by the same (host, PID).
process_lineage         +3   A process in one finding is the parent of one in the other.
sibling_lineage         +2   Both findings' processes were started by the *same parent
                             instance*, and that parent looks like a single session
                             rather than a launcher. The weakest structural signal --
                             see below -- and deliberately worth less than the others.
host_movement           +3   One finding's host is the other's authentication source or
                             target -- a directed host-to-host relationship.
auth_then_exec          +3   A successful authentication to a host, followed shortly by
                             service-based execution on that same host.
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

That is a real relationship but a weaker one, so it is priced lower, and the price has a
consequence worth stating: ``sibling_lineage(+2)`` plus ``same_device(+2)`` is 4, which
does **not** reach ``min_score``. A shared parent can therefore never link two findings
on its own. It always needs corroboration -- the same account, or proximity in time --
which is exactly the standard the other structural signals are held to.

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
* **PID reuse.** Windows recycles PIDs. Over a long enough window, ``same_process`` can
  join two genuinely different processes. Mitigated by ``max_gap`` but not eliminated;
  a real implementation would key on a process GUID, which our telemetry lacks.
* **Transitive drift.** Cases are connected components, so A-B and B-C put A and C in
  one case even if A and C share nothing. That is usually correct for intrusions --
  which are chains -- but it means one bad link can merge two cases.
* **Busy service accounts.** An account used by automation across many hosts generates
  ``same_user`` plus ``host_movement`` broadly, and would over-group.
* **A shell used for two unrelated things.** ``sibling_lineage`` cannot tell an operator
  who ran two stages of one attack from an administrator who ran two unrelated commands
  in one ``cmd.exe`` inside ten minutes. Both are genuinely "one session", and the
  correlator groups them. That is a deliberate trade: the session is the unit of human
  intent, and separating them would need intent, which the telemetry does not carry.
* **PID reuse, again.** The sibling relation keys on ``(device, parent_pid)`` and
  inherits the same recycling weakness as ``same_process``, bounded by the same
  ``max_gap``.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import pandas as pd

from ath.correlation.chain import FindingLink, InvestigationCase
from ath.hunting.finding import Finding, Severity
from ath.logging_setup import get_logger
from ath.mitre.mapper import map_finding
from ath.telemetry.loader import Telemetry

logger = get_logger(__name__)

# Signal weights. Structural signals are worth strictly more than circumstantial ones.
W_SHARED_EVIDENCE = 3
W_SAME_PROCESS = 3
W_PROCESS_LINEAGE = 3
W_SIBLING_LINEAGE = 2
W_HOST_MOVEMENT = 3
W_AUTH_THEN_EXEC = 3
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
    }
)

# Rules whose findings represent a successful authentication landing on a host.
_AUTH_RULES = frozenset({"ATH-005", "ATH-006"})
# Rules whose findings represent execution driven from elsewhere.
_REMOTE_EXEC_RULES = frozenset({"ATH-007"})


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
    sibling_window: timedelta = timedelta(minutes=10)
    max_session_fan_out: int = 12
    max_session_span: timedelta = timedelta(minutes=10)
    min_case_size: int = 2


class _ProcessIndex:
    """Look-ups from telemetry needed for process-level correlation.

    Built once per correlation run. Maps each telemetry event id to the
    ``(device, pid)`` it ran as, and to the ``(device, parent_pid)`` that started it,
    which is what lets us assert process lineage between two findings.

    It also records, for every parent observed, how many distinct children it started
    and over what span. Those two numbers are what separate a shell an operator is
    typing into from a launcher that starts things all day -- see
    :meth:`session_parents`.
    """

    def __init__(self, telemetry: Telemetry) -> None:
        self.pid_of: dict[str, tuple[str, int]] = {}
        self.parent_of: dict[str, tuple[str, int]] = {}
        self._children: dict[tuple[str, int], set[int]] = {}
        self._spawned_at: dict[tuple[str, int], list[Any]] = {}

        procs = telemetry.processes
        for row in procs.itertuples(index=False):
            if pd.notna(row.process_id):
                self.pid_of[row.event_id] = (row.device, int(row.process_id))
            if pd.notna(row.parent_process_id):
                parent = (row.device, int(row.parent_process_id))
                self.parent_of[row.event_id] = parent
                if pd.notna(row.process_id):
                    self._children.setdefault(parent, set()).add(int(row.process_id))
                self._spawned_at.setdefault(parent, []).append(row.timestamp)

        # Network events inherit the PID of the process that opened the connection,
        # which is what links a PowerShell execution to its own outbound traffic.
        net = telemetry.network
        for row in net.itertuples(index=False):
            if pd.notna(row.process_id):
                self.pid_of[row.event_id] = (row.device, int(row.process_id))

    def pids(self, finding: Finding) -> set[tuple[str, int]]:
        return {self.pid_of[e] for e in finding.event_ids if e in self.pid_of}

    def parents(self, finding: Finding) -> set[tuple[str, int]]:
        return {self.parent_of[e] for e in finding.event_ids if e in self.parent_of}

    def fan_out(self, parent: tuple[str, int]) -> int:
        """How many distinct child processes this parent was observed to start."""
        return len(self._children.get(parent, ()))

    def spawn_span(self, parent: tuple[str, int]) -> timedelta:
        """Wall-clock time between this parent's first and last observed child."""
        times = self._spawned_at.get(parent)
        if not times:
            return timedelta(0)
        return max(times) - min(times)

    def session_parents(
        self, finding: Finding, config: CorrelationConfig
    ) -> set[tuple[str, int]]:
        """Those of the finding's parents that look like a single session.

        A parent qualifies when it started few enough children, closely enough
        together, to read as one burst of activity rather than a launcher that starts
        things all day. Both bounds come off the telemetry, so no process is named here
        and there is no allow-list to keep up to date -- a renamed shell is measured
        exactly like any other.
        """
        return {
            parent
            for parent in self.parents(finding)
            if self.fan_out(parent) <= config.max_session_fan_out
            and self.spawn_span(parent) <= config.max_session_span
        }


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


def score_pair(
    a: Finding, b: Finding, index: _ProcessIndex, config: CorrelationConfig
) -> tuple[int, list[str], bool]:
    """Score the relationship between two findings.

    Returns:
        ``(score, signal_names, has_structural_signal)``. Signal names carry their
        weight so the reasoning is legible in output, e.g. ``"same_process(+3)"``.
    """
    signals: list[str] = []
    score = 0

    # -- structural ------------------------------------------------------------------
    if set(a.event_ids) & set(b.event_ids):
        score += W_SHARED_EVIDENCE
        signals.append(f"shared_evidence(+{W_SHARED_EVIDENCE})")

    pids_a, pids_b = index.pids(a), index.pids(b)
    if pids_a & pids_b:
        score += W_SAME_PROCESS
        signals.append(f"same_process(+{W_SAME_PROCESS})")

    if (pids_a & index.parents(b)) or (pids_b & index.parents(a)):
        score += W_PROCESS_LINEAGE
        signals.append(f"process_lineage(+{W_PROCESS_LINEAGE})")

    # Siblings: neither finding is the other's parent, but the same parent instance
    # started both, and that parent reads as one session rather than a launcher.
    if _time_gap(a, b) <= config.sibling_window and (
        index.session_parents(a, config) & index.session_parents(b, config)
    ):
        score += W_SIBLING_LINEAGE
        signals.append(f"sibling_lineage(+{W_SIBLING_LINEAGE})")

    # Directed host relationship: one finding's host is the other's auth source/target.
    hosts_a, hosts_b = _hosts_of(a), _hosts_of(b)
    if a.device != b.device and (a.device in hosts_b or b.device in hosts_a):
        score += W_HOST_MOVEMENT
        signals.append(f"host_movement(+{W_HOST_MOVEMENT})")

    # Authentication landing on a host, then execution on that host shortly after.
    if _auth_then_exec(a, b, config) or _auth_then_exec(b, a, config):
        score += W_AUTH_THEN_EXEC
        signals.append(f"auth_then_exec(+{W_AUTH_THEN_EXEC})")

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


def _auth_then_exec(auth: Finding, exec_: Finding, config: CorrelationConfig) -> bool:
    """True if ``auth`` is a successful logon that ``exec_`` plausibly followed."""
    if auth.rule_id not in _AUTH_RULES or exec_.rule_id not in _REMOTE_EXEC_RULES:
        return False
    if auth.device != exec_.device:
        return False
    delta = exec_.first_seen - auth.last_seen
    return timedelta(0) <= delta <= config.auth_exec_window


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
        Cases of at least ``config.min_case_size`` findings, ordered by start time.
        Findings that link to nothing are omitted -- an isolated finding is an alert,
        not a chain, and inventing single-finding "chains" would overstate the output.
    """
    config = config or CorrelationConfig()
    if not findings:
        return []

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
    union = _UnionFind(f.finding_id for f in ordered)
    links: list[FindingLink] = []

    for i, left in enumerate(ordered):
        for right in ordered[i + 1 :]:
            if _time_gap(left, right) > config.max_gap:
                continue  # too far apart to be compared at all

            score, signals, structural = score_pair(left, right, index, config)
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

    logger.info(
        "Correlated %d findings into %d case(s) via %d link(s)",
        len(findings), len(cases), len(links),
    )
    return cases
