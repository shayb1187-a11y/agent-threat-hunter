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

What stops unrelated findings from grouping
-------------------------------------------
* The structural requirement. The two false-positive findings on PC07 link to *each
  other* (same process, PID 5150) but to nothing on PC01: different host, different
  user, no shared process, no authentication path. Score 1, no structural signal.
* ``max_gap``. Findings further apart than this are never compared, which stops a chain
  growing indefinitely through transitive links across a whole day.
* Directionality. ``host_movement`` is asserted only where an authentication actually
  connects two hosts, not merely because two hosts appear in the same case.

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
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import timedelta

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
W_HOST_MOVEMENT = 3
W_AUTH_THEN_EXEC = 3
W_SAME_DEVICE = 2
W_SAME_USER = 2
W_TEMPORAL_CLOSE = 2
W_TEMPORAL_NEAR = 1

STRUCTURAL_SIGNALS = frozenset(
    {"shared_evidence", "same_process", "process_lineage", "host_movement", "auth_then_exec"}
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
    min_case_size: int = 2


class _ProcessIndex:
    """Look-ups from telemetry needed for process-level correlation.

    Built once per correlation run. Maps each telemetry event id to the
    ``(device, pid)`` it ran as, and to the ``(device, parent_pid)`` that started it,
    which is what lets us assert process lineage between two findings.
    """

    def __init__(self, telemetry: Telemetry) -> None:
        self.pid_of: dict[str, tuple[str, int]] = {}
        self.parent_of: dict[str, tuple[str, int]] = {}

        procs = telemetry.processes
        for row in procs.itertuples(index=False):
            if pd.notna(row.process_id):
                self.pid_of[row.event_id] = (row.device, int(row.process_id))
            if pd.notna(row.parent_process_id):
                self.parent_of[row.event_id] = (row.device, int(row.parent_process_id))

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
) -> list[InvestigationCase]:
    """Group findings into investigation cases using deterministic evidence.

    Args:
        findings: Findings to correlate.
        telemetry: Source telemetry, needed for process-lineage look-ups.
        config: Correlation parameters.

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
