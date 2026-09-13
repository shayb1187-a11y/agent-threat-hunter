"""Specialist investigation agents.

Each specialist owns one domain and answers one question:

============  ==========================================================
Endpoint      What ran on the host, and what started it?
Identity      Whose credentials were used, and from where?
Network       Who did the host talk to, and does the pattern look automated?
ATT&CK        What adversary behaviours does this match, and what is missing?
============  ==========================================================

Why specialists rather than one large agent
-------------------------------------------
Not because more agents is better -- it usually is not. The reason is *conditional
execution*. A case containing only authentication findings should never pay for endpoint
process-tree analysis, and an investigation that runs every module every time is a
report generator, not an investigation. Each specialist therefore exposes
:meth:`should_run`, which inspects the state and returns a decision **with a reason**.
The orchestrator uses those decisions to choose a path, and the reasons become the
explanation of why the investigation went the way it did.

How a specialist decides it is relevant
----------------------------------------
By declaring the telemetry it needs and responds to -- not by listing rule ids. Every
finding already carries ``fields_used``, so a case can be asked what *kinds* of
telemetry its evidence rests on, and a specialist matches against that. This is what
lets the roster apply to a rule catalogue nobody wrote it against, and what keeps it
from going stale when new rules are added. See :class:`Specialist` for the two concrete
failures this replaced.

Why these agents are deterministic
----------------------------------
Every claim below is produced by reading tool output, not by a model. The specialists
gather and structure evidence; the language model's role (in
:mod:`ath.agent.orchestrator`) is to plan and synthesise on top of what they found. This
keeps the evidence layer reproducible: run the same case twice, get identical claims.

A model *can* add INFERENCE and HYPOTHESIS claims, and its output goes through the same
verifier. It can never author a FACT -- :class:`~ath.agent.claims.Claim` refuses.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Any

import pandas as pd

from ath.agent.claims import Claim, ClaimType
from ath.agent.state import AgentResult, InvestigationState
from ath.agent.tools import ToolBox
from ath.environment import TelemetryChannel, channels_for_fields
from ath.instance_identity import INFERRED_FROM_PID
from ath.logging_setup import get_logger
from ath.mitre.mapper import tactics_covered

logger = get_logger(__name__)

# Tactics that, if present, indicate the intrusion progressed past a single host.
_PROGRESSION_TACTICS = ("Credential Access", "Lateral Movement", "Collection")


def channel_sources(state: InvestigationState) -> dict[TelemetryChannel, set[str]]:
    """Map each telemetry channel the case rests on to the rules that contributed it.

    Derived from the ``fields_used`` each member finding carries -- a declaration every
    rule already makes, and which travels with the finding by construction. That is
    what makes this work for *any* rule catalogue: a hypothetical ``AWS-001`` that
    declares its fields is understood here without anyone adding it to a list.

    The attribution matters for the recorded reason. Naming every rule in the case
    would be technically true and useless -- on a ten-finding case it lists all ten
    regardless of which ones actually evidence the channel in question. A skipped or
    selected agent is only as explainable as the specificity of its stated reason.
    """
    sources: dict[TelemetryChannel, set[str]] = defaultdict(set)
    for finding in state.case.findings:
        # A finding carries its own explicit channels when its rule declared them
        # (needed where fields_used column names alone are ambiguous -- see
        # Detector.channels); otherwise they are inferred from fields_used exactly as
        # before. Reading finding.channels rather than looking the rule up by id keeps
        # this working for a finding built by hand (as this project's own tests do) and
        # for a rule id no registry has ever heard of, which is the whole point of this
        # mechanism.
        channels = finding.channels or channels_for_fields(finding.fields_used)
        for channel in channels:
            sources[channel].add(finding.rule_id)
    return dict(sources)


def case_channels(state: InvestigationState) -> set[TelemetryChannel]:
    """Which telemetry channels this case's evidence actually rests on."""
    return set(channel_sources(state))


class Specialist(ABC):
    """Base class for a domain investigation agent.

    Eligibility is declared, not hardcoded
    ---------------------------------------
    A specialist used to decide whether it was relevant by matching literal rule ids::

        process_rules = {"ATH-001", "ATH-002", "ATH-004", "ATH-007", "ATH-008"}
        if not set(state.case.rule_ids) & process_rules:
            return False, "case contains no process-based findings"

    That has two failure modes, and this codebase hit both.

    *It goes stale silently.* ``ATH-009`` and ``ATH-010`` were added in Milestone 6.
    Both are process rules. Neither was added to that set, so endpoint lineage analysis
    quietly stopped applying to them -- with no error, no test failure, and a
    plausible-looking "case contains no process-based findings" as the recorded reason.

    *It cannot generalise.* A case built from a different rule catalogue -- cloud, or
    Kubernetes -- matches nothing, so *every* specialist declines and the investigation
    completes as ``EXHAUSTED`` having done nothing. The specialists' actual logic is not
    Windows-specific; only the allowlist was.

    So a specialist now declares what it *needs* and what it *responds to*, in the
    vendor-neutral vocabulary of :class:`~ath.environment.channels.TelemetryChannel`:

    ``reads_channels``
        Telemetry this specialist requires to do its job. If the environment says that
        telemetry is unavailable, the specialist declines *for that reason* rather than
        running and finding nothing -- the same distinction the visibility model draws
        between "nothing happened" and "we cannot see".

    ``triggered_by_channels`` / ``triggered_by_tactics``
        Evidence shapes that mean there is work here. Matched against what the case's
        findings actually rest on, never against their rule ids.
    """

    name: str = ""
    domain: str = ""

    reads_channels: frozenset[TelemetryChannel] = frozenset()
    """Telemetry required to do this specialist's job at all -- ALL of these must be
    observable, or the specialist declines. Use ``reads_channels_any`` instead when any
    one of several channels is sufficient (e.g. a specialist that works from either
    cloud or Kubernetes control-plane evidence, needing neither specifically)."""

    reads_channels_any: frozenset[TelemetryChannel] = frozenset()
    """Alternative telemetry requirement: at least ONE of these must be observable.

    Empty means no such requirement. Kept separate from ``reads_channels`` rather than
    overloading it, because AND and OR read very differently in the declined-reason
    text and conflating them would misreport which channels would actually help."""

    triggered_by_channels: frozenset[TelemetryChannel] = frozenset()
    """Case evidence resting on any of these means this specialist has work."""

    triggered_by_tactics: frozenset[str] = frozenset()
    """...or the case carrying any of these ATT&CK tactics."""

    accepts_follow_up: bool = False
    """Whether another specialist may request this one even absent a direct trigger."""

    def __init__(self, tools: ToolBox) -> None:
        self.tools = tools

    # -- eligibility ------------------------------------------------------------------

    def should_run(self, state: InvestigationState) -> tuple[bool, str]:
        """Decide whether this specialist has anything useful to do.

        Returns:
            ``(should_run, reason)``. The reason is recorded either way, so a skipped
            agent is as explainable as one that ran.
        """
        if state.has_run(self.name):
            return False, f"{self.name} analysis already completed"

        blocked = self.blocked_by_telemetry(state)
        if blocked is not None:
            return False, blocked

        return self.has_work(state)

    def blocked_by_telemetry(self, state: InvestigationState) -> str | None:
        """Return a reason this specialist cannot work here, or ``None``.

        Only consulted when an :class:`~ath.environment.model.EnvironmentModel` is
        attached to the state. Without one the specialist proceeds -- absence of a
        visibility assessment is not evidence that telemetry is missing, and refusing
        to run on that basis would be the very inference this project forbids.
        """
        environment = state.environment
        if environment is None or not (self.reads_channels or self.reads_channels_any):
            return None
        observable = environment.observable_channels

        if self.reads_channels:
            unavailable = sorted(
                (c for c in self.reads_channels if c not in observable),
                key=lambda c: c.value,
            )
            if unavailable:
                return (
                    "required telemetry is unavailable in this environment: "
                    + ", ".join(c.value for c in unavailable)
                    + " -- this specialist would find nothing regardless of what occurred"
                )

        if self.reads_channels_any and not (self.reads_channels_any & observable):
            return (
                "none of this specialist's alternative telemetry sources are "
                "available in this environment: "
                + ", ".join(sorted(c.value for c in self.reads_channels_any))
                + " -- this specialist would find nothing regardless of what occurred"
            )

        return None

    def has_work(self, state: InvestigationState) -> tuple[bool, str]:
        """Whether the case carries evidence this specialist is the right one for."""
        sources = channel_sources(state)
        present = set(sources) & self.triggered_by_channels
        if present:
            # Name only the rules that actually evidence the matched channels.
            contributing = sorted({r for c in present for r in sources[c]})
            return True, (
                "case evidence rests on "
                + ", ".join(sorted(c.value for c in present))
                + f" telemetry (from {', '.join(contributing)})"
            )

        tactics = set(state.case.tactics) & self.triggered_by_tactics
        if tactics:
            return True, (
                f"case covers the {', '.join(sorted(tactics))} tactic(s), which this "
                "specialist is responsible for following up"
            )

        if self.accepts_follow_up and self.name in state.follow_ups:
            return True, "a previous specialist requested this analysis"

        return False, (
            f"case evidence rests on no {self.domain} telemetry and no specialist "
            "requested it"
        )

    @abstractmethod
    def investigate(self, state: InvestigationState) -> AgentResult:
        """Run the investigation and return structured claims."""

    def _result(
        self, state: InvestigationState, reason: str, claims: list[Claim],
        follow_up: tuple[str, ...] = (), notes: tuple[str, ...] = (),
    ) -> AgentResult:
        """Assemble a result, attaching the tool calls this agent made."""
        return AgentResult(
            agent=self.name,
            ran_because=reason,
            claims=tuple(claims),
            tool_calls=tuple(self.tools.calls_by(self.name)),
            follow_up=follow_up,
            notes=notes,
        )


# ======================================================================================
# Endpoint
# ======================================================================================


class EndpointAgent(Specialist):
    """Reconstructs what executed on a host and what started it.

    The question that decides most endpoint investigations is *lineage*. A PowerShell
    process is unremarkable; a PowerShell process whose parent is WINWORD.EXE is an
    incident. This agent walks the ancestry of every process instance implicated in the
    case.

    *Instance*, not PID. A finding that carries a ``process_guid`` names one run and is
    walked by it. A finding that carries only a ``process_id`` names a slot, and this
    agent will only walk it when exactly one process held that slot -- otherwise it
    records an INFERENCE that the attribution cannot be made and asserts no parentage
    at all, because a FACT about "the" process behind an ambiguous pid is a FACT about
    a process picked at random. Where a hop could only be made on the pid, the claim
    text says ``inferred from pid``: the finding is still reported, and the reader can
    see what it rests on.
    """

    name = "endpoint"
    domain = "process execution and lineage"

    # Needs to see processes and who started them. Command lines are read opportunistically
    # (they enrich the claims) but lineage is what this specialist exists for.
    reads_channels = frozenset({
        TelemetryChannel.PROCESS_EXECUTION, TelemetryChannel.PROCESS_LINEAGE,
    })
    triggered_by_channels = frozenset({
        TelemetryChannel.PROCESS_EXECUTION,
        TelemetryChannel.PROCESS_COMMAND_LINE,
        TelemetryChannel.PROCESS_LINEAGE,
    })

    def investigate(self, state: InvestigationState) -> AgentResult:
        _, reason = self.should_run(state)
        claims: list[Claim] = []
        notes: list[str] = []
        follow_up: list[str] = []
        # What has already been walked, keyed by process *instance* where the finding
        # named one and by (device, pid) where it did not. Keyed on the pid alone, two
        # runs of one slot would be walked once and the second one's lineage silently
        # dropped -- the same conflation this milestone removed from the correlator.
        seen: set[tuple[str, Any]] = set()
        office_ancestor_claimed: set[str] = set()  # devices already carrying this claim

        for finding in state.case.findings:
            device = finding.device
            # The identity first, because it names one run; the pid only as a fallback,
            # and one this agent must then be able to say it fell back to.
            identity = str(finding.metadata.get("process_guid") or "")
            pid = finding.metadata.get("process_id")

            # Recover both from the finding's own evidence when metadata lacks them.
            if pid is None and not identity:
                events = self.tools.get_events(list(finding.event_ids), agent=self.name)
                rows = [e for e in events["events"] if e.get("process_id")]
                if rows:
                    pid = rows[0].get("process_id")
                    identity = str(rows[0].get("process_guid") or "")
            if pid is None and not identity:
                continue
            pid = int(pid) if pid is not None else None

            # Several findings on one case commonly point at the same execution
            # (ATH-001 and ATH-002 both cite the same WINWORD->powershell event), and
            # they do not all name it the same way: one may carry the identity and
            # another only the pid. So both names of an instance are remembered, and
            # either one matching is enough to know this tree has been walked.
            keys = {("identity", identity)} if identity else set()
            if pid is not None:
                keys.add(("pid", device, pid))
            if keys & seen:
                continue
            seen |= keys

            tree = self.tools.process_tree(
                device, pid, agent=self.name, process_guid=identity,
            )
            if tree["process_guid"]:
                seen.add(("identity", tree["process_guid"]))
            if tree["ancestry"]:
                seen.add(("pid", device, tree["ancestry"][0]["process_id"]))

            if tree["resolution"] == "ambiguous_pid":
                # An INFERENCE, and never a FACT about one candidate. The pid names a
                # slot that several processes passed through; picking one and asserting
                # its parentage is the failure this branch exists to refuse. What can
                # honestly be said is that the attribution cannot be made.
                candidates = tree["candidates"]
                claims.append(Claim(
                    claim_type=ClaimType.INFERENCE,
                    statement=(
                        f"PID {pid} on {device} was held by {tree['ambiguous_pid']} "
                        "different process instances "
                        f"({', '.join(sorted({c['process_name'] for c in candidates}))}), "
                        "so this finding's activity cannot be attributed to one of them "
                        "from the pid alone and no lineage is asserted for it."
                    ),
                    evidence_ids=tuple(c["event_id"] for c in candidates),
                    source="analysis", agent=self.name, confidence=0.5,
                ))
                continue

            ancestry = tree["ancestry"]
            if not ancestry:
                continue

            leaf = ancestry[0]
            parent_label = (
                f" (PID {leaf['parent_process_id']}, identity {INFERRED_FROM_PID})"
                if leaf["parent_resolution"] == INFERRED_FROM_PID
                else ""
            )
            claims.append(Claim(
                claim_type=ClaimType.FACT,
                statement=(
                    f"On {device}, {leaf['process_name']} (PID {leaf['process_id']}) was "
                    f"started by {leaf['parent_process_name']}{parent_label} under "
                    f"account {leaf['user']}."
                ),
                evidence_ids=(leaf["event_id"],),
                source="tool", agent=self.name,
            ))

            if len(ancestry) > 1:
                # ancestry is leaf-first; render it oldest-first for readability.
                chain = " -> ".join(
                    [ancestry[-1]["parent_process_name"]]
                    + [a["process_name"] for a in reversed(ancestry)]
                )
                inferred_hops = [
                    a for a in ancestry if a["resolved_by"] == INFERRED_FROM_PID
                ]
                # A chain is only as strong as its weakest hop. One hop that could only
                # be made on a pid makes the whole chain a chain of slots, and a reader
                # who is not told that will read it as observed lineage.
                chain_note = (
                    f" {len(inferred_hops)} of {len(ancestry)} step(s) in this chain "
                    f"are {INFERRED_FROM_PID} rather than from a process identity."
                    if inferred_hops else ""
                )
                claims.append(Claim(
                    claim_type=ClaimType.FACT,
                    statement=f"Execution chain on {device}: {chain}.{chain_note}",
                    evidence_ids=tuple(a["event_id"] for a in ancestry),
                    source="tool", agent=self.name,
                ))

            # An Office ancestor is the single most informative lineage result. Several
            # process trees on the same host (e.g. the PowerShell process and the
            # rundll32 it later spawns) can both trace back to the same Office ancestor,
            # so this is emitted once per device rather than once per tree walked.
            office = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
            ancestors = {a["parent_process_name"].lower() for a in ancestry}
            if (ancestors & office) and device not in office_ancestor_claimed:
                office_ancestor_claimed.add(device)
                claims.append(Claim(
                    claim_type=ClaimType.INFERENCE,
                    statement=(
                        f"Execution on {device} originated from a document opened in an "
                        "Office application rather than from user-initiated command "
                        "line activity, which is consistent with macro-based execution."
                    ),
                    evidence_ids=tuple(a["event_id"] for a in ancestry),
                    source="analysis", agent=self.name, confidence=0.8,
                ))
                follow_up.append("network")

            children = tree["children"]
            if children:
                inferred_children = [
                    c for c in children if c["resolved_by"] == INFERRED_FROM_PID
                ]
                child_note = (
                    f" {len(inferred_children)} of these are attributed to it "
                    f"{INFERRED_FROM_PID} rather than from a parent process identity."
                    if inferred_children else ""
                )
                claims.append(Claim(
                    claim_type=ClaimType.FACT,
                    statement=(
                        f"{leaf['process_name']} (PID {leaf['process_id']}) on {device} "
                        f"spawned {len(children)} child process(es): "
                        + ", ".join(sorted({c['process_name'] for c in children}))
                        + f".{child_note}"
                    ),
                    evidence_ids=tuple(c["event_id"] for c in children),
                    source="tool", agent=self.name,
                ))

        if not claims:
            notes.append("No process lineage could be reconstructed for this case.")

        # If credentials were touched, identity is the natural next domain.
        if "ATH-004" in state.case.rule_ids:
            follow_up.append("identity")

        return self._result(
            state, reason, claims, tuple(dict.fromkeys(follow_up)), tuple(notes)
        )


# ======================================================================================
# Identity
# ======================================================================================


class IdentityAgent(Specialist):
    """Examines account behaviour: where credentials are used and whether that changed."""

    name = "identity"
    domain = "authentication and account behaviour"

    reads_channels = frozenset({TelemetryChannel.AUTHENTICATION})
    triggered_by_channels = frozenset({
        TelemetryChannel.AUTHENTICATION, TelemetryChannel.AUTH_SOURCE_ATTRIBUTION,
    })
    # The old gate named ATH-004 specifically, to express "credentials were touched, so
    # check where those accounts were used next". That intent is a *tactic*, not a rule
    # id -- any rule mapping to Credential Access should trigger the same follow-up,
    # including ones not yet written.
    triggered_by_tactics = frozenset({"Credential Access"})

    def investigate(self, state: InvestigationState) -> AgentResult:
        _, reason = self.should_run(state)
        claims: list[Claim] = []
        notes: list[str] = []
        follow_up: list[str] = []

        for user in state.case.users:
            history = self.tools.user_auth_history(user, agent=self.name)
            summary = history.get("summary") or {}
            if not summary:
                notes.append(f"No authentication telemetry exists for account '{user}'.")
                continue

            claims.append(Claim(
                claim_type=ClaimType.FACT,
                statement=(
                    f"Account '{user}' has {summary['total']} authentication events "
                    f"({summary['failures']} failed, {summary['successes']} successful) "
                    f"across hosts {', '.join(summary['target_devices'])}."
                ),
                evidence_ids=tuple(e["event_id"] for e in history["events"]),
                source="tool", agent=self.name,
            ))

            sources = summary["source_devices"]
            if len(sources) > 1:
                claims.append(Claim(
                    claim_type=ClaimType.FACT,
                    statement=(
                        f"Account '{user}' authenticated from more than one source host: "
                        f"{', '.join(sources)}."
                    ),
                    evidence_ids=tuple(e["event_id"] for e in history["events"]),
                    source="tool", agent=self.name,
                ))
            elif not sources:
                # No resolved source hostname. That is the normal case for cloud
                # control-plane telemetry, which records only an address -- and
                # reporting nothing would drop the sole piece of origin evidence
                # available. Where an account authenticates, from, is the identity
                # question; the schema's preference for hostnames must not decide
                # whether it gets answered.
                addresses = sorted({
                    e["source_ip"] for e in history["events"] if e.get("source_ip")
                })
                if addresses:
                    claims.append(Claim(
                        claim_type=ClaimType.FACT,
                        statement=(
                            f"Account '{user}' authenticated from "
                            f"{len(addresses)} source address(es) with no resolved "
                            f"hostname: {', '.join(addresses)}."
                        ),
                        evidence_ids=tuple(e["event_id"] for e in history["events"]),
                        source="tool", agent=self.name,
                    ))

            failures = summary["failures"]
            if failures >= 10 and summary["successes"] > 0:
                failed_ids = tuple(
                    e["event_id"] for e in history["events"] if e["action"] == "failure"
                )
                claims.append(Claim(
                    claim_type=ClaimType.INFERENCE,
                    statement=(
                        f"The {failures} failed authentications for '{user}' followed by "
                        "success are consistent with the account's password having been "
                        "guessed rather than with ordinary user error."
                    ),
                    evidence_ids=failed_ids,
                    source="analysis", agent=self.name, confidence=0.85,
                ))
                follow_up.append("network")

        # Cross-host credential use is the lateral-movement signal.
        for finding in state.case.findings:
            if finding.rule_id != "ATH-006":
                continue
            source = finding.metadata.get("source_device")
            owners = finding.metadata.get("source_host_owners", [])
            targets = finding.metadata.get("target_devices", [])
            claims.append(Claim(
                claim_type=ClaimType.FACT,
                statement=(
                    f"Account '{finding.user}' authenticated to "
                    f"{', '.join(str(t) for t in targets)} from {source}, a host whose "
                    f"observed interactive user(s) are {', '.join(owners)}."
                ),
                evidence_ids=finding.event_ids,
                source="detector", agent=self.name,
            ))
            claims.append(Claim(
                claim_type=ClaimType.INFERENCE,
                statement=(
                    f"Credential use for '{finding.user}' originating from {source} is "
                    "consistent with credentials obtained on that host being reused to "
                    "reach another system."
                ),
                evidence_ids=finding.event_ids,
                source="analysis", agent=self.name, confidence=0.75,
            ))
            claims.append(Claim(
                claim_type=ClaimType.HYPOTHESIS,
                statement=(
                    f"The credentials for '{finding.user}' may have been obtained from "
                    f"memory on {source}. This is unverified: no telemetry links the "
                    "credential-access activity to this specific account."
                ),
                source="analysis", agent=self.name, confidence=0.4,
            ))

        return self._result(
            state, reason, claims, tuple(dict.fromkeys(follow_up)), tuple(notes)
        )


# ======================================================================================
# Network
# ======================================================================================


class NetworkAgent(Specialist):
    """Examines outbound communication and tests destinations for automated timing."""

    name = "network"
    domain = "outbound network communication"

    reads_channels = frozenset({TelemetryChannel.NETWORK_FLOW})
    triggered_by_channels = frozenset({TelemetryChannel.NETWORK_FLOW})
    # Endpoint analysis that finds Office-spawned execution asks for this specialist
    # even when the case carries no network finding of its own.
    accepts_follow_up = True

    def investigate(self, state: InvestigationState) -> AgentResult:
        _, reason = self.should_run(state)
        claims: list[Claim] = []
        notes: list[str] = []

        destinations: dict[str, list[str]] = {}
        for finding in state.case.findings:
            remote_ip = finding.metadata.get("remote_ip")
            if remote_ip:
                destinations.setdefault(str(remote_ip), []).append(finding.device)

        if not destinations:
            notes.append("No external destinations were recorded in this case's findings.")
            return self._result(state, reason, claims, notes=tuple(notes))

        for remote_ip, devices in destinations.items():
            unique_devices = sorted(set(devices))

            if len(unique_devices) > 1:
                # Shared infrastructure across hosts is a strong pivot: it converts
                # "two separate incidents" into "one operation".
                ids: list[str] = []
                for device in unique_devices:
                    activity = self.tools.host_network_activity(
                        device, remote_ip=remote_ip, agent=self.name
                    )
                    ids.extend(activity["event_ids"])

                claims.append(Claim(
                    claim_type=ClaimType.FACT,
                    statement=(
                        f"The external address {remote_ip} was contacted from more than "
                        f"one host: {', '.join(unique_devices)}."
                    ),
                    evidence_ids=tuple(sorted(set(ids))),
                    source="tool", agent=self.name,
                ))
                claims.append(Claim(
                    claim_type=ClaimType.INFERENCE,
                    statement=(
                        f"A single external address contacted from {len(unique_devices)} "
                        "separate hosts is consistent with shared adversary "
                        "infrastructure rather than with independent user activity."
                    ),
                    evidence_ids=tuple(sorted(set(ids))),
                    source="analysis", agent=self.name, confidence=0.8,
                ))

            for device in unique_devices:
                beacon = self.tools.analyse_beacon(device, remote_ip, agent=self.name)
                if beacon.get("regular"):
                    # The dispersion statistic is MAD/median, so it must be reported
                    # against the MEDIAN interval. Quoting it against the mean produces
                    # an incoherent sentence: a robust cv of 0.000 asserts that every
                    # interval is identical, which is false of the mean whenever a
                    # single outlier is present -- exactly the payload-fetch-then-
                    # heartbeat shape this statistic was chosen to survive.
                    claims.append(Claim(
                        claim_type=ClaimType.FACT,
                        statement=(
                            f"Connections from {device} to {remote_ip} occurred at a "
                            f"median interval of "
                            f"{beacon['median_interval_seconds']:.0f}s with a robust "
                            f"coefficient of variation (MAD/median) of "
                            f"{beacon['robust_cv']:.3f} across "
                            f"{beacon['samples']} connections."
                        ),
                        evidence_ids=tuple(beacon["event_ids"]),
                        source="tool", agent=self.name,
                    ))
                    claims.append(Claim(
                        claim_type=ClaimType.INFERENCE,
                        statement=(
                            f"The regularity of these intervals indicates automated "
                            f"rather than human-driven communication, which is "
                            f"consistent with command-and-control beaconing."
                        ),
                        evidence_ids=tuple(beacon["event_ids"]),
                        source="analysis", agent=self.name, confidence=0.85,
                    ))
                elif beacon.get("samples", 0) >= 3:
                    notes.append(
                        f"Connections from {device} to {remote_ip} are irregular "
                        f"(robust cv {beacon['robust_cv']:.2f} about a median interval "
                        f"of {beacon['median_interval_seconds']:.0f}s); note that "
                        "implants commonly add jitter specifically to defeat this test, "
                        "so this does not rule out beaconing."
                    )
                else:
                    notes.append(
                        f"Too few connections from {device} to {remote_ip} "
                        f"({beacon.get('samples', 0)}) to assess timing."
                    )

        return self._result(state, reason, claims, ("attack",), tuple(notes))


# ======================================================================================
# Control plane (cloud / Kubernetes)
# ======================================================================================


class ControlPlaneAgent(Specialist):
    """Reconstructs a control-plane privilege-escalation chain: who was granted power,
    and what they did with it.

    One specialist for both AWS and Kubernetes, deliberately -- an IAM policy grant and
    an RBAC role binding are the same shape at the level ``ath.schema.EVENT_CONTROL``
    models (an actor grants a role/permission to a target identity, who may then act on
    it), and the vendor-neutral evidence this agent reads (``actor``, ``target_actor``,
    ``role_ref``, ``verb``, ``resource_type``) does not care which cloud produced it.

    Not part of the fixed roster
    -----------------------------
    Unlike Endpoint/Identity/Network/ATT&CK, this specialist is never included in
    :func:`default_specialists`. It exists to be assembled *conditionally*, by
    ``ath.capabilities.crew.assemble_crew``, for environments whose telemetry actually
    carries cloud or Kubernetes control-plane evidence -- see that module for why a
    fixed roster is exactly the thing this specialist should not join.
    """

    name = "control_plane"
    domain = "cloud/container control-plane resource actions"

    # Either channel is sufficient -- an AWS-only or Kubernetes-only environment
    # should still stand this specialist up, not just a hybrid one.
    reads_channels_any = frozenset({
        TelemetryChannel.CLOUD_MANAGEMENT_ACTIVITY, TelemetryChannel.CONTAINER_AUDIT,
    })
    triggered_by_channels = frozenset({
        TelemetryChannel.CLOUD_MANAGEMENT_ACTIVITY, TelemetryChannel.CONTAINER_AUDIT,
    })

    def investigate(self, state: InvestigationState) -> AgentResult:
        _, reason = self.should_run(state)
        claims: list[Claim] = []
        notes: list[str] = []
        reconstructed = False

        for finding in state.case.findings:
            if not (set(finding.channels) & self.triggered_by_channels):
                continue  # a finding from another domain; nothing to add here

            events = self.tools.get_events(list(finding.event_ids), agent=self.name)
            rows = sorted(events["events"], key=lambda e: e["timestamp"])
            if not rows:
                continue

            # A row with a target_actor is a grant; a row without one, whose actor
            # matches the finding's beneficiary, is that beneficiary using it. This
            # mirrors the rules' own actor/target_actor split rather than re-deriving
            # it differently here.
            beneficiary = finding.metadata.get("target_actor") or finding.user
            grants = [r for r in rows if r.get("target_actor")]
            uses = [r for r in rows if not r.get("target_actor") and r.get("actor") == beneficiary]

            for grant in grants:
                reconstructed = True
                role = grant.get("role_ref") or grant.get("resource_type", "")
                claims.append(Claim(
                    claim_type=ClaimType.FACT,
                    statement=(
                        f"'{grant.get('actor', '?')}' granted '{role}' to "
                        f"'{grant.get('target_actor', '?')}' via {grant.get('resource_type', '?')} "
                        f"'{grant.get('resource_name', '?')}' on {grant.get('device', '?')}."
                    ),
                    evidence_ids=(grant["event_id"],),
                    source="tool", agent=self.name,
                ))

            for use in uses:
                reconstructed = True
                where = (
                    f" in namespace '{use['resource_namespace']}'"
                    if use.get("resource_namespace") else ""
                )
                claims.append(Claim(
                    claim_type=ClaimType.FACT,
                    statement=(
                        f"'{use.get('actor', '?')}' performed {use.get('verb', '?')} on "
                        f"{use.get('resource_type', '?')} '{use.get('resource_name', '?')}'"
                        f"{where}."
                    ),
                    evidence_ids=(use["event_id"],),
                    source="tool", agent=self.name,
                ))

            if grants and uses:
                delta = int((
                    pd.Timestamp(uses[0]["timestamp"]) - pd.Timestamp(grants[0]["timestamp"])
                ).total_seconds())
                claims.append(Claim(
                    claim_type=ClaimType.INFERENCE,
                    statement=(
                        f"'{beneficiary}' acted on the granted privilege {delta}s after "
                        "receiving it, which is consistent with the grant being used "
                        "for exploration or post-exploitation access rather than left "
                        "dormant."
                    ),
                    evidence_ids=tuple(r["event_id"] for r in grants + uses),
                    source="analysis", agent=self.name, confidence=0.75,
                ))
            elif grants and not uses:
                notes.append(
                    f"'{beneficiary}' was granted a privilege but no subsequent use of "
                    "it was observed in this case's evidence window."
                )

        if not reconstructed:
            notes.append(
                "No control-plane privilege chain could be reconstructed for this case."
            )

        return self._result(state, reason, claims, notes=tuple(notes))


# ======================================================================================
# ATT&CK
# ======================================================================================


class AttackMappingAgent(Specialist):
    """Summarises technique coverage and, importantly, names what is missing."""

    name = "attack"
    domain = "MITRE ATT&CK interpretation and coverage gaps"

    # Reads no telemetry directly -- it interprets mappings the deterministic layer
    # already produced -- so it declares no channel requirement and overrides the
    # default trigger logic with its own ordering constraint.
    def has_work(self, state: InvestigationState) -> tuple[bool, str]:
        if not state.case.mappings:
            return False, "case has no ATT&CK mappings to interpret"
        if state.step == 0:
            return False, (
                "deferred: ATT&CK interpretation is most useful once the domain agents "
                "have gathered evidence"
            )
        return True, "case has ATT&CK mappings and domain evidence has been gathered"

    def investigate(self, state: InvestigationState) -> AgentResult:
        _, reason = self.should_run(state)
        claims: list[Claim] = []
        notes: list[str] = []
        case = state.case

        for mapping in sorted(case.mappings, key=lambda m: -m.confidence.rank):
            details = self.tools.lookup_technique(mapping.technique_id, agent=self.name)
            if "error" in details:
                continue
            claim_type = (
                ClaimType.INFERENCE if mapping.confidence.rank >= 1 else ClaimType.HYPOTHESIS
            )
            claims.append(Claim(
                claim_type=claim_type,
                statement=(
                    f"Behaviour cited by {mapping.rule_id} is consistent with "
                    f"{mapping.display} ({mapping.tactic}). {mapping.reason}"
                ),
                evidence_ids=mapping.evidence_ids,
                source="mitre", agent=self.name,
                confidence=0.9 if mapping.confidence.rank == 2 else 0.6,
            ))

        tactics = tactics_covered(case.mappings)
        if tactics:
            claims.append(Claim(
                claim_type=ClaimType.INFERENCE,
                statement=(
                    f"The case spans {len(tactics)} ATT&CK tactics "
                    f"({' -> '.join(tactics)}). Progression across multiple tactics is "
                    "harder to explain as coincidental than activity confined to one."
                ),
                evidence_ids=case.event_ids,
                source="mitre", agent=self.name, confidence=0.8,
            ))

        # Naming the gaps is the most useful thing this agent does.
        missing = [t for t in _PROGRESSION_TACTICS if t not in tactics]
        if missing:
            notes.append(
                "No evidence was found for the following tactics: "
                f"{', '.join(missing)}. Their absence may reflect either that the "
                "activity did not occur or that we lack the telemetry to see it."
            )

        if "Collection" in tactics and "Exfiltration" not in tactics:
            claims.append(Claim(
                claim_type=ClaimType.HYPOTHESIS,
                statement=(
                    "Data staged on disk may have been transferred to the external "
                    "destination observed in this case. This is unverified: the "
                    "telemetry records archive creation and outbound connections "
                    "separately, and does not show the archive's contents leaving."
                ),
                source="analysis", agent=self.name, confidence=0.5,
            ))
            notes.append(
                "Confirming or excluding exfiltration would require network flow "
                "volumes or proxy logs, neither of which this dataset contains."
            )

        return self._result(state, reason, claims, notes=tuple(notes))


def default_specialists(tools: ToolBox) -> list[Specialist]:
    """The standard specialist roster, in default consideration order."""
    return [
        EndpointAgent(tools),
        IdentityAgent(tools),
        NetworkAgent(tools),
        AttackMappingAgent(tools),
    ]
