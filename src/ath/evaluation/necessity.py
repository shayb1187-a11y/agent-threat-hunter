"""M19b T4: the cross-specialist necessity audit, computed from cases, not asserted.

The fact this module exists to measure
---------------------------------------
M19's arm C consulted its planner on 1 case of 22. Not because the planner was broken,
but because on 21 cases exactly one *domain* specialist was ever eligible, so
``orchestrator.plan`` took its "only eligible specialist" path at every step. An
ablation between a crew and a single investigator cannot say anything about crews on a
case where the crew is one agent wearing four name tags.

So before M19b selects a benchmark case, every case this repository can build is put
through the test ``docs/m19b-plan.md`` fixed in advance:

1. two or more **domain** specialists (endpoint / identity / network / control_plane --
   the ATT&CK mapper is an interpreter, not a domain) have *materially relevant*
   evidence: rows in a channel they read, carried by a finding in the case;
2. the evidence is **not redundant**: removing one domain's findings removes a stage of
   the story rather than a second copy of one;
3. cross-domain synthesis could change the **verdict, the priority, or the next
   action**, stated concretely.

Why eligibility is simulated twice
-----------------------------------
Two different questions, and conflating them is what made M19's number hard to read.

``first_step``
    ``orchestrator.eligible`` on a *fresh* state: who could run at step 0, before any
    specialist has consumed its own trigger. This is the number that decides whether
    the planner is ever consulted, because the planner is only reached when more than
    one candidate exists at the same step. The ATT&CK mapper is deliberately absent
    here -- :meth:`AttackMappingAgent.has_work` defers itself at ``step == 0``.

``whole_run``
    ``agents_run | eligible_never_ran`` after a full deterministic investigation --
    exactly the set :func:`ath.evaluation.ablation.scoring.score_case` counts as
    ``specialists_eligible``. It includes the mapper, which is why 21 of M19's cases
    report "2 eligible" while having no choice at any step.

``tests/test_m19b_audit.py`` asserts the second against the recorded arm A rows, so a
drift in the pipeline shows up as a failed audit rather than as a quietly different
corpus.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ath.agent.claims import ClaimVerifier
from ath.agent.orchestrator import InvestigationConfig, InvestigationOrchestrator
from ath.agent.specialists import agent_family, channel_sources
from ath.agent.state import InvestigationState
from ath.agent.tools import ToolBox
from ath.channels import TelemetryChannel
from ath.correlation.chain import InvestigationCase
from ath.hunting.finding import Finding
from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS
from ath.telemetry.loader import Telemetry

DOMAIN_SPECIALISTS: tuple[str, ...] = ("endpoint", "identity", "network", "control_plane")
"""The four specialists that read telemetry. ``attack`` interprets what they found.

Named here rather than derived from ``default_specialists()`` because the default
roster does not contain ``control_plane`` at all (it is assembled conditionally by
``ath.capabilities.crew``), and an audit that took the roster's word for which agents
are domain agents would have silently excluded every cloud and Kubernetes case.
"""

TABLE_DOMAIN: Mapping[str, str] = {
    EVENT_PROCESS: "endpoint",
    EVENT_NETWORK: "network",
    EVENT_LOGON: "identity",
    EVENT_CONTROL: "control_plane",
}
"""Which domain a canonical table's rows belong to.

Used only to count *independent evidence sources*: a case whose 32 evidence ids are all
``control`` rows rests on one source however many rules cite them. This is a coarser
question than channel membership on purpose -- two channels of the same table (process
execution and process command line) are one observation of one event, and counting them
as two independent sources would be the audit flattering itself.
"""

STEP_BUDGET = 8
"""``ath.evaluation.ablation.arms.STEP_BUDGET``, restated so the audit's deterministic
walk is the same walk arm A took. Restated by value rather than imported so this module
stays importable without the ablation package's corpora; ``tests/test_m19b_audit.py``
asserts the two are equal."""


def _domain_agents() -> tuple[Any, ...]:
    from ath.agent.specialists import (  # noqa: PLC0415 -- avoids an import cycle
        ControlPlaneAgent,
        EndpointAgent,
        IdentityAgent,
        NetworkAgent,
    )

    return (EndpointAgent, IdentityAgent, NetworkAgent, ControlPlaneAgent)


def channel_domains(channels: Iterable[TelemetryChannel]) -> set[str]:
    """Which domains a set of channels is materially relevant to.

    Derived from each specialist's own ``triggered_by_channels`` declaration, not from
    a second table in this module -- a hand-kept copy would be exactly the staleness
    the channel vocabulary replaced (see ``Specialist``'s docstring on ``ATH-009``).
    """
    channels = set(channels)
    return {
        agent.name for agent in _domain_agents()
        if channels & set(agent.triggered_by_channels)
    }


@dataclass
class CaseAudit:
    """One case, measured against the necessity test.

    Every field is computed. Nothing here is a judgement about whether a case is
    *interesting*; the three booleans are the plan's three conditions and the prose
    fields say what was measured, including when the answer is "it could not".
    """

    corpus: str
    case_id: str
    provenance: str
    rule_ids: tuple[str, ...]
    finding_ids: tuple[str, ...]
    evidence_id_count: int
    channels: dict[str, list[str]]
    domains: tuple[str, ...]
    domains_by_finding: dict[str, list[str]]
    corpus_channels: tuple[str, ...]
    first_step_eligible: tuple[str, ...]
    first_step_domain_specialists: int
    whole_run_eligible: tuple[str, ...]
    whole_run_specialists_eligible: int
    agents_run: tuple[str, ...]
    evidence_sources: dict[str, int]
    independent_evidence_sources: int
    tactics: tuple[str, ...]
    techniques: tuple[str, ...]
    ground_truth: dict[str, Any]
    two_domains: bool
    non_redundant: bool
    synthesis_could_change: bool
    qualifies: bool
    failure_reason: str
    synthesis_statement: str
    held_out: bool
    tuned_against: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            key: (list(value) if isinstance(value, tuple) else value)
            for key, value in vars(self).items()
        }


def audit_case(
    case: InvestigationCase,
    *,
    corpus: str,
    provenance: str,
    telemetry: Telemetry,
    findings: Sequence[Finding],
    cases: Sequence[InvestigationCase],
    environment: Any,
    corpus_channels: Iterable[TelemetryChannel] = (),
    ground_truth: Mapping[str, Any] | None = None,
    tuned_against: Mapping[str, Any] | None = None,
    held_out: bool = False,
    evidence_index: Mapping[str, set[str]] | None = None,
) -> CaseAudit:
    """Run the necessity test on one case, exactly as the pipeline would investigate it.

    The deterministic investigation is actually executed rather than predicted. It is
    arm A's configuration (no model, planner and synthesis off, the same step budget),
    so ``whole_run_specialists_eligible`` is the same quantity arm A recorded and can be
    asserted against it -- which is the only way this audit can claim to describe the
    pipeline rather than a model of it.
    """
    from ath.environment.coverage import channels_for_fields  # noqa: PLC0415

    tools = ToolBox(telemetry, list(findings), list(cases))
    verifier = ClaimVerifier(telemetry)
    orchestrator = InvestigationOrchestrator(
        tools, verifier,
        config=InvestigationConfig(
            max_steps=STEP_BUDGET, use_llm_planner=False, use_llm_synthesis=False,
        ),
        environment=environment,
    )

    fresh = InvestigationState(case=case, environment=environment, max_steps=STEP_BUDGET)
    first_step = tuple(s.name for s, _ in orchestrator.eligible(fresh))
    first_step_domains = tuple(n for n in first_step if n in DOMAIN_SPECIALISTS)

    state = orchestrator.investigate(case)
    eligible_never_ran = [s.name for s, _ in orchestrator.eligible(state)]
    whole_run = sorted(
        {agent_family(a) for a in set(state.agents_run) | set(eligible_never_ran)}
    )

    sources = channel_sources(fresh)
    channels = {
        channel.value: sorted(rules)
        for channel, rules in sorted(sources.items(), key=lambda kv: kv[0].value)
    }
    domains = sorted(channel_domains(sources))

    # Which domains each finding is materially relevant to -- the input to the
    # redundancy test, because "removing a domain removes a stage" is a question about
    # findings, not about channels.
    domains_by_finding: dict[str, list[str]] = {}
    for finding in case.findings:
        finding_channels = set(finding.channels) or channels_for_fields(finding.fields_used)
        domains_by_finding[finding.finding_id] = sorted(channel_domains(finding_channels))

    index = event_id_index(telemetry) if evidence_index is None else evidence_index
    by_table = _evidence_by_table(index, case.event_ids)
    evidence_sources = {TABLE_DOMAIN[t]: n for t, n in by_table.items() if n}

    two_domains = len(domains) >= 2
    non_redundant, redundancy_note = _redundancy(domains, domains_by_finding)
    synthesis_statement, synthesis_could_change = _synthesis_statement(
        case, domains, evidence_sources, two_domains and non_redundant,
    )
    qualifies = bool(two_domains and non_redundant and synthesis_could_change)

    failure_reason = ""
    if not qualifies:
        if not domains:
            failure_reason = (
                "no domain specialist has materially relevant evidence: the case's "
                "findings rest on no channel any of the four domain agents reads"
            )
        elif not two_domains:
            failure_reason = (
                f"one domain only ({domains[0]}): every finding rests on "
                + ", ".join(channels)
                + " -- there is no second domain to synthesise with"
            )
        elif not non_redundant:
            failure_reason = redundancy_note
        else:
            failure_reason = (
                "two domains are present but no verdict, priority or next action turns "
                "on combining them"
            )

    return CaseAudit(
        corpus=corpus,
        case_id=case.case_id,
        provenance=provenance,
        rule_ids=tuple(case.rule_ids),
        finding_ids=tuple(sorted(f.finding_id for f in case.findings)),
        evidence_id_count=len(case.event_ids),
        channels=channels,
        domains=tuple(domains),
        domains_by_finding=domains_by_finding,
        corpus_channels=tuple(sorted(c.value for c in corpus_channels)),
        first_step_eligible=first_step,
        first_step_domain_specialists=len(first_step_domains),
        whole_run_eligible=tuple(whole_run),
        whole_run_specialists_eligible=len(whole_run),
        agents_run=tuple(state.agents_run),
        evidence_sources=evidence_sources,
        independent_evidence_sources=len(evidence_sources),
        tactics=tuple(case.tactics),
        techniques=tuple(case.techniques),
        ground_truth=dict(ground_truth or {}),
        two_domains=two_domains,
        non_redundant=non_redundant,
        synthesis_could_change=synthesis_could_change,
        qualifies=qualifies,
        failure_reason=failure_reason,
        synthesis_statement=synthesis_statement,
        held_out=held_out,
        tuned_against=dict(tuned_against or {}),
    )


def event_id_index(telemetry: Telemetry) -> dict[str, set[str]]:
    """Each canonical table's event ids, as a set, built once for a whole corpus.

    Hoisted out of :func:`audit_case` deliberately. Asking a 1.86M-row control table
    ``isin`` a case's thirty ids is cheap once and ruinous 281 times: on flaws.cloud
    that is half a billion row comparisons to answer a question whose input never
    changes between cases. Building the sets once turns the per-case cost into a set
    intersection over the case's own ids.
    """
    index: dict[str, set[str]] = {}
    for event_type in (EVENT_PROCESS, EVENT_NETWORK, EVENT_LOGON, EVENT_CONTROL):
        frame = telemetry.table(event_type)
        if frame.empty or "event_id" not in frame.columns:
            index[event_type] = set()
            continue
        index[event_type] = set(frame["event_id"].astype(str))
    return index


def _evidence_by_table(
    index: Mapping[str, set[str]], event_ids: Sequence[str],
) -> dict[str, int]:
    """How many of a case's evidence ids live in each canonical table."""
    wanted = {str(e) for e in event_ids}
    return {
        event_type: len(wanted & ids) for event_type, ids in index.items()
    }


def _redundancy(
    domains: Sequence[str], domains_by_finding: Mapping[str, Sequence[str]],
) -> tuple[bool, str]:
    """Whether removing a domain would remove a *stage* rather than a duplicate.

    Operationalised as: at least two domains each carry a finding that no other domain
    carries. A case whose every finding is relevant to both domains (one row two
    specialists both read) is one stage seen twice, and deleting either domain leaves
    the story intact -- redundancy, not corroboration from two independent sources.
    """
    if len(domains) < 2:
        return False, "fewer than two domains; redundancy is not defined"
    exclusive: dict[str, int] = {d: 0 for d in domains}
    for finding_domains in domains_by_finding.values():
        if len(finding_domains) == 1 and finding_domains[0] in exclusive:
            exclusive[finding_domains[0]] += 1
    carrying = [d for d, n in exclusive.items() if n]
    if len(carrying) >= 2:
        return True, ""
    return False, (
        "redundant: only " + (", ".join(carrying) or "no domain")
        + " carries a finding no other domain also reads, so removing the other "
        "domain(s) removes a second view of one stage, not a stage"
    )


_DOMAIN_PROSE = {
    "endpoint": "what executed on the host and what started it",
    "identity": "whose credentials were used and from where",
    "network": "who the host talked to and whether the timing looks automated",
    "control_plane": "which cloud/cluster resources an identity acted on",
}


def _synthesis_statement(
    case: InvestigationCase,
    domains: Sequence[str],
    evidence_sources: Mapping[str, int],
    eligible: bool,
) -> tuple[str, bool]:
    """A concrete statement of what synthesis could change -- or why it could not.

    Deliberately not a model call, and deliberately not a template that always says
    yes: on a case with one domain it returns the reason no synthesis is possible, and
    on this repository's corpora that is the answer it returns most often.
    """
    if not eligible:
        if not domains:
            return (
                "It could not: the case's findings rest on no channel a domain "
                "specialist reads, so there is no domain analysis to combine.",
                False,
            )
        if len(domains) == 1:
            only = domains[0]
            return (
                f"It could not: every finding in this case is {only} evidence "
                f"({_DOMAIN_PROSE[only]}). A second specialist would have no rows to "
                "read, so the verdict, the priority and the next action are whatever "
                f"the {only} specialist alone concludes.",
                False,
            )
        return (
            "It could not: the domains present are two readings of the same rows, so "
            "removing either leaves every stage of the story standing.",
            False,
        )

    parts = ", ".join(f"{d} ({_DOMAIN_PROSE[d]})" for d in domains)
    return (
        f"Synthesis across {parts} can change the verdict: each domain's finding is "
        "explicable on its own, and the other domain's rows are what decide whether "
        "that explanation survives. The case carries "
        + ", ".join(f"{n} {d} row(s)" for d, n in sorted(evidence_sources.items()))
        + f", spanning the {', '.join(case.tactics) or 'un-mapped'} tactic(s); a "
        "verdict reached from one domain alone cannot exclude the benign reading the "
        "other domain's rows rule out.",
        True,
    )


@dataclass
class CorpusAudit:
    """One corpus and every case it produced."""

    name: str
    provenance: str
    source: str
    rows: dict[str, int]
    corpus_channels: tuple[str, ...]
    findings: int
    cases: int
    case_audits: list[CaseAudit] = field(default_factory=list)
    notes: str = ""
    error: str = ""

    @property
    def qualifying(self) -> list[CaseAudit]:
        return [c for c in self.case_audits if c.qualifies]

    def summary(self) -> dict[str, Any]:
        multi = [c for c in self.case_audits if c.first_step_domain_specialists >= 2]
        return {
            "corpus": self.name,
            "provenance": self.provenance,
            "source": self.source,
            "rows": self.rows,
            "corpus_channels": list(self.corpus_channels),
            "findings": self.findings,
            "cases": self.cases,
            "cases_audited": len(self.case_audits),
            "qualifying_cases": len(self.qualifying),
            "qualifying_case_ids": [c.case_id for c in self.qualifying],
            "cases_with_two_domain_specialists_at_first_step": len(multi),
            "domains_seen": sorted({d for c in self.case_audits for d in c.domains}),
            "notes": self.notes,
            "error": self.error,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.summary(), "cases_detail": [c.to_dict() for c in self.case_audits]}


def audit_digest(payload: Any) -> str:
    """A digest over the audit, so a later milestone can say whether it changed."""
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
