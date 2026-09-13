"""The generalist investigator -- arm B of the M19 ablation, and nothing else.

Why this module exists
-----------------------
It is the industry-default agent shape this project exists to be compared against: **one
agent, every tool, a model deciding what to look at.** The ablation cannot say that a
constrained crew of specialists is worth its complexity unless the unconstrained
alternative is actually run, on the same cases, under the same budgets, and scored the
same way. Arm B was declared but unimplemented in M19-1 for exactly one reason -- its two
budgets were unsettled -- and a generalist whose call count is decided by how long anyone
was willing to wait measures patience, not design.

What it is not
---------------
These are **not** a fifth specialist, and they are deliberately not in
:mod:`ath.agent.specialists` or in :data:`~ath.capabilities.registry.CAPABILITY_REGISTRY`.
No environment assembles them; no case dispatches them. They are instantiated only by
:func:`~ath.evaluation.ablation.arms.run_arm` for arm B. Putting them in the registry
would let the thing being measured leak into the thing doing the measuring.

The M19-3 correction: a planner with nothing to choose between is not a planner
-------------------------------------------------------------------------------
M19-2 built arm B as a single :class:`GeneralistAgent` walking one fixed queue. The
orchestrator consults the model only when **more than one** specialist is eligible -- with
a crew of one it records ``"only eligible specialist"`` and moves on -- so arm B never
exercised the LLM planner at all: M19-2 measured **0** planner-chosen steps for B against
3 for C. What that arm actually measured was model *synthesis* laid over a fixed walk,
which is not the arm the brief describes.

The fix is not to change what a generalist may do; it is to make its next move a choice.
The tool surface is split into seven :class:`GeneralistFacet` instances, one per
:data:`KIND_ORDER` entry, **sharing one walk, one ToolBox and one budget**. Each is
eligible while its own kind still has un-walked entities, so on any case naming more than
one kind of entity the orchestrator has several candidates and asks the model which to
run next. Nothing else moves: the tool surface, the budgets, the claim rules and the
evidence discipline are identical to arm C, and the handlers below are the M19-2 handlers
unchanged. **The only difference between B and C is what the planner chooses among** --
facets of one agent's tool surface, or domain specialists.

The three constraints that make it a fair comparison
-----------------------------------------------------
1. **It calls the same tools with the same identity discipline.** A finding carrying a
   ``process_guid`` is walked by that identity, not by its pid slot (M18b-2). Losing the
   comparison because the generalist was written to a worse standard than the crew would
   say nothing about single-agent versus crew.
2. **It authors FACTs and nothing else.** Every claim is a tool result restated with the
   event ids that tool returned. Inference and hypothesis in arm B come from the model's
   synthesis stage, which is the arm's whole point -- so when arm B runs without a model
   (as the scripted harness proof does), **it produces no inference and no hypothesis at
   all**, and that zero is a property of the run, not a finding about single agents.
3. **It runs under the same budgets as every other arm**: the orchestrator's step budget,
   and the :class:`~ath.agent.tools.ToolBox`'s per-case tool-call cap. A facet walks
   :data:`ITEMS_PER_STEP` entities per step and the walk resumes where it stopped, so a
   case with more entities than the budgets allow ends with work visibly undone rather
   than with an arm that silently took longer.

The facets, and the walk each owns
-----------------------------------
Built once per case from the case itself -- no set iteration anywhere, so two runs walk
the same entities and produce byte-identical claims. The **order below is the fallback
order**: when no model is available, or when the model's answer is rejected, the
orchestrator takes the first eligible candidate in crew order, which is this one. A
keyless run of arm B is therefore still deterministic, and identical to the queue M19-2
walked.

===  ===============  ===========================================================
1    ``case``         :meth:`~ath.agent.tools.ToolBox.get_case`
2    ``finding``      :meth:`~ath.agent.tools.ToolBox.get_finding`, one per member
                      finding, in the case's own chronological order
3    ``process``      :meth:`~ath.agent.tools.ToolBox.process_tree`, one per distinct
                      process instance the findings name -- by ``process_guid`` where
                      the finding carries one, by ``(device, pid)`` where it does not
4    ``timeline``     :meth:`~ath.agent.tools.ToolBox.get_events` over every event id
                      the case cites, in one call
5    ``account``      :meth:`~ath.agent.tools.ToolBox.user_auth_history`, one per account
6    ``host``         :meth:`~ath.agent.tools.ToolBox.host_network_activity`, one per host
7    ``technique``    :meth:`~ath.agent.tools.ToolBox.lookup_technique`, one per mapped
                      technique, in ascending technique id
===  ===============  ===========================================================

Breadth-first by category, and the order is the architect's, not a preference: it puts
the entities a detection actually named before the ones the case merely contains. A large
case walked in fallback order therefore spends its budget on findings and process trees
and reaches the technique lookups only if the budget survives -- which is itself a
measurement of what a single agent with a fixed budget can cover. A *planned* run may
spend it differently, and that difference is the measurement arm B exists to make.

One agent, seven names
-----------------------
Each facet is named ``generalist:<kind>`` -- one family, ``generalist``, with a facet
suffix. The suffix is what makes the plan log say which part of the tool surface the
model chose; the family is what every aggregate counts, so
:func:`~ath.evaluation.ablation.scoring.score_case` reports arm B as **one** agent run
out of one eligible rather than seven, and its completeness stays a ratio of at most
1.0. See :func:`~ath.agent.specialists.agent_family`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ath.agent.claims import Claim, ClaimType
from ath.agent.specialists import Specialist, budget_note
from ath.agent.state import AgentResult, InvestigationState
from ath.agent.tools import ToolCall
from ath.logging_setup import get_logger

logger = get_logger(__name__)

ITEMS_PER_STEP = 5
"""Entities one facet walks per orchestrator step.

Chosen against the ablation's other two budgets rather than picked: the step budget is 8
and the tool-call cap is 40, so a run that uses every step at this rate spends exactly
the cap. Neither budget is slack, and an arm that hits one hits the other at the same
point -- which is what makes "it ran out" a single, reportable fact.

Unchanged by the M19-3 facet split, and that is the point: the seven facets share one
budget, so splitting the tool surface changed what arm B may *choose* and not what it
may *spend*.
"""


FAMILY = "generalist"
"""The agent family every facet belongs to, and the name aggregates count once."""

KIND_ORDER: tuple[str, ...] = (
    "case", "finding", "process", "timeline", "account", "host", "technique",
)
"""The seven facets, in the architect's fixed order.

Two things at once, deliberately. It is the order the facets are handed to the
orchestrator, and therefore -- because the orchestrator's deterministic fallback takes
the first eligible candidate in crew order -- it is also the order a keyless arm B walks
in. That makes a model-less arm B reproducible by construction and identical to the
single queue M19-2 walked, without a second list anywhere that could drift from this one.
"""

FACET_DOMAINS: dict[str, str] = {
    "case": "the case record itself -- what it links, and what evidence it cites",
    "finding": "each detection finding, as its detector recorded it",
    "process": "process lineage for each process instance the findings name",
    "timeline": "the case's cited telemetry, in time order",
    "account": "authentication history for each account the case names",
    "host": "outbound network activity for each host the case names",
    "technique": "the verified ATT&CK entry for each technique mapped to the case",
}
"""What each facet tells the planner it would do.

This is the text the model is choosing between: ``Specialist.domain`` is what the
orchestrator puts in the planner prompt beside each candidate. Seven facets whose domains
all read "every entity of the case" would be a menu with one item written seven times.
"""


@dataclass(frozen=True)
class WalkItem:
    """One entity to walk, and how to name it in the audit trail."""

    kind: str
    arguments: dict[str, Any] = field(default_factory=dict)


class GeneralistWalk:
    """One case's walk, shared by every facet of one generalist.

    This is the whole of the facet refactor's risk, so it is one small object rather
    than state spread over seven agents: the plan is built **once** for a case, and an
    entity is marked walked the moment a facet takes it. Two facets cannot walk the same
    entity, and no entity is dropped between them, because there is exactly one list and
    exactly one flag per item.

    Not a set of walked items: :class:`WalkItem` carries a dict and is not hashable, and
    a "walked" set keyed on anything else would have to invent an identity for an entity
    that already has a position. Positions are what is tracked, and the plan tuple is
    iterated in order, so nothing here depends on hash ordering.
    """

    def __init__(self) -> None:
        self.case_id: str = ""
        self.plan: tuple[WalkItem, ...] = ()
        self.walked: list[bool] = []

    def _sync(self, state: InvestigationState) -> None:
        """Rebuild the plan when the case changes. Idempotent within one case."""
        if state.case.case_id != self.case_id:
            self.case_id = state.case.case_id
            self.plan = tuple(plan_walk(state))
            self.walked = [False] * len(self.plan)

    def remaining(
        self, state: InvestigationState, kind: str | None = None,
    ) -> list[tuple[int, WalkItem]]:
        """Un-walked items, in plan order; all of them when ``kind`` is ``None``."""
        self._sync(state)
        return [
            (index, item)
            for index, item in enumerate(self.plan)
            if not self.walked[index] and (kind is None or item.kind == kind)
        ]

    def mark(self, index: int) -> None:
        """Record that the item at ``index`` has been taken. Never undone."""
        self.walked[index] = True

    def walked_items(self) -> list[WalkItem]:
        """Everything taken so far, in plan order. For tests and for the audit trail."""
        return [item for index, item in enumerate(self.plan) if self.walked[index]]


class GeneralistFacet(Specialist):
    """One facet of the single generalist: every entity of one kind, and no other.

    A facet is not an agent in its own right -- it shares its walk, its
    :class:`~ath.agent.tools.ToolBox` and therefore its budget with its six siblings, and
    it reports under the ``generalist`` family. It exists so that the orchestrator's
    planner has a menu: *which part of this case's tool surface is worth the next step?*

    ``kind=None`` is the M19-2 shape -- one agent over every kind, one queue -- and is
    kept as :class:`GeneralistAgent`. It is not assembled into any arm; it is the
    reference the facet split is asserted equal to in ``tests/test_generalist_agent.py``,
    which is the only thing that makes "the refactor changed no work" checkable rather
    than claimed.
    """

    name = FAMILY
    domain = "every entity of the case, through every tool"

    # Empty by design: a generalist is never declined for missing telemetry, because it
    # does not declare a domain that telemetry could be missing *for*. It asks, and a
    # tool with nothing to say says so. This is the permissiveness the ablation is
    # measuring the cost of, written down rather than argued about.
    reads_channels = frozenset()
    reads_channels_any = frozenset()

    def __init__(
        self,
        tools: Any,
        kind: str | None = None,
        walk: GeneralistWalk | None = None,
        items_per_step: int = ITEMS_PER_STEP,
    ) -> None:
        super().__init__(tools)
        if kind is not None and kind not in KIND_ORDER:
            raise ValueError(
                f"unknown generalist facet {kind!r}; the facets are {KIND_ORDER}. "
                "A facet whose kind no walk item carries would be permanently "
                "ineligible and would silently shrink arm B's tool surface."
            )
        self.kind = kind
        self.walk = walk if walk is not None else GeneralistWalk()
        self.items_per_step = max(1, items_per_step)
        # Instance attributes, shadowing the class ones: seven facets of one class need
        # seven names and seven domains, and the planner prompt is built from both.
        self.name = FAMILY if kind is None else f"{FAMILY}:{kind}"
        self.domain = self.domain if kind is None else FACET_DOMAINS[kind]

    # -- eligibility ------------------------------------------------------------------

    def should_run(self, state: InvestigationState) -> tuple[bool, str]:
        """Eligible while this facet's kind still has un-walked entities.

        Overrides the base gate entirely, and both halves of that matter. The base
        declines a specialist that has already run, which would make each facet a
        one-pass agent and silently answer the budget question M19-2 exists to settle.
        The base also declines on missing telemetry, which a generalist declares none of.
        """
        remaining = self.walk.remaining(state, self.kind)
        if not remaining:
            if self.kind is None:
                return False, f"every entity of {state.case.case_id} has been walked"
            return False, f"every {self.kind} entity has been walked"
        if self.kind is None:
            return True, (
                f"{len(remaining)} entit(ies) of {state.case.case_id} remain unwalked; "
                "a generalist investigates everything the case names"
            )
        return True, (
            f"{len(remaining)} {self.kind} entit(ies) of {state.case.case_id} remain "
            "unwalked"
        )

    # -- the walk ---------------------------------------------------------------------

    def investigate(self, state: InvestigationState) -> AgentResult:
        _, reason = self.should_run(state)
        batch = self.walk.remaining(state, self.kind)[: self.items_per_step]

        # This step's tool calls only. ``Specialist._result`` attaches
        # ``tools.calls_by(name)``, which is every call this agent has ever made -- fine
        # for an agent that runs once per case, and the exact cumulative-count defect
        # M19-2 corrected in scripts/m18_cloud_detection.py for one that does not. A
        # multi-step agent must slice.
        first_call = len(self.tools.calls)

        claims: list[Claim] = []
        notes: list[str] = []
        for index, item in batch:
            # Marked before the handler runs, not after. An entity that stayed unwalked
            # because its handler raised would leave this facet eligible forever, and
            # the orchestrator -- which contains one specialist's failure rather than
            # ending the run -- would spend the whole step budget retrying it.
            self.walk.mark(index)
            handler = getattr(self, f"_walk_{item.kind}")
            handler(state, item, claims, notes)

        step_calls: tuple[ToolCall, ...] = tuple(
            call for call in self.tools.calls[first_call:] if call.agent == self.name
        )
        logger.debug(
            "%s: walked %d item(s), %d call(s), %d claim(s); %d item(s) left for this "
            "facet", self.name, len(batch), len(step_calls), len(claims),
            len(self.walk.remaining(state, self.kind)),
        )
        return AgentResult(
            agent=self.name,
            ran_because=reason,
            claims=tuple(claims),
            tool_calls=step_calls,
            notes=tuple(notes),
        )

    # -- one handler per item kind ----------------------------------------------------

    def _walk_case(
        self, state: InvestigationState, item: WalkItem,
        claims: list[Claim], notes: list[str],
    ) -> None:
        case = state.case
        payload = self.tools.get_case(case.case_id, agent=self.name)
        if payload.get("refused"):
            notes.append(budget_note("get_case"))
            return
        if payload.get("error") or not case.event_ids:
            notes.append(f"The case record for {case.case_id} could not be retrieved.")
            return
        claims.append(Claim(
            claim_type=ClaimType.FACT,
            statement=(
                f"Case {case.case_id} links {len(case.findings)} finding(s) from "
                f"{', '.join(case.rule_ids)} across host(s) "
                f"{', '.join(case.devices) or 'none named'} and account(s) "
                f"{', '.join(case.users) or 'none named'}, citing "
                f"{len(case.event_ids)} telemetry event(s)."
            ),
            evidence_ids=case.event_ids,
            source="tool", agent=self.name,
        ))

    def _walk_finding(
        self, state: InvestigationState, item: WalkItem,
        claims: list[Claim], notes: list[str],
    ) -> None:
        finding_id = str(item.arguments["finding_id"])
        payload = self.tools.get_finding(finding_id, agent=self.name)
        if payload.get("refused"):
            notes.append(budget_note("get_finding"))
            return
        if payload.get("error"):
            notes.append(f"{finding_id} is not in the finding set handed to this run.")
            return
        event_ids = tuple(str(e) for e in payload.get("event_ids", ()))
        if not event_ids:
            notes.append(f"{finding_id} cites no evidence; nothing to assert from it.")
            return
        claims.append(Claim(
            claim_type=ClaimType.FACT,
            statement=(
                f"{payload['rule_id']} ({payload['severity']}) on "
                f"{payload['device']} under account {payload['user']}: "
                f"{payload['title']}. {payload['reason']}"
            ),
            evidence_ids=event_ids,
            source="detector", agent=self.name,
        ))

    def _walk_process(
        self, state: InvestigationState, item: WalkItem,
        claims: list[Claim], notes: list[str],
    ) -> None:
        device = str(item.arguments["device"])
        pid = item.arguments["pid"]
        identity = str(item.arguments.get("process_guid") or "")
        tree = self.tools.process_tree(
            device, pid, agent=self.name, process_guid=identity,
        )
        if tree.get("refused"):
            notes.append(budget_note("process_tree"))
            return
        if tree["resolution"] == "ambiguous_pid":
            # The crew records an INFERENCE here. The generalist records a note: it
            # authors no inference of its own by construction, and inventing one
            # exception would make its claim mix incomparable with arm B's own
            # model-authored inferences, which is the thing being measured.
            notes.append(
                f"PID {pid} on {device} was held by {tree['ambiguous_pid']} process "
                "instances; no lineage can be attributed to this finding from the pid "
                "alone."
            )
            return
        ancestry, children = tree["ancestry"], tree["children"]
        if not ancestry:
            notes.append(
                f"No process lineage could be reconstructed for "
                f"{identity or f'pid {pid}'} on {device}."
            )
            return
        leaf = ancestry[0]
        chain = " -> ".join(
            [ancestry[-1]["parent_process_name"]]
            + [a["process_name"] for a in reversed(ancestry)]
        )
        child_names = ", ".join(sorted({c["process_name"] for c in children}))
        claims.append(Claim(
            claim_type=ClaimType.FACT,
            statement=(
                f"On {device}, {leaf['process_name']} (PID {leaf['process_id']}) ran "
                f"under account {leaf['user']} with execution chain {chain}"
                + (f", spawning {len(children)} child process(es): {child_names}"
                   if children else ", spawning no observed child process")
                + f". Resolution: {tree['resolution']}."
            ),
            evidence_ids=tuple(
                [a["event_id"] for a in ancestry] + [c["event_id"] for c in children]
            ),
            source="tool", agent=self.name,
        ))

    def _walk_timeline(
        self, state: InvestigationState, item: WalkItem,
        claims: list[Claim], notes: list[str],
    ) -> None:
        wanted = list(state.case.event_ids)
        payload = self.tools.get_events(wanted, agent=self.name)
        if payload.get("refused"):
            notes.append(budget_note("get_events"))
            return
        rows = payload.get("events", [])
        if not rows:
            notes.append("The case's event ids returned no telemetry rows.")
            return
        claims.append(Claim(
            claim_type=ClaimType.FACT,
            statement=(
                f"The case timeline comprises {len(rows)} of {len(wanted)} cited "
                f"event(s), from {rows[0]['timestamp']} to {rows[-1]['timestamp']}."
            ),
            evidence_ids=tuple(str(r["event_id"]) for r in rows),
            source="tool", agent=self.name,
        ))
        if payload.get("not_found"):
            notes.append(
                f"{len(payload['not_found'])} cited event id(s) returned no row."
            )

    def _walk_account(
        self, state: InvestigationState, item: WalkItem,
        claims: list[Claim], notes: list[str],
    ) -> None:
        user = str(item.arguments["user"])
        history = self.tools.user_auth_history(user, agent=self.name)
        if history.get("refused"):
            notes.append(budget_note("user_auth_history"))
            return
        summary = history.get("summary") or {}
        if not summary:
            notes.append(f"No authentication telemetry exists for account '{user}'.")
            return
        claims.append(Claim(
            claim_type=ClaimType.FACT,
            statement=(
                f"Account '{user}' has {summary['total']} authentication event(s) "
                f"({summary['failures']} failed, {summary['successes']} successful) "
                f"across hosts {', '.join(summary['target_devices'])}, from source(s) "
                f"{', '.join(summary['source_devices']) or 'none resolved'}."
            ),
            evidence_ids=tuple(str(e["event_id"]) for e in history["events"]),
            source="tool", agent=self.name,
        ))

    def _walk_host(
        self, state: InvestigationState, item: WalkItem,
        claims: list[Claim], notes: list[str],
    ) -> None:
        device = str(item.arguments["device"])
        activity = self.tools.host_network_activity(device, agent=self.name)
        if activity.get("refused"):
            notes.append(budget_note("host_network_activity"))
            return
        event_ids = tuple(str(e) for e in activity.get("event_ids", ()))
        if not event_ids:
            notes.append(f"No outbound network telemetry exists for host {device}.")
            return
        destinations = ", ".join(
            f"{d['remote_ip']} ({d['connections']} via {d['process_name']})"
            for d in activity["destinations"][:5]
        )
        claims.append(Claim(
            claim_type=ClaimType.FACT,
            statement=(
                f"{device} made {activity['total']} outbound connection(s) to "
                f"{len(activity['destinations'])} destination(s); the most frequent "
                f"are {destinations}."
            ),
            evidence_ids=event_ids,
            source="tool", agent=self.name,
        ))

    def _walk_technique(
        self, state: InvestigationState, item: WalkItem,
        claims: list[Claim], notes: list[str],
    ) -> None:
        technique_id = str(item.arguments["technique_id"])
        details = self.tools.lookup_technique(technique_id, agent=self.name)
        if details.get("refused"):
            notes.append(budget_note("lookup_technique"))
            return
        if details.get("error"):
            notes.append(f"{technique_id} is not in the verified ATT&CK catalogue.")
            return
        mappings = [m for m in state.case.mappings if m.technique_id == technique_id]
        evidence = tuple(sorted({e for m in mappings for e in m.evidence_ids}))
        if not evidence:
            notes.append(f"{technique_id} is mapped to this case by no finding.")
            return
        claims.append(Claim(
            claim_type=ClaimType.FACT,
            statement=(
                f"{details['technique_id']} ({details['name']}) is catalogued under "
                f"{', '.join(details['tactics'])} and is mapped to this case by "
                f"{', '.join(sorted({m.rule_id for m in mappings}))}."
            ),
            evidence_ids=evidence,
            source="mitre", agent=self.name,
        ))


class GeneralistAgent(GeneralistFacet):
    """The M19-2 shape: one agent, one queue over every kind.

    Retained deliberately and used by no arm. The facet split's correctness is stated as
    an equality -- *the union of the seven facets' work is exactly this agent's work* --
    and an equality needs both sides. Written as ``kind=None`` rather than as a second
    implementation so there is no duplicate walk to drift from the facets'.
    """

    def __init__(self, tools: Any, items_per_step: int = ITEMS_PER_STEP) -> None:
        super().__init__(tools, kind=None, items_per_step=items_per_step)


def build_generalist_crew(
    tools: Any, items_per_step: int = ITEMS_PER_STEP,
) -> list[GeneralistFacet]:
    """Arm B's crew: seven facets of one generalist, in :data:`KIND_ORDER`.

    One :class:`GeneralistWalk` and one ``tools`` between them, so the seven share a
    walk, a tool-call budget and an audit trail. Handing back a list in ``KIND_ORDER``
    is what makes the orchestrator's deterministic fallback -- first eligible candidate
    in crew order -- equal to the fixed order this module documents.
    """
    walk = GeneralistWalk()
    return [
        GeneralistFacet(tools, kind=kind, walk=walk, items_per_step=items_per_step)
        for kind in KIND_ORDER
    ]


def plan_walk(state: InvestigationState) -> list[WalkItem]:
    """Every entity this case names, in the fixed order this module documents.

    Deterministic by construction: the case's finding tuple is chronological and fixed,
    accounts and hosts come from ``InvestigationCase`` already sorted, and technique ids
    are sorted here. No set is ever iterated -- the one place a set appears it is
    immediately sorted -- because set iteration order is the classic way a "reproducible"
    agent stops being one.
    """
    case = state.case
    items: list[WalkItem] = [WalkItem("case", {"case_id": case.case_id})]

    for finding in case.findings:
        items.append(WalkItem("finding", {"finding_id": finding.finding_id}))

    seen: list[tuple[str, str, Any]] = []
    for finding in case.findings:
        identity = str(finding.metadata.get("process_guid") or "")
        pid = finding.metadata.get("process_id")
        if pid is None and not identity:
            continue
        # The instance, then the slot: a finding that names the run is walked by the
        # run (M18b-2). Both names are remembered so two findings pointing at one
        # execution are walked once.
        key = (finding.device, identity, None if identity else int(pid))
        if key in seen:
            continue
        seen.append(key)
        items.append(WalkItem("process", {
            "device": finding.device,
            "pid": int(pid) if pid is not None else None,
            "process_guid": identity,
        }))

    items.append(WalkItem("timeline", {"case_id": case.case_id}))
    items += [WalkItem("account", {"user": user}) for user in case.users]
    items += [WalkItem("host", {"device": device}) for device in case.devices]
    items += [
        WalkItem("technique", {"technique_id": technique})
        for technique in sorted({m.technique_id for m in case.mappings})
    ]
    return items
