"""Label-free scoring: what can be checked about an investigation without a human.

The constraint
---------------
flaws.cloud has no verdict labels. COMISET has no verdict labels. Most real telemetry
never will, and an ablation that can only be scored where labels exist can only be run
where labels exist -- which is the synthetic benchmark, the one place a model arm has
the least to prove. So every metric here is computed from the claim verifier and the
telemetry: evidence either exists or it does not, a tool call either touched an event or
it did not, a technique either appears in the deterministic mapper's output or it does
not. **Nothing is scored by another model**, and nothing is scored by reading prose for
quality. Where labels *do* exist (the synthetic ground truth, the attack_data_aws
capture technique) they are used as an additional, clearly separated column -- see
:func:`ath.evaluation.incidents.score_labels`, called on the row's own state.

What is deliberately not here
------------------------------
No thresholds, and no pass/fail. This module defines no numeric constant of any kind:
a score that carries its own cutoff has decided the experiment's conclusion before the
experiment ran, and the point of pre-registering the arms is that the decision rule is
written down separately, by the architect, in
``reports/m19/ablation/PREREGISTERED.md``. The one exception is a by-construction
*check* -- a FACT with no evidence -- which cannot be a matter of degree because
:class:`~ath.agent.claims.Claim` refuses to construct one. If it is ever observed, that
is a defect in the claim layer and it raises rather than scoring badly.

Why techniques are read out of tool calls, not out of prose (M19-2)
--------------------------------------------------------------------
Until M19-2 the asserted-technique set was a regular expression over claim text. That is
reading an id that is literally present rather than inferring meaning, so it was
defensible -- and it was wrong in a way the first run showed. The ATT&CK mapper's own
reason for ``T1110.001`` ends "(a spray against many accounts would be T1110.003)", so
three arm A cases reported ``T1110.003`` as asserted-but-unmapped. A technique named as
a *contrast* counted as a technique asserted. The Jaccard those three cases produced was
not a weak measurement of agreement; it was a measurement of a sentence.

So the asserted set is now **structural**: the technique ids the investigation passed to
the ``lookup_technique`` tool, taken from the recorded
:class:`~ath.agent.tools.ToolCall` arguments. An investigation asserts a technique by
going and getting it, which is an action, recorded, with no wording to interpret. A
refused call (tool budget) is excluded: the investigation asked, was not answered, and
published nothing.

There is no structured technique field on :class:`~ath.agent.claims.Claim` to add to it.
That was checked rather than assumed, and none is added here: inventing a field for one
metric would let the metric shape the claim layer.

What this costs, stated plainly
--------------------------------
Only a specialist can call a tool -- a model can plan and synthesise, and neither
touches the toolbox -- so a model arm cannot add to the asserted set at all. On every
arm whose crew reaches the ATT&CK step, the asserted set therefore *is* the mapper's
set, and the metric degenerates towards a coverage question: **did this investigation
actually retrieve the techniques its own detection layer produced?** That is a real
question (a budget-capped or step-limited run answers it "no"), but it is no longer the
question of whether a model named a technique nothing supports.

That second question keeps its data: ``techniques_in_prose`` records the old regular
expression over claim text as a **diagnostic, never a score**. When a model arm writes a
technique id into a synthesised claim, the difference between ``techniques_in_prose`` and
``techniques_asserted`` is exactly that claim -- visible, separately reportable, and not
folded into a Jaccard where it would be indistinguishable from a mapper disagreement.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from itertools import combinations
from typing import Any, Iterable, Sequence

from ath.agent.claims import Claim, ClaimType, ClaimVerifier
from ath.agent.specialists import agent_family
from ath.agent.state import InvestigationState
from ath.correlation.chain import InvestigationCase
from ath.instance_identity import INFERRED_FROM_PID

_TECHNIQUE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# The sentence the endpoint specialist publishes when a pid was held by more than one
# process instance (M18b-2). Matched as a literal so that an arm which reworded it
# would show up as a change in the count rather than as a silent zero.
_AMBIGUOUS_PID_MARKER = "different process instances"


class ByConstructionViolation(AssertionError):
    """A property the type system was supposed to guarantee did not hold.

    Raised rather than scored: a FACT with no evidence cannot be constructed, so
    observing one means the claim layer has a hole and every other number in the run is
    suspect. Degrading it to a bad score would let the defect average away.
    """


def techniques_in(claims: Iterable[Claim]) -> tuple[str, ...]:
    """Technique ids literally present in the text of ``claims``."""
    found: set[str] = set()
    for claim in claims:
        found.update(_TECHNIQUE_PATTERN.findall(claim.statement))
    return tuple(sorted(found))


def techniques_looked_up(calls: Iterable[Any]) -> tuple[str, ...]:
    """Technique ids the investigation actually retrieved, from its own tool calls.

    Refused calls are excluded: a call the budget refused returned nothing and authored
    nothing, so counting it would credit an investigation with a technique it never got.
    """
    found: set[str] = set()
    for call in calls:
        if call.tool != "lookup_technique" or getattr(call, "refused", False):
            continue
        technique = str(call.arguments.get("technique_id", "")).strip()
        if technique:
            found.add(technique.upper())
    return tuple(sorted(found))


def _existing(verifier: ClaimVerifier, event_ids: Iterable[str]) -> set[str]:
    """Which of ``event_ids`` the verifier recognises as real telemetry.

    Asked of the verifier rather than recomputed from the telemetry tables, because the
    verifier is this project's single authority on "does this event id exist" and a
    second implementation here would be a second answer to that question.
    """
    real: set[str] = set()
    for event_id in event_ids:
        probe = Claim(
            claim_type=ClaimType.HYPOTHESIS,
            statement="existence probe",
            evidence_ids=(event_id,),
            source="tool",
        )
        if verifier.check(probe) is None:
            real.add(event_id)
    return real


@dataclass
class CaseScores:
    """Every label-free measurement for one investigated case.

    Plain data. Each field is a count or a ratio with a stated denominator, and no field
    encodes a judgement about whether the number is good.
    """

    # -- evidence correctness -------------------------------------------------------
    cited_event_ids: int = 0
    cited_event_ids_existing: int = 0
    rejected_claims: int = 0
    rejection_reasons: dict[str, int] = field(default_factory=dict)

    # -- unsupported claims ---------------------------------------------------------
    unsupported_claims: int = 0
    unsupported_by_type: dict[str, int] = field(default_factory=dict)
    facts_without_evidence: int = 0

    # -- evidence coverage ----------------------------------------------------------
    case_evidence_ids: int = 0
    case_evidence_touched: int = 0

    # -- technique agreement --------------------------------------------------------
    techniques_asserted: tuple[str, ...] = ()
    techniques_mapped: tuple[str, ...] = ()
    techniques_asserted_not_mapped: tuple[str, ...] = ()
    techniques_mapped_not_asserted: tuple[str, ...] = ()
    techniques_in_prose: tuple[str, ...] = ()
    """Ids appearing in claim *text* -- a diagnostic beside the score, never in it.

    Kept so the difference between what an investigation retrieved and what it wrote
    down stays visible. On arm A it is where the ``T1110.003`` contrast artefact went."""

    # -- completeness ---------------------------------------------------------------
    specialists_run: int = 0
    specialists_eligible: int = 0
    eligible_never_ran: tuple[str, ...] = ()
    steps: int = 0
    status: str = ""
    tool_calls: int = 0
    distinct_tools: int = 0
    facts: int = 0
    inferences: int = 0
    hypotheses: int = 0
    wall_seconds: float = 0.0
    tokens: int | None = None

    # -- identity hygiene (M18b-2) --------------------------------------------------
    facts_inferred_from_pid: int = 0
    ambiguous_pid_inferences: int = 0

    @property
    def evidence_correctness(self) -> float:
        """Cited event ids that exist, over cited event ids.

        1.0 when nothing was cited: an investigation that cited nothing has not made an
        incorrect citation. The claim *count* alongside it is what says whether that
        1.0 means anything.
        """
        if not self.cited_event_ids:
            return 1.0
        return self.cited_event_ids_existing / self.cited_event_ids

    @property
    def evidence_coverage(self) -> float:
        """Case evidence ids touched by at least one tool call, over all of them."""
        if not self.case_evidence_ids:
            return 0.0
        return self.case_evidence_touched / self.case_evidence_ids

    @property
    def technique_jaccard(self) -> float:
        """Overlap between asserted and mapped techniques.

        1.0 when both sets are empty -- a case the mapper produced no technique for and
        the investigation asserted none is in agreement, and the counts beside it say
        that the agreement is about nothing.
        """
        asserted, mapped = set(self.techniques_asserted), set(self.techniques_mapped)
        union = asserted | mapped
        if not union:
            return 1.0
        return len(asserted & mapped) / len(union)

    @property
    def specialist_completeness(self) -> float:
        """Specialists run over specialists eligible."""
        if not self.specialists_eligible:
            return 1.0
        return self.specialists_run / self.specialists_eligible

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_correctness": round(self.evidence_correctness, 4),
            "cited_event_ids": self.cited_event_ids,
            "cited_event_ids_existing": self.cited_event_ids_existing,
            "rejected_claims": self.rejected_claims,
            "rejection_reasons": dict(self.rejection_reasons),
            "unsupported_claims": self.unsupported_claims,
            "unsupported_by_type": dict(self.unsupported_by_type),
            "facts_without_evidence": self.facts_without_evidence,
            "evidence_coverage": round(self.evidence_coverage, 4),
            "case_evidence_ids": self.case_evidence_ids,
            "case_evidence_touched": self.case_evidence_touched,
            "technique_agreement": {
                "jaccard": round(self.technique_jaccard, 4),
                "asserted": list(self.techniques_asserted),
                "mapped": list(self.techniques_mapped),
                "asserted_not_mapped": list(self.techniques_asserted_not_mapped),
                "mapped_not_asserted": list(self.techniques_mapped_not_asserted),
                "in_prose": list(self.techniques_in_prose),
                "in_prose_not_asserted": sorted(
                    set(self.techniques_in_prose) - set(self.techniques_asserted)
                ),
            },
            "completeness": {
                "specialists_run": self.specialists_run,
                "specialists_eligible": self.specialists_eligible,
                "specialist_completeness": round(self.specialist_completeness, 4),
                "eligible_never_ran": list(self.eligible_never_ran),
                "steps": self.steps,
                "status": self.status,
                "tool_calls": self.tool_calls,
                "distinct_tools": self.distinct_tools,
                "facts": self.facts,
                "inferences": self.inferences,
                "hypotheses": self.hypotheses,
                "wall_seconds": round(self.wall_seconds, 3),
                "tokens": self.tokens,
            },
            "identity_hygiene": {
                "facts_inferred_from_pid": self.facts_inferred_from_pid,
                "ambiguous_pid_inferences": self.ambiguous_pid_inferences,
            },
        }


def scores_from_dict(payload: dict[str, Any]) -> CaseScores:
    """Rebuild scores from what :meth:`CaseScores.to_dict` wrote.

    An artifact that cannot be read back is a printout, not a record: the ``score``
    command re-aggregates from the committed per-case file rather than from a second
    run, so the aggregate can be checked against the rows it claims to summarise.
    """
    completeness = payload.get("completeness", {})
    agreement = payload.get("technique_agreement", {})
    hygiene = payload.get("identity_hygiene", {})
    return CaseScores(
        cited_event_ids=int(payload.get("cited_event_ids", 0)),
        cited_event_ids_existing=int(payload.get("cited_event_ids_existing", 0)),
        rejected_claims=int(payload.get("rejected_claims", 0)),
        rejection_reasons=dict(payload.get("rejection_reasons", {})),
        unsupported_claims=int(payload.get("unsupported_claims", 0)),
        unsupported_by_type=dict(payload.get("unsupported_by_type", {})),
        facts_without_evidence=int(payload.get("facts_without_evidence", 0)),
        case_evidence_ids=int(payload.get("case_evidence_ids", 0)),
        case_evidence_touched=int(payload.get("case_evidence_touched", 0)),
        techniques_asserted=tuple(agreement.get("asserted", ())),
        techniques_mapped=tuple(agreement.get("mapped", ())),
        techniques_asserted_not_mapped=tuple(agreement.get("asserted_not_mapped", ())),
        techniques_mapped_not_asserted=tuple(agreement.get("mapped_not_asserted", ())),
        techniques_in_prose=tuple(agreement.get("in_prose", ())),
        specialists_run=int(completeness.get("specialists_run", 0)),
        specialists_eligible=int(completeness.get("specialists_eligible", 0)),
        eligible_never_ran=tuple(completeness.get("eligible_never_ran", ())),
        steps=int(completeness.get("steps", 0)),
        status=str(completeness.get("status", "")),
        tool_calls=int(completeness.get("tool_calls", 0)),
        distinct_tools=int(completeness.get("distinct_tools", 0)),
        facts=int(completeness.get("facts", 0)),
        inferences=int(completeness.get("inferences", 0)),
        hypotheses=int(completeness.get("hypotheses", 0)),
        wall_seconds=float(completeness.get("wall_seconds", 0.0)),
        tokens=completeness.get("tokens"),
        facts_inferred_from_pid=int(hygiene.get("facts_inferred_from_pid", 0)),
        ambiguous_pid_inferences=int(hygiene.get("ambiguous_pid_inferences", 0)),
    )


def score_case(
    state: InvestigationState,
    case: InvestigationCase,
    verifier: ClaimVerifier,
    *,
    eligible_never_ran: Iterable[str] = (),
    wall_seconds: float = 0.0,
    tokens: int | None = None,
) -> CaseScores:
    """Measure one finished investigation against its case and its telemetry.

    Args:
        state: The finished investigation.
        case: The case it investigated -- the source of the evidence denominator and,
            through its mappings, of the deterministic technique set.
        verifier: The same verifier the run used; the authority on event existence.
        eligible_never_ran: Specialists still eligible when the run stopped. Computed
            by the caller, which holds the orchestrator.
        wall_seconds: Measured by the caller around the investigation only.
        tokens: Tokens the model client reported, or ``None`` when it reports none.

    Raises:
        ByConstructionViolation: if any accepted FACT carries no evidence.
    """
    accepted = list(state.claims)
    rejected = [r.claim for r in state.rejected_claims]

    cited = {e for claim in accepted + rejected for e in claim.evidence_ids}
    existing = _existing(verifier, cited)

    unsupported = [c for c in accepted if not c.evidence_ids]
    unsupported_by_type: dict[str, int] = {}
    for claim in unsupported:
        key = claim.claim_type.value
        unsupported_by_type[key] = unsupported_by_type.get(key, 0) + 1
    facts_without_evidence = unsupported_by_type.get(ClaimType.FACT.value, 0)
    if facts_without_evidence:
        raise ByConstructionViolation(
            f"{case.case_id}: {facts_without_evidence} accepted FACT(s) cite no "
            "evidence. Claim.__post_init__ refuses to construct one, so this means the "
            "claim layer was bypassed -- every other score in this run is suspect."
        )

    case_evidence = set(case.event_ids)
    touched = {e for call in state.tool_calls for e in call.event_ids}

    # Structural: what the investigation retrieved, not what it wrote. See the module
    # docstring for what that costs as well as what it fixes.
    asserted = set(techniques_looked_up(state.tool_calls))
    mapped = {m.technique_id for m in case.mappings}
    in_prose = set(techniques_in(accepted))

    reasons: dict[str, int] = {}
    for rejection in state.rejected_claims:
        reasons[rejection.reason] = reasons.get(rejection.reason, 0) + 1

    return CaseScores(
        cited_event_ids=len(cited),
        cited_event_ids_existing=len(existing),
        rejected_claims=len(state.rejected_claims),
        rejection_reasons=reasons,
        unsupported_claims=len(unsupported),
        unsupported_by_type=unsupported_by_type,
        facts_without_evidence=facts_without_evidence,
        case_evidence_ids=len(case_evidence),
        case_evidence_touched=len(case_evidence & touched),
        techniques_asserted=tuple(sorted(asserted)),
        techniques_mapped=tuple(sorted(mapped)),
        techniques_asserted_not_mapped=tuple(sorted(asserted - mapped)),
        techniques_mapped_not_asserted=tuple(sorted(mapped - asserted)),
        techniques_in_prose=tuple(sorted(in_prose)),
        # Distinct agent *families*, not steps and not facet names. Two corrections,
        # both to the same question -- how many agents did this run actually use?
        #
        # M19-2: an agent that resumes across steps (arm B's generalist) appears in
        # ``agents_run`` once per step, and counting those would report "2 of 1
        # specialists run" -- a completeness ratio above 1.0, which is not a weaker
        # score but a meaningless one.
        #
        # M19-3: arm B is now seven facets of one generalist sharing one walk, one
        # toolbox and one budget, so that its planner has something to choose between.
        # Counting ``generalist:case`` and ``generalist:process`` as two specialists
        # would make the single-agent arm look like a crew of seven, which is the exact
        # distinction this ablation exists to measure. ``agent_family`` collapses them,
        # on both sides of the ratio.
        #
        # Arm A and arm C carry no facet suffix and never run a specialist twice, so
        # every already-published number in those arms is unchanged by either
        # correction. ``eligible_never_ran`` keeps the facet names: which part of the
        # tool surface went unvisited is information, and it is the only place the
        # suffix is load-bearing in a score.
        specialists_run=len({agent_family(a) for a in state.agents_run}),
        specialists_eligible=len({
            agent_family(a) for a in set(state.agents_run) | set(eligible_never_ran)
        }),
        eligible_never_ran=tuple(sorted(set(eligible_never_ran))),
        steps=state.step,
        status=state.status.value,
        tool_calls=len(state.tool_calls),
        distinct_tools=len({call.tool for call in state.tool_calls}),
        facts=len(state.facts),
        inferences=len(state.inferences),
        hypotheses=len(state.hypotheses),
        wall_seconds=wall_seconds,
        tokens=tokens,
        facts_inferred_from_pid=sum(
            1 for c in state.facts if INFERRED_FROM_PID in c.statement
        ),
        ambiguous_pid_inferences=sum(
            1 for c in state.inferences if _AMBIGUOUS_PID_MARKER in c.statement
        ),
    )


def capture_label_scores(labels: dict[str, Any], scores: CaseScores) -> dict[str, Any]:
    """The label-based column for a corpus whose captures name their technique.

    Only ``attack_data_aws`` has this: the technique is in the capture file name, and it
    is the only cloud ground truth this project has. Asked twice, because the two
    questions differ -- did the *deterministic mapper* assert the labelled technique, and
    did the *investigation* end up naming it. An arm that drops a technique the mapper
    handed it is a different failure from a detection layer that never mapped it.
    Returns ``{}`` where there is no label, so an unlabelled case carries no column
    rather than a false zero.
    """
    technique = str(labels.get("labelled_technique") or "")
    if not technique:
        return {}
    return {
        "labelled_technique": technique,
        "labelled_technique_mapped": technique in scores.techniques_mapped,
        "labelled_technique_asserted": technique in scores.techniques_asserted,
    }


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def aggregate(results: Iterable[Any]) -> dict[str, Any]:
    """Means and totals per arm, with a per-corpus breakdown.

    ``results`` are :class:`~ath.evaluation.ablation.arms.CaseResult` objects. A result
    whose model degraded mid-run is aggregated under its degraded label rather than
    under the arm it was launched as -- see ``CaseResult.labelled_arm``.
    """
    rows = list(results)
    by_arm: dict[str, list[Any]] = {}
    for row in rows:
        by_arm.setdefault(row.labelled_arm, []).append(row)

    summary: dict[str, Any] = {"cases": len(rows), "arms": {}}
    for arm, arm_rows in sorted(by_arm.items()):
        by_corpus: dict[str, list[Any]] = {}
        for row in arm_rows:
            by_corpus.setdefault(row.corpus, []).append(row)
        summary["arms"][arm] = {
            "overall": _summarise(arm_rows),
            "by_corpus": {
                corpus: _summarise(corpus_rows)
                for corpus, corpus_rows in sorted(by_corpus.items())
            },
        }
    return summary


def _summarise(rows: list[Any]) -> dict[str, Any]:
    scores = [row.scores for row in rows]
    return {
        "cases": len(rows),
        "mean": {
            "evidence_correctness": round(
                _mean([s.evidence_correctness for s in scores]), 4
            ),
            "evidence_coverage": round(_mean([s.evidence_coverage for s in scores]), 4),
            "technique_jaccard": round(_mean([s.technique_jaccard for s in scores]), 4),
            "specialist_completeness": round(
                _mean([s.specialist_completeness for s in scores]), 4
            ),
            "unsupported_claims": round(_mean([s.unsupported_claims for s in scores]), 4),
            "facts": round(_mean([s.facts for s in scores]), 4),
            "inferences": round(_mean([s.inferences for s in scores]), 4),
            "hypotheses": round(_mean([s.hypotheses for s in scores]), 4),
            "tool_calls": round(_mean([s.tool_calls for s in scores]), 4),
            "steps": round(_mean([s.steps for s in scores]), 4),
            "wall_seconds": round(_mean([s.wall_seconds for s in scores]), 4),
        },
        "total": {
            "facts": sum(s.facts for s in scores),
            "inferences": sum(s.inferences for s in scores),
            "hypotheses": sum(s.hypotheses for s in scores),
            "unsupported_claims": sum(s.unsupported_claims for s in scores),
            "rejected_claims": sum(s.rejected_claims for s in scores),
            "facts_without_evidence": sum(s.facts_without_evidence for s in scores),
            "cited_event_ids": sum(s.cited_event_ids for s in scores),
            "cited_event_ids_existing": sum(s.cited_event_ids_existing for s in scores),
            "case_evidence_ids": sum(s.case_evidence_ids for s in scores),
            "case_evidence_touched": sum(s.case_evidence_touched for s in scores),
            "tool_calls": sum(s.tool_calls for s in scores),
            "steps": sum(s.steps for s in scores),
            "wall_seconds": round(sum(s.wall_seconds for s in scores), 3),
            "facts_inferred_from_pid": sum(s.facts_inferred_from_pid for s in scores),
            "ambiguous_pid_inferences": sum(s.ambiguous_pid_inferences for s in scores),
            "tokens": (
                None if all(s.tokens is None for s in scores)
                else sum(s.tokens or 0 for s in scores)
            ),
        },
        "statuses": _counts([s.status for s in scores]),
        "degraded_runs": sum(1 for row in rows if row.llm_degraded),
    }


def _counts(values: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


# ======================================================================================
# M19b: cross-domain necessity, planner activation, cost of context
# ======================================================================================
#
# Why these live here
# --------------------
# M19 asked "is the crew better than one LLM" and could not answer it: on 21 of 22 cases
# exactly one domain specialist was eligible at every step, so arm C's planner was never
# asked anything. M19b asks the same question on cases where two domains genuinely
# matter, and these are the measurements that question needs. Every one of them is
# computed from the artifacts -- claims, tool calls, the planner's own decision counts --
# and none is scored by a model or by reading prose for quality, which is the rule the
# rest of this module already runs under.
#
# Each function takes a finished investigation as either the live
# :class:`~ath.agent.state.InvestigationState`, the ``state`` payload it serialises to,
# or a whole results row containing one. That is not politeness: the same metric has to
# be computable inside ``run_arm`` (where the live state is at hand) and afterwards from
# a committed ``arm_*.json`` (where only the payload survives), and two implementations
# of one metric are two answers to one question.
#
# Still no thresholds and still no constants of degree. The one input that could carry a
# judgement -- what counts as mattering on a case -- is a *rubric*, written by the
# architect before any run and handed in, never chosen here.


class UnknownRubric(ValueError):
    """A pre-registered link or rubric item does not describe this telemetry.

    Raised rather than scored. A link whose two ids live in the same domain, or whose id
    exists in no canonical table, is a defect in the pre-registration -- and a
    pre-registration that quietly scored 0 for a case it was mis-written for would look
    exactly like a case every arm failed.
    """


RECOVERING_CLAIM_TYPES: tuple[str, ...] = (
    ClaimType.FACT.value, ClaimType.INFERENCE.value,
)
"""Claim types that can recover a link or carry a cross-domain contribution.

A HYPOTHESIS is excluded, by the plan's own definition: a link is recovered when an
accepted, *verified* claim cites both sides, and a HYPOTHESIS is the one claim type this
project allows to stand without being supported by what it cites. Counting one would let
"these two things may be connected" score as having connected them.
"""


def domain_tables() -> dict[str, frozenset[str]]:
    """Which canonical tables each domain specialist's telemetry lives in.

    Derived, not typed out: the domain ids come from
    :data:`~ath.capabilities.registry.CAPABILITY_REGISTRY` -- the same table the
    orchestrator assembles a crew from -- and each one's tables come from the evidence
    columns :mod:`ath.environment.channels` already records for the channels that
    specialist requires. So "which domain does this evidence belong to" has one answer in
    this repository, and a specialist added to the registry appears here without an edit.

    The ATT&CK mapper is absent because it requires no channel: it interprets mappings
    the deterministic layer produced and reads no telemetry of its own. That is exactly
    the plan's rule that the mapper does not count as a domain.
    """
    from ath.capabilities.registry import CAPABILITY_REGISTRY  # noqa: PLC0415
    from ath.environment.channels import CHANNEL_SPEC_BY_NAME  # noqa: PLC0415

    tables: dict[str, frozenset[str]] = {}
    for spec in CAPABILITY_REGISTRY:
        names: set[str] = set()
        for channel in set(spec.requires_all) | set(spec.requires_any):
            for table, _column in CHANNEL_SPEC_BY_NAME[channel].evidence_columns:
                names.add(table)
        if names:
            tables[spec.id] = frozenset(names)
    return tables


def domain_of_telemetry(telemetry: Any) -> Any:
    """Build ``domain_of``: an evidence id to the domain whose specialist reads it.

    The row already knows its telemetry, so this is the mapping the ablation harness
    hands to every cross-domain metric. An id in no canonical table gets ``None`` -- the
    metrics skip it, and :func:`cross_domain_evidence_recovery` raises when a
    *pre-registered* link names one, because that is a broken pre-registration rather
    than a failed investigation.
    """
    lookup: dict[str, str] = {}
    for domain, tables in sorted(domain_tables().items()):
        for table in sorted(tables):
            frame = telemetry.table(table)
            if frame is None or frame.empty:
                continue
            for event_id in frame["event_id"]:
                lookup[str(event_id)] = domain

    def domain_of(event_id: str) -> str | None:
        return lookup.get(str(event_id))

    return domain_of


def state_payload(state: Any) -> dict[str, Any]:
    """The serialised investigation, given a live state, a payload, or a whole row."""
    if hasattr(state, "to_dict"):
        return state.to_dict()
    if isinstance(state, dict):
        inner = state.get("state")
        return inner if isinstance(inner, dict) else state
    raise TypeError(
        "expected an InvestigationState, a serialised state or a results row, got "
        f"{type(state).__name__}"
    )


def _accepted(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [c for c in payload.get("claims", []) if isinstance(c, dict)]


def _cited(claim: dict[str, Any]) -> frozenset[str]:
    return frozenset(str(e) for e in (claim.get("evidence_ids") or []))


def _signature(kind: str, event_ids: Iterable[str], domains: Sequence[str]) -> str:
    """A contribution's identity: what it cites, and which domains that spans.

    A hash rather than the ids themselves, for a reason that is not brevity: one
    ``host_network_activity`` result on the COMISET corpus is 589,476 ids, and a metric
    whose output embedded them would have rebuilt the 36 MB artifact this milestone spent
    a whole task characterising. The id *count* travels beside the signature, so a reader
    can still see how large a contribution was.

    Prose is deliberately not in it. Two arms that state the same cross-domain
    relationship in different words have both produced it, and a uniqueness metric that
    compared sentences would report both as unique -- which is the precise way this
    metric could flatter a model arm.
    """
    return hashlib.sha256(
        json.dumps(
            {"kind": kind, "ids": sorted(event_ids), "domains": list(domains)},
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _domains_of(event_ids: Iterable[str], domain_of: Any) -> list[str]:
    return sorted({d for d in (domain_of(str(e)) for e in event_ids) if d})


def _link(pair: Sequence[str], domain_of: Any) -> dict[str, Any]:
    """One validated pre-registered link. Raises on anything that cannot be one."""
    ids = [str(e) for e in pair]
    if len(ids) != 2 or ids[0] == ids[1]:
        raise UnknownRubric(
            f"a cross-domain link is a pair of two different evidence ids, got {ids!r}"
        )
    domains = [domain_of(ids[0]), domain_of(ids[1])]
    for event_id, domain in zip(ids, domains):
        if domain is None:
            raise UnknownRubric(
                f"pre-registered link {ids!r} names {event_id!r}, which is in no "
                "canonical telemetry table: that link cannot be recovered or missed, "
                "only mis-registered"
            )
    if domains[0] == domains[1]:
        raise UnknownRubric(
            f"pre-registered link {ids!r} is not cross-domain: both ids are "
            f"{domains[0]} evidence"
        )
    ordered = sorted(ids)
    return {
        "evidence_ids": ordered,
        "domains": sorted(domains),
        "signature": _signature("link", ordered, sorted(domains)),
    }


def cross_domain_evidence_recovery(
    state: Any, links: Iterable[Sequence[str]], domain_of: Any
) -> dict[str, Any]:
    """CDER: how many pre-registered cross-domain links this investigation recovered.

    A *link* is a pair of evidence ids from two different domains that the ground truth
    says belong to one stage transition -- "this logon and this process start are the
    same hop". It is **recovered** when one accepted FACT or INFERENCE cites both sides:
    one claim, not two claims that each mention one end, because a link is the assertion
    that the two are connected and two separate claims assert no such thing.

    Arm A is scored on exactly this scale, deliberately. A deterministic crew that
    already recovers every link leaves the model arms nothing to add, and that would be
    an answer to the milestone's question rather than a weakness in the metric.

    Args:
        state: A finished investigation -- live state, payload, or results row.
        links: The pre-registered pairs. Order within a pair is irrelevant.
        domain_of: ``event_id -> domain``; see :func:`domain_of_telemetry`.

    Returns:
        ``defined``, ``recovered``, ``recovery`` (the ratio, ``None`` when no link was
        registered -- a case with no links is not a case this metric failed), and the
        recovered and missed links themselves.

    Raises:
        UnknownRubric: for a link that is not a pair of two different ids from two
            different domains, for one naming an id no canonical table carries, and for
            a link registered twice.
    """
    payload = state_payload(state)
    registered: list[dict[str, Any]] = []
    seen: set[str] = set()
    for pair in links:
        link = _link(pair, domain_of)
        if link["signature"] in seen:
            raise UnknownRubric(
                f"link {link['evidence_ids']} is registered twice; a repeated link "
                "counts twice in the denominator and once in the numerator"
            )
        seen.add(link["signature"])
        registered.append(link)

    cited = [
        _cited(claim) for claim in _accepted(payload)
        if claim.get("type") in RECOVERING_CLAIM_TYPES
    ]
    recovered = [
        link for link in registered
        if any(set(link["evidence_ids"]) <= ids for ids in cited)
    ]
    recovered_signatures = {link["signature"] for link in recovered}
    return {
        "defined": len(registered),
        "recovered": len(recovered),
        "recovery": (len(recovered) / len(registered)) if registered else None,
        "recovered_links": recovered,
        "missed_links": [
            link for link in registered if link["signature"] not in recovered_signatures
        ],
    }


def _cross_domain_entries(
    payload: dict[str, Any], domain_of: Any
) -> list[tuple[frozenset[str], dict[str, Any]]]:
    """Every accepted claim spanning two or more domains, with what it cited."""
    entries: list[tuple[frozenset[str], dict[str, Any]]] = []
    for claim in _accepted(payload):
        ids = _cited(claim)
        domains = _domains_of(ids, domain_of)
        if len(domains) < 2:
            continue
        entries.append((ids, {
            "type": str(claim.get("type", "")),
            "agent": str(claim.get("agent", "")),
            "source": str(claim.get("source", "")),
            "statement": str(claim.get("statement", "")),
            "domains": domains,
            "domain_pairs": ["|".join(pair) for pair in combinations(domains, 2)],
            "evidence_id_count": len(ids),
            "signature": _signature("claim", ids, domains),
        }))
    return entries


def cross_domain_claims(state: Any, domain_of: Any) -> dict[str, Any]:
    """Accepted claims citing evidence from two or more domains, and which pairs.

    The other half of CDER: a link says whether a *pre-registered* connection was made,
    and this says what cross-domain connections the investigation made at all --
    including ones nobody thought to register.

    Every accepted claim is listed, HYPOTHESIS included, with its type beside it: the
    count of unverified cross-domain guesses is information, and folding it into the same
    number as the verified ones would hide it. What consumes only the verified ones is
    :func:`unique_cross_domain_contribution`, through :data:`RECOVERING_CLAIM_TYPES`.

    A claim's ``evidence_ids`` are **not** in the result -- only their count and the
    signature computed from them. See :func:`_signature`.
    """
    entries = [
        entry for _ids, entry
        in _cross_domain_entries(state_payload(state), domain_of)
    ]
    by_type: dict[str, int] = {}
    pairs: dict[str, int] = {}
    for entry in entries:
        by_type[entry["type"]] = by_type.get(entry["type"], 0) + 1
        for pair in entry["domain_pairs"]:
            pairs[pair] = pairs.get(pair, 0) + 1
    return {
        "count": len(entries),
        "verified_count": sum(
            1 for e in entries if e["type"] in RECOVERING_CLAIM_TYPES
        ),
        "by_type": dict(sorted(by_type.items())),
        "domain_pairs": dict(sorted(pairs.items())),
        "claims": entries,
    }


RUBRIC_KINDS: tuple[str, ...] = ("stage", "verdict", "next_action")
"""What a pre-registered "matters" item can be: a stage of the chain, the verdict, or
the analyst's next action. The plan's three, and no fourth."""


@dataclass(frozen=True)
class RubricItem:
    """One thing a case's labels declare cross-domain synthesis could change.

    Attributes:
        name: The stage's name, the string ``"verdict"``, or the next action as the
            case's ``labels.json`` words it.
        kind: One of :data:`RUBRIC_KINDS`.
        evidence_ids: The evidence this item rests on. A contribution *maps to* this
            item when it cites at least two of these ids from two different domains --
            which is what "cross-domain synthesis could change this" means once it is
            made checkable: not that a claim mentioned the stage, but that it joined two
            domains' evidence for it.
    """

    name: str
    kind: str
    evidence_ids: frozenset = frozenset()

    def __post_init__(self) -> None:
        if not self.name:
            raise UnknownRubric("a rubric item must be named; an unnamed item maps nothing")
        if self.kind not in RUBRIC_KINDS:
            raise UnknownRubric(
                f"rubric item {self.name!r} has kind {self.kind!r}; the plan allows "
                f"{RUBRIC_KINDS}"
            )


@dataclass(frozen=True)
class CaseRubric:
    """What one benchmark case pre-registers, and how to read its evidence ids.

    Written before any run, by the architect, and never adjusted after seeing an arm's
    behaviour -- rule 3 of the plan. This type is the shape the metrics consume; the
    pre-registration writes the file.

    Attributes:
        case_id: The case this rubric belongs to.
        links: Pre-registered cross-domain links, as pairs of evidence ids.
        items: The "matters" items -- stages, the verdict, next actions.
        domain_of: ``event_id -> domain``. Carried on the rubric rather than passed
            beside it, so that every metric reading a rubric reads domains the same way.
    """

    case_id: str
    links: tuple = ()
    items: tuple = ()
    domain_of: Any = None

    @classmethod
    def from_dict(cls, payload: dict[str, Any], domain_of: Any) -> "CaseRubric":
        """Read a rubric from the case's ``labels.json`` payload."""
        return cls(
            case_id=str(payload.get("case_id", "")),
            links=tuple(
                (str(pair[0]), str(pair[1])) for pair in payload.get("links", ())
            ),
            items=tuple(
                RubricItem(
                    name=str(item.get("name", "")),
                    kind=str(item.get("kind", "")),
                    evidence_ids=frozenset(
                        str(e) for e in (item.get("evidence_ids") or ())
                    ),
                )
                for item in payload.get("matters", ())
            ),
            domain_of=domain_of,
        )

    def matters_for(self, event_ids: Iterable[str]) -> list[str]:
        """Which "matters" items a contribution citing ``event_ids`` maps to."""
        cited = {str(e) for e in event_ids}
        names: list[str] = []
        for item in self.items:
            shared = cited & item.evidence_ids
            if len(shared) >= 2 and len(_domains_of(shared, self.domain_of)) >= 2:
                names.append(item.name)
        return names


def unique_cross_domain_contribution(
    rows_by_arm: dict[str, Any], rubric: CaseRubric
) -> dict[str, Any]:
    """UCC: what each arm contributed on this case that no other arm did.

    For one case and every arm that ran it: the cross-domain links and cross-domain
    claims that arm produced, that are verified (FACT or INFERENCE), that **no other arm
    produced**, and that map to a pre-registered "matters" item. Symmetric by
    construction -- the same computation runs for A, B and C, because the milestone's
    question is comparative and a metric defined only for the crew would have answered it
    before it was asked.

    Uniqueness is decided by :func:`_signature`: the set of cited ids and the domain
    pair, never the wording. Two arms that produce the same link in different sentences
    have both produced it, and it is unique to neither.

    Args:
        rows_by_arm: ``arm name -> finished investigation`` (live state, payload or
            results row) for **one** case.
        rubric: That case's pre-registration.

    Returns:
        Per arm: how many contributions it made, how many were unique, how many of those
        map to a "matters" item, and the entries themselves. ``shared`` counts the
        contributions another arm made too -- reported, because "both arms found it" is
        the answer that would retire the crew, and it must be as visible as the unique
        column.
    """
    contributions: dict[str, list[dict[str, Any]]] = {}
    for arm, row in rows_by_arm.items():
        payload = state_payload(row)
        recovery = cross_domain_evidence_recovery(
            payload, rubric.links, rubric.domain_of,
        )
        entries: list[dict[str, Any]] = []
        for link in recovery["recovered_links"]:
            entries.append({
                "kind": "link",
                "signature": link["signature"],
                "domains": link["domains"],
                "evidence_ids": link["evidence_ids"],
                "matters": rubric.matters_for(link["evidence_ids"]),
            })
        for ids, entry in _cross_domain_entries(payload, rubric.domain_of):
            if entry["type"] not in RECOVERING_CLAIM_TYPES:
                continue
            entries.append({
                "kind": "claim",
                "signature": entry["signature"],
                "domains": entry["domains"],
                "type": entry["type"],
                "agent": entry["agent"],
                "statement": entry["statement"],
                "evidence_id_count": entry["evidence_id_count"],
                "matters": rubric.matters_for(ids),
            })
        contributions[arm] = entries

    produced_by: dict[str, set] = {}
    for arm, entries in contributions.items():
        for entry in entries:
            produced_by.setdefault(entry["signature"], set()).add(arm)

    result: dict[str, Any] = {}
    for arm, entries in contributions.items():
        unique = [e for e in entries if produced_by[e["signature"]] == {arm}]
        with_matters = [e for e in unique if e["matters"]]
        result[arm] = {
            "case_id": rubric.case_id,
            "contributions": len(entries),
            "links_recovered": sum(1 for e in entries if e["kind"] == "link"),
            "cross_domain_claims": sum(1 for e in entries if e["kind"] == "claim"),
            "shared": len(entries) - len(unique),
            "unique": len(unique),
            "unique_links": sum(1 for e in unique if e["kind"] == "link"),
            "unique_claims": sum(1 for e in unique if e["kind"] == "claim"),
            "unique_and_matters": len(with_matters),
            "entries": with_matters,
            "unique_without_matters": [e for e in unique if not e["matters"]],
        }
    return result


def planner_activation(state: Any) -> dict[str, Any]:
    """Whether this run's planner was ever asked anything, and what it picked.

    The measurement M19 could not make a claim from: arm C's planner was consulted on one
    case of 22, because on every other case exactly one specialist was eligible at every
    step. ``multi_candidate_steps`` is the denominator of that question -- steps that were
    a real choice -- and it counts a step where the planner was *not consulted* (arm A, or
    a model arm with the planner off) as a choice that existed, because the choice
    existing is a property of the case rather than of the arm. ``chosen_by_model`` is the
    numerator that separates a model arm which steered from one that ran the deterministic
    order under a model arm's label.

    ``domain_specialists_selected`` excludes the ATT&CK mapper, per the plan, and is empty
    for arm B: its seven facets are one agent. ``handoffs`` -- changes of agent *family*
    between consecutive steps -- is 0 for arm B for the same reason. That is the
    distinction the ablation exists to measure, reported rather than smoothed away.
    """
    payload = state_payload(state)
    planner = ((payload.get("llm") or {}).get("planner") or {})
    steps = int(payload.get("steps", 0))
    multi = int(planner.get("multi_candidate_steps", 0))
    selected = [str(a) for a in payload.get("agents_run", [])]
    families = [agent_family(a) for a in selected]
    domains = set(domain_tables())
    return {
        "steps": steps,
        "multi_candidate_steps": multi,
        "multi_candidate_share": (multi / steps) if steps else None,
        "chosen_by_model": int(planner.get("chosen_by_model", 0)),
        "decisions": dict(sorted((planner.get("decisions") or {}).items())),
        "specialists_selected": selected,
        "domain_specialists_selected": [
            a for a in selected if agent_family(a) in domains
        ],
        "handoffs": [
            f"{before}->{after}"
            for before, after in zip(families, families[1:]) if before != after
        ],
    }


def duplicate_tool_calls(state: Any) -> dict[str, Any]:
    """Identical ``(tool, arguments)`` calls within one case.

    Identity is the tool name and its arguments with keys sorted, so two calls differing
    only in the order the caller happened to pass them are the same call. This is a cost
    measurement, not a correctness one: the toolbox is read-only and deterministic, so
    asking twice buys nothing and is charged twice -- against the tool-call budget, and
    again in the prompt that carries the result.

    Refused calls are counted like any other: an investigation that asked the same
    question twice asked it twice, whether or not the budget answered.
    """
    payload = state_payload(state)
    calls = [
        call for result in payload.get("results", [])
        for call in result.get("tool_calls", [])
    ]
    counts: dict[str, int] = {}
    shapes: dict[str, dict[str, Any]] = {}
    for call in calls:
        key = json.dumps(
            [call.get("tool", ""), call.get("arguments") or {}],
            sort_keys=True, default=str,
        )
        counts[key] = counts.get(key, 0) + 1
        shapes.setdefault(key, {
            "tool": call.get("tool", ""), "arguments": call.get("arguments") or {},
        })
    repeated = [
        {**shapes[key], "calls": count} for key, count in counts.items() if count > 1
    ]
    repeated.sort(key=lambda entry: (-entry["calls"], entry["tool"]))
    return {
        "tool_calls": len(calls),
        "distinct_calls": len(counts),
        "duplicate_calls": sum(count - 1 for count in counts.values() if count > 1),
        "refused_calls": sum(1 for call in calls if call.get("refused")),
        "repeated": repeated,
    }


def context_size(state: Any) -> dict[str, Any]:
    """The largest and the total model request this case sent, in bytes and tokens.

    Read from the per-call records the ablation harness collects through
    :attr:`~ath.agent.llm.AnthropicLLM.request_observer` -- the measurement-only hook
    M19b-T2 added, handed :func:`~ath.agent.llm.request_measurement` over the body
    :func:`~ath.agent.llm.build_request_body` is about to send. So these are the bytes
    that went on the wire rather than a reconstruction of them: T2 measured arm B's
    synthesis request on one case at 36,827,172 bytes against a 33,554,432-byte limit,
    and that was answerable only because the number came from the builder instead of from
    a second builder in a script.

    Arm A records zeros: it sends no request at all. Input tokens are ``None`` rather
    than 0 when no call reported any -- "the model spent nothing" and "nobody told us
    what it spent" are different facts, and only one of them belongs in a cost column.
    """
    payload = state_payload(state)
    requests = ((payload.get("llm") or {}).get("requests") or [])
    sizes = [int(r.get("request_bytes", 0)) for r in requests]
    tokens = [
        int(r["input_tokens"]) for r in requests
        if isinstance(r.get("input_tokens"), int) and not isinstance(r["input_tokens"], bool)
    ]
    return {
        "model_calls": len(requests),
        "largest_request_bytes": max(sizes) if sizes else 0,
        "total_request_bytes": sum(sizes),
        "calls_with_input_tokens": len(tokens),
        "largest_input_tokens": max(tokens) if tokens else None,
        "total_input_tokens": sum(tokens) if tokens else None,
    }


# --------------------------------------------------------------------------------------
# Equal footing
# --------------------------------------------------------------------------------------

FOOTING_SHARED: tuple[str, ...] = ("tool_surface_sha256", "telemetry_hash")
"""What every arm on one case must match on, whatever else differs between them.

The tool surface, because the sentence this experiment rests on is that arm C received no
evidence arm B could not have requested through the same tools; and the telemetry hash,
because two arms scored against different corpora are not a comparison of arms.
"""

FOOTING_MODEL_ARMS: tuple[str, ...] = ("tool_call_cap", "max_steps")
"""Budgets, compared between the arms that run a model.

Arm A is uncapped and always was -- ``arm_a()`` passes no ``tool_call_cap`` -- so
comparing budgets across all three would refuse every run of the published design. That
difference is pre-registered, and it is named here rather than silently skipped: the
deterministic baseline is allowed to look at everything, which if anything works against
the model arms.
"""


def footing_differences(footings_by_arm: dict[str, dict[str, Any]]) -> list[str]:
    """Ways the arms on one case were not on equal footing. Empty when they were.

    Descriptions rather than a boolean, so a refused row can name what moved.
    """
    differences: list[str] = []
    arms = sorted(footings_by_arm)
    for field_name in FOOTING_SHARED:
        values = {arm: footings_by_arm[arm].get(field_name) for arm in arms}
        if len({repr(value) for value in values.values()}) > 1:
            differences.append(f"{field_name}: {values}")
    model_arms = [arm for arm in arms if footings_by_arm[arm].get("requires_model")]
    for field_name in FOOTING_MODEL_ARMS:
        values = {arm: footings_by_arm[arm].get(field_name) for arm in model_arms}
        if len({repr(value) for value in values.values()}) > 1:
            differences.append(f"{field_name} (model arms): {values}")
    return differences
