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
:func:`label_scores_from_outcome`.

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

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from ath.agent.claims import Claim, ClaimType, ClaimVerifier
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
        # Distinct specialists, not steps. An agent that resumes across steps (arm B's
        # generalist) appears in ``agents_run`` once per step, and counting those would
        # report "2 of 1 specialists run" -- a completeness ratio above 1.0, which is not
        # a weaker score but a meaningless one. Arm A never runs a specialist twice, so
        # every already-published arm A number is unchanged by this.
        specialists_run=len(set(state.agents_run)),
        specialists_eligible=len(set(state.agents_run) | set(eligible_never_ran)),
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


def label_scores_from_outcome(outcome: Any) -> dict[str, Any]:
    """The label-based columns, lifted from an :class:`IncidentOutcome` unchanged.

    Reused rather than re-implemented: event recall and the trust gate already exist in
    :mod:`ath.evaluation.incidents`, have been the benchmark's definition of those words
    since M14, and a second definition here would make the ablation's synthetic rows
    incomparable with every benchmark row this project has published.
    """
    return {
        "incident_id": outcome.incident.incident_id,
        "configuration": outcome.configuration,
        "llm_degraded": bool(outcome.llm_degraded),
        "passed": bool(outcome.passed),
        "event_recall": round(outcome.event_recall, 4),
        "trustworthy": bool(outcome.trustworthy),
        "hallucinated_citations": outcome.hallucinated_citations,
        "calibration_warnings": outcome.calibration_warnings,
        "overclaimed_as_fact": list(outcome.overclaimed_as_fact),
        "techniques_missing": list(outcome.techniques_missing),
        "conclusions_missed": list(outcome.conclusions_missed),
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
