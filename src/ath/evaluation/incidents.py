"""End-to-end evaluation against whole incidents, rather than rule by rule.

Why per-rule precision/recall is not enough
-------------------------------------------
:mod:`ath.evaluation.evaluator` answers "does each rule fire when it should". Every rule
in this project can score 1.00 there while the system as a whole is still useless to an
analyst, because rule-level scoring cannot see:

* **Fragmentation.** Ten correct findings split across seven unrelated cases is ten
  investigations, not one incident.
* **Contamination.** One case containing the intrusion *and* the administrator's
  legitimate work is worse than two clean cases -- it makes the analyst distrust the
  grouping.
* **Noise.** Cases containing nothing malicious cost triage time whether or not any
  individual rule was "precise".
* **Calibration.** A confident sentence about something the telemetry never showed is a
  correctness failure that no detection metric registers.
* **Cost.** An answer that takes a thousand tool calls is a different product from one
  that takes forty.

So this module runs the **whole pipeline** -- hunt, correlate, investigate -- over a
labelled incident and measures what an analyst would actually receive.

Usefulness is measured against a baseline, not in the abstract
---------------------------------------------------------------
"11 findings, 2 cases" means nothing on its own. The comparison that matters is against
what the analyst would face *without* the layer being justified: correlation earns its
place only if grouping reduces triage load without losing or contaminating the incident,
so :attr:`IncidentOutcome.triage_reduction` reports exactly that, alongside the recall
and purity figures that say whether the reduction was bought honestly.

A quiet day is a test case
---------------------------
The benign incident carries no malicious events and its success condition is *zero
detections*. Evaluation suites that only measure attack scenarios systematically reward
trigger-happy detection, because the cost of a false alarm never appears in the numbers.

Determinism, and the one deliberate exception
----------------------------------------------
By default this runs with no language model. Every figure is then reproducible from the
telemetry, so a regression shows up as a changed number rather than as a changed mood.

Milestone 14 adds a second *arm*: the identical pipeline -- same rules, correlation,
specialists, tools and verifier, same cases -- with a real model in place of
:class:`~ath.agent.llm.NullLLM`. The model plans and synthesises; it still cannot author
a FACT or create a finding. Nothing about the measurement changes between arms except
:attr:`IncidentOutcome.configuration`, which names which arm produced the row, and the
LLM arm's figures are recorded rather than reproduced, because they cannot be. The
criteria under which the LLM arm counts as an improvement are fixed in
``docs/m14-data-acquisition-plan.md`` section 5.1, before any run: more claims, longer
output and more tool calls are reported, never credited.

One definition of each label-based figure
------------------------------------------
:func:`score_labels` computes everything the answer key can decide -- event recall, the
techniques and conclusions the run was supposed to reach, the trust gate and the pass
condition -- from *one investigation*: the findings, the triage assessments, and the
state that investigation produced. :func:`run_incident` calls it, and so does the M19
ablation, on the state of the row it is scoring.

That second caller is why the function exists. The ablation used to obtain its synthetic
rows' label scores by calling :func:`run_incident` a second time, which ran a *different*
investigation -- its own toolbox, uncapped, with the environment-assembled crew -- and
attached the result to a row produced by something else. For arm B that was arm C's
architecture wearing arm B's label, and the tokens it spent were counted nowhere. A
row's label-based scores must describe the same investigation as the row's other scores:
same state, same budgets, same architecture.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from ath.agent.claims import ClaimType, ClaimVerifier
from ath.agent.llm import LLMClient, NullLLM
from ath.agent.orchestrator import InvestigationConfig, InvestigationOrchestrator
from ath.agent.state import InvestigationState
from ath.agent.tools import ToolBox
from ath.correlation import correlate
from ath.environment import build_environment_model
from ath.hunting import HuntConfig, run_hunt
from ath.hunting.finding import Finding
from ath.logging_setup import get_logger
from ath.mitre.mapper import map_findings
from ath.reporting.language import audit_calibration
from ath.telemetry.loader import Telemetry
from ath.triage import Disposition, assess_findings, set_aside_ids

logger = get_logger(__name__)


def event_recall_of(surfaced: int, total: int) -> float:
    """Fraction of an incident's events that any finding surfaced.

    A benign scenario has no malicious events, so the fraction is vacuously 1.0 rather
    than a division by zero -- "found all nothing of it" is the correct reading, and the
    benign scenario is graded on ``findings_after_triage`` instead.
    """
    if not total:
        return 1.0
    return surfaced / total


def is_trustworthy(
    *,
    hallucinated_citations: int,
    overclaimed_as_fact: Sequence[str],
    calibration_warnings: int,
    malicious_findings_called_benign: int,
) -> bool:
    """No fabricated citation, no unevidenced fact, no overclaim, no dismissed attack.

    A hard gate rather than a score: these are correctness failures, and one is enough
    to make the output unusable regardless of how good the metrics look.
    """
    return (
        hallucinated_citations == 0
        and not overclaimed_as_fact
        and calibration_warnings == 0
        and malicious_findings_called_benign == 0
    )


def incident_passed(
    *,
    is_benign: bool,
    detected: bool,
    findings_after_triage: int,
    techniques_missing: Sequence[str],
    conclusions_missed: Sequence[str],
    trustworthy: bool,
) -> bool:
    """Whether one incident met its success condition.

    The benign condition was originally ``cases == 0`` and is now
    ``findings_after_triage == 0``. That is a deliberate change of bar, not a relaxation
    of one, and it is worth stating plainly because moving a goalpost after building the
    thing that clears it deserves scrutiny.

    The question a quiet-day scenario asks is "was the analyst made to investigate
    anything". A case every one of whose findings carries an explicit, cited benign
    verdict does not cost an investigation -- but a *single* unexplained finding does,
    whether or not it correlated into anything. So the condition is stricter in the place
    that matters: it requires the triage layer to account for every false positive
    individually, where the old one could be satisfied merely by the correlator declining
    to group them. ``noise_cases`` stays reported either way, so the case that is still
    formed remains visible rather than hidden by the change.
    """
    if is_benign:
        return findings_after_triage == 0 and trustworthy
    return (
        detected
        and not techniques_missing
        and not conclusions_missed
        and trustworthy
    )


@dataclass(frozen=True)
class Incident:
    """A labelled scenario with a known answer key.

    Attributes:
        incident_id: Stable identifier.
        name: Short human-readable name.
        description: What the scenario represents.
        telemetry: The telemetry to run the pipeline over.
        malicious_event_ids: Every event that is part of the incident. Empty for a
            benign scenario, where the correct outcome is to find nothing.
        expected_techniques: ATT&CK techniques the system should assert.
        must_conclude: Substrings that must appear somewhere in the investigation's
            claims. These encode "did it actually work out what happened", which no
            count of findings can express.
        never_as_fact: Substrings that must never appear in a claim typed ``FACT``.
            The exfiltration claim is the canonical case: the telemetry shows an
            archive being made and, separately, an outbound connection -- never the
            bytes leaving. Asserting it as fact is the overclaim this project exists
            to prevent, and it must be measured, not merely hoped for.
    """

    incident_id: str
    name: str
    description: str
    telemetry: Telemetry
    malicious_event_ids: frozenset[str] = frozenset()
    expected_techniques: frozenset[str] = frozenset()
    must_conclude: tuple[str, ...] = ()
    never_as_fact: tuple[str, ...] = ()

    @property
    def is_benign(self) -> bool:
        """A scenario whose correct outcome is silence."""
        return not self.malicious_event_ids


@dataclass
class IncidentOutcome:
    """What the pipeline actually produced for one incident."""

    incident: Incident

    configuration: str = "deterministic"
    """Which arm produced this row: ``deterministic`` (NullLLM) or the model's name."""
    llm_degraded: bool = False
    """True when an LLM arm fell back to deterministic planning mid-run (key, quota,
    outage). Reported so an LLM row that silently ran deterministic cannot pass as one."""
    llm_status: str = ""

    # -- detection ------------------------------------------------------------------
    detected: bool = False
    malicious_events_surfaced: int = 0
    malicious_events_total: int = 0

    # -- analyst load ---------------------------------------------------------------
    findings: int = 0
    cases: int = 0
    noise_cases: int = 0

    # -- chain quality --------------------------------------------------------------
    primary_case_recall: float = 0.0
    primary_case_purity: float = 1.0

    # -- benign discrimination ------------------------------------------------------
    benign_findings_identified: int = 0
    """Findings on non-malicious activity correctly dispositioned ``likely_benign``."""
    benign_findings_total: int = 0
    malicious_findings_called_benign: int = 0
    """Findings on real attack activity wrongly dispositioned benign. Must be zero.

    The only asymmetric failure in this section: telling an analyst to disregard a true
    positive is categorically worse than failing to reassure them about a false one."""
    findings_after_triage: int = 0
    """Findings still needing a look once the benign ones are set aside."""

    # -- conclusions ----------------------------------------------------------------
    techniques_found: tuple[str, ...] = ()
    techniques_missing: tuple[str, ...] = ()
    conclusions_hit: tuple[str, ...] = ()
    conclusions_missed: tuple[str, ...] = ()
    overclaimed_as_fact: tuple[str, ...] = ()

    # -- trustworthiness ------------------------------------------------------------
    hallucinated_citations: int = 0
    rejected_claims: int = 0
    calibration_warnings: int = 0
    facts: int = 0
    inferences: int = 0
    hypotheses: int = 0

    # -- cost -----------------------------------------------------------------------
    tool_calls: int = 0
    runtime_seconds: float = 0.0

    notes: list[str] = field(default_factory=list)

    # -- derived --------------------------------------------------------------------

    @property
    def event_recall(self) -> float:
        """Fraction of the incident's events that any finding surfaced."""
        return event_recall_of(
            self.malicious_events_surfaced, self.malicious_events_total
        )

    @property
    def triage_reduction(self) -> float:
        """How much correlation shrank the analyst's queue.

        ``1 - cases/findings``. The number correlation exists to move -- and it is only
        meaningful read alongside recall and purity, because merging everything into one
        case would score a perfect reduction while destroying the answer.
        """
        if not self.findings:
            return 0.0
        return 1.0 - (self.cases / self.findings)

    @property
    def case_precision(self) -> float:
        """Fraction of cases that contain anything malicious at all."""
        if not self.cases:
            return 1.0
        return (self.cases - self.noise_cases) / self.cases

    @property
    def benign_recall(self) -> float:
        """Fraction of false-positive findings the triage layer explained away."""
        if not self.benign_findings_total:
            return 1.0
        return self.benign_findings_identified / self.benign_findings_total

    @property
    def triage_load_reduction(self) -> float:
        """How much of the analyst's queue triage removed, on top of correlation."""
        if not self.findings:
            return 0.0
        return 1.0 - (self.findings_after_triage / self.findings)

    @property
    def trustworthy(self) -> bool:
        """No fabricated citation, no unevidenced fact, no overclaim.

        One definition, shared with :func:`score_labels` -- see :func:`is_trustworthy`.
        """
        return is_trustworthy(
            hallucinated_citations=self.hallucinated_citations,
            overclaimed_as_fact=self.overclaimed_as_fact,
            calibration_warnings=self.calibration_warnings,
            malicious_findings_called_benign=self.malicious_findings_called_benign,
        )

    @property
    def passed(self) -> bool:
        """Whether this incident met its success condition. See :func:`incident_passed`."""
        return incident_passed(
            is_benign=self.incident.is_benign,
            detected=self.detected,
            findings_after_triage=self.findings_after_triage,
            techniques_missing=self.techniques_missing,
            conclusions_missed=self.conclusions_missed,
            trustworthy=self.trustworthy,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident.incident_id,
            "name": self.incident.name,
            "configuration": self.configuration,
            "llm_degraded": self.llm_degraded,
            "llm_status": self.llm_status,
            "passed": self.passed,
            "benign_scenario": self.incident.is_benign,
            "detection": {
                "detected": self.detected,
                "event_recall": round(self.event_recall, 4),
                "malicious_events_surfaced": self.malicious_events_surfaced,
                "malicious_events_total": self.malicious_events_total,
            },
            "analyst_load": {
                "findings": self.findings,
                "cases": self.cases,
                "noise_cases": self.noise_cases,
                "triage_reduction": round(self.triage_reduction, 4),
                "case_precision": round(self.case_precision, 4),
            },
            "chain_quality": {
                "primary_case_recall": round(self.primary_case_recall, 4),
                "primary_case_purity": round(self.primary_case_purity, 4),
            },
            "benign_discrimination": {
                "benign_findings_identified": self.benign_findings_identified,
                "benign_findings_total": self.benign_findings_total,
                "benign_recall": round(self.benign_recall, 4),
                "malicious_findings_called_benign": self.malicious_findings_called_benign,
                "findings_after_triage": self.findings_after_triage,
                "triage_load_reduction": round(self.triage_load_reduction, 4),
            },
            "conclusions": {
                "techniques_found": list(self.techniques_found),
                "techniques_missing": list(self.techniques_missing),
                "conclusions_hit": list(self.conclusions_hit),
                "conclusions_missed": list(self.conclusions_missed),
                "overclaimed_as_fact": list(self.overclaimed_as_fact),
            },
            "trust": {
                "trustworthy": self.trustworthy,
                "hallucinated_citations": self.hallucinated_citations,
                "rejected_claims": self.rejected_claims,
                "calibration_warnings": self.calibration_warnings,
                "facts": self.facts,
                "inferences": self.inferences,
                "hypotheses": self.hypotheses,
            },
            "cost": {
                "tool_calls": self.tool_calls,
                "runtime_seconds": round(self.runtime_seconds, 3),
            },
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class LabelScores:
    """Everything the answer key can decide about one investigation.

    Computed by :func:`score_labels` from one investigation's own inputs and its own
    state, so that the figures on a row describe the run that produced the row. Two
    callers: :func:`run_incident`, which copies them into its :class:`IncidentOutcome`,
    and the M19 ablation, which writes :meth:`to_dict` into the row's ``label_scores``.

    ``investigated`` is False when no case was raised. That is not a benign outcome for
    a malicious incident -- every conclusion requirement is then unmet rather than
    vacuously satisfied, because an incident that produced no case ran no investigation
    and must not report a clean pass.
    """

    incident_id: str
    is_benign: bool
    investigated: bool

    # -- detection ------------------------------------------------------------------
    detected: bool
    malicious_events_surfaced: int
    malicious_events_total: int

    # -- analyst load ---------------------------------------------------------------
    findings: int
    findings_after_triage: int
    benign_findings_total: int
    benign_findings_identified: int
    malicious_findings_called_benign: int

    # -- conclusions ----------------------------------------------------------------
    techniques_found: tuple
    techniques_missing: tuple
    conclusions_hit: tuple
    conclusions_missed: tuple
    overclaimed_as_fact: tuple

    # -- trustworthiness ------------------------------------------------------------
    hallucinated_citations: int
    calibration_warnings: int
    rejected_claims: int
    facts: int
    inferences: int
    hypotheses: int
    tool_calls: int

    @property
    def event_recall(self) -> float:
        return event_recall_of(
            self.malicious_events_surfaced, self.malicious_events_total
        )

    @property
    def trustworthy(self) -> bool:
        return is_trustworthy(
            hallucinated_citations=self.hallucinated_citations,
            overclaimed_as_fact=self.overclaimed_as_fact,
            calibration_warnings=self.calibration_warnings,
            malicious_findings_called_benign=self.malicious_findings_called_benign,
        )

    @property
    def passed(self) -> bool:
        return incident_passed(
            is_benign=self.is_benign,
            detected=self.detected,
            findings_after_triage=self.findings_after_triage,
            techniques_missing=self.techniques_missing,
            conclusions_missed=self.conclusions_missed,
            trustworthy=self.trustworthy,
        )

    def to_dict(self) -> dict[str, Any]:
        """The label-based column, as an ablation row records it.

        ``computed_from`` is part of the record rather than a comment: these figures
        were once lifted from a second, separate investigation of the same incident, and
        a reader of an older results file has no way to tell the two apart unless the
        file says which it is.
        """
        return {
            "incident_id": self.incident_id,
            "passed": self.passed,
            "event_recall": round(self.event_recall, 4),
            "trustworthy": self.trustworthy,
            "hallucinated_citations": self.hallucinated_citations,
            "calibration_warnings": self.calibration_warnings,
            "overclaimed_as_fact": list(self.overclaimed_as_fact),
            "techniques_missing": list(self.techniques_missing),
            "conclusions_missed": list(self.conclusions_missed),
            "investigated": self.investigated,
            "computed_from": "this row's own investigation state",
        }


def score_labels(
    incident: Incident,
    findings: Sequence[Finding],
    assessments: Mapping[str, Any],
    state: InvestigationState | None,
) -> LabelScores:
    """Grade one investigation against its incident's answer key.

    Args:
        incident: The labelled scenario, carrying the answer key.
        findings: Every finding the hunt produced for this incident's telemetry.
        assessments: The triage assessment per finding id.
        state: The investigation's own state, or ``None`` when no case was raised and
            therefore nothing was investigated.

    The whole function is a pure reading of its four arguments: there is no pipeline in
    here, and nothing it returns can describe a run other than the one it was handed.
    """
    malicious = set(incident.malicious_event_ids)
    surfaced = {event_id for f in findings for event_id in f.event_ids}

    benign_total = 0
    benign_identified = 0
    malicious_called_benign = 0
    after_triage = 0
    for finding in findings:
        is_malicious = bool(set(finding.event_ids) & malicious)
        called_benign = (
            assessments[finding.finding_id].disposition is Disposition.LIKELY_BENIGN
        )
        if is_malicious:
            malicious_called_benign += int(called_benign)
        else:
            benign_total += 1
            benign_identified += int(called_benign)
        after_triage += int(not called_benign)

    techniques = {
        m.technique_id
        for mappings in map_findings(list(findings)).values()
        for m in mappings
    }

    if state is None:
        # No case, no investigation: every conclusion requirement is unmet. Leaving
        # `conclusions_missed` empty here let an incident that produced no case at all
        # report a clean pass -- exactly the "passed for the wrong reason" failure this
        # harness exists to catch.
        conclusions_hit: tuple = ()
        conclusions_missed: tuple = tuple(incident.must_conclude)
        overclaimed: tuple = ()
        hallucinated = 0
        calibration = 0
        rejected = 0
        facts = inferences = hypotheses = tool_calls = 0
    else:
        statements = " ".join(c.statement for c in state.claims).lower()
        hit = [c for c in incident.must_conclude if c.lower() in statements]
        conclusions_hit = tuple(hit)
        conclusions_missed = tuple(c for c in incident.must_conclude if c not in hit)
        fact_text = " ".join(c.statement for c in state.facts).lower()
        overclaimed = tuple(
            phrase for phrase in incident.never_as_fact if phrase.lower() in fact_text
        )
        hallucinated = sum(
            1 for r in state.rejected_claims if "do not exist" in r.reason
        )
        calibration = len(audit_calibration(state.claims))
        rejected = len(state.rejected_claims)
        facts = len(state.facts)
        inferences = len(state.inferences)
        hypotheses = len(state.hypotheses)
        tool_calls = len(state.tool_calls)

    return LabelScores(
        incident_id=incident.incident_id,
        is_benign=incident.is_benign,
        investigated=state is not None,
        detected=bool(surfaced & malicious),
        malicious_events_surfaced=len(surfaced & malicious),
        malicious_events_total=len(malicious),
        findings=len(findings),
        findings_after_triage=after_triage,
        benign_findings_total=benign_total,
        benign_findings_identified=benign_identified,
        malicious_findings_called_benign=malicious_called_benign,
        techniques_found=tuple(sorted(techniques & incident.expected_techniques)),
        techniques_missing=tuple(sorted(incident.expected_techniques - techniques)),
        conclusions_hit=conclusions_hit,
        conclusions_missed=conclusions_missed,
        overclaimed_as_fact=overclaimed,
        hallucinated_citations=hallucinated,
        calibration_warnings=calibration,
        rejected_claims=rejected,
        facts=facts,
        inferences=inferences,
        hypotheses=hypotheses,
        tool_calls=tool_calls,
    )


def _apply_labels(outcome: IncidentOutcome, labels: LabelScores) -> None:
    """Copy the graded figures onto the outcome. The only place they are set."""
    outcome.detected = labels.detected
    outcome.malicious_events_surfaced = labels.malicious_events_surfaced
    outcome.malicious_events_total = labels.malicious_events_total
    outcome.findings = labels.findings
    outcome.findings_after_triage = labels.findings_after_triage
    outcome.benign_findings_total = labels.benign_findings_total
    outcome.benign_findings_identified = labels.benign_findings_identified
    outcome.malicious_findings_called_benign = labels.malicious_findings_called_benign
    outcome.techniques_found = labels.techniques_found
    outcome.techniques_missing = labels.techniques_missing
    outcome.conclusions_hit = labels.conclusions_hit
    outcome.conclusions_missed = labels.conclusions_missed
    outcome.overclaimed_as_fact = labels.overclaimed_as_fact
    outcome.hallucinated_citations = labels.hallucinated_citations
    outcome.calibration_warnings = labels.calibration_warnings
    outcome.rejected_claims = labels.rejected_claims
    outcome.facts = labels.facts
    outcome.inferences = labels.inferences
    outcome.hypotheses = labels.hypotheses
    outcome.tool_calls = labels.tool_calls


def run_incident(
    incident: Incident,
    config: HuntConfig | None = None,
    *,
    llm: LLMClient | None = None,
    investigation_config: InvestigationConfig | None = None,
) -> IncidentOutcome:
    """Run the full pipeline over one incident and measure the result.

    With no ``llm`` (the default) the run is fully deterministic. Passing a real client
    switches only the investigation stage to the LLM arm; detection, triage and
    correlation are identical either way, which is what makes the two rows comparable.
    """
    started = time.perf_counter()
    telemetry = incident.telemetry
    llm = llm if llm is not None else NullLLM()
    if investigation_config is None:
        investigation_config = InvestigationConfig(
            use_llm_planner=llm.available, use_llm_synthesis=llm.available,
        )
    outcome = IncidentOutcome(
        incident=incident,
        configuration=llm.name if llm.available else "deterministic",
    )
    malicious = set(incident.malicious_event_ids)

    hunt = run_hunt(telemetry, config=config or HuntConfig())

    # Benign discrimination, measured per finding against the answer key -- inside
    # score_labels, along with everything else the answer key decides.
    environment = build_environment_model(telemetry)
    assessments = assess_findings(hunt.findings, environment)

    # A group of findings every one of which triage explained is not raised as a case
    # (M15-4): the findings stay counted, the investigation they would have cost does
    # not happen.
    cases = correlate(hunt.findings, telemetry, set_aside=set_aside_ids(assessments))
    outcome.cases = len(cases)
    outcome.noise_cases = sum(
        1 for c in cases if not (set(c.event_ids) & malicious)
    )

    # Chain quality: fragmentation and contamination, measured on the case that
    # captured the most of the incident. Both matter and they pull against each other.
    if cases and malicious:
        primary = max(cases, key=lambda c: len(set(c.event_ids) & malicious))
        primary_events = set(primary.event_ids)
        hit = primary_events & malicious
        outcome.primary_case_recall = len(hit) / len(malicious)
        outcome.primary_case_purity = len(hit) / len(primary_events) if primary_events else 0.0

    if not cases:
        _apply_labels(outcome, score_labels(incident, hunt.findings, assessments, None))
        set_aside = outcome.findings - outcome.findings_after_triage
        outcome.notes.append(
            "no case was raised, so no investigation ran: this incident produced "
            f"{outcome.findings} finding(s), {set_aside} of them set aside by triage as "
            "likely benign, and nothing unexplained was severe enough or linked to "
            "anything"
        )
        outcome.runtime_seconds = time.perf_counter() - started
        return outcome

    # Investigate the case that best represents the incident (the largest, for a
    # benign scenario where nothing is malicious).
    target = (
        max(cases, key=lambda c: len(set(c.event_ids) & malicious))
        if malicious else max(cases, key=lambda c: len(c.findings))
    )
    tools = ToolBox(telemetry, hunt.findings, cases)
    orchestrator = InvestigationOrchestrator(
        tools,
        ClaimVerifier(telemetry),
        llm=llm,
        config=investigation_config,
        environment=environment,
    )
    state = orchestrator.investigate(target)

    outcome.llm_degraded = bool(state.llm_degraded)
    outcome.llm_status = str(state.llm_status)
    _apply_labels(outcome, score_labels(incident, hunt.findings, assessments, state))

    outcome.runtime_seconds = time.perf_counter() - started
    return outcome


@dataclass
class BenchmarkResult:
    """Outcomes across every incident in a suite."""

    outcomes: tuple[IncidentOutcome, ...]

    @property
    def passed(self) -> int:
        return sum(1 for o in self.outcomes if o.passed)

    @property
    def total(self) -> int:
        return len(self.outcomes)

    @property
    def all_passed(self) -> bool:
        return self.passed == self.total

    @property
    def total_noise_cases(self) -> int:
        return sum(o.noise_cases for o in self.outcomes)

    @property
    def any_untrustworthy(self) -> list[IncidentOutcome]:
        return [o for o in self.outcomes if not o.trustworthy]

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "total": self.total,
            "all_passed": self.all_passed,
            "total_noise_cases": self.total_noise_cases,
            "incidents": [o.to_dict() for o in self.outcomes],
        }


def run_benchmark(
    incidents: list[Incident],
    *,
    llm: LLMClient | None = None,
    investigation_config: InvestigationConfig | None = None,
) -> BenchmarkResult:
    """Run every incident under one arm and collect the outcomes."""
    return BenchmarkResult(outcomes=tuple(
        run_incident(i, llm=llm, investigation_config=investigation_config)
        for i in incidents
    ))
