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
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from ath.agent.claims import ClaimType, ClaimVerifier
from ath.agent.llm import LLMClient, NullLLM
from ath.agent.orchestrator import InvestigationConfig, InvestigationOrchestrator
from ath.agent.tools import ToolBox
from ath.correlation import correlate
from ath.environment import build_environment_model
from ath.hunting import HuntConfig, run_hunt
from ath.logging_setup import get_logger
from ath.mitre.mapper import map_findings
from ath.reporting.language import audit_calibration
from ath.telemetry.loader import Telemetry
from ath.triage import Disposition, assess_findings, set_aside_ids

logger = get_logger(__name__)


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
        if not self.malicious_events_total:
            return 1.0
        return self.malicious_events_surfaced / self.malicious_events_total

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

        A hard gate rather than a score: these are correctness failures, and one is
        enough to make the output unusable regardless of how good the metrics look.
        """
        return (
            self.hallucinated_citations == 0
            and not self.overclaimed_as_fact
            and self.calibration_warnings == 0
            and self.malicious_findings_called_benign == 0
        )

    @property
    def passed(self) -> bool:
        """Whether this incident met its success condition.

        The benign condition was originally ``cases == 0`` and is now
        ``findings_after_triage == 0``. That is a deliberate change of bar, not a
        relaxation of one, and it is worth stating plainly because moving a goalpost
        after building the thing that clears it deserves scrutiny.

        The question a quiet-day scenario asks is "was the analyst made to investigate
        anything". A case every one of whose findings carries an explicit, cited benign
        verdict does not cost an investigation -- but a *single* unexplained finding
        does, whether or not it correlated into anything. So the new condition is
        stricter in the place that matters: it requires the triage layer to account for
        every false positive individually, where the old one could be satisfied merely
        by the correlator declining to group them. ``noise_cases`` stays reported either
        way, so the case that is still formed remains visible rather than hidden by the
        change.
        """
        if self.incident.is_benign:
            return self.findings_after_triage == 0 and self.trustworthy
        return (
            self.detected
            and not self.techniques_missing
            and not self.conclusions_missed
            and self.trustworthy
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
    outcome.malicious_events_total = len(malicious)

    hunt = run_hunt(telemetry, config=config or HuntConfig())
    outcome.findings = len(hunt.findings)

    surfaced = {eid for f in hunt.findings for eid in f.event_ids}
    outcome.malicious_events_surfaced = len(surfaced & malicious)
    outcome.detected = bool(surfaced & malicious)

    # Benign discrimination, measured per finding against the answer key.
    environment = build_environment_model(telemetry)
    assessments = assess_findings(hunt.findings, environment)
    for finding in hunt.findings:
        is_malicious = bool(set(finding.event_ids) & malicious)
        called_benign = (
            assessments[finding.finding_id].disposition is Disposition.LIKELY_BENIGN
        )
        if is_malicious:
            outcome.malicious_findings_called_benign += int(called_benign)
        else:
            outcome.benign_findings_total += 1
            outcome.benign_findings_identified += int(called_benign)
        outcome.findings_after_triage += int(not called_benign)

    # A group of findings every one of which triage explained is not raised as a case
    # (M15-4): the findings stay counted above, the investigation they would have cost
    # does not happen.
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

    techniques = {
        m.technique_id
        for mappings in map_findings(hunt.findings).values()
        for m in mappings
    }
    outcome.techniques_found = tuple(sorted(techniques & incident.expected_techniques))
    outcome.techniques_missing = tuple(sorted(incident.expected_techniques - techniques))

    if not cases:
        # Every conclusion requirement is unmet, not vacuously satisfied. Leaving
        # `conclusions_missed` empty here let an incident that produced no case at all
        # -- and therefore ran no investigation -- report a clean pass: exactly the
        # "passed for the wrong reason" failure this harness exists to catch.
        outcome.conclusions_missed = tuple(incident.must_conclude)
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
    outcome.facts = len(state.facts)
    outcome.inferences = len(state.inferences)
    outcome.hypotheses = len(state.hypotheses)
    outcome.rejected_claims = len(state.rejected_claims)
    outcome.tool_calls = len(state.tool_calls)
    outcome.hallucinated_citations = sum(
        1 for r in state.rejected_claims if "do not exist" in r.reason
    )

    statements = " ".join(c.statement for c in state.claims).lower()
    hit_conclusions = [c for c in incident.must_conclude if c.lower() in statements]
    outcome.conclusions_hit = tuple(hit_conclusions)
    outcome.conclusions_missed = tuple(
        c for c in incident.must_conclude if c not in hit_conclusions
    )

    fact_text = " ".join(c.statement for c in state.facts).lower()
    outcome.overclaimed_as_fact = tuple(
        phrase for phrase in incident.never_as_fact if phrase.lower() in fact_text
    )

    outcome.calibration_warnings = len(audit_calibration(state.claims))

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
