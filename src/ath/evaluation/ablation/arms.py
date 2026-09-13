"""The arms, and the rule that an arm may only be labelled with what it actually was.

Three arms, one pipeline
-------------------------
Detection, correlation, triage, the tool surface and the claim verifier are identical in
every arm. The only thing that varies is what plans the investigation and what, if
anything, synthesises on top of the verified claims:

``A_deterministic``
    :class:`~ath.agent.llm.NullLLM`, planner and synthesis off. The baseline, and the
    only arm that can run without a key. Reproducible by construction: run it twice on
    the same manifest and every claim, every tool call and every score is identical.

``B_single_llm``
    One generalist with the whole tool surface, presented to the planner as the seven
    :class:`~ath.agent.generalist.GeneralistFacet` instances of that surface -- one walk,
    one toolbox, one budget -- with the LLM planner and synthesis on.

``C_crew_llm``
    The existing specialist crew with ``use_llm_planner`` and ``use_llm_synthesis`` on.

No silent fallback
-------------------
B and C refuse to run when no model is configured. That is the whole reason the arm
label exists: an arm that quietly ran :class:`NullLLM` because a key was missing and
then reported itself as "the LLM arm" is not a weak result, it is a false one. Two
mechanisms, because the failure has two shapes:

* *No key at all* -- :func:`run_arm` raises :class:`ArmUnavailable` before investigating
  anything.
* *A key that stops working mid-run* -- the orchestrator already records this on the
  state (``llm_requested`` and ``llm_errors``, surfacing as ``llm_degraded``), and
  :attr:`CaseResult.labelled_arm` appends ``_DEGRADED`` so the row aggregates separately
  from the arm it was launched as. The same semantics
  :class:`~ath.evaluation.incidents.IncidentOutcome` has used since M14; reused rather
  than restated so the two harnesses cannot drift on what "degraded" means.

The budgets, and why they are the same for every arm
-----------------------------------------------------
M19-1 left arm B declared and unbuilt because its two budgets were unsettled, and an
agent whose call count is decided by how long anyone was willing to wait measures
patience rather than design. The architect settled them for M19-2, and both LLM arms run
under the deterministic arm's own budget:

* :data:`STEP_BUDGET` -- ``max_steps = 8``, the same orchestrator budget arm A runs
  under. Arm B is therefore explicitly a *many-pass* single agent, not a one-shot one.
* :data:`TOOL_CALL_CAP` -- 40 tool calls per case, enforced by the
  :class:`~ath.agent.tools.ToolBox` itself. A call beyond the cap returns a structured
  refusal and is recorded as a refused :class:`~ath.agent.tools.ToolCall`; **nothing
  raises**, and an arm that hits the cap is not disqualified. The hit is counted, per
  case, in the row's ``budgets`` block.

The caps are identical for every case and are recorded on every row, because a budget
that is not written down next to the result is indistinguishable from a result. Arm A
keeps ``tool_call_cap: null`` -- the deterministic crew's calls are bounded by each
specialist's own scope, and capping the baseline to match a limit invented for the
generalist would change the thing every other arm is read against.

Arm B is one generalist, handed to ``InvestigationOrchestrator(specialists=[...])`` as
the seven facets of its tool surface: no orchestrator change, no registry entry, and no
route by which the agent being measured can be assembled into the crew doing the
measuring.

M19-2 handed it over as a *crew of one*, and the orchestrator consults the model only
when more than one candidate is eligible -- so arm B's planner was never asked anything
(0 planner-chosen steps for B against 3 for C). The arm measured synthesis over a fixed
walk. The facets fix that without touching the tool surface, the budgets, the claim rules
or the evidence discipline: **what changed is what arm B's planner chooses among, and
nothing else.** See :mod:`ath.agent.generalist`.

Scripted runs
--------------
``run_arm(..., scripted=True)`` exists for one purpose: proving the arm's path executes
end to end while no key exists, driven by :class:`~ath.agent.llm.ScriptedLLM`. Such a row
is labelled ``*_SCRIPTED`` by :attr:`CaseResult.labelled_arm`, so it can never be
aggregated into the arm it imitates. **A scripted row says nothing whatever about model
quality** -- the responses are canned, written by this repository, and chosen to exercise
code paths.
"""

from __future__ import annotations

import inspect
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

from ath.agent.claims import ClaimVerifier
from ath.agent.generalist import build_generalist_crew
from ath.agent.llm import LLMClient, NullLLM, build_llm
from ath.agent.orchestrator import InvestigationConfig, InvestigationOrchestrator
from ath.agent.state import InvestigationStatus
from ath.agent.tools import ToolBox
from ath.correlation.chain import InvestigationCase
from ath.environment.model import EnvironmentModel
from ath.evaluation.ablation.manifest import CaseManifest, telemetry_hash
from ath.evaluation.ablation.scoring import CaseScores, capture_label_scores, score_case
from ath.hunting.finding import Finding
from ath.logging_setup import get_logger
from ath.telemetry.loader import Telemetry

logger = get_logger(__name__)

ARM_A = "A_deterministic"
ARM_B = "B_single_llm"
ARM_C = "C_crew_llm"

MAX_SERIALISED_IDS = 5000
"""Longest event-id list written into a results file, per claim and per tool call.

Not a change to what any arm did, and not an input to any score: the counts, the
coverage and the correctness ratios are all computed from the full sets on the live
state, before this applies. It bounds the *file* only, and every truncated list carries
the number of ids it dropped beside it.

It exists because arm B's first full scripted run produced a **395 MB** ``arm_B.json``.
One generalist call -- ``host_network_activity`` unfiltered on a COMISET host -- returns
589,476 event ids, and both the tool call and the claim it fed recorded every one of
them, twice per case. A record nobody can open is not a record; and 589,476 ids attached
to the sentence "this host made 589,476 connections" are not evidence, they are the same
number written out longhand.

The value is set above the longest list any already-published arm A row contains (4,522,
on ``flaws_cloud``), so applying it moves no byte of an existing result. That is a
deliberate choice of constant and it is stated rather than hidden: the cap exists for
the pathological case, not to trim the normal one.
"""


class ManifestMismatch(RuntimeError):
    """The inputs are not the inputs the manifest pinned. The run is refused."""


class ArmUnavailable(RuntimeError):
    """An arm that requires a model was asked to run without one."""


@dataclass(frozen=True)
class ArmConfig:
    """One arm: what plans it, what synthesises for it, and whether it needs a key.

    Attributes:
        name: ``A_deterministic``, ``B_single_llm`` or ``C_crew_llm``.
        llm_factory: Builds the client for this arm. A factory rather than a client so
            an arm definition is reusable and so a test can inject
            :class:`~ath.agent.llm.ScriptedLLM` without touching the environment.
        config: Orchestrator settings, including which model stages are on.
        requires_model: When true, a client that reports ``available == False`` is a
            refusal rather than a fallback.
        tool_call_cap: Per-case tool-call budget handed to the ``ToolBox``. ``None`` is
            uncapped, which is what arm A runs under.
        generalist: Run the facets of one
            :class:`~ath.agent.generalist.GeneralistFacet` generalist as the whole crew,
            instead of the environment-assembled specialists.
        implemented: False for an arm that is declared but not built; running it raises
            :class:`NotImplementedError` with the design note.
        design_note: Why an unimplemented arm is unimplemented.
        model: The model id this arm pins, or ``None`` for an arm that uses none. Passed
            to ``llm_factory`` when the factory accepts it, and written into the results
            header. Pinned per arm rather than read from configuration because an
            experiment whose model id comes from an environment variable cannot say,
            afterwards, which model produced which row.
    """

    name: str
    llm_factory: Callable[..., LLMClient]
    config: InvestigationConfig
    requires_model: bool = False
    tool_call_cap: int | None = None
    generalist: bool = False
    implemented: bool = True
    design_note: str = ""
    model: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "model": self.model,
            "use_llm_planner": self.config.use_llm_planner,
            "use_llm_synthesis": self.config.use_llm_synthesis,
            "max_steps": self.config.max_steps,
            "tool_call_cap": self.tool_call_cap,
            "generalist": self.generalist,
            "requires_model": self.requires_model,
            "implemented": self.implemented,
        }


# The architect's budget ruling for M19-2, recorded verbatim in
# reports/m19/ablation/PREREGISTERED.md as a dated addendum. Both constants belong to
# the experiment rather than to this module's opinion: they are named here so that
# changing an arm's budget is a visible edit to a named constant rather than a
# parameter drifting.
STEP_BUDGET = 8
"""Orchestrator steps per case. The same budget arm A's orchestrator runs under."""

TOOL_CALL_CAP = 40
"""Tool calls per case for the model arms. A call beyond it is refused, not raised."""

ABLATION_MODEL = "claude-opus-5"
"""The model both LLM arms run, pinned by the experiment rather than by configuration.

The architect's Phase 1 ruling, recorded verbatim in ``PREREGISTERED.md`` and in
``ENVIRONMENT.md``: the ablation pins its own model id on :class:`ArmConfig` for arms B
and C -- the brief calls arm B "one strong general LLM investigator" -- and
``ath.config.DEFAULT_MODEL`` is left unchanged and out of scope. Two arms differing in
model would be a different experiment from two arms differing in reasoning
architecture, so the id is one constant read by both.
"""


def build_client(arm: "ArmConfig") -> LLMClient:
    """The client for an arm, with the arm's pinned model when the factory takes one.

    The factory is part of an arm's definition and tests inject their own -- typically a
    zero-argument lambda returning a :class:`~ath.agent.llm.ScriptedLLM`. So the model
    id is passed only to a factory that declares it, and the signature is inspected
    rather than the call attempted-and-excepted: a ``TypeError`` raised *inside* a
    factory would otherwise be silently retried as if the factory took no model, and an
    arm would run on the default id while the header said otherwise.
    """
    if arm.model is None:
        return arm.llm_factory()
    parameters = inspect.signature(arm.llm_factory).parameters
    takes_model = "model" in parameters or any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in parameters.values()
    )
    return arm.llm_factory(model=arm.model) if takes_model else arm.llm_factory()


def arm_a(llm_factory: Callable[[], LLMClient] | None = None) -> ArmConfig:
    """The deterministic baseline: no model, planner and synthesis off, no tool cap."""
    return ArmConfig(
        name=ARM_A,
        llm_factory=llm_factory or NullLLM,
        config=InvestigationConfig(
            max_steps=STEP_BUDGET, use_llm_planner=False, use_llm_synthesis=False,
        ),
    )


def arm_b(llm_factory: Callable[[], LLMClient] | None = None) -> ArmConfig:
    """One generalist investigator with every tool, under the shared budgets."""
    return ArmConfig(
        name=ARM_B,
        llm_factory=llm_factory or build_llm,
        config=InvestigationConfig(
            max_steps=STEP_BUDGET, use_llm_planner=True, use_llm_synthesis=True,
        ),
        requires_model=True,
        tool_call_cap=TOOL_CALL_CAP,
        generalist=True,
        model=ABLATION_MODEL,
    )


def arm_c(llm_factory: Callable[[], LLMClient] | None = None) -> ArmConfig:
    """The existing crew, with the model planning and synthesising."""
    return ArmConfig(
        name=ARM_C,
        llm_factory=llm_factory or build_llm,
        config=InvestigationConfig(
            max_steps=STEP_BUDGET, use_llm_planner=True, use_llm_synthesis=True,
        ),
        requires_model=True,
        tool_call_cap=TOOL_CALL_CAP,
        model=ABLATION_MODEL,
    )


ARM_BUILDERS: dict[str, Callable[..., ArmConfig]] = {
    ARM_A: arm_a, ARM_B: arm_b, ARM_C: arm_c,
}


@dataclass
class CaseResult:
    """What one arm produced for one pinned case.

    ``manifest_hash`` is recorded on every row: a results file that cannot say which
    manifest it ran on is not evidence about an experiment, it is a table of numbers.
    """

    arm: str
    corpus: str
    case_id: str
    manifest_hash: str
    telemetry_hash: str
    configuration: str
    llm_degraded: bool
    llm_status: str
    state: dict[str, Any]
    scores: CaseScores
    wall_seconds: float = 0.0
    tokens: int | None = None
    labels: dict[str, Any] = field(default_factory=dict)
    label_scores: dict[str, Any] = field(default_factory=dict)
    budgets: dict[str, Any] = field(default_factory=dict)
    """The budgets this case ran under, and whether either was hit.

    Recorded per row rather than only in the file header, because a budget that is not
    written next to the number it produced is indistinguishable from no budget: a reader
    comparing two arms' tool-call counts has to be able to see, on the row, that one of
    them was capped and whether the cap bound.
    """
    scripted: bool = False
    """This row was produced by canned responses, not by a model."""

    @property
    def labelled_arm(self) -> str:
        """The arm this row may honestly be reported as.

        An arm whose model failed mid-run planned deterministically for part of the
        case. Reporting that row as ``C_crew_llm`` would put a partly-deterministic
        result in the model arm's mean, which is the precise way an ablation lies. A
        scripted row is worse than partial -- it contains no model output at all -- so it
        carries its own suffix and can never land in the arm's mean either.
        """
        label = f"{self.arm}_SCRIPTED" if self.scripted else self.arm
        return f"{label}_DEGRADED" if self.llm_degraded else label

    def to_dict(self) -> dict[str, Any]:
        return {
            "arm": self.arm,
            "labelled_arm": self.labelled_arm,
            "corpus": self.corpus,
            "case_id": self.case_id,
            "manifest_hash": self.manifest_hash,
            "telemetry_hash": self.telemetry_hash,
            "configuration": self.configuration,
            "scripted": self.scripted,
            "llm_degraded": self.llm_degraded,
            "llm_status": self.llm_status,
            "wall_seconds": round(self.wall_seconds, 3),
            "tokens": self.tokens,
            "budgets": dict(self.budgets),
            "labels": dict(self.labels),
            "label_scores": dict(self.label_scores),
            "scores": self.scores.to_dict(),
            "state": cap_serialised_ids(self.state),
        }

    def comparable(self) -> dict[str, Any]:
        """The part of this row two runs of a deterministic arm must agree on exactly.

        Wall time and timestamps are removed, and nothing else is. They are the only
        fields that are *allowed* to differ between two runs of the same deterministic
        arm; if any other field moves, that is nondeterminism in the investigation and
        it is a defect to report rather than a variance to average over.
        """
        state = _strip_times(self.state)
        scores = self.scores.to_dict()
        scores["completeness"] = {
            k: v for k, v in scores["completeness"].items() if k != "wall_seconds"
        }
        return {
            "arm": self.labelled_arm,
            "corpus": self.corpus,
            "case_id": self.case_id,
            "manifest_hash": self.manifest_hash,
            "telemetry_hash": self.telemetry_hash,
            "configuration": self.configuration,
            "llm_degraded": self.llm_degraded,
            "budgets": dict(self.budgets),
            "scores": scores,
            "state": state,
            "label_scores": {
                k: v for k, v in self.label_scores.items() if k != "runtime_seconds"
            },
        }


def _cap(ids: list[Any]) -> tuple[list[Any], int]:
    if len(ids) <= MAX_SERIALISED_IDS:
        return list(ids), 0
    return list(ids[:MAX_SERIALISED_IDS]), len(ids) - MAX_SERIALISED_IDS


def _cap_claim(claim: dict[str, Any]) -> dict[str, Any]:
    kept, omitted = _cap(claim.get("evidence_ids", []))
    if not omitted:
        return claim
    return {**claim, "evidence_ids": kept, "evidence_ids_omitted": omitted}


def _cap_call(call: dict[str, Any]) -> dict[str, Any]:
    kept, omitted = _cap(call.get("event_ids", []))
    if not omitted:
        return call
    return {**call, "event_ids": kept, "event_ids_omitted": omitted}


def cap_serialised_ids(state: dict[str, Any]) -> dict[str, Any]:
    """A state payload whose id lists are bounded for the file. See MAX_SERIALISED_IDS.

    Truncation is always marked (``evidence_ids_omitted`` / ``event_ids_omitted``) and
    the marker is absent when nothing was dropped, so a row that fits is written exactly
    as it was before this existed.
    """
    kept_evidence, omitted_evidence = _cap(state.get("evidence_ids", []))
    capped = {
        **state,
        "claims": [_cap_claim(c) for c in state.get("claims", [])],
        "rejected_claims": [
            {**r, "claim": _cap_claim(r.get("claim", {}))}
            for r in state.get("rejected_claims", [])
        ],
        "results": [
            {
                **result,
                "claims": [_cap_claim(c) for c in result.get("claims", [])],
                "tool_calls": [_cap_call(t) for t in result.get("tool_calls", [])],
            }
            for result in state.get("results", [])
        ],
        "evidence_ids": kept_evidence,
    }
    if omitted_evidence:
        capped["evidence_ids_omitted"] = omitted_evidence
    return capped


def _strip_times(state: dict[str, Any]) -> dict[str, Any]:
    """A state payload with wall-clock stamps removed, nothing else."""
    stripped = {k: v for k, v in state.items() if k != "started_at"}
    stripped["results"] = [
        {
            **result,
            "tool_calls": [
                {k: v for k, v in call.items() if k != "called_at"}
                for call in result.get("tool_calls", [])
            ],
        }
        for result in stripped.get("results", [])
    ]
    return stripped


def _check_inputs(
    entries: Sequence[CaseManifest],
    digest: str,
    cases_by_id: dict[str, InvestigationCase],
) -> None:
    """Refuse the run unless the inputs are exactly the pinned ones."""
    for entry in entries:
        if entry.telemetry_hash != digest:
            raise ManifestMismatch(
                f"{entry.key}: telemetry hash {digest[:12]} does not match the pinned "
                f"{entry.telemetry_hash[:12]}. The corpus this arm was handed is not "
                "the corpus the manifest pinned; the run is refused rather than "
                "reported as a comparison."
            )
        case = cases_by_id.get(entry.case_id)
        if case is None:
            raise ManifestMismatch(
                f"{entry.key}: the pinned case no longer exists in this corpus's "
                f"{len(cases_by_id)} case(s)."
            )
        findings = tuple(sorted(f.finding_id for f in case.findings))
        if findings != entry.finding_ids:
            raise ManifestMismatch(
                f"{entry.key}: the case exists but is made of different findings "
                f"({len(findings)} now, {len(entry.finding_ids)} pinned). A case id is "
                "not an identity; its findings are."
            )


def run_arm(
    arm: ArmConfig,
    manifest: Sequence[CaseManifest],
    telemetry: Telemetry,
    cases: Sequence[InvestigationCase],
    *,
    manifest_digest: str = "",
    findings: Sequence[Finding] | None = None,
    environment: EnvironmentModel | None = None,
    llm: LLMClient | None = None,
    scripted: bool = False,
    label_scorer: Callable[[Any], dict[str, Any]] | None = None,
) -> list[CaseResult]:
    """Run one arm over the manifest entries belonging to this corpus.

    Every case gets a fresh :class:`~ath.agent.tools.ToolBox`. Sharing one across cases
    -- as ``scripts/m18_cloud_detection.py`` does -- makes ``ToolBox.calls_by`` return
    every call the agent has made since the first case, so each case's recorded tool
    calls include its predecessors'. That inflates the cost column of whichever arm
    happens to run more cases, which is exactly the column an ablation is for.

    Args:
        arm: The arm to run.
        manifest: Pinned entries; all must name this corpus's telemetry hash.
        telemetry: The corpus, re-loaded. Hashed and checked against the manifest.
        cases: Every case the corpus produced, so pinned ids can be looked up.
        manifest_digest: The whole manifest's hash, recorded on every row.
        findings: Every finding the corpus produced, for the tool surface. Defaults to
            the union of the given cases' findings.
        environment: The environment model; built from ``telemetry`` when omitted.
        llm: An already-built client, bypassing ``arm.llm_factory``. For tests.
        scripted: Mark every row as produced by canned responses. Labels the rows
            ``*_SCRIPTED`` so they cannot be aggregated into the arm they imitate, and
            is the only way an arm requiring a model may run without one.
        label_scorer: Grades a corpus that has an answer key, from **this row's own
            state**. Called once per case with the live
            :class:`~ath.agent.state.InvestigationState` the row was built from, and its
            result is merged into ``label_scores`` along with the row's own identity.

            It takes the state rather than the finished row because the row carries a
            serialised, id-capped copy. The caller supplies the answer key; this
            function supplies the run. That division is the point: M19-2 obtained these
            figures by running a *second* investigation of the same incident -- its own
            uncapped toolbox, the environment-assembled crew -- and attaching the result
            to a row produced by something else. For arm B that was arm C's architecture
            wearing arm B's label, and its tokens were counted nowhere.

    Raises:
        NotImplementedError: for a declared-but-unbuilt arm.
        ArmUnavailable: when the arm requires a model and none is configured.
        ManifestMismatch: when the inputs differ from the pinned ones.
    """
    if not arm.implemented:
        raise NotImplementedError(f"{arm.name} is declared, not implemented. {arm.design_note}")

    client = llm if llm is not None else build_client(arm)
    if scripted and not client.available:
        # A "scripted" run handed NullLLM would be a deterministic run wearing an LLM
        # arm's name with a reassuring suffix. The suffix is there to say *which* kind
        # of not-a-model produced the row, not to license any of them.
        raise ArmUnavailable(
            f"{arm.name} was asked for a scripted run but the client "
            f"{client.name!r} reports available=False. A scripted run must be given a "
            "scripted client; it is a proof that the arm's path executes, and a "
            "deterministic run relabelled as one would prove nothing at all."
        )
    if arm.requires_model and not client.available and not scripted:
        raise ArmUnavailable(
            f"{arm.name} requires a configured model and none is available "
            f"(client {client.name!r} reports available=False; set ATH_LLM_API_KEY). "
            "Refusing to run: a deterministic run relabelled as an LLM arm would be a "
            f"false row, not a weak one. Run {ARM_A} if a deterministic baseline is "
            "what is wanted."
        )

    entries = list(manifest)
    cases_by_id = {c.case_id: c for c in cases}
    digest = telemetry_hash(telemetry)
    _check_inputs(entries, digest, cases_by_id)

    if environment is None:
        from ath.environment import build_environment_model  # noqa: PLC0415

        environment = build_environment_model(telemetry)
    all_findings = (
        list(findings) if findings is not None
        else list({f.finding_id: f for c in cases for f in c.findings}.values())
    )
    verifier = ClaimVerifier(telemetry)

    results: list[CaseResult] = []
    for entry in entries:
        case = cases_by_id[entry.case_id]
        tools = ToolBox(
            telemetry, all_findings, list(cases), tool_call_budget=arm.tool_call_cap,
        )
        # Arm B is one generalist, presented to the planner as the seven facets of its
        # own tool surface (M19-3). Built per case, like the toolbox, because the facets
        # share a walk and a shared instance would arrive at the second case already
        # finished.
        crew = build_generalist_crew(tools) if arm.generalist else None
        orchestrator = InvestigationOrchestrator(
            tools, verifier, llm=client, config=arm.config, environment=environment,
            specialists=crew,
        )
        baseline = begin_token_accounting(client)
        started = time.perf_counter()
        state = orchestrator.investigate(case)
        elapsed = time.perf_counter() - started

        # Eligibility only disappears by running (``should_run`` declines a specialist
        # that has already run, and every other gate is monotone within one case), so
        # what is still eligible at the end is exactly the work the run left undone.
        eligible_never_ran = [s.name for s, _ in orchestrator.eligible(state)]
        tokens = tokens_spent(client, baseline)

        case_scores = score_case(
            state, case, verifier,
            eligible_never_ran=eligible_never_ran,
            wall_seconds=elapsed,
            tokens=tokens,
        )
        result = CaseResult(
            arm=arm.name,
            corpus=entry.corpus,
            case_id=entry.case_id,
            manifest_hash=manifest_digest,
            telemetry_hash=digest,
            configuration=client.name if client.available else "deterministic",
            llm_degraded=bool(state.llm_degraded),
            llm_status=str(state.llm_status),
            state=state.to_dict(),
            scores=case_scores,
            wall_seconds=elapsed,
            tokens=tokens,
            labels=dict(entry.labels),
            label_scores=capture_label_scores(entry.labels, case_scores),
            budgets=budgets_of(tools, arm, state),
            scripted=scripted,
        )
        graded = label_scorer(state) if label_scorer is not None else {}
        if graded:
            # The row says which arm these figures belong to. Before M19 Phase 1 the
            # label scores carried the configuration of a separate run, so a scripted
            # arm B row and a scripted arm C row could name the same thing.
            result.label_scores = {
                **result.label_scores,
                "incident_id": graded.get("incident_id"),
                "arm": result.labelled_arm,
                "configuration": result.configuration,
                "llm_degraded": result.llm_degraded,
                **{k: v for k, v in graded.items() if k != "incident_id"},
            }
        results.append(result)
        logger.info(
            "%s %s: %d fact(s), %d inference(s), %d hypothesis(es) in %.2fs",
            arm.name, entry.key, results[-1].scores.facts,
            results[-1].scores.inferences, results[-1].scores.hypotheses, elapsed,
        )
    return results


def begin_token_accounting(client: Any) -> int | None:
    """Start one case's token accounting and return the baseline to subtract, if any.

    ``CaseResult.tokens`` is a *per-case* number. A client accumulates across every call
    it makes, so without this the second case of a run would be charged for the first,
    and the last case of a 22-case manifest would carry the whole manifest's bill -- the
    cost column's version of the cumulative tool-call defect this milestone corrected in
    the M18 script.

    A client that can reset is reset. One that cannot is snapshotted and subtracted, so
    a third-party double that only exposes a running total still yields a per-case
    figure rather than a misleading one.
    """
    reset = getattr(client, "reset_token_accounting", None)
    if callable(reset):
        reset()
        return None
    return getattr(client, "tokens_used", None)


def tokens_spent(client: Any, baseline: int | None) -> int | None:
    """What this case cost, or ``None`` when the client reported nothing.

    Never ``0`` for a client that said nothing: "the model spent nothing" and "nobody
    told us what it spent" are different facts, and only one of them belongs in a cost
    column.
    """
    total = getattr(client, "tokens_used", None)
    if total is None:
        return None
    return total - (baseline or 0)


def budgets_of(tools: ToolBox, arm: ArmConfig, state: Any) -> dict[str, Any]:
    """What this case was allowed, and whether either allowance bound.

    Both budgets are reported whether or not they were reached, and ``budget_hit`` is
    recorded rather than inferred from the counts: an arm that hit its cap is not
    disqualified, and hiding the hit would turn a truncated investigation into a
    cheap-looking one.
    """
    return {
        "max_steps": arm.config.max_steps,
        "tool_call_cap": arm.tool_call_cap,
        "tool_calls_served": tools.calls_served,
        "tool_calls_refused": tools.budget_hits,
        "tool_budget_hit": bool(tools.budget_hits),
        "step_budget_hit": state.status is InvestigationStatus.STEP_LIMIT,
    }


def identical(left: Iterable[CaseResult], right: Iterable[CaseResult]) -> list[str]:
    """Differences between two runs of the same arm, empty when they are identical.

    Returns descriptions rather than a boolean so a reproducibility failure names the
    case and the field that moved.
    """
    left_rows = {(r.corpus, r.case_id): r for r in left}
    right_rows = {(r.corpus, r.case_id): r for r in right}
    differences: list[str] = []
    for key in sorted(set(left_rows) | set(right_rows)):
        if key not in left_rows or key not in right_rows:
            differences.append(f"{key[0]}/{key[1]}: present in only one run")
            continue
        lhs, rhs = left_rows[key].comparable(), right_rows[key].comparable()
        if lhs != rhs:
            differences.append(
                f"{key[0]}/{key[1]}: " + ", ".join(
                    field_name for field_name in sorted(set(lhs) | set(rhs))
                    if lhs.get(field_name) != rhs.get(field_name)
                )
            )
    return differences
