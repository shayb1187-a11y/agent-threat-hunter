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
    One generalist investigator with the whole tool surface, LLM planner and synthesis.
    **Declared, not implemented** -- see "Arm B" below for why, and for the design.

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

Arm B: the design, and why it is not implemented here
------------------------------------------------------
Arm B is the industry-default shape this project exists to be compared against: **one
agent, all the tools, a model deciding what to look at.** Expressed against the classes
that exist today it would be a :class:`~ath.agent.specialists.Specialist` whose
``should_run`` always passes, whose ``reads_channels`` is empty so it is never declined
for missing telemetry, and whose ``investigate`` walks the case's entities through the
whole :class:`~ath.agent.tools.ToolBox` -- process trees for every process the findings
name, the timeline, the logon history for every account, the network peers for every
host, the technique lookups -- emitting a FACT per tool result and letting the planner
and synthesis stages do the rest. Assembled as ``Crew(specialists=(GeneralistAgent
(tools),))``, it drops straight into ``InvestigationOrchestrator(specialists=[...])``
with no orchestrator change at all.

It is not implemented in this milestone for one reason: it needs a new
``Specialist`` subclass, and the specification for this work excludes adding one. The
estimate is ~120 lines, most of it the tool-walking that the four existing specialists
already contain in domain-shaped pieces, and implementing it badly would be worse than
not implementing it -- a generalist that calls fewer tools than the crew would lose the
comparison for a reason that says nothing about single-agent versus crew. Two things
should be settled before it is written:

1. **Its step budget.** The crew gets one step per specialist; a generalist gets one
   step total unless it is allowed to loop, and "one agent, one pass" versus "one agent,
   many passes" are different arms. The ablation should fix which one B is.
2. **Its tool budget.** The crew's tool calls are bounded by each specialist's own
   scope. A generalist walking every entity in a 40-finding flaws.cloud case is
   unbounded, and an arm that runs out of wall clock is not evidence about agent design.

Until then, :func:`run_arm` raises :class:`NotImplementedError` carrying this note, so
arm B is visible as a gap in the experiment rather than absent from it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

from ath.agent.claims import ClaimVerifier
from ath.agent.llm import LLMClient, NullLLM, build_llm
from ath.agent.orchestrator import InvestigationConfig, InvestigationOrchestrator
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
        implemented: False for an arm that is declared but not built; running it raises
            :class:`NotImplementedError` with the design note.
        design_note: Why an unimplemented arm is unimplemented.
    """

    name: str
    llm_factory: Callable[[], LLMClient]
    config: InvestigationConfig
    requires_model: bool = False
    implemented: bool = True
    design_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "use_llm_planner": self.config.use_llm_planner,
            "use_llm_synthesis": self.config.use_llm_synthesis,
            "max_steps": self.config.max_steps,
            "requires_model": self.requires_model,
            "implemented": self.implemented,
        }


def arm_a(llm_factory: Callable[[], LLMClient] | None = None) -> ArmConfig:
    """The deterministic baseline: no model, planner and synthesis off."""
    return ArmConfig(
        name=ARM_A,
        llm_factory=llm_factory or NullLLM,
        config=InvestigationConfig(use_llm_planner=False, use_llm_synthesis=False),
    )


def arm_b(llm_factory: Callable[[], LLMClient] | None = None) -> ArmConfig:
    """One generalist investigator with every tool. Declared; see the module docstring."""
    return ArmConfig(
        name=ARM_B,
        llm_factory=llm_factory or build_llm,
        config=InvestigationConfig(use_llm_planner=True, use_llm_synthesis=True),
        requires_model=True,
        implemented=False,
        design_note=(
            "Arm B needs a generalist Specialist subclass (always eligible, empty "
            "reads_channels, investigate() walking the whole ToolBox over the case's "
            "entities), assembled as a crew of one. That is a new agent class, which "
            "this milestone excludes, and its step and tool budgets must be fixed "
            "before it is written or the arm measures exhaustion rather than design. "
            "See ath.evaluation.ablation.arms.__doc__ for the full note."
        ),
    )


def arm_c(llm_factory: Callable[[], LLMClient] | None = None) -> ArmConfig:
    """The existing crew, with the model planning and synthesising."""
    return ArmConfig(
        name=ARM_C,
        llm_factory=llm_factory or build_llm,
        config=InvestigationConfig(use_llm_planner=True, use_llm_synthesis=True),
        requires_model=True,
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

    @property
    def labelled_arm(self) -> str:
        """The arm this row may honestly be reported as.

        An arm whose model failed mid-run planned deterministically for part of the
        case. Reporting that row as ``C_crew_llm`` would put a partly-deterministic
        result in the model arm's mean, which is the precise way an ablation lies.
        """
        return f"{self.arm}_DEGRADED" if self.llm_degraded else self.arm

    def to_dict(self) -> dict[str, Any]:
        return {
            "arm": self.arm,
            "labelled_arm": self.labelled_arm,
            "corpus": self.corpus,
            "case_id": self.case_id,
            "manifest_hash": self.manifest_hash,
            "telemetry_hash": self.telemetry_hash,
            "configuration": self.configuration,
            "llm_degraded": self.llm_degraded,
            "llm_status": self.llm_status,
            "wall_seconds": round(self.wall_seconds, 3),
            "tokens": self.tokens,
            "labels": dict(self.labels),
            "label_scores": dict(self.label_scores),
            "scores": self.scores.to_dict(),
            "state": self.state,
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
            "scores": scores,
            "state": state,
            "label_scores": {
                k: v for k, v in self.label_scores.items() if k != "runtime_seconds"
            },
        }


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

    Raises:
        NotImplementedError: for a declared-but-unbuilt arm.
        ArmUnavailable: when the arm requires a model and none is configured.
        ManifestMismatch: when the inputs differ from the pinned ones.
    """
    if not arm.implemented:
        raise NotImplementedError(f"{arm.name} is declared, not implemented. {arm.design_note}")

    client = llm if llm is not None else arm.llm_factory()
    if arm.requires_model and not client.available:
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
        tools = ToolBox(telemetry, all_findings, list(cases))
        orchestrator = InvestigationOrchestrator(
            tools, verifier, llm=client, config=arm.config, environment=environment,
        )
        started = time.perf_counter()
        state = orchestrator.investigate(case)
        elapsed = time.perf_counter() - started

        # Eligibility only disappears by running (``should_run`` declines a specialist
        # that has already run, and every other gate is monotone within one case), so
        # what is still eligible at the end is exactly the work the run left undone.
        eligible_never_ran = [s.name for s, _ in orchestrator.eligible(state)]
        tokens = getattr(client, "tokens_used", None)

        case_scores = score_case(
            state, case, verifier,
            eligible_never_ran=eligible_never_ran,
            wall_seconds=elapsed,
            tokens=tokens,
        )
        results.append(CaseResult(
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
        ))
        logger.info(
            "%s %s: %d fact(s), %d inference(s), %d hypothesis(es) in %.2fs",
            arm.name, entry.key, results[-1].scores.facts,
            results[-1].scores.inferences, results[-1].scores.hypotheses, elapsed,
        )
    return results


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
