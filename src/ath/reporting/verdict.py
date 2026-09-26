"""Derive a report's verdict, investigation tree and reasoning summary from the run.

Everything here reads what the investigation already recorded -- the D1 investigator's
per-round diagnostics, the operational audit, the orchestrator's results and plan log.
Nothing is inferred beyond that record, and nothing is scored: this system has no
verdict confidence, so none is computed, estimated, or implied here.

Two rules shape every function in this module:

* **An incomplete run gets an Incomplete verdict, and says why.** The operational layer
  downgrades an unreliable model run to ``abstain`` for scoring; a reader must not see
  that as the model having weighed the evidence and abstained. The recorded reasons
  travel with the verdict.
* **Model text is labelled as model text.** Explanations, probe reasons and the
  evidence-gap note are reproduced verbatim and attributed; what the report adds is
  which cited ids name events the investigation actually retrieved -- a check on the
  citation, never on the meaning of the sentence.
"""

from __future__ import annotations

from typing import Any

from ath.agent.state import InvestigationState, InvestigationStatus, shown_ids
from ath.reporting.models import (
    InvestigationStep,
    InvestigationTree,
    ModelExplanation,
    Verdict,
)

NO_CONFIDENCE_NOTE = (
    "This system does not compute a confidence score for its verdict. The evidence "
    "basis is a count of what was checked, not a measure of how likely the verdict is."
)
"""Fixed wording, rendered beside every verdict so its absence of a score is stated."""

MODEL_TEXT_NOTE = (
    "Quoted text below is model output, reproduced verbatim. It is not verified fact: "
    "the checks applied to it cover the event ids it cites and any typed premises it "
    "declared, not what its sentences assert. Each cited id is marked by whether it "
    "names an event the investigation retrieved."
)
"""Fixed wording, rendered above every block of model-written text."""


def no_reasoning_note(engine: str) -> str:
    """Why a report has no model-written reasoning, stated per engine."""
    if engine == "deterministic":
        return (
            "No model-written reasoning: this run used no model. Its reasoning is the "
            "specialist trace in the investigation tree and the findings below."
        )
    if engine == "d1":
        return (
            "No model explanation was recorded: the model gave no parseable concluding "
            "answer."
        )
    return (
        f"No bounded-investigator explanations: this run used the {engine} engine; any "
        "model contribution appears as labelled claims under the findings below."
    )


_DISPOSITIONS: dict[str, str] = {
    "malicious": "Malicious", "benign": "Benign", "abstain": "Abstain",
}

_PROBE_AGENT = "investigator:probe"
_ARGUMENT_CLIP = 80


def case_title(state: InvestigationState) -> str:
    """The case's title, from its own findings -- never written for the report.

    The highest-severity finding names the case (earliest first on a tie); the rest are
    counted, not summarised, so the title claims nothing the findings do not.
    """
    findings = sorted(state.case.findings, key=lambda f: (-f.severity.rank, f.first_seen))
    if not findings:
        return state.case.case_id
    title = findings[0].title
    others = len({f.title for f in findings}) - 1
    if others > 0:
        title += f" (+{others} related finding{'s' if others > 1 else ''})"
    return title


def engine_of(state: InvestigationState) -> str:
    """Which engine produced this state: ``d1``, ``deterministic`` or ``orchestrator``."""
    operational = state.investigation.get("operational") or {}
    if operational.get("engine"):
        return str(operational["engine"])
    if "rounds" in state.investigation:
        return "d1"
    return "deterministic" if not state.llm_requested else "orchestrator"


TRIAGE_SOURCE = "deterministic triage of the seed findings"
MODEL_SOURCE = "the model's concluding round"
GUARD_SOURCE = "the benign guard, which withheld the model's benign disposition: {reason}"
"""Operational-v7 only: the application, not the model, made this run an Abstain."""


def build_verdict(
    state: InvestigationState, model: str | None = None,
    triage_disposition: str | None = None,
) -> Verdict:
    """Map the run's recorded outcome onto one of four verdict labels.

    Args:
        state: The finished investigation.
        model: The model's identity, when the caller knows it. The investigation state
            does not record which model answered, so without this the verdict says so
            rather than guessing.
        triage_disposition: For the deterministic engine only: the disposition that
            rule-based triage assigned to the seed findings (``malicious``, ``benign``
            or ``abstain``). The deterministic engine records no disposition in the
            state, so without this its verdict is Incomplete. Ignored for model runs,
            whose disposition must come from the model's own conclusion.
    """
    investigation = state.investigation
    operational = investigation.get("operational") or {}
    engine = engine_of(state)
    disposition = investigation.get("final_disposition")
    source = MODEL_SOURCE
    if engine == "deterministic" and disposition is None and triage_disposition is not None:
        disposition, source = triage_disposition, TRIAGE_SOURCE
    stop_reason = str(investigation.get("stop_reason") or "")

    reasons: list[str] = []
    if operational and operational.get("outcome") != "complete":
        reasons.extend(str(r) for r in operational.get("reasons") or ())
        if not reasons:
            reasons.append(f"operational outcome recorded as {operational.get('outcome')!r}")
    elif not operational and state.status in (
        InvestigationStatus.STEP_LIMIT, InvestigationStatus.BUDGET_LIMIT,
        InvestigationStatus.INCOMPLETE,
    ):
        reasons.append(f"investigation ended with status {state.status.value}")
    if disposition is None and not reasons:
        if not investigation.get("rounds"):
            reasons.append(
                "no model concluded this run; the "
                + ("deterministic engine" if engine == "deterministic" else f"{engine} engine")
                + " does not issue a disposition"
            )
        else:
            reasons.append(
                "the model investigation stopped without a disposition"
                + (f": {stop_reason}" if stop_reason else "")
            )
    if disposition is not None and disposition not in _DISPOSITIONS and not reasons:
        reasons.append(f"unrecognised disposition {disposition!r}")
    if reasons and stop_reason and stop_reason not in reasons and stop_reason not in (
        "concluded", "model chose no probe",
    ):
        reasons.append(f"stop reason: {stop_reason}")

    label = "Incomplete" if reasons else _DISPOSITIONS[str(disposition)]
    guard = operational.get("benign_guard") or {}
    guarded = label == "Abstain" and bool(guard.get("applied"))
    if guarded:
        source = GUARD_SOURCE.format(reason=guard.get("reason") or "no reason recorded")
    concluding = _concluding_round(state)
    supporting: tuple[str, ...] = ()
    # A withheld benign's citations supported the benign, not the Abstain shown.
    if label != "Incomplete" and concluding and not guarded:
        supporting = tuple(dict.fromkeys(
            str(e) for x in concluding.get("explanations", ()) for e in x.get("evidence", ())
        ))
    retrieved = _retrieved_ids(state)
    verified = tuple(e for e in supporting if e in retrieved)

    model_disposition = operational.get("model_disposition", disposition) if operational else disposition
    if engine == "deterministic":
        model_text = "none (deterministic engine)"
    else:
        model_text = model or "not recorded in the investigation state"
    profile = (operational.get("profile") or {}).get("version", "") if operational else ""
    return Verdict(
        disposition=label,
        incomplete_reasons=tuple(reasons),
        model_disposition=model_disposition,
        evidence_gap=str((concluding or {}).get("evidence_gap") or ""),
        supporting_event_ids=supporting,
        verified_event_ids=verified,
        evidence_basis=_evidence_basis(state, engine, supporting, verified),
        engine=engine,
        profile=profile or "not recorded",
        model=model_text,
        disposition_source="" if label == "Incomplete" else source,
    )


def _evidence_basis(
    state: InvestigationState, engine: str, supporting: tuple[str, ...],
    verified: tuple[str, ...],
) -> str:
    """Counts of what was checked -- the only 'strength' a verdict here can claim."""
    parts: list[str] = []
    if supporting:
        parts.append(
            f"{len(verified)} of {len(supporting)} cited event id(s) name events the "
            "investigation retrieved"
        )
    checks = state.investigation.get("evidence_verification") or {}
    if "observations_verified" in checks:
        parts.append(
            f"{checks['observations_verified']} typed observation(s) checked against "
            "recorded telemetry"
        )
    parts.append(f"{len(state.rejected_claims)} claim(s) rejected by verification")
    if engine == "d1":
        probes = len(state.investigation.get("probes_run") or ())
        parts.append(f"{probes} probe(s) run")
    else:
        agents = [a for a in state.agents_run if a != "evidence_verifier"]
        parts.append(
            f"{len(agents)} specialist step(s) run"
            + (f" ({', '.join(agents)})" if agents else "")
        )
    operational = state.investigation.get("operational") or {}
    if "tool_calls_served" in operational:
        parts.append(
            f"{operational['tool_calls_served']} tool call(s) served, "
            f"{operational.get('tool_calls_refused', 0)} refused"
        )
    else:
        parts.append(f"{len(state.tool_calls)} tool call(s) recorded")
    return "; ".join(parts) + "."


def build_investigation_tree(state: InvestigationState, title: str) -> InvestigationTree:
    """Initial alert, then every step the run took, in order.

    A D1 run's branches are its model-chosen probes (with the model's stated reason and
    the new events each returned); a deterministic run's branches are its specialist
    steps (with the plan log's reason). A probe the model named but that was not on its
    menu is shown as not run, rather than silently omitted.
    """
    case = state.case
    seed = set(case.event_ids)
    engine = engine_of(state)
    steps: list[InvestigationStep] = []
    rounds = state.investigation.get("rounds")
    if rounds is not None:
        probe_results = iter(r for r in state.results if r.agent == _PROBE_AGENT)
        for record in rounds:
            if record.get("invalid_probe"):
                steps.append(InvestigationStep(
                    kind="refused_probe", name=str(record["invalid_probe"]),
                    reason=str(record.get("tool_choice_reason") or ""), reason_source="model",
                ))
            probe = record.get("chosen_probe")
            if not probe:
                continue
            result = next(probe_results, None)
            fresh = _new_ids(result.tool_calls if result else (), seed)
            steps.append(InvestigationStep(
                kind="probe", name=str(probe.get("tool", "")),
                arguments=_summarise_arguments(probe.get("arguments") or {}),
                reason=str(record.get("tool_choice_reason") or ""), reason_source="model",
                tools=tuple(t.tool for t in result.tool_calls) if result else (),
                new_event_ids=fresh,
                new_event_count=int(record.get("new_evidence_ids_returned", len(fresh))),
            ))
    else:
        for result in state.results:
            fresh = _new_ids(result.tool_calls, seed)
            steps.append(InvestigationStep(
                kind="specialist", name=result.agent, reason=result.ran_because,
                reason_source="deterministic",
                tools=tuple(t.tool for t in result.tool_calls),
                new_event_ids=fresh, new_event_count=len(fresh),
            ))
    return InvestigationTree(
        alert_title=title,
        rule_ids=case.rule_ids,
        seed_event_ids=case.event_ids,
        engine=engine,
        steps=tuple(steps),
        stop_reason=_stop_reason(state),
    )


def build_reasoning_summary(state: InvestigationState) -> tuple[ModelExplanation, ...]:
    """The concluding round's explanations, verbatim, each with what became of it."""
    concluding = _concluding_round(state)
    if not concluding:
        return ()
    retrieved = _retrieved_ids(state)
    accepted = {c.statement for c in state.claims if c.source == "llm"}
    rejected = {r.claim.statement: r.reason for r in state.rejected_claims if r.claim.source == "llm"}
    incomplete = (state.investigation.get("operational") or {}).get("outcome") not in (None, "complete")
    out: list[ModelExplanation] = []
    for item in concluding.get("explanations", ()):
        label = str(item.get("label", ""))
        statement = str(item.get("statement", ""))
        cited = tuple(str(e) for e in item.get("evidence", ()))
        key = f"[{label}] {statement}"
        if key in rejected:
            status = f"rejected: {rejected[key]}"
        elif key in accepted:
            status = "accepted"
        elif incomplete:
            status = "provisional (investigation incomplete)"
        else:
            status = "not recorded"
        out.append(ModelExplanation(
            label=label, statement=statement, evidence_ids=cited,
            verified_ids=tuple(e for e in cited if e in retrieved), status=status,
        ))
    return tuple(out)


# -- helpers ----------------------------------------------------------------------------


def _concluding_round(state: InvestigationState) -> dict[str, Any] | None:
    """The last round in which the model gave a parseable answer."""
    for record in reversed(state.investigation.get("rounds") or ()):
        if "explanations" in record:
            return record
    return None


def _retrieved_ids(state: InvestigationState) -> frozenset[str]:
    """Ids of real events the investigation had in hand: the seed plus what tools showed."""
    return shown_ids(state) | frozenset(state.case.event_ids)


def _new_ids(calls, seed: set[str]) -> tuple[str, ...]:
    ids: dict[str, None] = {}
    for call in calls:
        if call.refused:
            continue
        for e in call.shown_event_ids if call.truncated else call.event_ids:
            if e not in seed:
                ids[e] = None
    return tuple(ids)


def _summarise_arguments(arguments: dict[str, Any]) -> str:
    parts = []
    for key, value in arguments.items():
        text = repr(value) if isinstance(value, str) else str(value)
        if len(text) > _ARGUMENT_CLIP:
            text = text[: _ARGUMENT_CLIP - 3] + "..."
        parts.append(f"{key}={text}")
    return ", ".join(parts)


def _stop_reason(state: InvestigationState) -> str:
    recorded = state.investigation.get("stop_reason")
    if recorded:
        return str(recorded)
    for entry in reversed(state.plan_log):
        if "stop -- " in entry:
            return entry.split("stop -- ", 1)[1]
    return ""
