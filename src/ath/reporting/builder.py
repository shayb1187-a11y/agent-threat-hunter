"""Assemble a :class:`~ath.reporting.models.Report` from a completed investigation.

Nothing here calls a language model. An :class:`~ath.agent.state.InvestigationState`
already contains everything a report needs -- verified claims, a correlated case with
its timeline and ATT&CK mappings, and a plan log explaining the investigation path.
Building a report is therefore reorganisation and derivation, not generation: the
recommended actions are derived by pattern-matching against claims and coverage gaps
that already exist, not invented by a model, so the same investigation always produces
the same recommendations.

Recommended actions came from somewhere real
---------------------------------------------
Each :class:`~ath.reporting.models.RecommendedAction` names the specific claim or gap
that produced it (``based_on``). A recommendation with no traceable origin would be the
report-writing equivalent of an unevidenced Finding, and this project does not allow
those anywhere else -- there is no reason to allow them here.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ath.agent.state import InvestigationState
from ath.reporting.models import EvidenceAppendixEntry, RecommendedAction, Report
from ath.reporting.verdict import (
    build_investigation_tree,
    build_reasoning_summary,
    build_verdict,
    case_title,
)
from ath.telemetry.loader import Telemetry

# Tactics whose absence is worth calling out by name -- the ones that matter most for
# an analyst deciding what to check next. Mirrors ath.agent.specialists._PROGRESSION_TACTICS
# but expressed as display names since that is what Report.tactics carries.
_NOTABLE_TACTICS: tuple[str, ...] = (
    "Initial Access", "Discovery", "Credential Access", "Lateral Movement",
    "Collection", "Exfiltration",
)


def build_report(
    state: InvestigationState, telemetry: Telemetry, *, model: str | None = None,
    triage_disposition: str | None = None,
) -> Report:
    """Build a report from a completed (or partially completed) investigation.

    Args:
        state: The investigation to report on. Works even if the investigation ended at
            the step limit -- the report will simply reflect a partial picture, and
            says so.
        telemetry: Source telemetry, needed only to render the evidence appendix in
            human-readable form.
        model: The answering model's identity, when the caller knows it. The state
            does not record it, and the verdict says so when it is not supplied.
        triage_disposition: For deterministic runs, triage's disposition of the seed
            findings; see :func:`ath.reporting.verdict.build_verdict`.

    Returns:
        A populated, JSON-serialisable :class:`Report`.
    """
    case = state.case
    mappings = case.mappings
    tactics = case.tactics

    appendix = _build_evidence_appendix(state.evidence_ids, telemetry)
    data_sources = tuple(sorted({e.source for e in appendix if e.source}))

    recommended = _derive_recommendations(state, tactics)
    limitations = _derive_limitations(state, tactics, data_sources)
    executive_summary = _build_executive_summary(state, tactics)
    title = case_title(state)
    elapsed = state.investigation.get("operational", {}).get("elapsed_seconds")

    return Report(
        case_id=case.case_id,
        generated_at=datetime.now(timezone.utc),
        status=state.status.value,
        severity=case.severity,
        grouping_confidence=case.confidence,
        devices=case.devices,
        users=case.users,
        start_time=case.start_time,
        end_time=case.end_time,
        duration_seconds=case.duration_seconds,
        tactics=tactics,
        timeline=tuple(case.timeline()),
        executive_summary=executive_summary,
        facts=tuple(state.facts),
        inferences=tuple(state.inferences),
        hypotheses=tuple(state.hypotheses),
        rejected_claim_count=len(state.rejected_claims),
        mitre_mappings=mappings,
        agents_run=tuple(state.agents_run),
        investigation_path=tuple(state.plan_log),
        tool_call_count=len(state.tool_calls),
        recommended_actions=recommended,
        limitations=limitations,
        evidence_appendix=appendix,
        data_sources=data_sources,
        evidence_verification=state.investigation.get("evidence_verification", {}),
        title=title,
        verdict=build_verdict(state, model=model, triage_disposition=triage_disposition),
        investigation_tree=build_investigation_tree(state, title),
        reasoning_summary=build_reasoning_summary(state),
        elapsed_seconds=float(elapsed) if elapsed is not None else None,
    )


def _build_executive_summary(state: InvestigationState, tactics: tuple[str, ...]) -> str:
    """A short, deliberately hedged paragraph -- not a verdict.

    Built entirely from measured facts about the investigation (counts, hosts,
    tactics), never from free-text model output. The wording is fixed and has been
    written once, carefully, rather than templated per-run with model-generated prose,
    because the executive summary is the part of a report most likely to be read
    without the supporting detail -- it has to be impossible to misquote as a verdict.
    """
    case = state.case
    parts = [
        f"This report covers {case.case_id}, correlating {len(case.findings)} "
        f"detection finding(s) across {len(case.devices)} host(s) "
        f"({', '.join(case.devices)}) and {len(case.users)} account(s) "
        f"({', '.join(case.users)}) between {case.start_time.strftime('%H:%M:%S')} and "
        f"{case.end_time.strftime('%H:%M:%S')} UTC on "
        f"{case.start_time.strftime('%Y-%m-%d')}."
    ]
    if tactics:
        parts.append(
            f"The evidence is consistent with activity spanning {len(tactics)} MITRE "
            f"ATT&CK tactic(s): {' -> '.join(tactics)}. Each mapping is an "
            "interpretation of observed behaviour against a public taxonomy, not a "
            "determination that an intrusion occurred."
        )
    parts.append(
        f"{len(state.facts)} statement(s) below are directly established by telemetry, "
        f"{len(state.inferences)} are evidence-supported inferences, and "
        f"{len(state.hypotheses)} are explicitly unverified hypotheses requiring "
        "analyst confirmation."
    )
    if state.rejected_claims:
        parts.append(
            f"{len(state.rejected_claims)} candidate claim(s) produced during "
            "investigation failed verification against telemetry and were discarded; "
            "they do not appear anywhere in this report."
        )
    parts.append(
        "This report does not authorise or perform any response action. All "
        "recommendations below require human review before action is taken."
    )
    return " ".join(parts)


def _derive_recommendations(
    state: InvestigationState, tactics: tuple[str, ...]
) -> tuple[RecommendedAction, ...]:
    """Derive next-step recommendations from what the investigation actually found.

    Every recommendation traces to a specific hypothesis or coverage gap already present
    in the state -- nothing here is generic filler unconnected to the evidence. The
    patterns matched are the literal phrasing the specialists use (see
    :mod:`ath.agent.specialists`), which keeps this function a straightforward, testable
    mapping rather than free-text interpretation.
    """
    actions: list[RecommendedAction] = []

    for claim in state.hypotheses:
        text = claim.statement.lower()
        if "obtained from memory" in text or "credentials for" in text and "memory" in text:
            user = _extract_quoted(claim.statement) or "the affected account"
            actions.append(RecommendedAction(
                action=(
                    f"Reset credentials for {user} and audit LSASS access controls "
                    "(e.g. Credential Guard, LSA protection) on the affected host."
                ),
                rationale=(
                    "Credential-access behaviour was observed on this host and this "
                    "account subsequently authenticated elsewhere; the connection "
                    "between the two is a hypothesis, not a confirmed fact, so "
                    "resetting credentials is precautionary rather than conclusive."
                ),
                based_on=claim.statement,
            ))
        if "transferred" in text and ("external destination" in text or "exfiltrat" in text):
            actions.append(RecommendedAction(
                action=(
                    "Review proxy, firewall, or network-flow logs for data volume "
                    "transferred to the observed external destination to confirm or "
                    "rule out exfiltration."
                ),
                rationale=(
                    "This dataset records archive creation and outbound connections "
                    "separately and does not show data actually leaving; only flow "
                    "volumes or full packet capture can resolve this."
                ),
                based_on=claim.statement,
            ))

    if "Initial Access" not in tactics:
        actions.append(RecommendedAction(
            action=(
                "Retrieve email gateway or web-proxy logs to establish the initial "
                "access vector."
            ),
            rationale=(
                "No detection in this case targets initial access, so the delivery "
                "mechanism (e.g. a phishing attachment) is inferred from process "
                "lineage rather than confirmed from delivery telemetry."
            ),
            based_on="MITRE ATT&CK tactic coverage gap: Initial Access",
        ))

    if "Discovery" not in tactics and any(
        f.rule_id in ("ATH-001", "ATH-002") for f in state.case.findings
    ):
        actions.append(RecommendedAction(
            action=(
                "Review process telemetry on the affected host(s) for discovery "
                "commands (e.g. whoami, net group, nltest) around the time of "
                "execution to determine what the actor learned about the environment."
            ),
            rationale=(
                "Discovery activity is common in intrusions of this shape but is not "
                "targeted by any current detection rule, so it may be present in the "
                "telemetry without having produced a finding."
            ),
            based_on="MITRE ATT&CK tactic coverage gap: Discovery",
        ))

    if state.case.is_multi_host:
        actions.append(RecommendedAction(
            action=(
                f"Independently verify account activity on all hosts in scope "
                f"({', '.join(state.case.devices)}) rather than relying solely on the "
                "correlated case, in case related activity exists that current "
                "detections did not flag."
            ),
            rationale="This case spans multiple hosts, which increases the possible blast radius.",
            based_on="case.is_multi_host",
        ))

    actions.append(RecommendedAction(
        action="Escalate to a human analyst for validation before any remediation action is taken.",
        rationale=(
            "This system performs read-only investigation only. It has no capability "
            "to disable accounts, isolate hosts, or otherwise remediate, and this "
            "report is not authorisation to do so."
        ),
        based_on="system design constraint",
    ))

    return tuple(actions)


def _derive_limitations(
    state: InvestigationState, tactics: tuple[str, ...], data_sources: tuple[str, ...] = ()
) -> tuple[str, ...]:
    """Collect what this report does not and cannot establish.

    The first limitation is provenance-aware: it must never claim data is synthetic
    when it was actually imported from a real Microsoft Defender export, and vice
    versa -- an earlier version of this function hardcoded "synthetic" unconditionally,
    which would have made every report about real, imported telemetry lie about its own
    origin. ``data_sources`` (derived from the evidence appendix, never guessed) is
    what prevents that.
    """
    if data_sources and data_sources != ("synthetic",):
        provenance_note = (
            f"Telemetry underlying this report came from: {', '.join(data_sources)}. "
            "Field coverage depends entirely on what the originating export or sensor "
            "captured; this project's canonical schema does not model every field a "
            "real EDR product exposes (e.g. file hashes, signer information, session "
            "identifiers), and any of those were dropped during normalization."
        )
    else:
        provenance_note = (
            "Telemetry in this project is synthetic and does not include email, DNS, "
            "file-system, or endpoint-handle telemetry; several ATT&CK techniques "
            "referenced here would need additional log sources to confirm in a real "
            "environment."
        )

    limitations: list[str] = [
        provenance_note,
        "ATT&CK mappings are interpretations of observed behaviour against a public "
        "taxonomy. They indicate that behaviour is consistent with a technique, not "
        "that an adversary performed it.",
        "Grouping confidence describes how strongly correlated findings are linked to "
        "each other, not whether an intrusion occurred.",
    ]
    missing_notable = [t for t in _NOTABLE_TACTICS if t not in tactics]
    if missing_notable:
        limitations.append(
            "No evidence was found for the following ATT&CK tactics: "
            f"{', '.join(missing_notable)}. Their absence may reflect that the "
            "activity did not occur, or that available telemetry cannot observe it."
        )
    if state.status.value == "step_limit":
        limitations.append(
            "The investigation stopped at its step budget with further eligible work "
            "remaining; this report reflects a partial investigation, not a complete "
            "one."
        )
    operational = state.investigation.get("operational", {})
    if state.investigation.get("evidence_verification"):
        limitations.append(
            "Typed predicates are checked against recorded telemetry; free-text interpretations "
            "are not semantically verified. Missing identity is not a confirmed process link, "
            "and recorded event order does not establish causation."
        )
    if operational.get("outcome") == "incomplete":
        limitations.append(
            "Operational investigation incomplete; no final model verdict is available: "
            + "; ".join(operational["reasons"])
        )
    for result in state.results:
        for note in result.notes:
            if note not in limitations:
                limitations.append(note)
    return tuple(limitations)


def _build_evidence_appendix(
    event_ids: tuple[str, ...], telemetry: Telemetry
) -> tuple[EvidenceAppendixEntry, ...]:
    """Render every cited event as a self-contained, human-readable row."""
    if not event_ids:
        return ()
    unified = telemetry.unified()
    rows = unified[unified["event_id"].isin(event_ids)].sort_values("timestamp")
    return tuple(
        EvidenceAppendixEntry(
            event_id=row["event_id"], timestamp=row["timestamp"],
            device=row["device"], user=row["user"], summary=row["summary"],
            source=row.get("source", ""),
        )
        for _, row in rows.iterrows()
    )


def _extract_quoted(text: str) -> str | None:
    """Pull a single-quoted account name out of a specialist-generated sentence."""
    start = text.find("'")
    if start == -1:
        return None
    end = text.find("'", start + 1)
    if end == -1:
        return None
    return f"'{text[start + 1 : end]}'"
