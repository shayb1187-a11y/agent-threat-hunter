"""Render a :class:`~ath.reporting.models.Report` as Markdown.

Every claim passes through :func:`~ath.reporting.language.render_claim`, so the
FACT/INFERENCE/HYPOTHESIS prefix is never optional and never depends on the section
header alone -- a reader who copies one bullet out of context still sees its epistemic
status. Nothing in this module fabricates content: every section either iterates
something already on the :class:`Report`, or states a fixed disclaimer about what the
report does not claim.
"""

from __future__ import annotations

from ath.hunting.finding import Severity
from ath.reporting.language import render_claim
from ath.reporting.models import Report

_SEVERITY_BADGE: dict[Severity, str] = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}

# How many event ids to show inline before collapsing to "+N more". This is purely a
# rendering choice: the full list always remains on the Claim object (used by the
# verifier) and in the evidence appendix (used by the reader) -- nothing is lost, only
# the inline bullet is kept scannable. A claim like "43 authentication events" is
# genuinely supported by all 43 events; showing all 43 inline would bury the sentence.
_INLINE_EVIDENCE_LIMIT = 6


def _format_evidence_ids(evidence_ids: tuple[str, ...]) -> str:
    if len(evidence_ids) <= _INLINE_EVIDENCE_LIMIT:
        return ", ".join(evidence_ids)
    shown = ", ".join(evidence_ids[:_INLINE_EVIDENCE_LIMIT])
    return f"{shown}, +{len(evidence_ids) - _INLINE_EVIDENCE_LIMIT} more (see Evidence Appendix)"


def render_markdown(report: Report) -> str:
    """Render a full Markdown report."""
    sections = [
        _header(report),
        _executive_summary(report),
        _timeline(report),
        _mitre_summary(report),
        _findings(report),
        _recommended_actions(report),
        _limitations(report),
        _investigation_trace(report),
        _evidence_appendix(report),
    ]
    return "\n\n".join(s for s in sections if s).rstrip() + "\n"


def _header(report: Report) -> str:
    badge = _SEVERITY_BADGE[report.severity]
    sources = ", ".join(report.data_sources) if report.data_sources else "unknown source"
    disclaimer = (
        f"> This report was produced by an automated investigation over telemetry "
        f"from: **{sources}**. It presents evidence-backed findings for analyst "
        "review and does not authorise or perform any response action."
    )
    return "\n".join([
        f"# Investigation Report: {report.case_id}",
        "",
        f"**Generated:** {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')} UTC  ",
        f"**Status:** {report.status}  ",
        f"**Severity:** {badge}  |  **Grouping confidence:** {report.grouping_confidence}  ",
        f"**Hosts:** {', '.join(report.devices)}  ",
        f"**Accounts:** {', '.join(report.users)}  ",
        f"**Window:** {report.start_time.strftime('%Y-%m-%d %H:%M:%S')} -> "
        f"{report.end_time.strftime('%H:%M:%S')} UTC ({report.duration_seconds}s)",
        "",
        disclaimer,
    ])


def _executive_summary(report: Report) -> str:
    return "\n".join(["## Executive Summary", "", report.executive_summary])


def _timeline(report: Report) -> str:
    if not report.timeline:
        return ""
    lines = [
        "## Attack Timeline",
        "",
        "| Time | Rule | Severity | User | Host / Movement | ATT&CK | Events |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for entry in report.timeline:
        where = entry.movement or entry.device
        techniques = ", ".join(entry.techniques) or "-"
        events = entry.event_ids[0] + (
            f" (+{len(entry.event_ids) - 1})" if len(entry.event_ids) > 1 else ""
        )
        lines.append(
            f"| {entry.timestamp.strftime('%H:%M:%S')} | {entry.rule_id} | "
            f"{entry.severity.value} | {entry.user} | {where} | {techniques} | {events} |"
        )
    return "\n".join(lines)


def _mitre_summary(report: Report) -> str:
    if not report.mitre_mappings:
        return ""
    lines = [
        "## MITRE ATT&CK Summary",
        "",
        f"Tactics observed, in kill-chain order: **{' -> '.join(report.tactics)}**.",
        "",
        "Each row below is a candidate interpretation of observed behaviour, not a "
        "verdict -- see the confidence column and the reasoning beside it.",
        "",
        "| Technique | Tactic | Confidence | Rule | Reasoning |",
        "| --- | --- | --- | --- | --- |",
    ]
    # Deduplicate identical (technique, rule) pairs that can arise if a rule fires
    # more than once with the same interpretation.
    seen: set[tuple[str, str]] = set()
    for mapping in sorted(
        report.mitre_mappings, key=lambda m: (-m.confidence.rank, m.technique_id)
    ):
        key = (mapping.technique_id, mapping.rule_id)
        if key in seen:
            continue
        seen.add(key)
        lines.append(
            f"| {mapping.display} | {mapping.tactic} | {mapping.confidence} | "
            f"{mapping.rule_id} | {mapping.reason} |"
        )
    return "\n".join(lines)


def _findings(report: Report) -> str:
    lines = ["## Findings"]
    for label, claims, note in (
        (
            "Confirmed (FACT)", report.facts,
            "Directly established by telemetry or deterministic detection.",
        ),
        (
            "Assessed (INFERENCE)", report.inferences,
            "Evidence-supported conclusions. Confidence reflects how strongly the "
            "cited evidence supports the conclusion, not how severe it is.",
        ),
        (
            "Unconfirmed Hypotheses", report.hypotheses,
            "Possible explanations that have NOT been verified. Treat as open "
            "questions for the analyst, not as findings.",
        ),
    ):
        lines.append(f"\n### {label} ({len(claims)})\n\n*{note}*\n")
        if not claims:
            lines.append("_None._")
            continue
        for claim in claims:
            sentence = render_claim(claim)
            lines.append(f"- {sentence}")
            if claim.evidence_ids:
                lines.append(f"  - Evidence: `{_format_evidence_ids(claim.evidence_ids)}`")
    if report.rejected_claim_count:
        lines.append(
            f"\n> {report.rejected_claim_count} additional candidate claim(s) failed "
            "evidence verification during investigation and were discarded. They do "
            "not appear above."
        )
    return "\n".join(lines)


def _recommended_actions(report: Report) -> str:
    if not report.recommended_actions:
        return ""
    lines = [
        "## Recommended Next Steps",
        "",
        "*These are investigative recommendations for a human analyst. No response "
        "action has been taken or is authorised by this report.*",
        "",
    ]
    for i, action in enumerate(report.recommended_actions, start=1):
        lines.append(f"{i}. **{action.action}**")
        lines.append(f"   - Rationale: {action.rationale}")
        if action.based_on:
            lines.append(f"   - Based on: {action.based_on}")
    return "\n".join(lines)


def _limitations(report: Report) -> str:
    if not report.limitations:
        return ""
    lines = ["## Limitations & Scope", ""]
    lines.extend(f"- {item}" for item in report.limitations)
    return "\n".join(lines)


def _investigation_trace(report: Report) -> str:
    lines = [
        "## Investigation Trace",
        "",
        f"Agents run: {', '.join(report.agents_run) or '(none)'}  ",
        f"Tool calls made: {report.tool_call_count}",
        "",
    ]
    lines.extend(f"- {step}" for step in report.investigation_path)
    return "\n".join(lines)


def _evidence_appendix(report: Report) -> str:
    if not report.evidence_appendix:
        return ""
    lines = [
        "## Evidence Appendix",
        "",
        f"All {len(report.evidence_appendix)} telemetry events underlying this report, "
        "chronologically. Every claim above cites specific event ids from this list.",
        "",
        "| Event ID | Time | Device | User | Summary |",
        "| --- | --- | --- | --- | --- |",
    ]
    for entry in report.evidence_appendix:
        summary = entry.summary.replace("|", r"\|")
        lines.append(
            f"| `{entry.event_id}` | {entry.timestamp.strftime('%H:%M:%S')} | "
            f"{entry.device} | {entry.user} | {summary} |"
        )
    return "\n".join(lines)
