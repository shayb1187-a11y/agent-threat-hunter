"""Command-line interface for Agentic Threat Hunter.

Commands:

    generate  -- build the synthetic telemetry dataset
    stats     -- print a summary of what is in the dataset
    peek      -- show a slice of the unified timeline
    rules     -- list the registered detection rules
    hunt      -- run detections and print findings with their evidence
    evaluate  -- measure detector quality against ground truth
    chains    -- correlate findings into investigation cases and print timelines
    investigate -- run the autonomous investigation agent over a case
    report      -- render a calibrated, evidence-cited investigation report
    engineer    -- run the detection-engineering loop: propose, evaluate, iterate
    import-defender -- normalize a real Microsoft Defender advanced-hunting export Keeping a single entry point
means the README has one obvious "how do I run this" story.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

from ath.config import PROJECT_ROOT, Settings, load_settings
from ath.hunting import (
    HuntConfig,
    Severity,
    all_detectors,
    findings_to_frame,
    run_hunt,
)
from ath.agent import (
    ClaimType,
    ClaimVerifier,
    InvestigationConfig,
    InvestigationOrchestrator,
    NullLLM,
    ToolBox,
    build_llm,
)
from ath.correlation import CorrelationConfig, correlate
from ath.environment import (
    ChannelState,
    CoverageState,
    RuleVerdict,
    assess_coverage,
    build_environment_model,
)
from ath.evaluation import UNCOVERED_STAGES, evaluate
from ath.evaluation.incidents import run_benchmark
from ath.evaluation.suite import standard_suite
from ath.logging_setup import get_logger, setup_logging
from ath.mitre import ATTACK_VERSION, map_finding
from ath.engineering import propose_and_iterate
from ath.capabilities import CAPABILITY_REGISTRY, assemble_crew
from ath.telemetry import DefenderExportSource, write_normalized_telemetry
from ath.telemetry.cloudtrail_source import CloudTrailSource
from ath.telemetry.k8s_audit_source import K8sAuditSource
from ath.telemetry.loader import Telemetry, merge_telemetry
from ath.triage import (
    BENIGN_THRESHOLD,
    FEEDBACK_FILENAME,
    FeedbackStore,
    Verdict,
    assess_findings,
    score_feedback,
    set_aside_ids,
    triage_summary,
    verdict_from_assessment,
)
from ath.reporting import audit_calibration, build_report, render_markdown
from ath.schema import EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS
from ath.telemetry import (
    GeneratorConfig,
    generate_telemetry,
    load_telemetry,
    write_telemetry,
)
from ath.telemetry.source import SourceLoadResult

logger = get_logger(__name__)

# ANSI colours, disabled automatically when output is piped to a file.
_COLOURS = {
    "CRITICAL": "\033[1;91m",
    "HIGH": "\033[1;31m",
    "MEDIUM": "\033[1;33m",
    "LOW": "\033[0;36m",
    "INFO": "\033[0;37m",
    "RESET": "\033[0m",
    "DIM": "\033[2m",
    "BOLD": "\033[1m",
}


def _c(text: str, key: str) -> str:
    """Colourise ``text`` when stdout is a terminal."""
    if not sys.stdout.isatty():
        return text
    return f"{_COLOURS.get(key, '')}{text}{_COLOURS['RESET']}"


def _print_table(df: pd.DataFrame, max_rows: int = 40) -> None:
    """Print a DataFrame without pandas truncating the interesting columns."""
    with pd.option_context(
        "display.max_rows", max_rows,
        "display.max_columns", None,
        "display.width", 200,
        "display.max_colwidth", 90,
    ):
        print(df.to_string(index=False))


def cmd_generate(args: argparse.Namespace, settings: Settings) -> int:
    """Generate the synthetic telemetry dataset."""
    cfg = GeneratorConfig(seed=args.seed)
    tables, ground_truth = generate_telemetry(cfg)
    written = write_telemetry(tables, ground_truth, settings.raw_data_dir)

    print(f"\nWrote {len(written)} files to {settings.raw_data_dir}:")
    for path in written:
        print(f"  - {path.name}")

    total = sum(len(df) for df in tables.values())
    print(f"\nTotal events: {total}")
    for event_type, df in tables.items():
        print(f"  {event_type:<8} {len(df):>5}")
    return 0


def cmd_stats(args: argparse.Namespace, settings: Settings) -> int:
    """Print a descriptive summary of the loaded telemetry."""
    telemetry = load_telemetry(settings.raw_data_dir)
    start, end = telemetry.time_range

    print("\n=== Telemetry summary ===")
    print(f"Events      : {telemetry.event_count}")
    print(f"Time range  : {start.isoformat()}  ->  {end.isoformat()}")
    print(f"Devices     : {sorted(telemetry.unified()['device'].unique())}")
    print(f"Users       : {sorted(telemetry.unified()['user'].unique())}")

    print("\n--- Events per table ---")
    for label, df in (
        (EVENT_PROCESS, telemetry.processes),
        (EVENT_NETWORK, telemetry.network),
        (EVENT_LOGON, telemetry.logons),
    ):
        print(f"  {label:<8} {len(df):>5}")

    print("\n--- Top 10 process names ---")
    _print_table(
        telemetry.processes["process_name"]
        .value_counts()
        .head(10)
        .rename_axis("process_name")
        .reset_index(name="count")
    )

    print("\n--- Logon outcomes by device ---")
    _print_table(
        telemetry.logons.groupby(["device", "action"])
        .size()
        .reset_index(name="count")
        .sort_values(["device", "action"])
    )
    return 0


def cmd_peek(args: argparse.Namespace, settings: Settings) -> int:
    """Show a slice of the unified, chronological event timeline."""
    telemetry = load_telemetry(settings.raw_data_dir)
    unified = telemetry.unified()

    if args.device:
        unified = unified[unified["device"] == args.device]
    if args.user:
        unified = unified[unified["user"] == args.user]
    if args.event_type:
        unified = unified[unified["event_type"] == args.event_type]

    if unified.empty:
        print("No events matched those filters.")
        return 1

    print(f"\n=== Timeline ({len(unified)} matching events, showing {args.limit}) ===")
    view = unified.head(args.limit).copy()
    view["timestamp"] = view["timestamp"].dt.strftime("%H:%M:%S")
    _print_table(view, max_rows=args.limit)
    return 0


# ======================================================================================
# Milestone 2 commands
# ======================================================================================


def cmd_rules(args: argparse.Namespace, settings: Settings) -> int:
    """List every registered detection rule and its declared caveats."""
    detectors = all_detectors()
    print(f"\n=== {len(detectors)} registered detection rules ===\n")
    for det in detectors:
        print(
            f"{_c(det.rule_id, 'BOLD')}  "
            f"[{_c(det.severity.value, det.severity.value)}]  {det.title}"
        )
        print(f"  {det.description}")
        if args.verbose:
            print(f"  {_c('fields:', 'DIM')} {', '.join(det.fields_used)}")
            print(f"  {_c('known false positives:', 'DIM')}")
            for fp in det.false_positives:
                print(f"    - {fp}")
        print()
    return 0


def _print_finding(
    finding, show_evidence: bool = True, show_mitre: bool = False
) -> None:
    """Render one finding, with its evidence, in analyst-readable form."""
    sev = finding.severity.value
    print(_c(f"[{sev}] {finding.rule_id}  {finding.title}", sev))
    print(f"  device     : {finding.device}")
    print(f"  user       : {finding.user}")
    if finding.first_seen == finding.last_seen:
        print(f"  observed   : {finding.first_seen.isoformat()}")
    else:
        span = int((finding.last_seen - finding.first_seen).total_seconds())
        print(
            f"  window     : {finding.first_seen.isoformat()} -> "
            f"{finding.last_seen.isoformat()}  ({span}s)"
        )
    print(f"  event_ids  : {', '.join(finding.event_ids)}")
    print(f"  reason     : {finding.reason}")

    if show_evidence:
        print(f"  {_c('evidence:', 'DIM')}")
        for ev in finding.evidence:
            print(
                f"    {ev.timestamp.strftime('%H:%M:%S')}  "
                f"{_c(ev.event_id, 'BOLD')}  {ev.summary}"
            )

    decoded = finding.metadata.get("decoded_command")
    if decoded:
        print(f"  {_c('decoded payload:', 'DIM')} {decoded}")

    if show_mitre:
        mappings = map_finding(finding)
        print(f"  {_c('ATT&CK (candidate interpretations):', 'DIM')}")
        for m in mappings or []:
            print(f"    {m.display}  [{m.tactic}]  confidence={m.confidence}")
        if not mappings:
            print("    (no mapping justified by the available evidence)")

    if finding.false_positives:
        print(f"  {_c('false positives to rule out:', 'DIM')}")
        for fp in finding.false_positives[:3]:
            print(f"    - {fp}")
    print()


def cmd_hunt(args: argparse.Namespace, settings: Settings) -> int:
    """Run detection rules over the telemetry and print findings."""
    telemetry = load_telemetry(settings.raw_data_dir)

    min_severity = Severity(args.min_severity.upper()) if args.min_severity else None
    rule_ids = [r.upper() for r in args.rule] if args.rule else None

    result = run_hunt(
        telemetry, rule_ids=rule_ids, config=HuntConfig(), min_severity=min_severity
    )

    findings = result.findings
    if args.device:
        findings = [f for f in findings if f.device == args.device]
    if args.user:
        findings = [f for f in findings if f.user == args.user]

    # Triage annotates; it never filters. A finding assessed as likely benign is still
    # printed, still counted, and still carries all its evidence -- what changes is that
    # the analyst is handed the counter-case instead of having to reconstruct it.
    triage = None
    if args.triage:
        triage = assess_findings(findings, build_environment_model(telemetry))

    if args.json:
        payload = dict(result.to_dict(), findings=[f.to_dict() for f in findings])
        if triage is not None:
            payload["triage"] = {
                "summary": triage_summary(triage),
                "assessments": [a.to_dict() for a in triage.values()],
            }
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"Wrote {len(findings)} findings -> {out}")
        return 0

    print(f"\n{_c('=== HUNT RESULTS ===', 'BOLD')}")
    print(f"Rules run  : {len(result.rules_run)} ({', '.join(result.rules_run)})")
    if result.errors:
        print(_c(f"Rule errors: {result.errors}", "HIGH"))
    print(f"Findings   : {len(findings)}")

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    if counts:
        ordered = sorted(counts.items(), key=lambda kv: -Severity(kv[0]).rank)
        print("Severity   : " + "  ".join(f"{_c(k, k)}={v}" for k, v in ordered))

    if triage is not None:
        summary = triage_summary(triage)
        print(
            "Triage     : "
            + f"{_c('likely malicious', 'HIGH')}={summary['likely_malicious']}  "
            + f"{_c('needs review', 'MEDIUM')}={summary['needs_review']}  "
            + f"{_c('likely benign', 'LOW')}={summary['likely_benign']}"
        )

    if not findings:
        print(
            "\nNo findings. (This is a valid result -- absence of alerts is not "
            "absence of compromise.)"
        )
        return 0

    if args.summary:
        print()
        _print_table(findings_to_frame(findings))
        return 0

    print()
    for finding in findings:
        _print_finding(
            finding,
            show_evidence=not args.no_evidence,
            show_mitre=getattr(args, "mitre", False),
        )
        if triage is not None:
            assessment = triage[finding.finding_id]
            colour = {
                "likely_malicious": "HIGH",
                "needs_review": "MEDIUM",
                "likely_benign": "LOW",
            }[assessment.disposition.value]
            label = assessment.disposition.value.replace("_", " ")
            print(f"  triage     : {_c(label, colour)}  (benign score "
                  f"{assessment.score}/{BENIGN_THRESHOLD})")
            for line in _wrap(assessment.explanation, width=86):
                print(f"    {line}")
            print()
    return 0


def _wrap(text: str, width: int = 86) -> list[str]:
    """Wrap a long explanation so it stays readable in a terminal."""
    import textwrap

    return textwrap.wrap(text, width=width) or [""]


# ======================================================================================
# Parser
# ======================================================================================


# ======================================================================================
# Milestone 3 commands
# ======================================================================================


def cmd_evaluate(args: argparse.Namespace, settings: Settings) -> int:
    """Measure detector quality against ground truth labels."""
    telemetry = load_telemetry(settings.raw_data_dir)
    result = run_hunt(telemetry, config=HuntConfig())
    report = evaluate(result, settings.raw_data_dir, total_events=telemetry.event_count)

    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"Wrote evaluation -> {out}")
        return 0

    print(f"\n{_c('=== DETECTOR EVALUATION ===', 'BOLD')}")
    print(f"{telemetry.event_count} events | ground truth used for scoring only\n")
    print(f"{'Rule':<10}{'TP':>4}{'FP':>4}{'FN':>4}{'Precision':>11}{'Recall':>9}{'F1':>7}   Notes")
    print("-" * 88)
    for ev in report.rules:
        notes = []
        if ev.fp_benign_lookalike:
            notes.append(f"{ev.fp_benign_lookalike} FP = benign look-alike")
        if ev.fp_unexplained:
            notes.append(_c(f"{ev.fp_unexplained} FP unexplained", "HIGH"))
        if ev.missed_stages:
            notes.append(f"missed: {', '.join(ev.missed_stages)}")
        print(
            f"{ev.rule_id:<10}{ev.true_positives:>4}{ev.false_positives:>4}"
            f"{ev.false_negatives:>4}{ev.precision:>11.2f}{ev.recall:>9.2f}"
            f"{ev.f1:>7.2f}   {'; '.join(notes)}"
        )

    print("-" * 88)
    print(
        f"{'OVERALL':<10}{report.total_true_positives:>4}"
        f"{report.total_false_positives:>4}{'':>4}{report.overall_precision:>11.2f}"
    )
    print(
        f"\nAttack-stage coverage: {len(report.covered_stages)}/"
        f"{len(report.covered_stages) + len(report.uncovered_stages)} "
        f"({report.stage_coverage:.0%})"
    )
    if report.uncovered_stages:
        print(f"  Not detected by any rule: {', '.join(report.uncovered_stages)}")
        for stage in report.uncovered_stages:
            if stage in UNCOVERED_STAGES:
                print(f"    - {stage}: no rule targets this stage (by design)")
            else:
                print(_c(f"    - {stage}: a rule targets this but MISSED it", "HIGH"))

    print(
        "\nPrecision is finding-level (one alert = one triage). Recall is "
        "opportunity-level\n(declared attack stages detected). See "
        "src/ath/evaluation/evaluator.py for why."
    )
    return 0


def _print_case(case, show_links: bool = False) -> None:
    """Render one investigation case as an analyst-readable timeline."""
    print(
        _c(f"{case.case_id}", "BOLD")
        + f"  [{_c(case.severity.value, case.severity.value)}]  "
        f"confidence={case.confidence}"
    )
    print(f"  window   : {case.start_time.isoformat()} -> {case.end_time.isoformat()} "
          f"({case.duration_seconds}s)")
    print(f"  hosts    : {', '.join(case.devices)}")
    print(f"  accounts : {', '.join(case.users)}")
    print(f"  tactics  : {' -> '.join(case.tactics) if case.tactics else '(none)'}")
    print(f"  events   : {len(case.event_ids)} telemetry events")
    print()
    header = (
        f"  {'time':<9}{'rule':<9}{'severity':<10}{'user':<11}"
        f"{'host / movement':<20}{'technique':<26}events"
    )
    print(_c(header, "DIM"))
    for entry in case.timeline():
        where = entry.movement or entry.device
        techniques = ",".join(entry.techniques) or "-"
        events = entry.event_ids[0] + (
            f" (+{len(entry.event_ids) - 1})" if len(entry.event_ids) > 1 else ""
        )
        print(
            f"  {entry.timestamp.strftime('%H:%M:%S'):<9}{entry.rule_id:<9}"
            f"{_c(entry.severity.value, entry.severity.value):<10}{entry.user:<11}"
            f"{where:<20}{techniques:<26}{events}"
        )

    if show_links:
        print(f"\n  {_c('why these findings were linked:', 'DIM')}")
        for link in case.links:
            marker = "structural" if link.structural else _c("circumstantial", "MEDIUM")
            print(f"    {link.left_id} -> {link.right_id}  [{marker}] "
                  f"score={link.score}: {', '.join(link.signals)}")

    print(f"\n  {_c('summary:', 'DIM')} {case.explain()}")
    print()


def cmd_chains(args: argparse.Namespace, settings: Settings) -> int:
    """Correlate findings into investigation cases and print their timelines."""
    telemetry = load_telemetry(settings.raw_data_dir)
    result = run_hunt(telemetry, config=HuntConfig())

    config = CorrelationConfig(
        min_score=args.min_score,
        require_structural=not args.allow_circumstantial,
    )
    # Findings triage explained still print under `hunt --triage`; they do not raise a
    # case on their own (M15-4).
    assessments = assess_findings(result.findings, build_environment_model(telemetry))
    cases = correlate(result.findings, telemetry, config, set_aside=set_aside_ids(assessments))

    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps([c.to_dict() for c in cases], indent=2), encoding="utf-8"
        )
        print(f"Wrote {len(cases)} case(s) -> {out}")
        return 0

    correlated = sum(len(c.findings) for c in cases)
    print(f"\n{_c('=== INVESTIGATION CASES ===', 'BOLD')}")
    print(
        f"{len(cases)} case(s) from {result.finding_count} findings "
        f"({correlated} correlated, {result.finding_count - correlated} isolated)"
    )
    print(f"ATT&CK {ATTACK_VERSION}\n")

    if not cases:
        print("No findings correlated into a chain.")
        return 0

    for case in cases:
        if args.case and case.case_id.upper() != args.case.upper():
            continue
        _print_case(case, show_links=args.explain)
    return 0


# ======================================================================================
# Parser
# ======================================================================================


# ======================================================================================
# Milestone 4 commands
# ======================================================================================


def _print_investigation(state, verbose: bool = False) -> None:
    """Render an investigation as an analyst-readable report."""
    status_colour = {
        "complete": "MEDIUM", "exhausted": "LOW", "step_limit": "HIGH",
    }.get(state.status.value, "DIM")

    print(_c(f"=== INVESTIGATION: {state.case.case_id} ===", "BOLD"))
    print(f"status     : {_c(state.status.value, status_colour)}")
    print(f"steps      : {state.step}  |  agents run: {', '.join(state.agents_run) or '(none)'}")
    print(
        f"claims     : {len(state.facts)} facts, {len(state.inferences)} inferences, "
        f"{len(state.hypotheses)} hypotheses"
    )
    if state.rejected_claims:
        print(_c(
            f"rejected   : {len(state.rejected_claims)} claim(s) failed verification "
            "(see --verbose)", "HIGH",
        ))
    print(f"tool calls : {len(state.tool_calls)}")
    if state.llm_degraded:
        # Loud, because the alternative is a run that looks exactly like a healthy
        # deterministic one while silently having lost the model it was configured
        # to use.
        print(_c(f"llm        : {state.llm_status}", "HIGH"))
    print()

    print(_c("-- investigation path --", "DIM"))
    for line in state.plan_log:
        print(f"  {line}")
    print()

    for claim_type, label, colour in (
        (ClaimType.FACT, "FACTS (from telemetry / deterministic detection)", "LOW"),
        (ClaimType.INFERENCE, "INFERENCES (evidence-supported conclusions)", "MEDIUM"),
        (ClaimType.HYPOTHESIS, "HYPOTHESES (unverified, flagged as such)", "HIGH"),
    ):
        claims = state.claims_of(claim_type)
        if not claims:
            continue
        print(_c(f"-- {label} ({len(claims)}) --", "BOLD"))
        for claim in claims:
            evidence = f"  [{', '.join(claim.evidence_ids)}]" if claim.evidence_ids else ""
            conf = f"  (confidence {claim.confidence:.2f})" if claim.confidence is not None else ""
            print(f"  {_c(claim_type.value, colour)}: {claim.statement}{conf}")
            if evidence:
                print(f"    {_c('evidence:', 'DIM')}{evidence}")
        print()

    if verbose and state.rejected_claims:
        print(_c("-- rejected claims (verification failures) --", "HIGH"))
        for rejected in state.rejected_claims:
            print(f"  {rejected.claim}")
            print(f"    reason: {rejected.reason}")
        print()

    if verbose:
        print(_c("-- tool calls --", "DIM"))
        for call in state.tool_calls:
            print(f"  {call}")
        print()


def cmd_investigate(args: argparse.Namespace, settings: Settings) -> int:
    """Run the autonomous investigation agent over one or all correlated cases."""
    telemetry = load_telemetry(settings.raw_data_dir)
    result = run_hunt(telemetry, config=HuntConfig())
    environment = build_environment_model(telemetry)
    assessments = assess_findings(result.findings, environment)
    cases = correlate(result.findings, telemetry, set_aside=set_aside_ids(assessments))

    if not cases:
        print("No correlated cases to investigate. Run `python main.py chains` first.")
        return 0

    if args.case:
        cases = [c for c in cases if c.case_id.upper() == args.case.upper()]
        if not cases:
            print(f"No such case {args.case!r}.")
            return 2

    tools = ToolBox(telemetry, result.findings, cases)
    verifier = ClaimVerifier(telemetry)
    llm = NullLLM() if args.no_llm else build_llm()
    if llm.available:
        print(f"Using LLM: {llm.name}")
    else:
        print("No LLM configured (or --no-llm passed) -- running in deterministic mode. "
              "The investigation still completes; see README for what this means.")

    config = InvestigationConfig(
        max_steps=args.max_steps,
        use_llm_planner=not args.no_llm,
        use_llm_synthesis=not args.no_llm,
    )
    # Deriving the environment lets a specialist decline because the telemetry it needs
    # is absent, rather than run and report nothing -- the distinction between "nothing
    # happened" and "we cannot see", carried into the investigation layer.
    orchestrator = InvestigationOrchestrator(
        tools, verifier, llm=llm, config=config, environment=environment,
    )

    all_states = []
    for case in cases:
        state = orchestrator.investigate(case)
        all_states.append(state)

    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps([s.to_dict() for s in all_states], indent=2), encoding="utf-8"
        )
        print(f"Wrote {len(all_states)} investigation(s) -> {out}")
        return 0

    for state in all_states:
        _print_investigation(state, verbose=args.verbose)
    return 0


# ======================================================================================
# Parser
# ======================================================================================


# ======================================================================================
# Milestone 5 commands
# ======================================================================================


def cmd_report(args: argparse.Namespace, settings: Settings) -> int:
    """Investigate case(s) and render a calibrated Markdown report for each."""
    telemetry = load_telemetry(settings.raw_data_dir)
    result = run_hunt(telemetry, config=HuntConfig())
    environment = build_environment_model(telemetry)
    assessments = assess_findings(result.findings, environment)
    cases = correlate(result.findings, telemetry, set_aside=set_aside_ids(assessments))

    if not cases:
        print("No correlated cases to report on. Run `python main.py chains` first.")
        return 0

    if args.case:
        cases = [c for c in cases if c.case_id.upper() == args.case.upper()]
        if not cases:
            print(f"No such case {args.case!r}.")
            return 2

    tools = ToolBox(telemetry, result.findings, cases)
    verifier = ClaimVerifier(telemetry)
    llm = NullLLM() if args.no_llm else build_llm()
    config = InvestigationConfig(
        max_steps=args.max_steps,
        use_llm_planner=not args.no_llm,
        use_llm_synthesis=not args.no_llm,
    )
    # Deriving the environment lets a specialist decline because the telemetry it needs
    # is absent, rather than run and report nothing -- the distinction between "nothing
    # happened" and "we cannot see", carried into the investigation layer.
    orchestrator = InvestigationOrchestrator(
        tools, verifier, llm=llm, config=config, environment=environment,
    )

    out_dir = Path(args.out_dir) if args.out_dir else settings.reports_dir
    written: list[Path] = []

    for case in cases:
        state = orchestrator.investigate(case)
        report = build_report(state, telemetry)

        # Calibration is checked at generation time, not just in tests: if a claim's
        # own wording ever slipped past the lint (e.g. a future specialist added
        # careless phrasing), the report says so loudly rather than shipping silently.
        issues = audit_calibration(list(report.all_claims))
        if issues:
            print(_c(
                f"WARNING: {len(issues)} claim(s) in {case.case_id} failed the "
                "calibration check (overclaiming/underclaiming language). See "
                "src/ath/reporting/language.py.", "HIGH",
            ))
            for statement, found in issues.items():
                print(f"  - {statement[:100]}...  [{', '.join(found)}]")

        markdown = render_markdown(report)

        if args.stdout or not out_dir:
            print(markdown)
            continue

        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{case.case_id}.md"
        path.write_text(markdown, encoding="utf-8")
        written.append(path)

        if args.json:
            json_path = out_dir / f"{case.case_id}.json"
            json_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
            written.append(json_path)

    for path in written:
        print(f"Wrote {path}")
    return 0


# ======================================================================================
# Parser
# ======================================================================================


# ======================================================================================
# Milestone 6 commands
# ======================================================================================


def cmd_engineer(args: argparse.Namespace, settings: Settings) -> int:
    """Run the detection-engineering loop: propose candidate rules, evaluate, iterate."""
    telemetry = load_telemetry(settings.raw_data_dir)
    reports = propose_and_iterate(telemetry, settings.raw_data_dir)

    if not reports:
        print("No candidate rules to propose.")
        return 0

    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps([r.to_dict() for r in reports], indent=2), encoding="utf-8"
        )
        print(f"Wrote {len(reports)} iteration report(s) -> {out}")
        return 0

    print(f"\n{_c('=== DETECTION ENGINEERING: propose -> evaluate -> iterate ===', 'BOLD')}")
    print(
        "Ground truth is used here ONLY to score candidates -- never to generate them. "
        "See src/ath/engineering/candidates.py.\n"
    )

    for report in reports:
        print(_c(f"--- Gap: {report.target_stage} ---", "BOLD"))
        for label, result in (("v1", report.v1), ("v2", report.v2)):
            ev = result.evaluation
            print(
                f"  {label} [{result.candidate.candidate_id}] {result.candidate.title}"
            )
            print(
                f"      TP={ev.true_positives}  FP={ev.false_positives}  "
                f"precision={ev.precision:.2f}  stage_covered="
                f"{report.target_stage in ev.detected_stages}"
            )
            if result.false_positive_examples:
                print(f"      {_c('false positive examples:', 'DIM')}")
                for example in result.false_positive_examples[:3]:
                    print(f"        - {example}")
        print(f"  {_c('verdict:', 'DIM')} {report.verdict}")
        if report.promoted:
            print(f"  {_c('status:', 'DIM')} promoted to permanent rule {report.promoted_as}")
        print()

    return 0


# ======================================================================================
# Parser
# ======================================================================================


# ======================================================================================
# Telemetry ingestion commands
# ======================================================================================


def _print_admission(result: SourceLoadResult) -> None:
    """Print which candidate files the adapter vouched for, and which it refused.

    Printed *before* the row counts, because it is what those counts are counts of: a
    refused file contributes no rows read and no normalisation issues, so an import that
    silently skipped half a directory would otherwise look like a clean, small import.
    """
    if not result.admitted_files:
        return
    refused = result.rejected_files
    admitted = len(result.admitted_files) - len(refused)
    print(f"  files    {admitted} admitted, {len(refused)} rejected")
    for refusal in refused[:20]:
        print(
            f"    {_c('x', 'HIGH')} {refusal.path}: {refusal.reason} "
            f"({refusal.line_or_record_count} record(s) not read)"
        )
    if len(refused) > 20:
        print(f"    ... and {len(refused) - 20} more")


def cmd_import_defender(args: argparse.Namespace, settings: Settings) -> int:
    """Normalize a real Microsoft Defender advanced-hunting export into canonical telemetry."""
    directory = Path(args.directory) if args.directory else None
    source = DefenderExportSource(
        directory=directory,
        process_path=Path(args.process) if args.process else None,
        network_path=Path(args.network) if args.network else None,
        logon_path=Path(args.logon) if args.logon else None,
    )
    result = source.load()

    out_dir = Path(args.out_dir) if args.out_dir else settings.raw_data_dir
    written = write_normalized_telemetry(result, out_dir)

    print(f"\n{_c('=== DEFENDER EXPORT IMPORT ===', 'BOLD')}")
    print(result.summary())
    _print_admission(result)
    for event_type in ("process", "network", "logon"):
        df = result.tables.get(event_type)
        print(f"  {event_type:<8} {len(df) if df is not None else 0:>5} row(s)")

    if result.issues:
        print(f"\n{_c(f'{len(result.issues)} row(s) dropped during normalization:', 'HIGH')}")
        for issue in result.issues[:20]:
            print(f"  - {issue}")
        if len(result.issues) > 20:
            print(f"  ... and {len(result.issues) - 20} more")

    print(f"\nWrote {len(written)} file(s) -> {out_dir}")
    print(
        "\nNote: real imports carry no ground-truth labels, so `python main.py "
        "evaluate` cannot score this dataset -- hunt/chains/investigate/report all "
        "work normally."
    )
    return 0


# ======================================================================================
# Parser
# ======================================================================================


def cmd_import_cloudtrail(args: argparse.Namespace, settings: Settings) -> int:
    """Normalize an AWS CloudTrail export into canonical telemetry."""
    result = CloudTrailSource(directory=Path(args.directory)).load()

    out_dir = Path(args.out_dir) if args.out_dir else settings.raw_data_dir
    written = write_normalized_telemetry(result, out_dir)

    print(f"\n{_c('=== CLOUDTRAIL IMPORT ===', 'BOLD')}")
    print(result.summary())
    _print_admission(result)
    for event_type in ("process", "network", "logon", "control"):
        df = result.tables.get(event_type)
        print(f"  {event_type:<8} {len(df) if df is not None else 0:>5} row(s)")

    if result.issues:
        # Headed "unmapped", not "dropped": most of these are events the canonical
        # schema has no representation for, which is a fact about the schema rather
        # than a defect in the export. Reporting them as errors would be misleading.
        print(f"\n{_c(f'{len(result.issues)} record(s) not mapped:', 'MEDIUM')}")
        for issue in result.issues[:20]:
            print(f"  - {issue}")
        if len(result.issues) > 20:
            print(f"  ... and {len(result.issues) - 20} more")

    print(f"\nWrote {len(written)} file(s) -> {out_dir}")
    print(
        "\nNote: authentication maps to logon events; policy/access-key/logging "
        "management activity maps to control events. Only the AUTH_EVENTS / "
        "MANAGEMENT_EVENTS this adapter names are mapped -- everything else is "
        "reported above rather than coerced. Run `python main.py visibility` to see "
        "the resulting posture."
    )
    return 0


def cmd_import_k8s_audit(args: argparse.Namespace, settings: Settings) -> int:
    """Normalize a Kubernetes API server audit log into canonical telemetry."""
    result = K8sAuditSource(directory=Path(args.directory), cluster=args.cluster).load()

    out_dir = Path(args.out_dir) if args.out_dir else settings.raw_data_dir
    written = write_normalized_telemetry(result, out_dir)

    print(f"\n{_c('=== KUBERNETES AUDIT IMPORT ===', 'BOLD')}")
    print(result.summary())
    _print_admission(result)
    for event_type in ("process", "network", "logon", "control"):
        df = result.tables.get(event_type)
        print(f"  {event_type:<8} {len(df) if df is not None else 0:>5} row(s)")

    if result.issues:
        print(f"\n{_c(f'{len(result.issues)} record(s) not mapped:', 'MEDIUM')}")
        for issue in result.issues[:20]:
            print(f"  - {issue}")
        if len(result.issues) > 20:
            print(f"  ... and {len(result.issues) - 20} more")

    print(f"\nWrote {len(written)} file(s) -> {out_dir}")
    print(
        "\nNote: only RBAC-binding creation and pod-exec map to control events -- "
        "everything else is reported above rather than coerced. Run `python main.py "
        "visibility` to see the resulting posture."
    )
    return 0


def _feedback_store(settings: Settings, override: str | None = None) -> FeedbackStore:
    path = Path(override) if override else settings.raw_data_dir / FEEDBACK_FILENAME
    return FeedbackStore(path)


def cmd_feedback(args: argparse.Namespace, settings: Settings) -> int:
    """Record an analyst verdict, or report how well triage matched past verdicts."""
    store = _feedback_store(settings, args.store)

    if args.finding_id:
        # Recording a verdict re-derives what triage currently says, so agreement is
        # scored against a real disposition rather than an assumed one.
        telemetry = load_telemetry(settings.raw_data_dir)
        findings = run_hunt(telemetry, config=HuntConfig()).findings
        assessments = assess_findings(findings, build_environment_model(telemetry))
        assessment = assessments.get(args.finding_id)
        if assessment is None:
            print(_c(f"No such finding {args.finding_id!r}.", "HIGH"))
            print("Run `python main.py hunt --triage` to list current finding ids.")
            return 2
        store.record(verdict_from_assessment(
            assessment, Verdict(args.verdict), args.analyst, args.note or ""
        ))
        print(
            f"Recorded {_c(args.verdict, 'BOLD')} for {args.finding_id} "
            f"(triage said: {assessment.disposition.value}) -> {store.path}"
        )
        return 0

    verdicts = store.current()
    if not verdicts:
        print(f"No analyst feedback recorded yet ({store.path}).")
        print(
            "Record one with:  python main.py feedback --finding-id <id> "
            "--verdict false_positive --analyst <name>"
        )
        return 0

    metrics = score_feedback(verdicts.values())
    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(metrics.to_dict(), indent=2), encoding="utf-8")
        print(f"Wrote feedback metrics -> {out}")
        return 0

    print(f"\n{_c('=== ANALYST FEEDBACK ===', 'BOLD')}")
    print(f"  verdicts recorded : {metrics.total}")
    for name, count in sorted(metrics.by_verdict.items()):
        print(f"    {name:<22} {count}")
    print()
    # Reported together on purpose: a layer that abstains from everything scores a
    # perfect agreement rate while being useless.
    print(
        f"  agreement         : {metrics.agreement_rate:.0%} "
        f"({metrics.agreed}/{metrics.scored} where triage took a position)"
    )
    print(
        f"  opinion rate      : {metrics.opinion_rate:.0%} "
        f"({metrics.scored}/{metrics.total}; "
        f"{metrics.system_had_no_opinion} left as needs-review)"
    )

    if metrics.dangerous_disagreements:
        print()
        print(_c(
            f"  {len(metrics.dangerous_disagreements)} finding(s) called BENIGN that an "
            "analyst confirmed as real threats:", "HIGH",
        ))
        for finding_id in metrics.dangerous_disagreements:
            print(_c(f"    - {finding_id}", "HIGH"))

    if metrics.noisiest_rules:
        print()
        print(_c("  measured false-positive cost by rule:", "DIM"))
        for rule_id, count in metrics.noisiest_rules:
            print(f"    {rule_id}  {count} analyst-confirmed false positive(s)")
    return 0


def cmd_benchmark(args: argparse.Namespace, settings: Settings) -> int:
    """Run the incident suite end to end and report what an analyst would receive."""
    cloudtrail = Path(args.cloudtrail) if args.cloudtrail else (
        PROJECT_ROOT / "tests" / "fixtures" / "cloudtrail"
    )
    k8s_audit = Path(args.k8s_audit) if args.k8s_audit else (
        PROJECT_ROOT / "tests" / "fixtures" / "k8s_audit"
    )
    incidents = standard_suite(settings.raw_data_dir, cloudtrail, k8s_audit)
    llm = build_llm() if getattr(args, "llm", False) else NullLLM()
    if getattr(args, "llm", False) and not llm.available:
        print(_c(
            "--llm requested but no LLM is configured (set ATH_LLM_API_KEY); "
            "running the deterministic arm and labelling it as such.", "HIGH",
        ))
    result = run_benchmark(incidents, llm=llm)

    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        print(f"Wrote benchmark -> {out}")
        return 0

    print(f"\n{_c('=== INCIDENT BENCHMARK ===', 'BOLD')}\n")
    for outcome in result.outcomes:
        incident = outcome.incident
        verdict = _c("PASS", "LOW") if outcome.passed else _c("FAIL", "HIGH")
        arm = outcome.configuration + (" (DEGRADED)" if outcome.llm_degraded else "")
        print(f"{_c(incident.incident_id, 'BOLD')}  {incident.name}   [{verdict}]  arm={arm}")
        print(f"  {_c(incident.description, 'DIM')}")

        if incident.is_benign:
            print(
                f"  expected silence; produced {outcome.findings} finding(s) "
                f"in {outcome.cases} case(s), "
                f"{outcome.findings_after_triage} left after triage"
            )
        else:
            print(
                f"  detection : {'yes' if outcome.detected else 'NO'}  |  "
                f"event recall {outcome.event_recall:.0%} "
                f"({outcome.malicious_events_surfaced}/"
                f"{outcome.malicious_events_total})"
            )
            print(
                f"  chain     : the incident landed in one case at "
                f"{outcome.primary_case_recall:.0%} recall, "
                f"{outcome.primary_case_purity:.0%} purity"
            )
        print(
            f"  load      : {outcome.findings} finding(s) -> {outcome.cases} case(s)"
            f"  (triage reduction {outcome.triage_reduction:.0%}, "
            f"{outcome.noise_cases} noise case(s), "
            f"case precision {outcome.case_precision:.0%})"
        )
        print(
            f"  claims    : {outcome.facts} fact, {outcome.inferences} inference, "
            f"{outcome.hypotheses} hypothesis  |  "
            f"{outcome.tool_calls} tool call(s), {outcome.runtime_seconds:.2f}s"
        )
        if outcome.benign_findings_total or outcome.malicious_findings_called_benign:
            wrong = outcome.malicious_findings_called_benign
            print(
                f"  triage    : {outcome.benign_findings_identified}/"
                f"{outcome.benign_findings_total} false positive(s) explained as benign"
                f"  ({outcome.findings} -> {outcome.findings_after_triage} to review)"
                + (_c(f"  [{wrong} TRUE POSITIVE CALLED BENIGN]", "HIGH") if wrong else "")
            )
        trust = "clean" if outcome.trustworthy else "PROBLEM"
        print(
            f"  trust     : {trust} -- {outcome.hallucinated_citations} fabricated "
            f"citation(s), {outcome.calibration_warnings} calibration warning(s), "
            f"{len(outcome.overclaimed_as_fact)} overclaim(s)"
        )
        if outcome.techniques_missing:
            print(_c(f"  missing   : {', '.join(outcome.techniques_missing)}", "HIGH"))
        if outcome.conclusions_missed:
            print(_c(
                f"  not concluded: {', '.join(outcome.conclusions_missed)}", "HIGH"
            ))
        for note in outcome.notes:
            print(_c(f"  note      : {note}", "MEDIUM"))
        print()

    print(_c(
        f"{result.passed}/{result.total} incident(s) met their success condition; "
        f"{result.total_noise_cases} noise case(s) across the suite",
        "BOLD",
    ))
    return 0 if args.no_fail else (0 if result.all_passed else 1)


# ======================================================================================
# Milestone 8 commands: environment understanding and visibility
# ======================================================================================


def cmd_environment(args: argparse.Namespace, settings: Settings) -> int:
    """Describe the environment, including what could not be determined."""
    telemetry = load_telemetry(settings.raw_data_dir)
    env = build_environment_model(telemetry)

    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(env.to_dict(), indent=2), encoding="utf-8")
        print(f"Wrote environment model -> {out}")
        return 0

    print(_c("=== ENVIRONMENT MODEL ===", "BOLD"))
    print(f"platform    : {env.platform}  ({env.platform_reason})")
    if env.platforms:
        print(f"platforms   : {', '.join(sorted(env.platforms))}")
    print(f"sources     : {', '.join(env.data_sources) or 'unknown'}")
    print(
        f"observed    : {env.event_count} events over "
        f"{env.observation_hours:.1f}h"
    )
    print(f"hosts       : {len(env.hosts)}   identities: {len(env.identities)}")
    print()

    print(_c("-- hosts --", "DIM"))
    for host in env.hosts.values():
        print(f"  {host.name:<8} {_c(host.role, 'MEDIUM'):<24} {host.role_reason}")
    print()

    print(_c("-- identities --", "DIM"))
    for identity in env.identities.values():
        print(f"  {identity.name:<12} {identity.kind:<12} {identity.kind_reason}")
        for signal in identity.privileged_signals:
            print(f"    {_c('privilege signal:', 'HIGH')} {signal}")
    print()

    if env.security_controls:
        print(_c("-- security controls observed --", "DIM"))
        for image, product in sorted(env.security_controls.items()):
            print(f"  {product}  ({image})")
        print()

    # The most important section: printed last so it is what the reader leaves with.
    print(_c("-- NOT determinable from this telemetry --", "HIGH"))
    for unknown in env.undetermined:
        print(f"  - {unknown}")
    return 0


def cmd_crew(args: argparse.Namespace, settings: Settings) -> int:
    """Assemble the specialist crew for an environment, and show what got excluded.

    The visible artifact for Milestone 13's central claim: run this against a
    Windows-only environment, a cloud/Kubernetes-only one, and a hybrid of all three
    (by passing more than one telemetry flag at once), and see three different,
    capability-derived crews -- not the same roster relabeled.
    """
    sets: list[Telemetry] = []
    sources_described: list[str] = []

    if not args.no_windows:
        try:
            sets.append(load_telemetry(settings.raw_data_dir))
            sources_described.append(f"windows synthetic/imported ({settings.raw_data_dir})")
        except FileNotFoundError:
            if not (args.cloudtrail or args.k8s_audit):
                raise

    if args.cloudtrail:
        result = CloudTrailSource(Path(args.cloudtrail)).load()
        sets.append(Telemetry(
            processes=result.tables["process"], network=result.tables["network"],
            logons=result.tables["logon"], controls=result.tables["control"],
        ))
        sources_described.append(f"cloudtrail ({args.cloudtrail})")

    if args.k8s_audit:
        result = K8sAuditSource(Path(args.k8s_audit), cluster=args.cluster).load()
        sets.append(Telemetry(
            processes=result.tables["process"], network=result.tables["network"],
            logons=result.tables["logon"], controls=result.tables["control"],
        ))
        sources_described.append(f"k8s-audit ({args.k8s_audit}, cluster={args.cluster})")

    if not sets:
        print(_c(
            "No telemetry sources selected. Pass --cloudtrail/--k8s-audit, or drop "
            "--no-windows to use the local dataset.", "HIGH",
        ))
        return 1

    telemetry = sets[0] if len(sets) == 1 else merge_telemetry(sets)
    environment = build_environment_model(telemetry)
    tools = ToolBox(telemetry, findings=[], cases=[])
    crew = assemble_crew(environment, tools)

    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(crew.to_dict(), indent=2), encoding="utf-8")
        print(f"Wrote crew -> {out}")
        return 0

    print(_c("=== ASSEMBLED CREW ===", "BOLD"))
    print(f"sources    : {', '.join(sources_described)}")
    print(f"platforms  : {', '.join(sorted(environment.platforms)) or 'unknown'}")
    by_id = {spec.id: spec for spec in CAPABILITY_REGISTRY}
    print(f"\nstanding up ({len(crew.specialists)}):")
    for specialist in crew.specialists:
        print(f"  {_c('+', 'LOW')} {specialist.name:<14} {by_id[specialist.name].description}")
    print(f"\nexcluded ({len(crew.excluded)}):")
    for spec, reason in crew.excluded:
        print(f"  {_c('-', 'HIGH')} {spec.id:<14} {reason}")
    return 0


def cmd_visibility(args: argparse.Namespace, settings: Settings) -> int:
    """Report telemetry channel availability and the four-state ATT&CK coverage split."""
    telemetry = load_telemetry(settings.raw_data_dir)
    env = build_environment_model(telemetry)
    report = assess_coverage(env)

    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"Wrote coverage report -> {out}")
        return 0

    provenance = report.provenance
    print(_c("=== ASSESSED ENVIRONMENT ===", "BOLD"))
    print(
        f"  sources: {', '.join(provenance['data_sources']) or 'unknown'}  |  "
        f"platform: {provenance['platform']}  |  "
        f"{provenance['hosts']} host(s), {provenance['identities']} identity(ies)"
    )
    print(
        f"  {provenance['event_count']} events over "
        f"{provenance['observation_hours']}h  |  "
        f"{provenance['rules_assessed']} rule(s), "
        f"{provenance['techniques_assessed']} technique(s) assessed"
    )
    print()

    print(_c("=== TELEMETRY CHANNELS ===", "BOLD"))
    colours = {
        ChannelState.AVAILABLE: "LOW",
        ChannelState.PARTIAL: "MEDIUM",
        ChannelState.ABSENT_IN_DATA: "HIGH",
        ChannelState.ABSENT_BY_SCHEMA: "HIGH",
    }
    for assessment in env.channels.values():
        state = _c(assessment.state.value, colours[assessment.state])
        print(f"  {assessment.channel.value:<26} {state:<28} {assessment.detail}")
    print()

    print(_c("=== DETECTION SUPPORT ===", "BOLD"))
    # Three separate measurements, printed as three separate things: eligibility (are
    # there rows at all), usability (are the fields this rule filters on populated),
    # and the channel verdict. A rule whose required field is empty is reported here,
    # never as a silent zero in the hunt output.
    verdict_colours = {
        RuleVerdict.USABLE: "LOW",
        RuleVerdict.DEGRADED: "MEDIUM",
        RuleVerdict.UNUSABLE: "HIGH",
        RuleVerdict.NOT_ELIGIBLE: "MEDIUM",
    }
    for rule in report.rules:
        if rule.verdict is RuleVerdict.USABLE and not args.all:
            continue
        verdict = _c(rule.verdict.value, verdict_colours[rule.verdict])
        print(
            f"  {rule.rule_id}  {verdict} "
            f"[channels: {rule.support.value}, {rule.eligible_rows} eligible row(s)]: "
            f"{rule.detail}"
        )
        named = set(rule.sparse_fields)
        for usability in rule.fields:
            if usability.column in named or args.all:
                requirement = "required" if usability.required else "optional"
                print(
                    f"      {usability.column:<22} "
                    f"{usability.population.populated:>9,} of "
                    f"{usability.population.rows:<9,} {usability.table} row(s)  "
                    f"{usability.fraction:>8.2%}  ({requirement})"
                )
    if all(r.verdict is RuleVerdict.USABLE for r in report.rules) and not args.all:
        print("  every rule's declared fields are populated "
              "(use --all to list per-rule detail)")
    print()

    counts = report.counts
    print(_c("=== ATT&CK COVERAGE ===", "BOLD"))
    print(
        f"  detectable {counts['detectable']}  |  "
        f"observable but undetected {counts['observable_undetected']}  |  "
        f"unverifiable {counts['unverifiable']}  |  "
        f"unobservable {counts['unobservable']}"
    )
    print()

    for state, colour, heading in (
        (CoverageState.OBSERVABLE_UNDETECTED, "MEDIUM",
         "OBSERVABLE BUT UNDETECTED -- the data is already here; write a rule"),
        (CoverageState.UNVERIFIABLE, "HIGH",
         "UNVERIFIABLE -- a rule exists but its telemetry does not"),
        (CoverageState.UNOBSERVABLE, "HIGH",
         "UNOBSERVABLE -- no rule can close these; onboard telemetry"),
        (CoverageState.DETECTABLE, "LOW", "DETECTABLE -- covered"),
    ):
        entries = report.in_state(state)
        if not entries or (state is CoverageState.DETECTABLE and not args.all):
            continue
        print(_c(f"-- {heading} ({len(entries)}) --", colour))
        for coverage in entries:
            entry = coverage.entry
            line = f"  {entry.technique_id:<24} {entry.name}  [{entry.tactic}]"
            if coverage.missing_channels:
                line += f"\n      needs: {', '.join(c.value for c in coverage.missing_channels)}"
            if coverage.covering_rules:
                line += f"\n      rules: {', '.join(coverage.covering_rules)}"
            if coverage.degraded_rules:
                line += f"  ({_c('degraded', 'MEDIUM')}: "
                line += f"{', '.join(coverage.degraded_rules)})"
            print(line)
            if entry.note:
                print(f"      {_c(entry.note, 'DIM')}")
        print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="ath",
        description="Agentic Threat Hunter -- telemetry, hunting and AI investigation.",
    )
    parser.add_argument(
        "--log-level", default=None,
        help="Override log level (DEBUG, INFO, WARNING, ERROR).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_gen = sub.add_parser("generate", help="Generate the synthetic telemetry dataset.")
    p_gen.add_argument("--seed", type=int, default=1337, help="RNG seed (default: 1337).")
    p_gen.set_defaults(func=cmd_generate)

    p_stats = sub.add_parser("stats", help="Summarise the generated telemetry.")
    p_stats.set_defaults(func=cmd_stats)

    p_peek = sub.add_parser("peek", help="Show a slice of the unified event timeline.")
    p_peek.add_argument("--device", help="Filter by device, e.g. PC01.")
    p_peek.add_argument("--user", help="Filter by user, e.g. jdoe.")
    p_peek.add_argument(
        "--event-type", choices=[EVENT_PROCESS, EVENT_NETWORK, EVENT_LOGON],
        help="Filter by event type.",
    )
    p_peek.add_argument("--limit", type=int, default=25, help="Rows to display.")
    p_peek.set_defaults(func=cmd_peek)

    p_rules = sub.add_parser("rules", help="List registered detection rules.")
    p_rules.add_argument(
        "-v", "--verbose", action="store_true",
        help="Also show required fields and known false positives.",
    )
    p_rules.set_defaults(func=cmd_rules)

    p_hunt = sub.add_parser("hunt", help="Run detections over the telemetry.")
    p_hunt.add_argument(
        "--rule", action="append",
        help="Run only this rule, e.g. --rule ATH-001. Repeatable.",
    )
    p_hunt.add_argument("--device", help="Show only findings for this device.")
    p_hunt.add_argument("--user", help="Show only findings for this user.")
    p_hunt.add_argument(
        "--min-severity", choices=[s.value.lower() for s in Severity],
        help="Drop findings below this severity.",
    )
    p_hunt.add_argument(
        "--summary", action="store_true",
        help="Print a compact table instead of full detail.",
    )
    p_hunt.add_argument(
        "--no-evidence", action="store_true",
        help="Hide the per-event evidence lines.",
    )
    p_hunt.add_argument(
        "--mitre", action="store_true",
        help="Show candidate MITRE ATT&CK mappings for each finding.",
    )
    p_hunt.add_argument("--json", metavar="PATH", help="Write findings to a JSON file.")
    p_hunt.add_argument(
        "--triage", action="store_true",
        help="Assess each finding for evidence of legitimate activity (never filters).",
    )
    p_hunt.set_defaults(func=cmd_hunt)

    p_eval = sub.add_parser("evaluate", help="Measure detectors against ground truth.")
    p_eval.add_argument("--json", metavar="PATH", help="Write the report as JSON.")
    p_eval.set_defaults(func=cmd_evaluate)

    p_chains = sub.add_parser(
        "chains", help="Correlate findings into investigation cases."
    )
    p_chains.add_argument("--case", help="Show only this case, e.g. CASE-001.")
    p_chains.add_argument(
        "--explain", action="store_true",
        help="Show why each pair of findings was linked.",
    )
    p_chains.add_argument(
        "--min-score", type=int, default=5,
        help="Link score threshold (default: 5).",
    )
    p_chains.add_argument(
        "--allow-circumstantial", action="store_true",
        help="Permit links with no structural evidence -- demonstrates the naive "
             "time-based behaviour this correlator exists to avoid.",
    )
    p_chains.add_argument("--json", metavar="PATH", help="Write cases as JSON.")
    p_chains.set_defaults(func=cmd_chains)

    p_inv = sub.add_parser(
        "investigate", help="Run the autonomous investigation agent over case(s)."
    )
    p_inv.add_argument("--case", help="Investigate only this case, e.g. CASE-001.")
    p_inv.add_argument(
        "--no-llm", action="store_true",
        help="Force deterministic mode even if an API key is configured.",
    )
    p_inv.add_argument(
        "--max-steps", type=int, default=8, help="Specialist step budget (default: 8)."
    )
    p_inv.add_argument(
        "-v", "--verbose", action="store_true",
        help="Also show rejected claims and every tool call made.",
    )
    p_inv.add_argument("--json", metavar="PATH", help="Write investigations to JSON.")
    p_inv.set_defaults(func=cmd_investigate)

    p_report = sub.add_parser(
        "report", help="Investigate case(s) and render a calibrated Markdown report."
    )
    p_report.add_argument("--case", help="Report only this case, e.g. CASE-001.")
    p_report.add_argument(
        "--no-llm", action="store_true",
        help="Force deterministic mode even if an API key is configured.",
    )
    p_report.add_argument(
        "--max-steps", type=int, default=8, help="Specialist step budget (default: 8)."
    )
    p_report.add_argument(
        "--out-dir", metavar="DIR",
        help="Directory to write reports to (default: ./reports).",
    )
    p_report.add_argument(
        "--stdout", action="store_true", help="Print to stdout instead of writing files."
    )
    p_report.add_argument(
        "--json", action="store_true",
        help="Also write the structured report as JSON alongside the Markdown.",
    )
    p_report.set_defaults(func=cmd_report)

    p_engineer = sub.add_parser(
        "engineer", help="Run the detection-engineering loop (propose/evaluate/iterate)."
    )
    p_engineer.add_argument("--json", metavar="PATH", help="Write iteration reports as JSON.")
    p_engineer.set_defaults(func=cmd_engineer)

    p_import = sub.add_parser(
        "import-defender",
        help="Normalize a real Microsoft Defender advanced-hunting export.",
    )
    p_import.add_argument(
        "directory", nargs="?",
        help="Directory containing DeviceProcessEvents/DeviceNetworkEvents/"
             "DeviceLogonEvents export files (CSV or JSON, discovered by name).",
    )
    p_import.add_argument("--process", help="Explicit path to a DeviceProcessEvents export.")
    p_import.add_argument("--network", help="Explicit path to a DeviceNetworkEvents export.")
    p_import.add_argument("--logon", help="Explicit path to a DeviceLogonEvents export.")
    p_import.add_argument(
        "--out-dir", metavar="DIR",
        help="Where to write normalized telemetry (default: ./data/raw).",
    )
    p_import.set_defaults(func=cmd_import_defender)

    p_ct = sub.add_parser(
        "import-cloudtrail",
        help="Normalize an AWS CloudTrail export into canonical telemetry.",
    )
    p_ct.add_argument("directory", help="Directory of CloudTrail *.json files.")
    p_ct.add_argument("--out-dir", metavar="PATH", help="Where to write canonical CSVs.")
    p_ct.set_defaults(func=cmd_import_cloudtrail)

    p_k8s = sub.add_parser(
        "import-k8s-audit",
        help="Normalize a Kubernetes API server audit log into canonical telemetry.",
    )
    p_k8s.add_argument("directory", help="Directory of Kubernetes audit *.json files.")
    p_k8s.add_argument(
        "--cluster", default="default",
        help="Cluster identifier used to synthesise the device column (default: 'default').",
    )
    p_k8s.add_argument("--out-dir", metavar="PATH", help="Where to write canonical CSVs.")
    p_k8s.set_defaults(func=cmd_import_k8s_audit)

    p_env = sub.add_parser(
        "environment",
        help="Describe the environment this telemetry came from, and what it cannot show.",
    )
    p_env.add_argument("--json", metavar="PATH", help="Write the model as JSON.")
    p_env.set_defaults(func=cmd_environment)

    p_crew = sub.add_parser(
        "crew",
        help="Assemble the specialist crew for an environment, and show what got excluded.",
    )
    p_crew.add_argument(
        "--no-windows", action="store_true",
        help="Exclude the local Windows synthetic/imported dataset.",
    )
    p_crew.add_argument("--cloudtrail", metavar="PATH", help="Include a CloudTrail export.")
    p_crew.add_argument("--k8s-audit", metavar="PATH", help="Include a Kubernetes audit log.")
    p_crew.add_argument(
        "--cluster", default="default",
        help="Cluster identifier for --k8s-audit (default: 'default').",
    )
    p_crew.add_argument("--json", metavar="PATH", help="Write the assembled crew as JSON.")
    p_crew.set_defaults(func=cmd_crew)

    p_vis = sub.add_parser(
        "visibility",
        help="Telemetry channels and ATT&CK coverage: detectable / undetected / unobservable.",
    )
    p_vis.add_argument("--json", metavar="PATH", help="Write the coverage report as JSON.")
    p_vis.add_argument(
        "--all", action="store_true",
        help="List every assessed technique, not just gaps.",
    )
    p_vis.set_defaults(func=cmd_visibility)

    p_bench = sub.add_parser(
        "benchmark",
        help="Run the incident suite end to end and measure what an analyst receives.",
    )
    p_bench.add_argument("--json", metavar="PATH", help="Write results as JSON.")
    p_bench.add_argument("--cloudtrail", metavar="PATH",
                         help="Directory of CloudTrail JSON for the cloud incident.")
    p_bench.add_argument("--k8s-audit", metavar="PATH",
                         help="Directory of Kubernetes audit JSON for the K8s incident.")
    p_bench.add_argument("--no-fail", action="store_true",
                         help="Always exit 0, even when an incident misses its bar.")
    p_bench.add_argument("--llm", action="store_true",
                         help="Run the LLM arm: the identical pipeline with the configured "
                              "model planning and synthesising. Results are recorded, not "
                              "reproducible; see docs/m14-data-acquisition-plan.md 5.1.")
    p_bench.set_defaults(func=cmd_benchmark)

    p_fb = sub.add_parser(
        "feedback",
        help="Record an analyst verdict, or report triage agreement with past verdicts.",
    )
    p_fb.add_argument("--finding-id", help="Finding to record a verdict for.")
    p_fb.add_argument(
        "--verdict", choices=[v.value for v in Verdict],
        help="What the analyst concluded.",
    )
    p_fb.add_argument("--analyst", default="unknown", help="Who decided.")
    p_fb.add_argument("--note", help="Free-text rationale.")
    p_fb.add_argument("--store", metavar="PATH", help="Feedback log location.")
    p_fb.add_argument("--json", metavar="PATH", help="Write metrics as JSON.")
    p_fb.set_defaults(func=cmd_feedback)

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    settings = load_settings()
    setup_logging(args.log_level or settings.log_level)

    try:
        return int(args.func(args, settings))
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 2
    except KeyError as exc:
        # Unknown rule id: a caller error, reported clearly rather than as a crash.
        logger.error("%s", exc)
        return 2
    except Exception:  # noqa: BLE001 -- top-level guard, full trace goes to the log
        logger.exception("Unhandled error while running %r", args.command)
        return 1


if __name__ == "__main__":
    sys.exit(main())
