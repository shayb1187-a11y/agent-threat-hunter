"""One model's rows into numbers: per row, per run, rendered.

Every number is read from what the run recorded -- integers and sets, never prose. The
``summarise`` command refuses to report ``rows_written 0`` while row files sit beside
the target directory under another manifest or prompt version: that is exactly what
the 2026-09-18 Colab session did, and the summary it wrote looked like an empty run.
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from ath.evaluation.ablation import CaseManifest
from ath.evaluation.ablation.local import GIB, completed_rows, investigator_environment
from ath.evaluation.ablation.scoring import planner_activation, scores_from_dict
from ath.experiments.freeze import write_json, write_text
from ath.experiments.manifest_build import head, read_manifest
from ath.experiments.paths import ROOT, Layout
from ath.experiments.runner import guard_events
from ath.experiments.runs import RunRecord, now

COMPLETION_TARGET = 0.95
"""The V1 guardrail: completed-case rate >= 95 %."""
CORRECTNESS_FLOOR = 0.99
"""The V1 guardrail: evidence correctness >= 0.99 on every row."""


def _median(values: Sequence[float | None], digits: int = 3) -> float | None:
    """Middle of the sorted present values; a summary statistic over rows.

    Not the beacon timing median: that one lives in ``ath.behavior.features`` alone, by
    the rule ``tests/test_behavior.py`` enforces, and this module never touches it.
    """
    present = sorted(v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool))
    if not present:
        return None
    middle = len(present) // 2
    value = present[middle] if len(present) % 2 else (present[middle - 1] + present[middle]) / 2
    return round(value, digits)


def _p95(values: Sequence[float | None]) -> float | None:
    present = sorted(v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool))
    if not present:
        return None
    index = max(0, min(len(present) - 1, int(round(0.95 * (len(present) - 1)))))
    return round(present[index], 3)


INVESTIGATION_FIELDS: tuple[str, ...] = (
    "initial_hypothesis_count", "final_hypothesis_count",
    "benign_hypothesis_present_initial", "benign_hypothesis_present_final",
    "evidence_gap", "chosen_tool", "tool_choice_reason", "chosen_tools", "trajectory",
    "new_evidence_ids_returned", "new_evidence_ids_shown", "new_evidence_ids_used", "hypothesis_changed_after_tool",
    "labels_changed_after_tool", "abstained", "final_disposition", "output_truncated",
    "model_calls", "probes_run", "stop_reason",
)
"""The per-case diagnostics the investigator records and the summary reports."""


def links_are_scorable(payload: dict[str, Any], manifest_digest: str | None, telemetry_hashes: dict[str, str] | None) -> bool:
    """Whether this row's LINK scores may be read beside the current manifest.

    Every one of these must hold, or the scores are not this experiment's: the row was
    run against the current manifest, the scores were stamped with that manifest and
    with the row's own telemetry hash, and the manifest still pins that telemetry hash
    for this case. No score is ever computed here -- a row that carries none has none.
    """
    row = payload["row"]
    key = payload["key"]
    label_scores = row.get("label_scores") or {}
    scoring = label_scores.get("link_scoring") or {}
    if not manifest_digest or row.get("manifest_hash") != manifest_digest:
        return False
    if scoring.get("manifest_hash") != manifest_digest:
        return False
    if scoring.get("telemetry_hash") != row.get("telemetry_hash"):
        return False
    if telemetry_hashes is not None:
        pinned = telemetry_hashes.get(f"{key['corpus']}/{key['case_id']}")
        if pinned != row.get("telemetry_hash"):
            return False
    return isinstance(label_scores.get("links"), dict)


def row_summary(
    payload: dict[str, Any], *, manifest_digest: str | None = None,
    telemetry_hashes: dict[str, str] | None = None,
) -> dict[str, Any]:
    """One row's reportable facts, read from integers and sets; never from prose."""
    row = payload["row"]
    header = payload.get("header") or {}
    state = row.get("state") or {}
    llm = state.get("llm") or {}
    calls = header.get("calls") or []
    scores = scores_from_dict(row["scores"])
    errors = list(llm.get("errors") or [])
    context_refusals = [e for e in errors if "exceeds num_ctx" in e]
    by_kind: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for call in calls:
        by_kind[call.get("kind", "unknown")].append(call)
    investigation = state.get("investigation") or {}
    labels = row.get("labels") or {}
    links_valid = links_are_scorable(payload, manifest_digest, telemetry_hashes)
    links = dict((row.get("label_scores") or {}).get("links") or {}) if links_valid else None

    def kind_stats(kind: str) -> dict[str, Any]:
        entries = by_kind.get(kind, [])
        return {
            "calls": len(entries),
            "median_total_seconds": _median([c.get("total_seconds") for c in entries]),
            "median_prompt_eval_seconds": _median([c.get("prompt_eval_seconds") for c in entries]),
            "median_eval_seconds": _median([c.get("eval_seconds") for c in entries]),
            "median_prompt_tokens_per_second": _median([c.get("prompt_tokens_per_second") for c in entries]),
            "median_eval_tokens_per_second": _median([c.get("eval_tokens_per_second") for c in entries]),
            "prompt_tokens": sum(c.get("input_tokens") or 0 for c in entries),
            "completion_tokens": sum(c.get("output_tokens") or 0 for c in entries),
            "unsent": sum(1 for c in entries if c.get("sent") is False),
        }

    unparseable = int(llm.get("unparseable_responses") or 0)
    model_calls = len(calls)
    degraded = bool(row.get("llm_degraded"))
    completed_strict = not degraded and unparseable == 0 and not context_refusals
    return {
        "key": payload["key"],
        "run_id": (header.get("runner") or {}).get("run_id"),
        "labelled_arm": row.get("labelled_arm"),
        "status": state.get("status"),
        "degraded": degraded,
        "degradation_reason": errors[0] if errors else None,
        "errors": errors,
        "context_refusals": len(context_refusals),
        "unparseable_responses": unparseable,
        "unparseable_by_kind": dict(llm.get("unparseable_by_kind") or {}),
        "model_calls": model_calls,
        "parse_ok_calls": max(0, model_calls - unparseable - len(context_refusals)),
        "completed_strict": completed_strict,
        "wall_seconds": row.get("wall_seconds"),
        "tokens": row.get("tokens"),
        "planner": kind_stats("planner"),
        "synthesis": kind_stats("synthesis"),
        "investigator": kind_stats("investigator"),
        "planner_activation": planner_activation(state) if state else {},
        "investigation": {k: investigation.get(k) for k in INVESTIGATION_FIELDS},
        "verdict_label": labels.get("verdict"),
        "disposition": investigation.get("final_disposition"),
        "output_truncated": bool(investigation.get("output_truncated")) or any("truncated" in e for e in errors),
        "links": links,
        "links_valid": links_valid,
        "ram": {
            "preflight_available_bytes": (header.get("ram_preflight") or {}).get("available_bytes"),
            "preflight_resident_bytes": (header.get("ram_preflight") or {}).get("resident_bytes"),
            "model_size_bytes": (header.get("model_residency") or {}).get("size"),
            "model_vram_bytes": (header.get("model_residency") or {}).get("size_vram"),
            "after_bytes": header.get("ram_after_bytes"),
            "guard_ok": (header.get("ram_preflight") or {}).get("ok"),
        },
        "scores": {
            "evidence_correctness": scores.evidence_correctness,
            "evidence_coverage": scores.evidence_coverage,
            "rejected_claims": scores.rejected_claims,
            "unsupported_claims": sum((scores.unsupported_claims or {}).values()) if isinstance(scores.unsupported_claims, dict) else scores.unsupported_claims,
            "facts": scores.facts, "inferences": scores.inferences, "hypotheses": scores.hypotheses,
            "tool_calls": scores.tool_calls,
            "technique_jaccard": scores.technique_jaccard,
        },
        "label_scores": {k: v for k, v in (row.get("label_scores") or {}).items() if k in ("passed", "event_recall", "verdict_correct", "incident_id")},
        "budgets": row.get("budgets"),
        "counts": state.get("counts"),
    }


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 3) if denominator else None


def investigation_metrics(per_row: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """The stage's preview metrics, from the per-row diagnostics and the row labels.

    Verdict metrics use the row's ``labels.verdict`` -- written by the harness beside
    the row, never shown to the model -- against the investigator's own disposition.
    Unlabelled rows (flaws.cloud) are counted only in the label-free metrics. LINK
    metrics read only rows :func:`links_are_scorable` accepted.
    """
    inv = [r["investigation"] for r in per_row]
    labelled = [r for r in per_row if r["verdict_label"] in ("malicious", "benign")]
    malicious = [r for r in labelled if r["verdict_label"] == "malicious"]
    benign = [r for r in labelled if r["verdict_label"] == "benign"]
    with_disposition = [r for r in per_row if r["disposition"] in ("malicious", "benign", "abstain")]
    first_tools = [i["chosen_tool"] for i in inv if i.get("chosen_tool")]
    tool_counts: Counter = Counter(first_tools)
    all_tools: Counter = Counter(t for i in inv for t in (i.get("chosen_tools") or []))
    trajectories = Counter(tuple(i.get("trajectory") or []) for i in inv)
    link_rows = [r for r in per_row if r["links_valid"]]
    link_1 = [v for r in link_rows for k, v in r["links"].items() if k.endswith("LINK-1")]
    link_2 = [v for r in link_rows for k, v in r["links"].items() if k.endswith("LINK-2")]
    return {
        "truncated_rows": sum(1 for r in per_row if r["output_truncated"]),
        "truncation_rate": _rate(sum(1 for r in per_row if r["output_truncated"]), len(per_row)),
        "labelled_rows": len(labelled),
        "malicious_cases": len(malicious),
        "benign_cases": len(benign),
        "malicious_called_malicious": sum(1 for r in malicious if r["disposition"] == "malicious"),
        "malicious_called_benign": sum(1 for r in malicious if r["disposition"] == "benign"),
        "malicious_abstained": sum(1 for r in malicious if r["disposition"] == "abstain"),
        "benign_called_malicious": sum(1 for r in benign if r["disposition"] == "malicious"),
        "benign_called_benign": sum(1 for r in benign if r["disposition"] == "benign"),
        "benign_abstained": sum(1 for r in benign if r["disposition"] == "abstain"),
        "benign_false_narrative_rate": _rate(sum(1 for r in benign if r["disposition"] == "malicious"), len(benign)),
        "benign_retaining_benign_alternative": sum(1 for r in benign if r["investigation"].get("benign_hypothesis_present_final")),
        "rows_with_benign_alternative_initial": sum(1 for i in inv if i.get("benign_hypothesis_present_initial")),
        "rows_with_benign_alternative_final": sum(1 for i in inv if i.get("benign_hypothesis_present_final")),
        "abstentions": sum(1 for r in with_disposition if r["disposition"] == "abstain"),
        "abstention_rate": _rate(sum(1 for r in with_disposition if r["disposition"] == "abstain"), len(with_disposition)),
        "rows_with_disposition": len(with_disposition),
        "cases_with_tool_call": sum(1 for i in inv if i.get("probes_run")),
        "probes_total": sum(len(i.get("probes_run") or []) for i in inv),
        "first_tool_distribution": dict(sorted(tool_counts.items())),
        "tool_distribution": dict(sorted(all_tools.items())),
        "tool_choice_diversity": len(tool_counts),
        "unique_trajectories": len(trajectories),
        "trajectory_distribution": {" > ".join(k) or "(none)": v for k, v in sorted(trajectories.items())},
        "cases_retrieving_new_evidence": sum(1 for i in inv if (i.get("new_evidence_ids_returned") or 0) > 0),
        "cases_using_new_evidence": sum(1 for i in inv if (i.get("new_evidence_ids_used") or 0) > 0),
        "new_evidence_ids_returned_total": sum(i.get("new_evidence_ids_returned") or 0 for i in inv),
        "new_evidence_ids_shown_total": sum(i.get("new_evidence_ids_shown") or 0 for i in inv if i.get("new_evidence_ids_shown") is not None),
        "rows_recording_shown_ids": sum(1 for i in inv if i.get("new_evidence_ids_shown") is not None),
        "new_evidence_ids_used_total": sum(i.get("new_evidence_ids_used") or 0 for i in inv),
        "hypothesis_changed_after_tool": sum(1 for i in inv if i.get("hypothesis_changed_after_tool")),
        "labels_changed_after_tool": sum(1 for i in inv if i.get("labels_changed_after_tool")),
        "link_scorable_rows": len(link_rows),
        "link_unscorable_rows": sum(1 for r in per_row if not r["links_valid"] and r["verdict_label"] in ("malicious", "benign")),
        "link_1_recovered": sum(1 for v in link_1 if v),
        "link_1_defined": len(link_1),
        "link_1_score": _rate(sum(1 for v in link_1 if v), len(link_1)),
        "link_2_recovered": sum(1 for v in link_2 if v),
        "link_2_defined": len(link_2),
        "link_2_score": _rate(sum(1 for v in link_2 if v), len(link_2)),
        "investigator_median_seconds": _median([r["investigator"]["median_total_seconds"] for r in per_row]),
        "tool_calls_total": sum(r["scores"]["tool_calls"] or 0 for r in per_row),
    }


def summarise(
    rows: Sequence[dict[str, Any]], expected_cases: int, events: Sequence[dict[str, Any]] = (),
    *, manifest_digest: str | None = None, telemetry_hashes: dict[str, str] | None = None,
) -> dict[str, Any]:
    per_row = [row_summary(r, manifest_digest=manifest_digest, telemetry_hashes=telemetry_hashes) for r in rows]
    walls = [r["wall_seconds"] for r in per_row]
    model_calls = sum(r["model_calls"] for r in per_row)
    parse_ok = sum(r["parse_ok_calls"] for r in per_row)
    completed = sum(1 for r in per_row if r["completed_strict"])
    ec = [r["scores"]["evidence_correctness"] for r in per_row]
    all_calls = [c for r in rows for c in ((r.get("header") or {}).get("calls") or [])]
    failure_types: Counter = Counter()
    for r in per_row:
        for error in r["errors"]:
            if "exceeds num_ctx" in error:
                failure_types["context_budget_refusal"] += 1
            elif error.startswith("HTTP"):
                failure_types["http_" + error.split()[1]] += 1
            elif "truncated" in error:
                failure_types["generation_cap"] += 1
            elif "no text" in error:
                failure_types["no_text"] += 1
            else:
                failure_types["other:" + error[:40]] += 1
    return {
        "rows_written": len(per_row),
        "expected_cases": expected_cases,
        "completed_strict": completed,
        "completion_rate": round(completed / expected_cases, 3) if expected_cases else None,
        "meets_completion_target": (completed / expected_cases >= COMPLETION_TARGET) if expected_cases else None,
        "degraded_rows": sum(1 for r in per_row if r["degraded"]),
        "rows_with_unparseable": sum(1 for r in per_row if r["unparseable_responses"]),
        "rows_with_context_refusals": sum(1 for r in per_row if r["context_refusals"]),
        "model_calls": model_calls,
        "unparseable_responses": sum(r["unparseable_responses"] for r in per_row),
        "context_refusals": sum(r["context_refusals"] for r in per_row),
        "parse_rate": round(parse_ok / model_calls, 3) if model_calls else None,
        "total_wall_seconds": round(sum(w or 0 for w in walls), 1),
        "median_case_wall_seconds": _median(walls),
        "p95_case_wall_seconds": _p95(walls),
        "tokens_total": sum(r["tokens"] or 0 for r in per_row),
        "prompt_tokens_total": sum(c.get("input_tokens") or 0 for c in all_calls),
        "completion_tokens_total": sum(c.get("output_tokens") or 0 for c in all_calls),
        "median_prompt_tokens_per_second": _median([c.get("prompt_tokens_per_second") for c in all_calls]),
        "median_eval_tokens_per_second": _median([c.get("eval_tokens_per_second") for c in all_calls]),
        "planner_median_seconds": _median([c.get("total_seconds") for c in all_calls if c.get("kind") == "planner"]),
        "synthesis_median_seconds": _median([c.get("total_seconds") for c in all_calls if c.get("kind") == "synthesis"]),
        "ram_min_available_bytes": min(
            (v for r in per_row for v in (r["ram"]["preflight_available_bytes"], r["ram"]["after_bytes"]) if isinstance(v, int)),
            default=None,
        ),
        "ram_guard_events": len(events),
        "ram_guard_refusals": sum(1 for e in events if not e.get("overridden")),
        "ram_guard_overrides": sum(1 for e in events if e.get("overridden")),
        "rows_run_under_override": sum(1 for r in rows if ((r.get("header") or {}).get("ram_preflight") or {}).get("overridden")),
        "evidence_correctness_min": min((v for v in ec if v is not None), default=None),
        "evidence_correctness_all_at_least_floor": all(v is not None and v >= CORRECTNESS_FLOOR for v in ec) if ec else None,
        "rejected_claims_total": sum(r["scores"]["rejected_claims"] or 0 for r in per_row),
        "planner_model_chosen_steps": sum((r["planner_activation"] or {}).get("chosen_by_model", 0) or 0 for r in per_row),
        "planner_multi_candidate_steps": sum((r["planner_activation"] or {}).get("multi_candidate_steps", 0) or 0 for r in per_row),
        "run_ids": sorted({r["run_id"] for r in per_row if r.get("run_id")}),
        "failure_types": dict(failure_types),
        "investigation": investigation_metrics(per_row),
        "rows": per_row,
    }


def render_summary(summary: dict[str, Any], *, arm: str, model: str, head: str) -> str:
    def gib(value: Any) -> str:
        return f"{value / GIB:.2f}" if isinstance(value, int) else "--"

    lines = [
        f"# D1 baseline summary: arm {arm}, `{model}`",
        "",
        f"Generated {now()} at `{head}` from {summary['rows_written']} row file(s). MEASURED; no interpretation.",
        "",
        "| aggregate | value |", "| --- | --- |",
        ["completed (strict: not degraded, 0 unparseable, 0 context refusals)", f"{summary['completed_strict']} / {summary['expected_cases']} ({summary['completion_rate']})"],
        [f"meets >= {COMPLETION_TARGET:.0%} completion target", summary["meets_completion_target"]],
        ["rows written / degraded", f"{summary['rows_written']} / {summary['degraded_rows']}"],
        ["model calls / unparseable / context refusals", f"{summary['model_calls']} / {summary['unparseable_responses']} / {summary['context_refusals']}"],
        ["parse rate", summary["parse_rate"]],
        ["total wall s", summary["total_wall_seconds"]],
        ["median / p95 case wall s", f"{summary['median_case_wall_seconds']} / {summary['p95_case_wall_seconds']}"],
        ["planner / synthesis median call s", f"{summary['planner_median_seconds']} / {summary['synthesis_median_seconds']}"],
        ["tokens total (prompt / completion)", f"{summary['tokens_total']} ({summary['prompt_tokens_total']} / {summary['completion_tokens_total']})"],
        ["median prompt / gen tok/s", f"{summary['median_prompt_tokens_per_second']} / {summary['median_eval_tokens_per_second']}"],
        ["min available RAM seen (GiB)", gib(summary["ram_min_available_bytes"])],
        ["RAM guard events (refusals / overrides) / rows run under override", f"{summary['ram_guard_events']} ({summary['ram_guard_refusals']} / {summary['ram_guard_overrides']}) / {summary['rows_run_under_override']}"],
        ["evidence correctness min / all >= 0.99", f"{summary['evidence_correctness_min']} / {summary['evidence_correctness_all_at_least_floor']}"],
        ["rejected claims total", summary["rejected_claims_total"]],
        ["planner steps chosen by model / multi-candidate", f"{summary['planner_model_chosen_steps']} / {summary['planner_multi_candidate_steps']}"],
        ["run ids", ", ".join(r[:12] for r in summary.get("run_ids") or []) or "unrecorded"],
        ["failure types", json.dumps(summary["failure_types"])],
    ]
    inv = summary.get("investigation") or {}
    if inv:
        lines += [
            "",
            "## Investigation (D1 v2 preview metrics)",
            "",
            "| metric | value |", "| --- | --- |",
            ["truncated rows / rate", f"{inv['truncated_rows']} / {inv['truncation_rate']}"],
            ["labelled cases (malicious / benign)", f"{inv['labelled_rows']} ({inv['malicious_cases']} / {inv['benign_cases']})"],
            ["malicious called malicious / benign / abstained", f"{inv['malicious_called_malicious']} / {inv['malicious_called_benign']} / {inv['malicious_abstained']}"],
            ["benign called malicious / benign / abstained", f"{inv['benign_called_malicious']} / {inv['benign_called_benign']} / {inv['benign_abstained']}"],
            ["benign false-narrative rate", inv["benign_false_narrative_rate"]],
            ["benign cases retaining a benign alternative (final)", f"{inv['benign_retaining_benign_alternative']} / {inv['benign_cases']}"],
            ["rows with a benign alternative (initial / final)", f"{inv['rows_with_benign_alternative_initial']} / {inv['rows_with_benign_alternative_final']}"],
            ["abstentions / rate (rows with a disposition)", f"{inv['abstentions']} / {inv['abstention_rate']} ({inv['rows_with_disposition']})"],
            ["cases with a chosen tool call / probes total", f"{inv['cases_with_tool_call']} / {inv['probes_total']}"],
            ["first-tool distribution", json.dumps(inv["first_tool_distribution"])],
            ["tool distribution (all probes)", json.dumps(inv["tool_distribution"])],
            ["tool-choice diversity (distinct first tools)", inv["tool_choice_diversity"]],
            ["unique trajectories", f"{inv['unique_trajectories']} {json.dumps(inv['trajectory_distribution'])}"],
            ["cases retrieving / USING evidence outside the findings' citations", f"{inv['cases_retrieving_new_evidence']} / {inv['cases_using_new_evidence']} (ids returned {inv['new_evidence_ids_returned_total']} / shown {inv['new_evidence_ids_shown_total']} on {inv['rows_recording_shown_ids']} row(s) / used {inv['new_evidence_ids_used_total']})"],
            ["hypothesis changed after a tool (any / labels or disposition)", f"{inv['hypothesis_changed_after_tool']} / {inv['labels_changed_after_tool']}"],
            ["LINK-1 recovered / defined (score)", f"{inv['link_1_recovered']} / {inv['link_1_defined']} ({inv['link_1_score']})"],
            ["LINK-2 recovered / defined (score)", f"{inv['link_2_recovered']} / {inv['link_2_defined']} ({inv['link_2_score']})"],
            ["link-scorable rows / labelled rows without scorable links", f"{inv['link_scorable_rows']} / {inv['link_unscorable_rows']}"],
            ["investigator median call s / tool calls total", f"{inv['investigator_median_seconds']} / {inv['tool_calls_total']}"],
        ]
    out = []
    for line in lines:
        out.append(f"| {line[0]} | {line[1]} |" if isinstance(line, list) else line)
    out += [
        "",
        "## Per case",
        "",
        "| case | arm label | status | calls | unparse | ctx ref | wall s | tokens | ec | rejected | coverage | facts/inf/hyp | model-chosen steps | degradation |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | --- |",
    ]
    for r in summary["rows"]:
        k = r["key"]
        s = r["scores"]
        out.append(
            f"| {k['corpus']}/{k['case_id']} | {r['labelled_arm']} | {r['status']} | {r['model_calls']} | "
            f"{r['unparseable_responses']} | {r['context_refusals']} | {r['wall_seconds']} | {r['tokens']} | "
            f"{s['evidence_correctness']} | {s['rejected_claims']} | {s['evidence_coverage']} | "
            f"{s['facts']}/{s['inferences']}/{s['hypotheses']} | {(r['planner_activation'] or {}).get('chosen_by_model')} | "
            f"{(r['degradation_reason'] or '')[:60]} |"
        )
    if inv:
        out += [
            "",
            "## Per case: investigation",
            "",
            "| case | label | disposition | evidence gap | chosen tool(s) | new ids returned / used | benign alt (init / final) | changed after tool | LINK-1 | LINK-2 | truncated |",
            "| --- | --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- |",
        ]
        for r in summary["rows"]:
            k = r["key"]
            i = r["investigation"]
            links = r["links"] or {}
            l1 = next((v for name, v in links.items() if name.endswith("LINK-1")), None)
            l2 = next((v for name, v in links.items() if name.endswith("LINK-2")), None)
            out.append(
                f"| {k['corpus']}/{k['case_id']} | {r['verdict_label'] or 'unlabelled'} | {r['disposition']} | "
                f"{(i.get('evidence_gap') or '')[:70]} | {', '.join(i.get('chosen_tools') or []) or 'none'} | "
                f"{i.get('new_evidence_ids_returned')} / {i.get('new_evidence_ids_used')} | "
                f"{i.get('benign_hypothesis_present_initial')} / {i.get('benign_hypothesis_present_final')} | "
                f"{i.get('hypothesis_changed_after_tool')} | {'-' if l1 is None else l1} | {'-' if l2 is None else l2} | "
                f"{r['output_truncated']} |"
            )
    return "\n".join(out)


def select_rows(
    rows: Sequence[dict[str, Any]], entries: Sequence[CaseManifest], manifest_digest: str,
    *, model: str, repeat: int,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """The rows that belong to this experiment identity, and why the others do not.

    A row is in when its key names a manifest case, its model and repeat are the ones
    asked for, its manifest hash is the current one, its telemetry hash is the one the
    manifest pins for that case, and its header records the live investigator prompts
    and bounds. Everything else is counted by the reason it was excluded and never
    summarised: a stale row is not a weaker data point, it is another experiment's.
    """
    by_key = {(e.corpus, e.case_id): e for e in entries}
    live = investigator_environment()
    kept: list[dict[str, Any]] = []
    excluded: Counter = Counter()
    for row in rows:
        key = row["key"]
        entry = by_key.get((key["corpus"], key["case_id"]))
        header = row.get("header") or {}
        if entry is None:
            excluded["not_in_manifest"] += 1
        elif key.get("model") != model or key.get("repeat") != repeat:
            excluded["other_model_or_repeat"] += 1
        elif row["row"].get("manifest_hash") != manifest_digest or key.get("manifest_hash") not in (manifest_digest, ""):
            excluded["stale_manifest"] += 1
        elif row["row"].get("telemetry_hash") != entry.telemetry_hash:
            excluded["telemetry_hash_mismatch"] += 1
        elif dict(header.get("investigator") or {}) != live:
            excluded["investigator_prompt_drift"] += 1
        else:
            kept.append(row)
    return kept, dict(excluded)


class NothingToSummarise(SystemExit):
    """No rows under the target directory while rows exist beside it."""


def refuse_silent_zero(layout: Layout, rows: Sequence[Any], *, allow_empty: bool = False) -> None:
    if rows or allow_empty:
        return
    siblings = layout.sibling_row_dirs()
    if not siblings:
        return
    listing = "\n  ".join(f"{path.name}: {count} row file(s)" for path, count in siblings)
    raise NothingToSummarise(
        f"REFUSED: 0 rows under {layout.rows_dir} but rows exist under sibling directories:\n  "
        f"{listing}\n  they were written under another manifest hash or prompt version; "
        "run validate-rows on them, or pass --allow-empty to summarise nothing on purpose"
    )


def summarise_model(
    *, out_dir: Path, arm_letter: str, model: str, repeat: int = 1, allow_empty: bool = False,
    spec: Any = None, argv: list[str] | None = None,
    log: Callable[[str], None] = lambda text: print(text, file=sys.stderr),
) -> int:
    payload, entries, digest = read_manifest(out_dir)
    layout = Layout(Path(out_dir), arm_letter, model, digest)
    rows, excluded = select_rows(completed_rows(layout.rows_dir), entries, digest, model=model, repeat=repeat)
    refuse_silent_zero(layout, rows, allow_empty=allow_empty)
    record = RunRecord.start(layout, "summarise", argv=argv, spec=spec)
    telemetry_hashes = {e.key: e.telemetry_hash for e in entries}
    summary = summarise(
        rows, expected_cases=len(entries), events=guard_events(layout.rows_dir),
        manifest_digest=digest, telemetry_hashes=telemetry_hashes,
    )
    summary.update({
        "arm": arm_letter, "model": model, "manifest_hash": digest, "repeat": repeat,
        "head": head(), "rows_directory": str(layout.rows_dir.relative_to(ROOT)).replace("\\", "/"),
        "investigator": investigator_environment(), "rows_excluded": excluded,
        "summary_run_id": record.run_id,
    })
    write_json(layout.summary_json(repeat), summary)
    write_text(layout.summary_md(repeat), render_summary(summary, arm=arm_letter, model=model, head=summary["head"]))
    print(json.dumps({k: v for k, v in summary.items() if k != "rows"}, indent=1, default=str))
    log(f"wrote {layout.summary_json(repeat)} and {layout.summary_md(repeat)}")
    record.finish(0, {"rows": len(rows), **{f"excluded_{k}": v for k, v in excluded.items()}})
    return 0
