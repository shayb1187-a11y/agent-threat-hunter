"""``ath demo``: a two-minute, offline tour of ATH that writes one browsable folder.

For a reader with no API key, no GPU and very little time. It runs only existing code,
writes everything under ``--out``, and never touches ``data/raw`` or the network:

1. **Detect** -- generate the labelled synthetic telemetry (as ``generate`` does, but into
   the output folder), run every rule (as ``hunt``), and score each rule against the
   generator's ``ground_truth.json`` (as ``evaluate``).
2. **Correlate** -- group findings into cases with ATT&CK tactic chains (as ``chains``).
3. **Investigate** -- run :class:`ath.workflow.Workflow` with the deterministic engine
   over the three synthetic dev scenarios, writing a Markdown and an HTML report per case.
4. **Recorded model runs** -- copy the curated gallery ``docs/demo/recorded`` (built by
   ``scripts/curate_demo_rows.py``). These are recorded outputs replayed as static
   pages; no model is called.
5. **Measured honestly** -- the holdout-v1-windows headline, from
   :data:`HOLDOUT_V1_WINDOWS`. ``tests/test_demo.py`` checks those numbers against
   ``docs/holdout-v1-windows-results.md`` so the page cannot drift from the evidence.

The landing page is one self-contained file: inline CSS, light and dark themes, no
script, no external asset. Every string is HTML-escaped, including the text that came
from telemetry.
"""

from __future__ import annotations

import json
import shutil
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path

from ath import workflow as wf
from ath.config import PROJECT_ROOT
from ath.correlation import correlate
from ath.environment import build_environment_model
from ath.evaluation import auth_execution as pilot
from ath.evaluation import evaluate
from ath.evaluation import real_cases as real
from ath.hunting import HuntConfig, run_hunt
from ath.mitre import ATTACK_VERSION, map_finding
from ath.reporting import IndexEntry, render_index
from ath.reporting.html import _CSS, _e
from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS
from ath.telemetry import GeneratorConfig, generate_telemetry, load_telemetry, write_telemetry
from ath.telemetry.source import SourceLoadResult, write_normalized_telemetry
from ath.triage import assess_findings, set_aside_ids

MARKER = ".ath-demo"
"""Written into every demo folder. A non-empty folder without it is never overwritten."""
RECORDED_SOURCE = PROJECT_ROOT / "docs" / "demo" / "recorded"
SEED = 1337
PROFILE = "operational-v6"
"""The profile the recorded model runs used, so sections 3 and 4 are comparable."""
REPO = "https://github.com/shayb1187-a11y/agentic-threat-hunter/blob/main/"

HOLDOUT_V1_WINDOWS = {
    "run_id": "holdout-9b-v6-ecd865890442",
    "model": "qwen3.5:9b",
    "profile": "operational-v6",
    "cases": 12,
    "malicious_cases": 6,
    "benign_cases": 6,
    "malicious_correct": 0,
    "benign_correct": 5,
    "unsafe_clears": 3,
    "false_accusations": 1,
    "balanced_accuracy": 0.42,
    "deterministic_abstained": 18,
    "deterministic_rows": 18,
    "preregistration": REPO + "docs/holdout-v1-windows-preregistration.md",
    "results": REPO + "docs/holdout-v1-windows-results.md",
}
"""The holdout-v1-windows headline shown in section 5. It is the only copy of these numbers
in the code. ``tests/test_demo.py`` parses each one from
``docs/holdout-v1-windows-results.md`` and compares."""

SCENARIO_NOTES = {
    "malicious": "Remote service shell, then a credential export.",
    "benign": "Remote service shell, then routine maintenance.",
    "abstain": "Remote service shell; the deciding child process is deliberately absent.",
}


class DemoRefused(RuntimeError):
    """The output folder has content that a previous demo did not write."""


# -- run --------------------------------------------------------------------------------


def _prepare(out: Path) -> None:
    if out.exists() and any(out.iterdir()):
        if not (out / MARKER).exists():
            raise DemoRefused(f"{out} is not empty and was not written by `ath demo`; choose another --out")
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / MARKER).write_text("Written by `ath demo`; safe to delete.\n", encoding="utf-8")


def _write_json(path: Path, payload) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    return path.name


def _detect(out: Path) -> dict:
    """Sections 1 and 2: generate, hunt, score, correlate."""
    telemetry_dir = out / "telemetry"
    tables, ground_truth = generate_telemetry(GeneratorConfig(seed=SEED))
    write_telemetry(tables, ground_truth, telemetry_dir)
    telemetry = load_telemetry(telemetry_dir)
    hunt = run_hunt(telemetry, config=HuntConfig())
    report = evaluate(hunt, telemetry_dir, total_events=telemetry.event_count)
    assessments = assess_findings(hunt.findings, build_environment_model(telemetry))
    cases = correlate(hunt.findings, telemetry, set_aside=set_aside_ids(assessments))

    _write_json(out / "detection" / "findings.json", [f.to_dict() for f in hunt.findings])
    _write_json(out / "detection" / "evaluation.json", report.to_dict())
    _write_json(out / "detection" / "cases.json", [c.to_dict() for c in cases])

    findings = []
    for f in hunt.findings:
        mappings = map_finding(f) or []
        findings.append({
            "rule_id": f.rule_id, "severity": f.severity.value, "title": f.title,
            "device": f.device, "user": f.user, "events": len(f.event_ids),
            "attack": [f"{m.technique_id} ({m.tactic.display_name})" for m in mappings]})
    correlated = sum(len(c.findings) for c in cases)
    return {
        "events": telemetry.event_count,
        "tables": {kind: len(df) for kind, df in tables.items()},
        "rules_run": len(hunt.rules_run),
        "findings": findings,
        "true_positives": report.total_true_positives,
        "false_positives": report.total_false_positives,
        "stages_covered": len(report.covered_stages),
        "stages_total": len(report.covered_stages) + len(report.uncovered_stages),
        "rules": [{"rule_id": r.rule_id, "tp": r.true_positives, "fp": r.false_positives,
                   "fn": r.false_negatives, "precision": round(r.precision, 2), "recall": round(r.recall, 2),
                   "note": (f"{r.fp_benign_lookalike} FP from the labelled benign look-alike"
                            if r.fp_benign_lookalike else "")}
                  for r in report.rules if r.findings_total or r.detected_stages or r.missed_stages],
        "rules_silent": sorted(r.rule_id for r in report.rules
                               if not (r.findings_total or r.detected_stages or r.missed_stages)),
        "cases": [{"case_id": c.case_id, "severity": c.severity.value, "confidence": c.confidence,
                   "findings": len(c.findings), "devices": list(c.devices), "users": list(c.users),
                   "tactics": list(c.tactics), "summary": c.explain()} for c in cases],
        "correlated": correlated,
        "isolated": len(hunt.findings) - correlated,
        "attack_version": ATTACK_VERSION,
    }


def _investigate(out: Path) -> dict:
    """Section 3: the checkpointed workflow, deterministic engine, over the dev scenarios."""
    root = out / "investigations"
    flow = wf.Workflow("deterministic", PROFILE)
    rows, entries = [], []
    for scenario in pilot.scenarios("dev"):
        t = scenario.telemetry
        source = root / "sources" / scenario.key
        write_normalized_telemetry(SourceLoadResult(tables={
            EVENT_PROCESS: t.processes, EVENT_NETWORK: t.network,
            EVENT_LOGON: t.logons, EVENT_CONTROL: t.controls}), source)
        # Seed with the remote service shell (ATH-007's event), the same incident the
        # recorded dev-gate rows investigated.
        shell = t.processes[t.processes["process_name"] == "cmd.exe"]["event_id"].iloc[0]
        inputs = wf.CaseInputs(scenario.key, str(source), "canonical", real.DETECTION,
                               (f"generated:{shell}",), expected_decision=scenario.expected_decision)
        outcome = flow.run_case(root / "cases" / scenario.key, inputs)
        if outcome["status"] != wf.COMPLETE:
            raise RuntimeError(f"{scenario.key}: workflow ended {outcome['status']}")
        verdict = outcome["verdict"]
        child = t.processes[t.processes["event_id"].isin(scenario.useful_ids)]["command_line"].tolist()
        base = f"cases/{scenario.key}/{wf.STAGE_REPORT}/report"
        rows.append({"key": scenario.key, "expected": scenario.expected_decision,
                     "note": SCENARIO_NOTES[scenario.expected_decision],
                     "child_command": child[0] if child else None,
                     "verdict": verdict["disposition"], "decision": verdict["decision"],
                     "correct": bool(outcome["scoring"]["correct"]),
                     "html": f"investigations/{base}.html", "md": f"investigations/{base}.md"})
        entries.append(IndexEntry(label=scenario.key, href=f"{base}.html", verdict=verdict["disposition"],
                                  complete=verdict["complete"], elapsed_seconds=verdict.get("elapsed_seconds"),
                                  expected=scenario.expected_decision, title=verdict.get("title") or ""))
    (root / "index.html").write_text(
        render_index(entries, title="Deterministic investigations: synthetic dev scenarios"), encoding="utf-8")
    return {"profile": PROFILE, "engine": "deterministic", "rows": rows,
            "correct": sum(r["correct"] for r in rows)}


def _recorded(out: Path) -> dict:
    """Section 4: copy the curated gallery. Missing (an install without the repo) is said."""
    sources = RECORDED_SOURCE / "SOURCES.json"
    if not sources.exists():
        return {"available": False, "rows": []}
    shutil.copytree(RECORDED_SOURCE, out / "recorded")
    catalogue = json.loads(sources.read_text(encoding="utf-8"))
    return {"available": True, "run_id": catalogue["run_id"], "model": catalogue["model"],
            "profile": catalogue["profile"],
            "rows": [{**row, "href": f"recorded/{row['href']}", "md": f"recorded/{row['md']}"}
                     for row in catalogue["rows"]]}


def run_demo(out: Path) -> dict:
    """Build the demo folder at ``out`` and return what the landing page shows."""
    out = Path(out).resolve()
    _prepare(out)
    started = time.perf_counter()
    timings = {}
    with warnings.catch_warnings():
        # pandas deprecation notices from concat; they do not change any result shown.
        warnings.simplefilter("ignore", FutureWarning)
        detection = _detect(out)
        timings["detect_and_correlate"] = round(time.perf_counter() - started, 2)
        mark = time.perf_counter()
        investigations = _investigate(out)
        timings["investigate"] = round(time.perf_counter() - mark, 2)
    recorded = _recorded(out)
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "seconds": round(time.perf_counter() - started, 1), "timings": timings,
        "detection": detection, "investigations": investigations, "recorded": recorded,
        "holdout": HOLDOUT_V1_WINDOWS,
    }
    _write_json(out / "demo.json", data)
    (out / "index.html").write_text(render_landing(data), encoding="utf-8")
    return {**data, "out": str(out), "index": str(out / "index.html")}


# -- landing page -----------------------------------------------------------------------


_EXTRA_CSS = """
main{max-width:1040px}
header.hero{padding:8px 0 4px}
header.hero p{max-width:760px}
nav.flow{display:flex;flex-wrap:wrap;gap:6px;margin:14px 0 4px}
nav.flow a{border:1px solid var(--line);border-radius:999px;padding:3px 12px;
text-decoration:none;color:var(--fg);background:var(--card);font-size:14px}
a{color:inherit}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:12px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.tile b{display:block;font-size:1.45rem;line-height:1.2}
.tile span{color:var(--muted);font-size:13px}
.tile.bad b{color:var(--mal)}.tile.good b{color:var(--ben)}.tile.warn b{color:var(--abs)}
.chain{display:flex;flex-wrap:wrap;gap:4px;margin:6px 0}
.chain span{background:var(--code);border-radius:4px;padding:1px 7px;font-size:13px}
.callout{border-left:4px solid var(--mal);padding:10px 14px;background:var(--card);border-radius:4px;margin:12px 0}
.callout.note{border-left-color:var(--muted)}
section p.src{font-size:13px;color:var(--muted)}
.card.case{margin:10px 0}
.headline{font-size:1.2rem;font-weight:700;color:var(--mal)}
"""


def _link(href: str, text: str) -> str:
    return f'<a href="{_e(href)}">{_e(text)}</a>'


def _badge(verdict: str) -> str:
    return f'<span class="badge v-{_e(str(verdict).lower())}">{_e(verdict)}</span>'


def _table(headers: tuple[str, ...], rows: list[list[str]]) -> str:
    """Cells are already escaped HTML; headers are escaped here."""
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _tile(value, label: str, tone: str = "") -> str:
    return f'<div class="tile {_e(tone)}"><b>{_e(value)}</b><span>{_e(label)}</span></div>'


def _section(anchor: str, number: int, title: str, body: str) -> str:
    return f'<section id="{_e(anchor)}">\n<h2>{number}. {_e(title)}</h2>\n{body}\n</section>\n'


def _detect_section(d: dict) -> str:
    tables = ", ".join(f"{n} {k}" for k, n in d["tables"].items())
    findings = _table(("Severity", "Rule", "Finding", "Host", "Account", "ATT&CK (candidate)"), [
        [_e(f["severity"]), f"<code>{_e(f['rule_id'])}</code>", _e(f["title"]),
         _e(f["device"]), _e(f["user"]), _e("; ".join(f["attack"]) or "no mapping justified")]
        for f in d["findings"]])
    rules = _table(("Rule", "TP", "FP", "FN", "Precision", "Recall", "Note"), [
        [f"<code>{_e(r['rule_id'])}</code>", _e(r["tp"]), _e(r["fp"]), _e(r["fn"]),
         _e(f"{r['precision']:.2f}"), _e(f"{r['recall']:.2f}"), _e(r["note"])] for r in d["rules"]])
    silent = (f"<p class=\"muted\">{len(d['rules_silent'])} rules target telemetry this scenario does not contain "
              f"(for example cloud and Kubernetes rules) and stay silent: {_e(', '.join(d['rules_silent']))}.</p>"
              if d["rules_silent"] else "")
    return (
        f"<p>{_e(d['rules_run'])} deterministic rules ran over {_e(d['events'])} synthetic events "
        f"({_e(tables)}), generated with seed {SEED} into this folder.</p>"
        '<div class="tiles">'
        + _tile(d["events"], "events")
        + _tile(len(d["findings"]), "findings")
        + _tile(f"{d['true_positives']} / {d['false_positives']}", "true / false positives")
        + _tile(f"{d['stages_covered']}/{d['stages_total']}", "labelled attack stages detected")
        + "</div>"
        + findings
        + "<h3>Per-rule precision and recall against ground_truth.json</h3>"
        + rules + silent
        + '<div class="callout note">These are the constructed demo scenarios, scored against the labels the '
          "generator itself wrote. They show that the pipeline works and is measured. They are not a "
          "production detection rate.</div>"
        + '<p class="src">Evidence: ' + " · ".join([
            _link("telemetry/ground_truth.json", "ground_truth.json"),
            _link("detection/findings.json", "findings.json"),
            _link("detection/evaluation.json", "evaluation.json")]) + "</p>"
    )


def _correlate_section(d: dict) -> str:
    cards = []
    for c in d["cases"]:
        chain = "".join(f"<span>{_e(t)}</span>" for t in c["tactics"]) or "<span>no tactic mapped</span>"
        cards.append(
            f'<div class="card case"><b>{_e(c["case_id"])}</b> · {_e(c["severity"])} · '
            f'grouping confidence {_e(c["confidence"])} · {_e(c["findings"])} findings · hosts '
            f'{_e(", ".join(c["devices"]))} · accounts {_e(", ".join(c["users"]))}'
            f'<div class="chain">{chain}</div><div class="muted">{_e(c["summary"])}</div></div>')
    return (
        f"<p>Findings are joined into cases only on shared evidence: process lineage, hosts, accounts and "
        f"authentication context. {_e(d['correlated'])} findings formed {_e(len(d['cases']))} case(s); "
        f"{_e(d['isolated'])} stayed isolated. Tactics are listed in ATT&CK {_e(d['attack_version'])} "
        "kill-chain order. Each mapping must cite telemetry.</p>"
        + "".join(cards)
        + '<p class="src">Evidence: ' + _link("detection/cases.json", "cases.json") + "</p>"
    )


def _investigate_section(d: dict) -> str:
    rows = [[_e(r["key"]), _e(r["note"]) + (f"<br><code>{_e(r['child_command'])}</code>" if r["child_command"] else ""),
             _e(r["expected"]), _badge(r["verdict"]), "yes" if r["correct"] else '<span class="no">no</span>',
             _link(r["html"], "html") + " · " + _link(r["md"], "md")] for r in d["rows"]]
    wrong = len(d["rows"]) - d["correct"]
    return (
        "<p>The workflow runs telemetry → seed → investigation → report as sealed, resumable stages. "
        "Read-only tools retrieve the evidence. Each report separates FACT from INFERENCE and HYPOTHESIS. "
        "Verification rejects a cited event id that the investigation never retrieved and any unsupported typed "
        "premise. It does not prove that free prose is correct. Engine: deterministic, profile "
        f"{_e(d['profile'])}, over the three synthetic dev scenarios.</p>"
        + _table(("Scenario", "What happens", "Expected", "Verdict", "Correct", "Report"), rows)
        + (f'<div class="callout">The deterministic engine gets {_e(d["correct"])} of {_e(len(d["rows"]))} right. '
           "The rules fire the same way whether the child process is a credential export or a health scan, so "
           f"triage calls {_e(wrong)} non-malicious case(s) malicious. Telling these apart is the job of the model "
           "arm, recorded in section 4.</div>" if wrong else "")
        + '<p class="src">All reports: ' + _link("investigations/index.html", "investigations/index.html") + "</p>"
    )


def _recorded_section(d: dict) -> str:
    if not d["available"]:
        return ('<p class="muted">The recorded gallery (docs/demo/recorded) is not present in this installation; '
                "run the demo from a repository checkout to include it.</p>")
    rows = [[_e(r["key"]), _e("model (D1)" if r["arm"] == "d1" else "deterministic"), _e(r["provenance"]),
             _e(r["expected"]), _badge(r["decision"].capitalize()),
             f"<b>{_e(r['shows'])}</b>: {_e(r['line'])}", _link(r["href"], "html") + " · " + _link(r["md"], "md")]
            for r in d["rows"]]
    return (
        f"<p>No model runs in this demo. These are recorded outputs of {_e(d['model'])} ({_e(d['profile'])}) "
        f"from Colab run <code>{_e(d['run_id'])}</code>, replayed as static pages. The rows sample-01 to "
        "sample-03 are the same synthetic scenarios as section 3. The rows h05, h07 and h14 are real Windows "
        "logs from the DEDALE dataset (CC BY 4.0). The gallery keeps the failure in view.</p>"
        + _table(("Case", "Arm", "Data", "Expected", "Verdict", "What it shows", "Report"), rows)
        + '<p class="src">' + _link("recorded/index.html", "Gallery") + " · "
        + _link("recorded/ATTRIBUTION.md", "Attribution (DEDALE, CC BY 4.0)") + "</p>"
    )


def _measured_section(h: dict) -> str:
    return (
        '<p class="headline">Investigative value on Windows: NOT demonstrated.</p>'
        f"<p>Pre-registered evaluation on {_e(h['cases'])} fresh Windows cases from DEDALE "
        f"({_e(h['malicious_cases'])} malicious, {_e(h['benign_cases'])} benign), run "
        f"<code>{_e(h['run_id'])}</code>, {_e(h['model'])} on {_e(h['profile'])}:</p>"
        '<div class="tiles">'
        + _tile(f"{h['malicious_correct']}/{h['malicious_cases']}", "malicious cases called malicious", "bad")
        + _tile(h["unsafe_clears"], "unsafe clears: malicious called benign", "bad")
        + _tile(f"{h['benign_correct']}/{h['benign_cases']}", "benign cases cleared", "good")
        + _tile(f"{h['balanced_accuracy']:.2f}", "balanced accuracy (rule: > 0.5)", "bad")
        + _tile(f"{h['deterministic_abstained']}/{h['deterministic_rows']}", "deterministic arm abstained", "warn")
        + "</div>"
        "<ul>"
        f"<li>The sealed decision rule failed on two criteria: {_e(h['unsafe_clears'])} unsafe clears (at most 1 "
        "allowed) and no correct malicious case.</li>"
        f"<li>{_e(h['false_accusations'])} benign case was accused. The deterministic arm cleared nothing and accused nothing: it "
        f"abstained on all {_e(h['deterministic_rows'])} cases (0 correct), including "
        f"{_e(h['deterministic_rows'] - h['cases'])} secondary Kubernetes benign checks.</li>"
        "<li>Kubernetes malicious discrimination was <b>not evaluated</b>: no suitable fresh, labelled Kubernetes "
        "attack dataset was available.</li>"
        "<li>A v7 safety fix is in progress. These 12 cases are now seen, so it will be measured on a fresh "
        "holdout, not on them.</li>"
        "</ul>"
        '<p class="src">Evidence: ' + _link(h["preregistration"], "pre-registration") + " · "
        + _link(h["results"], "results") + "</p>"
    )


def render_landing(data: dict) -> str:
    """The landing page. Every value passes through ``_e``; the page has no script."""
    d, inv, rec, h = data["detection"], data["investigations"], data["recorded"], data["holdout"]
    sections = (
        ("detect", "Detect", _detect_section(d)),
        ("correlate", "Correlate", _correlate_section(d)),
        ("investigate", "Investigate with verified evidence", _investigate_section(inv)),
        ("recorded", "The model's recorded runs", _recorded_section(rec)),
        ("measured", "Measured honestly", _measured_section(h)),
    )
    nav = "".join(f'<a href="#{_e(a)}">{i}. {_e(t)}</a>' for i, (a, t, _) in enumerate(sections, 1))
    body = (
        '<header class="hero"><h1>Agentic Threat Hunter: offline demo</h1>'
        "<p>Deterministic detection first, evidence-constrained investigation second. This page was built on "
        f"this machine in {_e(data['seconds'])} s at {_e(data['generated_at'])}. It used no API key, no network "
        "and no model call. Each section links the files its numbers come from.</p>"
        f'<nav class="flow">{nav}</nav></header>\n'
        + "".join(_section(a, i, t, b) for i, (a, t, b) in enumerate(sections, 1))
        + '<p class="muted">ATH is a research prototype, not a production SOC product. '
          + _link(REPO + "README.md", "README") + "</p>"
    )
    title = "ATH offline demo"
    return (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "<meta name=\"color-scheme\" content=\"light dark\">\n"
        f"<title>{_e(title)}</title>\n<style>{_CSS}{_EXTRA_CSS}</style>\n</head>\n<body>\n<main>\n"
        f"{body}\n</main>\n</body>\n</html>\n"
    )
