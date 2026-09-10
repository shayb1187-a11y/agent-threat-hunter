"""Consolidate every reports/m14/*.json record into the one M14 evaluation table.

Rows come from three record kinds under ``reports/m14/``:

* ``<dataset>.json``                     -- label-free profile (scripts/m14_profile.py)
* ``<name>.deterministic.json``          -- labelled incident, deterministic arm
* ``<name>.llm.json``                    -- labelled incident, LLM arm (or ``unavailable``)

The "main failure class" column is not computed: it is a judgement, and judgements are
written down with their evidence in ``reports/m14/classification.json`` (one entry per
row key) and merged here verbatim. A row with no entry prints ``unclassified`` so the
omission is visible. Anything that did not run prints ``unavailable`` -- never zero, never
pass/fail.

Failure classes (from the M14 plan, fixed before the measurements):

* ``detection``      -- ATH can represent the event and a rule misses it;
* ``representation`` -- the relevant event has no canonical table or channel;
* ``triage``         -- detection works and produces too many benign cases;
* ``reasoning``      -- detection and correlation work, the investigation concludes wrongly;
* ``none``           -- the row measured no failure.

Usage::

    python scripts/m14_table.py                  # prints Markdown
    python scripts/m14_table.py --write docs/m14-table.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports" / "m14"
CLASSIFICATION = REPORTS / "classification.json"

COLUMNS = (
    "Row", "Provenance", "Arm", "Ingested", "Labelled events resolved / unresolved",
    "TP / FP findings, FN events", "Precision / recall", "Case precision",
    "Evidence correctness", "Investigation completeness", "Triage reduction",
    "Analyst load", "Main failure class",
)

UNAVAILABLE = "unavailable"


def _pct(x: float | None) -> str:
    return UNAVAILABLE if x is None else f"{x:.1%}"


def _profile_row(key: str, rec: dict, cls: dict) -> list[str]:
    e0, p = rec["e0_ingestion"], rec["profile_full"]
    det, tri, cor, tel = p["detection"], p["triage"], p["correlation"], p["telemetry"]
    return [
        key, cls.get("provenance", rec.get("provenance", "?")), "deterministic",
        f"{_pct(e0['kept_fraction'])} of {e0['rows_read']:,}",
        "no labels",
        "no labels" if not cls.get("benign_only") else f"0 / {det['findings']} (benign-only source), FN n/a",
        "no labels" if not cls.get("benign_only") else (f"0% / n/a" if det["findings"] else "n/a (0 findings)"),
        "no labels" if not cls.get("benign_only") else (f"0% ({cor['cases']} of {cor['cases']} benign)" if cor["cases"] else "n/a (0 cases)"),
        "not run (no incident)", "not run (no incident)",
        _pct(tri["triage_load_reduction"]) if det["findings"] else "n/a (0 findings)",
        f"{det['findings']} findings, {cor['cases']} cases ({cor['singleton_cases']} singleton) over {tel['window_days']:.1f} d; {det['findings_per_day']:.2f}/day",
        cls.get("failure_class", "unclassified"),
    ]


def _incident_row(key: str, rec: dict, cls: dict, arm: str) -> list[str]:
    if "outcome" not in rec:
        status = rec.get("status", UNAVAILABLE)
        return [key, rec.get("provenance", "?"), arm, status] + [UNAVAILABLE] * 8 + [cls.get("failure_class", "unclassified")]
    o, lab, ing = rec["outcome"], rec["labels"], rec["ingestion"]
    d, al, bd, cq, cn, tr = (o["detection"], o["analyst_load"], o["benign_discrimination"],
                             o["chain_quality"], o["conclusions"], o["trust"])
    tp_findings = al["findings"] - bd["benign_findings_total"]
    fp_findings = bd["benign_findings_total"]
    fn_events = d["malicious_events_total"] - d["malicious_events_surfaced"]
    precision = tp_findings / al["findings"] if al["findings"] else None
    claims = tr["facts"] + tr["inferences"] + tr["hypotheses"]
    evidence = (claims / (claims + tr["rejected_claims"])) if (claims + tr["rejected_claims"]) else None
    total_conclusions = len(cn["conclusions_hit"]) + len(cn["conclusions_missed"])
    completeness = (f"{len(cn['conclusions_hit'])}/{total_conclusions}" if total_conclusions else "n/a")
    if al["cases"] == 0:
        evidence_text, completeness_text = "not run (no case)", f"0/{total_conclusions} (no case)" if total_conclusions else "n/a"
    else:
        evidence_text = f"{_pct(evidence)} ({claims} claims, {tr['rejected_claims']} rejected, {tr['hallucinated_citations']} fabricated)"
        completeness_text = completeness
    degraded = " (DEGRADED)" if o.get("llm_degraded") else ""
    return [
        key, rec.get("provenance", "?"), o.get("configuration", arm) + degraded,
        f"{ing['rows_kept'] / ing['rows_read']:.2%} of {ing['rows_read']:,}" if ing["rows_read"] else UNAVAILABLE,
        f"{lab['malicious_refs_total'] - lab['malicious_refs_unresolved']} / {lab['malicious_refs_unresolved']} of {lab['malicious_refs_total']}",
        f"{tp_findings} / {fp_findings}, FN {fn_events} of {d['malicious_events_total']} resolved",
        f"{_pct(precision) if al['findings'] else 'n/a (0 findings)'} / {_pct(d['event_recall']) if d['malicious_events_total'] else 'n/a'}",
        _pct(al["case_precision"]) if al["cases"] else "n/a (0 cases)",
        evidence_text, completeness_text,
        _pct(1 - bd["findings_after_triage"] / al["findings"]) if al["findings"] else "n/a (0 findings)",
        f"{al['findings']} findings, {al['cases']} cases, {al['noise_cases']} noise; {o['cost']['tool_calls']} tool calls",
        cls.get("failure_class", "unclassified"),
    ]


def build_rows() -> list[list[str]]:
    classification = json.loads(CLASSIFICATION.read_text(encoding="utf-8")) if CLASSIFICATION.exists() else {}
    rows: list[list[str]] = []
    for path in sorted(REPORTS.glob("*.json")):
        if path.name == "classification.json" or ".before-" in path.name:
            continue  # regression artifacts are kept beside the live rows, not tabulated
        rec = json.loads(path.read_text(encoding="utf-8"))
        key = path.name[: -len(".json")]
        cls = classification.get(key, {})
        if "profile_full" in rec:
            rows.append(_profile_row(key, rec, cls))
        elif key.endswith(".deterministic"):
            rows.append(_incident_row(key, rec, cls, "deterministic"))
        elif key.endswith(".llm"):
            rows.append(_incident_row(key, rec, cls, "llm"))
    for key, cls in classification.items():
        if cls.get("status") == UNAVAILABLE and not any(r[0] == key for r in rows):
            rows.append([key, cls.get("provenance", "?"), cls.get("arm", "?"), f"{UNAVAILABLE}: {cls.get('reason', '')}"]
                        + [UNAVAILABLE] * 8 + [cls.get("failure_class", "unclassified")])
    return rows


def render(rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(COLUMNS) + " |", "|" + "---|" * len(COLUMNS)]
    out += ["| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |" for r in rows]
    classification = json.loads(CLASSIFICATION.read_text(encoding="utf-8")) if CLASSIFICATION.exists() else {}
    if classification:
        out += ["", "Failure-class evidence:", ""]
        for key, cls in classification.items():
            if cls.get("evidence"):
                out.append(f"- **{key}** -> `{cls.get('failure_class', '?')}`: {cls['evidence']}")
    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--write", type=Path, default=None)
    args = parser.parse_args()
    text = render(build_rows())
    if args.write:
        args.write.write_text(text, encoding="utf-8")
        print(f"wrote {args.write}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
