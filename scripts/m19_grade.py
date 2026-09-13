"""M19 Phase 3: grade the seven pre-registered predictions from the committed arm artifacts.

Reads ``reports/m19/ablation/arm_{A,B,C}.json`` and ``scores_{A,B,C}.json`` and writes
``reports/m19/ablation/GRADING.json`` plus ``HYPOTHESES.md`` (every model-arm hypothesis,
verbatim, for the manual reading that prediction (v) requires). It computes nothing the
experiment did not already record; it only joins rows across arms by ``(corpus,
case_id)`` and counts. It post-dates the runs and is not part of the frozen experiment
logic; the numbers it prints are read from the artifacts, never from a re-run.

The one constant the pre-registration left open -- the unsupported-claims threshold in
(vii), "to be set from arm A's inference count" -- is set here as arm A's mean inferences
per case, and the outcome is also reported for a threshold of 1.0 so the choice can be
seen not to matter.
"""

from __future__ import annotations

import json
import re
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "reports" / "m19" / "ablation"

ARMS = {"A": "A_deterministic", "B": "B_single_llm", "C": "C_crew_llm"}


def load(arm: str) -> tuple[dict, dict]:
    rows = json.loads((OUT / f"arm_{arm}.json").read_text(encoding="utf-8"))["cases"]
    scores = json.loads((OUT / f"scores_{arm}.json").read_text(encoding="utf-8"))
    return {(r["corpus"], r["case_id"]): r for r in rows}, scores


def planner_from_log(arm: str) -> dict[str, dict]:
    log = (OUT / f"run_{arm}.log").read_text(encoding="utf-8", errors="replace")
    out = {}
    for m in re.finditer(
        r"^\s*(?P<key>\S+/CASE-\d+): planner chose (?P<chose>\d+) of (?P<offered>\d+) "
        r"multi-candidate step\(s\); fallbacks (?P<fb>\{.*?\}); unparseable (?P<unp>\d+); "
        r"degraded (?P<deg>True|False)", log, re.M,
    ):
        out[m["key"]] = {"chose": int(m["chose"]), "offered": int(m["offered"]),
                         "unparseable": int(m["unp"]), "degraded": m["deg"] == "True"}
    return out


def claim_ids(row: dict, types: tuple[str, ...] | None = None) -> set[str]:
    ids: set[str] = set()
    for c in row["state"]["claims"]:
        if types is None or c["type"] in types:
            ids |= set(c.get("evidence_ids") or [])
    return ids


def tool_ids(row: dict) -> set[str]:
    ids: set[str] = set()
    for res in row["state"].get("results", []):
        for call in res.get("tool_calls", []):
            ids |= set(call.get("event_ids") or [])
    return ids


def main() -> int:
    A, sA = load("A"); B, sB = load("B"); C, sC = load("C")
    keys = list(A)
    assert set(keys) == set(B) == set(C), "the three arms do not cover the same cases"
    planner = {"B": planner_from_log("B"), "C": planner_from_log("C")}

    def overall(scores: dict, name: str) -> dict:
        return scores["summary"]["arms"][name]["overall"]

    g: dict = {"cases": len(keys), "arms": {}}
    for arm, name in ARMS.items():
        s = {"A": sA, "B": sB, "C": sC}[arm]
        g["arms"][name] = {k: overall(s, k) for k in s["summary"]["arms"]}

    # (i) evidence correctness and rejected claims, per row
    g["i_evidence_correctness"] = {
        arm: {"min_ec": min(r["scores"]["evidence_correctness"] for r in rows.values()),
              "rejected_total": sum(r["scores"]["rejected_claims"] for r in rows.values()),
              "facts_without_evidence": sum(r["scores"]["facts_without_evidence"] for r in rows.values())}
        for arm, rows in (("A", A), ("B", B), ("C", C))
    }
    # (ii) unsupported claims per case
    g["ii_unsupported"] = {
        arm: {"total": sum(r["scores"]["unsupported_claims"] for r in rows.values()),
              "per_case_mean": round(statistics.mean(r["scores"]["unsupported_claims"] for r in rows.values()), 4),
              "cases_with_any": sum(1 for r in rows.values() if r["scores"]["unsupported_claims"]),
              "by_type": sorted({t for r in rows.values() for t in r["scores"]["unsupported_by_type"]})}
        for arm, rows in (("A", A), ("B", B), ("C", C))
    }
    # (iii) coverage C vs A per case
    below = [k for k in keys if C[k]["scores"]["evidence_coverage"] < A[k]["scores"]["evidence_coverage"]]
    g["iii_coverage"] = {
        "cases_C_below_A": [f"{c}/{i}" for c, i in below],
        "mean_A": round(statistics.mean(A[k]["scores"]["evidence_coverage"] for k in keys), 4),
        "mean_B": round(statistics.mean(B[k]["scores"]["evidence_coverage"] for k in keys), 4),
        "mean_C": round(statistics.mean(C[k]["scores"]["evidence_coverage"] for k in keys), 4),
        "tool_budget_hit": {arm: [f"{c}/{i}" for (c, i), r in rows.items() if r["budgets"]["tool_budget_hit"]]
                            for arm, rows in (("A", A), ("B", B), ("C", C))},
        "step_budget_hit": {arm: [f"{c}/{i}" for (c, i), r in rows.items() if r["budgets"]["step_budget_hit"]]
                            for arm, rows in (("A", A), ("B", B), ("C", C))},
        "INC-001": {arm: rows[("synthetic:INC-001", "CASE-001")]["budgets"] | {"coverage": rows[("synthetic:INC-001", "CASE-001")]["scores"]["evidence_coverage"]}
                    for arm, rows in (("A", A), ("B", B), ("C", C))},
    }
    # (iv) technique agreement, both directions
    def directions(rows):
        anm = [(f"{c}/{i}", r["scores"]["technique_agreement"]["asserted_not_mapped"]) for (c, i), r in rows.items() if r["scores"]["technique_agreement"]["asserted_not_mapped"]]
        mna = [(f"{c}/{i}", r["scores"]["technique_agreement"]["mapped_not_asserted"]) for (c, i), r in rows.items() if r["scores"]["technique_agreement"]["mapped_not_asserted"]]
        return {"jaccard_mean": round(statistics.mean(r["scores"]["technique_agreement"]["jaccard"] for r in rows.values()), 4),
                "asserted_not_mapped": anm, "mapped_not_asserted": mna}
    g["iv_technique"] = {arm: directions(rows) for arm, rows in (("A", A), ("B", B), ("C", C))}
    # (v) hypotheses
    g["v_hypotheses"] = {arm: {"total": sum(r["scores"]["completeness"]["hypotheses"] for r in rows.values()),
                               "cases_with_any": sum(1 for r in rows.values() if r["scores"]["completeness"]["hypotheses"]),
                               "actionable_vs_restating": "UNAVAILABLE: manual reading required by the pre-registration; see HYPOTHESES.md"}
                         for arm, rows in (("A", A), ("B", B), ("C", C))}
    # (vi) cost
    def cost(rows):
        toks = [r["tokens"] for r in rows.values() if isinstance(r["tokens"], (int, float))]
        walls = [r["wall_seconds"] for r in rows.values()]
        return {"tokens_total": sum(toks), "tokens_mean": round(statistics.mean(toks), 1) if toks else None,
                "tokens_median": statistics.median(toks) if toks else None, "tokens_max": max(toks) if toks else None,
                "wall_total_s": round(sum(walls), 1), "wall_mean_s": round(statistics.mean(walls), 2), "wall_max_s": round(max(walls), 1)}
    g["vi_cost"] = {arm: cost(rows) for arm, rows in (("A", A), ("B", B), ("C", C))}
    # (vii) decision rule
    a_inf_mean = statistics.mean(r["scores"]["completeness"]["inferences"] for r in A.values())
    thresholds = {"A_mean_inferences_per_case": round(a_inf_mean, 4), "strict_1.0": 1.0}
    rule = {}
    for arm, rows in (("B", B), ("C", C)):
        per_case = []
        for k in keys:
            a_claims = claim_ids(A[k]); a_all = a_claims | tool_ids(A[k])
            hyps = [c for c in rows[k]["state"]["claims"] if c["type"] == "HYPOTHESIS"]
            new_vs_claims = any(set(h.get("evidence_ids") or []) - a_claims for h in hyps)
            new_vs_all = any(set(h.get("evidence_ids") or []) - a_all for h in hyps)
            per_case.append({"case": f"{k[0]}/{k[1]}", "hypotheses": len(hyps),
                             "unsupported": rows[k]["scores"]["unsupported_claims"],
                             "hyp_cites_evidence_A_claims_did_not": new_vs_claims,
                             "hyp_cites_evidence_A_never_touched": new_vs_all,
                             "degraded": rows[k]["llm_degraded"]})
        for tname, t in thresholds.items():
            cond1 = sum(1 for p in per_case if p["unsupported"] <= t)
            cond2a = sum(1 for p in per_case if p["hyp_cites_evidence_A_claims_did_not"])
            cond2b = sum(1 for p in per_case if p["hyp_cites_evidence_A_never_touched"])
            both_a = sum(1 for p in per_case if p["unsupported"] <= t and p["hyp_cites_evidence_A_claims_did_not"])
            both_b = sum(1 for p in per_case if p["unsupported"] <= t and p["hyp_cites_evidence_A_never_touched"])
            rule.setdefault(arm, {})[tname] = {"cases_under_threshold": cond1, "cases_with_new_evidence_hypothesis_vs_A_claims": cond2a,
                                               "cases_with_new_evidence_hypothesis_vs_A_tools": cond2b,
                                               "cases_meeting_both_vs_claims": both_a, "cases_meeting_both_vs_tools": both_b}
        rule[arm]["per_case"] = per_case
    g["vii_decision_rule"] = {"thresholds": thresholds, **rule}
    # labels
    g["labels"] = {arm: {f"{c}/{i}": r["label_scores"] for (c, i), r in rows.items() if r.get("label_scores")}
                   for arm, rows in (("A", A), ("B", B), ("C", C))}
    # planner and degradation
    g["planner"] = {arm: {"cases_with_a_choice": sum(1 for v in p.values() if v["offered"]),
                          "steps_offered": sum(v["offered"] for v in p.values()), "steps_chosen": sum(v["chose"] for v in p.values()),
                          "unparseable_replies": sum(v["unparseable"] for v in p.values()),
                          "degraded_cases": [k for k, v in p.items() if v["degraded"]],
                          "per_case": p} for arm, p in planner.items()}
    g["degraded"] = {arm: [{"case": f"{c}/{i}", "status": r["llm_status"]} for (c, i), r in rows.items() if r["llm_degraded"]]
                     for arm, rows in (("B", B), ("C", C))}
    g["identity_hygiene"] = {arm: {"facts_inferred_from_pid": sum(r["scores"]["identity_hygiene"]["facts_inferred_from_pid"] for r in rows.values()),
                                   "ambiguous_pid_inferences": sum(r["scores"]["identity_hygiene"]["ambiguous_pid_inferences"] for r in rows.values())}
                             for arm, rows in (("A", A), ("B", B), ("C", C))}

    (OUT / "GRADING.json").write_text(json.dumps(g, indent=2), encoding="utf-8")

    lines = ["# M19 hypotheses, verbatim, for manual reading (prediction v)", "",
             "Every HYPOTHESIS claim each arm produced, with its evidence ids. Classification as",
             "actionable versus restating the findings is left to a human reader, as pre-registered.", ""]
    for arm, rows in (("A", A), ("B", B), ("C", C)):
        lines.append(f"## {ARMS[arm]}")
        for k in keys:
            hyps = [c for c in rows[k]["state"]["claims"] if c["type"] == "HYPOTHESIS"]
            if not hyps:
                continue
            lines.append(f"\n### {k[0]} / {k[1]}")
            for h in hyps:
                lines.append(f"- ({h.get('agent','?')}) {h['statement']}  \n  evidence: `{', '.join(h.get('evidence_ids') or [])}`")
        lines.append("")
    (OUT / "HYPOTHESES.md").write_text("\n".join(lines), encoding="utf-8")

    print(json.dumps({k: g[k] for k in ("i_evidence_correctness", "ii_unsupported", "iii_coverage", "v_hypotheses", "vi_cost", "identity_hygiene")}, indent=1))
    print("iv:", {arm: {"jaccard": v["jaccard_mean"], "asserted_not_mapped": v["asserted_not_mapped"], "mapped_not_asserted": v["mapped_not_asserted"]} for arm, v in g["iv_technique"].items()})
    print("vii:", {arm: {t: v for t, v in g["vii_decision_rule"][arm].items() if t != "per_case"} for arm in ("B", "C")})
    print("planner:", {arm: {k: v for k, v in p.items() if k != "per_case"} for arm, p in g["planner"].items()})
    print("degraded:", g["degraded"])
    print("labels:", json.dumps(g["labels"], indent=0)[:1500])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
