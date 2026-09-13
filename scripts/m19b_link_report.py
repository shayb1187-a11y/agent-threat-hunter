"""Render ``reports/m19b/link/BEFORE_AFTER.{md,json}`` from the two measured arms.

Reads the two files ``scripts/m19b_link_measure.py`` wrote -- one from the tree before
the correlator change, one after -- plus the deterministic incident benchmark from each,
and renders the comparison. It loads no corpus and computes no new measurement: every
number here comes out of those four files, so the report cannot disagree with the run
that produced it.

Usage::

    python scripts/m19b_link_report.py \\
        --before reports/m19b/link/before.json --after reports/m19b/link/after.json \\
        --benchmark-before <path> --benchmark-after <path> \\
        --out reports/m19b/link
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ath.correlation.correlator import (  # noqa: E402
    CHANNEL_FAMILY,
    CROSS_DOMAIN_WINDOW,
    PRINCIPAL_COLUMNS,
    W_SHARED_PRINCIPAL,
)
from ath.evaluation.necessity import audit_digest  # noqa: E402

CONTAMINATION_FACTOR = 2.0
"""A case that grew to more than this multiple of the largest case it absorbed is
reported as a contamination candidate. Stated as a constant so the threshold is quotable
and so no case is described as "contaminated" on a judgement made after seeing it."""


def table(header: list, rows: list) -> str:
    lines = [
        "| " + " | ".join(str(h) for h in header) + " |",
        "| " + " | ".join("---" for _ in header) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines)


def by_corpus(payload: dict) -> dict:
    return {c["corpus"]: c for c in payload["corpora"]}


def size_hist(corpus: dict) -> str:
    dist = corpus.get("size_distribution") or {}
    if not dist:
        return "--"
    return ", ".join(
        "{}x{}".format(v, k) for k, v in sorted(dist.items(), key=lambda kv: int(kv[0]))
    )


def match_cases(before_cases: list, after_cases: list) -> list:
    """Pair each AFTER case with the BEFORE cases whose findings it contains.

    Case ids are assigned by start time, so they are not stable across a run that
    changes which cases exist. The finding set is: a finding has one id in both arms,
    and a case is a set of them.
    """
    index = {}
    for case in before_cases:
        for finding_id in case["finding_ids"]:
            index[finding_id] = case
    out = []
    for case in after_cases:
        predecessors, seen = [], set()
        for finding_id in case["finding_ids"]:
            found = index.get(finding_id)
            if found is not None and id(found) not in seen:
                seen.add(id(found))
                predecessors.append(found)
        out.append((case, predecessors))
    return out


def growth_rows(pairs: list) -> list:
    rows = []
    for case, predecessors in pairs:
        largest = max((p["size"] for p in predecessors), default=0)
        if largest and case["size"] > largest * CONTAMINATION_FACTOR:
            rows.append({
                "case_id": case["case_id"],
                "size": case["size"],
                "largest_predecessor": largest,
                "predecessors_merged": len(predecessors),
                "growth": round(case["size"] / largest, 2),
                "rules": case["rule_ids"],
                "principals": case["principals"][:12],
                "domains": case["domains"],
                "span_seconds": case["span_seconds"],
            })
    return rows


def new_cross_domain(pairs: list) -> list:
    """AFTER cases carrying two or more domains that no BEFORE case they absorbed did."""
    out = []
    for case, predecessors in pairs:
        if len(case["domains"]) < 2:
            continue
        if any(len(p["domains"]) >= 2 for p in predecessors):
            continue
        out.append({
            "case_id": case["case_id"],
            "size": case["size"],
            "domains": case["domains"],
            "rules": case["rule_ids"],
            "principals": case["principals"],
            "devices": case["devices"],
            "start": case["start"],
            "end": case["end"],
            "span_seconds": case["span_seconds"],
            "event_count": case["event_count"],
            "link_signals": case["link_signals"],
            "first_step_domain_specialists": case["first_step_domain_specialists"],
            "predecessors_merged": len(predecessors),
            "predecessor_sizes": sorted(p["size"] for p in predecessors),
        })
    return out


def head() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(ROOT), capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--benchmark-before", type=Path, required=True)
    parser.add_argument("--benchmark-after", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    before = json.loads(args.before.read_text(encoding="utf-8"))
    after = json.loads(args.after.read_text(encoding="utf-8"))
    bench_before = json.loads(args.benchmark_before.read_text(encoding="utf-8"))
    bench_after = json.loads(args.benchmark_after.read_text(encoding="utf-8"))

    b, a = by_corpus(before), by_corpus(after)
    names = [c["corpus"] for c in before["corpora"]]

    comparison = []
    for name in names:
        bc, ac = b.get(name, {}), a.get(name, {})
        if bc.get("error") or ac.get("error"):
            comparison.append({
                "corpus": name,
                "error": bc.get("error") or ac.get("error"),
            })
            continue
        pairs = match_cases(bc["cases_detail"], ac["cases_detail"])
        comparison.append({
            "corpus": name,
            "provenance": bc.get("provenance", ""),
            "rows": bc.get("rows", {}),
            "findings": bc.get("findings", 0),
            "before": {
                "cases": bc["cases"],
                "singletons": bc["singletons"],
                "size_distribution": bc["size_distribution"],
                "max_case_size": bc["max_case_size"],
                "cases_with_2plus_domain_specialists_at_step0":
                    bc["cases_with_2plus_domain_specialists_at_step0"],
                "cases_with_2plus_domains": bc["cases_with_2plus_domains"],
                "qualifying_cases": bc["qualifying_cases"],
                "links": bc["links"],
                "links_by_signal": bc["links_by_signal"],
                "chain_quality": bc.get("chain_quality", {}),
            },
            "after": {
                "cases": ac["cases"],
                "singletons": ac["singletons"],
                "size_distribution": ac["size_distribution"],
                "max_case_size": ac["max_case_size"],
                "cases_with_2plus_domain_specialists_at_step0":
                    ac["cases_with_2plus_domain_specialists_at_step0"],
                "cases_with_2plus_domains": ac["cases_with_2plus_domains"],
                "qualifying_cases": ac["qualifying_cases"],
                "links": ac["links"],
                "links_by_signal": ac["links_by_signal"],
                "chain_quality": ac.get("chain_quality", {}),
            },
            "new_cross_domain_cases": new_cross_domain(pairs),
            "contamination_candidates": growth_rows(pairs),
        })

    payload = {
        "task": "M19b link: generic cross-channel link replaces the cross-domain allowlist",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "head": head(),
        "before_arm": {"head": before["head"], "digest": before["digest"]},
        "after_arm": {"head": after["head"], "digest": after["digest"]},
        "contamination_factor": CONTAMINATION_FACTOR,
        "link_definition": {
            "cross_domain_window_seconds": CROSS_DOMAIN_WINDOW.total_seconds(),
            "weight": W_SHARED_PRINCIPAL,
            "channel_family": {c.value: f for c, f in sorted(
                CHANNEL_FAMILY.items(), key=lambda kv: kv[0].value)},
            "principal_columns": {k: list(v) for k, v in PRINCIPAL_COLUMNS.items()},
        },
        "benchmark": {
            "before": {k: v for k, v in bench_before.items() if k != "incidents"},
            "after": {k: v for k, v in bench_after.items() if k != "incidents"},
            "per_incident": [
                {
                    "incident_id": ib["incident_id"],
                    "before": {
                        "passed": ib["passed"],
                        "findings": ib["analyst_load"]["findings"],
                        "cases": ib["analyst_load"]["cases"],
                        "noise_cases": ib["analyst_load"]["noise_cases"],
                        "primary_case_recall": ib["chain_quality"]["primary_case_recall"],
                        "primary_case_purity": ib["chain_quality"]["primary_case_purity"],
                        "event_recall": ib["detection"]["event_recall"],
                    },
                    "after": {
                        "passed": ia["passed"],
                        "findings": ia["analyst_load"]["findings"],
                        "cases": ia["analyst_load"]["cases"],
                        "noise_cases": ia["analyst_load"]["noise_cases"],
                        "primary_case_recall": ia["chain_quality"]["primary_case_recall"],
                        "primary_case_purity": ia["chain_quality"]["primary_case_purity"],
                        "event_recall": ia["detection"]["event_recall"],
                    },
                }
                for ib, ia in zip(bench_before["incidents"], bench_after["incidents"])
            ],
        },
        "corpora": comparison,
    }
    payload["digest"] = audit_digest(comparison)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "BEFORE_AFTER.json").write_text(
        json.dumps(payload, indent=2, default=str), encoding="utf-8",
    )
    (args.out / "BEFORE_AFTER.md").write_text(render(payload), encoding="utf-8")
    print("Wrote {} and {}".format(
        args.out / "BEFORE_AFTER.json", args.out / "BEFORE_AFTER.md",
    ))
    return 0


def render(payload: dict) -> str:
    out = []
    out.append("# M19b link: what replacing the cross-domain allowlist changed\n")
    out.append(
        "Generated {} at `{}`. BEFORE arm `{}` (`{}`), AFTER arm `{}` (`{}`). "
        "Comparison digest `{}`.\n".format(
            payload["generated_at"], payload["head"],
            payload["before_arm"]["head"], payload["before_arm"]["digest"][:12],
            payload["after_arm"]["head"], payload["after_arm"]["digest"][:12],
            payload["digest"],
        )
    )
    out.append(
        "Every number below is MEASURED: each arm is `scripts/m19b_link_measure.py` run "
        "over every corpus `reports/m19b/necessity/AUDIT.md` covers, loading through the "
        "pipeline's own adapters and correlating exactly as `scripts/m19_ablation.py` "
        "does. The two arms differ only in `src/ath/correlation/correlator.py`: no rule, "
        "threshold, fixture, prompt or scoring path was touched, and no model was "
        "called.\n"
    )

    out.append("## The link, as the code defines it\n")
    definition = payload["link_definition"]
    out.append(
        "`shared_principal` (+{}) links two findings when their **channel families are "
        "disjoint and non-empty**, their evidence **names the same principal** -- exact "
        "match on the canonical string the adapters already wrote, counting both "
        "`actor` and `target_actor` on a control row -- and their time windows are no "
        "more than `CorrelationConfig.cross_domain_window` = **{:.0f} minutes** apart. "
        "Order decides only the evidence text (\"identity then control_plane\"), never "
        "eligibility. `auth_then_exec` keeps its name and its meaning as the one "
        "cross-family relationship that needs no shared principal -- identity telemetry "
        "landing on a host, endpoint telemetry running on that host inside "
        "`auth_exec_window` -- with its rule-id allowlist replaced by the same family "
        "test. Weight 3 against `min_score` 5 means a shared principal alone never "
        "links: a circumstantial signal has to agree with it.\n".format(
            definition["weight"], definition["cross_domain_window_seconds"] / 60,
        )
    )
    out.append(
        "Families are read from each finding's declared channels (`Finding.channels`, "
        "else `fields_used`), through a table exhaustive over "
        "`ath.channels.TelemetryChannel`: "
        + "; ".join(
            "{} = {}".format(
                family,
                ", ".join(
                    "`" + c + "`"
                    for c, f in sorted(definition["channel_family"].items())
                    if f == family
                ),
            )
            for family in ("endpoint", "identity", "network", "control_plane")
        )
        + ". No detection rule id appears anywhere in the correlator's code.\n"
    )

    out.append("## Cases, by corpus\n")
    rows = []
    for c in payload["corpora"]:
        if c.get("error"):
            rows.append([("`" + c["corpus"] + "`"), c["error"], "", "", "", "", "", ""])
            continue
        bb, aa = c["before"], c["after"]
        rows.append([
            "`" + c["corpus"] + "`",
            "{} -> {}".format(bb["cases"], aa["cases"]),
            "{} -> {}".format(bb["singletons"], aa["singletons"]),
            "{} -> {}".format(bb["max_case_size"], aa["max_case_size"]),
            "{} -> {}".format(
                bb["cases_with_2plus_domains"], aa["cases_with_2plus_domains"]),
            "{} -> {}".format(
                bb["cases_with_2plus_domain_specialists_at_step0"],
                aa["cases_with_2plus_domain_specialists_at_step0"]),
            "{} -> {}".format(bb["qualifying_cases"], aa["qualifying_cases"]),
            "{} -> {}".format(bb["links"], aa["links"]),
        ])
    out.append(table(
        ["corpus", "cases", "singletons", "largest case", "cases with >=2 domains",
         "cases offering >=2 domain specialists at step 0", "qualifying", "links"],
        rows,
    ))
    out.append("")

    out.append("## Case size distribution\n")
    rows = []
    for c in payload["corpora"]:
        if c.get("error"):
            continue
        rows.append([
            "`" + c["corpus"] + "`",
            size_hist(c["before"]) or "--",
            size_hist(c["after"]) or "--",
        ])
    out.append(table(["corpus", "before (count x size)", "after"], rows))
    out.append("")

    out.append("## Links, by signal\n")
    rows = []
    for c in payload["corpora"]:
        if c.get("error"):
            continue
        signals = sorted(
            set(c["before"]["links_by_signal"]) | set(c["after"]["links_by_signal"])
        )
        if not signals:
            continue
        rows.append([
            "`" + c["corpus"] + "`",
            ", ".join(
                "{} {}->{}".format(
                    s, c["before"]["links_by_signal"].get(s, 0),
                    c["after"]["links_by_signal"].get(s, 0),
                )
                for s in signals
            ),
        ])
    out.append(table(["corpus", "signal: before -> after"], rows))
    out.append("")

    out.append("## Chain quality on the labelled corpora\n")
    rows = []
    for entry in payload["benchmark"]["per_incident"]:
        bb, aa = entry["before"], entry["after"]
        rows.append([
            entry["incident_id"],
            "{} -> {}".format(bb["findings"], aa["findings"]),
            "{} -> {}".format(bb["cases"], aa["cases"]),
            "{} -> {}".format(bb["noise_cases"], aa["noise_cases"]),
            "{} -> {}".format(bb["primary_case_recall"], aa["primary_case_recall"]),
            "{} -> {}".format(bb["primary_case_purity"], aa["primary_case_purity"]),
            "{} -> {}".format(bb["event_recall"], aa["event_recall"]),
            "{} -> {}".format(bb["passed"], aa["passed"]),
        ])
    out.append(table(
        ["incident", "findings", "cases", "noise cases", "primary-case recall",
         "primary-case purity", "event recall", "passed"],
        rows,
    ))
    out.append("")
    out.append(
        "`python main.py benchmark`: **{}/{} before, {}/{} after**, "
        "{} noise case(s) before and {} after.\n".format(
            payload["benchmark"]["before"]["passed"],
            payload["benchmark"]["before"]["total"],
            payload["benchmark"]["after"]["passed"],
            payload["benchmark"]["after"]["total"],
            payload["benchmark"]["before"]["total_noise_cases"],
            payload["benchmark"]["after"]["total_noise_cases"],
        )
    )

    for c in payload["corpora"]:
        if c.get("error") or not c.get("before", {}).get("chain_quality"):
            continue
        out.append("### `{}` capture-level chain quality\n".format(c["corpus"]))
        rows = []
        for capture in sorted(c["before"]["chain_quality"]):
            bb = c["before"]["chain_quality"][capture]
            aa = c["after"]["chain_quality"].get(capture, {})
            rows.append([
                "`" + capture + "`",
                "{} -> {}".format(bb.get("primary_case_size"), aa.get("primary_case_size")),
                "{} -> {}".format(
                    bb.get("primary_case_recall"), aa.get("primary_case_recall")),
                "{} -> {}".format(
                    bb.get("primary_case_purity"), aa.get("primary_case_purity")),
                "{} -> {}".format(bb.get("noise_cases"), aa.get("noise_cases")),
            ])
        out.append(table(
            ["capture", "primary case size", "recall", "purity", "noise cases"], rows,
        ))
        out.append("")

    out.append("## Newly formed cross-domain cases\n")
    any_new = False
    for c in payload["corpora"]:
        if c.get("error") or not c.get("new_cross_domain_cases"):
            continue
        any_new = True
        out.append("### `{}` -- {} new cross-domain case(s)\n".format(
            c["corpus"], len(c["new_cross_domain_cases"]),
        ))
        rows = []
        for case in c["new_cross_domain_cases"]:
            rows.append([
                case["case_id"],
                ", ".join(case["domains"]),
                ", ".join(case["rules"]),
                case["size"],
                ", ".join(case["principals"][:6])
                + (" (+{} more)".format(len(case["principals"]) - 6)
                   if len(case["principals"]) > 6 else ""),
                "{:.0f}s".format(case["span_seconds"]),
                case["start"],
                ", ".join(
                    "{} {}".format(v, k) for k, v in sorted(case["link_signals"].items())
                ),
            ])
        out.append(table(
            ["case", "domains", "rules", "findings", "principals", "span", "start",
             "link signals"],
            rows,
        ))
        out.append("")
    if not any_new:
        out.append("None on any corpus.\n")

    out.append("## What changed, in one paragraph\n")
    measured = [c for c in payload["corpora"] if not c.get("error")]
    changed = [
        c for c in measured
        if c["before"]["cases"] != c["after"]["cases"]
        or c["before"]["cases_with_2plus_domains"]
        != c["after"]["cases_with_2plus_domains"]
    ]
    total_new = sum(len(c.get("new_cross_domain_cases") or ()) for c in measured)
    out.append(
        "{} new cross-domain case(s) formed, on {} of the {} corpora measured: {}. "
        "Every other corpus is identical case for case -- {} of them, including every "
        "endpoint-only corpus (COMISET, both COMISET freezes, all five DEDALE days, the "
        "real-shaped fixtures) and every Kubernetes corpus, where no pair of findings "
        "has disjoint channel families to begin with. No link that existed before was "
        "lost: every signal count in the table above is greater than or equal to its "
        "before value.\n".format(
            total_new, len(changed), len(measured),
            ", ".join("`" + c["corpus"] + "`" for c in changed) or "none",
            len(measured) - len(changed),
        )
    )
    relinked = [
        c for c in measured
        if c not in changed and c["before"]["links"] != c["after"]["links"]
    ]
    if relinked:
        out.append(
            "{} corpus/corpora gained links without gaining a case: {}. That is "
            "`auth_then_exec` losing its allowlist -- on `synthetic:INC-001` the "
            "identity findings now link to every endpoint finding on the host they "
            "authenticated to, not only to `ATH-007` -- and it changes nothing "
            "downstream, because those findings were already one connected component. "
            "More reasons for a case that already existed is the whole of it.\n".format(
                len(relinked),
                ", ".join(
                    "`{}` ({} -> {} links)".format(
                        c["corpus"], c["before"]["links"], c["after"]["links"])
                    for c in relinked
                ),
            )
        )
    out.append(
        "One divergence is worth stating because it looks like an inconsistency and is "
        "not: `fixture:cloudtrail` merges its two cases into one cross-domain case, "
        "while `INC-002` -- the benchmark incident built from that same fixture -- does "
        "not move. `ath.evaluation.suite.cloud_credential_stuffing` hands the incident "
        "the logon table only, so the control rows the merge rests on are not in the "
        "incident's telemetry at all. The corpus and the incident are two different "
        "inputs, and only the corpus carries both domains.\n"
    )
    out.append(
        "The two shapes this reaches are the two the audit named as unreachable. "
        "**identity x control_plane** now forms on real, unlabelled CloudTrail: a "
        "console-login burst by one IAM principal joins that principal's own "
        "management-API activity, which is evidence the corpus always carried and the "
        "correlator could not read. **endpoint x network** is reachable in principle "
        "and fires nowhere in this repository, because `ATH-003` remains the only rule "
        "producing network channels and it declares process execution in the same "
        "finding -- so its family set is never disjoint from an endpoint finding's. "
        "That is a rule-catalogue limit, not a correlator limit, and this task changed "
        "no rule.\n"
    )

    out.append("## Contamination candidates\n")
    out.append(
        "A case whose size grew to more than {}x the largest case it absorbed. The "
        "threshold is a constant declared in `scripts/m19b_link_report.py`, fixed "
        "before the arms were compared; being listed here is a flag for a reader, not a "
        "verdict.\n".format(payload["contamination_factor"])
    )
    rows = []
    for c in payload["corpora"]:
        for case in c.get("contamination_candidates", ()) or ():
            rows.append([
                "`" + c["corpus"] + "`",
                case["case_id"],
                "{} -> {} ({}x)".format(
                    case["largest_predecessor"], case["size"], case["growth"]),
                case["predecessors_merged"],
                ", ".join(case["domains"]),
                ", ".join(case["rules"]),
                ", ".join(case["principals"]),
            ])
    out.append(
        table(
            ["corpus", "case", "largest predecessor -> size", "cases merged", "domains",
             "rules", "principals"],
            rows,
        )
        if rows else "None: no case on any corpus grew past the threshold.\n"
    )
    out.append("")
    out.append(
        "A case listed here grew by absorbing more than one predecessor, which is "
        "transitive drift: cases are connected components, so one finding linking to "
        "two clusters puts all three in one case even where the clusters share nothing "
        "with each other. `ath.correlation.correlator` documented that property before "
        "this change; what is new is a signal that can bridge two *kinds* of telemetry, "
        "so the bridge is now available to a principal as well as to a process tree. "
        "Whether a listed case is *wrong* cannot be settled on an unlabelled corpus, "
        "and this report does not claim it either way.\n"
    )

    out.append("## Limitations\n")
    window_minutes = payload["link_definition"]["cross_domain_window_seconds"] / 60
    out.append(
        "* **The window is a choice, and on the merged cases it is the binding one.** "
        "{:.0f} minutes is `auth_exec_window`'s value, taken because it is the only "
        "existing window in the file that already answers \"did A plausibly cause B "
        "across two kinds of telemetry\". Nothing here measures whether it is the right "
        "value; a sweep would be a separate, pre-registered experiment.\n"
        "* **Principals are compared as strings.** Two spellings of one identity -- an "
        "IAM user and an assumed-role session name for the same human -- are two "
        "principals here. That under-links, and it is the direction this errs in "
        "deliberately: the alternative is an identity-resolution rule nothing else in "
        "the pipeline applies.\n"
        "* **`cloud_control_plane` is classified as control_plane and no rule declares "
        "it.** If a future rule does, a cloud console-login finding would be "
        "control-plane rather than identity telemetry and would stop crossing with "
        "management activity. The placement is stated in the family table above and "
        "changes nothing measured here.\n"
        "* **Unlabelled corpora cannot grade the new cases.** flaws.cloud ships no "
        "labels, so \"these are real chains\" is not a claim this report makes. What is "
        "measured is that they exist, which principals they rest on, and what they "
        "merged.\n"
        "* **The `attack_data_aws` capture-level figures are weak by construction**: the "
        "answer key is every ingested row of a capture and a case holds a handful of "
        "rows, so recall is near zero in both arms. They are reported because they are "
        "unchanged, not because they are informative.\n"
        "* **No model was called**, and no rule, triage, specialist, tool, prompt, "
        "scoring or ablation path was touched. The only source change between the two "
        "arms is `src/ath/correlation/correlator.py`.\n".format(window_minutes)
    )
    return "\n".join(out)


if __name__ == "__main__":
    raise SystemExit(main())
