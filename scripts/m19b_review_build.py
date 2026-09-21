"""M19b-T1: build the blinded human-review package for the M19 hypotheses.

What this produces, and why it is two steps
--------------------------------------------
``extract`` re-runs the deterministic layer (hunt, triage, correlate) over every corpus
the M19 manifest names, asserts each corpus's telemetry hash still equals the hash the
manifest pinned, and writes ``case_context.json``: per case, the findings every arm
started from, and a one-line description of every event any hypothesis cites. It needs
the external corpora -- 254 MB of flaws.cloud among them -- and takes a couple of
minutes.

``render`` needs none of that. It reads ``case_context.json`` and the three frozen
``arm_*.json`` files and writes the reviewer's package. Splitting the two means the
worksheet can be rebuilt, re-shuffled or re-worded by anyone who has the repository,
without re-reading a corpus that is not committed to it -- and it means the expensive
step's output is a committed artifact whose provenance (hashes, commit, counts) can be
checked rather than re-derived only by whoever happens to hold the data.

Blinding, and what it is not
-----------------------------
The worksheet carries no arm name, no model name, no agent or facet name, no ordering,
no token count and no wall time; ``KEY.sealed.json`` carries all of it, plus the shuffle
seed. This is *procedural* blinding: the arm files and this script are both in the
repository, so a reviewer who wants to de-blind themselves can. The key exists so that a
reviewer who does not want to cannot do it by accident. That limitation is stated in the
reviewer's README rather than hidden behind the word "sealed".

Nothing here classifies a hypothesis. The pre-registration forbids a model grading the
model's output as the primary assessment, and a suggested answer would anchor the
reviewer, so the one computed column that sits near a judgement -- whether a cited event
id was already cited on that case by the deterministic pass -- is a fact about two id
sets and is labelled as one everywhere it appears.

Usage::

    python scripts/m19b_review_build.py extract --external-root <checkout with data/external>
    python scripts/m19b_review_build.py render
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import subprocess
import sys
from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

M19_DIR = ROOT / "reports" / "m19" / "ablation"
OUT_DIR = ROOT / "reports" / "m19b" / "review"
CONTEXT_PATH = OUT_DIR / "case_context.json"

ARMS = ("A", "B", "C")

BASELINE_ARM = "A"
"""The arm whose citations define "already cited on this case".

It is the deterministic arm: every hypothesis is compared against what the non-model
pass had already pointed at, which is the comparison the reviewer needs and the only one
that is identical for all three arms.
"""

DEFAULT_SEED = 20260914
"""Shuffle seed. Recorded in the key, never in the worksheet."""

CLASSIFICATIONS = (
    "NEW_ACTIONABLE",
    "NEW_USEFUL_NONACTIONABLE",
    "RESTATEMENT",
    "SPECULATIVE_PLAUSIBLE",
    "UNSUPPORTED",
    "WRONG",
)

FLAGS = (
    "introduced_new_evidence",
    "connected_existing_evidence_usefully",
    "paraphrased_deterministic_finding",
    "would_change_next_action",
)

ANSWER_COLUMNS = ("review_id", "classification", *FLAGS, "reviewer_note")

MD_IDS_SHOWN = 12
"""How many of a finding's cited event ids the Markdown worksheet prints before saying
how many more there are. The CSV carries every id, so nothing is lost -- this is a
readability bound on a document a human reads 102 entries of."""

REASON_CHARS = 400
"""Cap on a finding's reason in the Markdown worksheet. The measured maximum over the
M19 cases is below it; the cap exists so that one future verbose rule cannot make the
worksheet unreadable without anybody noticing."""


# --------------------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------------------


def _head() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:  # noqa: BLE001 -- a missing git is not a reason to lose the build
        return "unknown"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def load_arm(arm: str) -> dict[str, Any]:
    return json.loads((M19_DIR / f"arm_{arm}.json").read_text(encoding="utf-8"))


def hypothesis_claims(arm_doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Every HYPOTHESIS claim in an arm file, with its case and its index in that case.

    The index is the claim's position among *all* of the case's claims, not among its
    hypotheses: it is a pointer back into the artifact, and a pointer that only resolves
    if you first filter the list the way this function does would be a worse one.
    """
    out: list[dict[str, Any]] = []
    for case in arm_doc["cases"]:
        for index, claim in enumerate(case["state"].get("claims", [])):
            if claim.get("type") != "HYPOTHESIS":
                continue
            out.append({
                "corpus": case["corpus"],
                "case_id": case["case_id"],
                "claim_index": index,
                "agent": claim.get("agent") or "",
                "source": claim.get("source") or "",
                "statement": " ".join(str(claim.get("statement", "")).split()),
                "evidence_ids": list(claim.get("evidence_ids") or []),
            })
    return out


def cited_ids_by_case(arm_doc: dict[str, Any]) -> dict[tuple[str, str], set[str]]:
    """Every event id any claim of this arm cites, per case."""
    out: dict[tuple[str, str], set[str]] = defaultdict(set)
    for case in arm_doc["cases"]:
        key = (case["corpus"], case["case_id"])
        for claim in case["state"].get("claims", []):
            out[key].update(claim.get("evidence_ids") or [])
    return dict(out)


# --------------------------------------------------------------------------------------
# extract
# --------------------------------------------------------------------------------------


def _corpora_needed(manifest: dict[str, Any]) -> list[str]:
    """Corpus loader names for the manifest's cases, synthetic incidents collapsed.

    ``load_bundles`` takes the loader's name, and every ``synthetic:INC-00n`` corpus
    comes out of the one ``synthetic`` suite, so the names are not the corpus names.
    """
    names: list[str] = []
    for corpus in sorted({c["corpus"] for c in manifest["cases"]}):
        name = "synthetic" if corpus.startswith("synthetic:") else corpus
        if name not in names:
            names.append(name)
    return names


def _describe_events(telemetry: Any, wanted: set[str]) -> dict[str, dict[str, str]]:
    """One line per wanted event id: when, where and who, and what the event shows.

    The description is ``Telemetry.unified()``'s own ``summary`` -- the same one-line
    rendering the CLI and the agent tools produce -- rather than a second formatter
    written here, which would be free to disagree with what the arms were shown. The
    tables are filtered to the wanted ids first because one corpus here has 1.9M rows.
    """
    from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS
    from ath.telemetry.loader import Telemetry

    slices = {}
    for event_type in (EVENT_PROCESS, EVENT_NETWORK, EVENT_LOGON, EVENT_CONTROL):
        frame = telemetry.table(event_type)
        slices[event_type] = (
            frame if frame.empty else frame[frame["event_id"].isin(wanted)].copy()
        )
    trimmed = Telemetry(
        processes=slices[EVENT_PROCESS], network=slices[EVENT_NETWORK],
        logons=slices[EVENT_LOGON], controls=slices[EVENT_CONTROL],
    )
    described: dict[str, dict[str, str]] = {}
    for row in trimmed.unified().to_dict("records"):
        described[str(row["event_id"])] = {
            "timestamp": str(row["timestamp"]),
            "device": str(row["device"] or ""),
            "actor": str(row["user"] or ""),
            "event_type": str(row["event_type"]),
            "summary": " ".join(str(row["summary"] or "").split()),
        }
    return described


def extract(external_root: Path) -> dict[str, Any]:
    """Re-derive the deterministic layer and describe every event the arms cited."""
    import m18_cloud_detection as m18_cloud

    # The external corpora are not committed to this worktree. `load_corpus` reads them
    # relative to its own module ROOT, so pointing that at a checkout that does have
    # them is the whole redirection -- read-only, and nothing is written back there.
    m18_cloud.ROOT = external_root

    import m19_ablation as ablation
    from ath.evaluation.ablation import telemetry_hash

    manifest = json.loads((M19_DIR / "MANIFEST.json").read_text(encoding="utf-8"))
    manifest_cases = {(c["corpus"], c["case_id"]): c for c in manifest["cases"]}

    # Per case, the ids that case's own entries will need described: everything the
    # case's findings rest on, plus everything any arm's hypothesis on that case cited
    # -- which is not a subset, because a hypothesis may cite an event a tool returned
    # from outside the case.
    wanted_by_case: dict[tuple[str, str], set[str]] = defaultdict(set)
    for arm in ARMS:
        for claim in hypothesis_claims(load_arm(arm)):
            wanted_by_case[(claim["corpus"], claim["case_id"])].update(
                claim["evidence_ids"]
            )
    for key, entry in manifest_cases.items():
        wanted_by_case[key].update(entry["evidence_ids"])

    wanted_by_corpus: dict[str, set[str]] = defaultdict(set)
    for (corpus, _case_id), ids in wanted_by_case.items():
        wanted_by_corpus[corpus].update(ids)

    cases_out: list[dict[str, Any]] = []
    hash_checks: dict[str, dict[str, Any]] = {}

    for bundle in ablation.load_bundles(_corpora_needed(manifest)):
        corpus = bundle.name
        selected = {case_id for (c, case_id) in manifest_cases if c == corpus}
        if not selected:
            continue
        pinned_hash = next(
            entry["telemetry_hash"] for (c, _), entry in manifest_cases.items()
            if c == corpus
        )
        rebuilt_hash = telemetry_hash(bundle.telemetry)
        hash_checks[corpus] = {
            "manifest_telemetry_hash": pinned_hash,
            "rebuilt_telemetry_hash": rebuilt_hash,
            "equal": rebuilt_hash == pinned_hash,
        }
        described = _describe_events(bundle.telemetry, wanted_by_corpus[corpus])
        by_id = {case.case_id: case for case in bundle.cases}

        for case_id in sorted(selected):
            pinned_case = manifest_cases[(corpus, case_id)]
            case = by_id.get(case_id)
            if case is None:
                cases_out.append({
                    "corpus": corpus, "case_id": case_id, "rebuilt": False,
                    "severity": "", "rule_ids": [], "findings": [],
                    "case_evidence_ids": list(pinned_case["evidence_ids"]),
                    "finding_ids_match_manifest": False,
                    "evidence_ids_match_manifest": False,
                    "events": {
                        eid: described[eid]
                        for eid in sorted(wanted_by_case[(corpus, case_id)])
                        if eid in described
                    },
                })
                continue
            findings = [{
                "finding_id": finding.finding_id,
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": str(finding.severity),
                "device": finding.device,
                "actor": finding.user,
                "reason": " ".join(str(finding.reason).split()),
                "event_ids": list(finding.event_ids),
            } for finding in case.findings]
            case_ids = list(case.event_ids)
            cases_out.append({
                "corpus": corpus,
                "case_id": case_id,
                "rebuilt": True,
                "severity": str(case.severity),
                "rule_ids": list(case.rule_ids),
                "findings": findings,
                "case_evidence_ids": case_ids,
                "finding_ids_match_manifest": (
                    sorted(f["finding_id"] for f in findings)
                    == sorted(pinned_case["finding_ids"])
                ),
                "evidence_ids_match_manifest": (
                    sorted(case_ids) == sorted(pinned_case["evidence_ids"])
                ),
                "events": {
                    eid: described[eid]
                    for eid in sorted(set(case_ids) | wanted_by_case[(corpus, case_id)])
                    if eid in described
                },
            })

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "head": _head(),
        "purpose": (
            "Deterministic context for the M19b blinded hypothesis review: the findings "
            "every arm started from, and a one-line description of every event any "
            "hypothesis cites. Contains no model output and no arm identity."
        ),
        "manifest_hash": manifest["manifest_hash"],
        "telemetry_hash_checks": hash_checks,
        "arm_file_sha256": {arm: _sha256(M19_DIR / f"arm_{arm}.json") for arm in ARMS},
        "cases": cases_out,
    }


# --------------------------------------------------------------------------------------
# render
# --------------------------------------------------------------------------------------


def _entries(context: dict[str, Any], seed: int) -> list[dict[str, Any]]:
    """Every HYPOTHESIS claim from all three arms, shuffled, with its computed facts."""
    by_case = {(c["corpus"], c["case_id"]): c for c in context["cases"]}
    arm_docs = {arm: load_arm(arm) for arm in ARMS}
    baseline = cited_ids_by_case(arm_docs[BASELINE_ARM])

    pool: list[dict[str, Any]] = []
    for arm in ARMS:
        for claim in hypothesis_claims(arm_docs[arm]):
            pool.append({**claim, "arm": arm_docs[arm]["arm"]["name"], "arm_key": arm})

    # Sorted before the shuffle so the order depends on the seed alone, and not on the
    # order in which the arm files happen to list their cases.
    pool.sort(key=lambda c: (c["arm_key"], c["corpus"], c["case_id"], c["claim_index"]))
    random.Random(seed).shuffle(pool)

    entries: list[dict[str, Any]] = []
    for number, claim in enumerate(pool, start=1):
        key = (claim["corpus"], claim["case_id"])
        case = by_case.get(key) or {
            "findings": [], "events": {}, "case_evidence_ids": [],
        }
        already = baseline.get(key, set())
        cited = []
        for event_id in claim["evidence_ids"]:
            described = case["events"].get(event_id)
            cited.append({
                "event_id": event_id,
                "timestamp": described["timestamp"] if described else "",
                "device": described["device"] if described else "",
                "actor": described["actor"] if described else "",
                "summary": (
                    described["summary"] if described
                    else "NOT DESCRIBABLE: this id is in no table of the case's corpus"
                ),
                "described": bool(described),
                "already_cited": event_id in already,
            })
        entries.append({
            "review_id": f"R{number:03d}",
            "corpus": claim["corpus"],
            "case_id": claim["case_id"],
            "statement": claim["statement"],
            "cited": cited,
            "new_ids": [c["event_id"] for c in cited if not c["already_cited"]],
            "undescribed_ids": [c["event_id"] for c in cited if not c["described"]],
            "findings": case["findings"],
            "case_evidence_count": len(case["case_evidence_ids"]),
            "_arm": claim["arm"],
            "_arm_key": claim["arm_key"],
            "_claim_index": claim["claim_index"],
            "_agent": claim["agent"],
            "_source": claim["source"],
        })
    return entries


def _ids_for_md(ids: Sequence[str]) -> str:
    shown = ", ".join(f"`{i}`" for i in ids[:MD_IDS_SHOWN])
    if len(ids) > MD_IDS_SHOWN:
        shown += (
            f" ... (+{len(ids) - MD_IDS_SHOWN} more; all of them are in worksheet.csv)"
        )
    return shown or "_none_"


def _cell(text: str) -> str:
    """Markdown-table-safe: a pipe in an event summary would otherwise split the row."""
    return " ".join(str(text).split()).replace("|", "\\|")


def render_worksheet_md(entries: Sequence[dict[str, Any]]) -> str:
    lines: list[str] = [
        "# M19 hypothesis review worksheet",
        "",
        f"{len(entries)} hypotheses, one per entry, in a shuffled order. Read "
        "`README.md` first, and do not open `KEY.sealed.json`.",
        "",
        "Each entry is self-contained: a case's deterministic findings are repeated "
        "under every hypothesis drawn from that case, because the entries are shuffled "
        "and nothing may be inferred from what sits next to what.",
        "",
        '"Already cited" is computed, not judged. It says whether the deterministic '
        "pass on this same case had itself already cited that event id; it is a fact "
        "about two sets of ids and says nothing about whether the hypothesis is any "
        "good.",
        "",
        "Record your answers in `answers_template.csv`.",
        "",
        "---",
        "",
    ]

    for entry in entries:
        lines += [
            f"## {entry['review_id']}",
            "",
            f"**Case:** `{entry['corpus']}` / `{entry['case_id']}` "
            f"({entry['case_evidence_count']} events in the case)",
            "",
            "**Deterministic findings on this case, as every pass saw them:**",
            "",
        ]
        if entry["findings"]:
            lines += [
                "| rule | severity | why it fired | events it cites |",
                "| --- | --- | --- | --- |",
            ]
            for finding in entry["findings"]:
                reason = _cell(finding["reason"])
                if len(reason) > REASON_CHARS:
                    reason = (
                        reason[:REASON_CHARS].rstrip()
                        + " ... (full text in worksheet.csv)"
                    )
                lines.append(
                    f"| `{finding['rule_id']}` | {finding['severity']} | {reason} | "
                    f"{len(finding['event_ids'])}: {_ids_for_md(finding['event_ids'])} |"
                )
        else:
            lines.append("_The deterministic findings for this case were unavailable._")

        lines += [
            "",
            "**Hypothesis (verbatim):**",
            "",
            f"> {entry['statement']}",
            "",
            f"**Evidence it cites ({len(entry['cited'])}):**",
            "",
        ]
        if entry["cited"]:
            lines += [
                "| event id | timestamp (UTC) | device / actor | what the event shows "
                "| already cited on this case? |",
                "| --- | --- | --- | --- | --- |",
            ]
            for cited in entry["cited"]:
                where = " / ".join(x for x in (cited["device"], cited["actor"]) if x)
                lines.append(
                    f"| `{cited['event_id']}` | {cited['timestamp']} | {_cell(where)} | "
                    f"{_cell(cited['summary'])} | "
                    f"{'yes' if cited['already_cited'] else 'NO'} |"
                )
            lines += [
                "",
                f"**Computed:** {len(entry['new_ids'])} of {len(entry['cited'])} cited "
                "ids were not cited on this case by the deterministic pass.",
            ]
        else:
            lines.append("_This hypothesis cites no event ids._")
        lines += ["", "---", ""]
    return "\n".join(lines)


WORKSHEET_CSV_COLUMNS = (
    "review_id",
    "corpus",
    "case_id",
    "case_event_count",
    "deterministic_findings",
    "hypothesis",
    "cited_event_ids",
    "cited_event_count",
    "cited_event_descriptions",
    "cited_ids_not_cited_by_deterministic_pass",
    "new_cited_id_count",
    "cited_ids_absent_from_corpus_tables",
)


def worksheet_rows(entries: Sequence[dict[str, Any]]) -> list[dict[str, str]]:
    """The Markdown worksheet's rows, one per entry, with nothing elided."""
    rows: list[dict[str, str]] = []
    for entry in entries:
        findings = " || ".join(
            f"{f['rule_id']} [{f['severity']}] {f['reason']} "
            f"(events: {' '.join(f['event_ids'])})"
            for f in entry["findings"]
        )
        described = " || ".join(
            f"{c['event_id']} @ {c['timestamp']} "
            f"[{' / '.join(x for x in (c['device'], c['actor']) if x)}] {c['summary']} "
            f"(already cited: {'yes' if c['already_cited'] else 'no'})"
            for c in entry["cited"]
        )
        rows.append({
            "review_id": entry["review_id"],
            "corpus": entry["corpus"],
            "case_id": entry["case_id"],
            "case_event_count": str(entry["case_evidence_count"]),
            "deterministic_findings": findings,
            "hypothesis": entry["statement"],
            "cited_event_ids": " ".join(c["event_id"] for c in entry["cited"]),
            "cited_event_count": str(len(entry["cited"])),
            "cited_event_descriptions": described,
            "cited_ids_not_cited_by_deterministic_pass": " ".join(entry["new_ids"]),
            "new_cited_id_count": str(len(entry["new_ids"])),
            "cited_ids_absent_from_corpus_tables": " ".join(entry["undescribed_ids"]),
        })
    return rows


def _write_csv(
    path: Path, columns: Sequence[str], rows: Iterable[dict[str, str]],
) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(columns), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def build_key(entries: Sequence[dict[str, Any]], seed: int) -> dict[str, Any]:
    arm_docs = {arm: load_arm(arm) for arm in ARMS}
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "head": _head(),
        "warning": (
            "The unblinding key for reports/m19b/review/worksheet.md. A reviewer must "
            "not read this file before submitting their answers."
        ),
        "seed": seed,
        "shuffle": (
            "entries sorted by (arm, corpus, case_id, claim_index), then "
            "random.Random(seed).shuffle"
        ),
        "baseline_arm": arm_docs[BASELINE_ARM]["arm"]["name"],
        # `cases_run` is the per-case denominator the scorer divides by, and the two
        # counts beside it are the reason it needs company: a case where the model was
        # unavailable, or where the run hit its step limit, produces few hypotheses for
        # a reason that is not restraint, and a per-case rate that hid that would read
        # as a finding about the architecture.
        "arms": {
            arm: {
                "name": doc["arm"]["name"],
                "model": doc["arm"].get("model") or "",
                "cases_run": len(doc["cases"]),
                "cases_model_degraded": sum(
                    1 for case in doc["cases"] if case.get("llm_degraded")
                ),
                "cases_incomplete": sum(
                    1 for case in doc["cases"]
                    if case["state"].get("status") != "complete"
                ),
            }
            for arm, doc in arm_docs.items()
        },
        "entries": {
            entry["review_id"]: {
                "arm": entry["_arm"],
                "corpus": entry["corpus"],
                "case_id": entry["case_id"],
                "claim_index": entry["_claim_index"],
                "agent": entry["_agent"],
                "source": entry["_source"],
            }
            for entry in entries
        },
    }


def render(seed: int) -> dict[str, Any]:
    context = json.loads(CONTEXT_PATH.read_text(encoding="utf-8"))
    entries = _entries(context, seed)

    (OUT_DIR / "worksheet.md").write_text(render_worksheet_md(entries), encoding="utf-8")
    _write_csv(OUT_DIR / "worksheet.csv", WORKSHEET_CSV_COLUMNS, worksheet_rows(entries))
    _write_csv(
        OUT_DIR / "answers_template.csv",
        ANSWER_COLUMNS,
        [
            {"review_id": e["review_id"], **{c: "" for c in ANSWER_COLUMNS[1:]}}
            for e in entries
        ],
    )
    (OUT_DIR / "KEY.sealed.json").write_text(
        json.dumps(build_key(entries, seed), indent=2) + "\n", encoding="utf-8"
    )

    per_arm: dict[str, int] = defaultdict(int)
    per_case: dict[str, int] = defaultdict(int)
    for entry in entries:
        per_arm[entry["_arm"]] += 1
        per_case[f"{entry['corpus']}/{entry['case_id']}"] += 1
    return {
        "entries": len(entries),
        "per_arm": dict(per_arm),
        "per_case": dict(sorted(per_case.items())),
        "undescribed": sorted({i for e in entries for i in e["undescribed_ids"]}),
        "no_evidence_entries": [e["review_id"] for e in entries if not e["cited"]],
    }


# --------------------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the M19b review package.")
    sub = parser.add_subparsers(dest="command", required=True)

    extract_cmd = sub.add_parser("extract", help="re-derive the deterministic context")
    extract_cmd.add_argument(
        "--external-root", type=Path, required=True,
        help="checkout whose data/external holds the corpora; read, never written",
    )

    render_cmd = sub.add_parser("render", help="write the reviewer's package")
    render_cmd.add_argument("--seed", type=int, default=DEFAULT_SEED)

    args = parser.parse_args(argv)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    if args.command == "extract":
        context = extract(args.external_root.resolve())
        CONTEXT_PATH.write_text(json.dumps(context, indent=1) + "\n", encoding="utf-8")
        mismatched_hashes = [
            corpus for corpus, check in context["telemetry_hash_checks"].items()
            if not check["equal"]
        ]
        mismatched_cases = [
            f"{c['corpus']}/{c['case_id']}" for c in context["cases"]
            if not (c["finding_ids_match_manifest"] and c["evidence_ids_match_manifest"])
        ]
        print(f"wrote {CONTEXT_PATH} ({CONTEXT_PATH.stat().st_size / 1024:.0f} KB)")
        print(f"  cases: {len(context['cases'])}")
        print(f"  telemetry hash mismatches: {mismatched_hashes or 'none'}")
        print(f"  cases differing from the manifest: {mismatched_cases or 'none'}")
        return 1 if mismatched_hashes or mismatched_cases else 0

    summary = render(args.seed)
    print(f"wrote the review package to {OUT_DIR}")
    print(f"  entries: {summary['entries']}  per arm: {summary['per_arm']}")
    print(f"  entries citing no evidence: {summary['no_evidence_entries']}")
    print(f"  cited ids absent from the corpus tables: {summary['undescribed'] or 'none'}")
    print("  hypotheses per case:")
    for case, count in summary["per_case"].items():
        print(f"    {case}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
