"""V1 dev split: a 20-case manifest disjoint by construction from every frozen benchmark.

Composition (the user's 2026-09-14 decision, with one recorded substitution)
------------------------------------------------------------------------------
* 10 fresh DEDALE-injected labelled cases (``scripts/local_inject_dedale.py``, day D02);
* ``synthetic:INC-003`` -- the one standard-suite incident neither M19 nor M19b froze;
* real, unlabelled ``flaws_cloud`` cases outside both frozen manifests, stratified by
  leading rule under a recorded seed, filling every seat the corpora above leave empty.

The decision said 6 flaws.cloud cases plus 3 from ``k8s_ci`` / ``k8ntext`` /
``attack_data_aws``. MEASURED 2026-09-15 at 195e369: ``k8s_ci`` and ``k8ntext`` form 0
cases (0 findings since the M18-9 declaration fix), ``attack_data_aws`` forms exactly the
two cases M19 froze, and ``synthetic:INC-003`` forms no case at all. Those seats go to
flaws.cloud, and the manifest says so under ``substitutions``.

Disjointness is structural, not nominal
----------------------------------------
Every corpus has a ``CASE-001``, so case-id strings prove nothing. A dev case is excluded
if it shares a ``(telemetry_hash, case_id)`` pair **or any finding id** with a frozen
case; the second test survives a correlator change renumbering flaws.cloud cases, which
is why M19b pins its two flaws cases by principal rather than by id. The same check is
what ``tests/test_contamination.py`` runs on every ``pytest``.
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import m19_ablation as m19  # noqa: E402
import m19b_manifest as manifest_script  # noqa: E402
import m19b_necessity_audit as necessity_script  # noqa: E402
from local_inject_dedale import DEFAULT_OUT as DEV_CASE_ROOT  # noqa: E402
from local_inject_dedale import DEV_CASES, DEV_SEED  # noqa: E402

from ath.evaluation.ablation import (  # noqa: E402
    CaseManifest,
    build_manifest,
    load_manifest,
    manifest_hash,
)
from ath.evaluation.ablation.local import refuse_frozen_path  # noqa: E402
from ath.evaluation.ablation.manifest import leading_rule_of  # noqa: E402
from ath.evaluation.external_labels import RESOLVED, load_external_labels, resolve_refs  # noqa: E402

DEV_DIR = ROOT / "reports" / "local" / "dev"
MANIFEST_PATH = DEV_DIR / "MANIFEST.json"
MANIFEST_MD = DEV_DIR / "MANIFEST.md"
FROZEN_MANIFESTS: tuple[Path, ...] = (
    ROOT / "reports" / "m19" / "ablation" / "MANIFEST.json",
    ROOT / "reports" / "m19b" / "MANIFEST.json",
)
SYNTHETIC_DEV = "synthetic:INC-003"
FLAWS_CASES = 9
DEV_INJECTED_IDS: tuple[str, ...] = tuple(c.case_id for c in DEV_CASES)
DEFAULT_EXTERNAL = manifest_script.DEFAULT_EXTERNAL


# --------------------------------------------------------------------------------------
# Disjointness
# --------------------------------------------------------------------------------------


def frozen_entries(paths: Sequence[Path] = FROZEN_MANIFESTS) -> list[CaseManifest]:
    entries: list[CaseManifest] = []
    for path in paths:
        entries.extend(load_manifest(json.loads(path.read_text(encoding="utf-8"))))
    return entries


def contamination(dev: Sequence[CaseManifest], frozen: Sequence[CaseManifest]) -> list[str]:
    """Every way a dev entry overlaps a frozen one. Empty when the split is clean."""
    frozen_pairs = {(e.telemetry_hash, e.case_id): e.key for e in frozen}
    frozen_findings: dict[str, str] = {}
    for entry in frozen:
        for finding_id in entry.finding_ids:
            frozen_findings.setdefault(finding_id, entry.key)
    frozen_keys = {e.key for e in frozen}
    problems: list[str] = []
    for entry in dev:
        pair = (entry.telemetry_hash, entry.case_id)
        if pair in frozen_pairs:
            problems.append(
                f"{entry.key}: same telemetry hash and case id as frozen {frozen_pairs[pair]}"
            )
        shared = sorted(f for f in entry.finding_ids if f in frozen_findings)
        if shared:
            problems.append(
                f"{entry.key}: shares finding id(s) {shared[:3]} with frozen "
                f"{frozen_findings[shared[0]]}"
            )
        if entry.key in frozen_keys:
            problems.append(f"{entry.key}: same corpus/case key as a frozen entry")
    return problems


# --------------------------------------------------------------------------------------
# Loading the dev corpora (cheapest first, flaws.cloud last)
# --------------------------------------------------------------------------------------


def synthetic_dev_bundle() -> m19.Bundle:
    for bundle in m19.load_bundles(["synthetic"]):
        if bundle.name == SYNTHETIC_DEV:
            return bundle
    raise SystemExit(f"the standard suite produced no {SYNTHETIC_DEV} bundle")


def injected_dev_bundle(case_id: str) -> m19.Bundle:
    if case_id not in DEV_INJECTED_IDS:
        raise SystemExit(f"{case_id!r} is not a dev-split injected case")
    started = time.perf_counter()
    telemetry = necessity_script._winlogbeat(DEV_CASE_ROOT / case_id / "winlogbeat")
    load_seconds = time.perf_counter() - started
    started = time.perf_counter()
    findings, cases, environment, assessments = m19._pipeline(telemetry)
    return m19.Bundle(
        name=f"dedale_injected_dev:{case_id}",
        telemetry=telemetry, findings=findings, cases=cases, environment=environment,
        assessments=assessments, load_seconds=load_seconds,
        pipeline_seconds=time.perf_counter() - started,
    )


def dev_bundles(external: Path, *, corpora: set[str] | None = None) -> Iterator[m19.Bundle]:
    """Every corpus the dev manifest names. ``corpora`` restricts to the ones wanted."""
    def wanted(name: str) -> bool:
        return corpora is None or name in corpora

    if wanted(SYNTHETIC_DEV):
        yield synthetic_dev_bundle()
    for case_id in DEV_INJECTED_IDS:
        if wanted(f"dedale_injected_dev:{case_id}"):
            yield injected_dev_bundle(case_id)
    if wanted("flaws_cloud"):
        yield manifest_script.flaws_bundle(external)


# --------------------------------------------------------------------------------------
# Selection
# --------------------------------------------------------------------------------------


def injected_labels(case_id: str, telemetry: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """The label block and the resolved cross-domain links for one dev case."""
    path = DEV_CASE_ROOT / case_id / "labels.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    labels = load_external_labels(path)
    if len(labels.scenarios) != 1:
        raise SystemExit(f"{case_id}: expected one scenario, got {len(labels.scenarios)}")
    scenario = labels.scenarios[0]
    refs = [side["ref"] for link in payload.get("links", ()) for side in (link["identity"], link["endpoint"])]
    resolved = resolve_refs(refs, telemetry)
    links: list[dict[str, Any]] = []
    for link in payload.get("links", ()):
        sides = {}
        for domain in ("identity", "endpoint"):
            match = resolved[link[domain]["ref"]]
            if match.status != RESOLVED:
                raise SystemExit(
                    f"{case_id}/{link['link_id']}: {domain} ref is {match.status} against this load"
                )
            sides[domain] = {"domain": domain, "ref": link[domain]["ref"], "event_id": match.event_id}
        links.append({
            "link_id": link["link_id"], "stage_transition": link["stage_transition"],
            "note": link.get("note", ""),
            "source": f"reports/local/dev/cases/dedale_injected/{case_id}/labels.json", **sides,
        })
    label_block = {
        "injected_case": case_id,
        "provenance": labels.provenance,
        "scenario": scenario.name,
        "verdict": "malicious" if scenario.malicious else "benign",
        "stages": [s.name for s in scenario.stages],
        "links": [link["link_id"] for link in links],
    }
    return label_block, links


def select_flaws(
    cases: Sequence[Any], frozen: Sequence[CaseManifest], telemetry_digest: str,
    *, count: int = FLAWS_CASES, seed: int = DEV_SEED,
) -> tuple[list[Any], dict[str, Any]]:
    """``count`` flaws.cloud cases outside the frozen set, one per leading rule in turn.

    Round-robin over the leading rules in sorted order, each rule's eligible cases shuffled
    once under the seed, so the sample covers as many rules as it can before it doubles up
    on one -- and is reproducible from the seed alone.
    """
    frozen_pairs = {(e.telemetry_hash, e.case_id) for e in frozen}
    frozen_findings = {f for e in frozen for f in e.finding_ids}
    eligible = [
        c for c in cases
        if (telemetry_digest, c.case_id) not in frozen_pairs
        and not ({f.finding_id for f in c.findings} & frozen_findings)
    ]
    excluded = len(cases) - len(eligible)
    by_rule: dict[str, list[Any]] = defaultdict(list)
    for case in eligible:
        by_rule[leading_rule_of(case)].append(case)
    rng = random.Random(seed)
    queues: dict[str, list[Any]] = {}
    for rule in sorted(by_rule):
        ordered = sorted(by_rule[rule], key=lambda c: c.case_id)
        rng.shuffle(ordered)
        queues[rule] = ordered
    chosen: list[Any] = []
    while len(chosen) < count and any(queues.values()):
        for rule in sorted(queues):
            if queues[rule] and len(chosen) < count:
                chosen.append(queues[rule].pop())
    detail = {
        "seed": seed,
        "eligible": len(eligible),
        "excluded_as_frozen": excluded,
        "strata": {rule: len(by_rule[rule]) for rule in sorted(by_rule)},
        "rule": "round-robin over leading rules in sorted order, each stratum shuffled once under the seed",
        "chosen": [{"case_id": c.case_id, "leading_rule": leading_rule_of(c)} for c in chosen],
    }
    return chosen, detail


# --------------------------------------------------------------------------------------
# build
# --------------------------------------------------------------------------------------


def _head() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def cmd_build(args: argparse.Namespace) -> int:
    refuse_frozen_path(args.out_dir, ROOT)
    frozen = frozen_entries()
    entries: list[CaseManifest] = []
    provenance: dict[str, Any] = {}
    links_by_key: dict[str, list[dict[str, Any]]] = {}
    substitutions: list[str] = [
        "the decided composition had 6 flaws.cloud + 3 k8s_ci/k8ntext/attack_data_aws cases; "
        "MEASURED 2026-09-15 at 195e369: k8s_ci and k8ntext form 0 cases and attack_data_aws "
        "forms only the two cases M19 froze, so those three seats went to flaws.cloud",
    ]
    flaws_seats = 0

    for bundle in dev_bundles(args.external):
        if bundle.name == SYNTHETIC_DEV:
            selected, selection, detail = m19.select(bundle)
            if not selected:
                # MEASURED 2026-09-15 at 195e369: INC-003 forms 0 cases (the same reason M19
                # froze INC-001/002/004/005 and not it). Its seat goes to flaws.cloud too.
                substitutions.append(
                    f"{SYNTHETIC_DEV} forms no case under the current correlator; its seat went to flaws.cloud"
                )
                provenance[bundle.name] = {"provenance": "synthetic", "cases_formed": 0, "included": False}
                print(f"{bundle.name}: 0 case(s) formed; seat reassigned", file=sys.stderr)
                continue
            entries += build_manifest(
                bundle.name, bundle.telemetry, selected, selection=selection, labels=bundle.labels,
            )
            provenance[bundle.name] = {"provenance": "synthetic", **detail}
        elif bundle.name.startswith("dedale_injected_dev:"):
            case_id = bundle.name.split(":", 1)[1]
            if len(bundle.cases) != 1:
                raise SystemExit(f"{bundle.name}: expected one case, formed {len(bundle.cases)}")
            label_block, links = injected_labels(case_id, bundle.telemetry)
            case = bundle.cases[0]
            entries += build_manifest(
                bundle.name, bundle.telemetry, [case],
                selection=f"the single case reports/local/dev/cases/dedale_injected/{case_id}/ forms",
                labels={case.case_id: label_block},
            )
            links_by_key[f"{bundle.name}/{case.case_id}"] = links
            provenance[bundle.name] = {
                "provenance": "real benign DEDALE background (D02) + injected labelled rows",
                "verdict": label_block["verdict"], "scenario": label_block["scenario"],
            }
        elif bundle.name == "flaws_cloud":
            from ath.evaluation.ablation.manifest import telemetry_hash  # noqa: PLC0415

            digest = telemetry_hash(bundle.telemetry)
            seats = args.expected - len(entries)   # flaws.cloud loads last and fills what is left
            chosen, detail = select_flaws(bundle.cases, frozen, digest, count=seats, seed=args.seed)
            if len(chosen) != seats:
                raise SystemExit(f"flaws_cloud: only {len(chosen)} eligible case(s) for {seats} seats")
            flaws_seats = seats
            entries += build_manifest(
                bundle.name, bundle.telemetry, chosen,
                selection="stratified sample outside both frozen manifests (see provenance.flaws_cloud)",
            )
            provenance[bundle.name] = {"provenance": "real, unlabelled CloudTrail", **detail}
        print(f"{bundle.name}: {len(bundle.cases)} case(s) formed", file=sys.stderr)

    problems = contamination(entries, frozen)
    if problems:
        raise SystemExit("REFUSED: the dev split overlaps a frozen benchmark:\n  " + "\n  ".join(problems))
    if len(entries) != args.expected:
        raise SystemExit(f"REFUSED: {len(entries)} entries, expected {args.expected}")

    digest = manifest_hash(entries)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "head": _head(),
        "split": "dev",
        "purpose": "V1 local-model development split; never used to grade a frozen benchmark",
        "seed": args.seed,
        "composition": {
            corpus: sum(1 for e in entries if e.corpus == corpus or (corpus == "dedale_injected_dev" and e.corpus.startswith("dedale_injected_dev:")))
            for corpus in ("dedale_injected_dev", SYNTHETIC_DEV, "flaws_cloud")
        },
        "decided_composition": {"dedale_injected_dev": 10, SYNTHETIC_DEV: 1, "flaws_cloud": 6, "k8s_or_attack_data_aws": 3},
        "substitutions": substitutions,
        "disjoint_from": [
            {"path": str(p.relative_to(ROOT)).replace("\\", "/"),
             "manifest_hash": json.loads(p.read_text(encoding="utf-8")).get("manifest_hash")}
            for p in FROZEN_MANIFESTS
        ],
        "disjointness_rule": (
            "no shared (telemetry_hash, case_id) pair and no shared finding id with any frozen entry; "
            "asserted before writing and by tests/test_contamination.py"
        ),
        "limitations": [
            "ten of twenty cases share one shape (endpoint x identity via auth_then_exec), the same "
            "shape as six of the nine M19b benchmark cases; tuning on them tunes to that shape",
            "the nine flaws.cloud cases are unlabelled: no completeness or discrimination metric",
        ],
        "provenance": provenance,
        "manifest_hash": digest,
        "cases": [
            {**e.to_dict(), **({"links": links_by_key[e.key]} if e.key in links_by_key else {})}
            for e in entries
        ],
    }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "MANIFEST.json").write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    (args.out_dir / "MANIFEST.md").write_text(render_markdown(payload) + "\n", encoding="utf-8")
    print(f"wrote {args.out_dir / 'MANIFEST.json'} ({len(entries)} cases, hash {digest[:12]})", file=sys.stderr)
    return 0


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# V1 dev split (20 cases)",
        "",
        f"Generated {payload['generated_at']} at `{payload['head']}`, seed {payload['seed']}, "
        f"manifest hash `{payload['manifest_hash'][:12]}`. {payload['purpose']}.",
        "",
        "**Substitutions:** " + " ".join(f"({i}) {t}." for i, t in enumerate(payload["substitutions"], 1)),
        "",
        "| corpus | case | leading rule | rules | findings | evidence ids | verdict |",
        "| --- | --- | --- | --- | ---: | ---: | --- |",
    ]
    for case in payload["cases"]:
        labels = case.get("labels") or {}
        verdict = labels.get("verdict") or ("synthetic" if case["corpus"].startswith("synthetic") else "unlabelled")
        lines.append(
            f"| {case['corpus']} | {case['case_id']} | {case['leading_rule']} | "
            f"{', '.join(case['rule_ids'])} | {len(case['finding_ids'])} | "
            f"{len(case['evidence_ids'])} | {verdict} |"
        )
    lines += ["", "## Disjointness", "", payload["disjointness_rule"] + ".", ""]
    for frozen in payload["disjoint_from"]:
        lines.append(f"- `{frozen['path']}` (hash `{str(frozen['manifest_hash'])[:12]}`)")
    lines += ["", "## Limitations", ""] + [f"- {l}" for l in payload["limitations"]]
    return "\n".join(lines)


def read_manifest(out_dir: Path = DEV_DIR) -> tuple[dict[str, Any], list[CaseManifest], str]:
    path = Path(out_dir) / "MANIFEST.json"
    if not path.exists():
        raise SystemExit(f"{path} does not exist; run `python scripts/local_manifest.py build` first")
    payload = json.loads(path.read_text(encoding="utf-8"))
    entries = load_manifest(payload)
    digest = manifest_hash(entries)
    if digest != payload.get("manifest_hash"):
        raise SystemExit(f"{path}: recorded hash {str(payload.get('manifest_hash'))[:12]} != recomputed {digest[:12]}")
    return payload, entries, digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p_build = sub.add_parser("build")
    p_build.add_argument("--external", type=Path, default=DEFAULT_EXTERNAL)
    p_build.add_argument("--out-dir", type=Path, default=DEV_DIR)
    p_build.add_argument("--seed", type=int, default=DEV_SEED)
    p_build.add_argument("--expected", type=int, default=20)
    p_build.set_defaults(func=cmd_build)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
