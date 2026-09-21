"""The dev split: a 20-case manifest disjoint by construction from every frozen benchmark.

Composition (the user's 2026-09-14 decision, with one recorded substitution)
------------------------------------------------------------------------------
* 10 fresh DEDALE-injected labelled cases (``scripts/local_inject_dedale.py``, day D02);
* ``synthetic:INC-003`` -- the one standard-suite incident neither M19 nor M19b froze;
* real, unlabelled ``flaws_cloud`` cases outside both frozen manifests, stratified by
  leading rule under a recorded seed, filling every seat the corpora above leave empty.

Disjointness is structural, not nominal
----------------------------------------
Every corpus has a ``CASE-001``, so case-id strings prove nothing. A dev case is excluded
if it shares a ``(telemetry_hash, case_id)`` pair **or any finding id** with a frozen
case. The same check is what ``tests/test_contamination.py`` runs on every ``pytest``.

The injected case definitions (``DEV_CASES``, ``DEV_SEED``, the case root) belong to the
hash-pinned ``scripts/local_inject_dedale.py`` and are read from it by path.
"""

from __future__ import annotations

import json
import random
import subprocess
import sys
from collections import defaultdict
from collections.abc import Iterator, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ath.evaluation.ablation import (
    CaseManifest,
    build_manifest,
    load_manifest,
    manifest_hash,
)
from ath.evaluation.ablation.local import refuse_frozen_path
from ath.evaluation.ablation.manifest import (
    _TABLES,
    DIGEST_VERSIONS,
    column_digests,
    leading_rule_of,
    telemetry_digest,
)
from ath.evaluation.dev_labels import injected_labels as _resolve_injected_labels
from ath.experiments import _frozen_scripts
from ath.experiments.bundles import (
    DEFAULT_EXTERNAL,
    Bundle,
    flaws_bundle,
    select_synthetic,
    synthetic_bundles,
    winlogbeat_bundle,
)
from ath.experiments.paths import DEV_DIR, ROOT

MANIFEST_PATH = DEV_DIR / "MANIFEST.json"
MANIFEST_MD = DEV_DIR / "MANIFEST.md"
FROZEN_MANIFESTS: tuple[Path, ...] = (
    ROOT / "reports" / "m19" / "ablation" / "MANIFEST.json",
    ROOT / "reports" / "m19b" / "MANIFEST.json",
)
SYNTHETIC_DEV = "synthetic:INC-003"
FLAWS_CASES = 9
INJECT_SCRIPT = "local_inject_dedale"


def _inject():
    """The pinned injector script, loaded by path (never copied)."""
    return _frozen_scripts.load(INJECT_SCRIPT)


def dev_seed() -> int:
    return int(_inject().DEV_SEED)


def dev_case_root() -> Path:
    return Path(_inject().DEFAULT_OUT)


def dev_injected_ids() -> tuple[str, ...]:
    return tuple(c.case_id for c in _inject().DEV_CASES)


# -- disjointness ---------------------------------------------------------------------


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


# -- loading the dev corpora (cheapest first, flaws.cloud last) ---------------------------


def synthetic_dev_bundle() -> Bundle:
    for bundle in synthetic_bundles():
        if bundle.name == SYNTHETIC_DEV:
            return bundle
    raise SystemExit(f"the standard suite produced no {SYNTHETIC_DEV} bundle")


def injected_dev_bundle(case_id: str) -> Bundle:
    if case_id not in dev_injected_ids():
        raise SystemExit(f"{case_id!r} is not a dev-split injected case")
    return winlogbeat_bundle(
        f"dedale_injected_dev:{case_id}", dev_case_root() / case_id / "winlogbeat",
    )


def dev_bundles(external: Path = DEFAULT_EXTERNAL, *, corpora: set[str] | None = None) -> Iterator[Bundle]:
    """Every corpus the dev manifest names. ``corpora`` restricts to the ones wanted."""
    def wanted(name: str) -> bool:
        return corpora is None or name in corpora

    if wanted(SYNTHETIC_DEV):
        yield synthetic_dev_bundle()
    for case_id in dev_injected_ids():
        if wanted(f"dedale_injected_dev:{case_id}"):
            yield injected_dev_bundle(case_id)
    if wanted("flaws_cloud"):
        yield flaws_bundle(external)


# -- selection ----------------------------------------------------------------------------


def injected_labels(case_id: str, telemetry: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """The label block and the resolved cross-domain links for one dev case."""
    return _resolve_injected_labels(
        dev_case_root() / case_id / "labels.json", case_id, telemetry,
        source=f"reports/local/dev/cases/dedale_injected/{case_id}/labels.json",
    )


def select_flaws(
    cases: Sequence[Any], frozen: Sequence[CaseManifest], telemetry_digest: str,
    *, count: int = FLAWS_CASES, seed: int | None = None,
) -> tuple[list[Any], dict[str, Any]]:
    """``count`` flaws.cloud cases outside the frozen set, one per leading rule in turn.

    Round-robin over the leading rules in sorted order, each rule's eligible cases shuffled
    once under the seed, so the sample covers as many rules as it can before it doubles up
    on one -- and is reproducible from the seed alone.
    """
    if seed is None:
        seed = dev_seed()
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


# -- build --------------------------------------------------------------------------------


def head() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def build_dev_manifest(
    *, external: Path = DEFAULT_EXTERNAL, out_dir: Path = DEV_DIR, seed: int | None = None,
    expected: int = 20, digest_version: int = 1, log=lambda text: print(text, file=sys.stderr),
) -> dict[str, Any]:
    """Build and write ``MANIFEST.json``/``.md`` under ``out_dir``; returns the payload.

    ``digest_version`` selects the telemetry digest the entries are pinned with. Version 1
    is what every frozen manifest carries and depends on the pandas release; version 2
    is runtime-stable. The version and a per-column digest detail are recorded on the
    payload, outside the hashed entries.
    """
    if digest_version not in DIGEST_VERSIONS:
        raise SystemExit(f"unknown digest version {digest_version}; known: {DIGEST_VERSIONS}")
    if seed is None:
        seed = dev_seed()
    out_dir = Path(out_dir)
    refuse_frozen_path(out_dir, ROOT)
    frozen = frozen_entries()
    entries: list[CaseManifest] = []
    provenance: dict[str, Any] = {}
    links_by_key: dict[str, list[dict[str, Any]]] = {}
    detail: dict[str, Any] = {}
    substitutions: list[str] = [
        "the decided composition had 6 flaws.cloud + 3 k8s_ci/k8ntext/attack_data_aws cases; "
        "MEASURED 2026-09-15 at 195e369: k8s_ci and k8ntext form 0 cases and attack_data_aws "
        "forms only the two cases M19 froze, so those three seats went to flaws.cloud",
    ]

    for bundle in dev_bundles(external):
        detail[bundle.name] = {
            name: column_digests(bundle.telemetry.table(event_type), digest_version)
            for name, event_type in _TABLES
        }
        if bundle.name == SYNTHETIC_DEV:
            selected, selection, detail = select_synthetic(bundle)
            if not selected:
                substitutions.append(
                    f"{SYNTHETIC_DEV} forms no case under the current correlator; its seat went to flaws.cloud"
                )
                provenance[bundle.name] = {"provenance": "synthetic", "cases_formed": 0, "included": False}
                log(f"{bundle.name}: 0 case(s) formed; seat reassigned")
                continue
            entries += build_manifest(
                bundle.name, bundle.telemetry, selected, selection=selection, labels=bundle.labels,
                digest_version=digest_version,
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
                labels={case.case_id: label_block}, digest_version=digest_version,
            )
            links_by_key[f"{bundle.name}/{case.case_id}"] = links
            provenance[bundle.name] = {
                "provenance": "real benign DEDALE background (D02) + injected labelled rows",
                "verdict": label_block["verdict"], "scenario": label_block["scenario"],
            }
        elif bundle.name == "flaws_cloud":
            digest = telemetry_digest(bundle.telemetry, digest_version)
            seats = expected - len(entries)   # flaws.cloud loads last and fills what is left
            chosen, detail = select_flaws(bundle.cases, frozen, digest, count=seats, seed=seed)
            if len(chosen) != seats:
                raise SystemExit(f"flaws_cloud: only {len(chosen)} eligible case(s) for {seats} seats")
            entries += build_manifest(
                bundle.name, bundle.telemetry, chosen,
                selection="stratified sample outside both frozen manifests (see provenance.flaws_cloud)",
                digest_version=digest_version,
            )
            provenance[bundle.name] = {"provenance": "real, unlabelled CloudTrail", **detail}
        log(f"{bundle.name}: {len(bundle.cases)} case(s) formed")

    problems = contamination(entries, frozen)
    if problems:
        raise SystemExit("REFUSED: the dev split overlaps a frozen benchmark:\n  " + "\n  ".join(problems))
    if len(entries) != expected:
        raise SystemExit(f"REFUSED: {len(entries)} entries, expected {expected}")

    digest = manifest_hash(entries)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "head": head(),
        "split": "dev",
        "purpose": "V1 local-model development split; never used to grade a frozen benchmark",
        "seed": seed,
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
        "digest_version": digest_version,
        "telemetry_digest_detail": detail,
        "manifest_hash": digest,
        "cases": [
            {**e.to_dict(), **({"links": links_by_key[e.key]} if e.key in links_by_key else {})}
            for e in entries
        ],
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "MANIFEST.json").write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    (out_dir / "MANIFEST.md").write_text(render_markdown(payload) + "\n", encoding="utf-8")
    log(f"wrote {out_dir / 'MANIFEST.json'} ({len(entries)} cases, hash {digest[:12]})")
    return payload


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
    """The dev manifest, its entries and its recomputed hash; refuses a hash mismatch."""
    path = Path(out_dir) / "MANIFEST.json"
    if not path.exists():
        raise SystemExit(f"{path} does not exist; run `ath-experiment manifest-build` first")
    payload = json.loads(path.read_text(encoding="utf-8"))
    entries = load_manifest(payload)
    digest = manifest_hash(entries)
    if digest != payload.get("manifest_hash"):
        raise SystemExit(f"{path}: recorded hash {str(payload.get('manifest_hash'))[:12]} != recomputed {digest[:12]}")
    return payload, entries, digest


def links_by_case(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """The manifest's cross-domain links by ``corpus/case_id``. Labels for scoring only;
    they are handed to the runner beside the rows and never to the model."""
    out: dict[str, list[dict[str, Any]]] = {}
    for case in payload.get("cases") or ():
        links = case.get("links") or []
        if links:
            out[f"{case['corpus']}/{case['case_id']}"] = list(links)
    return out


def inject_cases(only: Sequence[str] | None = None, external: Path | None = None) -> int:
    """Run the pinned injector script by path; returns its exit code."""
    command = [sys.executable, str(ROOT / "scripts" / f"{INJECT_SCRIPT}.py")]
    if external is not None:
        command += ["--external", str(external)]
    if only:
        command += ["--only", *only]
    return subprocess.run(command, cwd=ROOT).returncode
