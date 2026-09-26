r"""Write the first real-data assessment specs (detection and analyst seed modes).

Usage (writes spec-detection.json and spec-analyst.json into OUT_DIR, outside git)::

    $env:PYTHONPATH = "src"
    .\.venv\Scripts\python.exe scripts\first_real_assessment_spec.py OUT_DIR

Case selection is mechanical and fixed before any run:
- malicious: every DEDALE apt stage with at least one ref that resolves to an ingested
  record, one case per stage, windowed to that day's resolved records +/- 30 min on the
  stage's hosts. Seed invariant: the anchor is the stage's EARLIEST resolved record
  (by time, then event id); every other labelled ref of the stage is a useful_ref, hidden
  behind investigation and scored as follow-up evidence (unresolved refs are ignored);
- benign: for each benign Kubernetes corpus, the earliest event of each distinct
  (actor, verb, resource_type) among pods/exec, rolebindings and clusterrolebindings,
  sorted by first time, at most three per corpus; window +/- 30 min.
"""

import json
import sys
from pathlib import Path

import pandas as pd

from ath.evaluation.external_labels import resolve_refs
from ath.evaluation.real_cases import load_source

REPO = Path.cwd()
OUT = Path(sys.argv[1])
OUT.mkdir(parents=True, exist_ok=True)
PAD = pd.Timedelta(minutes=30)


def iso(ts):
    return pd.Timestamp(ts).tz_convert("UTC").strftime("%Y-%m-%dT%H:%M:%SZ")


cases = []
labels = json.loads((REPO / "data/external/dedale/labels/dedale_class1_labels.json").read_text(encoding="utf-8"))
stages = {name: st["refs"] for name, st in labels["scenarios"]["apt"]["stages"].items()}
for day in sorted(p.name for p in (REPO / "data/external/dedale/winlogbeat").iterdir() if p.is_dir()):
    telemetry, _ = load_source("winlogbeat", REPO / "data/external/dedale/winlogbeat" / day)
    rows = pd.concat([t[["event_id", "timestamp", "device"]] for t in
                      (telemetry.processes, telemetry.network, telemetry.logons)]).set_index("event_id")
    for stage, refs in stages.items():
        by_ref = {ref: r.event_id for ref, r in resolve_refs(refs, telemetry).items() if r.event_id}
        resolved = list(by_ref.values())
        if not resolved:
            continue
        hit = rows.loc[resolved]
        stamps = pd.to_datetime(hit["timestamp"], utc=True)
        order = sorted(by_ref, key=lambda ref: (pd.Timestamp(rows.loc[by_ref[ref], "timestamp"]), by_ref[ref]))
        seed_ref = order[0]
        cases.append({
            "key": f"dedale-{stage}-{day.lower()}".replace("_", "-"),
            "source": {"kind": "winlogbeat", "path": str(REPO / "data/external/dedale/winlogbeat" / day)},
            "window": {"start": iso(stamps.min() - PAD), "end": iso(stamps.max() + PAD)},
            "devices": sorted(set(hit["device"])),
            "expected_decision": "malicious", "provenance": "emulated-testbed",
            "label_source": f"DEDALE class-1 labels, apt stage {stage} (dedale_class1_labels.json)",
            "anchor_refs": [seed_ref], "useful_refs": [r for r in refs if r != seed_ref],
            "note": "DEDALE was used in earlier ablations; development/regression only, not fresh evidence.",
        })

BENIGN = {
    "k8s_ci": ("Kubernetes CI e2e conformance run (Prow job ci-kubernetes-e2e-gci-gce); automated tests, no attack activity. Corpus-level label.", "real"),
    "k8ntext": ("K8NTEXT (Franzil et al., 2025): documented benign admin operations on a kubeadm lab cluster; the paper states no attacks. Corpus-level label.", "emulated-testbed"),
}
for corpus, (source, provenance) in BENIGN.items():
    telemetry, _ = load_source("k8s", REPO / "data/external" / corpus / "raw")
    c = telemetry.controls.copy()
    c["ts"] = pd.to_datetime(c["timestamp"], utc=True)
    c = c[c["resource_type"].isin(["pods/exec", "rolebindings", "clusterrolebindings"])].sort_values(["ts", "event_id"])
    first = c.groupby(["actor", "verb", "resource_type"], sort=False).head(1).sort_values(["ts", "event_id"]).head(3)
    for i, (_, row) in enumerate(first.iterrows(), 1):
        cases.append({
            "key": f"{corpus.replace('_', '-')}-benign-{i:02d}",
            "source": {"kind": "k8s", "path": str(REPO / "data/external" / corpus / "raw")},
            "window": {"start": iso(row["ts"] - PAD), "end": iso(row["ts"] + PAD)},
            "expected_decision": "benign", "provenance": provenance, "label_source": source,
            "anchor_refs": [row["source_ref"].split(";")[0]],
            "note": f"Mechanical pick: earliest {row['verb']} on {row['resource_type']} by this actor.",
        })

for mode in ("detection", "analyst"):
    spec = {"spec_version": "real-cases-v1", "name": f"first-real-assessment-{mode}", "seed_mode": mode, "cases": cases}
    (OUT / f"spec-{mode}.json").write_text(json.dumps(spec, indent=1), encoding="utf-8")
print(json.dumps([{k: c[k] for k in ("key", "expected_decision")} for c in cases], indent=0))
