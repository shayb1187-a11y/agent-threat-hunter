r"""Build the holdout-v1-windows evaluation set: 18 analyst-seeded cases.

Primary cases (``holdout_role: primary``): the discrimination measurement
--------------------------------------------------------------------------
* ``windows-malicious`` x6 (real): DEDALE APT stages not used in any earlier milestone,
  2025-01-07, 08, 10, 11, 12 and 13, one case per stage. Seed = the earliest ingested
  labelled record whose process image is not the campaign implant (``IMPLANT_IMAGES``),
  falling back to the implant only when the stage has no other ingestible labelled record
  (``SELECTION_RULES['malicious_seed']``); the
  stage's other refs are follow-up evidence (``useful_refs``). Window = resolved records
  +/- 30 min on the stage's hosts, as in ``scripts/first_real_assessment_spec.py``.
* ``windows-benign`` x6 (real): Sysmon process events sampled with a fixed seed from
  DEDALE days that carry no APT label and were never used before, spread across >=4 days
  and >=4 hosts, with >=2 admin-looking picks (cmd, PowerShell, sc, net, ...) so a
  "PowerShell = bad" heuristic is not rewarded. "Benign" here means "on a day with no
  labelled attack activity", and the label_source says exactly that. Each
  benign window copies a paired malicious window's duration and seed offset, clipped to
  the day file (``SELECTION_RULES['window_matching']``).

Secondary cases (``holdout_role: secondary``): a false-accusation check only
----------------------------------------------------------------------------
* ``k8s-benign`` x6 (injected): hand-authored benign look-alikes from
  :mod:`holdout_scenarios`, each injected into an equal-width slice of the real
  ``k8s_ingress`` background. They support no Kubernetes discrimination claim.
  **Kubernetes malicious discrimination is not evaluated in holdout-v1**: no suitable
  fresh labelled dataset existed, and the malicious recording path could not be
  completed. No malicious Kubernetes case is authored, inferred or accepted here.

Case keys are neutral (``h01``..``h18``), from a seeded shuffle across all 18 cases, so a
key reveals neither quadrant nor role.

Determinism: every random choice draws from ``random.Random(SEED)``; auditIDs are
``uuid5`` of a fixed namespace. The same inputs give the same outputs.

Usage::

    $env:PYTHONPATH = "src"
    .\.venv\Scripts\python.exe scripts\build_holdout_v1.py --out C:\path\ath-holdout-v1

Options: ``--data-external`` (default: the main checkout's gitignored data/external) and
``--no-protocol``, which omits the top-level ``protocol`` key for a harness that does not
yet accept ``holdout-v1-windows``.

Blindness: this builder never reads the investigator, its prompts, or model outputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ath.evaluation.external_labels import resolve_refs  # noqa: E402
from ath.evaluation.real_cases import load_source  # noqa: E402
from holdout_scenarios import (  # noqa: E402
    K8S_BENIGN_PAYLOAD,
    assert_no_leaks,
    scenarios_from_payload,
)

SEED = 20260925
PROTOCOL = "holdout-v1-windows"
SPEC_VERSION = "real-cases-v1"
WINDOW_PAD = pd.Timedelta(minutes=30)
K8S_PAD = pd.Timedelta(minutes=3)
DEFAULT_EXTERNAL = Path(__file__).resolve().parents[1] / "data" / "external"

# DEDALE APT stages never used before, and the per-day file each lives in. A stage's
# refs name (host, record_id), and record_ids are a per-host counter partitioned by day
# file, so a stage resolves in exactly one day file; the builder asserts it.
MALICIOUS_STAGES = {
    "2025-01-07": "D16", "2025-01-08": "D17", "2025-01-10": "D19",
    "2025-01-11": "D20", "2025-01-12": "D21", "2025-01-13": "D22",
}
# DEDALE days with no APT label and never used before (D02, D03, D07 were).
BENIGN_CANDIDATE_DAYS = ["D01", "D04", "D05", "D06", "D08", "D09", "D10", "D11", "D12", "D13", "D14"]
_ADMIN_RE = re.compile(
    r"powershell|cmd\.exe|\bsc\.exe|schtasks|msiexec|wmic|\breg\.exe|\bnet1?\.exe|rundll32", re.I)

EXCLUDED = {
    "dedale_stages_used": {
        "2025-01-06": {"day": "D15", "host": "CLIENT2", "seed_record_id": 3298994},
        "2025-01-09": {"day": "D18", "host": "CLIENT1", "seed_record_id": 5774872},
    },
    "dedale_days_excluded_from_benign": {
        "used_before": ["D02", "D03", "D07"],
        "apt_labelled": ["D15", "D16", "D17", "D18", "D19", "D20", "D21", "D22"],
    },
    "k8s_corpora_excluded": ["k8s_ci", "k8ntext"],
    "k8s_note": ("K8NTEXT is licence ND and was not used; k8s_ci and k8ntext windows were used "
                 "in earlier milestones. The k8s_ingress background (Prow "
                 "ci-kubernetes-e2e-gci-gce-ingress run 2064903754573942784) was only scanned "
                 "by detection in M16/M19b, never cut into an evaluation case."),
}
NOT_EVALUATED = {
    "k8s_malicious_discrimination": (
        "Not evaluated. No suitable fresh labelled Kubernetes attack dataset existed, and the "
        "malicious recording path could not be completed. holdout-v1 contains no malicious "
        "Kubernetes case. The six injected Kubernetes cases are all benign, carry "
        "holdout_role 'secondary', and are only a false-accusation / generalisation check; "
        "no Kubernetes discrimination claim may be drawn from this set."),
}
ROLE = {"windows-malicious": "primary", "windows-benign": "primary", "k8s-benign": "secondary"}
EXPECTED_COUNTS = {"windows-malicious": 6, "windows-benign": 6, "k8s-benign": 6}

# The DEDALE campaign's implant, a fixed list. The DEDALE label file itself names it: its
# APT scenario note describes a "scvhost.exe/svcmon.exe implant", and svcmon.exe is the
# earliest ingestible labelled image in every attack stage. Seeding on it would let a model
# recognise one process name instead of investigating (holdout-v1 shortcut 1).
IMPLANT_IMAGES = ("svcmon.exe",)
IMPLANT_REASON = (
    "svcmon.exe is DEDALE's labelled implant, identified from the labels themselves: the "
    "dedale_class1_labels.json APT scenario note names the 'scvhost.exe/svcmon.exe implant', and "
    "svcmon.exe is the earliest ingestible labelled image in all six stages. A seed on it would "
    "reward recognising one image name rather than investigating.")

# Declared before the rebuild that applied them; copied verbatim into the manifest.
SELECTION_RULES = {
    "malicious_seed": (
        "For each DEDALE stage, take the labelled refs the loader ingests, in (time, event_id) "
        "order. The seed is the earliest one whose process image is not in the fixed implant "
        "list IMPLANT_IMAGES = ['svcmon.exe']. Only when the stage has no other ingestible "
        "labelled record is the seed the earliest implant record, marked seed_rule "
        "'fallback-implant-only'. Each case records seed_type 'implant' or 'non-implant'. The "
        "malicious window is unchanged by the seed choice (all resolved records +/- 30 min), so "
        "earlier implant records stay inside it and in useful_refs; only the seed's offset in "
        "the window moves. No hand-picking beyond the declared list."),
    "implant_list": {"images": list(IMPLANT_IMAGES), "why": IMPLANT_REASON},
    "malicious_window": "Resolved labelled records of the stage, min - 30 min to max + 30 min, on the stage's hosts.",
    "benign_seed": (
        "Fixed-seed sampler over unlabelled, never-used DEDALE days: each pick prefers a "
        "(day, host) group new on both axes, ties toward a new day; >=4 days, >=4 hosts; the "
        "first two groups that can supply one get an admin-looking record."),
    "window_matching": (
        "Benign cases are paired one-to-one with malicious cases by a seeded shuffle of the "
        "malicious list (random.Random(SEED)), zipped with the benign list in sampler order. Each "
        "benign window gets its partner's duration, with the benign seed at the same offset from "
        "the window start as the malicious seed has from its window start. No other volume "
        "matching is applied."),
    "window_clipping": (
        "Label-blind; duration takes priority over seed offset. The day file's coverage is its "
        "first to last ingested record. If the placed benign window starts before coverage, it "
        "is shifted forward to start at the first record and keeps the partner's full duration; "
        "if it ends after coverage, it is shifted back to end at the last record, symmetrically. "
        "Only if the day file is shorter than the duration is the window clipped to coverage, "
        "recorded in 'clipped'. The seed must stay inside the window (asserted). Each case "
        "records the actual seed_offset_hours and offset_shifted_hours (window start moved; "
        "positive = later, so the seed sits earlier in the window than its partner's)."),
    "keys": "h01..h18 from random.Random(SEED).shuffle over the fixed case order (malicious, benign, k8s).",
}
LIMITATIONS = [
    "The three CLIENT1 benign cases come from days (D06, D13, D14) that carry only CLIENT1 telemetry, so their surroundings are quieter than the weekday cases.",
    "Only two benign picks are admin-looking, and both are cmd.exe; no PowerShell benign case was drawn.",
    "All six malicious cases come from one DEDALE APT campaign; they are correlated and not independent samples.",
    "Only Sysmon process-creation records resolve from the DEDALE labels, so some stages have very few ingestible follow-up records.",
    "Windows benign means 'no labelled attack activity that day', not a publisher-verified benign label.",
    "Malicious cases generally carry more events than their benign partners (not in every pair). This comes from the data (attack activity adds events to its window) and was deliberately not volume-matched; only window duration was matched.",
]


def _iso(ts) -> str:
    return pd.Timestamp(ts).tz_convert("UTC").strftime("%Y-%m-%dT%H:%M:%SZ")


def _rows_by_id(telemetry) -> dict:
    frames = [t[["event_id", "timestamp", "device", "source_ref"]].assign(
        process_name=t["process_name"] if "process_name" in t else "")
        for t in (telemetry.processes, telemetry.network, telemetry.logons)]
    both = pd.concat(frames, ignore_index=True)
    return {r.event_id: r for r in both.itertuples(index=False)}


# -- primary: DEDALE malicious ----------------------------------------------------------


def select_malicious_seed(ordered: list[tuple[str, str]]) -> tuple[str, str, str]:
    """Apply SELECTION_RULES['malicious_seed'] to ``[(ref, image), ...]`` in time order.

    Returns ``(seed_ref, seed_rule, seed_type)``: the earliest record whose image is not an
    implant image; else the earliest record, ``fallback-implant-only``.
    """
    if not ordered:
        raise ValueError("a stage needs at least one ingested labelled record")
    implants = {img.lower() for img in IMPLANT_IMAGES}
    for ref, image in ordered:
        if image.lower() not in implants:
            return ref, "non-implant", "non-implant"
    return ordered[0][0], "fallback-implant-only", "implant"


def build_dedale_malicious(external: Path) -> list[dict]:
    labels = json.loads((external / "dedale/labels/dedale_class1_labels.json").read_text(encoding="utf-8"))
    stages = {name: st["refs"] for name, st in labels["scenarios"]["apt"]["stages"].items()}
    cases = []
    for stage_date, day in MALICIOUS_STAGES.items():
        day_dir = external / "dedale/winlogbeat" / day
        if not day_dir.is_dir():
            raise FileNotFoundError(f"DEDALE day {day} not fetched yet ({day_dir})")
        telemetry, _ = load_source("winlogbeat", day_dir)
        refs = stages[stage_date]
        resolved = {ref: r.event_id for ref, r in resolve_refs(refs, telemetry).items() if r.event_id}
        if not resolved:
            raise ValueError(f"stage {stage_date}: no ref resolves to an ingested record in {day}")
        rows = _rows_by_id(telemetry)
        order = sorted(resolved, key=lambda ref: (pd.Timestamp(rows[resolved[ref]].timestamp), resolved[ref]))
        seed_ref, seed_rule, seed_type = select_malicious_seed(
            [(ref, str(rows[resolved[ref]].process_name)) for ref in order])
        seed = rows[resolved[seed_ref]]
        stamps = pd.to_datetime([rows[resolved[r]].timestamp for r in order], utc=True)
        hosts = sorted({str(rows[resolved[r]].device) for r in order})
        cases.append({
            "_quadrant": "windows-malicious", "_id": f"mal-{stage_date}",
            "_identity": f"{seed.device} / {seed.process_name}",
            "_rationale": (f"DEDALE APT stage {stage_date} (file day {day}), labelled by the dataset "
                           f"publisher; {len(resolved)} of {len(refs)} labelled refs are ingested by the "
                           f"loader; seed chosen by rule '{seed_rule}' ({seed_type} seed)."),
            "_resolved": len(resolved), "_day": day, "_seed_image": str(seed.process_name),
            "_seed_rule": seed_rule, "_seed_type": seed_type,
            "_seed_ts": pd.Timestamp(seed.timestamp),
            "source": {"kind": "winlogbeat", "path": str(day_dir.resolve())},
            "window": {"start": _iso(stamps.min() - WINDOW_PAD), "end": _iso(stamps.max() + WINDOW_PAD)},
            "devices": hosts,
            "expected_decision": "malicious", "provenance": "emulated-testbed",
            "label_source": f"DEDALE class-1 labels, apt stage {stage_date} (dedale_class1_labels.json)",
            "anchor_refs": [seed_ref],
            "useful_refs": [r for r in refs if r != seed_ref],
            "note": "",
        })
    return cases


def check_stage_day_crossing(external: Path) -> dict:
    """Which day files each target stage resolves in (expected: exactly its own)."""
    labels = json.loads((external / "dedale/labels/dedale_class1_labels.json").read_text(encoding="utf-8"))
    stages = {name: st["refs"] for name, st in labels["scenarios"]["apt"]["stages"].items()}
    found: dict[str, list[str]] = {s: [] for s in MALICIOUS_STAGES}
    for day in sorted(set(MALICIOUS_STAGES.values())):
        telemetry, _ = load_source("winlogbeat", external / "dedale/winlogbeat" / day)
        for stage in MALICIOUS_STAGES:
            if any(r.event_id for r in resolve_refs(stages[stage], telemetry).values()):
                found[stage].append(day)
    bad = {s: d for s, d in found.items() if d != [MALICIOUS_STAGES[s]]}
    if bad:
        raise ValueError(f"stage/day crossing: {bad}")
    return found


# -- primary: DEDALE benign -------------------------------------------------------------


def build_dedale_benign(external: Path, count: int = 6) -> list[dict]:
    rng = random.Random(SEED)
    groups: dict[tuple[str, str], list] = {}
    coverage: dict[str, tuple[pd.Timestamp, pd.Timestamp]] = {}
    for day in BENIGN_CANDIDATE_DAYS:
        day_dir = external / "dedale/winlogbeat" / day
        if not day_dir.is_dir():
            continue
        telemetry, _ = load_source("winlogbeat", day_dir)
        coverage[day] = day_coverage(telemetry)
        for row in telemetry.processes.itertuples(index=False):
            text = f"{row.process_name} {row.command_line}"
            groups.setdefault((day, str(row.device)), []).append(
                (str(row.source_ref).split(";File=")[0], bool(_ADMIN_RE.search(text)),
                 pd.Timestamp(row.timestamp), str(row.process_name)))
    if not groups:
        raise FileNotFoundError("no benign DEDALE days on disk")
    keys = sorted(groups)
    rng.shuffle(keys)
    # Greedy spread: each pick prefers a group new on both axes (fewest already-seen of
    # day and host), ties broken toward a new day, since days are the scarcer axis.
    chosen: list[tuple[str, str]] = []
    seen_hosts: set[str] = set()
    seen_days: set[str] = set()
    remaining = list(keys)
    while remaining and len(chosen) < count:
        remaining.sort(key=lambda k: ((k[0] in seen_days) + (k[1] in seen_hosts), k[0] in seen_days))
        key = remaining.pop(0)
        chosen.append(key)
        seen_hosts.add(key[1])
        seen_days.add(key[0])
    if len(seen_days) < 4 or len(seen_hosts) < 4 or len(chosen) < count:
        raise ValueError(f"benign spread too narrow: {len(seen_days)} days, {len(seen_hosts)} hosts, "
                         f"{len(chosen)} groups (need >=4 days, >=4 hosts, {count} groups)")
    cases = []
    admin_needed, admin_assigned = 2, 0
    for day, host in chosen:
        members = sorted(groups[(day, host)], key=lambda m: (m[2], m[0]))
        admins = [m for m in members if m[1]]
        want_admin = admin_assigned < admin_needed and bool(admins)
        ref, is_admin, ts, pname = rng.choice(admins if want_admin else members)
        admin_assigned += int(want_admin)
        cases.append({
            "_quadrant": "windows-benign", "_id": f"ben-{day}-{host}",
            "_identity": f"{host} / {pname}", "_seed_image": pname, "_seed_ts": ts,
            "_coverage": coverage[day],
            "_rationale": (f"Sysmon process event on DEDALE day {day}, a day with no APT label; "
                           f"{'admin-looking but benign' if is_admin else 'ordinary'} ({pname})."),
            "_admin_looking": is_admin, "_day": day,
            "source": {"kind": "winlogbeat", "path": str((external / "dedale/winlogbeat" / day).resolve())},
            "window": {"start": _iso(ts - WINDOW_PAD), "end": _iso(ts + WINDOW_PAD)},
            "devices": [host],
            "expected_decision": "benign", "provenance": "emulated-testbed",
            "label_source": (f"No DEDALE APT label on day {day} (dedale_class1_labels.json labels the "
                             "attack stages 2025-01-06..13 only). 'Benign' means no labelled attack "
                             "activity that day, not a publisher-verified benign label."),
            "anchor_refs": [ref], "useful_refs": [], "note": "",
        })
    if admin_assigned < admin_needed:
        raise ValueError(f"only {admin_assigned} admin-looking benign picks; need {admin_needed}")
    return cases


def day_coverage(telemetry) -> tuple[pd.Timestamp, pd.Timestamp]:
    """First and last ingested record of a day file, across every table."""
    stamps = pd.concat([pd.to_datetime(t["timestamp"], utc=True)
                        for t in (telemetry.processes, telemetry.network, telemetry.logons) if len(t)])
    return stamps.min(), stamps.max()


def place_window(start, duration, coverage):
    """Apply SELECTION_RULES['window_clipping']: return ``(start, end, shift, clipped)``.

    ``shift`` is how far the window start moved (positive = later). Duration is kept by
    shifting inside the day file's coverage; only a day shorter than ``duration`` clips.
    """
    cov_start, cov_end = coverage[0].floor("s"), coverage[1].ceil("s")
    original = start
    if start < cov_start:
        start = cov_start
    if start + duration > cov_end:
        start = max(cov_end - duration, cov_start)
    end = start + duration
    clipped = []
    if end > cov_end:
        end, clipped = cov_end, ["end"]
    return start, end, start - original, clipped


def match_windows(malicious: list[dict], benign: list[dict]) -> list[dict]:
    """Apply SELECTION_RULES['window_matching'] in place; return one record per pair.

    The malicious list is shuffled with ``random.Random(SEED)`` and zipped with the benign
    list in sampler order. Each benign window takes its partner's duration, with the seed at
    the partner's relative offset, clipped to the benign day file's coverage.
    """
    if len(malicious) != len(benign):
        raise ValueError("window matching needs equal numbers of malicious and benign cases")
    partners = list(malicious)
    random.Random(SEED).shuffle(partners)
    pairs = []
    for mal, ben in zip(partners, benign):
        m_start, m_end = pd.Timestamp(mal["window"]["start"]), pd.Timestamp(mal["window"]["end"])
        duration, offset = m_end - m_start, mal["_seed_ts"] - m_start
        start = ben["_seed_ts"] - offset
        end = start + duration
        start, end, shift, clipped = place_window(start, duration, ben["_coverage"])
        if not start <= ben["_seed_ts"] <= end:
            raise ValueError(f"{ben['_id']}: seed falls outside its placed window")
        ben["window"] = {"start": _iso(start), "end": _iso(end)}
        ben["_paired_with"], mal["_paired_with"] = mal["_id"], ben["_id"]
        ben["_clipped"] = clipped
        ben["_offset_shifted_hours"] = round(shift.total_seconds() / 3600, 3)
        pairs.append({"malicious": mal["_id"], "benign": ben["_id"],
                      "duration_hours": round(duration.total_seconds() / 3600, 3),
                      "partner_seed_offset_hours": round(offset.total_seconds() / 3600, 3),
                      "offset_shifted_hours": ben["_offset_shifted_hours"],
                      "clipped": clipped})
    return pairs


# -- secondary: injected k8s benign -----------------------------------------------------


def load_background(external: Path) -> list[dict]:
    src = external / "k8s_ingress" / "raw"
    files = sorted(p for p in src.iterdir() if p.suffix.lower() in (".log", ".json", ".jsonl"))
    if not files:
        raise FileNotFoundError(f"no k8s_ingress background log in {src}")
    return [json.loads(line) for path in files
            for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _stamp(rec: dict):
    raw = rec.get("stageTimestamp") or rec.get("requestReceivedTimestamp")
    return pd.Timestamp(raw) if raw else pd.NaT


def build_k8s_benign(scenarios: list[dict], background: list[dict], out: Path) -> list[dict]:
    """One self-contained source per scenario, ``out/sources/<n>/kube-apiserver-audit.log``:
    the scenario's injected records plus every real background record within
    ``K8S_PAD`` of them, in time order, so injected lines sit among real ones."""
    stamped = [(rec, _stamp(rec)) for rec in background]
    cases = []
    for n, scenario in enumerate(scenarios, 1):
        recs = scenario["records"]
        stamps = pd.to_datetime([r["stageTimestamp"] for r in recs], utc=True)
        lo, hi = stamps.min() - K8S_PAD, stamps.max() + K8S_PAD
        bg = [rec for rec, ts in stamped if not pd.isna(ts) and lo <= ts <= hi]
        # A neutral directory name: the scenario id never reaches the telemetry path.
        source_dir = out / "sources" / f"k8s-{n:02d}"
        source_dir.mkdir(parents=True, exist_ok=True)
        combined = sorted(bg + recs, key=lambda r: _stamp(r))
        (source_dir / "kube-apiserver-audit.log").write_text(
            "".join(json.dumps(r) + "\n" for r in combined), encoding="utf-8")
        anchor = scenario["anchor_id"]
        anchor_rec = next(r for r in recs if r["auditID"] == anchor)
        link = scenario.get("link")
        cases.append({
            "_quadrant": "k8s-benign", "_identity": anchor_rec["user"]["username"],
            "_rationale": scenario["rationale"], "_scenario_id": scenario["id"],
            "_background_raw": len(bg), "_injected": len(recs),
            "source": {"kind": "k8s", "path": str(source_dir.resolve())},
            "expected_decision": "benign", "provenance": "real+injected",
            "label_source": ("Injected benign scenario authored for holdout-v1 into the real "
                             "k8s_ingress background; label by construction, rationale in "
                             "HOLDOUT-MANIFEST.json."),
            "anchor_refs": [f"auditID={anchor}"],
            "useful_refs": [f"auditID={r['auditID']}" for r in recs if r["auditID"] != anchor],
            **({"link": {"kind": link["kind"], "refs": [f"auditID={link['from_id']}",
                                                        f"auditID={link['to_id']}"]}} if link else {}),
            "note": "",
        })
    return cases


# -- assembly ---------------------------------------------------------------------------


def _sha256_dir(path: Path) -> str:
    digest = hashlib.sha256()
    for file in sorted(p for p in path.iterdir() if p.is_file()):
        digest.update(file.name.encode())
        with file.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
    return digest.hexdigest()


def assemble(cases: list[dict], with_protocol: bool = True) -> tuple[dict, dict]:
    counts: dict[str, int] = {}
    for c in cases:
        counts[c["_quadrant"]] = counts.get(c["_quadrant"], 0) + 1
    if counts != EXPECTED_COUNTS:
        raise ValueError(f"quadrant counts {counts} != {EXPECTED_COUNTS}")
    ordered = list(cases)
    random.Random(SEED).shuffle(ordered)
    key_of = {c["_id"]: f"h{i:02d}" for i, c in enumerate(ordered, 1) if "_id" in c}
    spec_cases, manifest_cases = [], []
    hashes: dict[str, str] = {}
    for i, case in enumerate(ordered, 1):
        key = f"h{i:02d}"
        quadrant = case["_quadrant"]
        platform = "k8s" if quadrant.startswith("k8s") else "windows"
        spec_case = {"key": key, **{k: v for k, v in case.items() if not k.startswith("_")},
                     "platform": platform,
                     "provenance_class": "injected" if platform == "k8s" else "real",
                     "quadrant": quadrant, "holdout_role": ROLE[quadrant],
                     # Carried into rows so malicious recall can be split by seed type.
                     **({"seed_type": case["_seed_type"]} if "_seed_type" in case else {})}
        spec_cases.append(spec_case)
        src = case["source"]["path"]
        if src not in hashes:
            hashes[src] = _sha256_dir(Path(src))
        manifest_cases.append({
            "key": key, "quadrant": quadrant, "holdout_role": ROLE[quadrant], "platform": platform,
            "provenance": case["provenance"], "provenance_class": spec_case["provenance_class"],
            "expected_decision": case["expected_decision"], "identity": case["_identity"],
            "anchor_ref": case["anchor_refs"][0], "useful_refs": len(case["useful_refs"]),
            "source_path": src, "source_sha256": hashes[src],
            "label_source": case["label_source"], "rationale": case["_rationale"],
            **{k[1:]: v for k, v in case.items()
               if k in ("_day", "_resolved", "_admin_looking", "_scenario_id", "_background_raw", "_injected",
                        "_seed_image", "_seed_rule", "_seed_type", "_clipped", "_offset_shifted_hours")},
            **({"seed_offset_hours": round((case["_seed_ts"] - pd.Timestamp(case["window"]["start"]))
                                           .total_seconds() / 3600, 3)}
               if case.get("window") and "_seed_ts" in case else {}),
            **({"paired_with": key_of[case["_paired_with"]]} if "_paired_with" in case else {}),
            **({"window_hours": round((pd.Timestamp(case["window"]["end"])
                                       - pd.Timestamp(case["window"]["start"])).total_seconds() / 3600, 3)}
               if case.get("window") else {}),
        })
    spec = {"spec_version": SPEC_VERSION, "name": "holdout-v1-windows",
            **({"protocol": PROTOCOL} if with_protocol else {}),
            "seed_mode": "analyst", "cases": spec_cases}
    manifest = {
        "protocol": PROTOCOL, "seed": SEED, "seed_mode": "analyst",
        "roles": {"primary": "12 Windows cases (6 malicious, 6 benign): the discrimination measurement.",
                  "secondary": "6 injected Kubernetes benign cases: a false-accusation / generalisation check only."},
        "quadrant_counts": counts, "not_evaluated": NOT_EVALUATED,
        "selection_rules": SELECTION_RULES, "limitations": LIMITATIONS,
        "excluded_previously_seen": EXCLUDED,
        "benign_sampler": {"seed": SEED, "candidate_days": BENIGN_CANDIDATE_DAYS,
                           "rule": ">=4 days, >=4 hosts, >=2 admin-looking picks; no labels on these days"},
        "k8s_background": {"corpus": "k8s_ingress", "pad_minutes": K8S_PAD.total_seconds() / 60},
        "cases": manifest_cases,
    }
    return spec, manifest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--data-external", type=Path, default=DEFAULT_EXTERNAL)
    parser.add_argument("--no-protocol", action="store_true",
                        help="Omit the top-level protocol key (for a harness without holdout-v1-windows)")
    args = parser.parse_args(argv)
    external, out = args.data_external, args.out
    out.mkdir(parents=True, exist_ok=True)

    crossing = check_stage_day_crossing(external)
    scenarios = scenarios_from_payload(K8S_BENIGN_PAYLOAD, "k8s-benign")
    assert_no_leaks([r for s in scenarios for r in s["records"]])
    malicious, benign = build_dedale_malicious(external), build_dedale_benign(external)
    pairs = match_windows(malicious, benign)
    cases = malicious + benign + build_k8s_benign(scenarios, load_background(external), out)
    spec, manifest = assemble(cases, with_protocol=not args.no_protocol)
    keys = {c["anchor_ref"]: c["key"] for c in manifest["cases"]}
    ids = {c["_id"]: keys[c["anchor_refs"][0]] for c in malicious + benign}
    manifest["window_pairs"] = [{**pair, "malicious": ids[pair["malicious"]], "benign": ids[pair["benign"]]}
                                for pair in pairs]
    manifest["stage_day_check"] = crossing
    (out / "injected-k8s-events.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for s in scenarios for r in s["records"]), encoding="utf-8")
    manifest["injected_file_sha256"] = hashlib.sha256((out / "injected-k8s-events.jsonl").read_bytes()).hexdigest()
    name = "spec-holdout-v1.json" if not args.no_protocol else "spec-holdout-v1.no-protocol.json"
    (out / name).write_text(json.dumps(spec, indent=1) + "\n", encoding="utf-8")
    (out / "HOLDOUT-MANIFEST.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({"spec": str(out / name), "cases": len(spec["cases"]),
                      "quadrants": manifest["quadrant_counts"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
