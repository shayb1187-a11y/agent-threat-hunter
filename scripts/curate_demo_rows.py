"""Build ``docs/demo/recorded/``: a small, allow-listed gallery of recorded model runs.

The demo cannot call a model (no API key, no GPU), so it replays a handful of reports
from the holdout-v1-windows Colab run (``holdout-9b-v6-ecd865890442``) as static pages.
This script is the only way those pages enter the repository, and it is deliberately
narrow:

* **Allow-list only.** Each copied file is named in :data:`ALLOW`. Only the ``.html``
  and ``.md`` report of a listed row is copied. The ``.json`` rows are read for their
  scores but never copied: they embed the full investigation state. ``real/index.html``
  is never copied: it links the Kubernetes cases, whose source licence is not recorded.
* **Labels come from the rows, not from this file.** Each allow-list entry declares
  what the row is meant to show (for example ``UNSAFE CLEAR``). The script derives the
  same category from the row's recorded ``expected_decision`` and ``decision``, and
  refuses to build if they disagree. A hand-written label therefore cannot drift from
  the evidence.
* **Leak scan.** Every copied file is scanned for Kubernetes auditID-shaped UUIDs,
  Kubernetes strings and local paths. The build fails if any appear.

Usage::

    python scripts/curate_demo_rows.py [--source RESULTS_DIR] [--dest docs/demo/recorded]

The source folder lives outside git (see docs/holdout-v1-windows-results.md, "Artifacts").
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ath.reporting import IndexEntry, render_index  # noqa: E402

RUN_ID = "holdout-9b-v6-ecd865890442"
DEFAULT_SOURCE = Path.home() / "Downloads" / "ath-holdout-v1" / "results-9b-colab" / f"ath-results-{RUN_ID}"
DEFAULT_DEST = ROOT / "docs" / "demo" / "recorded"
MODEL = "qwen3.5:9b"
PROFILE = "operational-v6"
DEDALE_URL = "https://dedale.inria.fr/"
DEDALE_DOI = "https://doi.org/10.57745/Y5JLDG"
SYNTHETIC, DEDALE = "synthetic", "DEDALE (CC BY 4.0)"
EXTENSIONS = (".html", ".md")

CORRECT_MALICIOUS, CORRECT_BENIGN, CORRECT_ABSTAIN = "correct malicious", "correct benign", "correct abstain"
SAFE_ABSTAIN, UNSAFE_CLEAR = "safe abstain", "UNSAFE CLEAR"
FALSE_ACCUSATION, OVER_CALL = "FALSE ACCUSATION", "OVER-CALL"


@dataclass(frozen=True)
class Allowed:
    """One recorded row the gallery may show.

    Attributes:
        group: The run sub-folder: ``dev-gate`` (synthetic) or ``real`` (DEDALE).
        key: Case key (``sample-01``, ``h05``).
        arm: ``d1`` (the model) or ``deterministic``.
        shows: The category this row is meant to illustrate; checked against the row.
        line: One line on what the page shows, for the gallery.
    """

    group: str
    key: str
    arm: str
    shows: str
    line: str

    @property
    def stem(self) -> str:
        return f"{self.key}_{self.arm}_1"

    @property
    def provenance(self) -> str:
        return SYNTHETIC if self.group == "dev-gate" else DEDALE


ALLOW: tuple[Allowed, ...] = (
    Allowed("dev-gate", "sample-01", "d1", CORRECT_MALICIOUS,
            "Probed the process tree, found reg.exe saving the SAM hive, called it malicious."),
    Allowed("dev-gate", "sample-01", "deterministic", CORRECT_MALICIOUS,
            "Deterministic triage calls the same incident malicious from the detection findings."),
    Allowed("dev-gate", "sample-02", "d1", CORRECT_BENIGN,
            "Found dism.exe /ScanHealth under the remote shell and cleared it as maintenance."),
    Allowed("dev-gate", "sample-02", "deterministic", FALSE_ACCUSATION,
            "Deterministic triage cannot tell maintenance from credential export: it accuses."),
    Allowed("dev-gate", "sample-03", "d1", CORRECT_ABSTAIN,
            "The deciding child process is deliberately missing; the model abstained and named the gap."),
    Allowed("dev-gate", "sample-03", "deterministic", OVER_CALL,
            "Deterministic triage calls it malicious although the telemetry cannot decide."),
    Allowed("real", "h14", "d1", CORRECT_BENIGN,
            "Real Windows logs: a user opening a local PDF in Firefox, correctly cleared."),
    Allowed("real", "h14", "deterministic", SAFE_ABSTAIN,
            "The deterministic arm abstains, as it did on all 18 holdout cases."),
    Allowed("real", "h07", "d1", SAFE_ABSTAIN,
            "APT implant (svcmon.exe): two process-tree probes, opaque child, abstained. Safe, but no answer."),
    Allowed("real", "h07", "deterministic", SAFE_ABSTAIN,
            "The deterministic arm abstains."),
    Allowed("real", "h05", "d1", UNSAFE_CLEAR,
            "The failure: an APT step cleared as benign, partly because whoami.exe is signed by Microsoft."),
    Allowed("real", "h05", "deterministic", SAFE_ABSTAIN,
            "The deterministic arm abstains instead of clearing."),
)

# A Kubernetes auditID is a random (RFC 4122) UUID. Sysmon process GUIDs in the DEDALE
# rows are UUID-shaped too, but always carry the ``sysmon:`` prefix and are not RFC 4122
# (e.g. ``sysmon:416dd0c5-12ee-6770-2904-000000000c00``). So: any UUID-shaped string not
# prefixed ``sysmon:`` fails, and any RFC 4122 UUID fails wherever it appears.
_UUID = re.compile(r"(?i)(sysmon:)?\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b")
_RFC4122 = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
# Local paths name the machine that ran or curated the rows. The dataset's own
# ``C:\Users\client1`` paths are testbed telemetry and are allowed.
_FORBIDDEN = re.compile(r"(?i)auditid|kubernetes|\bk8s|kube-|serviceaccount|shayb|[\\/]downloads[\\/]|/content/")


def category(expected: str, decision: str) -> str:
    """What a row shows, derived from its recorded expected label and decision."""
    if decision == expected:
        return {"malicious": CORRECT_MALICIOUS, "benign": CORRECT_BENIGN, "abstain": CORRECT_ABSTAIN}[expected]
    if decision == "abstain":
        return SAFE_ABSTAIN
    if expected == "malicious" and decision == "benign":
        return UNSAFE_CLEAR
    if decision == "malicious":
        return FALSE_ACCUSATION if expected == "benign" else OVER_CALL
    return f"WRONG ({decision} where {expected} was expected)"


def leaks(text: str) -> list[str]:
    """Every Kubernetes-, auditID- or local-path-shaped string in ``text``."""
    found = [m.group(0) for m in _FORBIDDEN.finditer(text)]
    for match in _UUID.finditer(text):
        prefixed, uuid = match.group(1), match.group(2)
        if not prefixed or _RFC4122.match(uuid):
            found.append(match.group(0))
    return found


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _scores(source: Path, item: Allowed) -> dict:
    """The row's recorded scores. Read here; the JSON row itself is never copied."""
    row = json.loads((source / item.group / "rows" / f"{item.stem}.json").read_text(encoding="utf-8"))
    if row.get("sample") != item.key or row.get("arm") != item.arm or row.get("scripted") is not False:
        raise SystemExit(f"{item.stem}: row identity does not match the allow-list, or it is scripted")
    return row["scores"]


def _gallery_note() -> str:
    """An escaped paragraph placed under the gallery heading (attribution and scope)."""
    e = html.escape
    return (
        f'<p class="muted">Recorded outputs of {e(MODEL)} ({e(PROFILE)}) and the deterministic arm, from '
        f"Colab run <code>{e(RUN_ID)}</code>, replayed as static pages. No model runs here. "
        "Synthetic rows use ATH's generated dev scenarios. Real rows are derived from the DEDALE dataset "
        f'(INRIA / IRISA, CC BY 4.0, <a href="{e(DEDALE_URL)}">{e(DEDALE_URL)}</a>, '
        f'<a href="{e(DEDALE_DOI)}">{e(DEDALE_DOI)}</a>); see '
        '<a href="ATTRIBUTION.md">ATTRIBUTION.md</a>. The Title column says what each row shows, '
        "including the failure.</p>\n"
    )


def _attribution(written: list[dict]) -> str:
    rows = "\n".join(f"| `{r['file']}` | {r['provenance']} | {r['sha256'][:16]}… |" for r in written)
    return f"""# Recorded model runs: attribution and scope

These pages are **recorded outputs replayed as static pages**. Nothing here calls a model.
Each file is the unmodified `.md` or `.html` report of one row from the Colab run
`{RUN_ID}` ({MODEL}, profile {PROFILE}, and the deterministic arm). The run is described
in [holdout-v1-windows-results.md](https://github.com/shayb1187-a11y/agentic-threat-hunter/blob/main/docs/holdout-v1-windows-results.md). The files were
selected by the allow-list in `scripts/curate_demo_rows.py`. That script also rebuilt
`index.html` and wrote `SOURCES.json`, which records each file's sha256 and its source row's scores.

## DEDALE (rows h05, h07, h14)

The `h*` reports are derived from **DEDALE: Dataset for Evaluating Detection of APT among
Logs and Events**, published by INRIA / IRISA PIRAT (Lanvin, Majorczyk). It is licensed
**CC BY 4.0**. Dataset: {DEDALE_DOI}. Project page: {DEDALE_URL}. (Citation and licence
as recorded in `data/external/MANIFEST.json`.) The reports quote host names, process
command lines and event identifiers from that dataset. The expected labels come from the
pre-registered holdout spec. They are shown for scoring only and were never an input to
the investigation.

## Synthetic rows (sample-01..03)

The `sample-*` reports investigate ATH's own generated development scenarios
(`ath.evaluation.auth_execution.scenarios("dev")`). No third-party data is involved.

## What is deliberately not here

- No `.json` rows: they embed the full investigation state.
- No `real/index.html` from the run: it links Kubernetes cases, and the licence of
  their background source is not recorded.
- No other case keys. The curation script scans every copied file for
  Kubernetes auditID-shaped UUIDs and Kubernetes strings, and it fails if any appear.

## Files

| File | Source | sha256 |
|---|---|---|
{rows}
"""


def build(source: Path, dest: Path) -> dict:
    """Copy the allow-listed reports, rebuild the gallery index, and return SOURCES."""
    source, dest = Path(source), Path(dest)
    for group in {a.group for a in ALLOW}:
        if not (source / group / "rows").is_dir():
            raise SystemExit(f"source rows not found: {source / group / 'rows'}")
    freezes = {g: json.loads((source / g / "FREEZE.json").read_text(encoding="utf-8"))["freeze_sha256"]
               for g in sorted({a.group for a in ALLOW})}
    if dest.exists():
        shutil.rmtree(dest)
    (dest / "rows").mkdir(parents=True)

    written, entries = [], []
    for item in ALLOW:
        scores = _scores(source, item)
        derived = category(scores["expected_decision"], scores["decision"])
        if derived != item.shows:
            raise SystemExit(f"{item.stem}: allow-list says {item.shows!r}, the row shows {derived!r}")
        if not scores.get("complete"):
            raise SystemExit(f"{item.stem}: incomplete row")
        for ext in EXTENSIONS:
            src = source / item.group / "rows" / f"{item.stem}{ext}"
            text = src.read_text(encoding="utf-8")
            found = leaks(text)
            if found:
                raise SystemExit(f"{src.name}: forbidden strings {sorted(set(found))[:5]}")
            target = dest / "rows" / src.name
            shutil.copyfile(src, target)
            written.append({"file": f"rows/{src.name}", "provenance": item.provenance,
                            "sha256": _sha256(target)})
        arm = f"{MODEL} (D1)" if item.arm == "d1" else "deterministic"
        entries.append(IndexEntry(
            label=f"{item.key} · {arm}", href=f"rows/{item.stem}.html",
            verdict=scores["decision"].capitalize(), complete=True,
            elapsed_seconds=scores.get("elapsed_seconds"), expected=scores["expected_decision"],
            title=f"[{item.provenance}] {item.shows}: {item.line}"))

    page = render_index(entries, title=f"Recorded runs: {MODEL} vs deterministic")
    heading_end = page.index("</h1>\n") + len("</h1>\n")
    page = page[:heading_end] + _gallery_note() + page[heading_end:]
    # LF on every platform, so the sha256s in SOURCES.json hold wherever it is checked out
    # (docs/demo/recorded is -text in .gitattributes).
    (dest / "index.html").write_text(page, encoding="utf-8", newline="\n")
    (dest / "ATTRIBUTION.md").write_text(_attribution(written), encoding="utf-8", newline="\n")

    sources = {
        "run_id": RUN_ID, "model": MODEL, "profile": PROFILE, "freeze_sha256": freezes,
        "note": "Recorded outputs replayed as static pages. Scores are copied from each row's "
                "recorded 'scores'; the rows themselves are not in the repository.",
        "rows": [{"key": a.key, "arm": a.arm, "group": a.group, "provenance": a.provenance,
                  "shows": a.shows, "line": a.line, "href": f"rows/{a.stem}.html", "md": f"rows/{a.stem}.md",
                  "expected": s["expected_decision"], "decision": s["decision"]}
                 for a, s in ((a, _scores(source, a)) for a in ALLOW)],
        "files": written,
    }
    (dest / "SOURCES.json").write_text(json.dumps(sources, indent=2) + "\n", encoding="utf-8", newline="\n")
    return sources


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE, help="The run's results folder.")
    parser.add_argument("--dest", type=Path, default=DEFAULT_DEST, help="Gallery directory (rebuilt).")
    args = parser.parse_args(argv)
    sources = build(args.source, args.dest)
    total = sum(p.stat().st_size for p in args.dest.rglob("*") if p.is_file())
    print(f"Wrote {len(sources['files'])} reports ({len(sources['rows'])} rows) to {args.dest}; "
          f"{total / 1024:.0f} KiB in total.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
