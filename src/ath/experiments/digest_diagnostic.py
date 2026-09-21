"""Which columns move a telemetry digest between two runtimes, measured, not assumed.

The laptop (CPython 3.9 then, numpy 2.0) and Colab (CPython 3.13, numpy 2.1) computed
different v1 digests for byte-identical cases. The commit range between the two manifests
also contains loader work, so the cause has to be measured: this writes one file per
runtime with a digest per corpus, per table, per column, under both digest versions, and
``compare`` names the columns whose digests differ between two such files.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from ath.evaluation.ablation.manifest import (
    _TABLES,
    DIGEST_VERSIONS,
    column_digests,
    table_digest,
    table_digest_v2,
    telemetry_digest,
)
from ath.experiments.freeze import write_json
from ath.experiments.runs import runtime_record


def corpus_digests(name: str, telemetry: Any) -> dict[str, Any]:
    tables: dict[str, Any] = {}
    for table_name, event_type in _TABLES:
        frame = telemetry.table(event_type)
        tables[table_name] = {
            "rows": int(len(frame)),
            "dtypes": {str(c): str(frame[c].dtype) for c in frame.columns},
            "v1": table_digest(frame),
            "v2": table_digest_v2(frame),
            "columns_v1": column_digests(frame, 1),
            "columns_v2": column_digests(frame, 2),
        }
    return {
        "corpus": name,
        "telemetry_hash": {f"v{v}": telemetry_digest(telemetry, v) for v in DIGEST_VERSIONS},
        "tables": tables,
    }


def diagnose(
    bundles: Iterable[Any], *, out_dir: Path, label: str,
    log: Callable[[str], None] = lambda text: print(text, file=sys.stderr),
) -> Path:
    runtime = runtime_record()
    corpora = []
    for bundle in bundles:
        log(f"digesting {bundle.name} ...")
        corpora.append(corpus_digests(bundle.name, bundle.telemetry))
    payload = {"label": label, "runtime": runtime, "corpora": corpora}
    path = write_json(Path(out_dir) / f"DIGEST_DIAGNOSTIC_{label}.json", payload)
    log(f"wrote {path}")
    return path


def compare(path_a: Path, path_b: Path) -> dict[str, Any]:
    a = json.loads(Path(path_a).read_text(encoding="utf-8"))
    b = json.loads(Path(path_b).read_text(encoding="utf-8"))
    by_a = {c["corpus"]: c for c in a["corpora"]}
    by_b = {c["corpus"]: c for c in b["corpora"]}
    report: dict[str, Any] = {
        "a": {"label": a["label"], "runtime": a["runtime"]},
        "b": {"label": b["label"], "runtime": b["runtime"]},
        "corpora": {},
    }
    for corpus in sorted(set(by_a) | set(by_b)):
        if corpus not in by_a or corpus not in by_b:
            report["corpora"][corpus] = {"only_in": "a" if corpus in by_a else "b"}
            continue
        ca, cb = by_a[corpus], by_b[corpus]
        entry: dict[str, Any] = {
            "telemetry_hash_agrees": {
                v: ca["telemetry_hash"].get(v) == cb["telemetry_hash"].get(v) for v in ("v1", "v2")
            },
            "tables": {},
        }
        for table in sorted(set(ca["tables"]) | set(cb["tables"])):
            ta, tb = ca["tables"].get(table, {}), cb["tables"].get(table, {})
            moved = {}
            for version in ("v1", "v2"):
                cols_a, cols_b = ta.get(f"columns_{version}", {}), tb.get(f"columns_{version}", {})
                moved[version] = sorted(
                    c for c in set(cols_a) | set(cols_b) if cols_a.get(c) != cols_b.get(c)
                )
            dtype_moves = {
                c: (ta.get("dtypes", {}).get(c), tb.get("dtypes", {}).get(c))
                for c in set(ta.get("dtypes", {})) | set(tb.get("dtypes", {}))
                if ta.get("dtypes", {}).get(c) != tb.get("dtypes", {}).get(c)
            }
            entry["tables"][table] = {
                "rows": (ta.get("rows"), tb.get("rows")),
                "columns_moved": moved,
                "dtypes_moved": dtype_moves,
            }
        report["corpora"][corpus] = entry
    return report


def render(report: dict[str, Any]) -> str:
    lines = [
        f"A: {report['a']['label']} ({report['a']['runtime'].get('python')}, "
        f"pandas {report['a']['runtime'].get('packages', {}).get('pandas')}, numpy {report['a']['runtime'].get('packages', {}).get('numpy')})",
        f"B: {report['b']['label']} ({report['b']['runtime'].get('python')}, "
        f"pandas {report['b']['runtime'].get('packages', {}).get('pandas')}, numpy {report['b']['runtime'].get('packages', {}).get('numpy')})",
        "",
    ]
    for corpus, entry in report["corpora"].items():
        if "only_in" in entry:
            lines.append(f"{corpus}: only in {entry['only_in']}")
            continue
        agree = entry["telemetry_hash_agrees"]
        lines.append(f"{corpus}: v1 {'agrees' if agree['v1'] else 'DIFFERS'}, v2 {'agrees' if agree['v2'] else 'DIFFERS'}")
        for table, detail in entry["tables"].items():
            v1, v2 = detail["columns_moved"]["v1"], detail["columns_moved"]["v2"]
            if v1 or v2 or detail["dtypes_moved"] or detail["rows"][0] != detail["rows"][1]:
                lines.append(f"  {table}: rows {detail['rows'][0]} vs {detail['rows'][1]}; v1 moved {v1 or 'none'}; v2 moved {v2 or 'none'}; dtypes {detail['dtypes_moved'] or 'same'}")
    return "\n".join(lines)


