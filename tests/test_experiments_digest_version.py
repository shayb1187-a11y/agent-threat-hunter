"""A manifest built under digest version 2 says so on every entry, and the diagnostic
names exactly the columns that moved between two runtimes."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from ath.evaluation.ablation import manifest as m  # noqa: E402
from ath.experiments.digest_diagnostic import compare, corpus_digests, render  # noqa: E402
from test_ablation_harness import corpus, manifest, pipeline  # noqa: F401,E402


def test_a_v2_manifest_pins_the_v2_digest_and_round_trips(corpus, pipeline) -> None:
    _findings, cases, _environment = pipeline
    v1 = m.build_manifest("fixture", corpus, cases)
    v2 = m.build_manifest("fixture", corpus, cases, digest_version=2)
    assert v1 and all(e.digest_version == 1 for e in v1) and all(e.digest_version == 2 for e in v2)
    assert {e.telemetry_hash for e in v1} == {m.telemetry_hash(corpus)}
    assert {e.telemetry_hash for e in v2} == {m.telemetry_digest(corpus, 2)}
    assert m.manifest_hash(v1) != m.manifest_hash(v2)
    reloaded = m.load_manifest({"cases": [e.to_dict() for e in v2]})
    assert reloaded == v2 and m.manifest_hash(reloaded) == m.manifest_hash(v2)


def test_the_diagnostic_names_the_moved_columns(tmp_path, corpus) -> None:
    a = {"label": "a", "runtime": {"python": "3.11"}, "corpora": [corpus_digests("fixture", corpus)]}
    b = json.loads(json.dumps(a))
    b["label"] = "b"
    b["corpora"][0]["tables"]["process"]["columns_v1"]["timestamp"] = "0" * 64
    b["corpora"][0]["telemetry_hash"]["v1"] = "0" * 64
    (tmp_path / "a.json").write_text(json.dumps(a), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps(b), encoding="utf-8")
    report = compare(tmp_path / "a.json", tmp_path / "b.json")
    fixture = report["corpora"]["fixture"]
    assert fixture["telemetry_hash_agrees"] == {"v1": False, "v2": True}
    assert fixture["tables"]["process"]["columns_moved"] == {"v1": ["timestamp"], "v2": []}
    text = render(report)
    assert "v1 DIFFERS, v2 agrees" in text and "timestamp" in text
