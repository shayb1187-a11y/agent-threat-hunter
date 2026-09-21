"""Row restore matches by exact layout path, and preflight reports rather than guesses.

No daemon: the preflight test points the client at a closed port and checks that the
daemon check fails while every other check still reports.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from ath.experiments.bootstrap_colab import _member_belongs, restore_rows, save_results
from ath.experiments.paths import Layout
from ath.experiments.preflight import preflight

DIGEST = "2298b0e81f2a02f8108a5159ddb961c1521ff153829510f36062289d0b9a48de"


def _layout(root: Path) -> Layout:
    return Layout(root / "reports" / "local" / "dev", "D1", "qwen3.5:4b", DIGEST)


def test_a_zip_member_counts_only_directly_under_this_experiments_rows_dir(tmp_path) -> None:
    rel = "rows/D1_qwen3.5-4b/m2298b0e81f2a_d1-investigator-v3"
    assert _member_belongs(f"agentic-threat-hunter/reports/local/dev/{rel}/row.json", rel)
    assert _member_belongs(f"{rel}/row.json", rel)
    assert not _member_belongs(f"reports/local/dev/{rel}/nested/row.json", rel)
    assert not _member_belongs(f"reports/local/dev/{rel}.quarantine/row.json", rel)
    assert not _member_belongs(f"reports/local/dev/{rel}/row.reason.json", rel)
    assert not _member_belongs("reports/local/dev/rows/D1_qwen3.5-4b/m2298b0e81f2a_d1-investigator-v2/row.json", rel)
    assert not _member_belongs("reports/local/dev/rows/D1_qwen3.5-4b/row.json", rel)
    assert not _member_belongs("reports/local/dev/GUARD_EVENTS.jsonl", rel)


def test_restore_rows_copies_only_this_identity_and_never_overwrites(tmp_path) -> None:
    layout = _layout(tmp_path / "session")
    rel = "rows/D1_qwen3.5-4b/m2298b0e81f2a_d1-investigator-v3"
    archive = tmp_path / "dev_results.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(f"dev_results/reports/local/dev/{rel}/a.json", '{"a": 1}')
        zf.writestr(f"dev_results/reports/local/dev/{rel}/b.json", '{"b": 1}')
        zf.writestr(f"dev_results/reports/local/dev/{rel}.quarantine/q.json", "{}")
        zf.writestr("dev_results/reports/local/dev/rows/D1_qwen3.5-4b/m2298b0e81f2a_d1-investigator-v2/c.json", "{}")
        zf.writestr("dev_results/reports/local/dev/rows/D1_qwen3.5-4b/flat.json", "{}")
    layout.rows_dir.mkdir(parents=True)
    (layout.rows_dir / "a.json").write_text('{"a": "already here"}', encoding="utf-8")
    results = tmp_path / "results"
    (results / DIGEST[:12] / rel).mkdir(parents=True)
    (results / DIGEST[:12] / rel / "d.json").write_text('{"d": 1}', encoding="utf-8")
    (results / DIGEST[:12] / rel / "d.reason.json").write_text("{}", encoding="utf-8")

    counts = restore_rows(layout, [archive], [results], log=lambda _t: None)

    assert counts == {"copied": 2, "skipped": 1}
    assert sorted(p.name for p in layout.rows_dir.glob("*.json")) == ["a.json", "b.json", "d.json"]
    assert json.loads((layout.rows_dir / "a.json").read_text(encoding="utf-8")) == {"a": "already here"}


def test_save_results_mirrors_the_dev_tree_by_manifest(tmp_path) -> None:
    layout = _layout(tmp_path / "session")
    layout.rows_dir.mkdir(parents=True)
    (layout.rows_dir / "a.json").write_text("{}", encoding="utf-8")
    layout.quarantine_dir.mkdir()
    (layout.quarantine_dir / "q.json").write_text("{}", encoding="utf-8")
    layout.runs_dir.mkdir()
    (layout.runs_dir / "RUN_x.json").write_text("{}", encoding="utf-8")
    (layout.out_dir / "MANIFEST.json").write_text("{}", encoding="utf-8")
    layout.environment_path.write_text("{}", encoding="utf-8")
    target = save_results(layout, tmp_path / "results", 1, log=lambda _t: None)
    rel = "rows/D1_qwen3.5-4b/m2298b0e81f2a_d1-investigator-v3"
    assert target == tmp_path / "results" / DIGEST[:12]
    assert (target / rel / "a.json").exists()
    assert (target / (rel + ".quarantine") / "q.json").exists()
    assert (target / "runs" / "RUN_x.json").exists()
    assert (target / "MANIFEST.json").exists() and (target / layout.environment_path.name).exists()


def test_preflight_reports_every_check_even_with_no_daemon(tmp_path) -> None:
    out_dir = tmp_path / "dev"
    out_dir.mkdir()
    report, code = preflight(
        out_dir=out_dir, arm_letter="D1", model="qwen3.5:4b", base_url="http://127.0.0.1:9",
        external=tmp_path / "external", allow_cpu=True, log=lambda _t: None,
    )
    by_name = {c["name"]: c for c in report["checks"]}
    assert code == 1 and not report["ok"]
    assert by_name["daemon"]["status"] == "fail"
    assert by_name["manifest"]["status"] == "fail"
    assert by_name["telemetry"]["status"] == "fail" and by_name["telemetry"]["data"]["missing"] == ["flaws_cloud", "dedale"]
    assert by_name["gpu"]["status"] in ("ok", "warn")
    assert by_name["checkout"]["status"] == "skip"
    assert "residency" not in by_name and "ram" not in by_name
    assert set(report["failed"]) >= {"daemon", "manifest", "telemetry"}
