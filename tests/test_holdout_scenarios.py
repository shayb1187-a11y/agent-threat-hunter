"""Holdout-v1 injected-telemetry guards: the label-leak lint and k8s ingest/anchor.

These tests protect the two properties the holdout's validity rests on for the injected
Kubernetes quadrants: no injected record leaks its own label into a string the model can
read, and every injected record survives :class:`K8sAuditSource` ingest with each anchor
resolving to exactly one ingested row. They use a tiny fixture authored here, never
K8NTEXT or any previously-used corpus.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from ath.evaluation.external_labels import resolve_refs  # noqa: E402
from ath.evaluation.real_cases import load_source  # noqa: E402
from holdout_scenarios import (  # noqa: E402
    K8S_BENIGN_PAYLOAD,
    assert_no_leaks,
    expand_record,
    scenarios_from_payload,
)


def _fixture_scenario(record_overrides=None):
    """A minimal, self-contained k8s-benign scenario (not derived from any real corpus)."""
    record = {
        "dt": 0, "actor": "system:serviceaccount:demo:deployer",
        "groups": ["system:serviceaccounts", "system:authenticated"],
        "verb": "create", "resource": "rolebindings", "name": "demo-app-admin",
        "namespace": "demo",
        "subjects": [{"kind": "ServiceAccount", "name": "demo-app", "namespace": "demo"}],
        "role_ref": {"kind": "ClusterRole", "name": "admin"},
        "source_ip": "10.1.2.3", "user_agent": "helm/v3.14.4 (linux/amd64)", "code": 201,
    }
    if record_overrides:
        record.update(record_overrides)
    return {
        "quadrant": "k8s-benign",
        "scenarios": [{
            "id": "fixture-01", "label": "benign", "rationale": "fixture",
            "base_time": "2026-06-11T03:05:00Z", "anchor": 0, "records": [record],
        }],
    }


def test_leak_lint_catches_planted_token():
    """A planted label token in an injected record must fail the lint."""
    # An ordinary namespaced grant whose binding name carries a label word.
    leaky = expand_record("s", 0, "2026-06-11T03:05:00Z", {
        "dt": 0, "actor": "system:serviceaccount:demo:deployer", "verb": "create",
        "resource": "rolebindings", "namespace": "demo", "name": "sanctioned-deploy-edit",
        "subjects": [{"kind": "ServiceAccount", "name": "demo-app", "namespace": "demo"}],
        "role_ref": {"kind": "ClusterRole", "name": "edit"}, "code": 201,
    })
    with pytest.raises(ValueError, match="label-leak"):
        assert_no_leaks([leaky])


def test_leak_lint_passes_clean_benign_scenarios():
    """The real quadrant-4 benign scenarios must contain no leak tokens."""
    scenarios_from_payload(K8S_BENIGN_PAYLOAD, "k8s-benign")  # runs assert_no_leaks internally


@pytest.mark.parametrize("token,value", [
    ("malicious", "malicious-binding"),
    ("c2", "c2-channel"),
    ("backdoor", "backdoor-sa"),
    ("test", "test"),
])
def test_leak_lint_tokens(token, value):
    rec = {"auditID": "a", "objectRef": {"name": value}}
    with pytest.raises(ValueError):
        assert_no_leaks([rec])


def test_leak_lint_allows_real_background_test_names():
    """Reused CI names like e2e.test and test-lb-* must not false-trip the lint."""
    rec = {"auditID": "a", "userAgent": "e2e.test/v1.37.0",
           "objectRef": {"name": "test-lb-rolling-update-abcde"}}
    assert_no_leaks([rec])  # no raise


def test_injected_records_ingest_and_anchor_resolves_once(tmp_path):
    payload = _fixture_scenario()
    scenarios = scenarios_from_payload(payload, "k8s-benign")
    records = [r for s in scenarios for r in s["records"]]
    src = tmp_path / "raw"
    src.mkdir()
    (src / "events.jsonl").write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")

    telemetry, ingestion = load_source("k8s", src, cluster="holdout-test")
    assert ingestion["rows_kept"] == len(records)
    assert ingestion["rows_read"] == len(records)

    anchor_ref = f"auditID={scenarios[0]['anchor_id']}"
    resolved = resolve_refs([anchor_ref], telemetry)
    assert resolved[anchor_ref].status == "resolved"
    assert len(resolved[anchor_ref].event_ids) == 1


def test_exec_record_ingests_as_exec(tmp_path):
    payload = _fixture_scenario({
        "resource": "pods/exec", "name": "demo-app-0", "container": "app",
        "command": "/bin/sh", "code": 101, "subjects": None, "role_ref": None,
    })
    scenarios = scenarios_from_payload(payload, "k8s-benign")
    record = scenarios[0]["records"][0]
    src = tmp_path / "raw"
    src.mkdir()
    (src / "events.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
    telemetry, ingestion = load_source("k8s", src, cluster="holdout-test")
    assert ingestion["rows_kept"] == 1
    row = telemetry.controls.iloc[0]
    assert row["verb"] == "exec"
    assert row["resource_type"] == "pods/exec"
    assert row["decision"] == "allowed"  # 101 upgrade is allowed, not denied


def test_quadrant_label_mismatch_rejected():
    payload = _fixture_scenario()
    payload["scenarios"][0]["label"] = "malicious"
    with pytest.raises(ValueError, match="label must be"):
        scenarios_from_payload(payload, "k8s-benign")


def _fake_case(tmp_path, quadrant, n):
    src = tmp_path / f"{quadrant}-{n}"
    src.mkdir()
    (src / "x.jsonl").write_text("{}\n", encoding="utf-8")
    return {"_quadrant": quadrant, "_identity": "id", "_rationale": "r",
            "source": {"kind": "k8s" if quadrant.startswith("k8s") else "winlogbeat", "path": str(src)},
            "expected_decision": "malicious" if quadrant.endswith("malicious") else "benign",
            "provenance": "real+injected" if quadrant.startswith("k8s") else "emulated-testbed",
            "label_source": "ls", "anchor_refs": [f"ref={quadrant}-{n}"], "useful_refs": []}


def test_assemble_is_18_cases_with_roles_and_neutral_keys(tmp_path):
    from build_holdout_v1 import PROTOCOL, assemble

    cases = [_fake_case(tmp_path, q, n) for q in ("windows-malicious", "windows-benign", "k8s-benign")
             for n in range(6)]
    spec, manifest = assemble(cases)
    assert spec["protocol"] == PROTOCOL == "holdout-v1-windows"
    assert [c["key"] for c in spec["cases"]] == [f"h{i:02d}" for i in range(1, 19)]
    roles = {c["quadrant"]: c["holdout_role"] for c in spec["cases"]}
    assert roles == {"windows-malicious": "primary", "windows-benign": "primary", "k8s-benign": "secondary"}
    assert not any(c["expected_decision"] == "malicious" and c["platform"] == "k8s" for c in spec["cases"])
    assert "k8s_malicious_discrimination" in manifest["not_evaluated"]
    # the shuffle interleaves quadrants: keys do not group by quadrant
    first6 = {c["quadrant"] for c in spec["cases"][:6]}
    assert len(first6) > 1
    spec2, _ = assemble(cases, with_protocol=False)
    assert "protocol" not in spec2


def test_assemble_refuses_wrong_counts(tmp_path):
    from build_holdout_v1 import assemble

    cases = [_fake_case(tmp_path, "windows-benign", n) for n in range(6)]
    with pytest.raises(ValueError, match="quadrant counts"):
        assemble(cases)


def test_malicious_seed_skips_implant():
    from build_holdout_v1 import select_malicious_seed

    ordered = [("r1", "svcmon.exe"), ("r2", "SVCMON.EXE"), ("r3", "cmd.exe"), ("r4", "cmd.exe")]
    # cmd.exe is the most frequent image, but only the implant is skipped.
    assert select_malicious_seed(ordered) == ("r3", "non-implant", "non-implant")


def test_malicious_seed_falls_back_only_when_all_implant():
    from build_holdout_v1 import select_malicious_seed

    ordered = [("r1", "svcmon.exe"), ("r2", "svcmon.exe")]
    assert select_malicious_seed(ordered) == ("r1", "fallback-implant-only", "implant")


def test_implant_list_is_fixed_and_declared():
    from build_holdout_v1 import IMPLANT_IMAGES, SELECTION_RULES

    assert IMPLANT_IMAGES == ("svcmon.exe",)
    assert SELECTION_RULES["implant_list"]["images"] == ["svcmon.exe"]
    assert "labels" in SELECTION_RULES["implant_list"]["why"]


def _window_case(case_id, start, end, seed, coverage=None):
    import pandas as pd

    case = {"_id": case_id, "_seed_ts": pd.Timestamp(seed)}
    if start:
        case["window"] = {"start": start, "end": end}
    if coverage:
        case["_coverage"] = tuple(pd.Timestamp(t) for t in coverage)
    return case


def test_window_matching_copies_duration_and_offset():
    from build_holdout_v1 import match_windows

    mal = [_window_case("m", "2025-01-07T08:00:00Z", "2025-01-07T12:00:00Z", "2025-01-07T09:00:00Z")]
    ben = [_window_case("b", None, None, "2025-01-01T14:00:00Z",
                        ("2025-01-01T07:00:00Z", "2025-01-01T19:00:00Z"))]
    pairs = match_windows(mal, ben)
    assert ben[0]["window"] == {"start": "2025-01-01T13:00:00Z", "end": "2025-01-01T17:00:00Z"}
    assert pairs[0]["duration_hours"] == 4.0 and pairs[0]["partner_seed_offset_hours"] == 1.0 and pairs[0]["offset_shifted_hours"] == 0.0
    assert pairs[0]["clipped"] == [] and ben[0]["_paired_with"] == "m" and mal[0]["_paired_with"] == "b"


def test_window_shifts_forward_keeping_duration():
    from build_holdout_v1 import match_windows

    # Partner: 8 h window, seed 7 h in. Benign seed 1 h after the day's first record.
    mal = [_window_case("m", "2025-01-07T08:00:00Z", "2025-01-07T16:00:00Z", "2025-01-07T15:00:00Z")]
    ben = [_window_case("b", None, None, "2025-01-01T09:00:00Z",
                        ("2025-01-01T08:00:00Z", "2025-01-01T18:00:00Z"))]
    pairs = match_windows(mal, ben)
    assert ben[0]["window"] == {"start": "2025-01-01T08:00:00Z", "end": "2025-01-01T16:00:00Z"}
    assert ben[0]["_offset_shifted_hours"] == 6.0 and pairs[0]["clipped"] == []


def test_window_shifts_back_at_end_of_day():
    from build_holdout_v1 import match_windows

    # Partner: 4 h window, seed 0.5 h in. Benign seed 1 h before the day's last record.
    mal = [_window_case("m", "2025-01-07T08:00:00Z", "2025-01-07T12:00:00Z", "2025-01-07T08:30:00Z")]
    ben = [_window_case("b", None, None, "2025-01-01T17:00:00Z",
                        ("2025-01-01T08:00:00Z", "2025-01-01T18:00:00Z"))]
    match_windows(mal, ben)
    assert ben[0]["window"] == {"start": "2025-01-01T14:00:00Z", "end": "2025-01-01T18:00:00Z"}
    assert ben[0]["_offset_shifted_hours"] == -2.5 and ben[0]["_clipped"] == []


def test_window_clips_end_only_when_day_is_shorter_than_duration():
    from build_holdout_v1 import match_windows

    mal = [_window_case("m", "2025-01-07T08:00:00Z", "2025-01-07T16:00:00Z", "2025-01-07T10:00:00Z")]
    ben = [_window_case("b", None, None, "2025-01-01T08:30:00Z",
                        ("2025-01-01T08:00:00Z", "2025-01-01T12:00:00Z"))]
    pairs = match_windows(mal, ben)
    assert ben[0]["window"] == {"start": "2025-01-01T08:00:00Z", "end": "2025-01-01T12:00:00Z"}
    assert pairs[0]["clipped"] == ["end"]
