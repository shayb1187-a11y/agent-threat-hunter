"""Real apiserver audit logs are one Event per line, not an EventList.

Both public Kubernetes sources examined for Milestone 14 (the Kubernetes CI
``kube-apiserver-audit.log`` and K8NTEXT) are NDJSON, and the adapter refused both. The
counts must be identical whichever shape the same events arrive in, the K8NTEXT label
keys must be ignored rather than read, and one bad line must cost one line.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ath.schema import EVENT_CONTROL
from ath.telemetry.k8s_audit_source import K8sAuditSource

FIXTURE = Path(__file__).parent / "fixtures" / "k8s_audit"
FIXTURE_FILE = FIXTURE / "k8s-audit-2026-08-17.json"


@pytest.fixture(scope="module")
def event_list():
    return K8sAuditSource(FIXTURE, cluster="c").load()


def _items() -> list[dict]:
    return json.loads(FIXTURE_FILE.read_text(encoding="utf-8"))["items"]


def _write_ndjson(path: Path, items: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(i) for i in items) + "\n", encoding="utf-8")


def test_ndjson_log_reads_identically_to_the_event_list(tmp_path, event_list) -> None:
    _write_ndjson(tmp_path / "kube-apiserver-audit.log", _items())
    result = K8sAuditSource(tmp_path, cluster="c").load()
    assert result.rows_read == event_list.rows_read
    assert result.rows_kept == event_list.rows_kept
    assert result.rows_dropped == event_list.rows_dropped
    lhs = event_list.tables[EVENT_CONTROL].drop(columns=["source_ref"])
    rhs = result.tables[EVENT_CONTROL].drop(columns=["source_ref"])
    assert lhs.reset_index(drop=True).equals(rhs.reset_index(drop=True))


def test_jsonl_extension_is_accepted(tmp_path, event_list) -> None:
    _write_ndjson(tmp_path / "audit.jsonl", _items())
    assert K8sAuditSource(tmp_path, cluster="c").load().rows_kept == event_list.rows_kept


def test_dataset_label_keys_are_ignored_not_read(tmp_path, event_list) -> None:
    """K8NTEXT ships ``label``/``cplabel`` on every event; the adapter must not care."""
    items = [{**i, "label": 7, "cplabel": 3} for i in _items()]
    _write_ndjson(tmp_path / "audit-log-dataset.log", items)
    result = K8sAuditSource(tmp_path, cluster="c").load()
    assert result.rows_kept == event_list.rows_kept
    assert "label" not in result.tables[EVENT_CONTROL].columns


def test_one_corrupt_line_costs_one_line(tmp_path, event_list) -> None:
    items = _items()
    lines = [json.dumps(i) for i in items]
    lines.insert(3, "{this is not json")
    (tmp_path / "audit.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = K8sAuditSource(tmp_path, cluster="c").load()
    assert result.rows_kept == event_list.rows_kept
    bad = [i for i in result.issues if "line is not valid JSON" in i.reason]
    assert len(bad) == 1
    assert bad[0].raw_reference == "audit.log#line=4"


def test_a_file_that_is_nothing_parseable_is_one_issue(tmp_path) -> None:
    (tmp_path / "audit.log").write_text("garbage\nmore garbage\n", encoding="utf-8")
    (tmp_path / "good.json").write_text(FIXTURE_FILE.read_text(encoding="utf-8"))
    result = K8sAuditSource(tmp_path, cluster="c").load()
    file_issues = [i for i in result.issues if i.raw_reference == "audit.log"]
    assert len(file_issues) == 1
    assert result.rows_kept > 0


def test_metadata_level_rbac_create_maps_with_an_empty_role(tmp_path) -> None:
    """A ``Metadata``-level policy logs the binding create without its body.

    The row is still a real RBAC create and is kept; ``role_ref`` and ``target_actor``
    are empty because the log genuinely does not say. That is the documented reason
    K8S-001 is blind on such policies -- a coverage fact the visibility model should
    carry, not something the adapter should invent.
    """
    item = {
        "kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "Metadata",
        "auditID": "m-1", "stage": "ResponseComplete", "verb": "create",
        "user": {"username": "admin"}, "sourceIPs": ["10.0.0.1"],
        "objectRef": {"resource": "clusterrolebindings", "name": "b"},
        "responseStatus": {"code": 201}, "stageTimestamp": "2026-06-11T13:00:00Z",
    }
    _write_ndjson(tmp_path / "audit.log", [item])
    result = K8sAuditSource(tmp_path, cluster="c").load()
    row = result.tables[EVENT_CONTROL].iloc[0]
    assert row["resource_type"] == "clusterrolebindings"
    assert row["role_ref"] == ""
    assert row["target_actor"] == ""
