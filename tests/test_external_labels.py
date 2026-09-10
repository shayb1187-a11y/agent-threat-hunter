"""External labels resolve through ``source_ref``, never through ``event_id``.

The property under test is stability: the same label file must name the same records
whatever order the adapter minted ids in, and a label the adapter could not ingest must
show up as a count, not vanish from the denominator.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from ath.evaluation.external_labels import (
    incident_from_labels,
    load_external_labels,
    resolve_labels,
)
from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS
from ath.telemetry.cloudtrail_source import CloudTrailSource
from ath.telemetry.loader import Telemetry

FIXTURE = Path(__file__).parent / "fixtures" / "cloudtrail"


@pytest.fixture(scope="module")
def telemetry() -> Telemetry:
    result = CloudTrailSource(FIXTURE).load()
    return Telemetry(
        processes=result.tables[EVENT_PROCESS], network=result.tables[EVENT_NETWORK],
        logons=result.tables[EVENT_LOGON], controls=result.tables[EVENT_CONTROL],
    )


def _write_labels(path: Path, refs: list[str], *, malicious: bool = True,
                  provenance: str = "synthetic", extra: dict | None = None) -> Path:
    payload = {
        "dataset": "cloudtrail-fixture",
        "provenance": provenance,
        "scenarios": {
            "stuffing": {
                "malicious": malicious,
                "stages": {"1-burst": {"note": "failed logins", "refs": refs}},
            },
            **(extra or {}),
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _attacker_refs(telemetry: Telemetry) -> list[str]:
    rows = telemetry.logons[telemetry.logons["source_ip"] == "203.0.113.42"]
    return [ref.split(";")[0] for ref in rows["source_ref"]]  # the eventID=... pair only


def test_refs_resolve_to_the_rows_that_carry_them(tmp_path, telemetry) -> None:
    refs = _attacker_refs(telemetry)
    labels = load_external_labels(_write_labels(tmp_path / "l.json", refs))
    resolved = resolve_labels(labels, telemetry)
    expected = set(telemetry.logons.loc[
        telemetry.logons["source_ip"] == "203.0.113.42", "event_id"
    ])
    assert set(resolved.malicious_event_ids) == expected
    assert resolved.resolved_refs == len(refs)
    assert resolved.malicious_refs_unresolved == 0


def test_resolution_survives_a_different_id_assignment(tmp_path, telemetry) -> None:
    """Re-mint every event_id in reverse; the labels must land on the same records."""
    refs = _attacker_refs(telemetry)
    labels = load_external_labels(_write_labels(tmp_path / "l.json", refs))
    original = resolve_labels(labels, telemetry)
    original_refs = set(telemetry.logons.loc[
        telemetry.logons["event_id"].isin(original.malicious_event_ids), "source_ref"
    ])

    reminted = telemetry.logons.copy()
    reminted["event_id"] = [f"renumbered-{i:04d}" for i in range(len(reminted), 0, -1)]
    shuffled = Telemetry(
        processes=telemetry.processes, network=telemetry.network,
        logons=reminted, controls=telemetry.controls,
    )
    again = resolve_labels(labels, shuffled)
    again_refs = set(reminted.loc[
        reminted["event_id"].isin(again.malicious_event_ids), "source_ref"
    ])
    assert again_refs == original_refs
    assert not (again.malicious_event_ids & original.malicious_event_ids)


def test_labels_the_adapter_never_ingested_are_counted_not_lost(tmp_path, telemetry) -> None:
    """A labelled record that was dropped at ingestion is the attack ATH cannot see."""
    refs = _attacker_refs(telemetry) + ["eventID=never-ingested-0001"]
    labels = load_external_labels(_write_labels(tmp_path / "l.json", refs))
    resolved = resolve_labels(labels, telemetry)
    assert resolved.unresolved["stuffing"] == ("eventID=never-ingested-0001",)
    assert resolved.malicious_refs_total == len(refs)
    assert resolved.malicious_refs_unresolved == 1
    # And the incident built from it only claims what was actually resolved.
    incident = incident_from_labels(
        resolved, telemetry, incident_id="X", name="x", description="x",
    )
    assert len(incident.malicious_event_ids) == len(refs) - 1


def test_ambiguous_refs_are_excluded_not_expanded(tmp_path, telemetry) -> None:
    logons = telemetry.logons.copy()
    logons["source_ref"] = "eventID=dup;File=f.json"  # every row now claims the same id
    dup = Telemetry(processes=telemetry.processes, network=telemetry.network,
                    logons=logons, controls=telemetry.controls)
    labels = load_external_labels(_write_labels(tmp_path / "l.json", ["eventID=dup"]))
    resolved = resolve_labels(labels, dup)
    assert resolved.ambiguous["stuffing"] == ("eventID=dup",)
    assert resolved.malicious_event_ids == frozenset()


def test_multi_pair_refs_require_every_pair(tmp_path, telemetry) -> None:
    row = telemetry.logons.iloc[0]
    event_id_pair, file_pair = row["source_ref"].split(";")[:2]
    labels = load_external_labels(_write_labels(
        tmp_path / "l.json", [f"{event_id_pair};{file_pair}", f"{event_id_pair};File=other.json"],
    ))
    resolved = resolve_labels(labels, telemetry)
    assert resolved.event_ids_by_scenario["stuffing"] == frozenset({row["event_id"]})
    assert resolved.unresolved["stuffing"] == (f"{event_id_pair};File=other.json",)


def test_benign_scenarios_never_enter_the_malicious_set(tmp_path, telemetry) -> None:
    refs = _attacker_refs(telemetry)
    benign_ref = telemetry.logons.loc[
        telemetry.logons["source_ip"] != "203.0.113.42", "source_ref"
    ].iloc[0].split(";")[0]
    labels = load_external_labels(_write_labels(
        tmp_path / "l.json", refs,
        extra={"owner-admin": {"malicious": False, "stages": {"s": {"refs": [benign_ref]}}}},
    ))
    resolved = resolve_labels(labels, telemetry)
    assert resolved.event_ids_by_scenario["owner-admin"]
    assert not (resolved.event_ids_by_scenario["owner-admin"] & resolved.malicious_event_ids)


def test_a_label_file_must_say_whether_each_scenario_is_malicious(tmp_path) -> None:
    path = tmp_path / "l.json"
    path.write_text(json.dumps({
        "provenance": "real", "scenarios": {"x": {"stages": {"s": {"refs": ["eventID=a"]}}}},
    }))
    with pytest.raises(ValueError, match="malicious"):
        load_external_labels(path)


def test_a_label_file_must_declare_its_provenance(tmp_path) -> None:
    path = tmp_path / "l.json"
    path.write_text(json.dumps({"scenarios": {}}))
    with pytest.raises(ValueError, match="provenance"):
        load_external_labels(path)


def test_no_module_outside_evaluation_imports_the_label_reader() -> None:
    """Labels are the answer key; adapters and detections must not be able to see it."""
    import re

    src = Path(__file__).parent.parent / "src" / "ath"
    offenders = []
    # An *import* is what would let a module read labels; a docstring that names the
    # module (the Winlogbeat adapter explains why its source_ref is shaped for it) is not.
    pattern = re.compile(r"^\s*(from\s+ath\.evaluation\.external_labels\s+import|import\s+ath\.evaluation\.external_labels)", re.M)
    for path in src.rglob("*.py"):
        if "evaluation" in path.parts:
            continue
        if pattern.search(path.read_text(encoding="utf-8")):
            offenders.append(str(path.relative_to(src)))
    assert offenders == []
