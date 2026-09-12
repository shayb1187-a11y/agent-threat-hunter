"""The adapter boundary admits only files it can positively recognise as its telemetry.

Why these tests exist
----------------------
Measured on COMISET (``reports/m17/H4_FROZEN.json``), the slice directory's own
statistics sidecar -- ``*.json``, sitting beside the slice, describing it -- was listed as
telemetry by ``ElasticWinEventSource`` and 513 of its lines were counted as records and
rejected one at a time. Nothing was *wrong* in the resulting table, by luck: had those
lines carried ``event_id`` and a timestamp, they would have been ingested as events with
no trace that they were never telemetry. The same directory-listing pattern existed in all
four JSON-shaped adapters.

What is asserted here, once, against all four
----------------------------------------------
Each case below uses its own directory, file names, hosts, users and accounts, because a
test that shared a fixture across adapters would only prove the fixture. For every one:

* a sidecar whose lines are valid JSON of the wrong shape is REJECTED, with a reason and
  the count of records it therefore never contributed;
* the denominator stays honest -- ``rows_read`` equals the telemetry file's record count,
  not the directory's line count;
* no ``NormalizationIssue`` originates from a rejected file;
* canonical rows come only from the admitted file, traceable by ``source_ref``.

And, crucially, that admission and normalisation are **two layers**: a file whose records
carry the identifying keys with nonsense values is admitted (shape is not truth) and then
refused record by record, with one issue each.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import pytest

from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_PROCESS
from ath.telemetry.admission import REASON_EMPTY, REASON_WRONG_SHAPE
from ath.telemetry.cloudtrail_source import CloudTrailSource
from ath.telemetry.elastic_winevent_source import ElasticWinEventSource
from ath.telemetry.k8s_audit_source import K8sAuditSource
from ath.telemetry.source import SourceLoadResult, TelemetrySource
from ath.telemetry.winlogbeat_source import WinlogbeatSource

VALID_RECORDS = 10

# --------------------------------------------------------------------------------------
# One case per JSON-shaped adapter. Deliberately different in every incidental detail.
# --------------------------------------------------------------------------------------


@dataclass
class Case:
    """How to build one adapter's directory, and what its telemetry looks like."""

    kind: str
    directory_name: str
    telemetry_file: str
    sidecar_file: str
    table: str
    build: Callable[[Path, str], TelemetrySource]
    write_valid: Callable[[Path, int], None]
    write_sidecar: Callable[[Path], int]
    write_adversarial: Callable[[Path], None]
    write_mixed: Callable[[Path, int, int], None]
    write_empty_shape: Callable[[Path], None] | None = None
    empty_reason: str = ""
    mixed_rows_read: int = 20
    """``rows_read`` for the 18-good/2-garbage file.

    Not uniform, and deliberately not made uniform here: the two adapters that parse
    line by line (Elastic winevent, Kubernetes audit) have always counted a record as
    "read" only once it parsed, so an unparseable line raises an issue without raising
    ``rows_read``. That predates this boundary and is a separate accounting question --
    what matters for admission is that all 20 lines are attributed to the *admitted*
    file and none to a refused one.
    """


# -- Elastic / HELK winevent ----------------------------------------------------------


def _elastic_record(index: int) -> dict[str, Any]:
    return {
        "_channel": "sysmon",
        "event_id": "1",
        "_doc_id": f"elastic-{index:04d}",
        "event_original_time": f"2026-08-01T10:{index:02d}:11.000Z",
        "host_name": "WKS-HELK.phoenix.local",
        "user_name": "emma.lang",
        "process_name": "powershell.exe",
        "process_id": 5100 + index,
        "CommandLine": "powershell.exe -NoProfile",
        "process_parent_name": "explorer.exe",
        "process_parent_id": 900,
        "process_path": "c:\\windows\\system32\\powershell.exe",
    }


def _write_ndjson(path: Path, objects: list[Any]) -> None:
    path.write_text(
        "\n".join(o if isinstance(o, str) else json.dumps(o) for o in objects) + "\n",
        encoding="utf-8",
    )


ELASTIC = Case(
    kind="elastic_winevent",
    directory_name="helk_slice",
    telemetry_file="winevent-slice.jsonl",
    sidecar_file="slice_seen_stats.json",
    table=EVENT_PROCESS,
    build=lambda directory, _: ElasticWinEventSource(directory),
    write_valid=lambda path, n: _write_ndjson(path, [_elastic_record(i) for i in range(n)]),
    # Valid JSON, wrong shape: what a slicing pipeline writes *about* a slice.
    write_sidecar=lambda path: (
        _write_ndjson(path, [{"files": 3, "records": 20000000}, {"files": 4, "records": 5}]),
        2,
    )[1],
    write_adversarial=lambda path: _write_ndjson(path, [
        {"_channel": "sysmon", "event_id": "1", "event_original_time": "not-a-time",
         "host_name": "WKS-HELK", "process_name": "x.exe"},
        {"_channel": "sysmon", "event_id": "1", "event_original_time": "also-not-a-time",
         "host_name": "WKS-HELK", "process_name": "y.exe"},
    ]),
    write_mixed=lambda path, good, bad: _write_ndjson(
        path,
        [_elastic_record(i) for i in range(good)] + ["{ not json at all" for _ in range(bad)],
    ),
    empty_reason=REASON_EMPTY,
    mixed_rows_read=18,
)


# -- Winlogbeat ECS -------------------------------------------------------------------


def _winlogbeat_record(index: int) -> dict[str, Any]:
    return {
        "@timestamp": f"2026-08-02T14:{index:02d}:09.771Z",
        "winlog": {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": 1,
            "record_id": 77000 + index,
        },
        "host": {"name": "CLIENT9.breach.local"},
        "user": {"name": "frank.oduya"},
        "process": {
            "name": "cmd.exe",
            "pid": 3300 + index,
            "command_line": "cmd.exe /c whoami",
            "executable": "C:\\Windows\\System32\\cmd.exe",
            "parent": {"name": "explorer.exe", "pid": 1200},
        },
    }


WINLOGBEAT = Case(
    kind="winlogbeat",
    directory_name="dedale_hour",
    telemetry_file="winlogbeat-2026-08-02.ndjson",
    sidecar_file="winlogbeat_zip_index.json",
    table=EVENT_PROCESS,
    build=lambda directory, _: WinlogbeatSource(directory),
    write_valid=lambda path, n: _write_ndjson(path, [_winlogbeat_record(i) for i in range(n)]),
    write_sidecar=lambda path: (
        _write_ndjson(path, [
            {"member": "wlb-01.jsonl.bz2", "bytes": 44_100_200},
            {"member": "wlb-02.jsonl.bz2", "bytes": 41_000_000},
            {"member": "wlb-03.jsonl.bz2", "bytes": 39_500_000},
        ]),
        3,
    )[1],
    write_adversarial=lambda path: _write_ndjson(path, [
        {"@timestamp": "whenever", "winlog": {
            "channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 1}},
        {"@timestamp": "sometime", "winlog": {
            "channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 1}},
    ]),
    write_mixed=lambda path, good, bad: _write_ndjson(
        path,
        [_winlogbeat_record(i) for i in range(good)] + ["<<truncated" for _ in range(bad)],
    ),
    empty_reason=REASON_EMPTY,
)


# -- Kubernetes apiserver audit -------------------------------------------------------


def _k8s_event(index: int) -> dict[str, Any]:
    return {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "level": "RequestResponse",
        "auditID": f"prod-eu-{index:04d}",
        "stage": "ResponseComplete",
        "verb": "create",
        "user": {"username": "release-bot", "groups": ["system:authenticated"]},
        "sourceIPs": ["10.44.0.9"],
        "objectRef": {"resource": "rolebindings", "namespace": "payments",
                      "name": f"grant-{index}"},
        "requestObject": {
            "subjects": [{"kind": "ServiceAccount", "name": "deployer",
                          "namespace": "payments"}],
            "roleRef": {"kind": "ClusterRole", "name": "edit"},
        },
        "responseStatus": {"code": 201},
        "stageTimestamp": f"2026-08-03T07:{index:02d}:44.100000Z",
    }


K8S = Case(
    kind="k8s",
    directory_name="prod_eu_audit",
    telemetry_file="kube-apiserver-audit.log",
    sidecar_file="probe_verb_histogram.json",
    table=EVENT_CONTROL,
    build=lambda directory, cluster: K8sAuditSource(directory, cluster=cluster),
    write_valid=lambda path, n: _write_ndjson(path, [_k8s_event(i) for i in range(n)]),
    write_sidecar=lambda path: (
        _write_ndjson(path, [
            {"verb": "get", "count": 1_200_400},
            {"verb": "list", "count": 88_000},
        ]),
        2,
    )[1],
    write_adversarial=lambda path: _write_ndjson(path, [
        {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "stage": "ResponseComplete",
         "verb": "flibble", "objectRef": {"resource": "widgets"},
         "user": {"username": "nobody"}, "stageTimestamp": "2026-08-03T07:00:00Z"},
        {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "stage": "ResponseComplete",
         "verb": "flibble", "objectRef": {"resource": "gadgets"},
         "user": {"username": "nobody"}, "stageTimestamp": "2026-08-03T07:00:01Z"},
    ]),
    write_mixed=lambda path, good, bad: _write_ndjson(
        path, [_k8s_event(i) for i in range(good)] + ["}{" for _ in range(bad)],
    ),
    write_empty_shape=lambda path: path.write_text(
        json.dumps({"kind": "EventList", "apiVersion": "audit.k8s.io/v1", "items": []}),
        encoding="utf-8",
    ),
    empty_reason=REASON_EMPTY,
    mixed_rows_read=18,
)


# -- AWS CloudTrail --------------------------------------------------------------------


def _cloudtrail_record(index: int) -> dict[str, Any]:
    return {
        "eventVersion": "1.08",
        "eventID": f"ct-{index:04d}",
        "eventTime": f"2026-08-04T16:{index:02d}:30Z",
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "awsRegion": "eu-west-1",
        "recipientAccountId": "909090909090",
        "sourceIPAddress": "203.0.113.44",
        "userIdentity": {"type": "IAMUser", "userName": "gita.rao",
                         "accountId": "909090909090"},
        "responseElements": {"ConsoleLogin": "Success"},
    }


CLOUDTRAIL = Case(
    kind="cloudtrail",
    directory_name="trail_eu_west_1",
    telemetry_file="CloudTrail_eu-west-1_2026-08-04.json",
    sidecar_file="trail_ingest_stats.json",
    table=EVENT_LOGON,
    build=lambda directory, _: CloudTrailSource(directory),
    write_valid=lambda path, n: path.write_text(
        json.dumps({"Records": [_cloudtrail_record(i) for i in range(n)]}), encoding="utf-8",
    ),
    # Two JSON objects, one per line: a shape this adapter accepts, carrying records that
    # are not CloudTrail.
    write_sidecar=lambda path: (
        _write_ndjson(path, [
            {"files": 3, "records": 20_000_000},
            {"files": 4, "records": 21_000_000},
        ]),
        2,
    )[1],
    write_adversarial=lambda path: path.write_text(
        json.dumps({"Records": [
            {"eventVersion": "1.08", "eventName": "ConsoleLogin", "eventTime": "not-a-time",
             "userIdentity": {"userName": "ghost"}},
            {"eventVersion": "1.08", "eventName": "ConsoleLogin", "eventTime": "nor-this",
             "userIdentity": {"userName": "ghost"}},
        ]}),
        encoding="utf-8",
    ),
    write_mixed=lambda path, good, bad: path.write_text(
        json.dumps({"Records": [_cloudtrail_record(i) for i in range(good)]
                    + ["not even an object" for _ in range(bad)]}),
        encoding="utf-8",
    ),
    write_empty_shape=lambda path: path.write_text(
        json.dumps({"Records": []}), encoding="utf-8",
    ),
)


CASES = [ELASTIC, WINLOGBEAT, K8S, CLOUDTRAIL]
ENVELOPE_CASES = [c for c in CASES if c.write_empty_shape is not None]
LINE_CASES = [c for c in CASES if c.empty_reason]


def _load(case: Case, tmp_path: Path) -> tuple[Case, Path]:
    """A fresh directory per case, so no case can see another's files."""
    directory = tmp_path / case.directory_name
    directory.mkdir()
    return case, directory


def _run(case: Case, directory: Path) -> SourceLoadResult:
    return case.build(directory, "prod-eu").load()


def _ids(cases: list[Case]) -> list[str]:
    return [c.kind for c in cases]


# --------------------------------------------------------------------------------------
# The boundary
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("case", CASES, ids=_ids(CASES))
def test_a_sidecar_beside_the_export_is_refused_and_costs_nothing(case, tmp_path) -> None:
    """How this fails: revert admission and the sidecar's lines land in ``rows_read``
    (and in the issue list) as telemetry this adapter could not normalise."""
    case, directory = _load(case, tmp_path)
    case.write_valid(directory / case.telemetry_file, VALID_RECORDS)
    sidecar_records = case.write_sidecar(directory / case.sidecar_file)

    result = _run(case, directory)

    refused = [a for a in result.rejected_files if a.path == case.sidecar_file]
    assert len(refused) == 1, f"sidecar was not refused: {result.admitted_files}"
    assert REASON_WRONG_SHAPE in refused[0].reason
    assert refused[0].line_or_record_count == sidecar_records

    admitted = [a for a in result.admitted_files if a.admitted]
    assert [a.path for a in admitted] == [case.telemetry_file]

    # The denominator is the telemetry file's records, not the directory's lines.
    assert result.rows_read == VALID_RECORDS
    assert len(result.tables[case.table]) == VALID_RECORDS

    # Nothing the boundary refused may appear as a normalisation failure...
    assert not [i for i in result.issues if case.sidecar_file in i.raw_reference]
    # ...nor as a canonical row.
    for table in result.tables.values():
        refs = table["source_ref"].astype(str)
        assert not refs.str.contains(case.sidecar_file, regex=False).any()
        if len(table):
            assert refs.str.contains(case.telemetry_file, regex=False).all()


@pytest.mark.parametrize("case", CASES, ids=_ids(CASES))
def test_right_keys_and_nonsense_values_are_admitted_then_refused_per_record(
    case, tmp_path
) -> None:
    """File admission judges shape; record normalisation judges values. Two layers.

    How this fails: fold the value checks into the predicate and this file is refused
    whole, turning two unusable records into one silent missing file -- and, worse, making
    every partially-corrupt real export disappear at the boundary.
    """
    case, directory = _load(case, tmp_path)
    case.write_adversarial(directory / case.telemetry_file)

    result = _run(case, directory)

    assert [a.path for a in result.admitted_files if a.admitted] == [case.telemetry_file]
    assert result.rows_read == 2
    assert len(result.tables[case.table]) == 0
    # Refused one record at a time, each with its own reason -- not as a file.
    assert len(result.issues) == 2
    assert all(case.telemetry_file in i.raw_reference for i in result.issues)


@pytest.mark.parametrize("case", ENVELOPE_CASES, ids=_ids(ENVELOPE_CASES))
def test_a_correctly_shaped_file_with_no_records_is_admitted(case, tmp_path) -> None:
    """``{"Records": []}`` is a real export that happens to be empty.

    How this fails: make admission require a matching record and an honest empty hour of
    a trail becomes "not CloudTrail", which is a false statement about the export.
    """
    case, directory = _load(case, tmp_path)
    case.write_empty_shape(directory / case.telemetry_file)

    result = _run(case, directory)

    assert [a.path for a in result.admitted_files if a.admitted] == [case.telemetry_file]
    assert result.rows_read == 0
    assert result.rows_kept == 0
    assert result.issues == []


@pytest.mark.parametrize("case", LINE_CASES, ids=_ids(LINE_CASES))
def test_a_file_with_no_lines_at_all_is_refused_as_empty(case, tmp_path) -> None:
    """How this fails: without the empty branch a zero-byte placeholder reports as an
    admitted file, i.e. as telemetry that genuinely contained nothing."""
    case, directory = _load(case, tmp_path)
    (directory / case.telemetry_file).write_text("", encoding="utf-8")
    case.write_valid(directory / f"real-{case.telemetry_file}", VALID_RECORDS)

    result = _run(case, directory)

    refused = [a for a in result.rejected_files if a.path == case.telemetry_file]
    assert len(refused) == 1
    assert refused[0].reason == case.empty_reason
    assert result.rows_read == VALID_RECORDS


@pytest.mark.parametrize("case", CASES, ids=_ids(CASES))
def test_a_mostly_valid_file_is_admitted_and_its_garbage_refused_per_record(
    case, tmp_path
) -> None:
    """90% telemetry and 10% garbage is a truncated export, not somebody else's file.

    How this fails: admit on *all* of the first K records instead of any, and one corrupt
    line early in a real export costs the whole file.
    """
    case, directory = _load(case, tmp_path)
    case.write_mixed(directory / case.telemetry_file, 18, 2)

    result = _run(case, directory)

    assert [a.path for a in result.admitted_files if a.admitted] == [case.telemetry_file]
    assert len(result.tables[case.table]) == 18
    assert len(result.issues) == 2
    assert result.rows_read == case.mixed_rows_read


@pytest.mark.parametrize("case", CASES, ids=_ids(CASES))
def test_the_summary_says_what_was_refused(case, tmp_path) -> None:
    """How this fails: leave ``summary()`` alone and the CLI prints a small clean import
    where half the directory was silently skipped."""
    case, directory = _load(case, tmp_path)
    case.write_valid(directory / case.telemetry_file, VALID_RECORDS)
    case.write_sidecar(directory / case.sidecar_file)

    text = _run(case, directory).summary()

    assert "1 file(s) admitted" in text
    assert "1 rejected" in text
    assert "never read" in text


# --------------------------------------------------------------------------------------
# No dataset names, no file names: the boundary recognises a shape
# --------------------------------------------------------------------------------------


def test_admission_never_names_a_file_or_a_dataset() -> None:
    """An anti-overfitting guard, because the temptation is a one-line denylist.

    How this fails: add ``if name == "comiset_seen.json"`` anywhere under ``src/`` and
    this test names the file that did it.
    """
    root = Path(__file__).resolve().parent.parent / "src"
    banned = ("comiset_seen", "comiset_slice", "probe_histogram", "flaws_cloudtrail",
              "kube-apiserver-audit", "dedale_winlogbeat")
    offenders = [
        f"{path.name}: {token}"
        for path in root.rglob("*.py")
        for token in banned
        if token in path.read_text(encoding="utf-8")
    ]
    assert not offenders
