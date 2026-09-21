"""M20 tooling: the refusals that make the corpus's claims checkable.

What is being protected
------------------------
M20's value is not the data. It is four claims about how the data was produced -- the
schedule was written first, the log of what happened is append-only, the holdout was
never looked at, and nothing was tuned on it. Each claim is protected by a refusal
somewhere in ``scripts/m20``, and a refusal that is never exercised is a comment. These
tests exercise them.

How each test fails
--------------------
*Schedule.* ``plan_covers_every_schedule_row`` re-derives the plan's own 14-row table
from the text quoted in ``sessions.py`` and checks the generated sessions against it. It
fails if a workflow the plan places on a day stops being scheduled on that day -- the
failure mode where a corpus is collected for two weeks and is quietly missing a workflow.

*Append-only.* The record tests fail if the planned columns ever become writable, if an
unknown session id is accepted (which would mean an unplanned session could enter the
log as if it had been declared), or if ``notes`` starts replacing rather than appending.

*Sealing.* ``holdout_file_is_hashed_without_being_opened`` puts a file with a valid
CloudTrail *name* and deliberately invalid gzip *content* into the holdout side. Any code
path that opened holdout content -- a gzip read, a JSON parse, a row count -- raises on
it. The test passes only while nothing does, which is the invariant stated as a test
rather than as a promise. The boundary tests fail if the day-9/day-10 edge ever moves,
and ``second_run_is_refused`` fails if a re-split could silently reclassify late
deliveries.

*No tuning.* The last two fail if either measurement script could be pointed at the
holdout -- the validator at all, the measurer before a complete pre-registration exists.
``PREREGISTERED.md`` still holding the template's ``__`` counts as incomplete, because a
template committed with its blanks in it would let the predictions be written after the
numbers were known.

Nothing here touches ``data/external`` or the repo's ``reports/``: every test writes
under ``tmp_path``.
"""

from __future__ import annotations

import csv
import gzip
import json
import sys
from datetime import datetime
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

from m20 import provenance as provenance_mod  # noqa: E402
from m20 import sessions as sessions_mod  # noqa: E402
from m20 import split as split_mod  # noqa: E402
from m20.common import holdout_gate, principal_names, refuse_holdout, unfilled_blanks  # noqa: E402

START = "2026-10-01"
PAST_START = "2026-08-01"
WORKFLOWS_DIR = SCRIPTS / "m20" / "workflows"


def _plan(tmp_path: Path, account_id: str = "012345678901") -> Path:
    path = tmp_path / "sessions.csv"
    sessions_mod.write_plan(path, sessions_mod.parse_start_date(START), account_id)
    return path


def _rows(path: Path) -> list:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


# --------------------------------------------------------------------------------------
# 1. The schedule is the plan's schedule
# --------------------------------------------------------------------------------------


def test_plan_covers_every_schedule_row(tmp_path) -> None:
    """Every workflow the plan's day table names has a session on that day.

    The check runs against ``SCHEDULE_TABLE``, which quotes the plan verbatim, so this
    fails if the generated schedule and the document it claims to implement diverge --
    in either direction.
    """
    rows = _rows(_plan(tmp_path))
    by_day = {}
    for row in rows:
        by_day.setdefault(int(row["day"]), set()).add(row["workflow_id"])

    for day, text in sessions_mod.SCHEDULE_TABLE:
        named = {w for w in sessions_mod.WORKFLOWS if w != "SETUP" and w in text}
        assert named <= by_day[day], (
            f"day {day} of the plan names {sorted(named)}; generated {sorted(by_day[day])}"
        )
    assert set(by_day) == {day for day, _ in sessions_mod.SCHEDULE_TABLE}


def test_every_catalogued_workflow_is_scheduled_the_declared_number_of_times(tmp_path) -> None:
    """Session counts match the catalogue's own "N sessions" declarations.

    W04 "3 sessions over 14 days", W05 "2 sessions", W06 "4 sessions", W07 "5 sessions",
    W08 "4 runs". These are the counts the corpus's volume estimate rests on; a schedule
    that generated three W07 sessions would silently be a different experiment.
    """
    counts = {}
    for row in _rows(_plan(tmp_path)):
        counts[row["workflow_id"]] = counts.get(row["workflow_id"], 0) + 1
    assert counts["W04"] == 3
    assert counts["W05"] == 2
    assert counts["W06"] == 4
    assert counts["W07"] == 5
    assert counts["W08"] == 4
    assert counts["W12"] == 1      # "one session, day 8"
    assert counts["W13"] == 1      # "day 6"
    assert counts["W09"] == 13     # daily from day 2
    assert counts["W10"] == 6      # daily from day 9
    assert set(counts) == set(sessions_mod.WORKFLOWS)


def test_plan_is_deterministic(tmp_path) -> None:
    """Same start date, same file -- byte for byte, ids included.

    Session ids are quoted in the workflow invocations and in the operator checklist, so
    a plan that renumbered on regeneration would break every reference at once.
    """
    first = (tmp_path / "a" / "sessions.csv")
    second = (tmp_path / "b" / "sessions.csv")
    sessions_mod.write_plan(first, sessions_mod.parse_start_date(START), "012345678901")
    sessions_mod.write_plan(second, sessions_mod.parse_start_date(START), "012345678901")
    assert first.read_bytes() == second.read_bytes()


def test_no_actor_has_two_overlapping_planned_windows(tmp_path) -> None:
    """The property row-to-session attribution depends on.

    If one actor had two overlapping windows, a telemetry row could belong to both and
    ``validate_dev.py``'s coverage number would stop being well defined.
    """
    planned = sessions_mod.planned_sessions(sessions_mod.parse_start_date(START))
    sessions_mod.verify_no_actor_overlap(planned)  # raises SystemExit if violated


def test_replanning_over_an_existing_file_is_refused(tmp_path) -> None:
    """INV-2: the predeclaration is written once.

    Regenerating over a file that already carries recorded actual times would erase the
    record and let the plan be rewritten after the fact.
    """
    path = _plan(tmp_path)
    with pytest.raises(SystemExit, match="already exists"):
        sessions_mod.write_plan(path, sessions_mod.parse_start_date("2026-11-01"), "012345678901")


# --------------------------------------------------------------------------------------
# 2. record is append-only
# --------------------------------------------------------------------------------------


def test_record_fills_actual_times_and_appends_notes(tmp_path) -> None:
    path = _plan(tmp_path)
    before = {row["session_id"]: dict(row) for row in _rows(path)}

    sessions_mod.record_session(
        path, "D02-W04-1", actual_start="2026-10-02T10:03:11Z", status="in_progress",
        notes="started late, coffee",
    )
    sessions_mod.record_session(
        path, "D02-W04-1", actual_end="2026-10-02T10:48:02Z", status="done",
        notes="one throttled call, retried",
    )

    after = {row["session_id"]: dict(row) for row in _rows(path)}
    row = after["D02-W04-1"]
    assert row["actual_start_utc"] == "2026-10-02T10:03:11Z"
    assert row["actual_end_utc"] == "2026-10-02T10:48:02Z"
    assert row["status"] == "done"
    # The planned label survives, and both notes are present: notes append, never replace.
    assert row["notes"].startswith("planned: ")
    assert "started late, coffee" in row["notes"]
    assert "one throttled call, retried" in row["notes"]
    assert len(after) == len(before)


def test_record_never_changes_a_planned_column(tmp_path) -> None:
    """INV-2: the head of the log is immutable.

    Fails if any planned column of any row -- not only the row being annotated -- can
    move while recording.
    """
    path = _plan(tmp_path)
    before = [
        {column: row[column] for column in sessions_mod.PLANNED_COLUMNS}
        for row in _rows(path)
    ]
    for session_id in ("D01-SETUP-1", "D06-W13-1", "D08-W12-1"):
        sessions_mod.record_session(
            path, session_id, actual_start="2026-10-06T09:00:00Z", status="in_progress",
        )
    after = [
        {column: row[column] for column in sessions_mod.PLANNED_COLUMNS}
        for row in _rows(path)
    ]
    assert after == before


def test_record_refuses_an_unknown_session_id(tmp_path) -> None:
    """An unplanned session cannot enter the log as if it had been declared."""
    path = _plan(tmp_path)
    with pytest.raises(SystemExit, match="unknown session id"):
        sessions_mod.record_session(path, "D99-W99-1", status="done")
    assert len(_rows(path)) == 110


def test_record_refuses_to_contradict_a_recorded_time(tmp_path) -> None:
    path = _plan(tmp_path)
    sessions_mod.record_session(path, "D05-W05-1", actual_start="2026-10-05T11:00:00Z")
    with pytest.raises(SystemExit, match="refusing to overwrite"):
        sessions_mod.record_session(path, "D05-W05-1", actual_start="2026-10-05T12:00:00Z")


def test_record_refuses_to_reopen_a_terminal_status(tmp_path) -> None:
    """A skipped session stays skipped: the plan says such a row is "kept"."""
    path = _plan(tmp_path)
    sessions_mod.record_session(path, "D07-W09-1", status="skipped", notes="operator away")
    with pytest.raises(SystemExit, match="already 'skipped'"):
        sessions_mod.record_session(path, "D07-W09-1", status="done")
    row = next(r for r in _rows(path) if r["session_id"] == "D07-W09-1")
    assert row["status"] == "skipped"


def test_record_refuses_a_file_whose_columns_are_not_the_declared_ones(tmp_path) -> None:
    path = tmp_path / "sessions.csv"
    path.write_text("session_id,workflow_id\nX,Y\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="Refusing to write"):
        sessions_mod.record_session(path, "X", status="done")


# --------------------------------------------------------------------------------------
# 3. The split reads names, not contents
# --------------------------------------------------------------------------------------


def _name(stamp: str, index: int = 0) -> str:
    return f"012345678901_CloudTrail_us-east-1_{stamp}_a1b2c3d{index}.json.gz"


def _write_trail_file(directory: Path, stamp: str, index: int = 0, records=None) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / _name(stamp, index)
    payload = json.dumps({"Records": records or []}).encode("utf-8")
    path.write_bytes(gzip.compress(payload))
    return path


def test_split_boundary_is_the_calendar_day_ten(tmp_path) -> None:
    """23:59Z on day 9 is development; 00:00Z on day 10 is sealed.

    The plan fixes this boundary "before collection starts, not a property of the data,
    so it cannot be moved once the findings are inconvenient". This test is that
    sentence.
    """
    source = tmp_path / "delivered"
    _write_trail_file(source, "20261009T2359Z", 1)
    _write_trail_file(source, "20261010T0000Z", 2)
    record = split_mod.split(source, tmp_path / "out", datetime(2026, 10, 1))

    assert [entry["name"] for entry in record["dev"]] == [_name("20261009T2359Z", 1)]
    assert [entry["name"] for entry in record["holdout"]] == [_name("20261010T0000Z", 2)]
    assert record["boundary_utc"] == "2026-10-10T00:00:00Z"
    assert (tmp_path / "out" / "dev" / _name("20261009T2359Z", 1)).exists()
    assert (tmp_path / "out" / "holdout" / _name("20261010T0000Z", 2)).exists()
    assert not list(source.glob("*.json.gz"))  # moved, not copied


def test_split_uses_the_key_timestamp_and_not_event_time(tmp_path) -> None:
    """A day-10 file full of day-1 events is still holdout.

    This is the INV-1 decision made visible: the only alternative -- reading eventTime --
    would require opening the file, and the whole point is that the sealed side is never
    opened. The cost (a delivery straddling the boundary is assigned by its name) is
    accepted deliberately.
    """
    source = tmp_path / "delivered"
    _write_trail_file(source, "20261010T0005Z", 3, records=[{
        "eventVersion": "1.08", "eventName": "ListBuckets",
        "eventTime": "2026-10-01T09:00:00Z",
    }])
    record = split_mod.split(source, tmp_path / "out", datetime(2026, 10, 1))
    assert record["dev"] == []
    assert len(record["holdout"]) == 1


def test_holdout_file_is_hashed_without_being_opened(tmp_path) -> None:
    """The sealing invariant, proved by a file that cannot be read.

    The holdout file here has a valid CloudTrail name and invalid gzip content. Every
    code path that would open it -- ``gzip.open``, ``json.loads``, a row count, the ATH
    adapter -- raises on this file. The split completes, records its size and sha256, and
    the assertions below hold only while nothing in the path opened it.
    """
    source = tmp_path / "delivered"
    source.mkdir()
    corrupt = source / _name("20261011T0300Z", 4)
    corrupt.write_bytes(b"\x1f\x8b\x08\x00this is not a valid deflate stream at all")
    _write_trail_file(source, "20261003T0300Z", 5)

    record = split_mod.split(source, tmp_path / "out", datetime(2026, 10, 1))

    holdout = tmp_path / "out" / "holdout"
    assert len(record["holdout"]) == 1
    entry = record["holdout"][0]
    assert entry["bytes"] == len(b"\x1f\x8b\x08\x00this is not a valid deflate stream at all")
    assert len(entry["sha256"]) == 64
    # Size and hash, and nothing else: SIZES and SHA256SUMS are the complete set of facts
    # recorded about a sealed file.
    sums = (holdout / "SHA256SUMS").read_text(encoding="utf-8")
    sizes = (holdout / "SIZES").read_text(encoding="utf-8")
    assert sums.split()[0] == entry["sha256"]
    assert sizes.split()[0] == str(entry["bytes"])
    assert sorted(p.name for p in holdout.iterdir()) == sorted(
        ["SHA256SUMS", "SIZES", corrupt.name]
    )
    # And the file really is unreadable, so the test above could not have passed by luck.
    with pytest.raises(Exception):  # noqa: B017 -- any read failure is the point
        with gzip.open(holdout / corrupt.name, "rb") as handle:
            handle.read()


def test_split_refuses_a_name_it_cannot_parse_before_moving_anything(tmp_path) -> None:
    """A file that is not a CloudTrail delivery aborts the run, with nothing moved.

    Assigning it would mean opening it. And a split that moved half the corpus before
    stopping would leave the operator reconstructing which files had moved -- by looking
    at them.
    """
    source = tmp_path / "delivered"
    _write_trail_file(source, "20261002T0300Z", 6)
    (source / "notes-about-the-corpus.json.gz").write_bytes(gzip.compress(b"{}"))

    with pytest.raises(SystemExit, match="not a CloudTrail delivery name"):
        split_mod.split(source, tmp_path / "out", datetime(2026, 10, 1))

    assert (source / _name("20261002T0300Z", 6)).exists()
    assert not (tmp_path / "out" / "dev").exists()


def test_split_refuses_a_second_run(tmp_path) -> None:
    """Re-splitting would move late day-9 deliveries into the sealed side."""
    source = tmp_path / "delivered"
    _write_trail_file(source, "20261004T0300Z", 7)
    split_mod.split(source, tmp_path / "out", datetime(2026, 10, 1))

    _write_trail_file(source, "20261005T0300Z", 8)
    with pytest.raises(SystemExit, match="already been split"):
        split_mod.split(source, tmp_path / "out", datetime(2026, 10, 1))
    assert (source / _name("20261005T0300Z", 8)).exists()


def test_classify_is_pure_and_boundary_inclusive_of_the_holdout() -> None:
    """The sealed side is the one that grows if the operator is imprecise."""
    boundary = split_mod.boundary_for(datetime(2026, 10, 1))
    assert split_mod.classify(_name("20261009T2359Z"), boundary) == "dev"
    assert split_mod.classify(_name("20261010T0000Z"), boundary) == "holdout"
    assert split_mod.classify(_name("20261001T0000Z"), boundary) == "dev"
    assert split_mod.classify(_name("20261231T2359Z"), boundary) == "holdout"


# --------------------------------------------------------------------------------------
# 4. The measurement scripts and the seal
# --------------------------------------------------------------------------------------


def test_validate_dev_refuses_any_holdout_path(tmp_path) -> None:
    """The validator has no holdout mode, at any depth of the path."""
    from m20 import validate_dev

    sessions_csv = _plan(tmp_path)
    for candidate in (
        tmp_path / "holdout",
        tmp_path / "m20_benign_cloud" / "holdout" / "nested",
        tmp_path / "HOLDOUT",
    ):
        with pytest.raises(SystemExit, match="sealed holdout"):
            validate_dev.validate(candidate, sessions_csv)

    # And the guard is not merely in main(): the function itself refuses.
    with pytest.raises(SystemExit, match="sealed holdout"):
        refuse_holdout(tmp_path / "a" / "holdout" / "b", "test")


def test_measure_dev_refuses_the_holdout_without_a_filled_preregistration(tmp_path) -> None:
    """INV-4: the prediction is committed first, and completely.

    Three states, three outcomes: no file (refused), the template with its blanks still
    in it (refused -- otherwise the predictions could be written after the numbers were
    known), and a completed document (allowed through the gate).
    """
    from m20 import measure_dev

    holdout = tmp_path / "m20_benign_cloud" / "holdout"
    holdout.mkdir(parents=True)
    prereg = tmp_path / "PREREGISTERED.md"

    with pytest.raises(SystemExit, match="does not exist"):
        measure_dev.measure(holdout, prereg)

    prereg.write_text(
        "findings/day by rule:  ATH-005 __  AWS-001 __\n"
        "  2. triage benign disposition fraction: >= __ %\n",
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="unfilled blank"):
        measure_dev.measure(holdout, prereg)

    prereg.write_text(
        "findings/day by rule:  ATH-005 0.11  AWS-001 0.00\n"
        "  2. triage benign disposition fraction: >= 60 %\n",
        encoding="utf-8",
    )
    # The gate now opens; the load fails for the ordinary reason that the directory holds
    # no CloudTrail files, which is a different refusal from the sealing one.
    with pytest.raises(FileNotFoundError):
        measure_dev.measure(holdout, prereg)


def test_the_blank_detector_reads_the_templates_own_blanks() -> None:
    """Section 5 writes blanks as runs of underscores, in two lengths."""
    assert unfilled_blanks("Development-split observation (days 1-9, N events = ____):")
    assert unfilled_blanks("  findings/day by rule:  ATH-005 __  AWS-001 __")
    assert unfilled_blanks("no single rule contributes > __ % of all")
    assert not unfilled_blanks("ATH-005 0.11  AWS-001 0.00")
    assert not unfilled_blanks("snake_case_names are not blanks")


def test_measure_dev_needs_no_gate_for_the_development_split(tmp_path) -> None:
    """The dev split is measurable with no pre-registration at all -- that is the point.

    The prediction is made *from* these numbers, so requiring it first would be circular.
    """
    from m20 import measure_dev

    dev = tmp_path / "dev"
    dev.mkdir()
    with pytest.raises(FileNotFoundError):   # no CloudTrail files, not a sealing refusal
        measure_dev.measure(dev, tmp_path / "does-not-exist.md")


def test_the_gate_is_silent_for_a_development_path() -> None:
    """The gate only engages on a sealed path -- and "sealed" means anywhere in the path.

    A synthetic path, deliberately: the guard matches the whole path string, so a test
    whose own tmp_path carried the sealed name in it would be refused for the right
    reason and prove nothing about this one.
    """
    holdout_gate(Path("corpus/dev"), Path("missing.md"), "test")  # no raise
    refuse_holdout(Path("corpus/dev"), "test")                    # no raise


# --------------------------------------------------------------------------------------
# 5. Validation over a small real corpus
# --------------------------------------------------------------------------------------


def _record(event_name: str, when: str, user_name: str, source: str = "iam.amazonaws.com") -> dict:
    return {
        "eventVersion": "1.08",
        "eventName": event_name,
        "eventTime": when,
        "eventSource": source,
        "awsRegion": "us-east-1",
        "recipientAccountId": "012345678901",
        "sourceIPAddress": "203.0.113.10",
        "userIdentity": {"type": "IAMUser", "userName": user_name,
                         "arn": "arn:aws:iam::012345678901:user/" + user_name},
        "requestParameters": {"userName": "dave"},
        "eventID": "evt-" + event_name + "-" + when,
    }


def test_validate_dev_reports_coverage_and_unexplained_activity(tmp_path) -> None:
    """A session that ran is covered; activity nobody declared is reported as such.

    The unexplained half is the one that matters: the corpus claims "benign by
    construction, every session predeclared in sessions.csv before it ran", and a row
    that belongs to no session is outside that construction.
    """
    from m20 import validate_dev

    # A start date in the past: ath.telemetry.normalize quarantines rows stamped in the
    # future, so a corpus dated after today would be dropped before it could be validated.
    sessions_csv = tmp_path / "sessions.csv"
    sessions_mod.write_plan(sessions_csv, sessions_mod.parse_start_date(PAST_START),
                            "012345678901")
    sessions_mod.record_session(
        sessions_csv, "D08-W12-1",
        actual_start="2026-08-08T15:30:00Z", actual_end="2026-08-08T15:45:00Z",
        status="done",
    )

    dev = tmp_path / "dev"
    dev.mkdir()
    payload = {"Records": [
        # Inside bob's W12 window: this covers the session.
        _record("UpdateAssumeRolePolicy", "2026-08-08T15:31:00Z", "bob"),
        # Nobody declared this: mallory is not in the catalogue at all.
        _record("CreateUser", "2026-08-08T16:10:00Z", "mallory"),
        # Declared actor, but hours outside any of her windows.
        _record("ListUsers", "2026-08-08T23:50:00Z", "bob"),
    ]}
    (dev / _name("20260808T1600Z")).write_bytes(gzip.compress(json.dumps(payload).encode()))

    report = validate_dev.validate(dev, sessions_csv)

    covered = next(s for s in report["sessions"] if s["session_id"] == "D08-W12-1")
    assert covered["covered"] is True
    assert covered["rows"]["control"] == 1
    assert report["summary"]["sessions_uncovered"] == 0
    assert report["summary"]["unexplained_rows"] == 2
    assert "mallory" in report["unexplained"]["by_actor"]
    assert report["unexplained"]["by_actor"]["mallory"] == 1


def test_principal_names_follow_the_adapters_own_rule() -> None:
    """How a sessions.csv ARN maps onto the principal CloudTrail records.

    ``cloudtrail_source._principal`` prefers ``userName``, then the ARN's last segment
    (an assumed role's *session* name), then the sessionIssuer's role name, then
    ``invokedBy``. Both names of a role are therefore accepted.
    """
    assert principal_names("arn:aws:iam::012345678901:user/alice") == {"alice"}
    assert principal_names("arn:aws:iam::012345678901:root") == {"root"}
    assert principal_names(
        "arn:aws:sts::012345678901:assumed-role/AdminRole/ath-m20-admin"
    ) == {"ath-m20-admin", "adminrole"}
    assert principal_names("lambda.amazonaws.com") == {"lambda.amazonaws.com"}


# --------------------------------------------------------------------------------------
# 6. Provenance
# --------------------------------------------------------------------------------------


def _provenance_inputs(tmp_path: Path):
    source = tmp_path / "delivered"
    _write_trail_file(source, "20261003T0300Z", 1)
    _write_trail_file(source, "20261011T0300Z", 2)
    split_dir = tmp_path / "corpus"
    split_mod.split(source, split_dir, datetime(2026, 10, 1))

    attestation = tmp_path / "ATTESTATION.txt"
    attestation.write_text("I ran every session in sessions.csv. Nothing adversarial.\n",
                           encoding="utf-8")
    policies = tmp_path / "iam_snapshots"
    policies.mkdir()
    (policies / "20261001T090000Z_AdminRole_attached.json").write_text("{}", encoding="utf-8")
    return split_dir, attestation, policies


def test_provenance_entry_carries_every_item_section_three_requires(tmp_path) -> None:
    """Section 3's "Provenance recorded" list, item by item."""
    split_dir, attestation, policies = _provenance_inputs(tmp_path)
    sessions_csv = _plan(tmp_path)

    entry = provenance_mod.build_entry(
        split_dir=split_dir, sessions_csv=sessions_csv, account_id="012345678901",
        regions=["us-east-1", "eu-west-1"],
        trail_arn="arn:aws:cloudtrail:us-east-1:REDACTED:trail/ath-m20-baseline",
        iam_policies_dir=policies, attestation=attestation.read_text(encoding="utf-8"),
        scripts_dir=SCRIPTS / "m20", fetched_on="2026-10-15",
    )

    collection = entry["collection_provenance"]
    assert collection["account_id_last4"] == "8901"
    assert collection["regions"] == ["us-east-1", "eu-west-1"]
    assert collection["trail_arn"].endswith("trail/ath-m20-baseline")
    assert collection["sessions_csv"]["sha256"]
    assert collection["scripts"]["sha256"]
    assert collection["iam_policy_snapshots"]["files"]
    assert collection["operator_attestation"].startswith("I ran every session")
    assert collection["delivered_files"] == {
        "count": 2, "dev": 1, "holdout": 1,
        "bytes": collection["delivered_files"]["bytes"],
        "note": collection["delivered_files"]["note"],
    }
    # files[] is the shape fetch_external.py reads, plus sessions.csv.
    assert all(set(f) >= {"path", "bytes", "sha256"} for f in entry["files"])
    assert any(f["path"].endswith("sessions.csv") for f in entry["files"])
    assert any("/holdout/" in f["path"] for f in entry["files"])


def test_provenance_refuses_to_emit_the_full_account_id(tmp_path) -> None:
    """The plan redacts the account to its last four digits; a leak is refused, not trimmed."""
    split_dir, attestation, policies = _provenance_inputs(tmp_path)
    sessions_csv = _plan(tmp_path, account_id="012345678901")

    with pytest.raises(SystemExit, match="full account id"):
        provenance_mod.build_entry(
            split_dir=split_dir, sessions_csv=sessions_csv, account_id="012345678901",
            regions=["us-east-1"],
            # The ARN an operator would paste straight out of describe-trails.
            trail_arn="arn:aws:cloudtrail:us-east-1:012345678901:trail/ath-m20-baseline",
            iam_policies_dir=policies, attestation=attestation.read_text(encoding="utf-8"),
            scripts_dir=SCRIPTS / "m20", fetched_on="2026-10-15",
        )


def test_provenance_writes_to_a_manifest_that_does_not_exist_yet(tmp_path) -> None:
    """A missing manifest is created in the shape fetch_external.py expects.

    Never ``data/external/MANIFEST.json``: this test writes under tmp_path, which is also
    how the operator should try it first.
    """
    split_dir, attestation, policies = _provenance_inputs(tmp_path)
    sessions_csv = _plan(tmp_path)
    entry = provenance_mod.build_entry(
        split_dir=split_dir, sessions_csv=sessions_csv, account_id="012345678901",
        regions=["us-east-1"], trail_arn="arn:aws:cloudtrail:us-east-1:REDACTED:trail/x",
        iam_policies_dir=policies, attestation=attestation.read_text(encoding="utf-8"),
        scripts_dir=SCRIPTS / "m20", fetched_on="2026-10-15",
    )

    manifest_path = tmp_path / "new" / "MANIFEST.json"
    provenance_mod.merge_into_manifest(manifest_path, entry)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert set(manifest) >= {"_about", "datasets"}
    assert manifest["datasets"]["m20_benign_cloud"]["name"].startswith("ATH M20 benign cloud")

    with pytest.raises(SystemExit, match="--force"):
        provenance_mod.merge_into_manifest(manifest_path, entry)


# --------------------------------------------------------------------------------------
# 7. The workflow scripts
# --------------------------------------------------------------------------------------


def test_no_workflow_script_can_stop_or_delete_the_trail() -> None:
    """AWS-002 is never exercised -- checked in the scripts, not only in the guard.

    The plan: "stopping the trail would delete the corpus. Its expected count is zero and
    that is a prediction, not an omission." The guard in ``_common.sh`` refuses these
    calls; this test fails if one is ever written into a workflow anyway, which is how the
    guard would come to be bypassed.
    """
    forbidden = ("stop-logging", "delete-trail", "update-trail", "put-event-selectors")
    for script in sorted(WORKFLOWS_DIR.glob("W*.sh")):
        text = script.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in text, f"{script.name} mentions {token}"


def test_every_catalogued_workflow_has_a_script() -> None:
    """Thirteen workflows, thirteen scripts, and each names its own id."""
    scripts = {p.name.split("_")[0]: p for p in WORKFLOWS_DIR.glob("W*.sh")}
    expected = {w for w in sessions_mod.WORKFLOWS if w != "SETUP"}
    assert set(scripts) == expected
    for workflow_id, path in scripts.items():
        text = path.read_text(encoding="utf-8")
        assert workflow_id in text
        assert "set -euo pipefail" in text
        assert "ath_session_start" in text and "ath_session_end" in text


def test_workflow_scripts_reach_sessions_record_through_the_shared_helper() -> None:
    """Session logging goes through one place, so it cannot be half-implemented."""
    common = (WORKFLOWS_DIR / "_common.sh").read_text(encoding="utf-8")
    assert "sessions.py" in common and "record" in common
    for script in sorted(WORKFLOWS_DIR.glob("W*.sh")):
        text = script.read_text(encoding="utf-8")
        assert "_common.sh" in text
        assert "\naws " not in text, f"{script.name} calls aws directly"


def test_provenance_records_that_file_names_carry_the_account_id(tmp_path) -> None:
    """The one place the account id survives, recorded rather than quietly tolerated.

    CloudTrail puts the account id in every object key, and ``files[]`` has to quote the
    names on disk or ``fetch_external.py`` could not verify them. Fails if that fact ever
    stops being written into the entry -- at which point the manifest would look fully
    redacted while the file names were not.
    """
    split_dir, attestation, policies = _provenance_inputs(tmp_path)
    entry = provenance_mod.build_entry(
        split_dir=split_dir, sessions_csv=_plan(tmp_path), account_id="012345678901",
        regions=["us-east-1"], trail_arn="arn:aws:cloudtrail:us-east-1:REDACTED:trail/x",
        iam_policies_dir=policies, attestation=attestation.read_text(encoding="utf-8"),
        scripts_dir=SCRIPTS / "m20", fetched_on="2026-10-15",
    )
    recorded = entry["collection_provenance"]["account_id_in_delivered_file_names"]
    assert recorded["value"] is True
    assert "redacted" in recorded["why"]
    assert any("012345678901_CloudTrail" in spec["path"] for spec in entry["files"])


def test_measure_dev_fills_the_observation_and_leaves_every_prediction_blank(tmp_path) -> None:
    """The rendered template is measurement on one side and a blank commitment on the other.

    The asymmetry is load-bearing: because the predictions are still ``__``, the document
    this script prints cannot itself open the holdout (``holdout_gate`` reads exactly
    those blanks). Fails if the renderer ever starts filling a prediction in -- which
    would let the tool make the commitment the operator is supposed to make.
    """
    from m20 import measure_dev

    dev = tmp_path / "dev"
    dev.mkdir()
    payload = {"Records": [
        _record("CreateUser", "2026-08-03T10:00:00Z", "alice"),
        _record("AttachUserPolicy", "2026-08-03T10:01:00Z", "alice"),
        _record("ListBuckets", "2026-08-03T10:02:00Z", "alice", source="s3.amazonaws.com"),
    ]}
    (dev / _name("20260803T1000Z")).write_bytes(gzip.compress(json.dumps(payload).encode()))

    measurements = measure_dev.measure(dev, tmp_path / "no-preregistration.md")

    assert measurements["split"] == "dev"
    assert measurements["import"]["events"] == 3
    assert measurements["days"]["event_days"] == ["2026-08-03"]
    # Every rule under test is reported, including the ones that fired zero times: a
    # missing key would read as "not measured" rather than "measured as zero".
    assert set(measure_dev.RULES_UNDER_TEST) <= set(measurements["per_rule"])
    assert measurements["per_rule"]["AWS-002"]["findings"] == 0
    assert measurements["analyst_load"]["analyst_hours"] == 8

    rendered = measure_dev.render_preregistration(measurements)
    assert "N events = 3" in rendered
    for prediction in ("benign by ATH's triage", "expected __ /day", "> __ % of all"):
        assert prediction in rendered
    # And the rendered document is, by construction, not a valid pre-registration yet.
    assert unfilled_blanks(rendered)
