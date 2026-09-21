"""M20 validation: did the development split contain the sessions the schedule declared?

The question
-------------
``sessions.csv`` says who did what, when. The trail says what the account actually
recorded. This script joins the two and reports the two ways they can disagree:

* a **session with no rows** -- the operator recorded it as ``done`` and the trail has
  nothing for that actor in that window. Either the calls never happened, the clock was
  wrong, or CloudTrail did not deliver. All three matter, and none is visible from
  ``sessions.csv`` alone.
* **rows with no session** -- activity nobody predeclared. This is the more interesting
  half. The corpus's central claim is "benign by construction, every session predeclared
  before it ran" (plan section 7); every row that cannot be attributed to a predeclared
  session is a hole in that claim, so it is reported as a finding in its own right rather
  than filtered out as noise.

Two tables, not one
--------------------
The task this script was written for says "control rows". CloudTrail's four
authentication events -- ``ConsoleLogin``, ``AssumeRole``, ``GetSessionToken``,
``GetFederationToken`` -- are routed to the **logon** table by
``ath.telemetry.cloudtrail_source.AUTH_EVENTS``, not the control table, so W01, W02, W03
and W13 (every console-login and role-assumption workflow) produce no control rows at
all. Checking control rows only would report four of the plan's thirteen workflows as
uncovered when they had in fact run exactly as declared.

So coverage is computed over both tables and each session's ``covered_by`` says which
one answered. This is a deliberate, visible widening of the check, not a silent one.

Attribution
------------
A row belongs to a session when its principal matches the session's actor
(:func:`ath.scripts.m20.common.principal_names`) and its timestamp lies within the
session's *actual* window. ``sessions.py`` guarantees no actor has two overlapping
planned windows, so a row can belong to at most one session -- when actual windows
overlap anyway (an operator ran two sessions at once), that is reported as its own
anomaly instead of being resolved arbitrarily.

Sealing
--------
This tool has no holdout mode. Any path mentioning the holdout is refused, in
:func:`validate` itself and again in ``main``, so importing the function does not route
around the guard (INV-1).

Usage::

    python scripts/m20/validate_dev.py --dev-dir data/external/m20_benign_cloud/dev \
        --sessions reports/m20/sessions.csv --out reports/m20/dev_validation.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from m20.common import (  # noqa: E402
    load_cloudtrail,
    parse_utc,
    principal_names,
    refuse_holdout,
)
from m20.sessions import read_sessions  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_OUT = ROOT / "reports" / "m20" / "dev_validation.json"
TOOL = "validate_dev.py"

#: (table, principal column). The control table names the caller in ``actor``; the logon
#: table has no ``actor`` column and names the principal in ``user``.
PRINCIPAL_COLUMN = {"control": "actor", "logon": "user"}


def _bounds(frame: pd.DataFrame, start, end):
    """Session bounds as timestamps comparable with this frame's timestamp column."""
    lower, upper = pd.Timestamp(start), pd.Timestamp(end)
    if len(frame) and getattr(frame["timestamp"].dtype, "tz", None) is not None:
        lower = lower.tz_localize("UTC") if lower.tzinfo is None else lower.tz_convert("UTC")
        upper = upper.tz_localize("UTC") if upper.tzinfo is None else upper.tz_convert("UTC")
    return lower, upper


def _match_mask(frame: pd.DataFrame, column: str, names: set, start, end) -> pd.Series:
    if not len(frame):
        return pd.Series([], dtype=bool)
    lower, upper = _bounds(frame, start, end)
    principals = frame[column].astype(str).str.lower()
    return principals.isin(names) & (frame["timestamp"] >= lower) & (frame["timestamp"] <= upper)


def validate(dev_dir: Path, sessions_csv: Path) -> dict:
    """Coverage per declared session, and every row that belongs to none.

    Raises:
        SystemExit: if ``dev_dir`` names the holdout (INV-1).
    """
    refuse_holdout(dev_dir, TOOL)

    rows = read_sessions(sessions_csv)
    telemetry, result = load_cloudtrail(dev_dir)
    frames = {"control": telemetry.controls, "logon": telemetry.logons}

    # One boolean per row per table: has any declared session claimed it?
    claimed = {
        table: pd.Series(False, index=frame.index) for table, frame in frames.items()
    }

    per_session = []
    for row in rows:
        names = principal_names(row["actor_arn"])
        entry = {
            "session_id": row["session_id"],
            "workflow_id": row["workflow_id"],
            "actor_arn": row["actor_arn"],
            "actor_type": row["actor_type"],
            "day": row["day"],
            "status": row["status"],
            "planned": [row["planned_start_utc"], row["planned_end_utc"]],
            "actual": [row["actual_start_utc"], row["actual_end_utc"]],
            "principal_names": sorted(names),
        }

        if not row["actual_start_utc"] or not row["actual_end_utc"]:
            entry["checked"] = False
            entry["reason"] = (
                "no actual window recorded; status={0}".format(row["status"])
            )
            per_session.append(entry)
            continue

        start = parse_utc(row["actual_start_utc"], row["session_id"])
        end = parse_utc(row["actual_end_utc"], row["session_id"])
        if end < start:
            entry["checked"] = False
            entry["reason"] = "actual_end_utc precedes actual_start_utc"
            per_session.append(entry)
            continue

        counts = {}
        for table, frame in frames.items():
            mask = _match_mask(frame, PRINCIPAL_COLUMN[table], names, start, end)
            counts[table] = int(mask.sum())
            if len(frame):
                # Rows of a *skipped* session still count as claimed: they were declared,
                # they just were not expected to appear. Reporting them twice -- once as
                # a skipped session that produced activity, once as unexplained activity
                # -- would double-count the same anomaly.
                claimed[table] = claimed[table] | mask

        entry["checked"] = True
        entry["rows"] = counts
        entry["rows_total"] = sum(counts.values())
        entry["covered"] = entry["rows_total"] > 0
        entry["covered_by"] = sorted(t for t, n in counts.items() if n)
        per_session.append(entry)

    done = [e for e in per_session if e["status"] == "done"]
    checked_done = [e for e in done if e.get("checked")]
    uncovered = [e for e in checked_done if not e["covered"]]
    unchecked_done = [e for e in done if not e.get("checked")]
    skipped_with_activity = [
        e for e in per_session
        if e["status"] == "skipped" and e.get("checked") and e.get("rows_total", 0) > 0
    ]

    unexplained = _unexplained(frames, claimed)

    return {
        "_about": (
            "M20 development-split validation. Coverage of predeclared sessions, and "
            "activity that belongs to no predeclared session. Holdout is never read."
        ),
        "dev_dir": dev_dir.as_posix(),
        "sessions_csv": sessions_csv.as_posix(),
        "import": {
            "rows_read": result.rows_read,
            "control_rows": int(len(telemetry.controls)),
            "logon_rows": int(len(telemetry.logons)),
            "files_admitted": sum(1 for a in result.admitted_files if a.admitted),
            "files_rejected": [str(a) for a in result.admitted_files if not a.admitted],
            "normalisation_issues": len(result.issues),
        },
        "summary": {
            "sessions_planned": len(per_session),
            "sessions_done": len(done),
            "sessions_done_checked": len(checked_done),
            "sessions_done_without_actual_window": len(unchecked_done),
            "sessions_covered": len(checked_done) - len(uncovered),
            "sessions_uncovered": len(uncovered),
            "skipped_sessions_with_activity": len(skipped_with_activity),
            "unexplained_rows": unexplained["total"],
        },
        "uncovered_sessions": [e["session_id"] for e in uncovered],
        "skipped_sessions_with_activity": [e["session_id"] for e in skipped_with_activity],
        "sessions": per_session,
        "unexplained": unexplained,
    }


def _unexplained(frames: dict, claimed: dict) -> dict:
    """Every row no declared session claimed, summarised by actor and by what it did.

    Kept as a summary plus a bounded sample rather than a row dump: the point is to tell
    the operator *what kind* of activity nobody declared and give enough event ids to go
    and look, not to reproduce the corpus in a JSON file.
    """
    by_actor = Counter()
    by_kind = Counter()
    samples = []
    total = 0
    per_table = {}
    for table, frame in frames.items():
        if not len(frame):
            per_table[table] = 0
            continue
        rest = frame[~claimed[table]]
        per_table[table] = int(len(rest))
        total += int(len(rest))
        column = PRINCIPAL_COLUMN[table]
        for actor, count in Counter(rest[column].astype(str)).items():
            by_actor[actor] += count
        if table == "control":
            kinds = rest["verb"].astype(str) + " " + rest["resource_type"].astype(str)
        else:
            kinds = "logon " + rest["action"].astype(str)
        for kind, count in Counter(kinds).items():
            by_kind[kind] += count
        for _, row in rest.head(20).iterrows():
            samples.append({
                "table": table,
                "event_id": str(row["event_id"]),
                "timestamp": str(row["timestamp"]),
                "principal": str(row[column]),
                "what": str(row["verb"]) + " " + str(row["resource_type"])
                        if table == "control" else "logon " + str(row["action"]),
                "source_ref": str(row["source_ref"]),
            })
    return {
        "total": total,
        "by_table": per_table,
        "by_actor": dict(by_actor.most_common(25)),
        "by_action": dict(by_kind.most_common(25)),
        "sample": samples[:40],
        "note": (
            "Every row here is activity no predeclared session accounts for. The corpus "
            "claims benignity by construction; these rows are outside that construction "
            "and must be explained in the report, not dropped."
        ),
    }


def _print_report(report: dict) -> None:
    summary = report["summary"]
    print("M20 dev-split validation -- {0}".format(report["dev_dir"]))
    print("  imported {0} record(s): {1} control row(s), {2} logon row(s), "
          "{3} file(s) rejected".format(
              report["import"]["rows_read"], report["import"]["control_rows"],
              report["import"]["logon_rows"], len(report["import"]["files_rejected"]),
          ))
    print("  sessions: {0} planned, {1} done, {2} checked, {3} covered, {4} UNCOVERED".format(
        summary["sessions_planned"], summary["sessions_done"],
        summary["sessions_done_checked"], summary["sessions_covered"],
        summary["sessions_uncovered"],
    ))
    if report["uncovered_sessions"]:
        print("  uncovered: " + ", ".join(report["uncovered_sessions"]))
    if report["skipped_sessions_with_activity"]:
        print("  skipped sessions that nevertheless show activity: "
              + ", ".join(report["skipped_sessions_with_activity"]))
    print("  unexplained rows: {0} ({1})".format(
        summary["unexplained_rows"], report["unexplained"]["by_table"],
    ))
    for actor, count in list(report["unexplained"]["by_actor"].items())[:10]:
        print(f"    {actor:>28}  {count}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dev-dir", type=Path, required=True,
                        help="the development split only; a holdout path is refused")
    parser.add_argument("--sessions", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--strict", action="store_true",
                        help="exit non-zero if any done session is uncovered")
    args = parser.parse_args(argv)

    refuse_holdout(args.dev_dir, TOOL)
    report = validate(args.dev_dir, args.sessions)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    _print_report(report)
    print(f"wrote {args.out}")
    if args.strict and report["summary"]["sessions_uncovered"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
