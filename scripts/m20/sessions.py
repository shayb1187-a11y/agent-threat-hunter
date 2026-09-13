"""M20 session labelling: the schedule, written down before anything runs.

Why this is a script and not a spreadsheet
-------------------------------------------
``docs/m20-benign-cloud-validation-plan.md`` section 3 requires a ``sessions.csv``
"committed to the repo before day 1 with one row per planned session", and afterwards
"an ``actual_start_utc``, ``actual_end_utc`` and a free-text ``notes`` column is filled
in -- appended, never overwriting the plan. A session that did not happen is marked
``skipped`` and kept."

That is an append-only log with a pre-committed head, and a spreadsheet cannot enforce
either half. This module can:

* ``plan`` derives every row from the tables below -- which are the plan's own section 2
  catalogue and section 3 schedule encoded as data -- and **refuses to overwrite** an
  existing file, because overwriting is how a predeclaration silently becomes a
  postdiction (INV-2, :func:`write_plan`).
* ``record`` may only touch ``actual_start_utc``, ``actual_end_utc``, ``notes`` and
  ``status``. It refuses an unknown session id, refuses to change a planned column,
  refuses to contradict an actual time already recorded, and appends to ``notes``
  rather than replacing them (INV-2, :func:`record_session`).

Faithfulness to the plan, and where it could not be exact
----------------------------------------------------------
:data:`SCHEDULE_TABLE` quotes the plan's 14-row day table verbatim, and
:func:`verify_schedule_covers_plan` checks the generated sessions against it in both
directions, so a workflow that the plan places on a day and this file forgets is an
error at ``plan`` time rather than a hole discovered after collection.

Three places where the plan is ambiguous and a choice had to be made. Each is a choice
of the *literal* reading, recorded here rather than smoothed over:

1. **Day 7 and day 13 say "quiet day: W01, W11, W09 only"**, while day 1 says W01, W03
   and W11 "begin and run daily from here". "only" is taken literally, so W03 (role
   assumption) does not run on days 7 and 13 -- see :data:`DAILY`. The alternative
   reading (W03 daily, the word "only" meaning "no *new* workflows") is equally
   defensible; it is reported rather than chosen silently.
2. **W02 is declared as "1/day, ~3 days of the 14"** but the schedule table places it on
   days 3 and 6 only. The table wins, giving two W02 sessions, because the table is the
   thing written as the schedule.
3. **Day 1's "account + trail setup (Root, once)"** is a session with an actor and a
   window but no workflow id in the catalogue. It is emitted with workflow id ``SETUP``
   so that the Root activity of day 1 is explained by a predeclared row instead of
   surfacing later as unexplained activity in ``validate_dev.py``.

Planned clock times are this file's own contribution: the plan fixes cadence ("daily at
02:00 UTC", "business hours", "5-15/day") and session counts, not wall-clock windows. The
times below realise that cadence, and :func:`verify_no_actor_overlap` enforces the one
property the validator depends on -- no two planned sessions of the same actor overlap,
so every row can be attributed to at most one session.

Usage::

    python scripts/m20/sessions.py plan --start-date 2026-10-01 --account-id 012345678901
    python scripts/m20/sessions.py record --session-id D02-W04-1 \
        --actual-start 2026-10-02T10:03:11Z --status in_progress
    python scripts/m20/sessions.py record --session-id D02-W04-1 \
        --actual-end 2026-10-02T10:48:02Z --status done --notes "one throttled call, retried"
    python scripts/m20/sessions.py record --session-id D07-W09-1 --status skipped \
        --notes "operator travelling; scan not run"
"""

from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, Optional, Sequence

ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_SESSIONS_CSV = ROOT / "reports" / "m20" / "sessions.csv"

TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

#: Columns fixed by the plan ("session_id, workflow_id, actor_arn, actor_type,
#: planned_start_utc, planned_end_utc, day"), followed by the four the plan says are
#: filled in afterwards. ``status`` carries the plan's "marked ``skipped`` and kept".
PLANNED_COLUMNS = (
    "session_id", "workflow_id", "actor_arn", "actor_type",
    "planned_start_utc", "planned_end_utc", "day",
)
MUTABLE_COLUMNS = ("actual_start_utc", "actual_end_utc", "notes", "status")
COLUMNS = PLANNED_COLUMNS + MUTABLE_COLUMNS

#: A row starts at ``planned`` and may move to any of the others. ``done`` and
#: ``skipped`` are terminal: a session that has been declared finished is not silently
#: re-finished.
STATUSES = ("planned", "in_progress", "done", "skipped", "failed")
TERMINAL_STATUSES = ("done", "skipped")

ACCOUNT_PLACEHOLDER = "<accountid>"


# --------------------------------------------------------------------------------------
# The plan's section 2 catalogue, as data
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Workflow:
    """One predeclared workflow, quoting the plan's own catalogue row.

    Attributes:
        id: ``W01`` .. ``W13``, or ``SETUP`` for day 1's Root account/trail creation.
        name: The plan's "workflow" cell.
        cadence: The plan's "calls / cadence" cell.
        services: The plan's "services, verb class" cell.
        rules: The plan's "rules that could fire" cell, including the quoted
            ``false_positives`` text where the plan quotes it. Carried so that a reader
            of ``sessions.csv`` never has to be told separately which expectations were
            declared in advance -- they are in the script that wrote the schedule.
    """

    id: str
    name: str
    cadence: str
    services: str
    rules: str


WORKFLOWS = {
    "SETUP": Workflow(
        id="SETUP",
        name="Account and trail setup (not in the section 2 catalogue; day 1 only)",
        cadence="once, day 1",
        services="organizations, cloudtrail, s3, iam, budgets; write",
        rules=(
            "none expected. Root is used once, for account setup only (section 2, "
            "identity types)."
        ),
    ),
    "W01": Workflow(
        id="W01",
        name="Console login with MFA",
        cadence="1-3/day each, business hours",
        services="signin ConsoleLogin, write",
        rules="none expected",
    ),
    "W02": Workflow(
        id="W02",
        name="Console login without MFA, incl. 2-4 mistyped passwords",
        cadence="1/day, ~3 days of the 14",
        services="signin, write",
        rules=(
            "ATH-005 only if a burst reaches 10 failures in 10 min; the declared cadence "
            "stays under it."
        ),
    ),
    "W03": Workflow(
        id="W03",
        name="Role assumption chain: user -> DeveloperRole -> DeployRole",
        cadence="5-15/day",
        services="sts AssumeRole, write",
        rules="none; feeds the actor identity of most other workflows",
    ),
    "W04": Workflow(
        id="W04",
        name=(
            "IAM administration: create user/role/group, attach/detach policies, rotate "
            "access keys"
        ),
        cadence="~30 calls, 3 sessions over 14 days",
        services="iam, write + delete",
        rules=(
            'AWS-001 ("Routine onboarding: an administrator grants a new identity '
            "permissions, and that identity (or a provisioning script) creates its first "
            'access key shortly after as part of normal setup."), AWS-005 ("Routine '
            'deprovisioning... Least-privilege cleanup campaigns")'
        ),
    ),
    "W05": Workflow(
        id="W05",
        name=(
            "Benign policy modification: widen then narrow a role's policy as its job "
            "changes"
        ),
        cadence="~12 calls, 2 sessions",
        services="iam, write",
        rules=(
            'AWS-005 ("Policy churn during development, where a role\'s permissions are '
            'attached and detached repeatedly while someone works out what it needs.")'
        ),
    ),
    "W06": Workflow(
        id="W06",
        name="EC2 lifecycle: run 2 t3.micro, tag, stop, start, terminate",
        cadence="~25 calls, 4 sessions",
        services="ec2, write + delete + read",
        rules="none expected; AWS-003 only if bundled with W09",
    ),
    "W07": Workflow(
        id="W07",
        name=(
            "S3 operations: create bucket, put/get/list objects, lifecycle policy, "
            "delete bucket"
        ),
        cadence="~40 calls, 5 sessions",
        services="s3, all classes",
        rules="none expected (object-level events are not enabled -- see section 3)",
    ),
    "W08": Workflow(
        id="W08",
        name=(
            "IaC: CloudFormation create-stack / delete-stack of a small VPC + SG + "
            "instance stack, run 4 times"
        ),
        cadence="~60 calls/run, 4 runs",
        services="cloudformation, ec2, iam, all classes",
        rules=(
            'AWS-001 ("Infrastructure-as-code pipelines that both attach policies and '
            'rotate access keys as part of a single automated run."), AWS-005 '
            '("Infrastructure-as-code runs that delete and recreate identity objects on '
            'every apply, so that a no-op change produces a removal."), AWS-003 '
            '("Infrastructure-as-code planning runs, which read the current state of '
            'every resource they manage before deciding what to change.")'
        ),
    ),
    "W09": Workflow(
        id="W09",
        name=(
            "Inventory scan -- describe-everything across every enabled service, read-only"
        ),
        cadence="~250 read calls in <10 min, daily at 02:00 UTC",
        services="15-25 services, read",
        rules=(
            'AWS-003 expected to fire, MEDIUM: "Cloud security posture and compliance '
            "scanners (the whole point of which is to read every service in the account, "
            'on a schedule, forever)" and "Inventory, asset-management, cost-explorer '
            'and backup tooling enumerating resources across services as designed." Also '
            "AWS-004 if the role lacks some reads"
        ),
    ),
    "W10": Workflow(
        id="W10",
        name=(
            "Least-privilege role probing its own permissions -- a newly scoped-down "
            "ReportingRole runs its normal daily job; calls outside its policy are denied"
        ),
        cadence="~40 calls/day of which ~28 denied, in <10 min",
        services="ce, cloudwatch, s3, ec2, mixed",
        rules=(
            'AWS-004 expected to fire, HIGH (>=5 resource types): "A pipeline or '
            "application whose role is missing a permission, retrying the call it cannot "
            'make -- by far the most common cause of denial runs" and "A newly created '
            "or newly scoped-down role exercising paths its old policy allowed, until the "
            'code catches up with the policy."'
        ),
    ),
    "W11": Workflow(
        id="W11",
        name=(
            "Routine service automation: scheduled Lambda (hourly) + one SSM RunCommand "
            "per day"
        ),
        cadence="24+1 /day",
        services="lambda, ssm, logs, read + write",
        rules="none expected; establishes the AWSService background rate",
    ),
    "W12": Workflow(
        id="W12",
        name=(
            "Malformed-policy iteration: an engineer hand-edits a trust policy, platform "
            "rejects it 6 times before accepting"
        ),
        cadence="7 calls, one session, day 8",
        services="iam, write, decision=failed",
        rules=(
            'AWS-006 expected ("An engineer iterating on a trust policy or a permission '
            'boundary by hand until the platform accepts it.")'
        ),
    ),
    "W13": Workflow(
        id="W13",
        name=(
            "Lockout episode: carol mistypes 12 times in 6 minutes, then resets and logs in"
        ),
        cadence="13 events, day 6",
        services="signin",
        rules=(
            'ATH-005 expected, HIGH ("A user whose phone or mapped drive holds an old '
            'password after a reset"; "Account lockout thresholds causing repeated '
            'failures after a single mistake.")'
        ),
    ),
}


@dataclass(frozen=True)
class Actor:
    """One of the plan's four identity types, with the ARN shape CloudTrail will show.

    ``arn`` is a template over ``{account}``. ``principal_names`` is what
    ``ath.telemetry.cloudtrail_source._principal`` will put in the canonical ``actor`` /
    ``user`` column for this identity: an IAM user's ``userName``, an assumed role's
    *session name* (the ARN's last segment) with the role name as the sessionIssuer
    fallback, and a service principal's ``invokedBy``. ``validate_dev.py`` matches rows
    to sessions through exactly these, so the mapping is written down once, here.
    """

    key: str
    arn: str
    actor_type: str
    principal_names: tuple  # type: ignore[type-arg]


def _role(role_name: str, session_name: str) -> Actor:
    return Actor(
        key=role_name,
        arn="arn:aws:sts::{account}:assumed-role/" + role_name + "/" + session_name,
        actor_type="AssumedRole",
        principal_names=(session_name, role_name),
    )


ACTORS = {
    "root": Actor(
        key="root", arn="arn:aws:iam::{account}:root", actor_type="Root",
        principal_names=("root",),
    ),
    "alice": Actor(
        key="alice", arn="arn:aws:iam::{account}:user/alice", actor_type="IAMUser",
        principal_names=("alice",),
    ),
    "bob": Actor(
        key="bob", arn="arn:aws:iam::{account}:user/bob", actor_type="IAMUser",
        principal_names=("bob",),
    ),
    "carol": Actor(
        key="carol", arn="arn:aws:iam::{account}:user/carol", actor_type="IAMUser",
        principal_names=("carol",),
    ),
    "AdminRole": _role("AdminRole", "ath-m20-admin"),
    "DeveloperRole": _role("DeveloperRole", "ath-m20-dev"),
    "DeployRole": _role("DeployRole", "ath-m20-deploy"),
    "AuditRole": _role("AuditRole", "ath-m20-audit"),
    "ReportingRole": _role("ReportingRole", "ath-m20-reporting"),
    "lambda": Actor(
        key="lambda", arn="lambda.amazonaws.com", actor_type="AWSService",
        principal_names=("lambda.amazonaws.com",),
    ),
    "ssm": Actor(
        key="ssm", arn="ssm.amazonaws.com", actor_type="AWSService",
        principal_names=("ssm.amazonaws.com",),
    ),
}


# --------------------------------------------------------------------------------------
# The plan's section 3 schedule, as data
# --------------------------------------------------------------------------------------

#: The plan's 14-row schedule table, quoted verbatim. Not decoration: the generated
#: sessions are checked against it in :func:`verify_schedule_covers_plan`, so this text
#: is the specification the tables below are tested against.
SCHEDULE_TABLE = (
    (1, "account + trail setup (Root, once); W01, W03, W11 begin and run daily from here"),
    (2, "W04 session 1 (onboard a user), W06 session 1, W09"),
    (3, "W07 sessions 1-2, W02, W09"),
    (4, "W08 run 1, W06 session 2, W09"),
    (5, "W05 session 1, W07 session 3, W09"),
    (6, "**W13 lockout episode**, W02, W09"),
    (7, "quiet day: W01, W11, W09 only -- the weekend baseline"),
    (8, "**W12 policy iteration**, W04 session 2, W09"),
    (9, "W08 run 2, W10 begins and runs daily from here, W09"),
    (10, "W06 session 3, W07 session 4, W09, W10"),
    (11, "W05 session 2, W08 run 3, W09, W10"),
    (12, "W04 session 3 (offboard a user -- AWS-005), W09, W10"),
    (13, "quiet day: W01, W11, W09, W10"),
    (14, "W08 run 4 + full teardown, W06 terminate, W07 delete bucket, W09, W10"),
)

QUIET_DAYS = (7, 13)

#: Workflows the plan says run every day from a given day. ``W03`` is absent on the two
#: quiet days: see the module docstring, ambiguity 1.
DAILY = (
    # workflow, actor key, planned start (UTC), minutes, days
    ("W01", "alice", "08:30", 30, tuple(range(1, 15))),
    ("W01", "bob", "13:00", 30, tuple(range(1, 15))),
    ("W03", "alice", "09:30", 480,
     tuple(d for d in range(1, 15) if d not in QUIET_DAYS)),
    ("W11", "lambda", "00:00", 1439, tuple(range(1, 15))),
    ("W11", "ssm", "12:00", 15, tuple(range(1, 15))),
    ("W09", "AuditRole", "02:00", 10, tuple(range(2, 15))),
    ("W10", "ReportingRole", "06:00", 10, tuple(range(9, 15))),
)

#: Every session the schedule table names on a specific day. The label is the table's
#: own wording for that session.
SPECIFIC = (
    # day, workflow, actor key, planned start (UTC), minutes, label
    (1, "SETUP", "root", "09:00", 120, "account + trail setup (Root, once)"),
    (2, "W04", "AdminRole", "10:00", 60, "session 1 (onboard a user)"),
    (2, "W06", "DeveloperRole", "14:00", 45, "session 1"),
    (3, "W07", "DeveloperRole", "10:30", 30, "session 1"),
    (3, "W07", "DeveloperRole", "15:00", 30, "session 2"),
    (3, "W02", "carol", "09:15", 15, "console login without MFA"),
    (4, "W08", "DeployRole", "13:00", 60, "run 1"),
    (4, "W06", "DeveloperRole", "14:00", 45, "session 2"),
    (5, "W05", "AdminRole", "11:00", 45, "session 1"),
    (5, "W07", "DeveloperRole", "10:30", 30, "session 3"),
    # W13 owns 09:00-09:20 on day 6, so day 6's W02 login is placed after it: two
    # sessions of the same actor may not overlap (verify_no_actor_overlap).
    (6, "W13", "carol", "09:00", 20, "lockout episode"),
    (6, "W02", "carol", "11:00", 15, "console login without MFA"),
    (8, "W12", "bob", "15:30", 30, "policy iteration"),
    (8, "W04", "AdminRole", "10:00", 60, "session 2"),
    (9, "W08", "DeployRole", "13:00", 60, "run 2"),
    (10, "W06", "DeveloperRole", "14:00", 45, "session 3"),
    (10, "W07", "DeveloperRole", "10:30", 30, "session 4"),
    (11, "W05", "AdminRole", "11:00", 45, "session 2"),
    (11, "W08", "DeployRole", "13:00", 60, "run 3"),
    (12, "W04", "AdminRole", "10:00", 60, "session 3 (offboard a user -- AWS-005)"),
    (14, "W08", "DeployRole", "13:00", 60, "run 4 + full teardown"),
    (14, "W06", "DeveloperRole", "15:00", 30, "terminate"),
    (14, "W07", "DeveloperRole", "16:00", 30, "delete bucket"),
)


@dataclass(frozen=True)
class PlannedSession:
    """One row of ``sessions.csv``, before any actual time is known."""

    session_id: str
    workflow_id: str
    actor_arn: str
    actor_type: str
    planned_start_utc: str
    planned_end_utc: str
    day: int
    label: str

    def as_row(self) -> dict:
        return {
            "session_id": self.session_id,
            "workflow_id": self.workflow_id,
            "actor_arn": self.actor_arn,
            "actor_type": self.actor_type,
            "planned_start_utc": self.planned_start_utc,
            "planned_end_utc": self.planned_end_utc,
            "day": str(self.day),
            "actual_start_utc": "",
            "actual_end_utc": "",
            # The label is the schedule table's own wording for this session. It lives
            # in notes because notes is the append-only free-text column; `record`
            # appends to it rather than replacing it.
            "notes": "planned: " + self.label,
            "status": "planned",
        }


def parse_start_date(value: str) -> datetime:
    """Day 1, 00:00 UTC. ``YYYY-MM-DD``; anything else is a caller error."""
    try:
        return datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise SystemExit("--start-date must be YYYY-MM-DD, got {0!r}: {1}".format(value, exc))


def _window(start_date: datetime, day: int, hhmm: str, minutes: int) -> tuple:
    hour, minute = (int(part) for part in hhmm.split(":"))
    begin = start_date + timedelta(days=day - 1, hours=hour, minutes=minute)
    end = begin + timedelta(minutes=minutes)
    return begin.strftime(TIME_FORMAT), end.strftime(TIME_FORMAT)


def planned_sessions(
    start_date: datetime, account_id: str = ACCOUNT_PLACEHOLDER,
) -> list:
    """Every planned session, deterministically ordered and deterministically numbered.

    Order is (day, planned start, workflow id, actor key) and the occurrence number is
    the 1-based position within a (day, workflow) group in that order. Deterministic ids
    matter because they are quoted in the workflow scripts, in the operator checklist
    and in the report; a re-run of ``plan`` that renumbered them would break every
    reference at once.
    """
    raw = list(SPECIFIC)
    for workflow_id, actor_key, hhmm, minutes, days in DAILY:
        for day in days:
            raw.append((day, workflow_id, actor_key, hhmm, minutes, "daily"))

    raw.sort(key=lambda entry: (entry[0], entry[3], entry[1], entry[2]))

    counters = {}
    sessions = []
    for day, workflow_id, actor_key, hhmm, minutes, label in raw:
        if workflow_id not in WORKFLOWS:
            raise SystemExit(
                "schedule names workflow {0!r}, which is not in the catalogue".format(workflow_id)
            )
        actor = ACTORS[actor_key]
        counters[(day, workflow_id)] = counters.get((day, workflow_id), 0) + 1
        start, end = _window(start_date, day, hhmm, minutes)
        sessions.append(PlannedSession(
            session_id="D{0:02d}-{1}-{2}".format(day, workflow_id, counters[(day, workflow_id)]),
            workflow_id=workflow_id,
            actor_arn=actor.arn.format(account=account_id),
            actor_type=actor.actor_type,
            planned_start_utc=start,
            planned_end_utc=end,
            day=day,
            label="{0} [{1}]".format(label, actor.key),
        ))
    return sessions


# --------------------------------------------------------------------------------------
# Self-checks: the generated schedule against the plan's own words
# --------------------------------------------------------------------------------------


def _workflow_ids_in(text: str) -> set:
    return set(token for token in WORKFLOWS if token != "SETUP" and token in text)


def verify_schedule_covers_plan(sessions: Sequence) -> None:
    """Check the generated sessions against :data:`SCHEDULE_TABLE`, both directions.

    Forward: every workflow the plan's table names on a day has at least one session on
    that day. Backward: every session on a day is either named in that day's row or is
    one of the daily workflows the plan says "run daily from here" (plus ``SETUP``,
    which is day 1's Root row).

    Raises:
        SystemExit: with the days and workflow ids that disagree. A schedule that has
            drifted from the plan it quotes is not one anybody can pre-register.
    """
    by_day = {}
    for session in sessions:
        by_day.setdefault(session.day, set()).add(session.workflow_id)

    daily_ids = set(workflow_id for workflow_id, _a, _h, _m, _d in DAILY)
    problems = []
    for day, text in SCHEDULE_TABLE:
        named = _workflow_ids_in(text)
        scheduled = by_day.get(day, set())
        missing = sorted(named - scheduled)
        if missing:
            problems.append(
                "day {0}: plan names {1} but no session was generated".format(day, missing)
            )
        extra = sorted(scheduled - named - daily_ids - set(["SETUP"]))
        if extra:
            problems.append(
                "day {0}: generated {1}, which the plan's row does not name".format(day, extra)
            )
    covered_days = set(day for day, _ in SCHEDULE_TABLE)
    if set(by_day) != covered_days:
        problems.append(
            "days generated {0} != days in the plan {1}".format(sorted(by_day), sorted(covered_days))
        )
    if problems:
        raise SystemExit(
            "sessions.py: generated schedule disagrees with the plan:\n  " + "\n  ".join(problems)
        )


def verify_no_actor_overlap(sessions: Sequence) -> None:
    """No two planned sessions of the same actor overlap in time.

    ``validate_dev.py`` attributes a telemetry row to a session by (actor, time window).
    If one actor had two overlapping windows a row could belong to both, and the
    coverage number would stop meaning anything. Enforced here, at plan time, because
    that is the only moment at which it can still be fixed for free.

    Raises:
        SystemExit: naming the two sessions that overlap.
    """
    by_actor = {}
    for session in sessions:
        by_actor.setdefault(session.actor_arn, []).append(session)
    for actor, group in sorted(by_actor.items()):
        ordered = sorted(group, key=lambda s: s.planned_start_utc)
        for earlier, later in zip(ordered, ordered[1:]):
            if later.planned_start_utc < earlier.planned_end_utc:
                raise SystemExit(
                    "sessions.py: {0} has overlapping planned sessions {1} ({2}..{3}) "
                    "and {4} ({5}..)".format(
                        actor, earlier.session_id, earlier.planned_start_utc,
                        earlier.planned_end_utc, later.session_id, later.planned_start_utc,
                    )
                )


# --------------------------------------------------------------------------------------
# plan
# --------------------------------------------------------------------------------------


def write_plan(path: Path, start_date: datetime, account_id: str) -> list:
    """Write ``sessions.csv``. Refuses to overwrite (INV-2).

    Raises:
        SystemExit: if ``path`` exists. Regenerating over a file that may already carry
            recorded actual times would delete the record of what happened and, worse,
            would let the plan itself be rewritten after the fact -- the one thing
            pre-registration exists to prevent.
    """
    if path.exists():
        raise SystemExit(
            "{0} already exists. sessions.csv is written once, before collection, and "
            "annotated afterwards with `record`. Delete it by hand if you are genuinely "
            "re-planning before day 1.".format(path)
        )
    sessions = planned_sessions(start_date, account_id)
    verify_schedule_covers_plan(sessions)
    verify_no_actor_overlap(sessions)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(COLUMNS), lineterminator="\n")
        writer.writeheader()
        for session in sessions:
            writer.writerow(session.as_row())
    return sessions


# --------------------------------------------------------------------------------------
# record
# --------------------------------------------------------------------------------------


def read_sessions(path: Path) -> list:
    """Read ``sessions.csv``, refusing a file whose columns are not the declared ones."""
    if not path.exists():
        raise SystemExit(
            "{0} does not exist. Run `sessions.py plan` before collection.".format(path)
        )
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if list(reader.fieldnames or ()) != list(COLUMNS):
            raise SystemExit(
                "{0}: columns {1} != {2}. Refusing to write a file whose shape is not "
                "the predeclared one.".format(path, reader.fieldnames, list(COLUMNS))
            )
        return [dict(row) for row in reader]


def _validate_time(value: str, flag: str) -> str:
    try:
        datetime.strptime(value, TIME_FORMAT)
    except ValueError as exc:
        raise SystemExit(
            "{0} must be {1} (UTC), got {2!r}: {3}".format(flag, TIME_FORMAT, value, exc)
        )
    return value


def record_session(
    path: Path,
    session_id: str,
    actual_start: Optional[str] = None,
    actual_end: Optional[str] = None,
    notes: Optional[str] = None,
    status: Optional[str] = None,
) -> dict:
    """Annotate one planned session. Append-only (INV-2).

    Four refusals, each one a way the log could otherwise stop being a record of what
    was planned:

    * unknown ``session_id`` -- a session nobody predeclared cannot be recorded, so a
      typo surfaces now rather than as a mysterious gap in coverage later;
    * a planned column would change -- checked over *every* row after the edit, not
      just the one touched, so a bug in this function cannot quietly rewrite the plan;
    * an actual time already recorded would be contradicted -- correct it with a note,
      which keeps both values;
    * a terminal status (``done``/``skipped``) would be replaced by a different one.

    ``notes`` is appended with ``" | "``, never replaced.

    Returns:
        The row as it now stands.
    """
    rows = read_sessions(path)
    before = [dict((column, row[column]) for column in PLANNED_COLUMNS) for row in rows]

    index = None
    for position, row in enumerate(rows):
        if row["session_id"] == session_id:
            index = position
            break
    if index is None:
        known = ", ".join(sorted(row["session_id"] for row in rows)[:6])
        raise SystemExit(
            "unknown session id {0!r}. sessions.csv holds {1} planned sessions "
            "(e.g. {2}...); `record` annotates a planned session and never creates "
            "one.".format(session_id, len(rows), known)
        )
    row = rows[index]

    if status is not None:
        if status not in STATUSES:
            raise SystemExit(
                "--status must be one of {0}, got {1!r}".format(list(STATUSES), status)
            )
        current = row["status"]
        if current in TERMINAL_STATUSES and status != current:
            raise SystemExit(
                "{0} is already {1!r}; refusing to change it to {2!r}. Add a note "
                "instead -- the log records what was declared and what happened, not "
                "the latest opinion.".format(session_id, current, status)
            )
        row["status"] = status

    for value, column, flag in (
        (actual_start, "actual_start_utc", "--actual-start"),
        (actual_end, "actual_end_utc", "--actual-end"),
    ):
        if value is None:
            continue
        _validate_time(value, flag)
        existing = row[column]
        if existing and existing != value:
            raise SystemExit(
                "{0} already records {1}={2!r}; refusing to overwrite it with {3!r}. "
                "Record the correction as a note.".format(session_id, column, existing, value)
            )
        row[column] = value

    if notes:
        row["notes"] = (row["notes"] + " | " + notes) if row["notes"] else notes

    after = [dict((column, r[column]) for column in PLANNED_COLUMNS) for r in rows]
    if after != before or len(rows) != len(before):
        raise SystemExit(
            "{0}: a planned column changed while recording {1}. Refusing to "
            "write.".format(path, session_id)
        )

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(COLUMNS), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return row


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------


def _print_summary(sessions: Iterable, path: Path) -> None:
    sessions = list(sessions)
    per_workflow = {}
    for session in sessions:
        per_workflow[session.workflow_id] = per_workflow.get(session.workflow_id, 0) + 1
    print("wrote {0} -- {1} planned sessions over 14 days".format(path, len(sessions)))
    for workflow_id in sorted(per_workflow):
        print("  {0}: {1:3d} session(s)  {2}".format(
            workflow_id, per_workflow[workflow_id], WORKFLOWS[workflow_id].name[:64],
        ))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command")

    plan = sub.add_parser("plan", help="write the predeclared sessions.csv (once, before day 1)")
    plan.add_argument("--start-date", required=True, help="day 1, YYYY-MM-DD (UTC)")
    plan.add_argument("--account-id", default=ACCOUNT_PLACEHOLDER,
                      help="12-digit account id for the ARNs; defaults to a placeholder")
    plan.add_argument("--out", type=Path, default=DEFAULT_SESSIONS_CSV)

    record = sub.add_parser("record", help="annotate a planned session (append-only)")
    record.add_argument("--session-id", required=True)
    record.add_argument("--sessions", type=Path, default=DEFAULT_SESSIONS_CSV)
    record.add_argument("--actual-start", default=None, help=TIME_FORMAT)
    record.add_argument("--actual-end", default=None, help=TIME_FORMAT)
    record.add_argument("--notes", default=None)
    record.add_argument("--status", default=None, choices=list(STATUSES))

    args = parser.parse_args(argv)
    if args.command is None:
        parser.error("a subcommand is required: plan, record")
    if args.command == "plan":
        sessions = write_plan(args.out, parse_start_date(args.start_date), args.account_id)
        _print_summary(sessions, args.out)
        return 0

    row = record_session(
        args.sessions, args.session_id, args.actual_start, args.actual_end,
        args.notes, args.status,
    )
    print("{0} {1} status={2} actual={3}..{4}".format(
        row["session_id"], row["workflow_id"], row["status"],
        row["actual_start_utc"] or "-", row["actual_end_utc"] or "-",
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
