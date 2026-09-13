"""Shared pieces of the M20 measurement scripts: loading, sealing guards, actor matching.

Three things ``validate_dev.py`` and ``measure_dev.py`` both need, kept in one place so
the sealing guard cannot be enforced in one script and forgotten in the other:

* :func:`refuse_holdout` -- a hard refusal of any path that mentions the holdout;
* :func:`holdout_gate` -- the pre-registration check that is the *only* way a holdout
  path may ever be measured (INV-4);
* :func:`principal_names` -- how a ``sessions.csv`` actor ARN maps onto the principal
  string CloudTrail rows actually carry.
"""

from __future__ import annotations

import re
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

DEFAULT_PREREGISTRATION = ROOT / "reports" / "m20" / "PREREGISTERED.md"

#: Section 5's template writes every unfilled number as a run of underscores ("N events
#: = ____", "ATH-005 __"). A document still containing one is a document whose
#: predictions have not been made.
BLANK_PATTERN = re.compile(r"_{2,}")

TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


# --------------------------------------------------------------------------------------
# Sealing guards (INV-1 / INV-4)
# --------------------------------------------------------------------------------------


def mentions_holdout(path: Path) -> bool:
    """Whether a path names the sealed side, anywhere in it and in any case."""
    return "holdout" in str(path).replace("\\", "/").lower()


def refuse_holdout(path: Path, tool: str) -> None:
    """Refuse a holdout path outright.

    Used by the validator, which has no legitimate reason to touch the sealed side at
    any point in the experiment: its whole job is "did the development split contain
    what the schedule said it would".

    Raises:
        SystemExit: naming the path.
    """
    if mentions_holdout(path):
        raise SystemExit(
            "{0}: {1} names the sealed holdout. Section 4 of the plan: no ATH code is "
            "run against the holdout -- not the adapter, not a probe, not a row count. "
            "This tool has no holdout mode.".format(tool, path)
        )


def unfilled_blanks(text: str) -> list:
    """The lines of a pre-registration that still carry an unfilled blank."""
    return [
        line.strip() for line in text.splitlines() if BLANK_PATTERN.search(line)
    ]


def holdout_gate(path: Path, preregistration: Path, tool: str) -> None:
    """Allow a holdout path only once the prediction is committed and complete (INV-4).

    The plan fixes the order: section 5's template is "Committed to
    ``reports/m20/PREREGISTERED.md`` **before** the holdout is opened", and its decision
    rule is "fixed before opening". So the gate is not "does a file exist" but "does a
    file exist with every number filled in" -- a template committed with its blanks
    still in it would satisfy the first and defeat the second, because the blanks could
    then be filled after the measurement.

    Raises:
        SystemExit: if the path names the holdout and the pre-registration is missing or
            still has blanks. Lists the offending lines, so the operator knows exactly
            what is left to predict.
    """
    if not mentions_holdout(path):
        return
    if not preregistration.exists():
        raise SystemExit(
            "{0}: {1} names the sealed holdout and {2} does not exist. Commit the "
            "section 5 pre-registration first -- that is the whole experiment.".format(
                tool, path, preregistration,
            )
        )
    blanks = unfilled_blanks(preregistration.read_text(encoding="utf-8"))
    if blanks:
        raise SystemExit(
            "{0}: {1} still contains {2} unfilled blank(s), so the predictions have not "
            "been made:\n  {3}".format(
                tool, preregistration, len(blanks), "\n  ".join(blanks[:8]),
            )
        )


# --------------------------------------------------------------------------------------
# Actors
# --------------------------------------------------------------------------------------


def principal_names(actor_arn: str) -> set:
    """The principal strings CloudTrail rows will carry for one ``sessions.csv`` actor.

    ``ath.telemetry.cloudtrail_source._principal`` prefers ``userIdentity.userName``,
    falls back to the ARN's last segment (which for an assumed role is the *session*
    name, not the role name), then to ``sessionContext.sessionIssuer.userName`` (the
    role name) and finally to ``invokedBy`` (a service principal). All four are
    therefore accepted here, because which one a given row carries depends on how the
    call was made, not on who made it:

    * ``arn:aws:iam::<a>:user/alice``                 -> ``{"alice"}``
    * ``arn:aws:iam::<a>:root``                       -> ``{"root"}``
    * ``arn:aws:sts::<a>:assumed-role/AdminRole/s1``  -> ``{"s1", "AdminRole"}``
    * ``lambda.amazonaws.com``                        -> ``{"lambda.amazonaws.com"}``

    Matching is case-insensitive on the caller's side; the names are returned lowercased.
    """
    value = actor_arn.strip()
    if not value:
        return set()
    if not value.startswith("arn:"):
        return {value.lower()}
    resource = value.split(":", 5)[-1]
    parts = [part for part in resource.split("/") if part]
    names = set()
    if not parts:
        return names
    if parts[0] == "assumed-role" and len(parts) >= 2:
        names.add(parts[-1].lower())   # session name
        names.add(parts[1].lower())    # role name
    elif parts[0] in ("user", "role", "group") and len(parts) >= 2:
        names.add(parts[-1].lower())
    else:
        names.add(parts[-1].lower())
    return names


def parse_utc(value: str, what: str) -> datetime:
    """Parse a ``sessions.csv`` timestamp, accepting the two forms operators type."""
    text = value.strip()
    for fmt in (TIME_FORMAT, "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    raise SystemExit("{0}: cannot parse {1!r} as a UTC timestamp".format(what, value))


# --------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------


def load_cloudtrail(directory: Path):
    """Load a directory of CloudTrail files through the adapter the CLI uses.

    Returns:
        ``(telemetry, result)`` -- the canonical :class:`ath.telemetry.loader.Telemetry`
        and the raw :class:`ath.telemetry.source.SourceLoadResult`, because the load
        result's admissions and issues are themselves part of what the validator
        reports: a delivered file the adapter refused is a gap in the corpus, not a
        detail of the import.
    """
    from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS
    from ath.telemetry.cloudtrail_source import CloudTrailSource
    from ath.telemetry.loader import Telemetry

    result = CloudTrailSource(directory).load()
    tables = result.tables
    telemetry = Telemetry(
        processes=tables[EVENT_PROCESS], network=tables[EVENT_NETWORK],
        logons=tables[EVENT_LOGON], controls=tables[EVENT_CONTROL],
    )
    return telemetry, result
