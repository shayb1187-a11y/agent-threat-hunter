"""Import AWS CloudTrail management events.

This adapter exists to stress-test the canonical schema against telemetry it was not
designed around. The Defender adapter proved the ``TelemetrySource`` seam works for a
*second Windows endpoint product*; that is a much weaker claim than it looks, because
Defender's advanced-hunting tables are the shape the canonical schema was modelled on.
CloudTrail is genuinely different, and the useful output of this module is as much the
**documented failure to map** as the mapping itself.

What maps cleanly
-----------------
**Authentication.** ``ConsoleLogin``, ``AssumeRole``, ``GetSessionToken`` and
``GetFederationToken`` are recognisably logon events: a principal, a source address, a
timestamp, and a success/failure verdict. These become canonical logon rows, and
``ATH-005`` (failed-logon burst followed by success) then fires on them **with no
change to the rule** -- because it keys on ``action``, ``user`` and ``source_ip`` and
never reads a Windows-specific field.

What now maps to the control-plane table
------------------------------------------
**Every other management API call.** These used to have no home in this schema, and the
tempting mapping was actively harmful::

    process_name        = <the API name>         # not a process
    parent_process_name = "iam.amazonaws.com"    # not a parent process
    process_id          = <invented>             # no such concept

Beyond being a bad analogy, it would have corrupted the visibility model: filling the
process table would make :mod:`ath.environment.channels` report ``process_execution`` as
**available** for an environment with no endpoint telemetry whatsoever.

``ath.schema.EVENT_CONTROL`` exists precisely so this does not happen: an actor performs
a verb on a resource, allowed or denied -- the same shape AWS management events and
Kubernetes audit events both have, without borrowing endpoint vocabulary for either.

**Why the API names are not enumerated.** This adapter used to hold a list of five API
names and refuse everything else, which measured as: 2 of 2,349 records (0.09%) ingested
from a real AWS attack capture, and 96 of 1.9M from a public trail. The rules were never
given the attack. An allowlist cannot be fixed by lengthening it -- AWS ships new API
names continuously, and any list is a list of the calls somebody already had an opinion
about, which is precisely the wrong input to a layer whose job is to describe.

So an event name is *parsed*, not looked up. Every CloudTrail name in both corpora --
1,241 of 1,242 distinct names on the public trail -- has the form ``VerbResourceNoun``,
and that is all the structure needed:

    ``eventName``    -> ``verb`` (first word, lowercased) + resource family (the rest,
                        singular kebab-case, with any trailing API-version suffix cut)
    ``eventSource``  -> service (the name minus ``.amazonaws.com``, kept literal)
    ``resource_type``-> ``"<service>:<family>"``, or just the service for a name with no
                        noun at all

Nothing here knows what any particular call *does*, and that is the property worth
keeping: a call nobody has ever heard of is represented exactly as well as a famous one.
Grouping verbs into kinds of action (read / create / grant / ...) is a separate question
answered a layer up, in :mod:`ath.behavior.control_plane`, where consumers can ask it --
representation must not depend on it.

**Actor vs. target.** A grant-shaped call names a *beneficiary* (the
``userName``/``roleName``/``groupName`` parameter) that is frequently a different
identity from the caller (``userIdentity``) making the API call: an administrator
attaching a policy to someone else's account is the normal case, not the exception.
``actor`` is always the caller; ``target_actor`` is the beneficiary, left empty for calls
that name no identity. Conflating the two would make a privilege-escalation chain match
the wrong identity's later activity -- see ``ath.hunting.rules.aws_rules``. This too is a
convention over ``requestParameters``, applied to the IAM service rather than to a list
of call names.

**Network flow.** CloudTrail records the *caller's* address, not connections a workload
opened. Mapping ``sourceIPAddress`` into the network table would describe traffic that
was never observed.

``logon_type`` has no cloud equivalent
---------------------------------------
The canonical schema stores the numeric **Windows** logon type. There is no such thing
for a console login, so this adapter leaves it null rather than inventing a code. That
is not a gap to paper over: it is why ``ATH-006`` (which infers host ownership from
interactive-vs-network logon types) correctly declines to fire here, while ``ATH-005``
correctly does. A forced value would have silently switched that off.

``device`` is a synthesised account/region identifier
------------------------------------------------------
"Host" is not a natural concept in control-plane telemetry -- an API call happens to an
*account*, not on a machine. Rows carry ``aws:<accountId>/<region>`` so downstream code
that groups by device still works, but the environment model will correctly classify it
as an unknown role: no interactive session, no inbound authentication, because neither
concept applies.
"""

from __future__ import annotations

import gzip
import json
import re
import tarfile
from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import pandas as pd

from ath.logging_setup import get_logger
from ath.schema import (
    EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS, TABLE_COLUMNS,
)
from ath.telemetry.admission import (
    FileAdmission,
    ParsedFile,
    SNIFF_RECORDS,
    admit_parsed,
)
from ath.telemetry.normalize import (
    coerce_and_validate,
    coerce_validate_and_quarantine,
    parse_event_time,
)
from ath.telemetry.source import NormalizationIssue, SourceLoadResult, TelemetrySource

logger = get_logger(__name__)

SOURCE_NAME = "cloudtrail"
# Distinct provenance value for management-plane rows on the control table, so
# CLOUD_CONTROL_PLANE (authentication) and CLOUD_MANAGEMENT_ACTIVITY (everything below)
# stay measurably different channels -- see ath.environment.channels.
MANAGEMENT_SOURCE_NAME = "cloudtrail_mgmt"

# Events that genuinely represent an authentication decision, and how to read the
# verdict from each. CloudTrail is not uniform about this: ConsoleLogin reports its
# outcome in `responseElements.ConsoleLogin`, while STS calls signal failure only by
# the presence of `errorCode`.
AUTH_EVENTS: frozenset[str] = frozenset(
    {"ConsoleLogin", "AssumeRole", "GetSessionToken", "GetFederationToken"}
)


TELEMETRY_NAME = "AWS CloudTrail records"


def _looks_like_record(record: Any) -> bool:
    """Does this object carry the fields that identify a CloudTrail record?

    ``eventVersion``, ``eventName`` and ``eventTime`` -- the three every record in every
    corpus this project reads carries (verified on attack_data_aws' NDJSON captures and
    on all of flaws.cloud's 1.9M records), and the three this adapter already depends on:
    ``eventName`` is the dispatch key in :meth:`CloudTrailSource.load`, ``eventTime`` is
    read by :func:`_normalise_auth_record` and :func:`_normalise_control_record`, and
    ``eventVersion`` is what makes the record self-identifying as CloudTrail rather than
    merely as "a JSON object with a name and a time".

    Presence only. A record naming an event this adapter does not map, or carrying an
    unparseable ``eventTime``, is still CloudTrail: it is refused per record, with its own
    issue, by the layer above.
    """
    if not isinstance(record, dict):
        return False
    return all(key in record for key in ("eventVersion", "eventName", "eventTime"))


# The service suffix every AWS event source carries. Removed, and nothing else is: no
# aliasing, so "monitoring" stays "monitoring" rather than becoming "cloudwatch". An
# alias table is an allowlist wearing a different hat, and it would make the family of a
# resource depend on whether somebody had gotten round to adding the service yet.
_SERVICE_SUFFIX = ".amazonaws.com"
_UNKNOWN_SERVICE = "unknown"

# The first word of an event name, when the name begins with a capitalised word followed
# by another capital or a digit: the verb, and everything after it is the resource noun.
_VERB_AND_NOUN = re.compile(r"^([A-Z][a-z]+)(?=[A-Z0-9])(.*)$", re.DOTALL)
# A name that is one capitalised word and nothing else: a verb with no noun.
_VERB_ONLY = re.compile(r"^[A-Z][a-z]+$")

# A trailing API-version stamp on the resource noun -- the dated variants AWS ships when
# a call's shape changes ("...20150331", "...2020_05_31", "...2015_03_31v2"). It is a
# property of the API's wire contract, not of the resource, and leaving it on would split
# one resource family across as many families as the service has API revisions.
_VERSION_SUFFIX = re.compile(r"[vV]?\d[\d_]*(?:[vV]\d+)?$")

# Words inside a CamelCase noun, acronym runs kept whole: "DBInstances" -> DB, Instances;
# "SAMLProvider" -> SAML, Provider.
_NOUN_WORDS = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+")

# English plurals this project's -s rules get wrong, as words rather than as API names.
# Five entries, not a dictionary: anything longer would be an allowlist again.
_IRREGULAR_PLURALS: dict[str, str] = {
    "aliases": "alias",
    "statuses": "status",
    "analyses": "analysis",
    "indices": "index",
    "vertices": "vertex",
}


def _singular(word: str) -> str:
    """The singular of one lowercase English word, by suffix rules only.

    The rules, in order, and what each is for:

    ``aliases`` -> ``alias``
        The handful of irregular plurals above, checked first.
    ``status``, ``access``, ``analysis``
        A word ending ``-us``, ``-ss`` or ``-is`` is left alone. These are the endings
        that *look* plural and are not, and stripping them is how a "family" column ends
        up holding ``statu`` and ``acces``.
    ``policies`` -> ``policy``, ``repositories`` -> ``repository``
        ``-ies`` becomes ``-y``.
    ``addresses`` -> ``address``, ``branches`` -> ``branch``, ``boxes`` -> ``box``
        ``-es`` after a sibilant (``ss``, ``sh``, ``ch``, ``x``, ``z``) is the whole
        plural marker.
    ``instances`` -> ``instance``, ``keys`` -> ``key``, ``databases`` -> ``database``
        Otherwise a trailing ``-s`` is the plural marker.
    """
    if word in _IRREGULAR_PLURALS:
        return _IRREGULAR_PLURALS[word]
    if not word.endswith("s") or word.endswith(("ss", "us", "is")):
        return word
    if word.endswith("ies") and len(word) > 4:
        return word[:-3] + "y"
    if word.endswith(("sses", "shes", "ches", "xes", "zes")):
        return word[:-2]
    return word[:-1]


def _family(noun: str) -> str:
    """A resource noun as a singular kebab-case family: ``UserPolicies`` -> ``user-policy``.

    The version stamp goes first (so ``Functions20150331`` and ``Functions`` are one
    family), then the noun is split on CamelCase boundaries with acronym runs kept whole,
    and only the **last** word is singularised -- ``AccessKeys`` is a kind of key, not a
    kind of access.
    """
    noun = _VERSION_SUFFIX.sub("", noun)
    words = [word.lower() for word in _NOUN_WORDS.findall(noun)]
    if not words:
        return ""
    words[-1] = _singular(words[-1])
    return "-".join(words)


@dataclass(frozen=True)
class ParsedEventName:
    """One event name read as a verb and a resource family.

    Attributes:
        verb: The first word of the name, lowercased. For a name with no capitalised
            first word, the whole name lowercased -- a row still gets a verb.
        family: The rest of the name as a singular kebab-case family, or ``""`` when the
            name is a bare verb (``Decrypt``) or was not parseable.
        parsed: Whether the name had the ``VerbNoun`` shape at all. ``False`` is reported
            as a normalisation issue *alongside* the row, so the fraction of names this
            morphology does not cover stays a visible number rather than an assumption.
    """

    verb: str
    family: str
    parsed: bool


@lru_cache(maxsize=None)
def parse_event_name(event_name: str) -> ParsedEventName:
    """Split an event name into a verb and a resource family.

    Cached because a trail names the same few thousand calls a few million times; the
    cache is bounded by the number of distinct names in the corpus (1,242 for the largest
    one this project reads), and it also keeps one string object per verb and family
    instead of one per row.
    """
    match = _VERB_AND_NOUN.match(event_name)
    if match is not None:
        return ParsedEventName(match.group(1).lower(), _family(match.group(2)), True)
    if _VERB_ONLY.match(event_name):
        return ParsedEventName(event_name.lower(), "", True)
    return ParsedEventName(event_name.lower(), "", False)


def _service(event_source: str) -> str:
    """The service an event source names: ``iam.amazonaws.com`` -> ``iam``."""
    if not event_source:
        return _UNKNOWN_SERVICE
    if event_source.endswith(_SERVICE_SUFFIX):
        return event_source[: -len(_SERVICE_SUFFIX)] or _UNKNOWN_SERVICE
    return event_source


@lru_cache(maxsize=None)
def resource_type_for(event_source: str, event_name: str) -> tuple[str, str, str]:
    """``(verb, resource_type, family)`` for one (source, name) pair.

    ``resource_type`` is ``"<service>:<family>"``, or the bare service when the name
    carries no resource noun -- a service with no family is a real answer ("something
    happened in KMS"), and inventing a family for it would be worse than saying so.
    """
    parsed = parse_event_name(event_name)
    service = _service(event_source)
    resource_type = f"{service}:{parsed.family}" if parsed.family else service
    return parsed.verb, resource_type, parsed.family


# Beneficiary and role, as conventions over `requestParameters` rather than as a fact
# about any particular call.
#
# `_TARGET_FIELDS` is ordered most-specific-identity-first: a call that names a user
# names that user as the beneficiary even if it also names the role or group the user is
# being put into. `_ROLE_FIELDS` is ordered by how completely the value identifies the
# thing granted -- a policy ARN is globally unique, a policy name is unique only within
# the identity it is attached to, a role ARN identifies a role being handed over, and an
# instance-profile name identifies only the vehicle a role is handed over *in*. Taking
# the first present of each is what makes "what was granted" a single column rather than
# a per-call decision.
_TARGET_FIELDS: tuple[str, ...] = ("userName", "roleName", "groupName")
_ROLE_FIELDS: tuple[str, ...] = ("policyArn", "policyName", "roleArn", "instanceProfileName")

# The identity service, whose `requestParameters` those conventions hold for. Read as a
# service, not as a set of call names: every call IAM has ever shipped names its
# beneficiary the same way, including the ones that do not exist yet.
_IDENTITY_SERVICE = "iam"

# The family whose calls target the caller when they name no one else: creating an access
# key with no `userName` creates one for yourself. A family-level rule, because it is
# true of every call on that family rather than of one call's name.
_SELF_TARGETING_FAMILY = "access-key"


@dataclass
class CloudTrailSource(TelemetrySource):
    """Read CloudTrail JSON files from a directory into canonical telemetry.

    Args:
        directory: Directory containing CloudTrail files. Each is expected to hold a
            top-level ``Records`` array, which is the shape both the console export and
            the S3 delivery format use. Three on-disk forms are read, because that is
            how CloudTrail actually arrives: plain ``*.json``, the gzipped
            ``*.json.gz`` that S3 delivery writes per hour, and ``*.tar`` bundles of
            either (how public research dumps such as flaws.cloud are distributed).
            Nothing is extracted to disk; members are decoded in memory one at a time.
    """

    directory: Path
    name: str = SOURCE_NAME

    def load(self) -> SourceLoadResult:
        if not self.directory.is_dir():
            raise FileNotFoundError(
                f"No CloudTrail *.json, *.json.gz or *.tar files found in "
                f"{self.directory}. Expected files containing a top-level 'Records' "
                "array."
            )
        files = sorted(
            p for p in self.directory.iterdir()
            if p.is_file() and _classify(p.name) is not None
        )
        if not files:
            raise FileNotFoundError(
                f"No CloudTrail *.json, *.json.gz or *.tar files found in "
                f"{self.directory}. Expected files containing a top-level 'Records' "
                "array."
            )

        logon_rows: list[tuple[Any, ...]] = []
        control_rows: list[tuple[Any, ...]] = []
        issues: list[NormalizationIssue] = []
        admissions: list[FileAdmission] = []
        rows_read = 0

        for file_name, parsed, records in _iter_payloads(files):
            # Shape first: a directory of hourly trail deliveries also holds whatever a
            # pipeline wrote about them, and those files end in .json too.
            admission = admit_parsed(
                file_name, parsed, _looks_like_record, telemetry=TELEMETRY_NAME,
            )
            admissions.append(admission)
            if not admission.admitted:
                continue

            for index, record in enumerate(records):
                rows_read += 1
                event_name = record.get("eventName", "") if isinstance(record, dict) else ""

                if event_name in AUTH_EVENTS:
                    row, issue = _normalise_auth_record(record, file_name, index)
                    target = logon_rows
                    columns = _LOGON_ORDER
                else:
                    # Everything that is not an authentication decision is management
                    # activity, and is represented rather than refused. What it *was* is
                    # read off the name's shape, not looked up.
                    row, issue = _normalise_control_record(record, file_name, index)
                    target = control_rows
                    columns = _CONTROL_ORDER

                if issue is not None:
                    issues.append(issue)
                if row is not None:
                    # Stored positionally, not as a dict per row. A real trail produces
                    # millions of control rows and a 17-key dict each would cost several
                    # times what the values themselves do.
                    target.append(tuple(row[column] for column in columns))

        logons, quarantined_logons = coerce_validate_and_quarantine(
            _frame(logon_rows, EVENT_LOGON, "cloudtrail-logon"), EVENT_LOGON,
        )
        controls, quarantined_controls = coerce_validate_and_quarantine(
            _frame(control_rows, EVENT_CONTROL, "cloudtrail-control"), EVENT_CONTROL,
        )
        issues.extend(quarantined_logons)
        issues.extend(quarantined_controls)
        tables = {
            EVENT_PROCESS: _empty(EVENT_PROCESS),
            EVENT_NETWORK: _empty(EVENT_NETWORK),
            EVENT_LOGON: logons,
            EVENT_CONTROL: controls,
        }

        rejected = [a for a in admissions if not a.admitted]
        logger.info(
            "CloudTrail import: %d file(s) admitted, %d rejected; %d record(s) read, "
            "%d authentication row(s) + %d management-activity row(s) kept, %d issue(s)",
            len(admissions) - len(rejected), len(rejected), rows_read,
            len(logon_rows), len(control_rows), len(issues),
        )
        for refusal in rejected:
            logger.warning("CloudTrail import: %s", refusal)
        return SourceLoadResult(
            tables=tables, issues=issues, rows_read=rows_read,
            admitted_files=tuple(admissions),
        )


def _classify(name: str) -> str | None:
    """Which reader a file name needs, or ``None`` when it is not CloudTrail input."""
    lowered = name.lower()
    if lowered.endswith(".json.gz"):
        return "gzip"
    if lowered.endswith(".json"):
        return "json"
    if lowered.endswith(".tar"):
        return "tar"
    return None


def _decode(name: str, raw: bytes) -> tuple[ParsedFile, list[Any]]:
    """Parse one CloudTrail document from bytes, gunzipping first when the name says so.

    Three on-the-wire shapes are accepted, and all three are normalised to the
    ``{"Records": [...]}`` form the caller expects:

    ``{"Records": [...]}``
        S3 delivery and console export. The original and still the common case.
    one JSON object per line
        How capture tools and research corpora hand out CloudTrail. Each line is one
        record.
    a single bare record
        A one-event capture, with ``eventVersion``/``eventName`` at the top level.

    This is an **ingestion-format** concern only. It changes which bytes can be read,
    never what is concluded from them: no rule, threshold, severity or correlation
    behaviour is involved, and a file that already parses as ``Records`` takes the first
    branch and is untouched. Added in M16 so held-out CloudTrail captures could be read
    at all -- without it they ingest zero rows and any result from them would be a
    statement about the reader, not about the detections.

    Returns:
        ``(parsed, records)``. ``parsed`` is what
        :func:`ath.telemetry.admission.admit_parsed` needs -- the shape recognised, the
        first records, the total count, and (when nothing parsed) what broke. ``records``
        is the full list, empty when the document was not recognised at all.
    """
    try:
        if _classify(name) == "gzip":
            raw = gzip.decompress(raw)
        text = raw.decode("utf-8")
    except (OSError, EOFError, UnicodeDecodeError) as exc:
        return ParsedFile(error=f"cannot be decoded: {exc}", count=1), []

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        records, bad_line = _decode_json_lines(text)
        if records is None:
            return ParsedFile(
                error=(
                    f"neither a JSON document nor JSON lines: {exc} "
                    f"(line {bad_line} does not parse)"
                ),
                count=max(bad_line, 1),
            ), []
        return _parsed("one JSON record per line", records), records

    # A single bare record. Wrapping it here keeps one shape for the caller rather than
    # teaching the row loop a second one.
    if isinstance(payload, dict) and "Records" not in payload and "eventName" in payload:
        return _parsed("a single bare record", [payload]), [payload]

    records = payload.get("Records") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        return ParsedFile(error="no top-level 'Records' array", count=1), []
    return _parsed("a top-level 'Records' array", records), records


def _parsed(shape: str, records: list[Any]) -> ParsedFile:
    return ParsedFile(
        shape=shape, records=tuple(records[:SNIFF_RECORDS]), count=len(records),
    )


def _decode_json_lines(text: str) -> tuple[list[Any] | None, int]:
    """Parse JSON-lines text, or report which line broke.

    All-or-nothing on purpose. Skipping unparseable lines would silently shrink the
    denominator, and a partially-read corpus reports a false-positive *rate* against an
    event count that was never actually read.
    """
    records: list[Any] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            records.append(json.loads(stripped))
        except json.JSONDecodeError:
            return None, number
    return (records, 0) if records else (None, 1)


def _iter_payloads(files: list[Path]) -> Iterator[tuple[str, ParsedFile, list[Any]]]:
    """Yield ``(name, parsed, records)`` for every document, tar members included.

    A tar member is named ``<tar>:<member>`` so ``source_ref`` still points at one
    specific record inside one specific archive -- and so the admission record names the
    member, not just the archive: admission is per document, because an archive can
    perfectly well hold one trail file and one manifest.

    An archive that cannot be opened at all is one rejected "file", not a crash, for the
    same reason a malformed row is one issue.
    """
    for path in files:
        kind = _classify(path.name)
        if kind == "tar":
            try:
                with tarfile.open(path) as archive:
                    for member in archive:
                        if not member.isfile() or _classify(member.name) not in ("json", "gzip"):
                            continue
                        handle = archive.extractfile(member)
                        if handle is None:
                            continue
                        parsed, records = _decode(member.name, handle.read())
                        yield f"{path.name}:{member.name}", parsed, records
            except tarfile.TarError as exc:
                yield path.name, ParsedFile(
                    error=f"tar archive cannot be read: {exc}", count=1,
                ), []
            continue
        parsed, records = _decode(path.name, path.read_bytes())
        yield path.name, parsed, records


def _empty(event_type: str) -> pd.DataFrame:
    """An empty, schema-valid table.

    Returned for process and network rather than omitted, so the loader and every
    downstream consumer see the same three tables regardless of source -- and so the
    visibility model measures those channels as genuinely absent rather than erroring.
    """
    return coerce_and_validate(
        pd.DataFrame(columns=list(TABLE_COLUMNS[event_type])), event_type
    )


def _principal(identity: dict[str, Any]) -> str:
    """Best available name for the acting principal.

    CloudTrail's ``userIdentity`` is a union type: an IAM user has ``userName``, an
    assumed role has only an ARN whose last segment is the session name, and a service
    principal may have neither. Preferring the specific over the generic keeps
    correlation working without inventing an identity where none was recorded.

    ``invokedBy`` is the last resort, not a guess: when an AWS service calls STS on the
    account's behalf (``userIdentity.type == "AWSService"``), CloudTrail records the
    service (``ec2.amazonaws.com``, ``config.amazonaws.com``) there and nowhere else.
    Measured on the flaws.cloud public trail before this fallback existed, 57,912
    authentication records -- 3% of the trail -- were dropped as unattributable for
    exactly this reason. The service name is kept verbatim, so a service-invoked
    failure burst is attributed to the service rather than hidden or attributed to a
    human.
    """
    for key in ("userName",):
        value = identity.get(key)
        if value:
            return str(value)
    arn = identity.get("arn")
    if arn:
        return str(arn).rsplit("/", 1)[-1]
    session = identity.get("sessionContext", {}).get("sessionIssuer", {}).get("userName")
    if session:
        return str(session)
    invoked_by = identity.get("invokedBy")
    return str(invoked_by) if invoked_by else ""


def _verdict(record: dict[str, Any]) -> str:
    """Read success/failure, accounting for CloudTrail's two different conventions."""
    if record.get("errorCode") or record.get("errorMessage"):
        return "failure"
    response = record.get("responseElements") or {}
    console = response.get("ConsoleLogin") if isinstance(response, dict) else None
    if isinstance(console, str):
        return "success" if console.lower() == "success" else "failure"
    return "success"


_LOGON_ORDER: tuple[str, ...] = TABLE_COLUMNS[EVENT_LOGON]
_CONTROL_ORDER: tuple[str, ...] = TABLE_COLUMNS[EVENT_CONTROL]


def _frame(rows: list[tuple[Any, ...]], event_type: str, prefix: str) -> pd.DataFrame:
    """Build one canonical frame from positional rows, minting dense event ids.

    Ids are assigned here rather than per row so they are dense and unique by
    construction -- a row that was refused never consumes one.
    """
    frame = pd.DataFrame(rows, columns=list(TABLE_COLUMNS[event_type]))
    frame["event_id"] = [f"{prefix}-{position:06d}" for position in range(1, len(frame) + 1)]
    return frame


def _normalise_auth_record(
    record: Any, file_name: str, index: int
) -> tuple[dict[str, Any] | None, NormalizationIssue | None]:
    """Turn one CloudTrail authentication record into a canonical logon row."""
    if not isinstance(record, dict):
        return None, NormalizationIssue(
            event_type=EVENT_LOGON, reason="record is not a JSON object",
            raw_reference=f"{file_name}#record={index}",
        )

    event_id = record.get("eventID", "?")
    reference = f"{file_name}#record={index}, eventID={event_id}"

    raw_time = record.get("eventTime", "")
    timestamp = parse_event_time(raw_time)
    if pd.isna(timestamp):
        return None, NormalizationIssue(
            event_type=EVENT_LOGON, field="eventTime", raw_reference=reference,
            reason=f"unparseable timestamp: {raw_time!r}",
        )

    identity = record.get("userIdentity") or {}
    user = _principal(identity if isinstance(identity, dict) else {})
    if not user:
        return None, NormalizationIssue(
            event_type=EVENT_LOGON, field="userIdentity", raw_reference=reference,
            reason=(
                "no usable principal name; an authentication event that cannot be "
                "attributed to an identity would correlate against nothing"
            ),
        )

    account = str(record.get("recipientAccountId") or identity.get("accountId") or "unknown")
    region = str(record.get("awsRegion") or "unknown")
    verdict = _verdict(record)

    return {
        "event_id": "",  # assigned by the caller, densely and uniquely
        "timestamp": timestamp,
        "event_type": EVENT_LOGON,
        # "Host" is not a cloud concept; see the module docstring.
        "device": f"aws:{account}/{region}",
        "user": user,
        "source": SOURCE_NAME,
        "source_ref": f"eventID={event_id};File={file_name}",
        # Deliberately null: there is no Windows logon type for a console login, and
        # inventing one would silently re-enable ATH-006's ownership inference on
        # telemetry where the concept of an interactive host session does not exist.
        "logon_type": pd.NA,
        "source_ip": str(record.get("sourceIPAddress") or ""),
        "source_device": "",  # CloudTrail records no originating hostname
        "action": verdict,
        "failure_reason": str(record.get("errorMessage") or record.get("errorCode") or "")
        if verdict == "failure" else "",
    }, None


def _normalise_control_record(
    record: Any, file_name: str, index: int
) -> tuple[dict[str, Any] | None, NormalizationIssue | None]:
    """Turn one CloudTrail management-API record into a canonical control row.

    Any record that is not an authentication decision arrives here -- there is no
    dispatch table to miss, and the only records refused are the ones that could not be
    used by anything: not an object, no name, no time, no caller.

    Returns:
        ``(row, issue)``. Both can be present at once, and that combination is the point:
        a name whose shape this parser does not cover still becomes a row (with the whole
        name as its verb), *and* reports an issue, so "how much of the naming convention
        holds" stays a measured number instead of an assumption.
    """
    if not isinstance(record, dict):
        return None, NormalizationIssue(
            event_type=EVENT_CONTROL, reason="record is not a JSON object",
            raw_reference=f"{file_name}#record={index}",
        )

    event_id = record.get("eventID", "?")
    event_name = str(record.get("eventName") or "")
    reference = f"{file_name}#record={index}, eventID={event_id}"
    if not event_name:
        return None, NormalizationIssue(
            event_type=EVENT_CONTROL, field="eventName", raw_reference=reference,
            reason=(
                "no event name; an action with no name is not a description of anything "
                "and would occupy a row saying so"
            ),
        )

    raw_time = record.get("eventTime", "")
    timestamp = parse_event_time(raw_time)
    if pd.isna(timestamp):
        return None, NormalizationIssue(
            event_type=EVENT_CONTROL, field="eventTime", raw_reference=reference,
            reason=f"unparseable timestamp: {raw_time!r}",
        )

    identity = record.get("userIdentity") or {}
    # Narrowed once, rather than at each read: `userIdentity` is a union type and a
    # corpus-scale run meets every member of it, including the ones that are not objects.
    identity = identity if isinstance(identity, dict) else {}
    actor = _shared(_principal(identity))
    if not actor:
        return None, NormalizationIssue(
            event_type=EVENT_CONTROL, field="userIdentity", raw_reference=reference,
            reason=(
                "no usable principal name; a control-plane action that cannot be "
                "attributed to a caller would correlate against nothing"
            ),
        )

    event_source = str(record.get("eventSource") or "")
    verb, resource_type, family = resource_type_for(event_source, event_name)
    service = _service(event_source)

    params = record.get("requestParameters") or {}
    params = params if isinstance(params, dict) else {}

    # The beneficiary of a grant, as distinct from the caller -- read from the identity
    # service's own parameter conventions. An access-key call that names no user creates
    # a key for the caller, so the beneficiary is the actor themself, not "no one", which
    # is what lets it chain to a prior grant.
    target_actor = ""
    role_ref = ""
    if service == _IDENTITY_SERVICE:
        target_actor = _first_present(params, _TARGET_FIELDS)
        role_ref = _first_present(params, _ROLE_FIELDS)
        if not target_actor and family == _SELF_TARGETING_FAMILY:
            target_actor = actor

    resource_name = target_actor or str(params.get("name") or "") or role_ref

    account = str(record.get("recipientAccountId") or identity.get("accountId") or "unknown")
    region = str(record.get("awsRegion") or "unknown")
    verdict = _verdict(record)

    # Reported *with* the row, never instead of it: the row is the representation, the
    # issue is the measurement of how far the naming convention holds.
    unparsed_name = None if parse_event_name(event_name).parsed else NormalizationIssue(
        event_type=EVENT_CONTROL, field="eventName", raw_reference=reference,
        reason=(
            f"{event_name!r} does not begin with a capitalised word, so no verb could be "
            "read from it; the row is still represented, with the whole name as its verb "
            "and the service alone as its resource type"
        ),
    )

    return {
        "event_id": "",  # assigned by the caller, densely and uniquely
        "timestamp": timestamp,
        "event_type": EVENT_CONTROL,
        "device": _device(account, region),  # "host" is not a cloud concept
        "user": target_actor or actor,
        "source": MANAGEMENT_SOURCE_NAME,
        "source_ref": f"eventID={event_id};File={file_name}",
        "actor": actor,
        "actor_groups": "",  # CloudTrail asserts no group memberships for a caller
        "verb": verb,
        "resource_type": resource_type,
        "resource_name": resource_name,
        "resource_namespace": "",  # not a cloud concept
        "target_actor": target_actor,
        "role_ref": role_ref,
        "decision": "denied" if verdict == "failure" else "allowed",
        "source_ip": _shared(str(record.get("sourceIPAddress") or "")),
    }, unparsed_name


def _first_present(params: dict[str, Any], fields: tuple[str, ...]) -> str:
    """The first of ``fields`` present and non-empty in ``params``, as a string."""
    for field_name in fields:
        value = params.get(field_name)
        if value:
            return _shared(str(value))
    return ""


# Values that repeat across most rows of a trail -- a few hundred distinct devices and
# caller names against millions of records. Held once each: on the public flaws.cloud
# trail this is the difference between one string object per row and one per distinct
# value, for six of the seventeen columns.
_SHARED_VALUES: dict[str, str] = {}


def _shared(value: str) -> str:
    """One string object per distinct value, for the low-cardinality columns."""
    return _SHARED_VALUES.setdefault(value, value)


def _device(account: str, region: str) -> str:
    return _shared(f"aws:{account}/{region}")
