"""Generic control-plane behaviour: breadth, refusal, removal, and rejected writes.

Four detections over ``ath.schema.EVENT_CONTROL``, and the thing they have in common is
what is **absent** from them: no API name, no service name, no actor name, no error
string. A rule that named `DescribeInstances` would need a new entry for every API AWS
ships, and would be silent about the ones it shipped last week; a rule that named
`cloudsploit` would be a memory of the capture it was written against. What these four
read instead is the control vocabulary -- the verb's *class*, the three-valued
``decision``, the identity-service predicate -- plus counts of distinct services and
distinct resource types inside a window. A test in
``tests/test_cloud_behaviour_rules.py`` reads this module's own source and fails if a
service, API or actor name appears in it.

Why these four, and why now
----------------------------
Three of the five attack_data_aws captures are discovery techniques, and every call in
them is individually unremarkable: a `Describe`, a `List`, a `Get`. What names the
behaviour is breadth and rate, which is a threshold -- and a threshold chosen after
looking at the attack corpus is not a detection, it is a memory of that corpus. So M18-7
measured the background distribution first (1,857,154 control rows of the public
flaws.cloud trail, 55 actors, 3.6 years) and published a candidate grid; the architect
pre-registered these four shapes and their thresholds in
``reports/m18/cloud_detection/PREREGISTERED.md`` at HEAD eb7d395, before this file
existed; and only then did anything run against the held-out captures. Every constant
these rules read lives on :class:`ath.hunting.base.HuntConfig` with the grid number it
came from, and a test parses the pre-registration file and fails if any of them moved.

Why none of them is CRITICAL
-----------------------------
Each of these behaviours has a common, entirely benign reading. Breadth of reads is what
a compliance scanner, a cost-explorer and an inventory job do all day. A run of
authorization denials is what a misconfigured pipeline produces. Removing an IAM policy
is Tuesday for an administrator. Rejected identity writes are what a script with a
malformed policy document produces. CRITICAL is reserved for behaviours with no ordinary
reading -- AWS-002's audit trail being switched off is one; none of these is. MEDIUM is
the floor, with a stated, evidence-backed grading condition lifting two of them to HIGH.

Why one finding per episode
----------------------------
A thousand-call scan is one thing that happened, and an analyst's queue should say so.
Each rule groups its rows per actor and sweeps them with the shared
:func:`ath.hunting.episodes.find_episodes`, the same non-overlapping sliding window
ATH-005 uses, and emits one finding per episode with the episode's true magnitude in
metadata and a bounded sample of rows as evidence.
"""

from __future__ import annotations

import pandas as pd

from ath.channels import TelemetryChannel
from ath.control_vocab import (
    DECISION_ALLOWED,
    DECISION_DENIED,
    DECISION_FAILED,
    DELETE,
    IDENTITY_SERVICES,
    READ,
    REVOKE,
    changes_authority,
    service_of,
    verb_class,
)
from ath.hunting.base import Detector, register
from ath.hunting.episodes import find_episodes
from ath.hunting.finding import Evidence, Finding, Severity
from ath.schema import EVENT_CONTROL
from ath.telemetry.loader import Telemetry

MAX_EVIDENCE = 20
"""How many rows a finding carries at most.

A bound on the *artifact*, never on the detection: the episode's true size is always in
metadata and always in the reason sentence, so a capped finding under-reports nothing.
Twenty because a reader can scan twenty lines and cannot scan a thousand, and because
one representative row per distinct service (AWS-003) or per distinct resource type
(AWS-004) is what makes the sample informative rather than merely short."""

# Severity grading conditions, both stated here rather than inline so the number a
# reviewer argues with is visible in one place.
_DENIED_MAJORITY = 0.5
"""AWS-003: fraction of a burst's calls that must be authorization denials before the
breadth is graded HIGH. Breadth the platform *allowed* is an inventory job; breadth the
platform mostly refused is a caller enumerating an account it has no rights in."""

_DENIAL_BREADTH_RESOURCE_TYPES = 5
"""AWS-004: distinct resource types a denial episode must span before it is graded HIGH.
One pipeline hammering one resource type it lacks a permission for is a configuration
bug; refusals spread across five kinds of object is someone finding out what they can
reach."""


def _controls_with_service(telemetry: Telemetry) -> pd.DataFrame | None:
    """The control table with the derived columns these rules share, or ``None``.

    ``verb_class``, ``service`` and a normalised ``decision`` are computed once per run
    rather than per rule, and they are *derived*, never stored: the canonical table keeps
    what the platform said, and the vocabulary decides what class of thing it was.
    """
    controls = telemetry.controls
    if controls.empty:
        return None
    frame = controls.copy()
    verbs = frame["verb"].astype("string").fillna("")
    resources = frame["resource_type"].astype("string").fillna("")
    frame["_verb_class"] = [verb_class(v) for v in verbs]
    frame["_service"] = [service_of(r) for r in resources]
    frame["_decision"] = frame["decision"].astype("string").fillna("")
    frame["_changes_authority"] = [
        changes_authority(v, r) for v, r in zip(verbs, resources)
    ]
    # The identity-service half of `changes_authority`, kept separately because two of
    # these rules (AWS-005, AWS-006) declare CLOUD_MANAGEMENT_ACTIVITY and only that
    # half is inside that channel. `changes_authority` has a second clause -- Kubernetes
    # RBAC binding objects -- which is correct for the column it was written for
    # (`target_actor`, filled by both adapters) and wider than what an AWS- rule with a
    # cloud-management declaration may cite. M18-9 split the two rather than narrowing
    # the predicate, because the predicate is right and the rules' use of it was not.
    frame["_identity_service"] = frame["_service"].isin(IDENTITY_SERVICES)
    return frame


def _episode_rows(group: pd.DataFrame, min_events: int, window) -> list[pd.DataFrame]:
    """One actor's rows, split into non-overlapping episodes of >= ``min_events``."""
    group = group.sort_values("timestamp", kind="stable").reset_index(drop=True)
    stamps = group["timestamp"].tolist()
    return [
        group.iloc[start : end + 1]
        for start, end in find_episodes(stamps, min_events, window)
    ]


def _first_per(episode: pd.DataFrame, column: str) -> pd.DataFrame:
    """The first row for each distinct value of ``column``, in time order, capped.

    What makes a bounded sample representative: twenty rows that are twenty *different*
    services say what the episode was; twenty rows that are the same service twenty times
    say almost nothing.
    """
    return episode.drop_duplicates(subset=[column]).head(MAX_EVIDENCE)


def _evidence(rows: pd.DataFrame, phrase) -> tuple[Evidence, ...]:
    return tuple(
        Evidence(
            event_id=row["event_id"], timestamp=row["timestamp"], summary=phrase(row),
        )
        for _, row in rows.iterrows()
    )


def _bounds(episode: pd.DataFrame) -> tuple[pd.Timestamp, pd.Timestamp]:
    stamps = episode["timestamp"]
    return stamps.iloc[0], stamps.iloc[-1]


def _seconds(start: pd.Timestamp, end: pd.Timestamp) -> int:
    return int((end - start).total_seconds())


@register
class CloudServiceDiscoveryBurst(Detector):
    """AWS-003 -- One identity read across many distinct services in a short window.

    Attacker behaviour
    ------------------
    The first thing an intruder does with a cloud credential is find out what it can
    reach. That is made entirely of read calls -- describe the instances, list the
    buckets, get the functions -- and not one of them is remarkable on its own. What
    separates enumeration from work is *breadth in time*: an application touches the two
    or three services it was built against, and a caller mapping an account touches
    everything it can think of, in minutes.

    Detection shape
    ---------------
    * keep read-class rows (``verb_class(verb) == "read"``), whatever the platform did
      with them -- a refused read is still an attempt to enumerate, and on one held-out
      capture the enumeration is *entirely* refusals;
    * group by ``actor``, because breadth is a property of one caller. Two identities
      reading five services each is two applications doing their jobs, and summing them
      would invent a scan nobody ran;
    * sweep with the shared non-overlapping sliding window, requiring at least
      ``cloud_discovery_min_services`` **distinct services** inside
      ``cloud_discovery_window``;
    * one finding per episode.

    Why distinct services rather than call volume
    ----------------------------------------------
    Volume measures how busy an identity is, not how widely it is looking: a backup job
    issuing ten thousand calls against one service is the busiest actor on the trail and
    is enumerating nothing. Distinct services is the breadth the behaviour is actually
    made of, and it is also what makes the threshold portable -- "ten services" means the
    same thing on an account with a thousand calls a day and one with a million.

    Why the denied majority decides the grade
    ------------------------------------------
    Breadth the platform *allowed* is, overwhelmingly, an inventory or compliance job
    doing exactly what it is entitled to do. Breadth the platform mostly *refused* is a
    caller who does not have the permissions it is reaching for, which is probing rather
    than administration. The grading condition is stated in the finding, and it reads
    only ``decision`` -- never an error string.

    What this rule cannot tell you
    -------------------------------
    Which services were read, and therefore whether the target was the account's service
    inventory (T1526) or its infrastructure (T1580). The rule counts distinct services;
    it does not inspect their names, which is deliberate, and it is why the ATT&CK layer
    asserts at most one of those two at HIGH confidence.

    Threshold provenance
    --------------------
    Pre-registered in ``reports/m18/cloud_detection/PREREGISTERED.md``. The background
    distribution over 55 flaws.cloud actors at a 10-minute window is p50 = 1, p90 = 11.8,
    p99 = 125.6; 10 distinct services sits just above the p90 knee.
    """

    rule_id = "AWS-003"
    title = "Cloud service discovery burst"
    severity = Severity.MEDIUM
    description = (
        "Detects one identity's read-class calls touching many distinct cloud services "
        "inside a short window -- the breadth that account enumeration is made of."
    )
    fields_used = (
        "actor", "verb", "resource_type", "resource_name", "decision", "timestamp",
    )
    tables = frozenset({EVENT_CONTROL})
    channels = frozenset({TelemetryChannel.CLOUD_MANAGEMENT_ACTIVITY})
    optional_fields = frozenset({"resource_name"})
    """Detection keys on ``verb`` (via ``verb_class(...) == READ``), on
    ``resource_type`` (the distinct-service count that *is* the threshold, and the
    resource-type count in metadata), on ``actor`` (the grouping), on ``timestamp`` (the
    window) and on ``decision`` -- which is REQUIRED, not optional, because
    ``denied_fraction > _DENIED_MAJORITY`` decides HIGH versus MEDIUM, and a field that
    moves severity moves whether the finding survives triage.

    ``resource_name`` is read on exactly one line -- the evidence summary's
    ``f"{row['actor']} {row['verb']} {row['resource_name'] or row['resource_type']}"``
    -- and appears in no filter, no count and no grading term. A row whose resource name
    the adapter could not recover is still counted toward the breadth, still produces the
    same finding at the same severity, and is described by its resource type instead."""
    false_positives = (
        "Cloud security posture and compliance scanners (the whole point of which is to "
        "read every service in the account, on a schedule, forever).",
        "Inventory, asset-management, cost-explorer and backup tooling enumerating "
        "resources across services as designed.",
        "Infrastructure-as-code planning runs, which read the current state of every "
        "resource they manage before deciding what to change.",
        "An administrator working through the console during an incident or an audit, "
        "opening one service page after another.",
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        frame = _controls_with_service(telemetry)
        if frame is None:
            return []
        reads = frame[frame["_verb_class"] == READ]
        if reads.empty:
            return []

        findings: list[Finding] = []
        window = self.config.cloud_discovery_window
        minimum = self.config.cloud_discovery_min_services

        for actor, group in reads.groupby(reads["actor"].astype("string").fillna("")):
            # A window cannot hold N distinct services with fewer than N rows, so the
            # row-count sweep is a sound pre-filter; the distinct count is then checked
            # on each candidate episode. Cheap first, exact second.
            for episode in _episode_rows(group, minimum, window):
                services = list(dict.fromkeys(episode["_service"].tolist()))
                if len(services) < minimum:
                    continue
                start, end = _bounds(episode)
                denied = int((episode["_decision"] == DECISION_DENIED).sum())
                fraction = denied / len(episode)
                probing = fraction > _DENIED_MAJORITY
                sample = _first_per(episode, "_service")

                findings.append(self.make_finding(
                    device=str(episode.iloc[0]["device"]),
                    user=str(actor),
                    severity=Severity.HIGH if probing else Severity.MEDIUM,
                    evidence=_evidence(sample, lambda row: (
                        f"{row['actor']} {row['verb']} "
                        f"{row['resource_name'] or row['resource_type']} "
                        f"({row['decision']})"
                    )),
                    reason=(
                        f"'{actor}' made {len(episode)} read calls across "
                        f"{len(services)} distinct services in "
                        f"{_seconds(start, end)}s"
                        + (
                            f", {denied} of them refused for want of authority "
                            f"({fraction:.0%}). Breadth with no permission behind it is "
                            "enumeration rather than administration"
                            if probing else
                            f", {denied} of them refused ({fraction:.0%}). Breadth on "
                            "this scale is consistent with account enumeration, and is "
                            "also exactly what inventory and compliance tooling does"
                        )
                        + ". The rule counts how many services were read, not which, so "
                        "it cannot say whether the target was the account's service "
                        "inventory or its infrastructure."
                    ),
                    metadata={
                        "actor": str(actor),
                        "distinct_services": len(services),
                        "distinct_resource_types": int(
                            episode["resource_type"].nunique()
                        ),
                        "call_count": int(len(episode)),
                        "denied_count": denied,
                        "denied_fraction": round(fraction, 4),
                        "denied_majority": probing,
                        "window_start": start,
                        "window_end": end,
                        "evidence_truncated": len(episode) > len(sample),
                    },
                ))
        return findings


@register
class AuthorizationDenialBurst(Detector):
    """AWS-004 -- One identity was refused authorization many times in a short window.

    Attacker behaviour
    ------------------
    A caller who does not know what its credential can do finds out by trying. The
    platform answers every attempt it is not entitled to with an authorization refusal,
    so a run of those refusals is the shadow of a permission probe -- the negative image
    of the same enumeration AWS-003 sees from the allowed side. It is also the shape a
    stolen credential produces before its holder learns its limits.

    Detection shape
    ---------------
    * keep rows the platform refused **for authorization reasons** --
      ``decision == "denied"``, which since M18-7 means authorization specifically and no
      longer "an error occurred". That distinction is the whole rule: the largest single
      contributor to the old two-valued column on the background trail was one account's
      throttled retry loop, and a rule counting those would have been counting a bug;
    * group by ``actor``; sweep the shared sliding window for
      ``cloud_denial_min_count`` refusals inside ``cloud_denial_window``;
    * one finding per episode.

    Why the resource-type breadth decides the grade
    ------------------------------------------------
    A pipeline missing one permission is refused over and over on one kind of object;
    that is a configuration defect and it is MEDIUM. Refusals spread across five or more
    kinds of object is a caller working out what it can reach, which is a different
    statement, and it is HIGH.

    Known limitation
    ----------------
    This is the loudest of the four on a real trail: on flaws.cloud three identities
    account for essentially every denial, each of them over years. The pre-registration
    priced that in advance rather than discovering it afterwards.
    """

    rule_id = "AWS-004"
    title = "Authorization-denial burst"
    severity = Severity.MEDIUM
    description = (
        "Detects one identity accumulating many authorization refusals in a short "
        "window -- the negative image of a permission probe."
    )
    fields_used = (
        "actor", "verb", "resource_type", "resource_name", "decision", "timestamp",
    )
    tables = frozenset({EVENT_CONTROL})
    channels = frozenset({TelemetryChannel.CLOUD_MANAGEMENT_ACTIVITY})
    optional_fields = frozenset({"resource_name", "verb"})
    """Detection keys on ``decision`` (``frame["_decision"] == DECISION_DENIED`` is the
    only filter), on ``actor`` (the grouping), on ``timestamp`` (the window) and on
    ``resource_type`` -- REQUIRED, because
    ``nunique() >= _DENIAL_BREADTH_RESOURCE_TYPES`` decides HIGH versus MEDIUM and a
    field that moves severity decides whether the finding survives triage.

    ``resource_name`` and ``verb`` are each read on one line only, both of them inside
    the evidence summary ``f"{row['actor']} was refused {row['verb']} on
    {row['resource_name'] or row['resource_type']}"``. Neither appears in a filter, a
    count, or a grading term: a source that supplies neither still produces this finding,
    at the same severity, over the same rows. ``verb`` is optional *here* and required in
    AWS-003 because the two rules read it for different jobs -- there it is the read-class
    filter, here it is a word in a sentence."""
    false_positives = (
        "A pipeline or application whose role is missing a permission, retrying the "
        "call it cannot make -- by far the most common cause of denial runs.",
        "Security scanners and posture tools, whose read attempts against services the "
        "account does not use are refused by design.",
        "A newly created or newly scoped-down role exercising paths its old policy "
        "allowed, until the code catches up with the policy.",
        "Cross-account or cross-region tooling pointed at an account it was never "
        "granted access to.",
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        frame = _controls_with_service(telemetry)
        if frame is None:
            return []
        denials = frame[frame["_decision"] == DECISION_DENIED]
        if denials.empty:
            return []

        findings: list[Finding] = []
        window = self.config.cloud_denial_window
        minimum = self.config.cloud_denial_min_count

        for actor, group in denials.groupby(denials["actor"].astype("string").fillna("")):
            for episode in _episode_rows(group, minimum, window):
                start, end = _bounds(episode)
                resource_types = int(episode["resource_type"].nunique())
                broad = resource_types >= _DENIAL_BREADTH_RESOURCE_TYPES
                sample = _first_per(episode, "resource_type")

                findings.append(self.make_finding(
                    device=str(episode.iloc[0]["device"]),
                    user=str(actor),
                    severity=Severity.HIGH if broad else Severity.MEDIUM,
                    evidence=_evidence(sample, lambda row: (
                        f"{row['actor']} was refused {row['verb']} on "
                        f"{row['resource_name'] or row['resource_type']}"
                    )),
                    reason=(
                        f"'{actor}' was refused authorization {len(episode)} times in "
                        f"{_seconds(start, end)}s, across {resource_types} distinct "
                        "resource types"
                        + (
                            ". Refusals spread across this many kinds of object are "
                            "consistent with a caller establishing what its credential "
                            "can reach"
                            if broad else
                            ". Concentrated on so few kinds of object, this is equally "
                            "the shape of an application missing one permission and "
                            "retrying"
                        )
                        + ". A refusal says what the platform would not do; it does not "
                        "say what the caller intended."
                    ),
                    metadata={
                        "actor": str(actor),
                        "denied_count": int(len(episode)),
                        "distinct_resource_types": resource_types,
                        "distinct_services": int(episode["_service"].nunique()),
                        "resource_type_breadth": broad,
                        "window_start": start,
                        "window_end": end,
                        "evidence_truncated": len(episode) > len(sample),
                    },
                ))
        return findings


@register
class IdentityAuthorityRemoved(Detector):
    """AWS-005 -- An identity's authority was deleted or revoked.

    Attacker behaviour
    ------------------
    Authority is removed for two very different reasons. An administrator detaches a
    policy someone no longer needs, or deletes a role a decommissioned service used. An
    intruder removes the authority that would stop them, or that would let a responder
    evict them -- detaching a policy from the account whose alerts they want silenced,
    deleting the role a security tool assumes, stripping a group membership. The
    telemetry is identical; the difference is context this rule does not have.

    So the rule makes the weaker, honest statement: *this happened, and here is all of
    it, grouped so a person can see the shape*. An hour in which one identity removes
    fourteen authorities looks different from an hour in which it removes one, and
    neither is graded above MEDIUM by the rule, because neither is an accusation.

    Detection shape
    ---------------
    * keep rows that changed an authority on the **identity service**
      (``changes_authority`` conjoined with ``service_of(resource_type) in
      IDENTITY_SERVICES``) whose verb class is ``delete`` or ``revoke`` -- the classes
      that take something away;
    * keep only ``decision == "allowed"``. A removal the platform refused is not a
      removal: it is a probe, and AWS-004 and AWS-006 are where those belong. Counting a
      refused delete here would report authority as gone while it is still in place --
      the worst kind of wrong an alert can be;
    * group by ``actor``, aggregate into ``cloud_identity_change_window`` episodes, one
      finding each.

    Why there is no count threshold
    --------------------------------
    A single deliberate removal is the one most worth seeing, and the background corpus
    prices it: at >= 1 removal per episode this reaches 6 identities on 25 actor-days
    across 3.6 years. Requiring three would be cheaper and would filter out exactly the
    quiet, targeted case the rule exists for.

    Why MEDIUM regardless of count
    -------------------------------
    Count is magnitude, not malice: a decommissioning script legitimately removes forty
    authorities in an afternoon, and an intruder removes one. Grading on volume would
    put the script above the intruder.

    What this rule does not claim (M18-9)
    --------------------------------------
    ``changes_authority`` is cross-platform by design: its second clause is a Kubernetes
    RBAC binding object, because that is how a permission is granted there. This rule is
    conjoined with the identity-service clause instead, so it reads cloud management
    activity only -- which is the channel it declares, and the only channel it is
    entitled to cite rows from. The Kubernetes equivalent (an RBAC binding deleted, a
    ClusterRoleBinding revoked) is real behaviour and is **not claimed here**: it would
    be a ``K8S-`` rule declaring ``CONTAINER_AUDIT``, with its own thresholds priced
    against a Kubernetes background, and no such rule exists. Before M18-9 this rule's
    predicate admitted those rows while its declaration excluded them, which made the
    coverage model's "this rule cannot fire here" false on a Kubernetes corpus.
    """

    rule_id = "AWS-005"
    title = "Identity authority removed"
    severity = Severity.MEDIUM
    description = (
        "Detects delete- and revoke-class changes to identity authority that the "
        "platform performed, grouped per identity per episode."
    )
    fields_used = (
        "actor", "verb", "resource_type", "resource_name", "target_actor", "role_ref",
        "decision", "timestamp",
    )
    tables = frozenset({EVENT_CONTROL})
    channels = frozenset({TelemetryChannel.CLOUD_MANAGEMENT_ACTIVITY})
    optional_fields = frozenset({"resource_name", "target_actor", "role_ref"})
    """Detection keys on ``verb`` and ``resource_type`` together (``changes_authority``
    plus ``verb_class in {DELETE, REVOKE}``), on ``decision``
    (``== DECISION_ALLOWED``), on ``actor`` (the grouping) and on ``timestamp`` (the
    episode). Severity is the class constant and no field moves it.

    The three optional fields are read on one line each and only to say *whose* authority
    moved: ``target_actor`` and ``role_ref`` inside the evidence summary's
    ``f"... {row['role_ref'] or row['resource_name'] or row['resource_type']}" +
    (f" from {row['target_actor']}" if row['target_actor'] else "")``, and
    ``resource_name`` in the same expression as the fallback. A CloudTrail row for a
    call that names no principal -- deleting a *policy* object, which is not a principal
    (M18-5) -- carries none of the three, is still counted, still produces this finding
    at MEDIUM, and is described by its resource type."""
    false_positives = (
        "Routine deprovisioning: an administrator or an HR-driven script removing the "
        "access of someone who has left, or of a service that was decommissioned.",
        "Infrastructure-as-code runs that delete and recreate identity objects on every "
        "apply, so that a no-op change produces a removal.",
        "Least-privilege cleanup campaigns, which remove large numbers of unused "
        "policies and group memberships on purpose.",
        "Policy churn during development, where a role's permissions are attached and "
        "detached repeatedly while someone works out what it needs.",
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        frame = _controls_with_service(telemetry)
        if frame is None:
            return []
        removals = frame[
            frame["_changes_authority"]
            & frame["_identity_service"]
            & frame["_verb_class"].isin([DELETE, REVOKE])
            & (frame["_decision"] == DECISION_ALLOWED)
        ]
        if removals.empty:
            return []

        findings: list[Finding] = []
        window = self.config.cloud_identity_change_window

        for actor, group in removals.groupby(
            removals["actor"].astype("string").fillna("")
        ):
            # One row is already an episode: there is no count threshold here, which is
            # `min_events=1` and not a special case.
            for episode in _episode_rows(group, 1, window):
                start, end = _bounds(episode)
                sample = episode.head(MAX_EVIDENCE)
                subjects = sorted(
                    {t for t in episode["target_actor"].astype("string").fillna("") if t}
                )

                findings.append(self.make_finding(
                    device=str(episode.iloc[0]["device"]),
                    user=str(actor),
                    evidence=_evidence(sample, lambda row: (
                        f"{row['actor']} {row['verb']} "
                        f"{row['role_ref'] or row['resource_name'] or row['resource_type']}"
                        + (f" from {row['target_actor']}" if row["target_actor"] else "")
                    )),
                    reason=(
                        f"'{actor}' removed {len(episode)} identity "
                        f"{'authority' if len(episode) == 1 else 'authorities'} in "
                        f"{_seconds(start, end)}s"
                        + (
                            f", affecting {', '.join(subjects)}"
                            if subjects else
                            " (the platform named no beneficiary on these calls, which "
                            "is what a change to a policy object rather than to a "
                            "principal looks like)"
                        )
                        + ". Removing authority is ordinary administration and is also "
                        "how an intruder strips the access that would evict them; this "
                        "evidence does not distinguish the two."
                    ),
                    metadata={
                        "actor": str(actor),
                        "removal_count": int(len(episode)),
                        "target_actors": subjects,
                        "distinct_resource_types": int(
                            episode["resource_type"].nunique()
                        ),
                        "verb_classes": sorted(set(episode["_verb_class"])),
                        "window_start": start,
                        "window_end": end,
                        "evidence_truncated": len(episode) > len(sample),
                    },
                ))
        return findings


@register
class RepeatedRejectedIdentityChanges(Detector):
    """AWS-006 -- Repeated attempts to write identity authority that the platform rejected.

    Attacker behaviour
    ------------------
    A caller who *is* authorized to change identity authority, but does not know how to
    write what it is trying to write, produces a run of rejections that are not
    authorization refusals: malformed policy documents, references to principals that do
    not exist, conflicting names. That is the signature of someone searching for a policy
    the platform will accept -- a permission brute force -- and it is a different
    statement from being told "you may not", which is AWS-004's subject.

    Detection shape
    ---------------
    * keep rows that changed an authority on the **identity service**
      (``changes_authority`` conjoined with ``service_of(resource_type) in
      IDENTITY_SERVICES``) with ``decision == "failed"`` -- rejected for validation,
      conflict, absence or anything else that is *not* an authorization answer. The
      three-valued decision column is what makes this expressible at all: under the old
      two-valued column these rows and AWS-004's were the same value;
    * group by ``actor``; require ``cloud_identity_failed_min_count`` inside
      ``cloud_identity_change_window``;
    * one finding per episode.

    Threshold provenance
    --------------------
    The background trail's maximum, over 55 identities and 3.6 years, is 4 in a window at
    both measured window lengths; 5 is the smallest value it never reaches. That is a
    statement about one trail and not a law, which is why it is a config constant.

    What this rule does not claim (M18-9)
    --------------------------------------
    This is the rule the invariant was found on. M18-8's pre-registration predicted zero
    findings on a Kubernetes CI corpus and got one: ``changes_authority``'s second clause
    is Kubernetes RBAC bindings, so the rule ran on ``k8s_audit`` rows and reported an
    add-on manager re-creating a ClusterRoleBinding twenty-one times, every attempt a
    409 conflict. The finding was true and the behaviour was the second false positive
    this rule declares -- and the rule had told the coverage model it reads
    ``CLOUD_MANAGEMENT_ACTIVITY``, which is what made it wrong. The predicate is now
    conjoined with the identity-service clause, so the declaration and the behaviour say
    the same thing. Repeated rejected RBAC writes on Kubernetes are real and are **not
    claimed here**: that would be a ``K8S-`` rule declaring ``CONTAINER_AUDIT``, priced
    against a Kubernetes background, and no such rule exists. The threshold did not
    move; ``ath.environment.coverage.findings_respect_declared_channels`` now fails a
    test if any rule cites a row outside its declaration again.
    """

    rule_id = "AWS-006"
    title = "Repeated rejected identity authority changes"
    severity = Severity.MEDIUM
    description = (
        "Detects repeated identity-authority writes the platform rejected for reasons "
        "other than authorization -- the shape of searching for a policy it will accept."
    )
    fields_used = (
        "actor", "verb", "resource_type", "resource_name", "decision", "timestamp",
    )
    tables = frozenset({EVENT_CONTROL})
    channels = frozenset({TelemetryChannel.CLOUD_MANAGEMENT_ACTIVITY})
    optional_fields = frozenset({"resource_name"})
    """Detection keys on ``verb`` and ``resource_type`` together (``changes_authority``),
    on ``decision`` (``== DECISION_FAILED``), on ``actor`` (the grouping) and on
    ``timestamp`` (the window). Severity is the class constant; no field moves it.

    ``resource_name`` is read once, in the evidence summary
    ``f"{row['actor']}'s {row['verb']} on {row['resource_name'] or
    row['resource_type']} was rejected"``, and in nothing else. A row without it is
    counted toward the threshold and described by its resource type."""
    false_positives = (
        "A deployment or policy-generation script emitting a malformed policy document "
        "and retrying it -- the single most common cause of this shape.",
        "Automation racing itself: two runs creating the same identity object, where "
        "the loser is rejected for a name conflict.",
        "An engineer iterating on a trust policy or a permission boundary by hand until "
        "the platform accepts it.",
        "A tool written against a newer or older API shape than the account exposes, "
        "whose every attempt is rejected as invalid.",
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        frame = _controls_with_service(telemetry)
        if frame is None:
            return []
        rejected = frame[
            frame["_changes_authority"]
            & frame["_identity_service"]
            & (frame["_decision"] == DECISION_FAILED)
        ]
        if rejected.empty:
            return []

        findings: list[Finding] = []
        window = self.config.cloud_identity_change_window
        minimum = self.config.cloud_identity_failed_min_count

        for actor, group in rejected.groupby(
            rejected["actor"].astype("string").fillna("")
        ):
            for episode in _episode_rows(group, minimum, window):
                start, end = _bounds(episode)
                sample = episode.head(MAX_EVIDENCE)

                findings.append(self.make_finding(
                    device=str(episode.iloc[0]["device"]),
                    user=str(actor),
                    evidence=_evidence(sample, lambda row: (
                        f"{row['actor']}'s {row['verb']} on "
                        f"{row['resource_name'] or row['resource_type']} was rejected"
                    )),
                    reason=(
                        f"'{actor}' had {len(episode)} identity-authority writes "
                        f"rejected in {_seconds(start, end)}s for reasons other than "
                        "authorization. Repeatedly failing to write authority the "
                        "caller is permitted to write is consistent with searching for "
                        "a form the platform will accept, and is equally what a script "
                        "emitting an invalid policy document produces."
                    ),
                    metadata={
                        "actor": str(actor),
                        "rejected_count": int(len(episode)),
                        "distinct_resource_types": int(
                            episode["resource_type"].nunique()
                        ),
                        "verb_classes": sorted(set(episode["_verb_class"])),
                        "window_start": start,
                        "window_end": end,
                        "evidence_truncated": len(episode) > len(sample),
                    },
                ))
        return findings


def denied_inclusive_rejected_identity_episodes(
    telemetry: Telemetry, minimum: int, window,
) -> list[dict]:
    """AWS-006's wider variant, **report-only**: ``decision in {failed, denied}``.

    Wider only in the one dimension being priced -- the decision value. It carries
    AWS-006's identity-service scope unchanged (M18-9), because a variant measured over
    a different population would price a rule nobody proposed.

    Not a detector, not registered, and it produces no :class:`Finding`. It exists so
    that the cost of widening AWS-006 to include authorization refusals can be *measured*
    on the background corpus before anyone proposes adopting it -- the same discipline
    that put the distribution before the threshold in the first place. A measurement
    script reads this; no rule, triage path or report does.

    Args:
        telemetry: The telemetry to measure.
        minimum: Rejections required inside the window.
        window: The episode length.

    Returns:
        One dict per episode: actor, count, and the episode's bounds.
    """
    frame = _controls_with_service(telemetry)
    if frame is None:
        return []
    rejected = frame[
        frame["_changes_authority"]
        & frame["_identity_service"]
        & frame["_decision"].isin([DECISION_FAILED, DECISION_DENIED])
    ]
    if rejected.empty:
        return []

    episodes: list[dict] = []
    for actor, group in rejected.groupby(rejected["actor"].astype("string").fillna("")):
        for episode in _episode_rows(group, minimum, window):
            start, end = _bounds(episode)
            episodes.append({
                "actor": str(actor),
                "count": int(len(episode)),
                "window_start": str(start),
                "window_end": str(end),
            })
    return episodes
