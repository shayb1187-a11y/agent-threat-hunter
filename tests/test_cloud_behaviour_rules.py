"""Tests for the four generic control-plane rules (AWS-003/004/005/006, M18-8).

Three things this module is testing that a "does it fire" test would miss.

**The thresholds are the pre-registered ones.** ``test_no_threshold_moved_after_the_fact``
parses ``reports/m18/cloud_detection/PREREGISTERED.md`` and compares every constant it
declares against :class:`ath.hunting.base.HuntConfig`. Tuning a number after seeing the
held-out corpus is the failure these four rules exist to avoid, and a comment saying
"don't do that" is not a test.

**The rules name nothing.** ``test_module_source_names_no_service_api_or_actor`` reads
this package's own source, strips docstrings and comments, and fails if any executable
token matches a service, API name or actor drawn from the two real corpora. The moment a
rule body knows the word for a cloud service it has stopped being a description of
behaviour and started being a memory of the trail it was written against.

**Per-actor is an invariant, not an implementation detail.** Every rule has a test in
which two identities each sit below the threshold and their sum exceeds it. Summing them
would invent a scan nobody ran, and it is exactly the mistake a naive `groupby` drop
produces.

The vocabulary below is invented -- ``quokka``-numbered services, marsupial actor names --
and ``test_invented_vocabulary_is_absent_from_both_corpora`` proves programmatically that
none of it appears in attack_data_aws or in the flaws.cloud top-100, so a rule tuned to
the data it was measured on could not pass its own tests. The one real token these tests
must use is the identity service prefix ``iam:``, because
:func:`ath.control_vocab.changes_authority` is *defined* by it: an identity-service
predicate with an invented service name would be testing a different predicate.
"""

from __future__ import annotations

import ast
import json
import re
from datetime import timedelta
from pathlib import Path

import pytest

from _builders import at, ctrl, telemetry
from ath.hunting.base import HuntConfig, all_detectors, get_detector
from ath.hunting.finding import Severity
from ath.hunting.rules import cloud_behaviour_rules as rules
from ath.hunting.rules.cloud_behaviour_rules import (
    MAX_EVIDENCE,
    denied_inclusive_rejected_identity_episodes,
)

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "src" / "ath" / "hunting" / "rules" / "cloud_behaviour_rules.py"
PREREGISTERED = ROOT / "reports" / "m18" / "cloud_detection" / "PREREGISTERED.md"
H3_RAW = ROOT / "data" / "external" / "attack_data_aws" / "raw"
FLAWS_HISTOGRAM = (
    ROOT / "data" / "external" / "flaws_cloud" / "probe_eventname_histogram.json"
)

DEVICE = "aws:519204773311/ap-southeast-2"

# Thirty invented services, disjoint from every corpus -- the same vocabulary
# tests/test_cloud_behaviour_stats.py uses, extended by numbering rather than by
# borrowing real service names.
SERVICES = tuple(f"quokka{index}" for index in range(30))

# Invented identities. Not one of them appears in either corpus; the disjointness test
# below checks that against the actor lists the M18-7 measurement wrote out.
SCANNER = "wombat_probe"
PIPELINE = "numbat_pipeline"
ADMIN = "bilby_admin"
SCRIPT = "quoll_script"
OTHER_SCANNER = "potoroo_probe"


def _read(actor: str, service: str, minute: float, decision: str = "allowed") -> dict:
    return ctrl(
        actor, "describe", f"{service}:ledger-fleet", f"ledger-{service}",
        decision=decision, device=DEVICE, source="cloudtrail_mgmt",
        when=at(minute),
    )


def _denied(actor: str, family: str, minute: float) -> dict:
    """One authorization refusal on an invented resource family."""
    return ctrl(
        actor, "describe", f"quokka0:{family}", f"{family}-01",
        decision="denied", device=DEVICE, source="cloudtrail_mgmt", when=at(minute),
    )


def _identity_change(
    actor: str, verb: str, minute: float, decision: str, *, target: str = "",
) -> dict:
    """An authority change on the identity service.

    ``iam:`` is the one real token these fixtures use, and it has to be: the
    identity-service predicate is defined by that prefix, so an invented service here
    would exercise a different predicate than the rules read. The resource *family* and
    the resource name are invented.
    """
    return ctrl(
        actor, verb, "iam:quokka-policy", f"quokka-policy-{minute}",
        target_actor=target, decision=decision, device=DEVICE,
        source="cloudtrail_mgmt", when=at(minute),
    )


def _findings(rule_id: str, ctrls: list[dict], config: HuntConfig | None = None) -> list:
    return get_detector(rule_id, config).detect(telemetry(ctrls=ctrls))


# ======================================================================================
# Anti-overfitting: the thresholds are the ones that were registered in advance
# ======================================================================================

_DECLARED = re.compile(r"`(cloud_[a-z_]+)`\s*=\s*(\d+)(\s*minutes)?")


def _preregistered_thresholds() -> dict[str, object]:
    """Every ``cloud_*`` constant the pre-registration declares, parsed from the prose.

    Parsed rather than restated, because a copy of the numbers in this file would be a
    second declaration that could drift from the first in either direction.
    """
    text = PREREGISTERED.read_text(encoding="utf-8")
    # Only the pre-registration proper -- the RESULTS section appended after measurement
    # quotes measured numbers, and a quoted measurement is not a declaration.
    text = text.split("<!-- RESULTS APPENDED BELOW")[0]
    declared: dict[str, set] = {}
    for name, value, minutes in _DECLARED.findall(text):
        parsed = timedelta(minutes=int(value)) if minutes else int(value)
        declared.setdefault(name, set()).add(parsed)
    return {name: values for name, values in declared.items()}


def test_no_threshold_moved_after_the_fact() -> None:
    """Every pre-registered constant equals the one the rules actually run with.

    Failure mode: someone sees a miss on the held-out corpus, nudges a default in
    ``HuntConfig``, and the measured recall stops being a measurement. This turns that
    into a red suite.
    """
    declared = _preregistered_thresholds()
    expected = {
        "cloud_discovery_min_services", "cloud_discovery_window",
        "cloud_denial_min_count", "cloud_denial_window",
        "cloud_identity_change_window", "cloud_identity_failed_min_count",
    }
    assert expected <= set(declared), (
        f"pre-registration no longer declares: {sorted(expected - set(declared))}"
    )

    config = HuntConfig()
    for name, values in declared.items():
        assert len(values) == 1, f"{name} is declared with conflicting values: {values}"
        assert getattr(config, name) == next(iter(values)), (
            f"HuntConfig.{name} differs from the value pre-registered for it"
        )


def test_preregistration_records_the_head_it_was_written_at() -> None:
    """A pre-registration without a commit hash cannot be shown to have come first."""
    text = PREREGISTERED.read_text(encoding="utf-8")
    assert re.search(r"`[0-9a-f]{40}`", text), "no HEAD hash in the pre-registration"


# ======================================================================================
# Anti-overfitting: the rules name nothing, and the tests borrow nothing
# ======================================================================================


def _executable_tokens(path: Path) -> set[str]:
    """Identifiers and string literals in executable code -- docstrings excluded.

    Docstrings and comments are excluded deliberately: they are where a rule *explains*
    that it names no service, and a check that failed on the word in that explanation
    would punish the documentation for describing the discipline it follows.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = {
        doc for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef))
        and (doc := ast.get_docstring(node, clean=False)) is not None
    }
    tokens: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value not in docstrings:
                tokens.add(node.value.lower())
        elif isinstance(node, ast.Name):
            tokens.add(node.id.lower())
        elif isinstance(node, ast.Attribute):
            # An attribute reached through `self` is this project's own object model
            # (`self.config`), not the cloud's vocabulary.
            if not (isinstance(node.value, ast.Name) and node.value.id == "self"):
                tokens.add(node.attr.lower())
        elif isinstance(node, ast.arg):
            tokens.add(node.arg.lower())
        elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            tokens.add(node.name.lower())
    return tokens


def _corpus_vocabulary() -> tuple[set[str], set[str], set[str]]:
    """(API names, service names, actor names) drawn from the two real corpora."""
    names: set[str] = set()
    services: set[str] = set()
    for path in sorted(H3_RAW.glob("*.json")):
        text = path.read_text(encoding="utf-8")
        try:
            payload = json.loads(text)
            records = payload["Records"] if isinstance(payload, dict) else payload
        except (json.JSONDecodeError, KeyError):
            records = [json.loads(line) for line in text.splitlines() if line.strip()]
        for record in records:
            names.add(str(record.get("eventName", "")).lower())
            services.add(str(record.get("eventSource", "")).split(".")[0].lower())

    histogram = json.loads(FLAWS_HISTOGRAM.read_text(encoding="utf-8"))["eventNames"]
    names |= {
        name.lower() for name, _ in sorted(histogram.items(), key=lambda kv: -kv[1])[:100]
    }

    actors: set[str] = set()
    behaviour = ROOT / "reports" / "m18" / "cloud_behaviour"
    for corpus in ("attack_data_aws", "flaws_cloud"):
        record = json.loads((behaviour / f"{corpus}.json").read_text(encoding="utf-8"))
        actors |= {
            str(entry["actor"]).lower() for entry in record["pooled"]["actors"]
        }
    return names - {""}, services - {""}, actors - {""}


@pytest.mark.skipif(
    not H3_RAW.is_dir() or not FLAWS_HISTOGRAM.exists(),
    reason="external corpora not present in this checkout",
)
def test_module_source_names_no_service_api_or_actor() -> None:
    """The rule bodies contain no cloud vocabulary at all.

    Failure mode: a rule gains an `if service == "..."` and silently becomes a detection
    for the one trail it was written against, invisible to every behavioural test.
    """
    names, services, actors = _corpus_vocabulary()
    tokens = _executable_tokens(MODULE)
    borrowed = sorted(tokens & (names | services | actors))
    assert not borrowed, f"rule code names cloud vocabulary: {borrowed}"


@pytest.mark.skipif(
    not H3_RAW.is_dir() or not FLAWS_HISTOGRAM.exists(),
    reason="external corpora not present in this checkout",
)
def test_invented_vocabulary_is_absent_from_both_corpora() -> None:
    """The fixtures below are invented, checked rather than asserted in prose."""
    names, services, actors = _corpus_vocabulary()
    mine = {s.lower() for s in SERVICES} | {
        SCANNER, PIPELINE, ADMIN, SCRIPT, OTHER_SCANNER,
        K8S_AUTOMATION, K8S_SUBJECT,
    }
    borrowed = sorted(mine & (names | services | actors))
    assert not borrowed, f"test vocabulary taken from a measured corpus: {borrowed}"


# ======================================================================================
# The burst helper moved; ATH-005 did not change
# ======================================================================================


def test_ath005_uses_the_shared_episode_helper() -> None:
    """One sliding window, not two.

    Failure mode: the control-plane rules grow their own window implementation, the two
    drift, and a threshold priced against one shape is applied with the other.
    """
    from ath.hunting.episodes import find_episodes
    from ath.hunting.rules.logon_rules import _find_bursts

    assert _find_bursts is find_episodes
    assert rules.find_episodes is find_episodes


def test_ath005_still_finds_the_same_burst_after_the_move() -> None:
    """ATH-005's behaviour is byte-identical: ten failures then a success is CRITICAL."""
    from _builders import failures, logon

    logons = failures("wallaby", "PC42", "198.51.100.7", 10, spacing_seconds=30)
    logons.append(logon("wallaby", "PC42", logon_type=3, source_ip="198.51.100.7",
                        action="success", when=at(6)))
    found = get_detector("ATH-005").detect(telemetry(logons=logons))
    assert len(found) == 1
    assert found[0].severity is Severity.CRITICAL
    assert found[0].metadata["failure_count"] == 10


# ======================================================================================
# AWS-003 -- cloud service discovery burst
# ======================================================================================


def test_aws003_fires_on_breadth_across_services() -> None:
    """True positive: fifteen distinct services read by one identity in four minutes."""
    ctrls = [_read(SCANNER, SERVICES[i], i * 0.25) for i in range(15)]
    found = _findings("AWS-003", ctrls)
    assert len(found) == 1
    assert found[0].user == SCANNER
    assert found[0].metadata["distinct_services"] == 15
    assert found[0].metadata["call_count"] == 15


def test_aws003_stays_quiet_one_service_below_the_threshold() -> None:
    """Benign look-alike: nine services is an application, not a scan.

    Failure mode: an off-by-one in the distinct-service comparison turns every
    multi-service job in the account into an alert.
    """
    ctrls = [_read(PIPELINE, SERVICES[i], i * 0.25) for i in range(9)]
    assert _findings("AWS-003", ctrls) == []


def test_aws003_fires_exactly_at_the_threshold() -> None:
    """Boundary: ten distinct services is the pre-registered condition, inclusive."""
    ctrls = [_read(SCANNER, SERVICES[i], i * 0.25) for i in range(10)]
    found = _findings("AWS-003", ctrls)
    assert len(found) == 1
    assert found[0].metadata["distinct_services"] == 10


def test_aws003_stays_quiet_when_the_same_breadth_is_spread_beyond_the_window() -> None:
    """The same fifteen services, twenty minutes apart, is an inventory job.

    Failure mode: a window bug (or fixed buckets) turns a slow, ordinary enumeration
    into the same alert as a scanner emptying its target list in three minutes.
    """
    ctrls = [_read(PIPELINE, SERVICES[i], i * 20) for i in range(15)]
    assert _findings("AWS-003", ctrls) == []


def test_aws003_grades_high_when_most_of_the_burst_was_refused() -> None:
    """Severity grading: breadth with no permission behind it is probing."""
    ctrls = [_read(SCANNER, SERVICES[i], i * 0.25, decision="denied") for i in range(12)]
    found = _findings("AWS-003", ctrls)
    assert found[0].severity is Severity.HIGH
    assert found[0].metadata["denied_majority"] is True


def test_aws003_grades_medium_when_the_platform_allowed_the_breadth() -> None:
    """The same breadth, allowed, is what compliance tooling does -- MEDIUM."""
    ctrls = [_read(PIPELINE, SERVICES[i], i * 0.25) for i in range(12)]
    found = _findings("AWS-003", ctrls)
    assert found[0].severity is Severity.MEDIUM
    assert found[0].metadata["denied_fraction"] == 0.0


def test_aws003_grades_medium_at_exactly_half_denied() -> None:
    """A tie is not a majority: the grading condition is strictly greater than half."""
    ctrls = [_read(SCANNER, SERVICES[i], i * 0.25) for i in range(6)]
    ctrls += [
        _read(SCANNER, SERVICES[6 + i], (6 + i) * 0.25, decision="denied")
        for i in range(6)
    ]
    found = _findings("AWS-003", ctrls)
    assert found[0].metadata["denied_fraction"] == 0.5
    assert found[0].severity is Severity.MEDIUM


def test_aws003_does_not_sum_two_actors() -> None:
    """Per-actor invariant: two identities reading six services each is two jobs.

    Failure mode: dropping the actor grouping invents a fifteen-service scan out of two
    applications doing exactly what they were built to do.
    """
    ctrls = [_read(SCANNER, SERVICES[i], i * 0.25) for i in range(6)]
    ctrls += [_read(OTHER_SCANNER, SERVICES[6 + i], (6 + i) * 0.25) for i in range(6)]
    assert _findings("AWS-003", ctrls) == []


def test_aws003_caps_evidence_and_keeps_the_true_count() -> None:
    """Evidence is a bounded sample; the magnitude is never truncated with it."""
    ctrls = [_read(SCANNER, SERVICES[i], i * 0.1) for i in range(30)]
    found = _findings("AWS-003", ctrls)
    assert len(found[0].evidence) == MAX_EVIDENCE
    assert found[0].metadata["call_count"] == 30
    assert found[0].metadata["distinct_services"] == 30
    assert found[0].metadata["evidence_truncated"] is True


def test_aws003_evidence_is_one_row_per_distinct_service() -> None:
    """Twenty rows of the same service would say nothing about the breadth."""
    ctrls = []
    for index in range(25):
        for repeat in range(4):
            ctrls.append(_read(SCANNER, SERVICES[index], index * 0.1 + repeat * 0.01))
    found = _findings("AWS-003", ctrls)
    summaries = [e.summary for e in found[0].evidence]
    assert len(summaries) == len(set(summaries)) == MAX_EVIDENCE


def test_aws003_reports_one_finding_per_episode() -> None:
    """Two scans three hours apart are two episodes, not one and not six hundred."""
    ctrls = [_read(SCANNER, SERVICES[i], i * 0.25) for i in range(12)]
    ctrls += [_read(SCANNER, SERVICES[i], 180 + i * 0.25) for i in range(12)]
    assert len(_findings("AWS-003", ctrls)) == 2


def test_aws003_ignores_non_read_verbs() -> None:
    """Writing to fifteen services is deployment, not discovery."""
    ctrls = [
        ctrl(ADMIN, "create", f"{SERVICES[i]}:ledger-fleet", f"ledger-{i}",
             device=DEVICE, source="cloudtrail_mgmt", when=at(i * 0.25))
        for i in range(15)
    ]
    assert _findings("AWS-003", ctrls) == []


# ======================================================================================
# AWS-004 -- authorization-denial burst
# ======================================================================================


def test_aws004_fires_on_a_run_of_refusals() -> None:
    """True positive: thirty refusals across six resource families in five minutes."""
    ctrls = [_denied(SCANNER, f"family{i % 6}", i * 0.15) for i in range(30)]
    found = _findings("AWS-004", ctrls)
    assert len(found) == 1
    assert found[0].metadata["denied_count"] == 30
    assert found[0].metadata["distinct_resource_types"] == 6


def test_aws004_stays_quiet_one_refusal_below_the_threshold() -> None:
    """Benign look-alike: 24 refusals is under the pre-registered 25."""
    ctrls = [_denied(PIPELINE, f"family{i % 6}", i * 0.15) for i in range(24)]
    assert _findings("AWS-004", ctrls) == []


def test_aws004_fires_exactly_at_the_threshold() -> None:
    ctrls = [_denied(SCANNER, f"family{i % 6}", i * 0.15) for i in range(25)]
    found = _findings("AWS-004", ctrls)
    assert len(found) == 1
    assert found[0].metadata["denied_count"] == 25


def test_aws004_stays_quiet_when_the_refusals_are_spread_beyond_the_window() -> None:
    """Thirty refusals over ten hours is a pipeline retrying, not a probe."""
    ctrls = [_denied(PIPELINE, f"family{i % 6}", i * 20) for i in range(30)]
    assert _findings("AWS-004", ctrls) == []


def test_aws004_grades_high_on_resource_type_breadth() -> None:
    ctrls = [_denied(SCANNER, f"family{i % 5}", i * 0.15) for i in range(30)]
    found = _findings("AWS-004", ctrls)
    assert found[0].severity is Severity.HIGH
    assert found[0].metadata["distinct_resource_types"] == 5


def test_aws004_grades_medium_below_the_breadth_condition() -> None:
    """Four resource types is an application missing one permission -- MEDIUM."""
    ctrls = [_denied(PIPELINE, f"family{i % 4}", i * 0.15) for i in range(30)]
    found = _findings("AWS-004", ctrls)
    assert found[0].severity is Severity.MEDIUM
    assert found[0].metadata["distinct_resource_types"] == 4


def test_aws004_ignores_failures_that_are_not_authorization_refusals() -> None:
    """``failed`` is not ``denied``: throttling and validation say nothing about authority.

    Failure mode: the two-valued decision column returning by the back door, and the rule
    counting one account's retry loop as a permission probe (flaws.cloud, M18-7).
    """
    ctrls = [
        ctrl(PIPELINE, "describe", "quokka0:family0", "family0-01", decision="failed",
             device=DEVICE, source="cloudtrail_mgmt", when=at(i * 0.15))
        for i in range(40)
    ]
    assert _findings("AWS-004", ctrls) == []


def test_aws004_does_not_sum_two_actors() -> None:
    """Per-actor invariant: two roles refused twenty times each are two misconfigurations."""
    ctrls = [_denied(SCANNER, f"family{i % 6}", i * 0.15) for i in range(20)]
    ctrls += [_denied(OTHER_SCANNER, f"family{i % 6}", i * 0.15) for i in range(20)]
    assert _findings("AWS-004", ctrls) == []


def test_aws004_caps_evidence_and_keeps_the_true_count() -> None:
    ctrls = [_denied(SCANNER, f"family{i}", i * 0.05) for i in range(60)]
    found = _findings("AWS-004", ctrls)
    assert len(found[0].evidence) == MAX_EVIDENCE
    assert found[0].metadata["denied_count"] == 60
    assert found[0].metadata["evidence_truncated"] is True


# ======================================================================================
# AWS-005 -- identity authority removed
# ======================================================================================


def test_aws005_fires_on_a_single_performed_removal() -> None:
    """True positive: one detach the platform performed is the whole condition."""
    ctrls = [_identity_change(ADMIN, "detach", 0, "allowed", target="wallaby_svc")]
    found = _findings("AWS-005", ctrls)
    assert len(found) == 1
    assert found[0].severity is Severity.MEDIUM
    assert found[0].metadata["removal_count"] == 1
    assert found[0].metadata["target_actors"] == ["wallaby_svc"]


def test_aws005_stays_quiet_on_a_removal_the_platform_refused() -> None:
    """Benign look-alike (and the important one): a removal that did not happen.

    Failure mode: reporting authority as gone while it is still in place -- the worst
    kind of wrong an alert can be, and the reason `decision` is a hard filter here.
    """
    ctrls = [
        _identity_change(SCRIPT, "detach", i, "denied") for i in range(4)
    ] + [
        _identity_change(SCRIPT, "delete", i + 10, "failed") for i in range(4)
    ]
    assert _findings("AWS-005", ctrls) == []


def test_aws005_stays_quiet_on_a_delete_outside_the_identity_service() -> None:
    """Benign look-alike: deleting a storage object is not an authority change."""
    ctrls = [
        ctrl(ADMIN, "delete", f"{SERVICES[3]}:ledger-fleet", "ledger-03",
             device=DEVICE, source="cloudtrail_mgmt", when=at(i))
        for i in range(5)
    ]
    assert _findings("AWS-005", ctrls) == []


def test_aws005_ignores_additive_changes_to_the_identity_service() -> None:
    """An attach adds authority; this rule is about authority being taken away."""
    ctrls = [_identity_change(ADMIN, "attach", i, "allowed") for i in range(5)]
    assert _findings("AWS-005", ctrls) == []


def test_aws005_splits_episodes_beyond_the_window() -> None:
    """The same removals spread over a day are separate episodes, not one.

    Failure mode: an unbounded grouping reports a year of routine deprovisioning as one
    finding whose window bounds are meaningless.
    """
    ctrls = [_identity_change(ADMIN, "detach", i * 90, "allowed") for i in range(4)]
    found = _findings("AWS-005", ctrls)
    assert len(found) == 4
    assert all(f.metadata["removal_count"] == 1 for f in found)


def test_aws005_aggregates_one_episode_into_one_finding() -> None:
    """Fourteen removals in half an hour is one thing that happened."""
    ctrls = [_identity_change(ADMIN, "delete", i * 2, "allowed") for i in range(14)]
    found = _findings("AWS-005", ctrls)
    assert len(found) == 1
    assert found[0].metadata["removal_count"] == 14


def test_aws005_does_not_merge_two_actors() -> None:
    """Per-actor invariant: two administrators are two findings, never one."""
    ctrls = [_identity_change(ADMIN, "detach", i, "allowed") for i in range(3)]
    ctrls += [_identity_change(SCRIPT, "detach", i, "allowed") for i in range(3)]
    found = _findings("AWS-005", ctrls)
    assert len(found) == 2
    assert {f.user for f in found} == {ADMIN, SCRIPT}
    assert all(f.metadata["removal_count"] == 3 for f in found)


def test_aws005_stays_medium_however_many_were_removed() -> None:
    """Count is magnitude, not malice: a decommissioning script must not outrank an intruder."""
    ctrls = [_identity_change(ADMIN, "delete", i * 0.5, "allowed") for i in range(40)]
    found = _findings("AWS-005", ctrls)
    assert found[0].severity is Severity.MEDIUM


def test_aws005_caps_evidence_and_keeps_the_true_count() -> None:
    ctrls = [_identity_change(ADMIN, "delete", i * 0.5, "allowed") for i in range(40)]
    found = _findings("AWS-005", ctrls)
    assert len(found[0].evidence) == MAX_EVIDENCE
    assert found[0].metadata["removal_count"] == 40
    assert found[0].metadata["evidence_truncated"] is True


def test_aws005_describes_a_removal_that_names_no_principal() -> None:
    """A policy object is not a principal; the finding says so instead of going silent."""
    ctrls = [_identity_change(ADMIN, "delete", 0, "allowed")]
    found = _findings("AWS-005", ctrls)
    assert found[0].metadata["target_actors"] == []
    assert "named no beneficiary" in found[0].reason


# ======================================================================================
# AWS-006 -- repeated rejected identity authority changes
# ======================================================================================


def test_aws006_fires_on_repeated_rejected_identity_writes() -> None:
    """True positive: five rejected authority writes inside the hour."""
    ctrls = [_identity_change(SCRIPT, "create", i, "failed") for i in range(5)]
    found = _findings("AWS-006", ctrls)
    assert len(found) == 1
    assert found[0].severity is Severity.MEDIUM
    assert found[0].metadata["rejected_count"] == 5


def test_aws006_stays_quiet_one_rejection_below_the_threshold() -> None:
    """Benign look-alike: four is the background corpus's observed maximum."""
    ctrls = [_identity_change(SCRIPT, "create", i, "failed") for i in range(4)]
    assert _findings("AWS-006", ctrls) == []


def test_aws006_stays_quiet_when_the_rejections_are_spread_beyond_the_window() -> None:
    """Five rejections over five hours is an engineer iterating, not a brute force."""
    ctrls = [_identity_change(SCRIPT, "create", i * 61, "failed") for i in range(5)]
    assert _findings("AWS-006", ctrls) == []


def test_aws006_ignores_authorization_refusals() -> None:
    """``denied`` belongs to AWS-004: being told 'you may not' is a different statement.

    Failure mode: the two rules overlapping, so one behaviour raises two findings and the
    background cost of AWS-006 is silently the cost of AWS-004.
    """
    ctrls = [_identity_change(SCRIPT, "create", i, "denied") for i in range(20)]
    assert _findings("AWS-006", ctrls) == []


def test_aws006_ignores_rejected_writes_outside_the_identity_service() -> None:
    ctrls = [
        ctrl(SCRIPT, "create", f"{SERVICES[4]}:ledger-fleet", "ledger-04",
             decision="failed", device=DEVICE, source="cloudtrail_mgmt", when=at(i))
        for i in range(10)
    ]
    assert _findings("AWS-006", ctrls) == []


def test_aws006_does_not_sum_two_actors() -> None:
    """Per-actor invariant: two scripts failing four times each is two broken scripts."""
    ctrls = [_identity_change(SCRIPT, "create", i, "failed") for i in range(4)]
    ctrls += [_identity_change(PIPELINE, "create", i, "failed") for i in range(4)]
    assert _findings("AWS-006", ctrls) == []


def test_aws006_caps_evidence_and_keeps_the_true_count() -> None:
    ctrls = [_identity_change(SCRIPT, "create", i * 0.5, "failed") for i in range(35)]
    found = _findings("AWS-006", ctrls)
    assert len(found[0].evidence) == MAX_EVIDENCE
    assert found[0].metadata["rejected_count"] == 35
    assert found[0].metadata["evidence_truncated"] is True


def test_aws006_denied_inclusive_variant_is_report_only() -> None:
    """The wider variant computes episodes and produces no finding.

    It exists so the cost of widening AWS-006 can be measured before anyone adopts it;
    if it ever starts returning Findings, the pre-registered cost of the narrow rule has
    quietly become the cost of the wide one.
    """
    ctrls = [_identity_change(SCRIPT, "create", i, "denied") for i in range(5)]
    assert _findings("AWS-006", ctrls) == []
    episodes = denied_inclusive_rejected_identity_episodes(
        telemetry(ctrls=ctrls), 5, timedelta(minutes=60),
    )
    assert len(episodes) == 1
    assert episodes[0]["actor"] == SCRIPT
    assert episodes[0]["count"] == 5
    assert all(not hasattr(e, "rule_id") for e in episodes)


# ======================================================================================
# M18-9: the two identity rules read the channel they declare, and no other
#
# `changes_authority` has two clauses, because two platforms model identity differently:
# AWS' identity service, and Kubernetes RBAC binding objects. That is right for the
# column it was written for -- `target_actor`, which both adapters fill. It was wrong as
# the whole predicate of a rule declaring CLOUD_MANAGEMENT_ACTIVITY, which is evidenced
# by `source == "cloudtrail_mgmt"` and by nothing Kubernetes emits. M18-8's P13 measured
# the consequence: the coverage model told an operator AWS-006 could not fire on a
# Kubernetes corpus, and it fired.
#
# The Kubernetes shapes below are deliberately the *same behaviour* as the CloudTrail
# ones beside them -- a binding create rejected six times, a binding delete performed --
# so these tests say "not claimed here", not "not interesting". The names on either side
# are disjoint, so neither pair can pass by accidentally matching the other's rows.
# ======================================================================================

K8S_AUTOMATION = "koala_operator"
K8S_SUBJECT = "glider_agent"


def _k8s_binding_change(
    actor: str, verb: str, resource: str, minute: float, decision: str,
) -> dict:
    """A Kubernetes RBAC authority change: the second clause of ``changes_authority``.

    The binding resource names are real (``rolebindings``, ``clusterrolebindings``)
    because the predicate is defined by them; everything else is invented.
    """
    return ctrl(
        actor, verb, resource, f"glider-binding-{minute}",
        target_actor=K8S_SUBJECT, role_ref="view", decision=decision,
        device="k8s:c1", source="k8s_audit", namespace="glider-ns", when=at(minute),
    )


def test_aws006_stays_quiet_on_rejected_kubernetes_rbac_writes() -> None:
    """Six rejected ClusterRoleBinding creates are not this rule's subject.

    Failure mode: this is exactly the k8s_ci finding P13 recorded -- an add-on manager
    re-creating a binding, every attempt a 409. It is real behaviour and a ``K8S-`` rule
    declaring CONTAINER_AUDIT could claim it; AWS-006 declares cloud management activity
    and may not. If the identity-service scope is removed, this returns a finding again.
    """
    ctrls = [
        _k8s_binding_change(K8S_AUTOMATION, "create", "clusterrolebindings", i, "failed")
        for i in range(6)
    ]
    assert _findings("AWS-006", ctrls) == []
    # ...and the identical shape on the identity service still fires, so the test is
    # discriminating between platforms rather than between fixtures.
    cloud = [_identity_change(SCRIPT, "create", i, "failed") for i in range(6)]
    assert len(_findings("AWS-006", cloud)) == 1


def test_aws005_stays_quiet_on_a_performed_kubernetes_rbac_removal() -> None:
    """A RoleBinding the apiserver deleted is not this rule's subject either.

    Failure mode: the same predicate widening, on the removal rule. AWS-005 has no count
    threshold, so a single Kubernetes binding delete was enough to produce a finding
    declaring a channel the row does not belong to.
    """
    ctrls = [_k8s_binding_change(K8S_AUTOMATION, "delete", "rolebindings", 0, "allowed")]
    assert _findings("AWS-005", ctrls) == []
    cloud = [_identity_change(ADMIN, "delete", 0, "allowed")]
    assert len(_findings("AWS-005", cloud)) == 1


def test_aws006_denied_inclusive_variant_carries_the_same_scope() -> None:
    """The report-only variant is wider in decision only, not in platform.

    Failure mode: the variant keeps measuring a population the rule no longer reads, and
    the cost it prices is the cost of a rule nobody proposed.
    """
    ctrls = [
        _k8s_binding_change(K8S_AUTOMATION, "create", "clusterrolebindings", i, "denied")
        for i in range(6)
    ]
    assert denied_inclusive_rejected_identity_episodes(
        telemetry(ctrls=ctrls), 5, timedelta(minutes=60),
    ) == []


# ======================================================================================
# Contracts shared by all four
# ======================================================================================

NEW_RULES = ("AWS-003", "AWS-004", "AWS-005", "AWS-006")


@pytest.mark.parametrize("rule_id", NEW_RULES)
def test_none_of_these_rules_can_emit_critical(rule_id: str) -> None:
    """CRITICAL is for behaviour with no ordinary reading; all four of these have one.

    Checked on the source rather than by sampling outputs: a grading branch that could
    reach CRITICAL on some input a test did not think of would still fail this.
    """
    detector = get_detector(rule_id)
    assert detector.severity is not Severity.CRITICAL
    source = MODULE.read_text(encoding="utf-8")
    body = source[source.index(f'rule_id = "{rule_id}"'):]
    body = body[: body.find("@register", 1) if "@register" in body[1:] else len(body)]
    assert "Severity.CRITICAL" not in body


@pytest.mark.parametrize("rule_id", NEW_RULES)
def test_each_rule_declares_its_inputs_and_its_caveats(rule_id: str) -> None:
    from ath.channels import TelemetryChannel
    from ath.schema import EVENT_CONTROL

    detector = get_detector(rule_id)
    assert detector.tables == frozenset({EVENT_CONTROL})
    assert detector.channels == frozenset({TelemetryChannel.CLOUD_MANAGEMENT_ACTIVITY})
    assert detector.optional_fields <= set(detector.fields_used)
    assert len(detector.false_positives) >= 3
    assert detector.title and detector.description


@pytest.mark.parametrize("rule_id", NEW_RULES)
def test_each_rule_is_silent_on_empty_telemetry(rule_id: str) -> None:
    assert _findings(rule_id, []) == []


@pytest.mark.parametrize("rule_id", NEW_RULES)
def test_each_rule_is_silent_on_windows_telemetry(rule_id: str) -> None:
    """No control rows means no findings, never a crash on a missing column."""
    from _builders import proc

    detector = get_detector(rule_id)
    assert detector.detect(telemetry(procs=[proc("notepad.exe", "notepad.exe", "explorer.exe")])) == []


def test_the_four_rules_are_registered() -> None:
    registered = {d.rule_id for d in all_detectors()}
    assert set(NEW_RULES) <= registered


# ======================================================================================
# ATT&CK
# ======================================================================================


@pytest.mark.parametrize(
    "rule_id,expected",
    [
        ("AWS-003", {"T1526", "T1580"}),
        ("AWS-004", {"T1580"}),
        ("AWS-005", {"T1098"}),
        ("AWS-006", {"T1098"}),
    ],
)
def test_each_rule_maps_to_its_technique(rule_id: str, expected: set[str]) -> None:
    from ath.mitre.mapper import MAPPING_RULES

    assert {
        m.technique_id for m in MAPPING_RULES if m.rule_id == rule_id
    } == expected


def test_at_most_one_of_the_discovery_pair_is_high_confidence() -> None:
    """AWS-003 counts distinct services and never reads their names.

    Which of T1526 and T1580 a burst was is decided by *which* services were read, so the
    rule cannot separate them -- asserting both at HIGH would claim a distinction the
    evidence does not carry.
    """
    from ath.mitre.attack import Confidence
    from ath.mitre.mapper import MAPPING_RULES

    high = [
        m for m in MAPPING_RULES
        if m.rule_id == "AWS-003" and m.confidence is Confidence.HIGH
    ]
    assert len(high) == 1
    assert high[0].technique_id == "T1526"


def test_the_discovery_techniques_are_in_the_verified_catalogue() -> None:
    from ath.mitre.attack import Tactic, get_technique

    for technique_id, name in (
        ("T1526", "Cloud Service Discovery"),
        ("T1580", "Cloud Infrastructure Discovery"),
    ):
        technique = get_technique(technique_id)
        assert technique.name == name
        assert technique.tactics == (Tactic.DISCOVERY,)
        assert technique.parent_id is None


def test_aws006_maps_at_low_confidence_because_nothing_was_manipulated() -> None:
    """Every row behind an AWS-006 finding is a change the platform did not make."""
    from ath.mitre.attack import Confidence
    from ath.mitre.mapper import MAPPING_RULES

    mapping = next(m for m in MAPPING_RULES if m.rule_id == "AWS-006")
    assert mapping.confidence is Confidence.LOW


# ======================================================================================
# Coverage: three watchlist techniques flip to DETECTABLE where the telemetry exists
# ======================================================================================


def test_watchlist_techniques_are_now_covered_by_a_rule() -> None:
    """The mapping table credits a rule for each of the three techniques.

    Coverage is a property of the rule *set*, read off MAPPING_RULES, and not of whether
    an attack happened to be in the telemetry on disk -- so this is the half of the
    check that does not need a corpus.
    """
    from ath.environment.coverage import _rules_covering

    assert "AWS-003" in _rules_covering("T1526")
    assert {"AWS-003", "AWS-004"} <= set(_rules_covering("T1580"))
    assert {"AWS-005", "AWS-006"} <= set(_rules_covering("T1098"))


def test_watchlist_techniques_flip_to_detectable_on_a_cloud_environment() -> None:
    """T1098/T1526/T1580 were OBSERVABLE_UNDETECTED wherever a management trail existed.

    The state machine has four states and the distinction that matters here is between
    "nobody wrote the rule" and "a rule exists and its telemetry is present". Asserted on
    a real :func:`assess_coverage` run over an environment built from control rows, not
    on the mapping table alone: OBSERVABLE_UNDETECTED is what you get when a technique
    has *no* covering rule, and DETECTABLE needs the covering rule to also be runnable on
    the measured channels. Both halves have to hold, and only one of them is a mapping.

    Failure mode: the coverage report keeps reporting a detection-engineering gap that
    has been filled -- or reports one filled while the rule is actually unsupported on
    the channels this environment has.
    """
    from ath.environment import build_environment_model
    from ath.environment.coverage import CoverageState, assess_coverage

    rows = [_read(SCANNER, SERVICES[i], i * 0.25, decision="denied") for i in range(12)]
    report = assess_coverage(build_environment_model(telemetry(ctrls=rows)))
    states = {t.entry.technique_id: t.state for t in report.techniques}

    for technique_id in ("T1098", "T1526", "T1580"):
        assert states[technique_id] is CoverageState.DETECTABLE, (
            f"{technique_id} is {states[technique_id]} on a cloud control-plane "
            "environment"
        )

    # ...and on an environment with no control rows at all the same three techniques are
    # UNOBSERVABLE, not undetected: a rule cannot help where the telemetry is absent, and
    # conflating the two is how a visibility gap gets filed as a detection gap.
    from _builders import proc

    windows = build_environment_model(
        telemetry(procs=[proc("notepad.exe", "notepad.exe", "explorer.exe")])
    )
    windows_states = {
        t.entry.technique_id: t.state for t in assess_coverage(windows).techniques
    }
    for technique_id in ("T1098", "T1526", "T1580"):
        assert windows_states[technique_id] is CoverageState.UNOBSERVABLE
