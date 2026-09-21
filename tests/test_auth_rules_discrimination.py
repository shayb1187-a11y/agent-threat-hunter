"""Are ATH-005 and ATH-006 discriminative, or merely quiet?

Every measurement these two rules have on real telemetry is a *false-positive* number.
DEDALE D02 gave them 34,736 logon rows and they said nothing; COMISET gave them 6,063 and
they said nothing; flaws.cloud's 36 ATH-005 findings were downgraded to MEDIUM because
nothing in that corpus ever succeeded. All of that is evidence they do not shout. None of
it is evidence they can hear.

A rule that never fires scores perfectly on every false-positive metric, so silence has to
be separated from correctness deliberately. Each rule gets five cases:

``true positive``     the behaviour the rule exists to catch
``benign neighbour``  the same shape minus the one detail that makes it malicious
``boundary``          either side of the threshold, so the edge is pinned rather than assumed
``missing field``     telemetry that omits what the rule depends on
``repeated``          the pattern twice, so one finding is not silently collapsed from two

The benign-neighbour case is the one that matters. Anything can be made to fire; the
question is whether it stops firing when the malicious detail is removed.
"""

from __future__ import annotations

import pytest
from tests._builders import at, failures, logon, telemetry

from ath.hunting import Severity
from ath.hunting.base import get_detector

# Mirrors HuntConfig.bruteforce_min_failures / _window / _success_window.
MIN_FAILURES = 10
SUCCESS_WINDOW_MINUTES = 15


# ======================================================================================
# ATH-005 -- a burst of failures that ends in a success
# ======================================================================================


def _burst(count: int, *, success_after: float | None, user="svc_backup",
           device="FS02", source_ip="10.0.0.44", spacing=20.0):
    rows = failures(user, device, source_ip, count, spacing_seconds=spacing)
    if success_after is not None:
        rows.append(logon(user, device, logon_type=3, source_ip=source_ip,
                          when=at(success_after)))
    return telemetry(logons=rows)


def test_ath005_true_positive_burst_then_success() -> None:
    """The behaviour the rule exists for: guessing, then getting in."""
    produced = get_detector("ATH-005").run(_burst(12, success_after=5))
    assert len(produced) == 1
    assert produced[0].severity.rank > Severity.MEDIUM.rank
    assert produced[0].user == "svc_backup"
    assert produced[0].event_count >= MIN_FAILURES


def test_ath005_benign_neighbour_identical_burst_that_never_succeeds() -> None:
    """The same 12 failures with the success removed.

    This is flaws.cloud's shape -- 36 of them -- and the whole of M15-2. It is still
    reported, because a sustained failure burst is worth seeing, but it is not graded as
    a compromise.
    """
    produced = get_detector("ATH-005").run(_burst(12, success_after=None))
    assert len(produced) == 1
    assert produced[0].severity is Severity.MEDIUM


def test_ath005_benign_neighbour_a_user_mistyping_their_password() -> None:
    """Three failures then a success is a human, not an attack."""
    assert not get_detector("ATH-005").run(_burst(3, success_after=2))


@pytest.mark.parametrize("count,expected", [
    (MIN_FAILURES - 1, 0),
    (MIN_FAILURES, 1),
])
def test_ath005_boundary_on_failure_count(count, expected) -> None:
    """The threshold is pinned on both sides rather than assumed."""
    assert len(get_detector("ATH-005").run(_burst(count, success_after=5))) == expected


@pytest.mark.parametrize("delay,should_escalate", [
    (SUCCESS_WINDOW_MINUTES - 10, True),
    (SUCCESS_WINDOW_MINUTES + 45, False),
])
def test_ath005_boundary_on_how_long_after_the_burst_a_success_counts(
    delay, should_escalate
) -> None:
    """A success hours later is a different event, not the end of this burst.

    Both sides still produce a finding -- the burst happened either way -- so what is
    asserted is the *grading*, which is where the causal claim lives.
    """
    produced = get_detector("ATH-005").run(_burst(12, success_after=delay))
    assert len(produced) == 1
    escalated = produced[0].severity.rank > Severity.MEDIUM.rank
    assert escalated is should_escalate


def test_ath005_missing_source_ip_still_detects_the_burst() -> None:
    """Source attribution is often absent in real logs; the burst is still real.

    Recorded as a deliberate property: the rule degrades to a weaker claim rather than
    going silent, because an unattributed burst is still worth an analyst's time.
    """
    rows = failures("svc_backup", "FS02", "", 12)
    rows.append(logon("svc_backup", "FS02", logon_type=3, source_ip="", when=at(5)))
    produced = get_detector("ATH-005").run(telemetry(logons=rows))
    assert len(produced) == 1


def test_ath005_two_separate_bursts_are_not_collapsed_into_one() -> None:
    """Two attacks on two accounts must not arrive as a single alert."""
    rows = failures("svc_backup", "FS02", "10.0.0.44", 12)
    rows.append(logon("svc_backup", "FS02", logon_type=3, source_ip="10.0.0.44", when=at(5)))
    rows += failures("admin", "FS02", "10.0.0.77", 12, start_minute=120)
    rows.append(logon("admin", "FS02", logon_type=3, source_ip="10.0.0.77", when=at(125)))
    produced = get_detector("ATH-005").run(telemetry(logons=rows))
    assert len(produced) == 2
    assert {f.user for f in produced} == {"svc_backup", "admin"}


# ======================================================================================
# ATH-006 -- a credential used from a host it has no business being on
# ======================================================================================


def _owned(device: str, owner: str, minute: float = 0):
    """An interactive session, which is what establishes ownership of a host."""
    return logon(owner, device, logon_type=2, when=at(minute))


def test_ath006_true_positive_credential_used_from_someone_elses_workstation() -> None:
    """Lateral movement: svc_backup authenticating *from* Alice's laptop.

    Both halves are individually unremarkable -- svc_backup logs into FS02 constantly,
    and WS-ALICE is an ordinary workstation. The pairing is the signal.
    """
    produced = get_detector("ATH-006").run(telemetry(logons=[
        _owned("WS-ALICE", "alice"),
        logon("svc_backup", "FS02", logon_type=3, source_device="WS-ALICE", when=at(30)),
    ]))
    assert len(produced) == 1
    assert produced[0].user == "svc_backup"


def test_ath006_benign_neighbour_the_owner_using_their_own_machine() -> None:
    """One field differs from the true positive: who is authenticating."""
    assert not get_detector("ATH-006").run(telemetry(logons=[
        _owned("WS-ALICE", "alice"),
        logon("alice", "FS02", logon_type=3, source_device="WS-ALICE", when=at(30)),
    ]))


def test_ath006_boundary_rdp_does_not_confer_ownership() -> None:
    """An attacker with stolen credentials can RDP in.

    If type 10 established ownership, an intruder would legitimise themselves simply by
    arriving, and every subsequent use of that host would be silent. This is the case
    that makes the ownership model worth anything, so it is pinned explicitly.
    """
    produced = get_detector("ATH-006").run(telemetry(logons=[
        logon("mallory", "WS-ALICE", logon_type=10, when=at(0)),   # RDP, not ownership
        _owned("WS-ALICE", "alice", minute=1),
        logon("mallory", "FS02", logon_type=3, source_device="WS-ALICE", when=at(30)),
    ]))
    assert len(produced) == 1
    assert produced[0].user == "mallory"


def test_ath006_missing_source_device_cannot_be_judged_and_stays_silent() -> None:
    """Without knowing where the credential came from, the rule has no claim to make.

    Silence here is correct rather than a miss, and it is the asymmetry worth keeping:
    ATH-005 degrades to a weaker claim on missing data, ATH-006 abstains, because its
    entire assertion is about provenance.
    """
    assert not get_detector("ATH-006").run(telemetry(logons=[
        _owned("WS-ALICE", "alice"),
        logon("svc_backup", "FS02", logon_type=3, source_device="", when=at(30)),
    ]))


def test_ath006_unknown_source_host_is_not_assumed_hostile() -> None:
    """A host with no ownership data is unknown, not unowned.

    Treating "we have never seen an interactive logon here" as "nobody owns it" would
    make every first sighting an alert -- the failure mode that makes self-baselining
    rules unusable in their first week.
    """
    assert not get_detector("ATH-006").run(telemetry(logons=[
        logon("svc_backup", "FS02", logon_type=3, source_device="WS-UNSEEN", when=at(30)),
    ]))


def test_ath006_repeated_use_from_the_same_foreign_host() -> None:
    """The same credential used repeatedly from one host is one story."""
    produced = get_detector("ATH-006").run(telemetry(logons=[
        _owned("WS-ALICE", "alice"),
        logon("svc_backup", "FS02", logon_type=3, source_device="WS-ALICE", when=at(30)),
        logon("svc_backup", "FS02", logon_type=3, source_device="WS-ALICE", when=at(35)),
        logon("svc_backup", "DC01", logon_type=3, source_device="WS-ALICE", when=at(40)),
    ]))
    assert produced
    assert all(f.user == "svc_backup" for f in produced)
    assert sum(f.event_count for f in produced) >= 3


# ======================================================================================
# Both rules, on the benign volume they were previously only measured against
# ======================================================================================


def test_neither_rule_fires_on_ordinary_logon_volume() -> None:
    """The half that was already evidenced, kept so the pair is visible together.

    200 successful logons across 10 users and 5 hosts: the shape of a working morning.
    """
    rows = [
        logon(f"user{i % 10}", f"PC{i % 5:02d}", logon_type=3,
              source_ip=f"10.0.0.{i % 200}", when=at(i * 0.5))
        for i in range(200)
    ]
    assert not get_detector("ATH-005").run(telemetry(logons=rows))
    assert not get_detector("ATH-006").run(telemetry(logons=rows))
