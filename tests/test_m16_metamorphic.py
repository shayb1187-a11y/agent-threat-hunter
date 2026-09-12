"""M16 layer 3: does each M15 fix depend on security semantics or on the corpus?

Held-out datasets answer that question with evidence but little control: when DEDALE D02
stays silent, that is one environment agreeing with one other environment. These tests
answer the same question by construction instead. For each M15 fix they take the exact
input that provoked the original real-data failure and **permute everything that carries
no security meaning** -- hostname, username, process id, parent id, timestamp, file-path
prefix, cluster name, namespace, service-account name -- then require the verdict not to
move.

That is a metamorphic relation: the transformation is known to preserve the property
under test, so any change in output is a defect rather than a judgement call. It is the
cheapest available evidence that a fix keys on *what happened* rather than on *where it
was seen*, and unlike a held-out corpus it can be run on a laptop in a second.

Three questions per fix, per the M16 brief:

``regression``    the exact original real-data failure is still fixed
``generalization`` the same benign shape, wearing different identifiers, is still fixed
``true positive``  a malicious variant still fires

The third matters most. A fix that silenced a false positive by silencing the rule would
pass the first two and fail only here.
"""

from __future__ import annotations

import pytest

from ath.hunting import Severity
from ath.hunting.base import get_detector
from tests._builders import at, ctrl, failures, logon, proc, telemetry

# Identifier permutations. Every field varied here is a *name or a number*, never a
# security property: a different host, a different analyst, a different pid, an hour
# later. If any of these changes an outcome, the rule is reading the wrong thing.
IDENTITIES = [
    pytest.param("PC01", "jdoe", 4242, 1000, 0, id="original"),
    pytest.param("WKS-9917", "a.moreau", 31337, 644, 137, id="other-host-user-pid"),
    pytest.param("srv-fin-02", "SYSTEM", 8, 4, 401, id="server-system-low-pids"),
    pytest.param("LAPTOP-7Q2", "contoso\\svc_backup", 65001, 9999, 823, id="domain-user"),
]


# ======================================================================================
# M15-1 -- ATH-004 must read argv[0], not "the string lsass appeared"
# ======================================================================================


def _lsass_starting(device, user, pid, ppid, minute):
    """LSASS starting at boot: it names its own image in argv[0], every host, every boot.

    This is the exact shape that produced 30 false positives a day on DEDALE.
    """
    return telemetry(procs=[proc(
        "lsass.exe", r"C:\Windows\system32\lsass.exe", "wininit.exe",
        device=device, user=user, pid=pid, ppid=ppid, when=at(minute),
        path=r"C:\Windows\System32\lsass.exe",
    )])


def _lsass_being_dumped(device, user, pid, ppid, minute):
    """A different process naming LSASS as its *target*. Semantically the opposite."""
    return telemetry(procs=[proc(
        "rundll32.exe",
        r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 "
        r"C:\Users\Public\lsass.dmp full",
        "cmd.exe",
        device=device, user=user, pid=pid, ppid=ppid, when=at(minute),
    )])


@pytest.mark.parametrize("device,user,pid,ppid,minute", IDENTITIES)
def test_ath004_stays_silent_on_lsass_starting_whoever_it_belongs_to(
    device, user, pid, ppid, minute
) -> None:
    """Generalization: boot-time LSASS is benign on every host, not just DEDALE's."""
    assert not get_detector("ATH-004").run(
        _lsass_starting(device, user, pid, ppid, minute)
    )


@pytest.mark.parametrize("device,user,pid,ppid,minute", IDENTITIES)
def test_ath004_still_fires_on_lsass_being_dumped_wherever_it_happens(
    device, user, pid, ppid, minute
) -> None:
    """True positive: the fix must not have silenced the rule.

    Same permutations as the benign case, opposite required outcome. If M15-1 had been
    implemented by narrowing the pattern too far, this is where it shows.
    """
    produced = get_detector("ATH-004").run(
        _lsass_being_dumped(device, user, pid, ppid, minute)
    )
    assert len(produced) == 1


def test_ath004_fires_on_a_renamed_dumper() -> None:
    """The binary name is not the signal; the target named in the arguments is."""
    assert get_detector("ATH-004").run(telemetry(procs=[proc(
        "svc-helper.exe",
        r"svc-helper.exe -accepteula -ma lsass.exe C:\Temp\out.dmp", "cmd.exe",
    )]))


def test_ath004_is_not_fooled_by_an_unquoted_path_containing_a_space() -> None:
    r"""**M16-1, found by this layer and now fixed.**

    ``_arguments()`` used to remove argv[0] with ``split(None, 1)``, which is correct for
    a bare path and wrong for an unquoted one containing a space: for
    ``D:\Program Files\vendor\lsass.exe`` the split yielded ``Files\vendor\lsass.exe``
    as "the arguments", matching the explicit-lsass-reference indicator and firing ATH-004
    CRITICAL on a process that was merely starting.

    DEDALE could not have exposed it -- LSASS lives in ``C:\Windows\System32``, which has
    no space -- so the tuning corpus held only the case where guessing works. The fix
    reads the authoritative image path instead of guessing; see :func:`_arguments`.
    """
    assert not get_detector("ATH-004").run(telemetry(procs=[proc(
        "lsass.exe", r"D:\Program Files\vendor\lsass.exe", "services.exe",
        path=r"D:\Program Files\vendor\lsass.exe",
    )]))


# --------------------------------------------------------------------------------------
# argv[0] parsing, adversarially. Each case is a shape real Windows telemetry produces.
# --------------------------------------------------------------------------------------

ARGV0_BENIGN = [
    pytest.param(r"C:\Windows\System32\lsass.exe", r"C:\Windows\System32\lsass.exe",
                 id="bare-path-no-spaces"),
    pytest.param(r'"C:\Program Files\vendor\lsass.exe"', r"C:\Program Files\vendor\lsass.exe",
                 id="quoted-path-with-spaces"),
    pytest.param(r"D:\Program Files\vendor\lsass.exe", r"D:\Program Files\vendor\lsass.exe",
                 id="unquoted-path-with-spaces"),
    pytest.param(r"C:\WINDOWS\SYSTEM32\LSASS.EXE", r"C:\Windows\System32\lsass.exe",
                 id="mixed-case"),
    pytest.param(r"C:\Program Files (x86)\Odd Vendor\lsass.exe",
                 r"C:\Program Files (x86)\Odd Vendor\lsass.exe", id="two-spaces-and-parens"),
    pytest.param("", r"C:\Windows\System32\lsass.exe", id="missing-command-line"),
]


@pytest.mark.parametrize("command_line,image_path", ARGV0_BENIGN)
def test_ath004_silent_when_lsass_only_names_itself(command_line, image_path) -> None:
    """Every shape of "LSASS is starting". None is credential access."""
    assert not get_detector("ATH-004").run(telemetry(procs=[proc(
        "lsass.exe", command_line, "wininit.exe", path=image_path,
    )]))


ARGV0_MALICIOUS = [
    pytest.param(r"procdump64.exe -accepteula -ma lsass.exe C:\Temp\out.dmp",
                 r"C:\Tools\procdump64.exe", "procdump64.exe", id="executable-plus-real-arguments"),
    pytest.param(r'"C:\Program Files\Tools\dump.exe" -ma lsass.exe out.dmp',
                 r"C:\Program Files\Tools\dump.exe", "dump.exe", id="quoted-path-then-lsass-target"),
    pytest.param(r"C:\Program Files\My Tools\svc.exe -ma lsass.exe out.dmp",
                 r"C:\Program Files\My Tools\svc.exe", "svc.exe",
                 id="unquoted-spaced-path-then-lsass-target"),
    pytest.param(r"C:\Tools\LSASS-Dumper.exe -ma lsass.exe out.dmp",
                 r"C:\Tools\LSASS-Dumper.exe", "LSASS-Dumper.exe",
                 id="image-name-repeated-inside-a-real-argument"),
]


@pytest.mark.parametrize("command_line,image_path,name", ARGV0_MALICIOUS)
def test_ath004_still_fires_when_lsass_is_the_target(command_line, image_path, name) -> None:
    """The fix must not have been a way of silencing the rule.

    Each of these names LSASS in the *arguments*, which is the thing ATH-004 exists to
    see, and each wears a path shape that the parsing change had to handle.
    """
    assert get_detector("ATH-004").run(telemetry(procs=[proc(
        name, command_line, "cmd.exe", path=image_path,
    )])), f"{name} did not fire"


def test_ath004_handles_image_and_command_line_disagreeing() -> None:
    """Telemetry is not always self-consistent; argv[0] must still be removed.

    Here ``file_path`` says one thing and the command line another, so strategy 2 cannot
    apply and the fall-back to the image *name* is what has to work.
    """
    assert not get_detector("ATH-004").run(telemetry(procs=[proc(
        "lsass.exe", r"\?\D:\Odd Path\lsass.exe", "wininit.exe",
        path=r"C:\Windows\System32\lsass.exe",
    )]))


def test_ath004_with_no_image_field_falls_back_and_says_so() -> None:
    """A source carrying no image path at all still parses, by the documented fallback."""
    assert get_detector("ATH-004").run(telemetry(procs=[proc(
        "x.exe", "x.exe -ma lsass.exe out.dmp", "cmd.exe", path="",
    )]))


# ======================================================================================
# M15-2 -- ATH-005 must grade on whether anything succeeded
# ======================================================================================


@pytest.mark.parametrize("device,user,pid,ppid,minute", IDENTITIES)
def test_ath005_grades_a_failed_burst_medium_regardless_of_who(
    device, user, pid, ppid, minute
) -> None:
    """Generalization: 36 of these were graded HIGH on flaws.cloud. None succeeded."""
    produced = get_detector("ATH-005").run(telemetry(
        logons=failures(user, device, "203.0.113.9", 12, start_minute=minute),
    ))
    assert len(produced) == 1
    assert produced[0].severity is Severity.MEDIUM


@pytest.mark.parametrize("device,user,pid,ppid,minute", IDENTITIES)
def test_ath005_still_escalates_when_the_burst_succeeds(
    device, user, pid, ppid, minute
) -> None:
    """True positive: a burst that ends in a successful logon is the real thing."""
    rows = failures(user, device, "203.0.113.9", 12, start_minute=minute)
    rows.append(logon(user, device, source_ip="203.0.113.9",
                      when=at(minute + 5)))
    produced = get_detector("ATH-005").run(telemetry(logons=rows))
    assert len(produced) == 1
    assert produced[0].severity.rank > Severity.MEDIUM.rank


# ======================================================================================
# M15-3 -- K8S-001 must read the grantor's standing
# ======================================================================================

SUPERUSER_GROUPS = "system:masters,system:authenticated"

CLUSTERS = [
    pytest.param("k8s:c1", "kube-system", "bootstrap-admin", "system:apiserver", id="original"),
    pytest.param("k8s:prod-eu", "platform", "rb-7f3a", "kubecfg", id="other-cluster"),
    pytest.param("k8s:edge-17", "default", "grant-xyz", "admin@corp.example", id="human-admin"),
]


@pytest.mark.parametrize("device,ns,name,actor", CLUSTERS)
def test_k8s001_silent_when_the_grantor_already_outranks_the_grantee(
    device, ns, name, actor
) -> None:
    """Generalization across cluster, namespace, binding name and grantor identity.

    ``system:masters`` is kept constant on purpose: it is not an identifier, it is the
    Kubernetes API contract that the authorizer allows that group everything before RBAC
    is consulted. That is the security semantics the fix reads, so varying it would
    change the property under test rather than preserve it.
    """
    assert not get_detector("K8S-001").run(telemetry(ctrls=[ctrl(
        actor, "create", "clusterrolebindings", name,
        target_actor="system:serviceaccount:kube-system:deployer",
        role_ref="cluster-admin", namespace=ns, device=device,
        actor_groups=SUPERUSER_GROUPS,
    )]))


@pytest.mark.parametrize("device,ns,name,actor", CLUSTERS)
def test_k8s001_fires_when_the_grantor_does_not_outrank_the_grantee(
    device, ns, name, actor
) -> None:
    """True positive: the same grant by someone who is not already a superuser.

    One field differs from the test above -- the grantor's groups -- and it must flip
    the verdict. This is the assertion that separates "reads the grantor's standing"
    from "stopped alerting on cluster-admin".
    """
    produced = get_detector("K8S-001").run(telemetry(ctrls=[ctrl(
        actor, "create", "clusterrolebindings", name,
        target_actor="system:serviceaccount:kube-system:deployer",
        role_ref="cluster-admin", namespace=ns, device=device,
        actor_groups="system:authenticated",
    )]))
    assert len(produced) == 1


# ======================================================================================
# M15-4 -- ATH-001 must know a document application when it sees one
# ======================================================================================


@pytest.mark.parametrize("office", ["WINWORD.EXE", "EXCEL.EXE", "soffice.bin", "soffice.exe"])
@pytest.mark.parametrize("interpreter", ["powershell.exe", "cmd.exe", "wscript.exe"])
def test_ath001_fires_for_any_document_application_and_interpreter(
    office, interpreter
) -> None:
    """The Microsoft-only list was the defect; LibreOffice spawning a shell is the same
    event with a different vendor's name on it."""
    produced = get_detector("ATH-001").run(telemetry(procs=[proc(
        interpreter, f"{interpreter} -enc SQBFAFgA", office,
    )]))
    assert len(produced) == 1, f"{office} -> {interpreter} did not fire"


def test_ath001_does_not_fire_for_an_ordinary_parent() -> None:
    """The complement: a shell started by a shell is not a document macro."""
    assert not get_detector("ATH-001").run(telemetry(procs=[proc(
        "powershell.exe", "powershell.exe -enc SQBFAFgA", "explorer.exe",
    )]))
