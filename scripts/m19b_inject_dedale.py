"""M19b T5, Route A: labelled endpoint x identity cases injected into real DEDALE hours.

What this script builds, and why it has to exist
--------------------------------------------------
``reports/m19b/necessity/AUDIT.md`` measured 1 qualifying cross-domain case in 294, and
proved from the code why: ``ath.correlation.correlator`` can join two *different* domains
only through ``_auth_then_exec``, which is gated by a hardcoded allowlist::

    _AUTH_RULES = frozenset({"ATH-005", "ATH-006"})
    _REMOTE_EXEC_RULES = frozenset({"ATH-007"})

So the only cross-domain case this architecture can form at all is **identity -> endpoint**:
a logon finding followed by a service-launched shell on the same host inside
``auth_exec_window``. Route A of that audit is to build the benchmark shortfall in exactly
that shape, on the most honest background available, and to say plainly that the resulting
benchmark measures one kind of cross-domain investigation.

The background is real; the attack is not
------------------------------------------
Every case here is **real benign DEDALE background + injected attack rows**. Never "real".
The DEDALE D03 (2024-12-25) and D18 (2025-01-09) Winlogbeat slices produce **zero** findings
under the current rules (MEASURED, ``reports/m19b/necessity/AUDIT.md``), which is what makes
them usable as a background: every finding a case raises is caused by an injected row, and
the labels are therefore the only ground truth, complete by construction.

What DEDALE does *not* contain, measured here before anything was written:

* **no Security 4625 at all** on D03 or D18 -- the whole identity half of every failed-logon
  burst is injected;
* **no Sysmon 3** worth the name (2 records on D18, both NetBIOS broadcast), so no network
  domain is reachable from this data even if the correlator could use it;
* **no human account in any 4624**: the only ``TargetUserName`` values are ``SYSTEM``,
  ``UMFD-0/1``, ``DWM-1``, ``LOCAL SERVICE``, ``NETWORK SERVICE`` and the machine accounts
  ``CLIENT<N>$``. The human accounts (``BREACH\\client<N>``) appear as Sysmon ``user.name``
  and in the type 7/11 unlock records. Account names used below are therefore real DEDALE
  accounts, and each account's SID is copied from the real 4624 that carries it;
* **no whoami.exe / nltest.exe / systeminfo.exe / hostname.exe / quser.exe** process-create
  record anywhere in D03 or D18. ``ATH-010`` needs two *distinct* discovery binaries, and the
  only discovery binary DEDALE runs is ``net.exe``. Rather than invent a SHA-256 for a binary
  this dataset never hashed, the follow-on discovery in every malicious case is two
  ``net.exe`` commands, and ATH-010 deliberately does not fire. Stated, not hidden.

How an injected record is built
--------------------------------
Field values are *copied*, never imagined. Each injected record starts as a deep copy of a
real DEDALE record of the same kind (a Sysmon 1 for ``cmd.exe`` / ``net.exe``; the target
host's own Security 4624), and only the fields the story needs are overwritten. The service
context of a Service Control Manager child (``IntegrityLevel``, ``LogonId 0x3e7``,
``TerminalSessionId 0``, ``ParentUser``) is copied from that host's own real
``services.exe -> svchost.exe`` record, and the ``services.exe`` parent object -- pid,
``entity_id``, path -- is that host's real one.

Three classes of value have no real original and are generated deterministically from the
seed, because no event that did not happen has a real one: ``TargetLogonId``, the source
``IpPort``, and the injected pids / ``ProcessGuid``s. The ``ProcessGuid``s are built in
Sysmon's own encoding
(``{<machine>-<createtime lo16>-<createtime hi16>-<counter>00-<session>}``, verified against
three real DEDALE records), with the host's real machine and session groups.

The 4625 shape
---------------
DEDALE has no 4625, so its shape comes from Microsoft's documented field list for "An account
failed to log on" as Winlogbeat 7.10.2 renders it, laid on the target host's own real 4624
record: ``Status`` / ``SubStatus`` / ``FailureReason`` / ``LogonType`` / ``LogonProcessName`` /
``AuthenticationPackageName`` / ``WorkstationName`` / ``IpAddress`` / ``IpPort``,
``TargetUserSid`` = ``S-1-0-0`` (Windows writes the null SID on a failure), ``keywords`` =
``["Audit Failure"]``, ``event.outcome`` = ``failure``.
``ath.telemetry.winlogbeat_source._logon_row`` reads ``TargetUserName``, ``LogonType``,
``SubStatus`` (falling back to ``Status``), ``IpAddress`` and ``WorkstationName``; all five
are present on every injected 4625.

Determinism
------------
Everything is a pure function of ``(seed, case spec, the two DEDALE day files)``. Background
lines are re-serialised with ``json.dumps`` defaults, which round-trips DEDALE's own
formatting byte-for-byte (verified over 5,001 records), so a background line in a case file
is byte-identical to its source line minus the ``message`` field -- dropped because it is a
rendered copy of ``event_data``, unused by every adapter, and two thirds of the bytes. The
same trimming, for the same reason, as ``scripts/cut_real_shaped_fixtures.py``.

The held-out case
------------------
``HELDOUT_H1`` is generated by this same script from its own parameters; its ``labels.json``
is written to ``HELDOUT_H1/SEALED/`` and only its SHA-256 is recorded in the manifest. The
plan's words are the honest ones: *what makes it held out is the seal, not the construction*
-- the parameters are in this file, in the repository, readable by anyone. What the seal
covers is the answer key: which records are injected, what the stages are, and what the
cross-domain links are. Nothing runs ATH against H1 until the final evaluation.

Data provenance and licence
----------------------------
DEDALE (INRIA/IRISA PIRAT), https://doi.org/10.57745/Y5JLDG, https://dedale.inria.fr/ --
CC BY 4.0. The background rows committed under ``reports/m19b/cases/dedale_injected/`` are
DEDALE's bytes; the attribution travels with them in every ``CASE.md`` and in
``PROVENANCE.md``.

The external data directory is read-only input and is never written to. It is not in this
worktree (``data/external/*`` is gitignored); ``--external`` defaults to the sibling checkout
``../agentic-threat-hunter/data/external``, the same default
``scripts/m19b_necessity_audit.py`` uses.

Usage::

    python scripts/m19b_inject_dedale.py                     # all seven cases + manifest
    python scripts/m19b_inject_dedale.py --out /tmp/regen     # regeneration check
    python scripts/m19b_inject_dedale.py --only M1 L2         # a subset; no manifest
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from random import Random
from typing import Any, Iterable, Iterator

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EXTERNAL = ROOT.parent / "agentic-threat-hunter" / "data" / "external"
DEFAULT_OUT = ROOT / "reports" / "m19b" / "cases" / "dedale_injected"
DEFAULT_SEED = 19026

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SECURITY_CHANNEL = "Security"

DAYS: dict[str, str] = {"D03": "2024-12-25", "D18": "2025-01-09"}

ATTRIBUTION = (
    "DEDALE (INRIA/IRISA PIRAT), https://doi.org/10.57745/Y5JLDG, "
    "https://dedale.inria.fr/ -- licence CC BY 4.0."
)


def host_ip(host: str) -> str:
    """The estate's address for a host.

    MEASURED: CLIENT10's own Sysmon 3 records on D18 give ``source.ip`` ``172.16.1.11``.
    That is the only host -> address datum in either day file, so the addressing scheme is
    read off one host and applied as a rule -- HYPOTHESIS, and deliberately inconsequential:
    no rule reads ``source_ip`` except to group by it and to print it, so a wrong octet
    changes no verdict and no link.
    """
    return f"172.16.1.{int(host.removeprefix('CLIENT')) + 1}"


# --------------------------------------------------------------------------------------
# Case specifications
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Failure:
    """One injected 4625: when, and why it failed."""

    offset_seconds: float
    status: str
    sub_status: str
    failure_reason: str


def _bad_password(offset: float) -> Failure:
    """0xC000006D / 0xC000006A -- "unknown user name or bad password" (``%%2313``)."""
    return Failure(offset, "0xc000006d", "0xc000006a", "%%2313")


def _locked_out(offset: float) -> Failure:
    """0xC0000234 -- "account currently locked out" (``%%2307``).

    Both ``Status`` and ``SubStatus`` carry the code. Some real Windows builds write
    ``SubStatus`` ``0x0`` for this case, and ``winlogbeat_source._logon_row`` would then
    report ``failure_reason`` ``"0x0"``: it computes ``sub_status or status``, and ``"0x0"``
    is a non-empty string, so the fallback to ``Status`` never happens and the locked-out
    reason is lost. That is a real defect in the adapter; it is reported with this task and
    not worked around here. These records carry the code in both fields, which is also a
    shape real environments emit.
    """
    return Failure(offset, "0xc0000234", "0xc0000234", "%%2307")


def _even(count: int, span_seconds: float) -> tuple[Failure, ...]:
    """``count`` bad-password failures evenly spread across ``span_seconds``."""
    step = span_seconds / max(count - 1, 1)
    return tuple(_bad_password(round(i * step, 3)) for i in range(count))


SMB_EXEC_TAIL = r" 1> \\127.0.0.1\ADMIN$\__1735130400.5423 2>&1"
"""The output redirection an SMB remote-execution framework writes.

``ATH-007``'s ``_ADMIN_SHARE_REDIRECT`` matches ``\\\\<host>\\ADMIN$``; the numeric tail is
the epoch-stamped scratch file smbexec names its output after.
"""


@dataclass(frozen=True)
class CaseSpec:
    """One case: which real hours to stand on, and what to inject into them.

    ``condition_3`` is written by hand per case and is not derived from the other fields.
    ``ath.evaluation.necessity._synthesis_statement`` derives its version of condition 3 from
    conditions 1 and 2, which that module reports as a limitation; the plan asks for a
    concrete statement per case, so each one is argued below in the case's own terms.
    """

    case_id: str
    day: str
    source_host: str
    target_host: str
    hours: tuple[tuple[str, str], ...]       # (host, hour) background segments
    account: str
    malicious: bool
    scenario: str
    burst_start: str                         # HH:MM:SS, inside the target host's hour
    failures: tuple[Failure, ...]
    success_offset: float | None             # seconds after the last failure, or None
    exec_offset: float                       # seconds after the success, else the last failure
    shell_command: str
    children: tuple[tuple[float, str], ...]  # (seconds after the shell, command line)
    expected_rules: tuple[str, ...]
    expected_findings: int
    headline: str
    story: str
    condition_3: str
    stage_notes: dict[str, str]
    sealed: bool = False

    @property
    def directory_name(self) -> str:
        return "HELDOUT_H1" if self.sealed else self.case_id

    def parameters(self) -> dict[str, Any]:
        """Everything about this case that is a choice, for the manifest."""
        return {
            "day": self.day,
            "date": DAYS[self.day],
            "background_segments": [f"{h}:{hour}" for h, hour in self.hours],
            "source_host": self.source_host,
            "source_ip": host_ip(self.source_host),
            "target_host": self.target_host,
            "account": self.account,
            "malicious": self.malicious,
            "scenario": self.scenario,
            "burst_start": self.burst_start,
            "failure_count": len(self.failures),
            "failure_span_seconds": self.failures[-1].offset_seconds,
            "failure_sub_status": sorted({f.sub_status for f in self.failures}),
            "success_offset_seconds": self.success_offset,
            "exec_offset_seconds": self.exec_offset,
            "admin_share_redirect": "ADMIN$" in self.shell_command,
            "shell_command": self.shell_command,
            "child_commands": [c for _, c in self.children],
            "expected_rules": list(self.expected_rules),
            "expected_findings": self.expected_findings,
        }


_LOCKOUT_CASCADE: tuple[Failure, ...] = (
    _bad_password(0.0), _bad_password(19.0), _bad_password(41.0),
    _locked_out(64.0), _locked_out(88.0), _locked_out(113.0),
    _locked_out(139.0), _locked_out(162.0), _locked_out(187.0),
    _locked_out(211.0), _locked_out(234.0), _locked_out(258.0),
)
"""Three bad passwords, then nine retries against an already-locked account.

The shape a cached credential produces and password guessing does not: guessing keeps
receiving ``0xC000006A`` because the attacker is not the account's owner and does not stop
when it locks.
"""


CASES: tuple[CaseSpec, ...] = (
    CaseSpec(
        case_id="M1",
        day="D03",
        source_host="CLIENT7",
        target_host="CLIENT9",
        hours=(("CLIENT7", "11"), ("CLIENT9", "11")),
        account="client9",
        malicious=True,
        scenario="guessed-credential-then-remote-exec",
        burst_start="11:12:04",
        failures=_even(12, 234.0),
        success_offset=43.0,
        exec_offset=91.0,
        shell_command=(
            r'C:\Windows\system32\cmd.exe /Q /c "net group "Domain Admins" /domain'
            r' & net localgroup administrators"' + SMB_EXEC_TAIL
        ),
        children=(
            (2.4, r'net  group "Domain Admins" /domain'),
            (6.1, r"net  localgroup administrators"),
        ),
        expected_rules=("ATH-005", "ATH-007"),
        expected_findings=2,
        headline="Password guessing from CLIENT7 lands on CLIENT9, then a service-launched shell",
        story="""An operator working from **CLIENT7** guesses the password of **client9**, the
account that owns **CLIENT9**. Twelve network logons for that account fail on CLIENT9 inside
four minutes, all with sub-status `0xC000006A` (bad password); the thirteenth attempt succeeds
(type 3, NTLM, from CLIENT7). Ninety-one seconds later the Service Control Manager on CLIENT9
starts a command shell whose output is redirected to `\\\\127.0.0.1\\ADMIN$` -- the signature
of an SMB remote-execution framework collecting results over the wire -- and that shell runs
two domain-enumeration commands.""",
        condition_3="""The endpoint rows on CLIENT9 show `services.exe` starting `cmd.exe`
**as SYSTEM**. That is all they can show: a service body has no user, so on the endpoint
evidence alone the shell is anonymous, and the honest endpoint verdict is the one ATH-007
writes -- "consistent with remote command execution via a temporary service", which is also
what a patch-management agent looks like. The identity rows name an account and an origin
host, and say the credential was guessed rather than known; they cannot show that anything
was *done* with it, because a type 3 logon that guesses right and then does nothing is a
scanner.

Combining them changes all three things the plan asks about. **Verdict**: an anonymous SYSTEM
shell becomes a shell whose arrival is explained by a credential that was being guessed ninety
seconds earlier from a named host. **Priority**: ATH-005 alone is triaged as "attempted, check
the account"; ATH-007 alone as "confirm which admin tool did this"; together they describe a
landed intrusion on a host the operator now executes on. **Next action**: neither finding alone
implicates CLIENT7 -- the source host appears only in the identity rows, and the thing worth
containing, the operator's foothold, is there and not on CLIENT9.""",
        stage_notes={
            "1-credential-guessing": "twelve failed type 3 logons for one account from one host in 234s",
            "2-successful-logon": "the same account, same source, succeeds 43s after the last failure",
            "3-remote-service-execution": "services.exe starts cmd.exe, output redirected to ADMIN$",
            "4-discovery": "domain and local group enumeration from that shell",
        },
    ),
    CaseSpec(
        case_id="M2",
        day="D03",
        source_host="CLIENT12",
        target_host="CLIENT3",
        hours=(("CLIENT12", "12"), ("CLIENT3", "12")),
        account="client3",
        malicious=True,
        scenario="slow-guessing-then-delayed-remote-exec",
        burst_start="12:03:00",
        failures=_even(14, 570.0),
        success_offset=130.0,
        exec_offset=760.0,
        shell_command=(
            r'C:\Windows\system32\cmd.exe /Q /c "net localgroup administrators'
            r' & net group "Domain Computers" /domain"' + SMB_EXEC_TAIL
        ),
        children=(
            (3.2, r"net  localgroup administrators"),
            (9.7, r'net  group "Domain Computers" /domain'),
        ),
        expected_rules=("ATH-005", "ATH-007"),
        expected_findings=2,
        headline="A slower burst against CLIENT3, and execution at the far edge of the correlation window",
        story="""The same shape as M1, paced to sit against two of the pipeline's own
thresholds rather than comfortably inside them. Fourteen failures for **client3** on
**CLIENT3** from **CLIENT12** are spread over **9m30s** -- inside `bruteforce_window`
(10 minutes) with thirty seconds to spare, so one episode is reported rather than two. The
success arrives 130s later, and the service-launched shell **12m40s** after that: inside
`auth_exec_window` (15 minutes), which is what lets the correlator join the identity finding
to the endpoint one at all. A benchmark that only ever tested the middle of a window would
not notice the day either bound moved.""",
        condition_3="""Same structure as M1, with the timing doing extra work. Thirteen
minutes is long enough that an analyst reading the endpoint finding alone has no reason to
look back at authentication: the two events are not adjacent in any queue, and the shell is
the only thing in the case whose severity demands attention. The identity rows supply the
*interval* -- "a credential for this host was guessed twelve minutes before this service
started" is a statement neither domain can make alone, and it is the statement that decides
whether the shell is an admin tool or the second stage of an intrusion.

**Next action** differs from M1's as well: at this spacing the credential has been usable for
over twelve minutes, so the containment question is what *else* it reached in that window --
a question only the identity rows can be asked.""",
        stage_notes={
            "1-credential-guessing": "fourteen failed type 3 logons over 570s, just inside the 10-minute window",
            "2-successful-logon": "success 130s after the last failure",
            "3-remote-service-execution": "the service-launched shell arrives 760s later, near the 15-minute edge",
            "4-discovery": "local and domain group enumeration from that shell",
        },
    ),
    CaseSpec(
        case_id="M3",
        day="D18",
        source_host="CLIENT7",
        target_host="CLIENT9",
        hours=(("CLIENT7", "08"), ("CLIENT9", "09")),
        account="client9",
        malicious=True,
        scenario="foreign-host-credential-use-then-remote-exec",
        burst_start="09:21:16",
        failures=_even(11, 188.0),
        success_offset=37.0,
        exec_offset=104.0,
        shell_command=(
            r'C:\Windows\system32\cmd.exe /Q /c "net group "Domain Admins" /domain'
            r' & net use"' + SMB_EXEC_TAIL
        ),
        children=(
            (2.9, r'net  group "Domain Admins" /domain'),
            (7.8, r"net  use"),
        ),
        expected_rules=("ATH-005", "ATH-006", "ATH-007"),
        expected_findings=3,
        headline="The same chain where the origin host has an ownership baseline, so ATH-006 fires too",
        story="""**CLIENT7**'s background segment here is its boot hour, so the real data
contains client7's own interactive unlock on CLIENT7 -- an *ownership baseline* in ATH-006's
sense. The operator guesses **client9**'s password from CLIENT7 and succeeds, so the identity
domain reads the same successful logon twice: ATH-005 grades the guessing, and ATH-006
observes that client9 has no session on the host the credential is being used from. The
endpoint half is unchanged -- a service-launched shell with an ADMIN$ redirect on CLIENT9,
104 seconds after the success.

This is the only case here whose identity evidence carries two findings, and the only one that
exercises the other half of the correlator's allowlist: `_AUTH_RULES` contains ATH-006 as well
as ATH-005, and no case in the corpus audit ever exercised that edge.""",
        condition_3="""ATH-006's whole claim is about a host it has no other evidence from:
"this credential is being used from CLIENT7, where it has no session". Whether that matters
depends entirely on what happened at the destination -- an account authenticating from an
unusual host and then doing nothing is a mapped drive or a `runas /netonly`, the first false
positive ATH-006's own docstring lists. The endpoint rows on CLIENT9 are what turn "unusual
origin" into "unusual origin, then a shell".

The converse is sharper here than in M1: with two identity findings an analyst who reads only
the identity domain sees corroboration -- two rules agreeing -- and can still be entirely wrong
about severity, because both rules are reading **the same logon rows**. The endpoint rows are
the only independent evidence source in the case, which is exactly what condition 2 is asking
about.""",
        stage_notes={
            "1-credential-guessing": "eleven failed type 3 logons for client9 on CLIENT9 from CLIENT7",
            "2-successful-logon": "success from a host where the account has no interactive session",
            "3-remote-service-execution": "services.exe starts cmd.exe with an ADMIN$ redirect",
            "4-discovery": "domain group enumeration and a mapped-drive listing",
        },
    ),
    CaseSpec(
        case_id="M4",
        day="D18",
        source_host="CLIENT12",
        target_host="CLIENT3",
        hours=(("CLIENT12", "13"), ("CLIENT3", "13")),
        account="client3",
        malicious=True,
        scenario="unsuccessful-guessing-then-remote-exec",
        burst_start="13:31:00",
        failures=_even(11, 260.0),
        success_offset=None,
        exec_offset=105.0,
        shell_command=(
            r'C:\Windows\system32\cmd.exe /Q /c "net localgroup administrators'
            r' & net group "Domain Admins" /domain"' + SMB_EXEC_TAIL
        ),
        children=(
            (3.6, r"net  localgroup administrators"),
            (8.4, r'net  group "Domain Admins" /domain'),
        ),
        expected_rules=("ATH-005", "ATH-007"),
        expected_findings=2,
        headline="The burst never succeeds: does the cross-domain link survive a MEDIUM?",
        story="""Eleven failures for **client3** on **CLIENT3** from **CLIENT12**, and no
successful logon from that source at all. ATH-005 grades this **MEDIUM**, not CRITICAL -- its
stated condition, a success, was not met -- and M14 established that grading such a burst HIGH
produced 35 untriageable singleton cases on flaws.cloud. The endpoint half is unchanged, and
fires HIGH.

The case is here to answer a question the benchmark would otherwise never ask: the
correlator's `_auth_then_exec` is gated on **rule id**, not on severity, so a MEDIUM identity
finding should still link. If it does, this is the case where the model arms have the most to
add and the least to lean on -- the identity evidence is graded as *not* an incident, and the
story exists only across the two domains.""",
        condition_3="""This is the case where one-domain reasoning reaches the wrong answer
rather than an incomplete one. The identity rows say, correctly, that the guessing did not
land: no success from CLIENT12 exists, which is why the rule grades MEDIUM, and read alone the
right next action is "monitor". The endpoint rows say a service started a shell with an ADMIN$
redirect on the same host 105 seconds after the last failure -- read alone, the right next
action is "confirm with the owner which tool did this".

Together they say something neither says: the operator reached execution on CLIENT3 without a
logon this telemetry can show, so **the credential did not come from this burst**. That is a
different incident -- a host already compromised, or an account whose success was logged
somewhere this collection does not cover -- and the next action is a collection question, not
a containment one. A crew that reports "brute force, unsuccessful; plus a suspicious service"
has produced two true statements and the wrong investigation.""",
        stage_notes={
            "1-credential-guessing": "eleven failed type 3 logons and no success from that source",
            "3-remote-service-execution": "a service-launched shell with an ADMIN$ redirect 105s later",
            "4-discovery": "local and domain group enumeration from that shell",
        },
    ),
    CaseSpec(
        case_id="L1",
        day="D03",
        source_host="CLIENT7",
        target_host="CLIENT9",
        hours=(("CLIENT9", "08"), ("CLIENT7", "09")),
        account="client9",
        malicious=False,
        scenario="administrator-lockout-then-remote-support",
        burst_start="08:41:12",
        failures=_LOCKOUT_CASCADE,
        success_offset=430.0,
        exec_offset=90.0,
        shell_command=(
            r'C:\Windows\system32\cmd.exe /Q /c "net stop spooler & net start spooler"'
            + SMB_EXEC_TAIL
        ),
        children=(
            (2.1, r"net  stop spooler"),
            (11.9, r"net  start spooler"),
        ),
        expected_rules=("ATH-005", "ATH-007"),
        expected_findings=2,
        headline=(
            "BENIGN LOOK-ALIKE: an account lockout and a PsExec support action -- the same "
            "rules at the same severities as M1"
        ),
        story="""**client9** is the support engineer whose own workstation is CLIENT9: the real
background hour carries that account's genuine interactive unlock there (type 11 and type 7 at
08:02:59, real DEDALE records, not injected). Working from a colleague's desk at **CLIENT7**, a
client holding a cached old password retries three times (`0xC000006A`), trips the lockout
threshold, and then retries nine more times against a locked account (`0xC0000234`). The
service desk unlocks it; seven minutes later the engineer authenticates successfully from
CLIENT7 and runs a remote-support action on their own workstation -- PsExec restarting the
print spooler, which writes its output to `ADMIN$` exactly as an attacker's tooling does.

**Labelled `malicious: false`.** It fires ATH-005 CRITICAL and ATH-007 HIGH: the same rules at
the same severities as M1, forming the same single cross-domain case. Detection alone cannot
separate the two, which is the reason this case exists.""",
        condition_3="""Here cross-domain synthesis changes the verdict in the direction that
costs a team its trust in the tool, and it is the only thing that can. Three facts decide it,
and no two of them live in the same domain:

1. the **failure reasons** are a lockout cascade -- three bad passwords, then nine
   `0xC0000234` retries against an already-locked account -- which is what a stale cached
   credential does and not what guessing does, since guessing keeps receiving `0xC000006A`;
2. the **account owns the target host**: the same background hour carries client9's real
   interactive unlock on CLIENT9, so the credential is being used *towards* the host it
   belongs on rather than away from one;
3. the **executed commands** are `net stop spooler` / `net start spooler` -- a ticket, not
   enumeration -- and that is endpoint evidence, invisible to identity.

An analyst with only the identity rows escalates: twelve failures then a success is the
textbook CRITICAL. An analyst with only the endpoint rows escalates: an ADMIN$ redirect is the
textbook remote-execution signature. Only the combination de-escalates, and the next action it
produces -- close it, and ask why an old password was still cached at CLIENT7 -- is not
reachable from either domain alone.""",
        stage_notes={
            "1-stale-credential-lockout": "three bad-password failures, then nine against a locked account",
            "2-logon-after-unlock": "success from the same host after the service desk unlocks it",
            "3-remote-support-action": "PsExec-style service-launched shell, output to ADMIN$",
            "4-support-commands": "the print spooler is stopped and started",
        },
    ),
    CaseSpec(
        case_id="L2",
        day="D18",
        source_host="CLIENT3",
        target_host="CLIENT12",
        hours=(("CLIENT3", "14"), ("CLIENT12", "14")),
        account="client3",
        malicious=False,
        scenario="scheduled-backup-with-stale-password",
        burst_start="14:02:10",
        failures=tuple(_bad_password(round(i * 48.0, 3)) for i in range(12)),
        success_offset=48.0,
        exec_offset=94.0,
        shell_command=(
            r'C:\Windows\system32\cmd.exe /Q /c "C:\BREACH\backup\prejob.cmd'
            r' --target CLIENT12 --set nightly"'
        ),
        children=(),
        expected_rules=("ATH-005", "ATH-007"),
        expected_findings=2,
        headline=(
            "BENIGN LOOK-ALIKE: a scheduled job whose stored password went stale, then that "
            "job's own pre-job script"
        ),
        story="""A backup schedule on **CLIENT3** authenticates to **CLIENT12** as **client3**
every 48 seconds. The stored password was rotated and the schedule was not updated, so twelve
consecutive cycles fail with `0xC000006A` over 8m48s. An operator corrects the stored
credential; the next cycle succeeds, and 94 seconds later the backup agent's service starts its
pre-job script through the Service Control Manager -- `services.exe -> cmd.exe` running
`C:\\BREACH\\backup\\prejob.cmd`, with **no ADMIN$ redirect**, so ATH-007 grades it MEDIUM and
says so: "this may be a legitimate service-based automation".

**Labelled `malicious: false`.** ATH-005 still grades CRITICAL, because its stated condition --
failures then a success from the same source -- is met exactly.""",
        condition_3="""The discriminating evidence is a *rhythm* and a *path*, and they are in
different domains. The identity rows carry the rhythm: twelve failures spaced 48.000 seconds
apart, which no human and no guessing tool produces -- a fact ATH-005 does not look at, because
it counts failures and never measures their spacing. The endpoint rows carry the path: what the
service started is `C:\\BREACH\\backup\\prejob.cmd --target CLIENT12 --set nightly`, named for
the schedule and for the target, with no redirect to an administrative share.

Either alone is a false positive. Identity alone is a CRITICAL brute-force verdict on a backup
job. Endpoint alone is a MEDIUM finding an analyst sets aside without ever learning that a dozen
failed logons preceded it, and so without asking the one question that matters -- **is anything
else on this estate still authenticating with the old password?** That next action is reachable
only from the two domains together, and it is an operational finding, not an incident.""",
        stage_notes={
            "1-stale-scheduled-credential": "twelve failures at an exact 48s cadence",
            "2-credential-corrected": "the next scheduled cycle succeeds",
            "3-service-started-script": "services.exe starts the backup agent's pre-job script, no ADMIN$ redirect",
        },
    ),
    CaseSpec(
        case_id="H1",
        day="D18",
        source_host="CLIENT26",
        target_host="CLIENT28",
        hours=(("CLIENT26", "16"), ("CLIENT28", "16")),
        account="client28",
        malicious=True,
        scenario="guessed-credential-then-remote-exec",
        burst_start="16:18:22",
        failures=_even(13, 301.0),
        success_offset=66.0,
        exec_offset=143.0,
        shell_command=(
            r'C:\Windows\system32\cmd.exe /Q /c "net localgroup administrators'
            r' & net group "Domain Admins" /domain"' + SMB_EXEC_TAIL
        ),
        children=(
            (3.1, r"net  localgroup administrators"),
            (8.8, r'net  group "Domain Admins" /domain'),
        ),
        expected_rules=("ATH-005", "ATH-007"),
        expected_findings=2,
        headline="HELD OUT until the final evaluation",
        story="""Generated by this same script, from its own parameters, into the same kind of
real benign DEDALE background. **Nothing is run against this case until the final
evaluation**: no hunt, no correlation, no investigation, no arm.

Its `labels.json` -- which records are injected, what the stages are, and what the cross-domain
links are -- is sealed in `SEALED/`, and only its SHA-256 appears in `MANIFEST.json`. The
plan's sentence is the honest description: *what makes it held out is the seal, not the
construction.* The parameters are in `scripts/m19b_inject_dedale.py`, in this repository,
readable by anyone who chooses to; the discipline is what is being relied on, and it is being
relied on openly.""",
        condition_3="""Stated without the case's specifics, which are sealed: this is the same
endpoint x identity shape as M1-M4 -- an identity finding over Security logon rows and an
endpoint finding over Sysmon process rows, joined by `auth_then_exec`, each domain carrying a
stage the other does not. Verdict, priority and next action turn on combining them for the
reasons argued case by case in `M1/CASE.md` and `M4/CASE.md`; the concrete argument for this
case is in the sealed label file and is written out at the final evaluation, not before.""",
        stage_notes={
            "1-credential-guessing": "sealed",
            "2-successful-logon": "sealed",
            "3-remote-service-execution": "sealed",
            "4-discovery": "sealed",
        },
        sealed=True,
    ),
)


# --------------------------------------------------------------------------------------
# Reading the real day, once
# --------------------------------------------------------------------------------------


def _ts(record: dict[str, Any]) -> dt.datetime:
    return dt.datetime.fromisoformat(str(record["@timestamp"]).replace("Z", "+00:00"))


def _iso(stamp: dt.datetime) -> str:
    """Winlogbeat's own rendering: millisecond precision, ``Z``."""
    return stamp.strftime("%Y-%m-%dT%H:%M:%S.") + f"{stamp.microsecond // 1000:03d}Z"


@dataclass
class HostTemplates:
    """The real records of one host that an injected record is built out of."""

    agent: dict[str, Any]
    host: dict[str, Any]
    ecs: dict[str, Any]
    security: dict[str, Any] | None = None        # a real 4624 from this host
    service_child: dict[str, Any] | None = None   # a real services.exe -> * process create
    security_lag: float = 120.0                   # median event.created - @timestamp
    sysmon_lag: float = 120.0


@dataclass
class DayExtract:
    """Everything one DEDALE day file yields for the cases built on it."""

    day: str
    date: str
    path: Path
    segments: dict[tuple[str, str], list[dict[str, Any]]]
    hosts: dict[str, HostTemplates]
    account_sids: dict[str, str]
    binaries: dict[str, dict[str, Any]]
    binary_origin: dict[str, str]


def _median(values: list[float], default: float) -> float:
    if not values:
        return default
    values = sorted(values)
    return values[len(values) // 2]


def read_day(
    path: Path, day: str, wanted: set[tuple[str, str]], accounts: set[str]
) -> DayExtract:
    """One pass over a 300 MB day file, collecting every input the cases need.

    A cheap substring test decides whether a line is worth parsing; at ~4 KB per record and
    ~80,000 records a full ``json.loads`` sweep is minutes, and nothing here needs the
    records this test skips.
    """
    date = DAYS[day]
    want_hosts = {h for h, _ in wanted}
    host_markers = tuple(f'"host": {{"name": "{h}.breach.local"}}' for h in sorted(want_hosts))
    hour_prefixes = tuple(sorted({f'{{"@timestamp": "{date}T{hour}:' for _, hour in wanted}))

    segments: dict[tuple[str, str], list[dict[str, Any]]] = {k: [] for k in wanted}
    hosts: dict[str, HostTemplates] = {}
    account_sids: dict[str, str] = {}
    binaries: dict[str, dict[str, Any]] = {}
    binary_origin: dict[str, str] = {}
    lags: dict[tuple[str, str], list[float]] = {}

    want_binaries = {"cmd.exe", "net.exe"}
    account_markers = {a: f'"TargetUserName": "{a}"' for a in accounts}

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            in_segment = (
                line.startswith(hour_prefixes)
                and any(marker in line for marker in host_markers)
            )
            wants_binary = any(f'"name": "{b}"' in line for b in want_binaries - set(binaries))
            wants_account = any(m in line for a, m in account_markers.items() if a not in account_sids)
            wants_service = '"name": "services.exe"' in line
            if not (in_segment or wants_binary or wants_account or wants_service):
                continue

            record = json.loads(line)
            record.pop("message", None)
            winlog = record.get("winlog") or {}
            channel = str(winlog.get("channel") or "")
            event_id = winlog.get("event_id")
            short = str((record.get("host") or {}).get("name") or "").split(".")[0]
            stamp = _ts(record)
            hour = f"{stamp.hour:02d}"

            if (short, hour) in segments and stamp.strftime("%Y-%m-%d") == date:
                segments[(short, hour)].append(record)
                created = record.get("event", {}).get("created")
                if created:
                    lag = (dt.datetime.fromisoformat(created.replace("Z", "+00:00")) - stamp)
                    lags.setdefault((short, channel), []).append(lag.total_seconds())

            if short in want_hosts and short not in hosts:
                hosts[short] = HostTemplates(
                    agent=copy.deepcopy(record["agent"]),
                    host=copy.deepcopy(record["host"]),
                    ecs=copy.deepcopy(record.get("ecs", {"version": "1.5.0"})),
                )
            if short in hosts:
                entry = hosts[short]
                if entry.security is None and channel == SECURITY_CHANNEL and event_id == 4624:
                    entry.security = copy.deepcopy(record)
                process = record.get("process") or {}
                if (
                    entry.service_child is None
                    and channel == SYSMON_CHANNEL
                    and event_id == 1
                    and str((process.get("parent") or {}).get("name") or "").lower() == "services.exe"
                ):
                    entry.service_child = copy.deepcopy(record)

            if channel == SECURITY_CHANNEL and event_id == 4624:
                data = winlog.get("event_data") or {}
                name = str(data.get("TargetUserName") or "")
                sid = str(data.get("TargetUserSid") or "")
                if name in accounts and name not in account_sids and sid.startswith("S-1-5-21"):
                    account_sids[name] = sid

            if channel == SYSMON_CHANNEL and event_id == 1:
                name = str((record.get("process") or {}).get("name") or "").lower()
                if name in want_binaries and name not in binaries:
                    binaries[name] = copy.deepcopy(record)
                    binary_origin[name] = f"{short} {record['@timestamp']}"

    for (host, channel), values in lags.items():
        if host not in hosts:
            continue
        if channel == SECURITY_CHANNEL:
            hosts[host].security_lag = round(_median(values, 120.0), 3)
        elif channel == SYSMON_CHANNEL:
            hosts[host].sysmon_lag = round(_median(values, 120.0), 3)

    for key, rows in segments.items():
        rows.sort(key=_ts)
        if not rows:
            raise SystemExit(f"REFUSED: {path.name} carries no records for segment {key}")
    for host in want_hosts:
        entry = hosts.get(host)
        if entry is None or entry.security is None or entry.service_child is None:
            raise SystemExit(
                f"REFUSED: {path.name} carries no 4624 and/or services.exe-child template "
                f"for {host}; an injected record would have to invent fields"
            )
    missing_accounts = accounts - set(account_sids)
    if missing_accounts:
        raise SystemExit(
            f"REFUSED: no real SID found in {path.name} for {sorted(missing_accounts)}; "
            "an injected logon would have to invent one"
        )
    for binary in want_binaries:
        if binary not in binaries:
            raise SystemExit(f"REFUSED: {path.name} carries no Sysmon 1 record for {binary}")

    return DayExtract(
        day=day, date=date, path=path, segments=segments, hosts=hosts,
        account_sids=account_sids, binaries=binaries, binary_origin=binary_origin,
    )


# --------------------------------------------------------------------------------------
# Building the injected records
# --------------------------------------------------------------------------------------


def _process_guid(template_guid: str, stamp: dt.datetime, counter: int) -> str:
    """A Sysmon ProcessGuid in Sysmon's own encoding, for this host and this moment.

    Verified against three real DEDALE records: ``{416dd0c5-bc26-676b-a600-000000000900}``
    at ``08:02:46`` decodes as ``0x676bbc26`` = that second, with group 1 the machine and
    group 5 the boot session. Groups 1 and 5 are copied from the host's own record so an
    injected process belongs to the same machine and boot as the real ones around it.
    """
    parts = template_guid.strip("{}").split("-")
    seconds = int(stamp.timestamp())
    return "{%s-%04x-%04x-%02x00-%s}" % (
        parts[0], seconds & 0xFFFF, (seconds >> 16) & 0xFFFF, counter & 0xFF, parts[4],
    )


def _used_pids(records: Iterable[dict[str, Any]]) -> set[int]:
    used: set[int] = set()
    for record in records:
        process = record.get("process") or {}
        for value in (process.get("pid"), (process.get("parent") or {}).get("pid")):
            if isinstance(value, int):
                used.add(value)
    return used


class _Injector:
    """Builds one case's injected records from one day's real ones."""

    def __init__(self, spec: CaseSpec, extract: DayExtract, seed: int) -> None:
        self.spec = spec
        self.extract = extract
        self.rng = Random(f"{seed}:{spec.case_id}")
        self.target = extract.hosts[spec.target_host]
        self.segment = extract.segments[(spec.target_host, self._target_hour())]
        self.pid_pool = _used_pids(self.segment)
        self.records: list[dict[str, Any]] = []
        self.refs: dict[str, list[str]] = {}

    def _target_hour(self) -> str:
        for host, hour in self.spec.hours:
            if host == self.spec.target_host:
                return hour
        raise SystemExit(f"REFUSED: {self.spec.case_id} has no segment for its target host")

    # -- primitives ------------------------------------------------------------------

    def _next_pid(self) -> int:
        while True:
            pid = self.rng.randrange(600, 9000) * 4
            if pid not in self.pid_pool:
                self.pid_pool.add(pid)
                return pid

    def _jitter(self) -> int:
        """Milliseconds. Real Winlogbeat timestamps are never round."""
        return self.rng.randrange(1, 999)

    def _at(self, base: dt.datetime, offset: float) -> dt.datetime:
        return base + dt.timedelta(seconds=offset, milliseconds=self._jitter())

    def _logon_skeleton(self, stamp: dt.datetime) -> dict[str, Any]:
        record = copy.deepcopy(self.target.security)
        record.pop("message", None)
        record["@timestamp"] = _iso(stamp)
        record["event"] = dict(record["event"])
        record["event"]["created"] = _iso(
            stamp + dt.timedelta(seconds=self.target.security_lag)
        )
        record["winlog"] = copy.deepcopy(record["winlog"])
        # A per-operation correlation GUID belonging to a real, different operation would be
        # a false join; the real records that lack one show the shape is valid without it.
        record["winlog"].pop("activity_id", None)
        return record

    def _logon_id(self) -> str:
        return "0x%x" % self.rng.randrange(0x40000, 0xFFFFF)

    def _port(self) -> str:
        return str(self.rng.randrange(49152, 65535))

    # -- the records themselves --------------------------------------------------------

    def failure(self, stamp: dt.datetime, failure: Failure) -> dict[str, Any]:
        record = self._logon_skeleton(stamp)
        record["event"]["code"] = 4625
        record["event"]["action"] = "Logon"
        record["event"]["outcome"] = "failure"
        winlog = record["winlog"]
        winlog["event_id"] = 4625
        winlog["keywords"] = ["Audit Failure"]
        winlog["task"] = "Logon"
        winlog["version"] = 0
        winlog["event_data"] = {
            "AuthenticationPackageName": "NTLM",
            "FailureReason": failure.failure_reason,
            "IpAddress": host_ip(self.spec.source_host),
            "IpPort": self._port(),
            "KeyLength": "0",
            "LmPackageName": "-",
            "LogonProcessName": "NtLmSsp ",
            "LogonType": "3",
            "ProcessId": "0x0",
            "ProcessName": "-",
            "Status": failure.status,
            "SubStatus": failure.sub_status,
            "SubjectDomainName": "-",
            "SubjectLogonId": "0x0",
            "SubjectUserName": "-",
            "SubjectUserSid": "S-1-0-0",
            "TargetDomainName": "BREACH",
            "TargetUserName": self.spec.account,
            "TargetUserSid": "S-1-0-0",
            "TransmittedServices": "-",
            "WorkstationName": self.spec.source_host,
        }
        return record

    def success(self, stamp: dt.datetime) -> dict[str, Any]:
        record = self._logon_skeleton(stamp)
        record["event"]["code"] = 4624
        record["event"]["action"] = "Logon"
        record["event"]["outcome"] = "success"
        winlog = record["winlog"]
        winlog["event_id"] = 4624
        winlog["keywords"] = ["Audit Success"]
        winlog["task"] = "Logon"
        winlog["version"] = 2
        winlog["event_data"] = {
            "AuthenticationPackageName": "NTLM",
            "ElevatedToken": "%%1842",
            "ImpersonationLevel": "%%1833",
            "IpAddress": host_ip(self.spec.source_host),
            "IpPort": self._port(),
            "KeyLength": "128",
            "LmPackageName": "NTLM V2",
            "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
            "LogonProcessName": "NtLmSsp ",
            "LogonType": "3",
            "ProcessId": "0x0",
            "ProcessName": "-",
            "RestrictedAdminMode": "-",
            "SubjectDomainName": "-",
            "SubjectLogonId": "0x0",
            "SubjectUserName": "-",
            "SubjectUserSid": "S-1-0-0",
            "TargetDomainName": "BREACH",
            "TargetLinkedLogonId": "0x0",
            "TargetLogonId": self._logon_id(),
            "TargetOutboundDomainName": "-",
            "TargetOutboundUserName": "-",
            "TargetUserName": self.spec.account,
            "TargetUserSid": self.extract.account_sids[self.spec.account],
            "TransmittedServices": "-",
            "VirtualAccount": "%%1843",
            "WorkstationName": self.spec.source_host,
        }
        return record

    def process(
        self,
        stamp: dt.datetime,
        binary: str,
        command_line: str,
        parent: dict[str, Any],
        counter: int,
    ) -> dict[str, Any]:
        """A Sysmon 1 for ``binary``, built on the real record of that same binary."""
        template = self.extract.binaries[binary]
        service_child = self.target.service_child
        record = copy.deepcopy(template)
        record.pop("message", None)
        record["@timestamp"] = _iso(stamp)
        record["agent"] = copy.deepcopy(self.target.agent)
        record["host"] = copy.deepcopy(self.target.host)
        record["ecs"] = copy.deepcopy(self.target.ecs)
        record["event"] = dict(record["event"])
        record["event"]["created"] = _iso(stamp + dt.timedelta(seconds=self.target.sysmon_lag))
        # A service body runs as SYSTEM: this is why the endpoint domain cannot name the
        # account, and why the case needs the identity rows to do it.
        record["user"] = {"domain": "NT AUTHORITY", "name": "SYSTEM"}
        record["related"] = copy.deepcopy(record.get("related") or {})
        record["related"]["user"] = "SYSTEM"

        pid = self._next_pid()
        process = copy.deepcopy(record["process"])
        process["pid"] = pid
        process["entity_id"] = _process_guid(
            service_child["process"]["entity_id"], stamp, counter,
        )
        process["command_line"] = command_line
        process["args"] = command_line.split(" ")
        process["working_directory"] = "C:\\Windows\\system32\\"
        process["parent"] = copy.deepcopy(parent)
        record["process"] = process

        winlog = copy.deepcopy(record["winlog"])
        winlog["computer_name"] = self.target.host["name"]
        winlog["process"] = copy.deepcopy(service_child["winlog"]["process"])
        data = dict(winlog["event_data"])
        service_data = service_child["winlog"]["event_data"]
        for key in ("IntegrityLevel", "LogonGuid", "LogonId", "ParentUser", "TerminalSessionId"):
            if key in service_data:
                data[key] = service_data[key]
        data["ParentUser"] = "NT AUTHORITY\\SYSTEM"
        winlog["event_data"] = data
        record["winlog"] = winlog
        return record

    def build(self) -> list[tuple[str, dict[str, Any]]]:
        """Every injected record, tagged with the stage it belongs to."""
        spec = self.spec
        hour = int(self._target_hour())
        h, m, s = (int(p) for p in spec.burst_start.split(":"))
        date = dt.datetime.strptime(self.extract.date, "%Y-%m-%d").replace(
            tzinfo=dt.timezone.utc
        )
        base = date.replace(hour=h, minute=m, second=s)
        if h != hour:
            raise SystemExit(
                f"REFUSED: {spec.case_id} starts at {spec.burst_start}, outside its "
                f"target segment hour {hour:02d}"
            )

        stages = list(spec.stage_notes)
        tagged: list[tuple[str, dict[str, Any]]] = []

        for failure in spec.failures:
            stamp = self._at(base, failure.offset_seconds)
            tagged.append((stages[0], self.failure(stamp, failure)))

        last_failure = base + dt.timedelta(seconds=spec.failures[-1].offset_seconds)
        if spec.success_offset is not None:
            anchor = self._at(last_failure, spec.success_offset)
            tagged.append((stages[1], self.success(anchor)))
        else:
            anchor = last_failure

        exec_stamp = self._at(anchor, spec.exec_offset)
        parent = copy.deepcopy(self.target.service_child["process"]["parent"])
        shell = self.process(exec_stamp, "cmd.exe", spec.shell_command, parent, counter=0x8C)
        exec_stage = stages[-2] if spec.children else stages[-1]
        tagged.append((exec_stage, shell))

        shell_parent = {
            "args": list(shell["process"]["args"]),
            "command_line": shell["process"]["command_line"],
            "entity_id": shell["process"]["entity_id"],
            "executable": shell["process"]["executable"],
            "name": "cmd.exe",
            "pid": shell["process"]["pid"],
        }
        for index, (offset, command) in enumerate(spec.children, start=1):
            stamp = self._at(exec_stamp, offset)
            child = self.process(
                stamp, "net.exe", command, shell_parent, counter=0x8C + index,
            )
            tagged.append((stages[-1], child))

        if exec_stamp.hour != hour or tagged[-1][1]["@timestamp"][11:13] != f"{hour:02d}":
            raise SystemExit(
                f"REFUSED: {spec.case_id} injects outside its background hour; the "
                "background would not cover the story"
            )
        return tagged


# --------------------------------------------------------------------------------------
# Assembling a case directory
# --------------------------------------------------------------------------------------


def _args(command_line: str) -> list[str]:
    """A plausible ``process.args`` for a command line.

    Windows' own argv splitting is not a whitespace split, and DEDALE's records show it:
    ``net  use Z: ...`` splits to ``["net", "use", "Z:", ...]`` while a quoted batch path
    keeps its trailing space. This is an approximation -- whitespace outside double quotes,
    empties dropped, quotes removed -- and it is honest to call it one. No adapter in this
    repository reads ``process.args``; the field is populated so the record looks like the
    records around it, not because anything depends on its exact tokenisation.
    """
    out: list[str] = []
    current: list[str] = []
    quoted = False
    for char in command_line:
        if char == '"':
            quoted = not quoted
        elif char == " " and not quoted:
            if current:
                out.append("".join(current))
                current = []
        else:
            current.append(char)
    if current:
        out.append("".join(current))
    return out


def _ref(record: dict[str, Any]) -> str:
    """The native label ref for a record: what DEDALE's own label files name.

    ``ath.evaluation.external_labels.resolve_labels`` matches every ``key=value`` pair of a
    ref against the ``key=value`` pairs of a row's ``source_ref``, which
    ``winlogbeat_source._reference`` writes as
    ``host=...;channel=...;record_id=...;File=...``. ``File`` is deliberately left off:
    the triple already identifies the record, and a ref carrying the file name would stop
    resolving the day a case's segments were split differently.
    """
    winlog = record["winlog"]
    return (
        f"host={record['host']['name']};channel={winlog['channel']};"
        f"record_id={winlog['record_id']}"
    )


def _write(path: Path, text: str) -> None:
    r"""Write UTF-8 with LF endings, on every platform.

    ``Path.write_text`` opens in text mode, so on Windows it turns every ``\n`` into
    ``\r\n``: the committed telemetry would stop being byte-identical to DEDALE's own lines,
    and every SHA-256 in ``MANIFEST.json`` would be a Windows-only digest. The matching half
    of this is the ``.gitattributes`` entry marking these paths ``-text``, so git checks them
    out verbatim instead of converting them back.

    (``Path.write_text`` grew a ``newline`` argument in 3.10; this project runs on 3.9.)
    """
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _script_sha256(path: Path) -> str:
    """The generator's own hash over LF-normalised bytes.

    The manifest hashes case files as committed bytes (protected by .gitattributes), but
    the script itself is checked out under core.autocrlf on Windows, so its on-disk bytes
    differ by line ending from the bytes that were hashed at generation time. Normalising
    makes the identity claim about the code, not about the checkout.
    """
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def _segment_file(host: str, date: str, hour: str) -> str:
    return f"{host}_{date}T{hour}.jsonl"


def assign_record_ids(
    tagged: list[tuple[str, dict[str, Any]]], background: list[dict[str, Any]]
) -> None:
    """Give every injected record a record id no background record on its channel holds.

    Ids continue that host-and-channel's own sequence from the highest id in the case's
    background, which keeps them in the range a reader of these files would expect. It
    also means an injected record's id is numerically ahead of background records logged
    *after* it -- record ids and timestamps do not agree for injected rows. Nothing reads
    record ids as an ordering (the adapter uses them only for identity), and inventing a
    consistent interleaving would mean renumbering real records, which this script will not
    do. Stated as a limitation rather than hidden.
    """
    highest: dict[str, int] = {}
    taken: dict[str, set[int]] = {}
    for record in background:
        winlog = record.get("winlog") or {}
        channel = str(winlog.get("channel") or "")
        record_id = winlog.get("record_id")
        if isinstance(record_id, int):
            highest[channel] = max(highest.get(channel, 0), record_id)
            taken.setdefault(channel, set()).add(record_id)

    counters: dict[str, int] = {}
    for _, record in tagged:
        channel = record["winlog"]["channel"]
        counters[channel] = counters.get(channel, highest.get(channel, 0)) + 1
        record_id = counters[channel]
        if record_id in taken.get(channel, set()):
            raise SystemExit(
                f"REFUSED: injected record id {record_id} on {channel} collides with a "
                "background record; the label ref would be ambiguous"
            )
        record["winlog"]["record_id"] = record_id


def build_case(
    spec: CaseSpec, extract: DayExtract, out_dir: Path, seed: int
) -> dict[str, Any]:
    """Write one case directory and return its manifest entry."""
    injector = _Injector(spec, extract, seed)
    tagged = injector.build()
    for _, record in tagged:
        process = record.get("process")
        if process is not None:
            process["args"] = _args(process["command_line"])

    background: list[dict[str, Any]] = []
    for host, hour in spec.hours:
        background.extend(extract.segments[(host, hour)])
    assign_record_ids(tagged, background)

    injected_by_host_hour: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for _, record in tagged:
        host = str(record["host"]["name"]).split(".")[0]
        hour = str(record["@timestamp"])[11:13]
        injected_by_host_hour.setdefault((host, hour), []).append(record)

    case_dir = out_dir / spec.directory_name
    telemetry_dir = case_dir / "winlogbeat"
    telemetry_dir.mkdir(parents=True, exist_ok=True)
    for stale in telemetry_dir.glob("*.jsonl"):
        stale.unlink()

    files: dict[str, str] = {}
    segment_rows: dict[str, dict[str, int]] = {}
    for host, hour in spec.hours:
        rows = list(extract.segments[(host, hour)])
        injected = injected_by_host_hour.get((host, hour), [])
        merged = sorted(rows + injected, key=_ts)
        name = _segment_file(host, extract.date, hour)
        path = telemetry_dir / name
        _write(path, "".join(json.dumps(record) + "\n" for record in merged))
        segment_rows[name] = {"background": len(rows), "injected": len(injected)}
        files[f"winlogbeat/{name}"] = _sha256(path)

    labels = build_labels(spec, extract, tagged, segment_rows, seed)
    labels_path = (
        case_dir / "SEALED" / "labels.json" if spec.sealed else case_dir / "labels.json"
    )
    labels_path.parent.mkdir(parents=True, exist_ok=True)
    _write(labels_path, json.dumps(labels, indent=2) + "\n")
    files[str(labels_path.relative_to(case_dir)).replace("\\", "/")] = _sha256(labels_path)

    case_md = case_dir / "CASE.md"
    _write(case_md, render_case_md(spec, extract, labels, segment_rows, seed))
    files["CASE.md"] = _sha256(case_md)

    entry: dict[str, Any] = {
        "case_id": spec.case_id,
        "directory": spec.directory_name,
        "seed": seed,
        "case_seed": f"{seed}:{spec.case_id}",
        "provenance": "real+injected",
        "provenance_note": "real benign DEDALE background + injected attack rows",
        "sealed": spec.sealed,
        "parameters": spec.parameters(),
        "segments": segment_rows,
        "injected_count": len(tagged),
        "bytes": sum((case_dir / name).stat().st_size for name in files),
        "files": dict(sorted(files.items())),
    }
    if spec.sealed:
        entry["injected_record_ids"] = (
            "sealed -- in SEALED/labels.json, whose sha256 is above"
        )
        entry["links"] = "sealed -- in SEALED/labels.json"
        entry["expected_rules"] = "sealed until the final evaluation"
        entry["parameters"] = {
            key: value for key, value in spec.parameters().items()
            if key not in ("expected_rules", "expected_findings")
        }
    else:
        entry["injected_record_ids"] = [
            {
                "host": record["host"]["name"],
                "channel": record["winlog"]["channel"],
                "event_id": record["winlog"]["event_id"],
                "record_id": record["winlog"]["record_id"],
                "stage": stage,
                "ref": _ref(record),
            }
            for stage, record in tagged
        ]
        entry["links"] = [link["link_id"] for link in labels["links"]]
    return entry


def build_labels(
    spec: CaseSpec,
    extract: DayExtract,
    tagged: list[tuple[str, dict[str, Any]]],
    segment_rows: dict[str, dict[str, int]],
    seed: int,
) -> dict[str, Any]:
    """The answer key: every injected record, by stage, plus the cross-domain links.

    Loadable by ``ath.evaluation.external_labels.load_external_labels`` -- ``dataset``,
    ``provenance`` (``real+injected``, the vocabulary's own word for this) and ``scenarios``
    are what that reader consumes; everything else is extra and ignored by it.

    ``links`` is the pre-registered input to the CDER metric: pairs of evidence ids from two
    different domains that ground truth says belong to **one stage transition**. A link is
    recovered when one accepted claim cites evidence on both sides of the pair.
    """
    stages: dict[str, dict[str, Any]] = {}
    for stage, record in tagged:
        entry = stages.setdefault(
            stage, {"note": spec.stage_notes.get(stage, ""), "refs": []}
        )
        entry["refs"].append(_ref(record))

    logon_records = [
        (stage, record) for stage, record in tagged
        if record["winlog"]["channel"] == SECURITY_CHANNEL
    ]
    process_records = [
        (stage, record) for stage, record in tagged
        if record["winlog"]["channel"] == SYSMON_CHANNEL
    ]
    success = [
        (stage, record) for stage, record in logon_records
        if record["winlog"]["event_id"] == 4624
    ]
    identity_stage, identity_record = success[-1] if success else logon_records[-1]
    endpoint_stage, shell = process_records[0]

    def _link(link_id: str, identity: dict[str, Any], endpoint: dict[str, Any],
              from_stage: str, to_stage: str, note: str) -> dict[str, Any]:
        return {
            "link_id": link_id,
            "stage_transition": f"{from_stage} -> {to_stage}",
            "identity": {
                "domain": "identity",
                "host": identity["host"]["name"],
                "channel": identity["winlog"]["channel"],
                "event_id": identity["winlog"]["event_id"],
                "record_id": identity["winlog"]["record_id"],
                "ref": _ref(identity),
            },
            "endpoint": {
                "domain": "endpoint",
                "host": endpoint["host"]["name"],
                "channel": endpoint["winlog"]["channel"],
                "event_id": endpoint["winlog"]["event_id"],
                "record_id": endpoint["winlog"]["record_id"],
                "ref": _ref(endpoint),
            },
            "note": note,
        }

    links = [
        _link(
            f"{spec.case_id}-LINK-1", identity_record, shell, identity_stage, endpoint_stage,
            "the authentication that the service-launched shell on the same host followed; "
            "the only cross-domain join this architecture can make (auth_then_exec)",
        )
    ]
    if len(process_records) > 1:
        child_stage, child = process_records[1]
        links.append(
            _link(
                f"{spec.case_id}-LINK-2", identity_record, child, identity_stage, child_stage,
                "the same authentication and the first command run under the shell it "
                "explains. Deliberately harder than LINK-1: no finding cites this process "
                "row, so recovering it means an arm went looking at the shell's children "
                "rather than reading the case's own evidence. It measures investigation, "
                "not detection.",
            )
        )

    return {
        "dataset": f"dedale_injected/{spec.case_id}",
        "provenance": "real+injected",
        "provenance_note": (
            "real benign DEDALE background + injected attack rows. The background rows are "
            "DEDALE's own bytes; every row named in this file was written by "
            "scripts/m19b_inject_dedale.py and never happened."
        ),
        "case_id": spec.case_id,
        "seed": seed,
        "case_seed": f"{seed}:{spec.case_id}",
        "generated_by": "scripts/m19b_inject_dedale.py",
        "attribution": ATTRIBUTION,
        "background": [
            {
                "day": spec.day,
                "date": extract.date,
                "host": host,
                "hour": hour,
                "file": _segment_file(host, extract.date, hour),
                "background_records": segment_rows[_segment_file(host, extract.date, hour)][
                    "background"
                ],
                "injected_records": segment_rows[_segment_file(host, extract.date, hour)][
                    "injected"
                ],
            }
            for host, hour in spec.hours
        ],
        "domains": ["endpoint", "identity"],
        "scenarios": {
            spec.scenario: {
                "malicious": spec.malicious,
                "note": spec.headline,
                "stages": stages,
            }
        },
        "links": links,
    }


# --------------------------------------------------------------------------------------
# CASE.md
# --------------------------------------------------------------------------------------


_LIMITATION = """## The architectural limitation this case inherits

Every case in this directory is **endpoint x identity**, because that is the only
cross-domain pair `ath.correlation.correlator` can form. Of `score_pair`'s six signals, four
(`shared_evidence`, `same_process`, `process_lineage`, `sibling_lineage`) need the two
findings to cite the same event or the same process instance, which findings from two
different canonical tables cannot do; `host_movement` needs a directed host relationship no
cloud or container finding carries; and `auth_then_exec`, the one that can span tables, is
gated by a hardcoded allowlist:

```python
_AUTH_RULES = frozenset({"ATH-005", "ATH-006"})
_REMOTE_EXEC_RULES = frozenset({"ATH-007"})
```

No other pair of rule ids can produce a cross-domain case, whatever the telemetry holds.
VERIFIED FROM CODE; the argument is `reports/m19b/necessity/AUDIT.md`.

A benchmark built from these cases therefore measures whether a specialist crew helps on
*one* kind of cross-domain investigation. It is not evidence about cross-domain investigation
in general, and the pre-registration has to say so."""


def render_case_md(
    spec: CaseSpec,
    extract: DayExtract,
    labels: dict[str, Any],
    segment_rows: dict[str, dict[str, int]],
    seed: int,
) -> str:
    """The case's own page: provenance, story, domains, and condition 3 argued for it."""
    background_rows = sum(v["background"] for v in segment_rows.values())
    injected_rows = sum(v["injected"] for v in segment_rows.values())

    segment_lines = []
    for host, hour in spec.hours:
        name = _segment_file(host, extract.date, hour)
        counts = segment_rows[name]
        segment_lines.append(
            f"| `{name}` | {host} | {extract.date} {hour}:00Z | "
            f"{counts['background']} | {counts['injected']} |"
        )
    segments = "\n".join(segment_lines)

    if spec.sealed:
        injected_table = (
            "The injected records, their stages and the cross-domain links are **sealed** in "
            "`SEALED/labels.json`; only its SHA-256 is published, in `MANIFEST.json`.\n"
        )
        rules = "Sealed until the final evaluation.\n"
        links = "Sealed.\n"
    else:
        rows = []
        for stage, spec_refs in labels["scenarios"][spec.scenario]["stages"].items():
            rows.append(
                f"| `{stage}` | {len(spec_refs['refs'])} | {spec_refs['note']} |"
            )
        injected_table = (
            "| stage | injected records | what it is |\n| --- | --- | --- |\n"
            + "\n".join(rows)
            + "\n\nEvery injected record's native ref (`host=...;channel=...;record_id=...`) is "
            "in `labels.json` and in the top-level `MANIFEST.json`. Nothing in the telemetry "
            "marks a row as injected -- a marker inside a record would leak the answer key "
            "into the thing being measured.\n"
        )
        rules = (
            "| rule | domain | severity this case is built for |\n| --- | --- | --- |\n"
            + "\n".join(
                f"| `{rule}` | {'identity' if rule in ('ATH-005', 'ATH-006') else 'endpoint'} | "
                f"{_EXPECTED_SEVERITY.get((spec.case_id, rule), '')} |"
                for rule in spec.expected_rules
            )
            + f"\n\nExpected findings: **{spec.expected_findings}**, correlating into "
            "**one** case.\n"
        )
        links = (
            "| link | stage transition | identity record | endpoint record |\n"
            "| --- | --- | --- | --- |\n"
            + "\n".join(
                f"| `{link['link_id']}` | {link['stage_transition']} | "
                f"`{link['identity']['channel']}` {link['identity']['record_id']} | "
                f"`{link['endpoint']['channel']}` {link['endpoint']['record_id']} |"
                for link in labels["links"]
            )
            + "\n\nThese are the pre-registered pairs the **CDER** metric scores: a link is "
            "recovered when one accepted claim cites evidence on both sides. `LINK-1` is "
            "reachable from the case's own evidence -- both rows are cited by a finding, so "
            "a deterministic arm can recover it. Any further link points at a process row "
            "**no finding cites** (a command run under the shell), so recovering it means an "
            "arm went looking: it measures investigation rather than detection. Each link's "
            "note in `labels.json` says which it is.\n"
        )

    verdict = "malicious: **true**" if spec.malicious else "malicious: **false** (benign look-alike)"

    return f"""# {spec.case_id} -- {spec.headline}

**Provenance: real benign DEDALE background + injected attack rows.** Not real data about
an intrusion, however real the background is. The background rows below are DEDALE's own
bytes; every row listed in `labels.json` was written by `scripts/m19b_inject_dedale.py` and
never happened. Ground truth for this case is the label file and nothing else -- which is
sound here only because the background produces **zero** findings under the current rules
(MEASURED, `reports/m19b/necessity/AUDIT.md`), so every finding the case raises is caused by
an injected row.

Labelled {verdict}.

## Generation

| | |
| --- | --- |
| seed | `{seed}` (case seed `{seed}:{spec.case_id}`) |
| script | `scripts/m19b_inject_dedale.py` |
| source | DEDALE `{spec.day}` (`{extract.date}`), `{extract.path.name}` |
| background records | {background_rows} |
| injected records | {injected_rows} |
| regenerate | `python scripts/m19b_inject_dedale.py --only {spec.case_id} --out <dir>` |

## Background

| file | host | hour | background records | injected records |
| --- | --- | --- | --- | --- |
{segments}

Real DEDALE Winlogbeat NDJSON (7.10.2 / ECS 1.5.0), copied verbatim except for the
`message` field -- a rendered copy of `event_data`, unused by every adapter, two thirds of
the bytes -- dropped exactly as `scripts/cut_real_shaped_fixtures.py` drops it.
`winlog.record_id`, `host.name` and `winlog.channel` are untouched, which is what lets label
refs resolve. The external dataset directory is read-only input and was never written to.

{ATTRIBUTION}

## The story

{spec.story}

## Domains

**endpoint** (Sysmon 1 process creates: what ran on the target and what started it) and
**identity** (Security 4624/4625: whose credential was used, from where, and whether it
worked). Each domain carries a stage the other does not, so removing either removes a stage
rather than a second view of one -- condition 2 of `docs/m19b-plan.md`.

## Rules this case is built to fire

{rules}
## Pre-registered cross-domain links

{links}
## Why cross-domain synthesis changes the verdict, the priority, or the next action

{spec.condition_3}

{_LIMITATION}

## What was injected

{injected_table}
"""


_EXPECTED_SEVERITY: dict[tuple[str, str], str] = {
    ("M1", "ATH-005"): "CRITICAL (the burst succeeded)",
    ("M1", "ATH-007"): "HIGH (ADMIN$ redirect)",
    ("M2", "ATH-005"): "CRITICAL (the burst succeeded)",
    ("M2", "ATH-007"): "HIGH (ADMIN$ redirect)",
    ("M3", "ATH-005"): "CRITICAL (the burst succeeded)",
    ("M3", "ATH-006"): "HIGH (no session on the origin host)",
    ("M3", "ATH-007"): "HIGH (ADMIN$ redirect)",
    ("M4", "ATH-005"): "MEDIUM (no success followed)",
    ("M4", "ATH-007"): "HIGH (ADMIN$ redirect)",
    ("L1", "ATH-005"): "CRITICAL (the lockout was followed by a success)",
    ("L1", "ATH-007"): "HIGH (ADMIN$ redirect -- PsExec writes one too)",
    ("L2", "ATH-005"): "CRITICAL (the stale credential was corrected and succeeded)",
    ("L2", "ATH-007"): "MEDIUM (no ADMIN$ redirect)",
}


PROVENANCE_MD = f"""# Provenance -- `reports/m19b/cases/dedale_injected/`

**Real benign DEDALE background + injected attack rows.** Never "real". Every case
directory here holds one or two real benign hours of DEDALE Winlogbeat telemetry with a
labelled endpoint x identity chain written into them by
`scripts/m19b_inject_dedale.py`; `labels.json` names every injected record.

## Source

{ATTRIBUTION}

Files: `data/external/dedale/winlogbeat/D03/D03_2024-12-25.jsonl` and
`.../D18/D18_2025-01-09.jsonl` (Winlogbeat 7.10.2, ECS 1.5.0), read-only, never modified.
`data/external/` is gitignored and is not part of this worktree; the generator's
`--external` default is the sibling checkout `../agentic-threat-hunter/data/external`, the
same default `scripts/m19b_necessity_audit.py` uses.

## Trimming

Background records lose the `message` field (a rendered copy of `event_data`, unused by
every adapter, about two thirds of the bytes) and nothing else. `json.dumps` round-trips
DEDALE's own formatting byte-for-byte, so each background line here is byte-identical to its
source line minus that field.

## Why this background

D03 and D18 produce **zero** findings under the current rules (MEASURED,
`reports/m19b/necessity/AUDIT.md`), so every finding a case raises is caused by an injected
row and the labels are complete by construction. The dataset carries **no Security 4625 at
all**, no usable Sysmon 3, and no human account in any 4624 -- so the identity half of every
chain here is injected, and the accounts used are the real DEDALE accounts that appear as
Sysmon `user.name` and in the real type 7/11 unlock records, with their real SIDs.

## The held-out case

`HELDOUT_H1/` is generated by the same script; its `labels.json` is sealed in
`HELDOUT_H1/SEALED/` and only its SHA-256 is published, in `MANIFEST.json`. Nothing is run
against it until the final evaluation. What makes it held out is the seal, not the
construction: the parameters are in the committed generator.
"""


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------


def day_path(external: Path, day: str) -> Path:
    path = external / "dedale" / "winlogbeat" / day / f"{day}_{DAYS[day]}.jsonl"
    if not path.is_file():
        raise SystemExit(
            f"REFUSED: {path} not found. This script reads DEDALE from --external "
            "(default: the sibling checkout's data/external), which is gitignored and "
            "fetched by scripts/fetch_external.py."
        )
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--external", type=Path, default=DEFAULT_EXTERNAL)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument(
        "--only", nargs="*", default=None,
        help="case ids to build; the manifest is only written when all of them are built",
    )
    args = parser.parse_args(argv)

    wanted = [c for c in CASES if args.only is None or c.case_id in set(args.only)]
    if not wanted:
        raise SystemExit(f"REFUSED: --only {args.only} matches no case")

    args.out.mkdir(parents=True, exist_ok=True)
    extracts: dict[str, DayExtract] = {}
    for day in sorted({c.day for c in wanted}):
        segments = {seg for c in wanted if c.day == day for seg in c.hours}
        accounts = {c.account for c in wanted if c.day == day}
        path = day_path(args.external, day)
        print(f"reading {path.name} for {len(segments)} segment(s) ...", file=sys.stderr)
        extracts[day] = read_day(path, day, segments, accounts)

    entries: dict[str, Any] = {}
    for spec in wanted:
        entry = build_case(spec, extracts[spec.day], args.out, args.seed)
        entries[spec.case_id] = entry
        print(
            f"  {spec.case_id}: {entry['injected_count']} injected row(s), "
            f"{entry['bytes'] / 1024:.0f} KB",
            file=sys.stderr,
        )

    _write(args.out / "PROVENANCE.md", PROVENANCE_MD)

    if args.only is not None:
        print(
            "--only was given: case files written, MANIFEST.json left alone "
            "(it describes the whole set or nothing).",
            file=sys.stderr,
        )
        return 0

    manifest = {
        "generated_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "seed": args.seed,
        "script": "scripts/m19b_inject_dedale.py",
        "script_sha256": _script_sha256(Path(__file__).resolve()),
        "provenance": "real+injected",
        "provenance_note": "real benign DEDALE background + injected attack rows",
        "attribution": ATTRIBUTION,
        "source_files": {
            f"{day}/{day_path(args.external, day).name}": {
                "sha256": _sha256(day_path(args.external, day)),
                "bytes": day_path(args.external, day).stat().st_size,
            }
            for day in sorted({c.day for c in CASES})
        },
        "notes": [
            "Every case is endpoint x identity: the only cross-domain pair "
            "ath.correlation.correlator can form (_AUTH_RULES x _REMOTE_EXEC_RULES). "
            "VERIFIED FROM CODE, reports/m19b/necessity/AUDIT.md.",
            "HELDOUT_H1's labels are sealed in HELDOUT_H1/SEALED/labels.json; only its "
            "sha256 appears here. Its injected record ids, stages and links are not "
            "published. Its parameters are, because they are in the committed generator "
            "and pretending otherwise would be theatre: what makes it held out is the "
            "seal and the discipline, not the construction.",
            "Injected record ids continue their host-and-channel's sequence from the "
            "highest id in the case's background, so an injected row's record id is "
            "numerically ahead of background rows logged after it. No adapter or rule "
            "reads record ids as an ordering.",
        ],
        "cases": entries,
    }
    manifest_path = args.out / "MANIFEST.json"
    _write(manifest_path, json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {manifest_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
