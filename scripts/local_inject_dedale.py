"""V1 dev split: ten labelled endpoint x identity cases injected into real DEDALE day D02.

Why a sibling of ``scripts/m19b_inject_dedale.py`` rather than an edit
-------------------------------------------------------------------------
That generator is hash-pinned: ``tests/test_m19b_inject.py`` asserts its sha256 against the
frozen ``reports/m19b/cases/dedale_injected/MANIFEST.json``, so editing it would turn the
benchmark's provenance record false. Everything that builds a record -- the case spec, the
day reader, the injector, the label writer -- is imported from it unchanged; this file
adds only the ten dev-split specs, the day they stand on, and a check the frozen cases
were given by hand (T5b): that the background alone raises no finding.

Why day D02
------------
The frozen cases (M1-M4, L1, L2, HELDOUT_H1) stand on D03 and D18. D02 (2024-12-24) is a
different day of the same estate and carries hour 08 for all thirty hosts with both the
Security and the Sysmon channel (MEASURED, 2026-09-15). D15 carries DEDALE's own attack
labels and is excluded; D07 is an 8 MB fragment. The pinned generator's ``DAYS`` table has no
D02 entry, so this module adds one at import -- a runtime extension of a table, recorded in
the manifest as the mechanism, rather than an edit to the pinned file.

Host pairs avoid every host a frozen case uses (CLIENT3/7/9/12/26/28) and the two hosts
whose owning account has no domain SID on D02 (CLIENT11, CLIENT14). Ten disjoint pairs,
twenty hosts, all on hour 08.

What the ten cases vary
------------------------
Six malicious, four benign look-alikes; the same two rules (ATH-005 needs >= 10 failures
in 10 minutes then a success within 15; ATH-007 is ``services.exe -> cmd.exe``, HIGH with
an ADMIN$ redirect and MEDIUM without) so every case forms the one cross-domain shape the
correlator can make -- but with different burst sizes, cadences, delays, sub-status
mixes, shell commands and benign explanations from the benchmark's six, so tuning on
these does not clone the benchmark. Recorded as a limitation regardless: it is one shape.

Contamination
--------------
The case ids (V1..V10), the day, the hosts and the seed all differ from the frozen set;
``tests/test_contamination.py`` checks the resulting manifest structurally.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import m19_ablation as m19  # noqa: E402
import m19b_inject_dedale as inject  # noqa: E402
import m19b_necessity_audit as necessity_script  # noqa: E402
from m19b_inject_dedale import (  # noqa: E402
    _LOCKOUT_CASCADE,
    SMB_EXEC_TAIL,
    CaseSpec,
    _bad_password,
    _even,
    _locked_out,
    _script_sha256,
    _segment_file,
    _sha256,
    _write,
    build_case,
    read_day,
)

from ath.evaluation.ablation.local import refuse_frozen_path  # noqa: E402

DEV_DAY = "D02"
DEV_DATE = "2024-12-24"
inject.DAYS.setdefault(DEV_DAY, DEV_DATE)
"""The runtime extension. ``read_day``, ``build_case`` and ``day_path`` all read the date
from this table; the pinned file is not edited."""

DEV_SEED = 26_0915
"""Distinct from the benchmark generator's 19026. Recorded in the manifest and every label."""

DEFAULT_EXTERNAL = inject.DEFAULT_EXTERNAL
DEFAULT_OUT = ROOT / "reports" / "local" / "dev" / "cases" / "dedale_injected"
HOUR = "08"

_LOCKOUT_MIX: tuple[inject.Failure, ...] = (
    _bad_password(0.0), _bad_password(21.0), _bad_password(39.0), _bad_password(58.0),
    _locked_out(80.0), _locked_out(104.0), _locked_out(127.0), _locked_out(151.0),
    _locked_out(175.0), _locked_out(199.0), _locked_out(222.0), _locked_out(246.0),
)
"""Four bad passwords, then eight retries against the locked account."""


def _pair(source: str, target: str) -> tuple[tuple[str, str], ...]:
    return ((source, HOUR), (target, HOUR))


DEV_CASES: tuple[CaseSpec, ...] = (
    # -- malicious ---------------------------------------------------------------------
    CaseSpec(
        case_id="V1", day=DEV_DAY, source_host="CLIENT1", target_host="CLIENT2",
        hours=_pair("CLIENT1", "CLIENT2"), account="client2", malicious=True,
        scenario="guessed-credential-then-remote-exec",
        burst_start="08:07:12", failures=_even(13, 300.0), success_offset=25.0, exec_offset=70.0,
        shell_command=(
            r'C:\Windows\system32\cmd.exe /Q /c "net group "Domain Admins" /domain'
            r' & net localgroup administrators"' + SMB_EXEC_TAIL
        ),
        children=((2.2, r'net  group "Domain Admins" /domain'), (5.9, r"net  localgroup administrators")),
        expected_rules=("ATH-005", "ATH-007"), expected_findings=2,
        headline="Thirteen guesses from CLIENT1 land on CLIENT2, then a service-launched shell enumerates groups",
        story="""An operator on **CLIENT1** guesses **client2**'s password: thirteen network logons
fail on CLIENT2 within five minutes (`0xC000006A`), the next succeeds, and seventy seconds later
the Service Control Manager starts a shell whose output is redirected to `ADMIN$`; it enumerates
domain and local administrators.""",
        condition_3="""Endpoint alone: an anonymous SYSTEM shell that could be a patch agent.
Identity alone: a guessed credential with nothing done. Together: a landed intrusion whose
foothold is CLIENT1, which only the identity rows name.""",
        stage_notes={
            "1-credential-guessing": "thirteen failed type 3 logons for one account from one host in 300s",
            "2-successful-logon": "the same account and source succeed 25s after the last failure",
            "3-remote-service-execution": "services.exe starts cmd.exe, output redirected to ADMIN$",
            "4-discovery": "domain and local administrator enumeration from that shell",
        },
    ),
    CaseSpec(
        case_id="V2", day=DEV_DAY, source_host="CLIENT4", target_host="CLIENT5",
        hours=_pair("CLIENT4", "CLIENT5"), account="client5", malicious=True,
        scenario="slow-guessing-then-delayed-remote-exec",
        burst_start="08:04:30", failures=_even(11, 540.0), success_offset=200.0, exec_offset=400.0,
        shell_command=(
            r'C:\Windows\system32\cmd.exe /Q /c "net user /domain'
            r' & net group "Domain Computers" /domain"' + SMB_EXEC_TAIL
        ),
        children=((3.1, r"net  user /domain"), (9.4, r'net  group "Domain Computers" /domain')),
        expected_rules=("ATH-005", "ATH-007"), expected_findings=2,
        headline="A nine-minute guessing burst on CLIENT5, a success, and a shell seven minutes later",
        story="""Eleven failures for **client5** on **CLIENT5** from **CLIENT4** are spread over nine
minutes -- inside ATH-005's window but slow enough to look like a user. A success follows
after 200 seconds, and the shell arrives 400 seconds after that, enumerating domain users
and computers.""",
        condition_3="""The delay between the credential and the shell is the point: each half
sits on its own, minutes apart, and only the shared account and source join them.""",
        stage_notes={
            "1-credential-guessing": "eleven failed logons spread over 540s",
            "2-successful-logon": "success 200s after the last failure",
            "3-remote-service-execution": "services.exe starts cmd.exe 400s later, ADMIN$ redirect",
            "4-discovery": "domain user and computer enumeration",
        },
    ),
    CaseSpec(
        case_id="V3", day=DEV_DAY, source_host="CLIENT6", target_host="CLIENT8",
        hours=_pair("CLIENT6", "CLIENT8"), account="client8", malicious=True,
        scenario="unsuccessful-guessing-then-remote-exec",
        burst_start="08:12:00", failures=_even(12, 240.0), success_offset=None, exec_offset=120.0,
        shell_command=(
            r'C:\Windows\system32\cmd.exe /Q /c "net localgroup administrators & net view"'
            + SMB_EXEC_TAIL
        ),
        children=((2.8, r"net  localgroup administrators"), (7.2, r"net  view")),
        expected_rules=("ATH-005", "ATH-007"), expected_findings=2,
        headline="The burst never succeeds, yet a shell follows: the MEDIUM identity half",
        story="""Twelve failures for **client8** on **CLIENT8** from **CLIENT6** and no success from
that source. ATH-005 grades the burst MEDIUM. Two minutes after the last failure a shell starts
under the Service Control Manager anyway -- the credential came from somewhere else.""",
        condition_3="""Identity alone says an unsuccessful attempt; endpoint alone says a shell.
Only together do they say the attacker got in by a route the identity rows did not see.""",
        stage_notes={
            "1-credential-guessing": "twelve failed logons in 240s, no success",
            "2-remote-service-execution": "services.exe starts cmd.exe 120s after the last failure, ADMIN$ redirect",
            "3-discovery": "local administrator enumeration and a network view",
        },
    ),
    CaseSpec(
        case_id="V4", day=DEV_DAY, source_host="CLIENT10", target_host="CLIENT13",
        hours=_pair("CLIENT10", "CLIENT13"), account="client13", malicious=True,
        scenario="rapid-spray-then-share-enumeration",
        burst_start="08:21:40", failures=_even(20, 60.0), success_offset=15.0, exec_offset=45.0,
        shell_command=(
            r'C:\Windows\system32\cmd.exe /Q /c "net use & net share"' + SMB_EXEC_TAIL
        ),
        children=((1.9, r"net  use"), (4.4, r"net  share")),
        expected_rules=("ATH-005", "ATH-007"), expected_findings=2,
        headline="Twenty failures in one minute, then share enumeration from a service shell",
        story="""A tool, not a hand: twenty failures for **client13** on **CLIENT13** from
**CLIENT10** in sixty seconds, a success fifteen seconds later, and a shell forty-five seconds
after that listing mapped drives and shares.""",
        condition_3="""The cadence (identity) says automation; the commands (endpoint) say
lateral-movement reconnaissance. Neither domain carries the other's half.""",
        stage_notes={
            "1-credential-spray": "twenty failed logons in 60s",
            "2-successful-logon": "success 15s after the last failure",
            "3-remote-service-execution": "services.exe starts cmd.exe, ADMIN$ redirect",
            "4-discovery": "mapped drives and shares enumerated",
        },
    ),
    CaseSpec(
        case_id="V5", day=DEV_DAY, source_host="CLIENT15", target_host="CLIENT16",
        hours=_pair("CLIENT15", "CLIENT16"), account="client16", malicious=True,
        scenario="guessing-then-privileged-group-discovery",
        burst_start="08:09:05", failures=_even(10, 420.0), success_offset=60.0, exec_offset=200.0,
        shell_command=(
            r'C:\Windows\system32\cmd.exe /Q /c "net accounts /domain'
            r' & net group "Enterprise Admins" /domain"' + SMB_EXEC_TAIL
        ),
        children=((2.5, r"net  accounts /domain"), (6.8, r'net  group "Enterprise Admins" /domain')),
        expected_rules=("ATH-005", "ATH-007"), expected_findings=2,
        headline="Exactly the threshold: ten failures, then a shell reading the password policy",
        story="""Ten failures -- ATH-005's minimum -- for **client16** on **CLIENT16** from
**CLIENT15** over seven minutes, a success a minute later, and a service-launched shell that
reads the domain password policy and the Enterprise Admins group.""",
        condition_3="""A threshold-edge burst is easy to dismiss on identity alone; a policy read
is easy to dismiss on endpoint alone. The join is what makes either worth an analyst.""",
        stage_notes={
            "1-credential-guessing": "ten failed logons in 420s, the rule's minimum",
            "2-successful-logon": "success 60s after the last failure",
            "3-remote-service-execution": "services.exe starts cmd.exe, ADMIN$ redirect",
            "4-discovery": "password policy and Enterprise Admins read",
        },
    ),
    CaseSpec(
        case_id="V6", day=DEV_DAY, source_host="CLIENT17", target_host="CLIENT18",
        hours=_pair("CLIENT17", "CLIENT18"), account="client18", malicious=True,
        scenario="guessing-then-long-dwell-remote-exec",
        burst_start="08:03:20", failures=_even(15, 180.0), success_offset=30.0, exec_offset=780.0,
        shell_command=(
            r'C:\Windows\system32\cmd.exe /Q /c "net localgroup "Remote Desktop Users"'
            r' & net session"' + SMB_EXEC_TAIL
        ),
        children=((2.0, r'net  localgroup "Remote Desktop Users"'), (5.5, r"net  session")),
        expected_rules=("ATH-005", "ATH-007"), expected_findings=2,
        headline="Thirteen minutes of dwell between the credential and the shell",
        story="""Fifteen failures for **client18** on **CLIENT18** from **CLIENT17** in three
minutes, a success, then nothing for thirteen minutes -- and then a service-launched shell
listing remote-desktop users and sessions. (A 900 s dwell sat exactly on the correlator's
15-minute cross-domain window and split the story into two cases; 780 s keeps it one.)""",
        condition_3="""The dwell separates the two halves in time as well as in domain; a
correlation keyed on the account and the source is the only thing that rejoins them.""",
        stage_notes={
            "1-credential-guessing": "fifteen failed logons in 180s",
            "2-successful-logon": "success 30s after the last failure",
            "3-remote-service-execution": "services.exe starts cmd.exe 780s later, ADMIN$ redirect",
            "4-discovery": "remote-desktop users and sessions listed",
        },
    ),
    # -- benign look-alikes -------------------------------------------------------------
    CaseSpec(
        case_id="V7", day=DEV_DAY, source_host="CLIENT19", target_host="CLIENT20",
        hours=_pair("CLIENT19", "CLIENT20"), account="client20", malicious=False,
        scenario="lockout-cascade-then-remote-support",
        burst_start="08:14:50", failures=_LOCKOUT_CASCADE, success_offset=400.0, exec_offset=80.0,
        shell_command=(
            r'C:\Windows\system32\cmd.exe /Q /c "net stop wuauserv & net start wuauserv"'
            + SMB_EXEC_TAIL
        ),
        children=((2.3, r"net  stop wuauserv"), (12.6, r"net  start wuauserv")),
        expected_rules=("ATH-005", "ATH-007"), expected_findings=2,
        headline="BENIGN LOOK-ALIKE: a lockout cascade and a PsExec restart of Windows Update",
        story="""**client20** owns **CLIENT20**. From a colleague's desk at **CLIENT19** a cached old
password fails three times, locks the account, and retries nine times against the lock
(`0xC0000234`). After the service desk unlocks it the engineer authenticates and restarts the
Windows Update service on their own workstation through PsExec, whose output goes to `ADMIN$`.
**Labelled benign.** Same rules, same severities as the malicious cases.""",
        condition_3="""The failure reasons (a lockout cascade, not repeated bad passwords), the
account's ownership of the target, and the service-restart commands each live in one domain;
only the three together de-escalate.""",
        stage_notes={
            "1-stale-credential-lockout": "three bad-password failures, then nine against a locked account",
            "2-logon-after-unlock": "success from the same host after the unlock",
            "3-remote-support-action": "PsExec-style service-launched shell, output to ADMIN$",
            "4-support-commands": "Windows Update service stopped and started",
        },
    ),
    CaseSpec(
        case_id="V8", day=DEV_DAY, source_host="CLIENT21", target_host="CLIENT22",
        hours=_pair("CLIENT21", "CLIENT22"), account="client22", malicious=False,
        scenario="scheduled-replication-with-stale-password",
        burst_start="08:02:10", failures=tuple(_bad_password(round(i * 45.0, 3)) for i in range(12)),
        success_offset=45.0, exec_offset=100.0,
        shell_command=(
            r'C:\Windows\system32\cmd.exe /Q /c "C:\BREACH\replica\sync.cmd'
            r' --peer CLIENT22 --profile hourly"'
        ),
        children=(),
        expected_rules=("ATH-005", "ATH-007"), expected_findings=2,
        headline="BENIGN LOOK-ALIKE: a replication job's stored password went stale, then its own sync script",
        story="""A replication schedule on **CLIENT21** authenticates to **CLIENT22** as **client22**
every 45 seconds. Its stored password was rotated; twelve cycles fail at an exact cadence, an
operator fixes the credential, the next cycle succeeds, and the replication agent's service
starts its sync script -- no `ADMIN$` redirect, so ATH-007 grades it MEDIUM. **Labelled benign.**""",
        condition_3="""The rhythm (identity: 45.000 s spacing) and the path (endpoint: a named
sync script with no redirect) are in different domains; either alone is a false positive.""",
        stage_notes={
            "1-stale-scheduled-credential": "twelve failures at an exact 45s cadence",
            "2-credential-corrected": "the next scheduled cycle succeeds",
            "3-service-started-script": "services.exe starts the replication agent's sync script, no ADMIN$ redirect",
        },
    ),
    CaseSpec(
        case_id="V9", day=DEV_DAY, source_host="CLIENT23", target_host="CLIENT24",
        hours=_pair("CLIENT23", "CLIENT24"), account="client24", malicious=False,
        scenario="monitoring-agent-expired-credential",
        burst_start="08:18:30", failures=_even(10, 270.0), success_offset=30.0, exec_offset=60.0,
        shell_command=(
            r'C:\Windows\system32\cmd.exe /Q /c "C:\BREACH\monitoring\collect.cmd --host CLIENT24"'
        ),
        children=((3.0, r"net  statistics workstation"),),
        expected_rules=("ATH-005", "ATH-007"), expected_findings=2,
        headline="BENIGN LOOK-ALIKE: a monitoring collector with an expired service credential",
        story="""The monitoring server **CLIENT23** polls **CLIENT24** as **client24** every thirty
seconds; the credential expired overnight and ten polls fail before the on-call engineer renews
it. The next poll succeeds and the collector's service runs its collection script, which
gathers workstation statistics. No `ADMIN$` redirect. **Labelled benign.**""",
        condition_3="""Identity alone: ten failures then a success from one host, the textbook
burst. Endpoint alone: a MEDIUM service shell. Together with the 30 s cadence and the named
collector script, an expired credential -- and the next action is a credential-lifecycle fix.""",
        stage_notes={
            "1-expired-service-credential": "ten failures at a 30s polling cadence",
            "2-credential-renewed": "the next poll succeeds",
            "3-collector-script": "services.exe starts the collector's script, no ADMIN$ redirect",
            "4-collection-command": "workstation statistics gathered",
        },
    ),
    CaseSpec(
        case_id="V10", day=DEV_DAY, source_host="CLIENT25", target_host="CLIENT27",
        hours=_pair("CLIENT25", "CLIENT27"), account="client27", malicious=False,
        scenario="typo-lockout-then-helpdesk-inventory",
        burst_start="08:25:15", failures=_LOCKOUT_MIX, success_offset=300.0, exec_offset=120.0,
        shell_command=(
            r'C:\Windows\system32\cmd.exe /Q /c "net config workstation & net time \\CLIENT27"'
            + SMB_EXEC_TAIL
        ),
        children=((2.4, r"net  config workstation"), (6.0, r"net  time \\CLIENT27")),
        expected_rules=("ATH-005", "ATH-007"), expected_findings=2,
        headline="BENIGN LOOK-ALIKE: a mistyped password locks the account, then a helpdesk inventory run",
        story="""**client27** mistypes a new password four times from **CLIENT25**, locks the account,
and a client keeps retrying against the lock. After the unlock the helpdesk runs its inventory
step on **CLIENT27** through PsExec -- workstation configuration and time -- with the usual
`ADMIN$` redirect, so ATH-007 grades it HIGH. **Labelled benign.**""",
        condition_3="""Four bad passwords then eight lockout retries is a typo's signature; the
inventory commands are a ticket's; the account owns the host. No single domain holds two of
those three.""",
        stage_notes={
            "1-typo-lockout": "four bad-password failures, then eight against a locked account",
            "2-logon-after-unlock": "success after the unlock",
            "3-helpdesk-remote-exec": "PsExec-style service-launched shell, output to ADMIN$",
            "4-inventory-commands": "workstation configuration and time read",
        },
    ),
)

FROZEN_HOSTS = frozenset({"CLIENT3", "CLIENT7", "CLIENT9", "CLIENT12", "CLIENT26", "CLIENT28"})
FROZEN_IDS = frozenset({"M1", "M2", "M3", "M4", "L1", "L2", "H1", "HELDOUT_H1"})


def check_specs(cases: tuple[CaseSpec, ...] = DEV_CASES) -> None:
    """Refuse a spec set that could collide with the frozen benchmark."""
    hosts = [h for c in cases for h in (c.source_host, c.target_host)]
    if len(set(hosts)) != len(hosts):
        raise SystemExit("REFUSED: dev host pairs must be disjoint")
    if set(hosts) & FROZEN_HOSTS:
        raise SystemExit(f"REFUSED: dev cases reuse frozen hosts {sorted(set(hosts) & FROZEN_HOSTS)}")
    if {c.case_id for c in cases} & FROZEN_IDS:
        raise SystemExit("REFUSED: dev case ids collide with frozen ids")
    if any(c.day != DEV_DAY for c in cases):
        raise SystemExit("REFUSED: every dev case stands on D02")
    if any(c.sealed for c in cases):
        raise SystemExit("REFUSED: the dev split seals nothing")


def background_findings(spec: CaseSpec, extract: inject.DayExtract) -> dict[str, Any]:
    """Hunt the case's background hours with nothing injected.

    T5b asserted by hand that the frozen cases' hours yield 0 findings at HEAD; here it is
    computed, per case, before the case is written, because a background that already
    fires a rule would make the injected story impossible to attribute.
    """
    temporary = Path(tempfile.mkdtemp(prefix=f"ath-bg-{spec.case_id}-"))
    try:
        for host, hour in spec.hours:
            rows = extract.segments[(host, hour)]
            _write(
                temporary / _segment_file(host, extract.date, hour),
                "".join(json.dumps(record) + "\n" for record in rows),
            )
        telemetry = necessity_script._winlogbeat(temporary)
        findings, cases, _environment, _assessments = m19._pipeline(telemetry)
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
    return {
        "findings": len(findings),
        "cases": len(cases),
        "rules": sorted({f.rule_id for f in findings}),
    }


def verify_case(case_dir: Path, spec: CaseSpec) -> dict[str, Any]:
    """Hunt the written case and check it forms exactly the story's one case."""
    telemetry = necessity_script._winlogbeat(case_dir / "winlogbeat")
    findings, cases, _environment, _assessments = m19._pipeline(telemetry)
    rules = sorted({f.rule_id for f in findings})
    verdict = {
        "findings": len(findings),
        "rules": rules,
        "cases": len(cases),
        "case_rules": [sorted(c.rule_ids) for c in cases],
    }
    verdict["expected_rules"] = sorted(spec.expected_rules)
    verdict["extra_rules"] = sorted(set(rules) - set(spec.expected_rules))
    if len(cases) != 1 or not set(spec.expected_rules) <= set(rules):
        raise SystemExit(
            f"REFUSED: {spec.case_id} formed {verdict} but the spec expects one case "
            f"carrying at least {sorted(spec.expected_rules)}"
        )
    # The deterministic layer may add a rule the spec did not name -- on D02 the owning
    # account's real logons let ATH-006 (foreign-host use) fire on top of ATH-005/007.
    # That is a fact about the corpus, recorded here; the spec's expected_rules are the
    # story's minimum, not a prediction of everything the hunt sees.
    return verdict


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--external", type=Path, default=DEFAULT_EXTERNAL)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--seed", type=int, default=DEV_SEED)
    parser.add_argument("--only", nargs="*", default=None)
    args = parser.parse_args(argv)

    check_specs()
    refuse_frozen_path(args.out, ROOT)
    wanted = [c for c in DEV_CASES if args.only is None or c.case_id in set(args.only)]
    if not wanted:
        raise SystemExit(f"REFUSED: --only {args.only} matches no case")

    path = inject.day_path(args.external, DEV_DAY)
    segments = {seg for c in wanted for seg in c.hours}
    accounts = {c.account for c in wanted}
    print(f"reading {path.name} for {len(segments)} segment(s) ...", file=sys.stderr)
    extract = read_day(path, DEV_DAY, segments, accounts)

    args.out.mkdir(parents=True, exist_ok=True)
    entries: dict[str, Any] = {}
    for spec in wanted:
        background = background_findings(spec, extract)
        if background["findings"]:
            raise SystemExit(
                f"REFUSED: {spec.case_id}'s background hours already raise "
                f"{background['findings']} finding(s) {background['rules']}; pick other hours"
            )
        entry = build_case(spec, extract, args.out, args.seed)
        entry["background_check"] = background
        entry["verified"] = verify_case(args.out / spec.directory_name, spec)
        entries[spec.case_id] = entry
        print(
            f"  {spec.case_id}: background 0 findings; {entry['injected_count']} injected "
            f"row(s); forms {entry['verified']['cases']} case with {entry['verified']['rules']}",
            file=sys.stderr,
        )

    _write(args.out / "PROVENANCE.md", PROVENANCE_MD)
    if args.only is not None:
        print("--only was given: MANIFEST.json left alone", file=sys.stderr)
        return 0

    manifest = {
        "generated_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "split": "dev",
        "seed": args.seed,
        "script": "scripts/local_inject_dedale.py",
        "script_sha256": _script_sha256(Path(__file__).resolve()),
        "generator": "scripts/m19b_inject_dedale.py",
        "generator_sha256": _script_sha256(ROOT / "scripts" / "m19b_inject_dedale.py"),
        "days_extension": {DEV_DAY: DEV_DATE},
        "provenance": "real+injected",
        "provenance_note": "real benign DEDALE background (day D02) + injected attack rows",
        "attribution": inject.ATTRIBUTION,
        "source_files": {
            f"{DEV_DAY}/{path.name}": {"sha256": _sha256(path), "bytes": path.stat().st_size},
        },
        "frozen_hosts_avoided": sorted(FROZEN_HOSTS),
        "notes": [
            "Dev split for the V1 local-model stage; not part of any frozen benchmark.",
            "Every case is endpoint x identity, the one cross-domain shape the correlator forms; "
            "recorded as a limitation of this split.",
            "Each case's background hours were hunted with nothing injected and raised 0 "
            "findings (background_check), and the written case was hunted and forms exactly "
            "the expected findings in one case (verified).",
        ],
        "cases": entries,
    }
    manifest_path = args.out / "MANIFEST.json"
    _write(manifest_path, json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {manifest_path}", file=sys.stderr)
    return 0


PROVENANCE_MD = f"""# Provenance -- `reports/local/dev/cases/dedale_injected/`

Ten labelled endpoint x identity cases (V1..V10; six malicious, four benign look-alikes)
injected into real benign DEDALE background from day {DEV_DAY} ({DEV_DATE}), hour 08, by
`scripts/local_inject_dedale.py` using the pinned generator `scripts/m19b_inject_dedale.py`
unchanged. Seed {DEV_SEED}. {inject.ATTRIBUTION}

These cases are the V1 *development* split. They are not part of the frozen M19b benchmark
and must never be used to grade it; `tests/test_contamination.py` checks the two are disjoint.
"""


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
