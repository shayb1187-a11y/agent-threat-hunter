"""Detections over process execution telemetry.

Rules in this module all read ``DeviceProcessEvents``-shaped data. Each class carries
its own security rationale in the docstring -- read those, not just the code.
"""

from __future__ import annotations

import re

import pandas as pd

from ath.hunting.base import (
    OFFICE_APPLICATIONS,
    SCRIPT_INTERPRETERS,
    Detector,
    register,
)
from ath.hunting.finding import Evidence, Finding, Severity
from ath.hunting.indicators import (
    decode_powershell_b64,
    extract_encoded_command,
    find_download_indicators,
    find_evasion_flags,
    truncate,
)
from ath.telemetry.loader import Telemetry


def _lower(series: pd.Series) -> pd.Series:
    """Lower-case a string column safely (telemetry is normalised to '' not NaN)."""
    return series.fillna("").astype(str).str.lower()


# ======================================================================================
# ATH-001
# ======================================================================================


@register
class OfficeSpawnsInterpreter(Detector):
    """ATH-001 -- A Microsoft Office application spawned a script interpreter.

    Attacker behaviour
    ------------------
    The oldest reliable route into an enterprise is a document with a macro. The user
    opens ``Invoice.docm``, clicks "Enable Content", and the macro calls out to a
    script interpreter to fetch and run the real payload. The document itself is
    usually harmless -- it is a launcher.

    Why this is high-signal
    -----------------------
    Word is a word processor. In normal operation it renders documents; it does not
    need to start ``powershell.exe``. Detections built on *process lineage* like this
    are far more durable than detections built on file hashes or IP addresses, because
    the attacker can trivially change the payload but cannot easily avoid the parent
    process relationship -- it is inherent to how macro execution works.

    This is the single best rule in the set: near-zero volume, very hard to evade
    without abandoning the technique entirely.
    """

    rule_id = "ATH-001"
    title = "Office application spawned a script interpreter"
    severity = Severity.HIGH
    description = "Detects Office applications launching PowerShell, cmd, or other LOLBins."
    fields_used = (
        "parent_process_name", "process_name", "command_line", "device", "user", "timestamp",
    )
    false_positives = (
        "Legitimate Office add-ins or COM automation that shell out to scripts.",
        "Line-of-business applications that drive Excel/Word macros for reporting.",
        "RPA tooling (UiPath, Power Automate Desktop) automating Office.",
        "Enterprise document templates that invoke signed helper scripts on open.",
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        procs = telemetry.processes
        if procs.empty:
            return []

        mask = _lower(procs["parent_process_name"]).isin(OFFICE_APPLICATIONS) & _lower(
            procs["process_name"]
        ).isin(SCRIPT_INTERPRETERS)
        hits = procs[mask]

        findings: list[Finding] = []
        for _, row in hits.iterrows():
            evidence = (
                Evidence(
                    event_id=row["event_id"],
                    timestamp=row["timestamp"],
                    summary=(
                        f"{row['parent_process_name']} (PID {row['parent_process_id']}) "
                        f"spawned {row['process_name']} (PID {row['process_id']}): "
                        f"{truncate(row['command_line'], 160)}"
                    ),
                ),
            )
            findings.append(
                self.make_finding(
                    device=row["device"],
                    user=row["user"],
                    evidence=evidence,
                    reason=(
                        f"{row['parent_process_name']} started {row['process_name']}. "
                        "Office applications have no routine need to launch script "
                        "interpreters; this parent/child relationship is consistent "
                        "with macro-based code execution from a document."
                    ),
                    metadata={
                        "parent_process": row["parent_process_name"],
                        "child_process": row["process_name"],
                        "command_line": row["command_line"],
                    },
                )
            )
        return findings


# ======================================================================================
# ATH-002
# ======================================================================================


@register
class EncodedPowerShell(Detector):
    """ATH-002 -- PowerShell executed a base64-encoded command.

    Attacker behaviour
    ------------------
    ``powershell.exe -EncodedCommand <base64>`` runs a script supplied as base64 of
    UTF-16LE text. Attackers use it to defeat command-line string matching, to survive
    quoting problems when launching from a macro, and to keep the payload off disk
    entirely (fileless execution).

    What this rule adds beyond "the string -enc appeared"
    -----------------------------------------------------
    1. It handles PowerShell's *parameter prefix matching*. ``-e``, ``-en``, ``-enc``
       and ``-EncodedCommand`` are all valid and equivalent. A rule that greps for the
       full flag name misses the short forms, which is exactly what attackers use.
    2. It **decodes the payload** and inspects it. Encoding alone is weak evidence --
       legitimate tooling encodes commands too. What the payload *does* is the strong
       evidence, so severity is raised only when the decoded script fetches or
       executes remote code.
    3. It records co-occurring evasion flags (``-w hidden``, ``-nop``) as supporting
       context rather than as the detection itself.

    Severity is intentionally graded: this rule *will* fire on legitimate automation,
    and treating every hit as HIGH would train an analyst to ignore it.
    """

    rule_id = "ATH-002"
    title = "Encoded PowerShell command execution"
    severity = Severity.MEDIUM
    description = "Detects and decodes PowerShell -EncodedCommand payloads."
    fields_used = ("process_name", "command_line", "parent_process_name", "device", "user")
    false_positives = (
        "Configuration management (SCCM/Intune/Ansible/Chef) routinely wraps scripts "
        "in -EncodedCommand to avoid shell quoting issues.",
        "Software installers and vendor agents invoking helper scripts.",
        "Administrators using encoded commands to pass multi-line scripts remotely.",
        "CI/CD agents executing build steps on Windows runners.",
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        procs = telemetry.processes
        if procs.empty:
            return []

        is_powershell = _lower(procs["process_name"]).isin({"powershell.exe", "pwsh.exe"})
        candidates = procs[is_powershell]

        findings: list[Finding] = []
        for _, row in candidates.iterrows():
            command_line = row["command_line"] or ""
            blob = extract_encoded_command(command_line)
            if not blob:
                continue

            decoded = decode_powershell_b64(blob)
            evasion = find_evasion_flags(command_line)
            downloads = find_download_indicators(decoded or "")

            # Grade the severity by what the payload actually does.
            if downloads:
                severity = Severity.HIGH
                verdict = (
                    "The decoded payload retrieves and executes remote content, which "
                    "is consistent with a first-stage downloader."
                )
            elif evasion:
                severity = Severity.MEDIUM
                verdict = (
                    "The payload does not obviously fetch remote code, but the command "
                    "line also suppresses the console window and/or the user profile."
                )
            else:
                severity = Severity.LOW
                verdict = (
                    "Encoding alone is weak evidence and is common in legitimate "
                    "automation; review the decoded content below."
                )

            detail = f"decoded: {truncate(decoded, 200)}" if decoded else "payload did not decode to text"
            evidence = (
                Evidence(
                    event_id=row["event_id"],
                    timestamp=row["timestamp"],
                    summary=(
                        f"{row['parent_process_name']} -> {row['process_name']} with an "
                        f"encoded command; {detail}"
                    ),
                ),
            )
            findings.append(
                self.make_finding(
                    device=row["device"],
                    user=row["user"],
                    evidence=evidence,
                    severity=severity,
                    reason=(
                        f"PowerShell ran a base64-encoded command. {verdict}"
                        + (f" Evasion flags observed: {', '.join(evasion)}." if evasion else "")
                    ),
                    metadata={
                        "encoded_length": len(blob),
                        "decoded_command": decoded,
                        "evasion_flags": evasion,
                        "download_indicators": downloads,
                        "parent_process": row["parent_process_name"],
                    },
                )
            )
        return findings


# ======================================================================================
# ATH-004
# ======================================================================================

# Patterns describing attempts to read or dump LSASS process memory.
_LSASS_PATTERNS: dict[str, str] = {
    "comsvcs.dll MiniDump": r"comsvcs\.dll.{0,40}minidump",
    "explicit lsass reference": r"\blsass(\.exe|\.dmp)?\b",
    "procdump against lsass": r"procdump(64)?\.exe.{0,60}lsass",
    "mimikatz sekurlsa module": r"sekurlsa::",
    "credential dump keyword": r"\b(lsadump|dumpcreds|logonpasswords)\b",
    "rundll32 MiniDump export": r"rundll32.{0,80}\bminidump\b",
}

# Indicators that describe LSASS as the *target* of a command, and so are matched
# against the arguments only. ``lsass.exe`` names itself in argv[0] every time it
# starts (``wininit.exe -> C:\Windows\system32\lsass.exe`` at boot), and a rule that
# reads that as "a command line referenced lsass" fires once per host per boot: 30
# findings a day on a 30-host estate doing nothing (DEDALE, M14). The image path is
# what a process *is*, never what it acts on.
_ARGUMENT_ONLY_INDICATORS: frozenset[str] = frozenset({"explicit lsass reference"})


def _arguments(command_line: str, image_path: str = "", process_name: str = "") -> str:
    """The command line with argv[0] removed -- what the process *acts on*.

    Four strategies, strongest evidence first. The order is the point: the earlier ones
    read a field that actually says where the image ends, and only the last one guesses.

    1. **Quoted argv[0]** (``"C:\\Program Files\\app.exe" -flag``). Unambiguous: Windows
       itself uses the quotes to delimit the image, so the closing quote is the answer.
    2. **The authoritative image path.** ``file_path`` is the executable the sensor
       resolved, independent of how the command line happens to be spelled. When the
       command line starts with it, its length is exactly where argv[0] ends -- spaces
       and all.
    3. **The image's file name.** When the path was recorded differently from the command
       line (a short path, a mapped drive, a different case), the *name* usually still
       appears; argv[0] ends at the end of its first occurrence.
    4. **First whitespace token.** The original behaviour, kept only as a last resort for
       telemetry carrying no image field at all, and documented as unreliable rather than
       silently relied upon.

    Strategy 4 is what defect M16-1 was: for ``D:\\Program Files\\vendor\\lsass.exe`` it
    yields ``Files\\vendor\\lsass.exe`` as "the arguments", so an argument-only indicator
    matched a process that was merely starting and ATH-004 fired CRITICAL. DEDALE could
    not expose it -- LSASS lives in ``C:\\Windows\\System32``, which has no space in it --
    so the tuning corpus contained only the case where guessing works.

    Matching is case-insensitive because Windows paths are, and an attacker choosing
    ``LSASS.EXE`` must not land in a different branch from ``lsass.exe``.

    Args:
        command_line: The full command line. May be empty; an absent command line is a
            fact about the telemetry, not an error, and yields no arguments.
        image_path: The resolved executable path, when the source carries one.
        process_name: The image file name, when the source carries one.

    Returns:
        The argument portion, or ``""`` when the command line is empty or consists of
        argv[0] alone.
    """
    stripped = command_line.strip()
    if not stripped:
        return ""

    if stripped.startswith('"'):
        closing = stripped.find('"', 1)
        return stripped[closing + 1:].strip() if closing != -1 else ""

    folded = stripped.casefold()

    path = (image_path or "").strip().strip('"').casefold()
    if path and folded.startswith(path):
        return stripped[len(path):].strip()

    name = (process_name or "").strip().strip('"').casefold()
    if name:
        position = folded.find(name)
        if position != -1:
            return stripped[position + len(name):].strip()

    parts = stripped.split(None, 1)
    return parts[1].strip() if len(parts) > 1 else ""


@register
class LsassCredentialAccess(Detector):
    """ATH-004 -- Behaviour consistent with dumping LSASS process memory.

    Attacker behaviour
    ------------------
    LSASS (``lsass.exe``, the Local Security Authority Subsystem Service) holds
    credential material for sessions on the machine -- password hashes, Kerberos
    tickets, sometimes plaintext. Dumping its memory and parsing it offline is how an
    intruder turns "code execution on one laptop" into "valid credentials for the
    domain". It is the hinge between local compromise and enterprise compromise, which
    is why this rule is CRITICAL.

    The specific technique in this dataset is *living off the land*: instead of
    dropping Mimikatz, the attacker calls the ``MiniDump`` export of Microsoft's own
    signed ``comsvcs.dll`` via ``rundll32.exe``. No attacker binary touches disk, so
    antivirus file scanning sees nothing unusual.

    What a reference to LSASS is, and is not
    -----------------------------------------
    The "explicit lsass reference" indicator means *another process named LSASS on its
    command line*, as a target. It is therefore matched against the arguments, never
    argv[0]: ``lsass.exe`` starting at boot carries its own image path and nothing
    else, and that is the service starting, not credential access. The tool-shaped
    indicators (``comsvcs.dll ... MiniDump``, ``procdump ... lsass``, ``sekurlsa::``)
    are matched against the full line because the tool name is part of the evidence.

    Honest limitation -- state this in an interview
    ------------------------------------------------
    This rule inspects **command lines only**, because that is what our telemetry
    contains. Real credential dumping is better detected by observing a process
    *opening a handle to lsass.exe* with read-memory access rights (in Defender:
    ``DeviceEvents | where ActionType == "OpenProcess"`` with a granted-access mask
    such as 0x1010). An attacker who dumps LSASS from within their own implant, using
    a direct API call, produces no suspicious command line at all and would be
    invisible to this rule. Command-line detection is the cheap 80% -- not the whole
    picture. The corresponding KQL file shows the handle-based version.
    """

    rule_id = "ATH-004"
    title = "Possible LSASS credential access"
    severity = Severity.CRITICAL
    description = "Detects command lines consistent with dumping LSASS process memory."
    fields_used = ("command_line", "process_name", "parent_process_name", "device", "user")
    false_positives = (
        "IT support intentionally capturing an LSASS dump to debug an authentication "
        "or crash issue (Sysinternals procdump is a legitimate tool).",
        "Endpoint security and DFIR products that legitimately read LSASS memory.",
        "Performance or crash-dump tooling configured to capture all processes.",
        "Security testing, red-team exercises, or detection validation runs.",
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        procs = telemetry.processes
        if procs.empty:
            return []

        findings: list[Finding] = []
        for _, row in procs.iterrows():
            command_line = (row["command_line"] or "").lower()
            if not command_line:
                continue
            arguments = _arguments(
                command_line,
                image_path=str(row.get("file_path") or ""),
                process_name=str(row.get("process_name") or ""),
            )
            matched = [
                name for name, pattern in _LSASS_PATTERNS.items()
                if re.search(
                    pattern,
                    arguments if name in _ARGUMENT_ONLY_INDICATORS else command_line,
                )
            ]
            if not matched:
                continue

            evidence = (
                Evidence(
                    event_id=row["event_id"],
                    timestamp=row["timestamp"],
                    summary=(
                        f"{row['parent_process_name']} -> {row['process_name']}: "
                        f"{truncate(row['command_line'], 180)}"
                    ),
                ),
            )
            findings.append(
                self.make_finding(
                    device=row["device"],
                    user=row["user"],
                    evidence=evidence,
                    reason=(
                        f"Command line matched credential-access indicators "
                        f"({', '.join(matched)}). This may indicate an attempt to "
                        "extract credential material from LSASS memory, which would "
                        "enable authentication as other users. Requires immediate "
                        "verification against the account's expected activity."
                    ),
                    metadata={
                        "indicators": matched,
                        "command_line": row["command_line"],
                        "parent_process": row["parent_process_name"],
                    },
                )
            )
        return findings


# ======================================================================================
# ATH-007
# ======================================================================================

# Output redirection to an administrative share is the signature of remote-exec
# tooling (PsExec, smbexec, Impacket) collecting command results over SMB.
_ADMIN_SHARE_REDIRECT = re.compile(r"\\\\[^\\]+\\(admin\$|c\$|ipc\$)", re.IGNORECASE)


@register
class RemoteServiceExecution(Detector):
    """ATH-007 -- Command shell spawned by the Service Control Manager.

    Attacker behaviour
    ------------------
    To run a command on a remote Windows host, tooling such as PsExec and Impacket's
    ``smbexec`` authenticates over SMB, writes a temporary service definition, and asks
    the Service Control Manager (``services.exe``) to start it. The service body is a
    command shell. Results are written back to an administrative share (``ADMIN$``) so
    the operator can read them remotely.

    The telemetry signature is therefore ``services.exe -> cmd.exe`` (or
    ``-> powershell.exe``), frequently with output redirected to ``\\\\...\\ADMIN$\\``.

    Why lineage matters again
    --------------------------
    ``services.exe`` legitimately spawns a great many processes -- that is its entire
    job. What is abnormal is specifically an *interactive command interpreter* as a
    service body. Anchoring on the child process rather than the parent keeps this rule
    quiet: in this dataset ``services.exe`` starts Defender and the patch-management
    agent dozens of times without firing.
    """

    rule_id = "ATH-007"
    title = "Remote service execution (PsExec-style)"
    severity = Severity.HIGH
    description = "Detects command interpreters started by the Service Control Manager."
    fields_used = (
        "parent_process_name", "process_name", "command_line", "device", "user", "timestamp",
    )
    false_positives = (
        "IT administrators legitimately using PsExec for remote support.",
        "Monitoring, backup or deployment agents that run scripts via a service.",
        "Scheduled maintenance jobs implemented as transient services.",
        "Vulnerability scanners performing authenticated remote checks.",
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        procs = telemetry.processes
        if procs.empty:
            return []

        shells = {"cmd.exe", "powershell.exe", "pwsh.exe"}
        mask = (_lower(procs["parent_process_name"]) == "services.exe") & _lower(
            procs["process_name"]
        ).isin(shells)
        hits = procs[mask]

        findings: list[Finding] = []
        for _, row in hits.iterrows():
            command_line = row["command_line"] or ""
            share_match = _ADMIN_SHARE_REDIRECT.search(command_line)

            if share_match:
                severity = Severity.HIGH
                extra = (
                    f" Command output is redirected to the administrative share "
                    f"'{share_match.group(0)}', which is characteristic of remote "
                    "execution frameworks collecting results over SMB."
                )
            else:
                severity = Severity.MEDIUM
                extra = (
                    " No administrative-share redirection was observed, so this may be "
                    "a legitimate service-based automation."
                )

            evidence = (
                Evidence(
                    event_id=row["event_id"],
                    timestamp=row["timestamp"],
                    summary=(
                        f"services.exe (PID {row['parent_process_id']}) spawned "
                        f"{row['process_name']}: {truncate(command_line, 160)}"
                    ),
                ),
            )
            findings.append(
                self.make_finding(
                    device=row["device"],
                    user=row["user"],
                    evidence=evidence,
                    severity=severity,
                    reason=(
                        "The Service Control Manager started an interactive command "
                        "interpreter. This pattern is consistent with remote command "
                        "execution via a temporary service." + extra
                    ),
                    metadata={
                        "command_line": command_line,
                        "admin_share_redirect": bool(share_match),
                        "process": row["process_name"],
                    },
                )
            )
        return findings


# ======================================================================================
# ATH-008
# ======================================================================================

_ARCHIVE_TOOLS = re.compile(
    r"\b(compress-archive|7z(a|r)?\.exe|winrar\.exe|rar\.exe|tar\.exe|makecab\.exe"
    r"|zip\.exe|\[io\.compression\.zipfile\])\b",
    re.IGNORECASE,
)

# Directories an attacker stages data in: writable by many, ignored by most.
_STAGING_PATHS = re.compile(
    r"(c:\\windows\\temp|c:\\temp|c:\\users\\public|\\appdata\\local\\temp"
    r"|c:\\programdata|\\\$recycle\.bin)",
    re.IGNORECASE,
)

# A wildcard over a whole directory implies bulk collection rather than one file.
_BULK_SOURCE = re.compile(r"-path\s+\S*\*|\s\S+\\\*(\s|$)", re.IGNORECASE)


@register
class DataStagingArchive(Detector):
    """ATH-008 -- Bulk archive creation into a staging directory.

    Attacker behaviour
    ------------------
    Before exfiltration, data is usually *collected and staged*: interesting files are
    compressed into a single archive so they can leave the network in one transfer.
    Compression also shrinks the volume and obscures content from inspection.

    The archive is written somewhere unremarkable and world-writable --
    ``C:\\Windows\\Temp``, ``C:\\Users\\Public``, ``ProgramData`` -- rather than to the
    operator's own profile.

    Detection shape
    ---------------
    Archive utility **and** (bulk wildcard source **or** staging destination). Requiring
    two conditions is what keeps this usable: a user zipping one file to email is
    normal, and firing on every ``Compress-Archive`` would be intolerable.

    This rule detects *collection*, not exfiltration. Proving data actually left
    requires correlating with an outbound transfer, which is a chaining problem for the
    next milestone rather than something a single-event rule can assert.
    """

    rule_id = "ATH-008"
    title = "Bulk data staged into an archive"
    severity = Severity.MEDIUM
    description = "Detects archive creation over bulk paths or into staging directories."
    fields_used = ("command_line", "process_name", "parent_process_name", "device", "user")
    false_positives = (
        "Legitimate backup jobs and scheduled archive tasks.",
        "Users compressing a folder to share or email.",
        "Log rotation and diagnostic bundle collection by IT tooling.",
        "Software build and packaging steps producing artefacts in temp directories.",
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        procs = telemetry.processes
        if procs.empty:
            return []

        findings: list[Finding] = []
        for _, row in procs.iterrows():
            command_line = row["command_line"] or ""
            if not _ARCHIVE_TOOLS.search(command_line):
                continue

            staged = bool(_STAGING_PATHS.search(command_line))
            bulk = bool(_BULK_SOURCE.search(command_line))
            if not (staged or bulk):
                continue

            reasons = []
            if bulk:
                reasons.append("the source path uses a wildcard, implying bulk collection")
            if staged:
                reasons.append("the destination is a shared staging directory")

            evidence = (
                Evidence(
                    event_id=row["event_id"],
                    timestamp=row["timestamp"],
                    summary=(
                        f"{row['parent_process_name']} -> {row['process_name']}: "
                        f"{truncate(command_line, 180)}"
                    ),
                ),
            )
            findings.append(
                self.make_finding(
                    device=row["device"],
                    user=row["user"],
                    evidence=evidence,
                    severity=Severity.HIGH if (staged and bulk) else Severity.MEDIUM,
                    reason=(
                        f"An archive utility was invoked and {' and '.join(reasons)}. "
                        "This is consistent with staging data prior to exfiltration, "
                        "but does not by itself show that any data left the network."
                    ),
                    metadata={
                        "command_line": command_line,
                        "bulk_source": bulk,
                        "staging_destination": staged,
                    },
                )
            )
        return findings
