"""Process identity: what a binary *is*, as distinct from what it is called.

Why this exists
---------------
A process name is a claim a file makes about itself. Anyone can copy a binary and name
it ``MsMpEng.exe``, and every layer that reasons about trust from the name alone hands
an attacker the reputation of whatever they choose to imitate. That was a real, stated
hole in this project's benign-triage layer: ``is_known_security_tool`` matched on image
name, so a payload dropped as ``MsMpEng.exe`` would have inherited Microsoft Defender's
standing and contributed 3 points toward being dismissed as legitimate.

Three fields close it, in increasing order of strength:

``file_path``
    Weakest. ``C:\\Users\\jdoe\\AppData\\Local\\Temp\\MsMpEng.exe`` is not where Defender
    lives, and location alone is enough to reject most crude impersonation. Defeated by
    an attacker who can write to a system directory -- which usually requires the
    privilege they were trying to obtain.

``signer`` / ``signature_status``
    Strong. A signature is a cryptographic assertion by a named organisation, and an
    attacker cannot forge Microsoft's without Microsoft's key. Defeated by *stolen*
    signing keys, and -- far more commonly -- irrelevant against **living off the land**:
    ``powershell.exe`` and ``rundll32.exe`` are genuinely signed by Microsoft while
    running an attacker's payload. Signature answers "is this file what it claims to
    be", never "is what it is doing legitimate".

``sha256``
    The only truly stable identifier. Same content, same hash, regardless of name or
    path. What makes cross-host prevalence meaningful: "this exact binary runs on 40
    hosts" is a statement no rename can fake.

Synthetic identity is derived, not random
------------------------------------------
The generator needs these fields to be *consistent*: the same binary must produce the
same hash on every host, or prevalence analysis over hashes would be noise. So identity
is derived deterministically from the image name and its path rather than sampled --
same input, same identity, every run.
"""

from __future__ import annotations

import hashlib
from typing import Final

from ath.schema import SIG_UNSIGNED, SIG_VALID

# Publishers for the binaries this project's telemetry contains, keyed by lower-case
# image name. Deliberately a short list of things actually observed -- an invented
# catalogue of every Windows binary would be unverifiable and would rot.
KNOWN_PUBLISHERS: Final[dict[str, str]] = {
    # Microsoft operating system and platform components
    "svchost.exe": "Microsoft Corporation",
    "cmd.exe": "Microsoft Corporation",
    "powershell.exe": "Microsoft Corporation",
    "rundll32.exe": "Microsoft Corporation",
    "net.exe": "Microsoft Corporation",
    "net1.exe": "Microsoft Corporation",
    "nltest.exe": "Microsoft Corporation",
    "whoami.exe": "Microsoft Corporation",
    "notepad.exe": "Microsoft Corporation",
    "systeminfo.exe": "Microsoft Corporation",
    "hostname.exe": "Microsoft Corporation",
    "quser.exe": "Microsoft Corporation",
    "services.exe": "Microsoft Corporation",
    "lsass.exe": "Microsoft Corporation",
    "explorer.exe": "Microsoft Corporation",
    "winlogon.exe": "Microsoft Corporation",
    "schtasks.exe": "Microsoft Corporation",
    "vssadmin.exe": "Microsoft Corporation",
    # Microsoft applications and agents
    "msmpeng.exe": "Microsoft Corporation",
    "ccmexec.exe": "Microsoft Corporation",
    "onedrive.exe": "Microsoft Corporation",
    "teams.exe": "Microsoft Corporation",
    "outlook.exe": "Microsoft Corporation",
    "winword.exe": "Microsoft Corporation",
    "excel.exe": "Microsoft Corporation",
    "powerpnt.exe": "Microsoft Corporation",
    # Third party
    "chrome.exe": "Google LLC",
    "firefox.exe": "Mozilla Corporation",
}

# Directory prefixes where a signed vendor binary legitimately lives. Lower-cased.
TRUSTED_PATH_PREFIXES: Final[tuple[str, ...]] = (
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\programdata\\microsoft\\windows defender\\",
)

# Per-user install locations. Legitimate for a handful of applications that genuinely
# install there (Teams, OneDrive), and a favourite staging area for everything else --
# so membership here is not by itself evidence either way.
USER_INSTALL_MARKERS: Final[tuple[str, ...]] = (
    "\\appdata\\local\\microsoft\\teams\\",
    "\\appdata\\local\\microsoft\\onedrive\\",
)


def _fake_sha256(process_name: str, signer: str) -> str:
    """A stable, synthetic content hash.

    Derived from the image name and its publisher so that the same binary yields the
    same hash on every host -- which is the property that makes hash prevalence mean
    anything -- and so that an impersonating copy, having a different publisher, gets a
    different hash exactly as it would in reality.
    """
    material = f"{process_name.lower()}|{signer}".encode()
    return hashlib.sha256(material).hexdigest()


def derive_identity(process_name: str, file_path: str) -> tuple[str, str, str]:
    """Return ``(sha256, signer, signature_status)`` for a synthetic process image.

    A binary is treated as signed by its known publisher only when it is *also* running
    from a location that publisher would install to. A file named ``MsMpEng.exe`` in a
    temp directory is unsigned and unattributed, which is the whole point: the name
    earns nothing on its own.
    """
    name = (process_name or "").lower()
    path = (file_path or "").lower()

    publisher = KNOWN_PUBLISHERS.get(name)
    in_trusted_dir = any(path.startswith(prefix) for prefix in TRUSTED_PATH_PREFIXES)
    in_user_install = any(marker in path for marker in USER_INSTALL_MARKERS)

    if publisher and (in_trusted_dir or in_user_install):
        return _fake_sha256(name, publisher), publisher, SIG_VALID

    # Either an unrecognised binary, or a recognised name in a place its publisher
    # would never install to. Both are unsigned and unattributed here.
    return _fake_sha256(name, ""), "", SIG_UNSIGNED
