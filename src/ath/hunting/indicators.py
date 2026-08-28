"""Shared indicator helpers used by more than one rule.

Kept separate from the rules themselves because these are the parts most worth unit
testing in isolation -- a bug in ``extract_encoded_command`` would silently disable a
detection, which is a false negative rather than a crash.
"""

from __future__ import annotations

import base64
import binascii
import re

# Re-exported so existing imports keep working; the single definition lives in
# ath.netaddr, which ath.behavior can reach without pulling in the hunting layer.
from ath.netaddr import is_public_ip

# PowerShell accepts *any unambiguous prefix* of a parameter name. That means all of
# -e, -en, -enc, -encod and -EncodedCommand are valid and equivalent. Attackers use
# this to slip past naive rules that only look for the literal string "-EncodedCommand".
# We therefore match any -<letters> flag followed by a base64-looking blob, and then
# check in Python whether those letters are a prefix of "encodedcommand".
_FLAG_AND_BLOB = re.compile(
    r"(?:^|\s)[-/](?P<flag>[A-Za-z]+)[\s:]+(?P<blob>[A-Za-z0-9+/=]{20,})"
)

_ENCODED_COMMAND = "encodedcommand"

# Flags that indicate an operator is trying to run PowerShell unobtrusively. None is
# malicious alone; together they describe a script that does not want to be seen.
#
# Note what is deliberately NOT here: `-NonInteractive`. It is ubiquitous in
# legitimate scheduled automation and carries no evasive intent, so counting it as
# evasion would inflate the severity of every benign patch-management script. Keeping
# this list honest is what lets severity grading do useful work.
EVASION_FLAG_PATTERNS: dict[str, str] = {
    "hidden window": r"(?:^|\s)[-/]w(?:indowstyle)?\s+hidden",
    "no profile": r"(?:^|\s)[-/]nop(?:rofile)?(?:\s|$)",
    "execution policy bypass": r"(?:^|\s)[-/]e(?:x|xecutionpolicy)?\s+bypass",
}

# Substrings that, once a payload is decoded, indicate it fetches or runs remote code.
DOWNLOAD_INDICATORS: tuple[str, ...] = (
    "downloadstring", "downloadfile", "downloaddata", "invoke-webrequest",
    "invoke-restmethod", "iex", "invoke-expression", "start-bitstransfer",
    "net.webclient", "http://", "https://", "frombase64string",
)


def is_prefix_of_encoded_command(flag: str) -> bool:
    """Return True if ``flag`` is a valid PowerShell abbreviation of -EncodedCommand."""
    flag = flag.lower()
    return bool(flag) and _ENCODED_COMMAND.startswith(flag) and flag[0] == "e"


def extract_encoded_command(command_line: str) -> str | None:
    """Extract the base64 payload from a PowerShell ``-EncodedCommand`` invocation.

    Args:
        command_line: The full process command line.

    Returns:
        The base64 blob, or ``None`` if the command line has no encoded payload.
    """
    if not command_line:
        return None
    for match in _FLAG_AND_BLOB.finditer(command_line):
        if is_prefix_of_encoded_command(match.group("flag")):
            return match.group("blob")
    return None


def decode_powershell_b64(blob: str) -> str | None:
    """Decode a PowerShell ``-EncodedCommand`` payload.

    PowerShell encodes **UTF-16LE** bytes, not UTF-8. Decoding as UTF-8 yields text
    riddled with null bytes, which is why so many write-ups show mangled payloads.

    Args:
        blob: The base64 string.

    Returns:
        The decoded script, or ``None`` if it does not decode to sensible text.
    """
    if not blob:
        return None
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        return None

    for encoding in ("utf-16-le", "utf-8"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        # Reject binary noise that happens to base64-decode.
        printable = sum(c.isprintable() or c in "\r\n\t" for c in text)
        if text and printable / len(text) > 0.85:
            return text
    return None


def find_evasion_flags(command_line: str) -> list[str]:
    """Return the names of evasion-style PowerShell flags present in a command line."""
    lowered = (command_line or "").lower()
    return [
        name
        for name, pattern in EVASION_FLAG_PATTERNS.items()
        if re.search(pattern, lowered)
    ]


def find_download_indicators(decoded: str) -> list[str]:
    """Return remote-code-execution indicators present in a decoded payload."""
    lowered = (decoded or "").lower()
    return [ind for ind in DOWNLOAD_INDICATORS if ind in lowered]


def truncate(text: str, limit: int = 120) -> str:
    """Shorten long command lines for display without losing the informative head."""
    text = (text or "").strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."
