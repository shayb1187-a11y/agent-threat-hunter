"""Map detection findings to candidate ATT&CK interpretations.

Design: mappings are **gated on evidence**, not on rule identity
---------------------------------------------------------------
The lazy implementation is a dictionary::

    {"ATH-002": ["T1059.001", "T1027.010", "T1105"]}

That is wrong, and it is wrong in a way an interviewer will probe. It asserts
``T1105 Ingress Tool Transfer`` for *every* encoded PowerShell finding -- including the
IT administrator's hardware-inventory script, which downloads nothing. Blanket mapping
inflates your ATT&CK heat map with techniques you never actually observed, and a heat
map that says "we see credential access everywhere" is worse than no heat map.

So each candidate mapping carries a **gate**: a predicate over the finding's metadata
that must hold before the mapping is emitted. ``T1105`` is only asserted when the
decoded payload actually contains download indicators. The gate is why the same rule
produces three techniques for the attacker and one for the administrator.

Confidence is separate from severity
------------------------------------
``severity`` (on the Finding) answers *how urgently should someone look at this?*
``confidence`` (on the Mapping) answers *how sure are we this is the technique named?*
They move independently. A CRITICAL LSASS finding can be a HIGH-confidence T1003.001
mapping; a LOW-severity encoded PowerShell finding is still a HIGH-confidence
T1027.010 mapping, because the administrator genuinely *is* obfuscating a command --
that is simply not evidence of an attack.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from ath.hunting.finding import Finding
from ath.logging_setup import get_logger
from ath.mitre.attack import AttackMapping, Confidence, get_technique

logger = get_logger(__name__)

# A gate receives the finding and returns True when the mapping is justified.
Gate = Callable[[Finding], bool]

ALWAYS: Gate = lambda _f: True  # noqa: E731 -- the mapping holds whenever the rule fires


def _meta(finding: Finding, key: str, default: Any = None) -> Any:
    return finding.metadata.get(key, default)


@dataclass(frozen=True)
class MappingRule:
    """One candidate technique interpretation for one detection rule.

    Attributes:
        rule_id: The ATH rule this applies to.
        technique_id: Technique to assert, validated against the catalogue.
        confidence: Confidence in the interpretation when the gate passes.
        reason: Justification template; formatted with the finding's metadata.
        gate: Predicate that must hold before the mapping is emitted.
    """

    rule_id: str
    technique_id: str
    confidence: Confidence
    reason: str
    gate: Gate = ALWAYS

    def __post_init__(self) -> None:
        get_technique(self.technique_id)  # fail at import time, not at runtime

    def apply(self, finding: Finding) -> AttackMapping | None:
        """Emit a mapping for ``finding`` if the gate passes."""
        if finding.rule_id != self.rule_id or not self.gate(finding):
            return None
        return AttackMapping(
            technique_id=self.technique_id,
            rule_id=finding.rule_id,
            confidence=self.confidence,
            reason=self.reason,
            evidence_ids=finding.event_ids,
        )


# --------------------------------------------------------------------------------------
# Gates
# --------------------------------------------------------------------------------------


def _child_is(*names: str) -> Gate:
    return lambda f: str(_meta(f, "child_process", "")).lower() in names


def _has_download_indicators(f: Finding) -> bool:
    return bool(_meta(f, "download_indicators"))


def _is_web_port(f: Finding) -> bool:
    return bool(set(_meta(f, "ports", []) or []) & {80, 443, 8080, 8443})


def _retrieved_content(f: Finding) -> bool:
    """Cleartext HTTP or an observed URL: evidence something was *fetched*."""
    return bool(_meta(f, "cleartext_http")) or bool(_meta(f, "urls"))


def _lsass_indicator(f: Finding) -> bool:
    indicators = {str(i).lower() for i in _meta(f, "indicators", []) or []}
    return any(
        key in ind
        for ind in indicators
        for key in ("lsass", "comsvcs", "procdump", "sekurlsa", "minidump", "dump")
    )


def _rundll32_proxy(f: Finding) -> bool:
    cmd = str(_meta(f, "command_line", "")).lower()
    return "rundll32" in cmd and "comsvcs.dll" in cmd


def _bruteforce_succeeded(f: Finding) -> bool:
    return bool(_meta(f, "succeeded"))


def _logon_type(*types: int) -> Gate:
    return lambda f: bool(set(_meta(f, "logon_types", []) or []) & set(types))


def _admin_share(f: Finding) -> bool:
    return bool(_meta(f, "admin_share_redirect"))


def _staged_locally(f: Finding) -> bool:
    return bool(_meta(f, "staging_destination"))


# --------------------------------------------------------------------------------------
# The mapping table
# --------------------------------------------------------------------------------------

MAPPING_RULES: tuple[MappingRule, ...] = (
    # -- ATH-001 : Office spawned a script interpreter ------------------------------
    MappingRule(
        "ATH-001", "T1204.002", Confidence.MEDIUM,
        "An Office application spawned an interpreter, which is consistent with a user "
        "opening a document that executed embedded code. The document itself was not "
        "observed in telemetry, so the file's maliciousness is inferred, not confirmed.",
    ),
    MappingRule(
        "ATH-001", "T1059.001", Confidence.HIGH,
        "PowerShell was executed as a child of an Office application.",
        gate=_child_is("powershell.exe", "pwsh.exe"),
    ),
    MappingRule(
        "ATH-001", "T1059.003", Confidence.HIGH,
        "The Windows command shell was executed as a child of an Office application.",
        gate=_child_is("cmd.exe"),
    ),
    # Deliberately NOT mapped here: T1566.001 Spearphishing Attachment. The dataset
    # contains no email telemetry, so delivery by phishing is a guess. Mapping it would
    # be asserting a technique we cannot evidence.

    # -- ATH-002 : Encoded PowerShell -----------------------------------------------
    MappingRule(
        "ATH-002", "T1059.001", Confidence.HIGH,
        "The command was executed by powershell.exe.",
    ),
    MappingRule(
        "ATH-002", "T1027.010", Confidence.HIGH,
        "The command was passed base64-encoded via -EncodedCommand, which meets "
        "ATT&CK's definition of command obfuscation. Note that legitimate automation "
        "also does this: the technique is present, but it is not by itself evidence "
        "of an adversary.",
    ),
    MappingRule(
        "ATH-002", "T1105", Confidence.MEDIUM,
        "The decoded payload retrieves remote content, which is consistent with "
        "transferring a further tool or stage onto the host.",
        gate=_has_download_indicators,
    ),
    # -- ATH-003 : Interpreter egress -----------------------------------------------
    MappingRule(
        "ATH-003", "T1071.001", Confidence.MEDIUM,
        "A script interpreter communicated outbound over web protocol ports, which is "
        "consistent with command-and-control over HTTP/HTTPS. Ordinary scripted API "
        "calls produce the same shape.",
        gate=_is_web_port,
    ),
    MappingRule(
        "ATH-003", "T1105", Confidence.MEDIUM,
        "A URL or cleartext HTTP retrieval was observed from the interpreter, which is "
        "consistent with pulling an additional payload onto the host.",
        gate=_retrieved_content,
    ),
    # -- ATH-004 : LSASS ------------------------------------------------------------
    MappingRule(
        "ATH-004", "T1003.001", Confidence.HIGH,
        "The command line targets LSASS process memory for dumping, which is the "
        "defining behaviour of this sub-technique.",
        gate=_lsass_indicator,
    ),
    MappingRule(
        "ATH-004", "T1218.011", Confidence.MEDIUM,
        "The dump was performed by invoking an export of a signed Microsoft DLL "
        "through rundll32.exe, using trusted binaries as a proxy for execution.",
        gate=_rundll32_proxy,
    ),
    # -- ATH-005 : Brute force ------------------------------------------------------
    MappingRule(
        "ATH-005", "T1110.001", Confidence.HIGH,
        "Repeated failed authentications for a single account from a single source are "
        "consistent with systematically guessing that account's password. (A spray "
        "against many accounts would be T1110.003 and is not what was observed.)",
    ),
    MappingRule(
        "ATH-005", "T1078", Confidence.MEDIUM,
        "A successful authentication followed the failure burst, which is consistent "
        "with the account credential now being under adversary control.",
        gate=_bruteforce_succeeded,
    ),
    # -- ATH-006 : Foreign-host authentication --------------------------------------
    MappingRule(
        "ATH-006", "T1021.002", Confidence.MEDIUM,
        "The account authenticated to a remote host over a network (SMB) logon from a "
        "machine where it holds no session, which is consistent with using valid "
        "credentials to reach another system.",
        gate=_logon_type(3),
    ),
    MappingRule(
        "ATH-006", "T1021.001", Confidence.MEDIUM,
        "The account established a remote interactive (RDP) session from a machine "
        "where it holds no session.",
        gate=_logon_type(10),
    ),
    MappingRule(
        "ATH-006", "T1078", Confidence.MEDIUM,
        "A valid account was used from a host it does not operate on. Legitimate "
        "alternate-credential workflows produce the same pattern.",
    ),
    # -- ATH-007 : Remote service execution -----------------------------------------
    MappingRule(
        "ATH-007", "T1569.002", Confidence.HIGH,
        "A command interpreter was started by the Service Control Manager, which is "
        "the defining behaviour of executing a payload as a Windows service.",
    ),
    MappingRule(
        "ATH-007", "T1021.002", Confidence.MEDIUM,
        "Command output was redirected to an administrative share, indicating the "
        "service was driven over an authenticated SMB session from another host.",
        gate=_admin_share,
    ),
    # -- ATH-008 : Collection -------------------------------------------------------
    MappingRule(
        "ATH-008", "T1560.001", Confidence.HIGH,
        "A standard archive utility was used to compress data, which is the defining "
        "behaviour of archiving collected data via a utility.",
    ),
    MappingRule(
        "ATH-008", "T1074.001", Confidence.MEDIUM,
        "The archive was written to a shared staging directory rather than the "
        "operator's own profile, consistent with staging data locally before transfer.",
        gate=_staged_locally,
    ),
    # Deliberately NOT mapped anywhere: any Exfiltration technique (T1041, T1567...).
    # The dataset shows an archive being created and, separately, an outbound
    # connection. It never shows the archive's bytes leaving. Asserting exfiltration
    # would be inferring the conclusion we most want to be true, which is exactly the
    # bias this layer exists to resist.

    # -- ATH-009 : Macro-enabled document opened via email client (Milestone 6) -----
    MappingRule(
        "ATH-009", "T1204.002", Confidence.MEDIUM,
        "A user opened a document in a macro-capable format delivered by an email "
        "client. This is consistent with a malicious attachment being executed, "
        "though the email itself (sender, headers, delivery path) was not observed -- "
        "only that the file was opened.",
    ),
    # Deliberately NOT mapped here: T1566.001 Spearphishing Attachment. That technique
    # describes the DELIVERY mechanism -- the malicious email arriving -- which this
    # telemetry does not observe directly; only that Outlook subsequently opened a
    # macro-capable file. Asserting the delivery vector from the open event alone would
    # be inferring evidence we do not have, so this rule (like ATH-001) stops at
    # User Execution rather than reaching for Initial Access's Spearphishing technique.

    # -- ATH-010 : Discovery command sequence (Milestone 6) -------------------------
    MappingRule(
        "ATH-010", "T1033", Confidence.MEDIUM,
        "whoami, systeminfo, hostname or quser was among the discovery commands "
        "observed, consistent with identifying the current user or system context.",
        gate=lambda f: "T1033" in (f.metadata.get("candidate_techniques") or []),
    ),
    MappingRule(
        "ATH-010", "T1069.002", Confidence.MEDIUM,
        "net.exe was used with domain-group enumeration syntax, consistent with "
        "mapping domain-level permission groups.",
        gate=lambda f: "T1069.002" in (f.metadata.get("candidate_techniques") or []),
    ),
    MappingRule(
        "ATH-010", "T1482", Confidence.MEDIUM,
        "nltest was among the discovery commands observed, consistent with "
        "enumerating domain trust relationships to identify lateral-movement "
        "opportunities.",
        gate=lambda f: "T1482" in (f.metadata.get("candidate_techniques") or []),
    ),
)


def map_finding(finding: Finding) -> list[AttackMapping]:
    """Return every candidate ATT&CK interpretation for one finding.

    Args:
        finding: The detection finding to interpret.

    Returns:
        Mappings whose gates passed, ordered highest-confidence first. May be empty --
        a rule with no justified mapping is a correct outcome, not a bug.
    """
    mappings = [m for rule in MAPPING_RULES if (m := rule.apply(finding))]
    mappings.sort(key=lambda m: (-m.confidence.rank, m.technique_id))
    return mappings


def map_findings(findings: Iterable[Finding]) -> dict[str, list[AttackMapping]]:
    """Map many findings, keyed by :attr:`Finding.finding_id`."""
    result = {f.finding_id: map_finding(f) for f in findings}
    total = sum(len(v) for v in result.values())
    logger.info("Produced %d ATT&CK mappings across %d findings", total, len(result))
    return result


def unique_techniques(mappings: Iterable[AttackMapping]) -> list[str]:
    """Distinct technique ids, sorted."""
    return sorted({m.technique_id for m in mappings})


def tactics_covered(mappings: Iterable[AttackMapping]) -> list[str]:
    """Distinct tactic names, ordered by the ATT&CK kill-chain sequence.

    Tactic breadth is a far better signal of a real intrusion than finding count: ten
    Execution alerts are probably noise, whereas Execution -> Credential Access ->
    Lateral Movement -> Collection is a story.
    """
    order = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Stealth", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact",
        "Defense Impairment",
    ]
    names = {m.tactic.display_name for m in mappings}
    return [t for t in order if t in names]
