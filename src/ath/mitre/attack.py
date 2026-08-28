"""A small, hand-verified MITRE ATT&CK catalogue.

Why a catalogue instead of free-text technique IDs
--------------------------------------------------
The fastest way to make a security project look amateurish is to sprinkle plausible
technique IDs through the code. ``T1059.001`` in a string literal is untyped,
unverifiable, and one typo away from being wrong forever.

So every technique this project can emit is declared here, once, with its name, its
tactic(s), its parent technique, and the URL it was verified against.
:class:`AttackMapping` validates against this catalogue at construction time, which
means **there is no code path that can emit an invented technique ID**. A typo raises;
it does not ship.

ATT&CK version
--------------
Verified against ATT&CK for Enterprise **v19.2** -- see :data:`ATTACK_VERSION`, which is
the single source of truth for the version string; nothing else may restate it.

The one thing to know about v19: the ``Defense Evasion`` tactic was retired and split.
``TA0005`` was *kept* but renamed to **Stealth** (hiding within legitimate activity),
and a new tactic ``TA0112`` **Defense Impairment** was created for actively attacking
security controls. Detections tagged ``TA0005`` still resolve, but now describe a
narrower set of behaviours. Techniques like T1027 (Obfuscated Files or Information) and
T1218 (System Binary Proxy Execution) sit under Stealth.

Two consequences that are easy to get wrong, both verified against attack.mitre.org
rather than recalled:

* **T1112 Modify Registry moved to Defense Impairment.** It appears in the TA0112
  listing and is absent from TA0005. Anything still filing it under Stealth is stale.
* **T1562 is gone.** The current object for disabling security tooling is **T1685**,
  under Defense Impairment, whose sub-techniques ``.001``-``.006`` are all *log*-specific.
  Behaviour like killing an EDR process or stopping a security service belongs to the
  **parent**, T1685 -- naming a sub-technique would claim more specificity than the
  evidence carries. See :data:`RETIRED_TECHNIQUE_IDS`.

Vocabulary, since these words get used loosely
----------------------------------------------
**Tactic** -- the adversary's *goal*, the "why". `Credential Access` is a tactic:
the attacker wants credentials. There are ~14 of them and they are deliberately
coarse. Tactics answer "what stage of the intrusion is this?"

**Technique** -- the *how*. `T1003 OS Credential Dumping` is a technique: one general
method of achieving the Credential Access goal.

**Sub-technique** -- a more specific *how*. `T1003.001 LSASS Memory` is a sub-technique
of T1003: dumping credentials specifically out of LSASS process memory, as opposed to
`T1003.002` (SAM database) or `T1003.003` (NTDS.dit). Sub-techniques share their
parent's tactic. Report the sub-technique when the evidence supports that level of
specificity, and the parent when it does not -- claiming T1003.001 when you only know
"credentials were stolen somehow" is overclaiming.

**TTP** -- "Tactics, Techniques and Procedures". The *procedure* is the concrete
implementation an actor uses: not just "LSASS Memory" but specifically
"``rundll32.exe comsvcs.dll, MiniDump``". Procedures are what you actually write
detections against; techniques are how you communicate about them. A useful way to hold
it: tactic = why, technique = how, procedure = exactly how, in this case.

The critical distinction this module encodes
--------------------------------------------
There is a real difference between::

    "this event looks suspicious"            <- a Finding
    "this behaviour is consistent with T1X"  <- an AttackMapping

A finding is an observation about telemetry. A mapping is an *interpretation* of that
observation against a public taxonomy. ATT&CK describes what adversaries do; it does
not certify that any particular event was adversarial. Legitimate administrators
perform ATT&CK techniques constantly -- an IT engineer running an encoded PowerShell
script is genuinely performing T1027.010, and is not an attacker.

That is why every :class:`AttackMapping` carries a ``confidence`` and a ``reason``, and
why the wording throughout is "consistent with" rather than "proves".
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Tactic(Enum):
    """ATT&CK Enterprise tactics (the adversary's goal at a given stage).

    Values are ``(tactic_id, display_name)``.
    """

    INITIAL_ACCESS = ("TA0001", "Initial Access")
    EXECUTION = ("TA0002", "Execution")
    PERSISTENCE = ("TA0003", "Persistence")
    PRIVILEGE_ESCALATION = ("TA0004", "Privilege Escalation")
    STEALTH = ("TA0005", "Stealth")  # v19: renamed from "Defense Evasion"
    CREDENTIAL_ACCESS = ("TA0006", "Credential Access")
    DISCOVERY = ("TA0007", "Discovery")
    LATERAL_MOVEMENT = ("TA0008", "Lateral Movement")
    COLLECTION = ("TA0009", "Collection")
    EXFILTRATION = ("TA0010", "Exfiltration")
    COMMAND_AND_CONTROL = ("TA0011", "Command and Control")
    IMPACT = ("TA0040", "Impact")
    DEFENSE_IMPAIRMENT = ("TA0112", "Defense Impairment")  # v19: new

    @property
    def tactic_id(self) -> str:
        return self.value[0]

    @property
    def display_name(self) -> str:
        return self.value[1]

    def __str__(self) -> str:
        return self.display_name


class Confidence(str, Enum):
    """How strongly the observed evidence supports the technique interpretation.

    This grades the *interpretation*, not the severity of the behaviour:

    * ``HIGH``   -- the telemetry directly shows the technique's defining behaviour.
    * ``MEDIUM`` -- the telemetry is consistent with the technique, but a benign
      explanation is equally available, or one element is inferred rather than observed.
    * ``LOW``    -- the technique is plausible but a key element was never observed.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2}[self.value]

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Technique:
    """A single ATT&CK technique or sub-technique.

    Attributes:
        technique_id: e.g. ``"T1003.001"``.
        name: Official technique name.
        tactics: Every tactic the technique is listed under. Many techniques appear
            under several -- ``T1078 Valid Accounts`` is one of them.
        parent_id: For sub-techniques, the parent technique id; ``None`` otherwise.
        url: The attack.mitre.org page this entry was verified against.
    """

    technique_id: str
    name: str
    tactics: tuple[Tactic, ...]
    parent_id: str | None
    url: str

    @property
    def is_sub_technique(self) -> bool:
        return self.parent_id is not None

    @property
    def primary_tactic(self) -> Tactic:
        """The tactic this project reports for the technique.

        Multi-tactic techniques are listed with the most relevant tactic first in
        :data:`TECHNIQUES`, so the first entry is the one we surface.
        """
        return self.tactics[0]

    def __str__(self) -> str:
        return f"{self.technique_id} {self.name}"


def _t(
    technique_id: str, name: str, tactics: tuple[Tactic, ...], parent_id: str | None
) -> Technique:
    """Build a Technique, deriving its canonical attack.mitre.org URL."""
    path = technique_id.replace(".", "/")
    return Technique(
        technique_id=technique_id,
        name=name,
        tactics=tactics,
        parent_id=parent_id,
        url=f"https://attack.mitre.org/techniques/{path}/",
    )


# --------------------------------------------------------------------------------------
# The catalogue. Only techniques this project can actually evidence appear here --
# a deliberately short list is a feature, not a gap.
# --------------------------------------------------------------------------------------

TECHNIQUES: dict[str, Technique] = {
    t.technique_id: t
    for t in (
        # -- Execution --------------------------------------------------------------
        _t("T1059", "Command and Scripting Interpreter", (Tactic.EXECUTION,), None),
        _t("T1059.001", "PowerShell", (Tactic.EXECUTION,), "T1059"),
        _t("T1059.003", "Windows Command Shell", (Tactic.EXECUTION,), "T1059"),
        _t("T1204", "User Execution", (Tactic.EXECUTION,), None),
        _t("T1204.002", "Malicious File", (Tactic.EXECUTION,), "T1204"),
        _t("T1569", "System Services", (Tactic.EXECUTION,), None),
        _t("T1569.002", "Service Execution", (Tactic.EXECUTION,), "T1569"),
        # -- Stealth (TA0005, formerly Defense Evasion) -----------------------------
        _t("T1027", "Obfuscated Files or Information", (Tactic.STEALTH,), None),
        _t("T1027.010", "Command Obfuscation", (Tactic.STEALTH,), "T1027"),
        _t("T1218", "System Binary Proxy Execution", (Tactic.STEALTH,), None),
        _t("T1218.011", "Rundll32", (Tactic.STEALTH,), "T1218"),
        # -- Credential Access ------------------------------------------------------
        _t("T1003", "OS Credential Dumping", (Tactic.CREDENTIAL_ACCESS,), None),
        _t("T1003.001", "LSASS Memory", (Tactic.CREDENTIAL_ACCESS,), "T1003"),
        _t("T1110", "Brute Force", (Tactic.CREDENTIAL_ACCESS,), None),
        _t("T1110.001", "Password Guessing", (Tactic.CREDENTIAL_ACCESS,), "T1110"),
        # -- Valid Accounts: genuinely multi-tactic ---------------------------------
        _t(
            "T1078",
            "Valid Accounts",
            (
                Tactic.PERSISTENCE,
                Tactic.PRIVILEGE_ESCALATION,
                Tactic.INITIAL_ACCESS,
                Tactic.STEALTH,
            ),
            None,
        ),
        _t(
            "T1078.002",
            "Domain Accounts",
            (
                Tactic.PERSISTENCE,
                Tactic.PRIVILEGE_ESCALATION,
                Tactic.INITIAL_ACCESS,
                Tactic.STEALTH,
            ),
            "T1078",
        ),
        # -- Lateral Movement -------------------------------------------------------
        _t("T1021", "Remote Services", (Tactic.LATERAL_MOVEMENT,), None),
        _t("T1021.001", "Remote Desktop Protocol", (Tactic.LATERAL_MOVEMENT,), "T1021"),
        _t("T1021.002", "SMB/Windows Admin Shares", (Tactic.LATERAL_MOVEMENT,), "T1021"),
        # -- Command and Control ----------------------------------------------------
        _t("T1071", "Application Layer Protocol", (Tactic.COMMAND_AND_CONTROL,), None),
        _t("T1071.001", "Web Protocols", (Tactic.COMMAND_AND_CONTROL,), "T1071"),
        _t("T1105", "Ingress Tool Transfer", (Tactic.COMMAND_AND_CONTROL,), None),
        # -- Collection -------------------------------------------------------------
        _t("T1560", "Archive Collected Data", (Tactic.COLLECTION,), None),
        _t("T1560.001", "Archive via Utility", (Tactic.COLLECTION,), "T1560"),
        _t("T1074", "Data Staged", (Tactic.COLLECTION,), None),
        _t("T1074.001", "Local Data Staging", (Tactic.COLLECTION,), "T1074"),
        # -- Discovery ---------------------------------------------------------------
        # Added for ATH-010 (Milestone 6 detection-engineering loop). Verified against
        # attack.mitre.org on the date this catalogue entry was added; each has no
        # ambiguity in tactic assignment (all single-tactic, Discovery only).
        _t("T1033", "System Owner/User Discovery", (Tactic.DISCOVERY,), None),
        _t("T1069", "Permission Groups Discovery", (Tactic.DISCOVERY,), None),
        _t("T1069.002", "Domain Groups", (Tactic.DISCOVERY,), "T1069"),
        _t("T1482", "Domain Trust Discovery", (Tactic.DISCOVERY,), None),
        # -- Impact ------------------------------------------------------------------
        # Added for ATH-011. Verified against attack.mitre.org: T1490 sits under Impact,
        # has no sub-techniques, and its description explicitly names vssadmin,
        # wbadmin, bcdedit and REAgentC -- the exact procedures the rule keys on.
        _t("T1490", "Inhibit System Recovery", (Tactic.IMPACT,), None),
        # -- Defense Impairment (TA0112, new in v19) ----------------------------------
        # Added for ATH-012. T1685 replaces the retired T1562 lineage; see
        # RETIRED_TECHNIQUE_IDS below for why the old id must never reappear.
        #
        # Mapped at PARENT level deliberately. T1685's own description covers "stopping
        # specific services, killing processes, modifying or deleting tool configuration
        # files and Registry keys" -- which is exactly what ATH-012 observes. Every one
        # of its sub-techniques (.001-.006) is log-specific (Windows Event Log, Cloud
        # Log, Tool UI, Linux Audit, Clear Windows/Linux logs), so naming one would
        # assert a narrower, different claim than the evidence supports.
        _t("T1685", "Disable or Modify Tools", (Tactic.DEFENSE_IMPAIRMENT,), None),
        # T1112 moved from Defense Evasion to Defense Impairment in v19: it is present
        # in the TA0112 listing and absent from TA0005. Carried here so the coverage
        # watchlist can reference a catalogue entry rather than a bare string.
        _t("T1112", "Modify Registry", (Tactic.DEFENSE_IMPAIRMENT,), None),
    )
}

# The ATT&CK content release this catalogue was verified against. Single source of
# truth: the README reads this value rather than restating it, so the two cannot drift.
ATTACK_VERSION = "v19.2 (Enterprise, content release August 2026)"

# Tactic names retired by the v19 split. Any of these surviving anywhere in the
# catalogue or the coverage watchlist means a mapping is silently mis-attributed, so a
# test fails the build rather than letting the analysis quietly rot.
RETIRED_TACTIC_NAMES: frozenset[str] = frozenset({"Defense Evasion"})

# Technique ids this project must never emit again, with what replaced them.
#
# T1562 (and its .001 sub-technique) was the pre-v19 home for "Disable or Modify Tools".
# It appears in neither the current TA0005 Stealth listing nor the TA0112 Defense
# Impairment listing, and its own pages no longer serve content. T1685 is the current
# object. Recorded as data rather than prose so the drift test can enforce it.
RETIRED_TECHNIQUE_IDS: dict[str, str] = {
    "T1562": "T1685",
    "T1562.001": "T1685",
}


class UnknownTechniqueError(KeyError):
    """Raised when a technique id is not in the verified catalogue."""


def get_technique(technique_id: str) -> Technique:
    """Look up a technique by id.

    Raises:
        UnknownTechniqueError: if the id is not in the catalogue. This is the guard
            that makes invented technique IDs structurally impossible.
    """
    try:
        return TECHNIQUES[technique_id]
    except KeyError:
        raise UnknownTechniqueError(
            f"{technique_id!r} is not in the verified ATT&CK catalogue. "
            "Add it to ath.mitre.attack.TECHNIQUES only after checking "
            "https://attack.mitre.org -- never from memory."
        ) from None


@dataclass(frozen=True)
class AttackMapping:
    """A candidate ATT&CK interpretation of a detection finding.

    This is explicitly a *candidate interpretation*, not a verdict. It says "the
    behaviour we observed matches how ATT&CK describes technique X", which is a
    different and weaker claim than "an attacker performed technique X".

    Attributes:
        technique_id: Must exist in :data:`TECHNIQUES`; validated on construction.
        rule_id: The detection rule whose finding produced this interpretation.
        confidence: How strongly the evidence supports the interpretation.
        reason: Plain-language justification, phrased with appropriate hedging.
        evidence_ids: Telemetry event ids backing the mapping. Must be non-empty --
            a mapping without evidence is exactly the kind of ATT&CK decoration this
            project exists to avoid.
    """

    technique_id: str
    rule_id: str
    confidence: Confidence
    reason: str
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        get_technique(self.technique_id)  # raises on anything not verified
        if not self.evidence_ids:
            raise ValueError(
                f"{self.technique_id}: an ATT&CK mapping must cite telemetry evidence."
            )

    # -- derived from the catalogue, never stored, so they cannot drift -------------

    @property
    def technique(self) -> Technique:
        return get_technique(self.technique_id)

    @property
    def technique_name(self) -> str:
        return self.technique.name

    @property
    def tactic(self) -> Tactic:
        return self.technique.primary_tactic

    @property
    def sub_technique_of(self) -> str | None:
        """Parent technique id when this is a sub-technique, else ``None``."""
        return self.technique.parent_id

    @property
    def parent_name(self) -> str | None:
        parent = self.technique.parent_id
        return get_technique(parent).name if parent else None

    @property
    def display(self) -> str:
        """e.g. ``"T1003.001 OS Credential Dumping: LSASS Memory"``."""
        if self.parent_name:
            return f"{self.technique_id} {self.parent_name}: {self.technique_name}"
        return f"{self.technique_id} {self.technique_name}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "display": self.display,
            "tactic": self.tactic.display_name,
            "tactic_id": self.tactic.tactic_id,
            "sub_technique_of": self.sub_technique_of,
            "confidence": self.confidence.value,
            "reason": self.reason,
            "evidence_ids": list(self.evidence_ids),
            "rule_id": self.rule_id,
            "url": self.technique.url,
        }

    def __str__(self) -> str:
        return f"{self.display} [{self.tactic}] ({self.confidence})"
