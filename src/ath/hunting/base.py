"""Detector base class, tunable thresholds, and the rule registry.

Two ideas here are worth understanding before reading any rule:

**1. Thresholds live in config, not in rule bodies.**
A number buried inside a rule ("if failures > 10") is untunable and untestable. Every
threshold lives on :class:`HuntConfig`, so a test can lower it to prove the boundary
behaviour, and an analyst can raise it for a noisy environment without editing logic.

**2. Rules declare their own limitations.**
``fields_used`` and ``false_positives`` are class attributes, not comments. They are
carried into every :class:`Finding` the rule produces. This is how the eventual report
stays honest: the caveat is attached to the evidence at the moment of detection and
cannot be dropped later.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import timedelta

from ath.channels import TelemetryChannel
from ath.hunting.finding import Finding, Severity
from ath.telemetry.loader import Telemetry


@dataclass(frozen=True)
class HuntConfig:
    """Tunable detection thresholds.

    Every value is a trade-off between false negatives and false positives. Defaults
    are chosen for *this* dataset and are documented per rule; they are not universal
    truths, and in a real environment each would be derived from a baseline.
    """

    # --- ATH-005 brute force ---
    bruteforce_min_failures: int = 10
    """Failures required inside the window before we call it a burst. Set above the
    number of times a human plausibly mistypes a password in ten minutes."""

    bruteforce_window: timedelta = timedelta(minutes=10)
    """Sliding window the failures must fall inside."""

    bruteforce_success_window: timedelta = timedelta(minutes=15)
    """How long after a burst a success still counts as 'the burst worked'."""

    # --- ATH-003 script interpreter egress ---
    allowed_external_destinations: frozenset[str] = frozenset()
    """Destination IPs treated as known-good. **Deliberately empty by default** so the
    benign IT-automation traffic in the dataset still produces a false positive you can
    see and reason about. Populating this is the first tuning step, not a code change."""

    # --- ATH-006 lateral movement ---
    ownership_logon_types: frozenset[int] = frozenset({2, 7, 11})
    """Logon types that establish 'this account belongs on this host': console,
    unlock, cached interactive. Type 10 (RDP) is excluded -- an attacker with stolen
    credentials can RDP in, so RDP does not prove ownership."""

    remote_logon_types: frozenset[int] = frozenset({3, 10})
    """Logon types that represent authenticating *to* a host from elsewhere."""

    # --- AWS-001 / K8S-002 privilege-escalation-then-abuse chains ---
    privilege_escalation_window: timedelta = timedelta(minutes=30)
    """How long after a privilege grant its use still counts as the same chain.

    Shared by AWS-001 (policy attach -> access-key creation by the newly-privileged
    identity) and K8S-002 (RBAC grant -> pod exec by the newly-privileged identity) --
    both are the same shape: a grant, then that grant's beneficiary acting on it."""


# Process names treated as script interpreters / LOLBins capable of executing
# attacker-supplied code. Lower-cased for case-insensitive comparison.
SCRIPT_INTERPRETERS: frozenset[str] = frozenset(
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "bitsadmin.exe",
        "certutil.exe", "msbuild.exe", "installutil.exe",
    }
)

# Office-suite applications that should essentially never spawn an interpreter. The
# behaviour ATH-001 describes -- a document's macro reaching for a shell -- is a property
# of the document format, not of the vendor: LibreOffice opens .doc/.docm files, runs
# their macros, and on DEDALE's attack day was the application that opened the lure
# (``soffice.exe`` launches ``soffice.bin``, which is the process that spawns; M14 D15).
OFFICE_APPLICATIONS: frozenset[str] = frozenset(
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "msaccess.exe", "onenote.exe", "visio.exe", "mspub.exe",
        "soffice.exe", "soffice.bin",
    }
)


class Detector(ABC):
    """Base class for every deterministic detection rule.

    Subclasses declare their identity and caveats as class attributes and implement
    :meth:`detect`. :meth:`run` wraps that with the config plumbing, so a rule body
    contains only detection logic.
    """

    rule_id: str = ""
    title: str = ""
    severity: Severity = Severity.MEDIUM
    description: str = ""
    fields_used: tuple[str, ...] = ()
    false_positives: tuple[str, ...] = ()

    tables: frozenset[str] = frozenset()
    """Canonical tables (``ath.schema`` ``EVENT_*`` values) this rule reads.

    Declared because eligibility -- "was there any input for this rule at all" -- is
    otherwise not computable from the detector. The M17 evaluation had to carry a
    hard-coded rule-id-to-table map outside the rule set to report it, and that map
    had already drifted from the code it described (it credited ATH-007 with the logon
    table, which ATH-007 never reads).

    Eligibility, usability and detection are three separate measurements:
    eligibility is this declaration against row counts, usability is `fields_used`
    against per-field population, and detection is findings. Collapsing any two of
    them is how "0 findings" comes to mean "clean data" when it meant "empty table" or
    "the field this rule filters on was never populated".
    """

    optional_fields: frozenset[str] = frozenset()
    """The subset of `fields_used` this rule reads only to sharpen or explain a
    finding, and never gates detection on.

    Where the line falls, exactly
    ------------------------------
    A field is **REQUIRED** if it affects *either* whether a finding exists *or* what
    severity that finding receives. **OPTIONAL** only if it affects evidence text or
    metadata alone.

    Severity is on the required side of that line because severity is not decoration: it
    is what `ath.triage` compares against its benign boundary, so a field that only
    "adjusts severity" decides whether the finding survives triage at all -- which is
    indistinguishable, from an analyst's queue, from deciding whether the finding exists.
    A field declared optional because "it only changes the severity" would make a rule
    that silently drops every finding it produces read as healthy.

    The two worked examples this rule of thumb was drawn from (M18-1):

    * ATH-003's `remote_port` -- REQUIRED. The rule fires without it, but the port is
      what raises the finding to high; unpopulated, every finding lands below triage's
      boundary.
    * ATH-005's `logon_type` -- OPTIONAL. It appears only in the evidence sentence, so
      the Windows logon type CloudTrail cannot supply costs phrasing, not detection.

    An unpopulated *required* field makes a rule blind (or silently benign); an
    unpopulated optional field makes its output less precise while the rule still fires,
    and still fires at the same severity, on its remaining fields. Reporting both as
    failure would mark working detections broken.

    Every entry must appear in `fields_used`, and each one is justified against the
    line of the rule body that reads it.
    """

    channels: frozenset[TelemetryChannel] = frozenset()
    """Telemetry channels this rule depends on, declared explicitly.

    Empty (the default) means "infer from `fields_used` via
    `ath.environment.coverage.channels_for_fields()`" -- which is exactly today's
    behaviour, so none of the ten existing Windows rules need to set this.

    Set it explicitly when column-name inference would be ambiguous or wrong. The
    motivating case: AWS management-API rules and Kubernetes audit rules both read a
    column literally named `verb`/`resource_type` on the same canonical `control`
    table, and no amount of column-name matching can tell those two telemetry sources
    apart -- `fields_used` stays real column names for evidence/report text, and this
    attribute carries the disambiguating channel identity instead of `fields_used`
    being overloaded with synthetic tags.
    """

    def __init__(self, config: HuntConfig | None = None) -> None:
        self.config = config or HuntConfig()

    @abstractmethod
    def detect(self, telemetry: Telemetry) -> list[Finding]:
        """Return findings for this rule. Must not read ground truth."""

    def run(self, telemetry: Telemetry) -> list[Finding]:
        """Execute the rule and return findings sorted chronologically."""
        findings = self.detect(telemetry)
        return sorted(findings, key=lambda f: f.first_seen)

    # -- helper used by every rule to build findings consistently ---------------

    def make_finding(
        self,
        *,
        device: str,
        user: str,
        evidence: tuple,
        reason: str,
        severity: Severity | None = None,
        metadata: dict | None = None,
    ) -> Finding:
        """Construct a Finding pre-populated with this rule's declared metadata."""
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=severity or self.severity,
            device=device,
            user=user,
            evidence=tuple(evidence),
            reason=reason,
            fields_used=self.fields_used,
            false_positives=self.false_positives,
            metadata=metadata or {},
            channels=self.channels,
        )


# --------------------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------------------

_REGISTRY: dict[str, type[Detector]] = {}


def register(cls: type[Detector]) -> type[Detector]:
    """Class decorator that adds a detector to the global registry.

    Raises:
        ValueError: on a missing or duplicated rule id. Rule ids appear in reports and
            tickets, so a silent collision would corrupt the audit trail.
    """
    if not cls.rule_id:
        raise ValueError(f"{cls.__name__} must define a rule_id")
    if cls.rule_id in _REGISTRY:
        raise ValueError(
            f"Duplicate rule_id {cls.rule_id!r}: "
            f"{cls.__name__} collides with {_REGISTRY[cls.rule_id].__name__}"
        )
    _REGISTRY[cls.rule_id] = cls
    return cls


def all_detectors(config: HuntConfig | None = None) -> list[Detector]:
    """Instantiate every registered detector, ordered by rule id."""
    from ath.hunting import rules  # noqa: F401  -- import triggers registration

    return [_REGISTRY[rid](config) for rid in sorted(_REGISTRY)]


def get_detector(rule_id: str, config: HuntConfig | None = None) -> Detector:
    """Instantiate a single detector by rule id.

    Raises:
        KeyError: if the rule id is unknown.
    """
    from ath.hunting import rules  # noqa: F401

    key = rule_id.upper()
    if key not in _REGISTRY:
        raise KeyError(f"Unknown rule {rule_id!r}. Known rules: {sorted(_REGISTRY)}")
    return _REGISTRY[key](config)


def registered_rule_ids() -> list[str]:
    """Return all registered rule ids."""
    from ath.hunting import rules  # noqa: F401

    return sorted(_REGISTRY)
