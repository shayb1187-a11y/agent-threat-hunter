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

import dataclasses
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

    # --- AWS-003 / AWS-004 / AWS-005 / AWS-006 generic control-plane behaviour ---
    #
    # Every number below was pre-registered in reports/m18/cloud_detection/PREREGISTERED.md
    # at HEAD eb7d395, *before* any of these four rules existed and before anything ran
    # against the held-out attack corpus. Each is traced there to the background
    # distribution in reports/m18/cloud_behaviour/flaws_cloud.json (flaws.cloud,
    # 1,857,154 control rows, 55 actors, ~3.6 years) and to the candidate grid M18-7
    # evaluated in advance. A test parses that file and fails if any value here differs
    # from what was registered, so tuning after seeing the results is not a quiet edit.

    cloud_discovery_min_services: int = 10
    """AWS-003: distinct services a single actor's read-class calls must touch inside
    :attr:`cloud_discovery_window` before the breadth is called a discovery burst.

    The background distribution over 55 actors at a 10-minute window is p50 = 1,
    p90 = 11.8, p99 = 125.6, max = 145. The pre-registered grid prices the candidates at
    that window: >= 5 reaches 9 actors on 335 actor-days, >= 10 reaches 7 actors on 179
    actor-days, >= 20 reaches 4 actors on 89 actor-days. 10 sits just above p90 -- the
    knee -- and below the 19 services the T1526 capture reaches, because a breadth rule
    that misses breadth is the failure this exists to avoid."""

    cloud_discovery_window: timedelta = timedelta(minutes=10)
    """AWS-003: the sliding window the distinct services must fall inside. Ten minutes is
    the window the background distribution above was measured over; a rule applying a
    threshold at a different window than the one it was priced at is a different rule."""

    cloud_denial_min_count: int = 25
    """AWS-004: authorization denials (``decision == "denied"``, never "an error
    occurred") one actor must accumulate inside :attr:`cloud_denial_window`.

    Background at 10 minutes: p50 = 0, p90 = 1.6, p99 = 2,417, max = 2,639 -- a trail
    where almost every actor is never refused and three are refused constantly. The grid
    prices 10/25/50/100 at 306/203/162/134 actor-days. 25 takes most of the volume
    reduction available; past it the cost stops falling, because the remaining cost is
    the same three tail identities."""

    cloud_denial_window: timedelta = timedelta(minutes=10)
    """AWS-004: the sliding window those denials must fall inside."""

    cloud_identity_change_window: timedelta = timedelta(minutes=60)
    """AWS-005 and AWS-006: the episode length over which one actor's authority changes
    on the identity service are aggregated into a single finding.

    Sixty minutes, not ten, because the behaviour is a person or a script working through
    a list of identities rather than a scanner emptying a target list -- and because the
    background statistics were measured at both lengths, so this one is priced too."""

    cloud_identity_failed_min_count: int = 5
    """AWS-006: identity authority changes the platform *rejected for a reason other than
    authorization* that one actor must accumulate inside
    :attr:`cloud_identity_change_window`.

    The background distribution is p50 = 0, p90 = 0, p99 = 2.92, max = 4, at both window
    lengths; the grid reaches 1 actor on 1 actor-day at >= 3 and **no actor at all** at
    >= 5 or >= 10. 5 is the smallest value flaws.cloud never reaches -- exactly one above
    its observed maximum."""


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
        """Execute the rule on the telemetry its declaration entitles it to see.

        The restriction is the point, not the sorting. A rule that declares
        ``channels`` is telling the coverage model which telemetry it depends on, and
        that statement is only worth printing if the rule cannot then cite something
        else anyway. Until M18b-1 the two were connected by a check *after* the fact
        (``findings_respect_declared_channels``), which reports a violation once it has
        already been produced -- and a fixture that happens not to contain the offending
        shape reports nothing at all. Here the rule is handed a table it cannot violate:
        ``detect`` never sees the rows in the first place.
        """
        findings = self.detect(self.scoped_telemetry(telemetry))
        return sorted(findings, key=lambda f: f.first_seen)

    def scoped_telemetry(self, telemetry: Telemetry) -> Telemetry:
        """``telemetry`` with the control table cut down to this rule's channels.

        Only the control table, because it is the only one whose channel is not
        derivable from the row's own columns: a CloudTrail management row and a
        Kubernetes audit row fill exactly the same columns and are told apart by
        ``source`` alone (see :func:`ath.environment.channels.channel_of_control_row`).
        The process, network and logon tables are handed over untouched -- their
        channels are evidenced by the columns a row carries, so restricting them would
        mean deciding that a row with an empty ``remote_url`` is not a network row.

        A rule with no explicit ``channels`` is unaffected, which is every one of the
        ten Windows rules: their channels are inferred from ``fields_used``, and
        inferring a scope from column names is exactly the ambiguity this attribute
        exists to avoid.

        Costs one boolean mask per run, built from the handful of distinct ``source``
        values rather than per row, and returns ``telemetry`` itself whenever nothing
        would be dropped -- so the common case copies no frame at all.
        """
        # Imported here, not at module scope: `ath.environment.coverage` imports this
        # module for `Detector`, and importing the package from here at import time
        # closes that loop. One function-level import is cheaper than splitting the
        # catalogue to break a cycle that exists only in the import graph.
        from ath.environment.channels import channel_of_control_row

        if not self.channels:
            return telemetry
        controls = telemetry.controls
        if controls.empty:
            return telemetry

        sources = controls["source"].astype("string").fillna("")
        admitted = {
            value: channel_of_control_row(value) in self.channels
            for value in sources.unique().tolist()
        }
        if all(admitted.values()):
            return telemetry
        mask = sources.map(admitted).astype(bool).to_numpy()
        return dataclasses.replace(
            telemetry, controls=controls.loc[mask].reset_index(drop=True),
        )

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
