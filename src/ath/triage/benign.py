"""Benign-evidence assessment: arguing the innocent explanation, with evidence.

The gap this closes
-------------------
Every layer before this one looks for reasons to be suspicious. None looks for reasons
not to be -- and the system was already *computing* the exculpatory evidence and
throwing it away. ``ATH-002`` decodes the administrator's payload, observes that it
carries no evasion flags and fetches nothing, notes that its parent is patch-management
tooling, uses all of that to grade the finding ``LOW`` -- and then emits an alert
indistinguishable in kind from the attacker's.

"Low severity" is not the same statement as "here is why this is legitimate". The first
still costs an analyst a triage decision and gives them nothing to make it with. So this
module turns the evidence that was already there into an explicit, cited counter-case.

Why interpretation, not suppression
------------------------------------
This is the same shape as :mod:`ath.mitre.mapper`: a table of gated interpretations over
findings the deterministic layer already produced. It **never deletes a finding and
never edits one**. A :class:`Disposition` is an opinion with reasons attached, exactly
as an ``AttackMapping`` is, and an analyst can disagree with it while still seeing
everything the detection saw. A pipeline that silently dropped alerts it believed benign
would be unauditable -- and the first time it was wrong, nobody would ever know.

The veto, and why it is not symmetric
--------------------------------------
Benign signals can be **out-voted but never out-weighed**. Any incriminating indicator
in :data:`VETOES` blocks a benign disposition outright, regardless of how much
exculpatory evidence accumulated. The asymmetry is deliberate: the cost of wrongly
reassuring an analyst about a real intrusion is not comparable to the cost of asking
them to look at something legitimate.

This matters most for prevalence. "Lots of hosts talk to this address" is the strongest
benign signal available without threat intelligence, and it is exactly the signal an
adversary defeats by living off trusted infrastructure -- C2 over a cloud storage or
collaboration service inherits the reach of the legitimate product. Prevalence therefore
contributes weight but is powerless against a veto, so a beacon through a popular
service still cannot be marked benign on reach alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

from ath.environment.model import EnvironmentModel
from ath.hunting.finding import Finding, Severity

# Weight at which accumulated benign evidence justifies a benign disposition. Set so
# that a single signal is never enough: the administrator's script clears it on three
# independent observations (recognised tooling, no evasion, no download), not on one.
BENIGN_THRESHOLD: int = 4

# A rule that graded its own finding HIGH or above did so on evidence this layer does
# not re-litigate. Benign assessment may only speak to findings the detection layer was
# itself unsure about.
MAX_SEVERITY_FOR_BENIGN: Severity = Severity.MEDIUM

# Repeat outbound contacts by a script interpreter beyond which reach can no longer
# excuse the traffic. See _sustained_interpreter_contact for why this veto exists.
SUSTAINED_CONTACT_THRESHOLD: int = 5


class Disposition(str, Enum):
    """What an analyst should do with a finding, and why."""

    LIKELY_MALICIOUS = "likely_malicious"
    """An incriminating indicator is present. Triage first."""

    NEEDS_REVIEW = "needs_review"
    """The default. Nothing decisive either way -- the honest answer for most alerts."""

    LIKELY_BENIGN = "likely_benign"
    """Affirmative, cited evidence of legitimate activity, and nothing incriminating."""

    @property
    def rank(self) -> int:
        return {"likely_malicious": 2, "needs_review": 1, "likely_benign": 0}[self.value]


@dataclass(frozen=True)
class Signal:
    """One observation bearing on whether a finding is legitimate.

    Attributes:
        name: Stable identifier.
        reason: Analyst-facing explanation, rendered verbatim.
        weight: Contribution toward :data:`BENIGN_THRESHOLD`.
        affirmative: Whether this is positive evidence *of legitimacy* (this was
            started by a known management product) as opposed to the mere *absence*
            of an incriminating marker (no evasion flags were present).

            The distinction is load-bearing -- see :data:`BENIGN_SIGNALS`.
    """

    name: str
    reason: str
    weight: int = 0
    affirmative: bool = False


# A gate reads a finding plus the environment and returns a rendered reason, or None
# when the signal does not apply. Same shape as the ATT&CK mapper's gates.
Gate = Callable[[Finding, EnvironmentModel], "str | None"]


def _meta(finding: Finding, key: str, default: Any = None) -> Any:
    return finding.metadata.get(key, default)


# --------------------------------------------------------------------------------------
# Benign signals -- reasons to believe this is ordinary activity
# --------------------------------------------------------------------------------------


def _known_management_tool(finding: Finding, env: EnvironmentModel) -> str | None:
    """The process was started by a **verifiably** recognised management product.

    The single most informative fact about the administrator's encoded PowerShell, and
    one the environment model already establishes -- it identifies ``CcmExec.exe`` as
    Microsoft Configuration Manager.

    ``is_known_security_tool`` requires a consistent valid signature as well as a
    matching name, so a payload dropped as ``MsMpEng.exe`` earns nothing here. That
    check used to be name-only, which handed an attacker the largest single benign
    signal in the table for the price of a rename.
    """
    parent = str(_meta(finding, "parent_process", "") or "")
    if not parent:
        return None
    product = env.is_known_security_tool(parent)
    if product is None:
        return None
    profile = env.processes.get(parent.lower())
    signer = profile.signers[0] if profile and profile.signers else "an unnamed publisher"
    return (
        f"started by {parent}, identified in this environment as {product} and validly "
        f"signed by {signer} in every observation"
    )


def _established_tooling(finding: Finding, env: EnvironmentModel) -> str | None:
    """The parent process is widespread estate tooling rather than a one-off."""
    parent = str(_meta(finding, "parent_process", "") or "")
    if not parent or env.is_known_security_tool(parent) is not None:
        return None  # already covered, and more specifically, by the signal above
    reach = env.process_reach(parent)
    profile = env.processes.get(parent.lower())
    if reach < 0.5 or profile is None or profile.spawned_children < 5:
        return None
    return (
        f"parent process {parent} runs on {reach:.0%} of hosts and has spawned "
        f"{profile.spawned_children} child processes here, which is the profile of "
        "estate tooling rather than of a one-off execution"
    )


def _no_evasion_indicators(finding: Finding, env: EnvironmentModel) -> str | None:
    """The command line carries none of the flags that describe hiding.

    Only meaningful where the rule actually looked -- absence of a key means the rule
    never inspected it, which is not the same as having checked and found nothing.
    """
    if "evasion_flags" not in finding.metadata:
        return None
    if _meta(finding, "evasion_flags"):
        return None
    return "the command line carries no hidden-window, no-profile or bypass flags"


def _no_download_indicators(finding: Finding, env: EnvironmentModel) -> str | None:
    """The decoded payload does not fetch or execute remote code."""
    if "download_indicators" not in finding.metadata:
        return None
    if _meta(finding, "download_indicators"):
        return None
    decoded = str(_meta(finding, "decoded_command", "") or "")
    detail = f": {decoded[:80]}" if decoded else ""
    return f"the decoded payload retrieves no remote code{detail}"


def _ubiquitous_destination(finding: Finding, env: EnvironmentModel) -> str | None:
    """The destination is contacted broadly, by many unrelated processes.

    Distinct *processes* is the discriminating part. Many hosts reaching an address
    could be many copies of one implant; a browser, a mail client and the antivirus
    engine all reaching it is what shared infrastructure looks like.
    """
    remote_ip = str(_meta(finding, "remote_ip", "") or "")
    if not remote_ip:
        return None
    profile = env.destinations.get(remote_ip)
    if profile is None:
        return None
    reach = env.destination_reach(remote_ip)
    if reach < 0.5 or len(profile.processes) < 3:
        return None
    if not profile.windowed.is_established:
        # Wide reach that appeared recently is not evidence of legitimacy -- it is the
        # shape of something spreading, and a rollout and a worm look identical here.
        # Breadth only reassures when the thing has been part of the environment for a
        # while, so a newly ubiquitous destination gets no benign credit.
        return None
    return (
        f"{remote_ip} is contacted by {reach:.0%} of hosts via "
        f"{len(profile.processes)} different processes "
        f"({', '.join(profile.processes[:4])}) and has been present across the "
        "observation window rather than appearing recently, which is the profile of "
        "shared infrastructure rather than of a single implant's callback"
    )


def _encrypted_standard_port(finding: Finding, env: EnvironmentModel) -> str | None:
    """Traffic is TLS on 443 only, with no cleartext channel alongside it."""
    ports = _meta(finding, "ports")
    if not ports or _meta(finding, "cleartext_http"):
        return None
    if set(int(p) for p in ports) != {443}:
        return None
    return "all observed traffic is TLS on port 443, with no cleartext channel"


# Signals, with whether each is *affirmative* evidence of legitimacy or merely the
# absence of an incriminating marker.
#
# The split exists because of a hole adversarial testing found: a finding naming a
# parent process this environment has never seen, with an empty command line, scored
# `no_evasion_indicators` (2) + `no_download_indicators` (2) = 4 and was cleared as
# benign. Nothing about it was known to be legitimate; it had simply avoided tripping
# anything. That is absence of evidence being read as evidence of absence -- the exact
# error this project refuses everywhere else -- and it is trivially reachable by an
# attacker, since "carry no recognised bad indicators" is the easy half of evasion.
#
# A benign verdict now requires at least one affirmative signal as well as the score.
BENIGN_SIGNALS: tuple[tuple[str, int, bool, Gate], ...] = (
    # Affirmative: something is positively known about this activity.
    ("known_management_tool", 3, True, _known_management_tool),
    ("established_tooling", 2, True, _established_tooling),
    ("ubiquitous_destination", 3, True, _ubiquitous_destination),
    # Supporting: an incriminating marker was looked for and not found. Corroborates
    # an affirmative signal; never substitutes for one.
    ("no_evasion_indicators", 2, False, _no_evasion_indicators),
    ("no_download_indicators", 2, False, _no_download_indicators),
    ("encrypted_standard_port", 1, False, _encrypted_standard_port),
)


# --------------------------------------------------------------------------------------
# Vetoes -- any one of these blocks a benign disposition outright
# --------------------------------------------------------------------------------------


def _evasion_present(finding: Finding, env: EnvironmentModel) -> str | None:
    flags = _meta(finding, "evasion_flags") or []
    if not flags:
        return None
    return f"the command line carries evasion flags: {', '.join(flags)}"


def _download_present(finding: Finding, env: EnvironmentModel) -> str | None:
    indicators = _meta(finding, "download_indicators") or []
    if not indicators:
        return None
    return f"the decoded payload retrieves remote code: {', '.join(indicators)}"


def _office_parent(finding: Finding, env: EnvironmentModel) -> str | None:
    from ath.hunting.base import OFFICE_APPLICATIONS

    parent = str(_meta(finding, "parent_process", "") or "").lower()
    if parent not in OFFICE_APPLICATIONS:
        return None
    return f"the interpreter was spawned by {parent}, which does not run scripts legitimately"


def _cleartext_egress(finding: Finding, env: EnvironmentModel) -> str | None:
    if not _meta(finding, "cleartext_http"):
        return None
    return "code or content was retrieved over cleartext HTTP to an external address"


def _sustained_interpreter_contact(finding: Finding, env: EnvironmentModel) -> str | None:
    """Repeated contact with one destination by a script interpreter.

    This exists to close a hole the prevalence signal opens. An implant that beacons
    through a popular cloud service inherits that service's reach, so
    ``_ubiquitous_destination`` fires on it and -- before this veto -- was enough on its
    own to mark a 48-connection beacon ``likely_benign``. Telling an analyst to ignore
    live C2 is the worst output this system could produce.

    Volume separates the two cases where reach cannot. An inventory script checks in
    once; a beacon keeps going. The threshold is deliberately low and is a property of
    the *shape* rather than of any dataset: a legitimate interpreter making the same
    outbound call five times over is already unusual enough to look at.

    Note this reads ``connection_count``, which only the script-interpreter egress rule
    records -- so the veto is scoped to exactly the findings where an interpreter is
    definitionally the process involved.
    """
    count = _meta(finding, "connection_count")
    if count is None or int(count) < SUSTAINED_CONTACT_THRESHOLD:
        return None
    return (
        f"a script interpreter contacted this destination {int(count)} times; repeat "
        "contact is the shape of automated callback, and reach alone cannot excuse it"
    )


def _suspiciously_regular_contact(finding: Finding, env: EnvironmentModel) -> str | None:
    """The relationship's inter-arrival timing is machine-regular.

    The veto this milestone exists for. ``_sustained_interpreter_contact`` catches
    *volume*, which is why a 48-connection beacon was already blocked -- but four TLS
    connections to a popular destination stayed under the threshold and were returned
    as ``likely_benign``. The regularity that would have distinguished them was
    computed in ``analyse_beacon``, inside the investigation layer, which triage cannot
    reach.

    It now reads the same :class:`~ath.behavior.features.ConnectionPattern` every other
    layer reads, so volume is no longer the only temporal signal available here.

    What this deliberately does *not* claim
    ----------------------------------------
    Three intervals do not establish a beacon. Nothing here asserts one. Firing this
    veto removes ``likely_benign`` and yields ``needs_review`` -- an analyst is asked to
    look, not told what they will find. Promoting it to ``likely_malicious`` would
    repeat the prevalence mistake in the opposite direction: a legitimate update client
    polls on a timer and is indistinguishable on this evidence alone.
    """
    remote_ip = str(_meta(finding, "remote_ip", "") or "")
    host = finding.device
    if not remote_ip or not host:
        return None

    pattern = env.connection_pattern(host, remote_ip)
    if pattern is None or not pattern.is_regular:
        return None

    median_seconds = pattern.median_interval.total_seconds()
    return (
        f"contact with {remote_ip} recurs at a machine-regular interval "
        f"(median {median_seconds:.0f}s, MAD/median {pattern.robust_cv:.2f} across "
        f"{pattern.interarrival_count} intervals). That is thin support and does not "
        "establish a beacon -- but it is enough that this cannot be set aside as "
        "ordinary traffic on the strength of the destination being popular"
    )


def _identity_conflict(finding: Finding, env: EnvironmentModel) -> str | None:
    """The image name means different things in different places in this environment.

    Impersonation's fingerprint. Visible only because process identity is profiled
    across every host rather than judged per event: a name that is Microsoft-signed on
    six machines and unsigned on one is not a name any conclusion may rest on, and the
    unsigned copy is the interesting one.
    """
    for key in ("parent_process", "process_name"):
        name = str(_meta(finding, key, "") or "")
        if not name:
            continue
        conflict = env.identity_conflict(name)
        if conflict is not None:
            return conflict
    return None


def _high_severity(finding: Finding, env: EnvironmentModel) -> str | None:
    if finding.severity.rank <= MAX_SEVERITY_FOR_BENIGN.rank:
        return None
    return (
        f"the detection graded this {finding.severity} on its own evidence, which this "
        "layer does not re-litigate"
    )


VETOES: tuple[tuple[str, Gate], ...] = (
    ("evasion_flags_present", _evasion_present),
    ("download_indicators_present", _download_present),
    ("office_application_parent", _office_parent),
    ("cleartext_external_retrieval", _cleartext_egress),
    ("sustained_interpreter_contact", _sustained_interpreter_contact),
    ("process_identity_conflict", _identity_conflict),
    ("graded_high_by_detection", _high_severity),
)

# Observations strong enough to withdraw reassurance, but not strong enough to
# incriminate. A disqualifier forces `needs_review`; it never yields
# `likely_malicious`.
#
# The distinction matters because the alternative is to overclaim in the direction
# opposite to the one this layer was built to prevent. Four regular intervals to a
# popular destination genuinely might be an update client polling on a timer. Refusing
# to call that benign is correct; calling it malicious would be a different false
# statement made with the same unearned confidence.
DISQUALIFIERS: tuple[tuple[str, Gate], ...] = (
    ("suspiciously_regular_contact", _suspiciously_regular_contact),
)


# --------------------------------------------------------------------------------------
# Assessment
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class TriageAssessment:
    """The benign/malicious reading of one finding, with everything it rests on."""

    finding_id: str
    rule_id: str
    disposition: Disposition
    benign_signals: tuple[Signal, ...] = ()
    vetoes: tuple[Signal, ...] = ()
    disqualifiers: tuple[Signal, ...] = ()
    """Reasons this could not be cleared, which are not reasons to suspect it."""
    score: int = 0

    @property
    def explanation(self) -> str:
        """One sentence an analyst can act on."""
        if self.disposition is Disposition.LIKELY_MALICIOUS:
            return "Incriminating: " + "; ".join(v.reason for v in self.vetoes)
        if self.disqualifiers:
            return (
                "Cannot be set aside as ordinary activity: "
                + "; ".join(d.reason for d in self.disqualifiers)
            )
        if self.disposition is Disposition.LIKELY_BENIGN:
            return "Consistent with legitimate activity: " + "; ".join(
                s.reason for s in self.benign_signals
            )
        if self.benign_signals and not any(s.affirmative for s in self.benign_signals):
            return (
                "Nothing incriminating was found, but nothing positively identifies "
                "this as legitimate either: "
                + "; ".join(s.reason for s in self.benign_signals)
            )
        if self.benign_signals:
            return (
                "Some indication of legitimate activity, but not enough to set it "
                "aside: " + "; ".join(s.reason for s in self.benign_signals)
            )
        return "No evidence either way beyond what the detection itself reported."

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "disposition": self.disposition.value,
            "score": self.score,
            "threshold": BENIGN_THRESHOLD,
            "benign_signals": [
                {
                    "name": s.name, "weight": s.weight,
                    "affirmative": s.affirmative, "reason": s.reason,
                }
                for s in self.benign_signals
            ],
            "vetoes": [{"name": v.name, "reason": v.reason} for v in self.vetoes],
            "disqualifiers": [
                {"name": d.name, "reason": d.reason} for d in self.disqualifiers
            ],
            "explanation": self.explanation,
        }


def assess_finding(finding: Finding, environment: EnvironmentModel) -> TriageAssessment:
    """Weigh the benign and incriminating evidence for one finding.

    Deterministic and side-effect free. The finding itself is never modified: this
    returns an opinion *about* it, the way an ``AttackMapping`` does.
    """
    vetoes = tuple(
        Signal(name=name, reason=reason)
        for name, gate in VETOES
        if (reason := gate(finding, environment)) is not None
    )
    disqualifiers = tuple(
        Signal(name=name, reason=reason)
        for name, gate in DISQUALIFIERS
        if (reason := gate(finding, environment)) is not None
    )
    signals = tuple(
        Signal(name=name, reason=reason, weight=weight, affirmative=affirmative)
        for name, weight, affirmative, gate in BENIGN_SIGNALS
        if (reason := gate(finding, environment)) is not None
    )
    score = sum(s.weight for s in signals)
    has_affirmative = any(s.affirmative for s in signals)

    if vetoes:
        disposition = Disposition.LIKELY_MALICIOUS
    elif disqualifiers:
        # Enough to withdraw reassurance, deliberately not enough to incriminate.
        disposition = Disposition.NEEDS_REVIEW
    elif score >= BENIGN_THRESHOLD and has_affirmative:
        disposition = Disposition.LIKELY_BENIGN
    else:
        # Includes the case where enough weight accumulated purely from absent
        # indicators. Nothing was found *wrong* with it, which is not the same as
        # anything being known *right* about it.
        disposition = Disposition.NEEDS_REVIEW

    return TriageAssessment(
        finding_id=finding.finding_id,
        rule_id=finding.rule_id,
        disposition=disposition,
        benign_signals=signals,
        vetoes=vetoes,
        disqualifiers=disqualifiers,
        score=score,
    )


def assess_findings(
    findings: list[Finding], environment: EnvironmentModel
) -> dict[str, TriageAssessment]:
    """Assess every finding, keyed by ``finding_id``."""
    return {f.finding_id: assess_finding(f, environment) for f in findings}


def triage_summary(assessments: dict[str, TriageAssessment]) -> dict[str, int]:
    """Count findings by disposition."""
    counts = {d.value: 0 for d in Disposition}
    for assessment in assessments.values():
        counts[assessment.disposition.value] += 1
    return counts
