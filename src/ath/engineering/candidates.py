"""Candidate detection rules for the two coverage gaps this project has documented
since Milestone 3: **Initial Access** (the document being opened) and **Discovery**
(post-execution reconnaissance commands).

This module is where the "detection engineer" half of Milestone 6 lives. Everything
here is deterministic pandas logic, hand-authored by reading the telemetry shape a real
intrusion of this kind produces -- exactly what a human detection engineer does when
pivoting from a confirmed case to find nearby, unflagged activity. **Nothing in this
module reads ``ground_truth.json``**; that would be grading the candidate against the
answer key while writing the question, and a dedicated test enforces the boundary the
same way it is enforced for every rule in ``ath.hunting``.

Why two versions of each candidate
-----------------------------------
Real detection engineering is iterative: propose a rule, run it, look at what it got
wrong, tighten it, run it again. Milestone 8 of the original roadmap asked for exactly
this loop to be demonstrated rather than asserted, so each candidate below has a
genuinely too-broad ``v1`` and a measurably tightened ``v2`` -- the false positives
``v1`` produces are real rows already present in this project's synthetic benign
telemetry (not manufactured for the demo), and ``v2`` removes them by adding one
specific, explainable condition. See ``src/ath/engineering/harness.py`` for the
evaluation that proves this, and ``docs/detection-engineering.md`` for the walk-through.

What happens after evaluation
------------------------------
A candidate that scores well is *promoted*: its ``v2`` logic is re-implemented as a
permanent, registered rule in ``ath.hunting.rules`` (ATH-009 and ATH-010), with the
full complement of KQL, false-positive documentation, and tests every other rule has.
The classes in this module remain afterward as the historical record of how that rule
was arrived at -- deliberately not deleted, because a promoted rule with no visible
provenance is less trustworthy than one you can watch being built.
"""

from __future__ import annotations

import re

import pandas as pd

from ath.hunting.finding import Evidence, Finding, Severity
from ath.hunting.indicators import truncate
from ath.telemetry.loader import Telemetry

# Extensions capable of carrying an Office macro. A rule keyed on these is anchored in
# how Office actually works (macros live in these container formats), not tuned to this
# dataset's specific attachment name.
MACRO_EXTENSIONS: tuple[str, ...] = (".docm", ".dotm", ".xlsm", ".xlsb", ".pptm", ".ppsm")

OFFICE_APPS: frozenset[str] = frozenset(
    {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
)

# Windows discovery utilities commonly run in the reconnaissance phase of an intrusion,
# each mapped to the ATT&CK technique it corresponds to (see candidate_to_finding below
# and, for the promoted rule, ath.hunting.rules.discovery_rules).
DISCOVERY_BINARIES: dict[str, str] = {
    "whoami.exe": "T1033",       # System Owner/User Discovery
    "net.exe": "T1069.002",      # Permission Groups Discovery: Domain Groups
    "nltest.exe": "T1482",       # Domain Trust Discovery
    "systeminfo.exe": "T1033",
    "hostname.exe": "T1033",
    "quser.exe": "T1033",
}


class Candidate:
    """A proposed, unregistered detection rule.

    Deliberately not a subclass of :class:`ath.hunting.base.Detector`: candidates are
    not part of the permanent rule set (they are never picked up by
    :func:`ath.hunting.all_detectors`), so keeping the type distinct prevents one from
    accidentally being registered before it has been evaluated and promoted.

    Attributes:
        candidate_id: Identifier, e.g. ``"CAND-INITACCESS-v1"``.
        version: ``"v1"`` or ``"v2"``, for the harness to report side by side.
        title: Human-readable name.
        target_stage: The ground-truth stage name this candidate targets. Used only by
            the evaluation harness for scoring -- never read by ``detect``.
        rationale: Why this pattern is generalizable, not just fitted to this dataset.
    """

    candidate_id: str = ""
    version: str = ""
    title: str = ""
    target_stage: str = ""
    rationale: str = ""

    def detect(self, telemetry: Telemetry) -> list[Finding]:  # pragma: no cover - abstract
        raise NotImplementedError


# ======================================================================================
# Initial Access candidates
# ======================================================================================


class OfficeMacroDocumentOpenedV1(Candidate):
    """v1 -- ANY Office application launched by Outlook.

    The naive first pass: "an email client opened an Office document" is the shape of
    every phishing-delivered attachment, so alert on the parent/child relationship
    alone. This is exactly the kind of rule a detection engineer writes first and
    immediately regrets -- it is indistinguishable from someone reading a perfectly
    ordinary email with an attachment.
    """

    candidate_id = "CAND-INITACCESS-v1"
    version = "v1"
    title = "Office document opened by an email client"
    target_stage = "1-initial-access"
    rationale = (
        "Malicious attachments are, structurally, Office documents launched by "
        "Outlook. This is the correct parent/child shape, but v1 does not yet "
        "distinguish it from the enormous volume of ordinary email attachments "
        "opened every day."
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        procs = telemetry.processes
        mask = (procs["parent_process_name"].str.lower() == "outlook.exe") & (
            procs["process_name"].str.lower().isin(OFFICE_APPS)
        )
        return [
            _office_open_finding(row, self.candidate_id, self.title)
            for _, row in procs[mask].iterrows()
        ]


class OfficeMacroDocumentOpenedV2(Candidate):
    """v2 -- Outlook launched an Office application opening a **macro-enabled** file.

    The single tightening condition: check the file extension in the command line
    against the small, closed set of extensions that can actually carry a macro
    (``MACRO_EXTENSIONS``). A plain ``.docx`` cannot contain a macro at all -- the
    Office Open XML format only permits macros in the ``m``-suffixed container formats,
    which is precisely why Office itself refuses to run macros from a renamed ``.docx``.
    This is not a threshold tuned to this dataset; it is a fact about the file format.

    This is the version that gets promoted to a permanent rule (see
    ``ath.hunting.rules.initial_access_rules.OfficeMacroAttachmentOpened``).
    """

    candidate_id = "CAND-INITACCESS-v2"
    version = "v2"
    title = "Macro-enabled document opened by an email client"
    target_stage = "1-initial-access"
    rationale = (
        "Restricting v1 to extensions that can structurally contain a macro "
        "(.docm/.dotm/.xlsm/.xlsb/.pptm/.ppsm) removes ordinary attachment-reading "
        "activity without losing the technique: a non-macro document cannot deliver "
        "code execution via this vector regardless of content."
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        procs = telemetry.processes
        mask = (procs["parent_process_name"].str.lower() == "outlook.exe") & (
            procs["process_name"].str.lower().isin(OFFICE_APPS)
        )
        candidates = procs[mask]
        macro_mask = candidates["command_line"].str.lower().str.contains(
            "|".join(re.escape(ext) for ext in MACRO_EXTENSIONS), regex=True, na=False
        )
        return [
            _office_open_finding(row, self.candidate_id, self.title)
            for _, row in candidates[macro_mask].iterrows()
        ]


def _office_open_finding(row: pd.Series, candidate_id: str, title: str) -> Finding:
    evidence = (
        Evidence(
            event_id=row["event_id"], timestamp=row["timestamp"],
            summary=f"OUTLOOK.EXE opened {row['process_name']}: {truncate(row['command_line'], 140)}",
        ),
    )
    return Finding(
        rule_id=candidate_id, title=title, severity=Severity.MEDIUM,
        device=row["device"], user=row["user"], evidence=evidence,
        reason=(
            f"An email client launched {row['process_name']} to open a document: "
            f"{truncate(row['command_line'], 160)}"
        ),
        fields_used=("parent_process_name", "process_name", "command_line"),
        false_positives=("Ordinary email attachments that happen to use a macro-capable "
                         "container format without containing an active macro.",),
    )


# ======================================================================================
# Discovery candidates
# ======================================================================================


class DiscoveryCommandSequenceV1(Candidate):
    """v1 -- ANY known discovery binary executes, anywhere.

    The naive first pass: alert whenever ``whoami.exe``, ``net.exe``, ``nltest.exe``,
    ``systeminfo.exe``, ``hostname.exe`` or ``quser.exe`` runs. Every one of these is a
    legitimate everyday admin and troubleshooting tool -- ``ipconfig``, `whoami`` and
    friends run constantly in ordinary IT support work, which is exactly what this
    project's own benign telemetry contains.
    """

    candidate_id = "CAND-DISCOVERY-v1"
    version = "v1"
    title = "Discovery command executed"
    target_stage = "5-discovery"
    rationale = (
        "Anchoring on individual binary names is the most basic possible signature "
        "for reconnaissance activity, and is included here specifically to measure "
        "how noisy that is before tightening it."
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        procs = telemetry.processes
        mask = procs["process_name"].str.lower().isin(DISCOVERY_BINARIES) | (
            procs["command_line"].str.lower().str.contains("ipconfig", na=False)
        )
        return [
            _discovery_finding((row,), self.candidate_id, self.title)
            for _, row in procs[mask].iterrows()
        ]


class DiscoveryCommandSequenceV2(Candidate):
    """v2 -- **two or more distinct** discovery binaries from the **same parent process**
    within a short window.

    The tightening condition targets what actually distinguishes reconnaissance from
    routine troubleshooting: an attacker who has landed on a host runs a *sequence* of
    discovery commands from the *same* shell in quick succession (whoami, then net
    group, then nltest), because they are systematically mapping the environment. A
    help-desk technician runs `ipconfig /all`` once, from Explorer, in isolation. This
    condition -- diversity and shared parentage, not any single binary name -- is the
    generalizable signature, and it is the version promoted to a permanent rule (see
    ``ath.hunting.rules.discovery_rules.DiscoveryCommandSequence``).
    """

    candidate_id = "CAND-DISCOVERY-v2"
    version = "v2"
    title = "Sequence of discovery commands from one parent process"
    target_stage = "5-discovery"
    min_distinct_binaries = 2
    window = pd.Timedelta(minutes=5)
    rationale = (
        "Requiring >=2 DISTINCT discovery binaries sharing one parent process within a "
        "short window separates systematic reconnaissance from an admin running one "
        "tool once. This is the pattern real intrusion reports describe -- a sequence, "
        "not a single command -- rather than a name-based blocklist."
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        procs = telemetry.processes
        is_discovery = procs["process_name"].str.lower().isin(DISCOVERY_BINARIES)
        candidates = procs[is_discovery].copy()
        if candidates.empty:
            return []

        findings: list[Finding] = []
        for (_device, parent_pid), group in candidates.groupby(
            ["device", "parent_process_id"], dropna=False
        ):
            if pd.isna(parent_pid):
                continue
            group = group.sort_values("timestamp")
            span = group["timestamp"].max() - group["timestamp"].min()
            distinct = set(group["process_name"].str.lower())
            if len(distinct) < self.min_distinct_binaries or span > self.window:
                continue
            findings.append(_discovery_finding(
                tuple(group.itertuples()), self.candidate_id, self.title
            ))
        return findings


def _discovery_finding(rows, candidate_id: str, title: str) -> Finding:
    evidence = tuple(
        Evidence(
            event_id=r.event_id, timestamp=r.timestamp,
            summary=f"{r.parent_process_name} -> {r.process_name}: {truncate(r.command_line, 100)}",
        )
        for r in rows
    )
    device = rows[0].device
    user = rows[0].user
    binaries = sorted({r.process_name.lower() for r in rows})
    return Finding(
        rule_id=candidate_id, title=title, severity=Severity.MEDIUM,
        device=device, user=user, evidence=evidence,
        reason=f"Discovery-related command(s) observed: {', '.join(binaries)}.",
        fields_used=("process_name", "parent_process_id", "timestamp"),
        false_positives=("IT support running a single discovery command during "
                         "routine troubleshooting.",),
    )


ALL_CANDIDATES: tuple[type[Candidate], ...] = (
    OfficeMacroDocumentOpenedV1, OfficeMacroDocumentOpenedV2,
    DiscoveryCommandSequenceV1, DiscoveryCommandSequenceV2,
)
