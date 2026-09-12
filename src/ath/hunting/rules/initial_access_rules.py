"""Detections targeting the Initial Access stage of an intrusion.

Provenance
----------
ATH-009 did not start as a hand-written rule. It began as a proposal from the
detection-engineering harness (``ath.engineering.candidates.OfficeMacroDocumentOpenedV1``),
was measured against this project's own telemetry, found to be far too broad, tightened
once, re-measured, and promoted. That history is preserved rather than hidden -- see
``docs/detection-engineering.md`` for the full walk-through and the exact numbers.
"""

from __future__ import annotations

import re

import pandas as pd

from ath.hunting.base import Detector, register
from ath.hunting.finding import Evidence, Finding, Severity
from ath.hunting.indicators import truncate
from ath.schema import EVENT_PROCESS
from ath.telemetry.loader import Telemetry

# Extensions that can structurally contain an Office macro. This is a fact about the
# Office Open XML container format, not a threshold fitted to any particular dataset --
# a plain .docx literally cannot carry VBA content regardless of what its bytes say.
MACRO_EXTENSIONS: tuple[str, ...] = (".docm", ".dotm", ".xlsm", ".xlsb", ".pptm", ".ppsm")

_MACRO_PATTERN = re.compile(
    "|".join(re.escape(ext) for ext in MACRO_EXTENSIONS), re.IGNORECASE
)

OFFICE_APPS: frozenset[str] = frozenset(
    {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
)


@register
class OfficeMacroAttachmentOpened(Detector):
    """ATH-009 -- A macro-capable Office document was opened via an email client.

    Attacker behaviour
    ------------------
    This rule fires one step *earlier* in the kill chain than ATH-001 (Office spawning
    an interpreter): it catches the attachment being opened at all, independent of
    whether the embedded macro subsequently executes. That matters for two reasons.
    First, it gives visibility into initial access even when the macro fails to run
    (blocked by policy, a stale exploit, user declining "Enable Content") -- cases
    ATH-001 is structurally blind to. Second, it is the earliest point at which the
    intrusion could have been interrupted, which is operationally the most valuable
    place to have a detection.

    Why the macro-extension check, specifically
    ---------------------------------------------
    Attachments opened via email are extremely common and entirely benign the vast
    majority of the time -- alerting on "Outlook opened Word" alone would be one of the
    highest-volume, lowest-value rules imaginable. The one condition that is both
    necessary for this attack technique and rare in ordinary use is the file format:
    only ``.docm``/``.dotm``/``.xlsm``/``.xlsb``/``.pptm``/``.ppsm`` can carry a macro at
    all. A plain ``.docx`` is not "probably safe" here; it is *structurally incapable*
    of delivering this technique, which is a stronger and more durable basis for a rule
    than a volume threshold or a reputation score.

    History
    -------
    This rule was proposed as a v1/v2 pair by the detection-engineering harness. v1
    (any Office app opened by Outlook, no extension check) scored 0.03 precision on
    this project's own telemetry -- 29 false positives, every one of them an ordinary
    ``Notes.docx`` opened by a real employee, against a single true positive. Adding the
    extension check alone brought precision to 1.00 with no loss of recall. See
    ``ath.engineering.candidates`` for the exact classes and
    ``docs/detection-engineering.md`` for the measured numbers.
    """

    rule_id = "ATH-009"
    title = "Macro-enabled document opened via email client"
    severity = Severity.MEDIUM
    description = "Detects Outlook opening an Office document in a macro-capable format."
    fields_used = ("parent_process_name", "process_name", "command_line", "device", "user")
    tables = frozenset({EVENT_PROCESS})
    false_positives = (
        "Legitimate business documents that happen to be distributed in a macro-capable "
        "format (e.g. .xlsm templates used for shared calculations) without containing "
        "an actively malicious macro.",
        "Internal mail-merge or reporting workflows that routinely email .xlsm/.docm "
        "files to staff.",
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        procs = telemetry.processes
        if procs.empty:
            return []

        mask = (
            procs["parent_process_name"].str.lower() == "outlook.exe"
        ) & procs["process_name"].str.lower().isin(OFFICE_APPS)
        candidates = procs[mask]
        if candidates.empty:
            return []

        is_macro = candidates["command_line"].apply(
            lambda cmd: bool(_MACRO_PATTERN.search(cmd or ""))
        )
        hits = candidates[is_macro]

        findings: list[Finding] = []
        for _, row in hits.iterrows():
            evidence = (
                Evidence(
                    event_id=row["event_id"], timestamp=row["timestamp"],
                    summary=(
                        f"OUTLOOK.EXE opened {row['process_name']}: "
                        f"{truncate(row['command_line'], 150)}"
                    ),
                ),
            )
            findings.append(self.make_finding(
                device=row["device"], user=row["user"], evidence=evidence,
                reason=(
                    f"Outlook launched {row['process_name']} to open a document in a "
                    "macro-capable format. This is consistent with a malicious "
                    "attachment being opened, independent of whether any embedded "
                    "macro subsequently ran."
                ),
                metadata={
                    "process": row["process_name"],
                    "command_line": row["command_line"],
                },
            ))
        return findings
