"""Data model for correlated attack chains.

An :class:`InvestigationCase` is a set of findings that deterministic evidence says
belong to the same operation, plus the *reasons* they were linked. The reasons are
first-class: a case that says "these nine findings are related" without saying why is
indistinguishable from a guess, and cannot be argued with in a review.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ath.hunting.finding import Finding, Severity
from ath.mitre.attack import AttackMapping


@dataclass(frozen=True)
class FindingLink:
    """A justified relationship between two findings.

    Attributes:
        left_id: :attr:`Finding.finding_id` of the earlier finding.
        right_id: :attr:`Finding.finding_id` of the later finding.
        score: Total weight of the signals supporting the link.
        signals: Human-readable signal names, each with its weight.
        structural: Whether at least one *structural* signal was present. Structural
            signals describe a concrete relationship in the data (shared event, shared
            process, parent/child, host-to-host movement, auth-then-execute) as opposed
            to circumstantial ones (same host, close in time). A link with no structural
            signal is refused -- see :mod:`ath.correlation.correlator`.
    """

    left_id: str
    right_id: str
    score: int
    signals: tuple[str, ...]
    structural: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "left_id": self.left_id,
            "right_id": self.right_id,
            "score": self.score,
            "signals": list(self.signals),
            "structural": self.structural,
        }

    def __str__(self) -> str:
        return f"{self.left_id} -> {self.right_id} (score {self.score}: {', '.join(self.signals)})"


@dataclass(frozen=True)
class TimelineEntry:
    """One row of a case timeline, traceable to raw telemetry."""

    timestamp: datetime
    rule_id: str
    severity: Severity
    title: str
    device: str
    user: str
    source_device: str | None
    target_devices: tuple[str, ...]
    techniques: tuple[str, ...]
    event_ids: tuple[str, ...]

    @property
    def movement(self) -> str | None:
        """``"PC01 -> FS02"`` when this finding represents host-to-host movement."""
        if self.source_device and self.target_devices:
            return f"{self.source_device} -> {', '.join(self.target_devices)}"
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "device": self.device,
            "user": self.user,
            "movement": self.movement,
            "techniques": list(self.techniques),
            "event_ids": list(self.event_ids),
        }


@dataclass
class InvestigationCase:
    """A group of findings deterministically linked into a possible attack chain.

    Nothing here is generated or inferred by a language model. Every field is computed
    from findings, their evidence, and telemetry relationships.

    Attributes:
        case_id: Stable identifier, e.g. ``"CASE-001"``.
        findings: Member findings, chronological.
        links: The justified relationships that formed the case.
        mappings: ATT&CK interpretations of the member findings.
    """

    case_id: str
    findings: tuple[Finding, ...]
    links: tuple[FindingLink, ...] = ()
    mappings: tuple[AttackMapping, ...] = ()

    # -- derived properties ---------------------------------------------------------

    @property
    def start_time(self) -> datetime:
        return min(f.first_seen for f in self.findings)

    @property
    def end_time(self) -> datetime:
        return max(f.last_seen for f in self.findings)

    @property
    def duration_seconds(self) -> int:
        return int((self.end_time - self.start_time).total_seconds())

    @property
    def devices(self) -> tuple[str, ...]:
        """Every host involved, including hosts referenced only as a movement source."""
        hosts: set[str] = set()
        for finding in self.findings:
            hosts.add(finding.device)
            source = finding.metadata.get("source_device")
            if source:
                hosts.add(str(source))
            hosts.update(str(d) for d in finding.metadata.get("target_devices", []) or [])
        return tuple(sorted(hosts))

    @property
    def users(self) -> tuple[str, ...]:
        return tuple(sorted({f.user for f in self.findings}))

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(sorted({f.rule_id for f in self.findings}))

    @property
    def event_ids(self) -> tuple[str, ...]:
        """Every telemetry event underpinning the case, deduplicated and sorted."""
        return tuple(sorted({eid for f in self.findings for eid in f.event_ids}))

    @property
    def severity(self) -> Severity:
        """The case inherits its highest member severity."""
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    @property
    def techniques(self) -> tuple[str, ...]:
        return tuple(sorted({m.technique_id for m in self.mappings}))

    @property
    def tactics(self) -> tuple[str, ...]:
        """Distinct tactics in ATT&CK kill-chain order."""
        from ath.mitre.mapper import tactics_covered

        return tuple(tactics_covered(self.mappings))

    @property
    def is_multi_host(self) -> bool:
        return len(self.devices) > 1

    @property
    def is_singleton(self) -> bool:
        """A case built from one finding that linked to nothing else.

        Kept explicit because a single-finding case is a genuinely different object
        from a chain: there is no grouping to trust or distrust, and the word "case"
        should not quietly imply corroboration that was never found.
        """
        return len(self.findings) == 1

    @property
    def confidence(self) -> str:
        """How strongly the *grouping* is supported -- not how malicious it is.

        Driven by tactic breadth and structural linkage, because a chain that spans
        several adversary goals and is joined by concrete data relationships is far
        harder to explain away than two findings that merely share a hostname.

        A singleton is always ``low``: nothing was corroborated, so there is no
        grouping to be confident about. Letting tactic breadth alone push a lone
        finding to ``medium`` would let one rule's own ATT&CK mappings masquerade as
        independent agreement.
        """
        if self.is_singleton:
            return "low"
        structural_links = sum(1 for link in self.links if link.structural)
        if len(self.tactics) >= 4 and structural_links >= 3:
            return "high"
        if len(self.tactics) >= 2 and structural_links >= 1:
            return "medium"
        return "low"

    def timeline(self) -> list[TimelineEntry]:
        """The case as an ordered, evidence-backed timeline."""
        by_finding: dict[str, list[AttackMapping]] = {}
        for mapping in self.mappings:
            by_finding.setdefault(mapping.rule_id, []).append(mapping)

        entries: list[TimelineEntry] = []
        for finding in sorted(self.findings, key=lambda f: (f.first_seen, f.rule_id)):
            techniques = tuple(
                sorted(
                    {
                        m.technique_id
                        for m in self.mappings
                        if m.rule_id == finding.rule_id
                        and set(m.evidence_ids) == set(finding.event_ids)
                    }
                )
            )
            source = finding.metadata.get("source_device")
            entries.append(
                TimelineEntry(
                    timestamp=finding.first_seen,
                    rule_id=finding.rule_id,
                    severity=finding.severity,
                    title=finding.title,
                    device=finding.device,
                    user=finding.user,
                    source_device=str(source) if source else None,
                    target_devices=tuple(
                        str(d) for d in finding.metadata.get("target_devices", []) or []
                    ),
                    techniques=techniques,
                    event_ids=finding.event_ids,
                )
            )
        return entries

    def explain(self) -> str:
        """A deterministic, template-generated summary of why this case exists.

        Deliberately mechanical prose assembled from measured facts. It is not a
        narrative and does not speculate about intent -- that is what the (not yet
        built) AI investigation layer is for, and keeping the deterministic summary
        obviously template-shaped makes the boundary between the two visible.
        """
        if self.is_singleton:
            finding = self.findings[0]
            parts = [
                f"{self.case_id}: a single {finding.severity} finding "
                f"({finding.rule_id}) on {finding.device}/{finding.user} at "
                f"{self.start_time.strftime('%H:%M:%S')} that correlated with no other "
                "activity. It is raised for investigation on its own severity, not "
                "because a chain was found -- nothing here corroborates it."
            ]
        else:
            parts = [
                f"{self.case_id}: {len(self.findings)} findings correlated across "
                f"{len(self.devices)} host(s) ({', '.join(self.devices)}) and "
                f"{len(self.users)} account(s) ({', '.join(self.users)}) over "
                f"{self.duration_seconds}s "
                f"({self.start_time.strftime('%H:%M:%S')}-"
                f"{self.end_time.strftime('%H:%M:%S')})."
            ]
        if self.tactics:
            parts.append(
                f"Behaviour is consistent with {len(self.tactics)} ATT&CK tactic(s): "
                f"{' -> '.join(self.tactics)}."
            )
        structural = [link for link in self.links if link.structural]
        if structural:
            parts.append(
                f"{len(structural)} of {len(self.links)} links rest on structural "
                "evidence (shared events, process lineage, or host-to-host movement) "
                "rather than timing alone."
            )
        parts.append(
            f"Grouping confidence: {self.confidence}. "
            f"Backed by {len(self.event_ids)} telemetry events. "
            "This is a correlation of observed behaviour and requires analyst "
            "confirmation; it does not establish that an intrusion occurred."
        )
        return " ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": self.duration_seconds,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "devices": list(self.devices),
            "users": list(self.users),
            "rule_ids": list(self.rule_ids),
            "techniques": list(self.techniques),
            "tactics": list(self.tactics),
            "event_ids": list(self.event_ids),
            "explanation": self.explain(),
            "timeline": [e.to_dict() for e in self.timeline()],
            "links": [link.to_dict() for link in self.links],
            "findings": [f.to_dict() for f in self.findings],
        }

    def __str__(self) -> str:
        return (
            f"{self.case_id} [{self.severity}] {len(self.findings)} findings, "
            f"{len(self.devices)} host(s), confidence={self.confidence}"
        )
