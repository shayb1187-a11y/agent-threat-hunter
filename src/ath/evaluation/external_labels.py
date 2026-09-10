"""Ground truth for telemetry this project did not generate.

Why labels live in native ids, not ``event_id``
-------------------------------------------------
The synthetic generator hands out ``event_id`` and writes ``ground_truth.json`` in the
same breath, so its labels can name events directly. An external dataset cannot: ATH
mints ``event_id`` at load time, in whatever order the adapter happens to read files,
and a label file that named ``cloudtrail-logon-004656`` would silently point at a
different record the moment a file was added, removed or re-sorted. So an external label
names the record the way its *publisher* does -- CloudTrail's ``eventID``, a Kubernetes
``auditID``, Winlogbeat's ``host.name`` + ``winlog.record_id`` -- and this module
resolves those through the ``source_ref`` column every adapter already writes.

Labels are read here and nowhere else
--------------------------------------
This module is in ``ath.evaluation`` for the same reason ``load_ground_truth`` is: an
evaluation harness that cannot see the answer key is not an evaluation harness, and a
detection or adapter that *can* is grading its own homework. No adapter imports this
module. The label file format is deliberately separate from anything an adapter reads,
so a dataset that ships labels *inside* its records (K8NTEXT's ``label`` key, DEDALE's
verbatim-copy jsonl) has to be translated into this shape by hand or by a script that
lives beside the dataset, never by the ingestion path.

What cannot be resolved is a measurement
-----------------------------------------
A labelled record the adapter dropped -- an unmapped ``eventName``, a Sysmon event id
with no canonical table -- resolves to nothing. That is not an error to hide: it is the
count of labelled attack activity ATH never ingested, and it belongs in the evaluation
table beside recall, which would otherwise be computed over a denominator that quietly
excluded everything the system cannot see.

Label file shape::

    {
      "dataset": "flaws_cloud",
      "provenance": "real",                 # real | real+injected | emulated-testbed | synthetic
      "scenarios": {
        "role-enumeration": {
          "malicious": true,
          "note": "...",
          "stages": {
            "1-enumerate": {"note": "...", "refs": ["eventID=abc", "eventID=def"]}
          }
        },
        "owner-admin": {"malicious": false, "stages": {...}}
      }
    }

A ``ref`` is one or more ``key=value`` pairs joined by ``;``. It matches a row when every
pair appears in that row's ``source_ref`` (which adapters write as ``key=value;key=value``).
Extra pairs on the row are fine; extra pairs on the ref are not. A ref that matches more
than one row is reported as ambiguous rather than silently expanded.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ath.evaluation.incidents import Incident
from ath.telemetry.loader import Telemetry

PROVENANCES: tuple[str, ...] = ("real", "real+injected", "emulated-testbed", "synthetic")


@dataclass(frozen=True)
class LabelledStage:
    name: str
    refs: tuple[str, ...]
    note: str = ""


@dataclass(frozen=True)
class LabelledScenario:
    name: str
    malicious: bool
    stages: tuple[LabelledStage, ...]
    note: str = ""

    @property
    def refs(self) -> tuple[str, ...]:
        return tuple(ref for stage in self.stages for ref in stage.refs)


@dataclass(frozen=True)
class ExternalLabels:
    dataset: str
    provenance: str
    scenarios: tuple[LabelledScenario, ...]

    @property
    def malicious_scenarios(self) -> tuple[LabelledScenario, ...]:
        return tuple(s for s in self.scenarios if s.malicious)


def load_external_labels(path: Path) -> ExternalLabels:
    """Read and validate a label file. Fails loudly: a malformed answer key is a bug."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    provenance = str(payload.get("provenance", ""))
    if provenance not in PROVENANCES:
        raise ValueError(
            f"{path}: provenance must be one of {PROVENANCES}, got {provenance!r}; "
            "the evaluation table reports it verbatim, so it cannot be left vague"
        )
    scenarios: list[LabelledScenario] = []
    for name, spec in (payload.get("scenarios") or {}).items():
        if "malicious" not in spec:
            raise ValueError(
                f"{path}: scenario {name!r} does not say whether it is malicious; "
                "a benign look-alike counted as an attack is the measurement bug "
                "this field exists to prevent"
            )
        stages = tuple(
            LabelledStage(
                name=stage_name,
                refs=tuple(str(r) for r in (stage.get("refs") or [])),
                note=str(stage.get("note", "")),
            )
            for stage_name, stage in (spec.get("stages") or {}).items()
        )
        scenarios.append(LabelledScenario(
            name=name, malicious=bool(spec["malicious"]), stages=stages,
            note=str(spec.get("note", "")),
        ))
    return ExternalLabels(
        dataset=str(payload.get("dataset", path.stem)),
        provenance=provenance,
        scenarios=tuple(scenarios),
    )


@dataclass
class ResolvedLabels:
    """Native refs turned into ``event_id`` sets, plus what could not be turned."""

    labels: ExternalLabels
    event_ids_by_scenario: dict[str, frozenset[str]] = field(default_factory=dict)
    unresolved: dict[str, tuple[str, ...]] = field(default_factory=dict)
    """Refs per scenario that matched no ingested row -- labelled activity ATH never saw."""
    ambiguous: dict[str, tuple[str, ...]] = field(default_factory=dict)
    """Refs per scenario that matched more than one row; excluded rather than guessed."""

    @property
    def malicious_event_ids(self) -> frozenset[str]:
        ids: set[str] = set()
        for scenario in self.labels.malicious_scenarios:
            ids |= self.event_ids_by_scenario.get(scenario.name, frozenset())
        return frozenset(ids)

    @property
    def total_refs(self) -> int:
        return sum(len(s.refs) for s in self.labels.scenarios)

    @property
    def resolved_refs(self) -> int:
        return self.total_refs - sum(len(v) for v in self.unresolved.values()) - sum(
            len(v) for v in self.ambiguous.values()
        )

    @property
    def malicious_refs_total(self) -> int:
        return sum(len(s.refs) for s in self.labels.malicious_scenarios)

    @property
    def malicious_refs_unresolved(self) -> int:
        return sum(
            len(self.unresolved.get(s.name, ())) for s in self.labels.malicious_scenarios
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset": self.labels.dataset,
            "provenance": self.labels.provenance,
            "refs_total": self.total_refs,
            "refs_resolved": self.resolved_refs,
            "malicious_refs_total": self.malicious_refs_total,
            "malicious_refs_unresolved": self.malicious_refs_unresolved,
            "unresolved": {k: list(v) for k, v in self.unresolved.items() if v},
            "ambiguous": {k: list(v) for k, v in self.ambiguous.items() if v},
        }


def _pairs(ref: str) -> frozenset[str]:
    return frozenset(part.strip() for part in ref.split(";") if part.strip())


def resolve_labels(labels: ExternalLabels, telemetry: Telemetry) -> ResolvedLabels:
    """Map every ref to the ``event_id`` rows whose ``source_ref`` carries all its pairs."""
    by_pair: dict[str, set[str]] = defaultdict(set)
    for table in (telemetry.processes, telemetry.network, telemetry.logons, telemetry.controls):
        if table.empty:
            continue
        for event_id, source_ref in zip(table["event_id"], table["source_ref"]):
            for pair in _pairs(str(source_ref)):
                by_pair[pair].add(str(event_id))

    resolved = ResolvedLabels(labels=labels)
    for scenario in labels.scenarios:
        ids: set[str] = set()
        missing: list[str] = []
        multiple: list[str] = []
        for ref in scenario.refs:
            pairs = _pairs(ref)
            if not pairs:
                missing.append(ref)
                continue
            candidates: set[str] | None = None
            for pair in pairs:
                hits = by_pair.get(pair, set())
                candidates = set(hits) if candidates is None else candidates & hits
                if not candidates:
                    break
            if not candidates:
                missing.append(ref)
            elif len(candidates) > 1:
                multiple.append(ref)
            else:
                ids |= candidates
        resolved.event_ids_by_scenario[scenario.name] = frozenset(ids)
        resolved.unresolved[scenario.name] = tuple(missing)
        resolved.ambiguous[scenario.name] = tuple(multiple)
    return resolved


def incident_from_labels(
    resolved: ResolvedLabels,
    telemetry: Telemetry,
    *,
    incident_id: str,
    name: str,
    description: str,
    expected_techniques: frozenset[str] = frozenset(),
    must_conclude: tuple[str, ...] = (),
    never_as_fact: tuple[str, ...] = (),
) -> Incident:
    """An :class:`Incident` whose answer key is the resolved malicious label set.

    Only *resolved* ids go into ``malicious_event_ids``, so ``event_recall`` measures
    recall over what ATH ingested. The evaluation table must print
    ``malicious_refs_unresolved`` beside it; a recall figure without that count would
    be flattering in exactly the way this project refuses to be.
    """
    return Incident(
        incident_id=incident_id,
        name=name,
        description=description,
        telemetry=telemetry,
        malicious_event_ids=resolved.malicious_event_ids,
        expected_techniques=expected_techniques,
        must_conclude=must_conclude,
        never_as_fact=never_as_fact,
    )
