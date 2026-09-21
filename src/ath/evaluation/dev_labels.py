"""The dev split's answer key for one injected case, resolved against a loaded corpus.

Lives under ``ath.evaluation`` because the label reader is the answer key: nothing that
detects or investigates may import it (``tests/test_external_labels.py`` enforces that),
and the experiment layer reaches labels only through this module.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ath.evaluation.external_labels import RESOLVED, load_external_labels, resolve_refs


def injected_labels(
    labels_path: Path, case_id: str, telemetry: Any, *, source: str | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """The label block and the resolved cross-domain links for one injected case.

    ``source`` is what each link records as where it came from; by default the labels
    file's own repository-relative path.
    """
    labels_path = Path(labels_path)
    payload = json.loads(labels_path.read_text(encoding="utf-8"))
    labels = load_external_labels(labels_path)
    if len(labels.scenarios) != 1:
        raise SystemExit(f"{case_id}: expected one scenario, got {len(labels.scenarios)}")
    scenario = labels.scenarios[0]
    refs = [side["ref"] for link in payload.get("links", ()) for side in (link["identity"], link["endpoint"])]
    resolved = resolve_refs(refs, telemetry)
    links: list[dict[str, Any]] = []
    for link in payload.get("links", ()):
        sides = {}
        for domain in ("identity", "endpoint"):
            match = resolved[link[domain]["ref"]]
            if match.status != RESOLVED:
                raise SystemExit(
                    f"{case_id}/{link['link_id']}: {domain} ref is {match.status} against this load"
                )
            sides[domain] = {"domain": domain, "ref": link[domain]["ref"], "event_id": match.event_id}
        links.append({
            "link_id": link["link_id"], "stage_transition": link["stage_transition"],
            "note": link.get("note", ""),
            "source": source or str(labels_path).replace("\\", "/"), **sides,
        })
    label_block = {
        "injected_case": case_id,
        "provenance": labels.provenance,
        "scenario": scenario.name,
        "verdict": "malicious" if scenario.malicious else "benign",
        "stages": [s.name for s in scenario.stages],
        "links": [link["link_id"] for link in links],
    }
    return label_block, links
