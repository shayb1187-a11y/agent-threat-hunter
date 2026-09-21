"""Restored rows against the live freeze and manifest, with the reason written down.

``run`` skips any parseable row by path alone, so a row copied in from another session
must pass this before it may stand in for a case. A row that fails is *moved* to the
sibling ``<rows_dir>.quarantine/`` directory, never deleted and never overwritten there,
and a ``<row>.reason.json`` is written beside it saying why -- the reasons used to be
printed to stdout and lost.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from ath.agent.investigator import D1_PROMPT_VERSION
from ath.evaluation.ablation import CaseManifest
from ath.evaluation.ablation.local import (
    RowKey,
    investigator_environment,
    read_row,
    refuse_frozen_path,
)
from ath.experiments.freeze import read_environment, write_json
from ath.experiments.manifest_build import read_manifest
from ath.experiments.paths import ROOT, Layout
from ath.experiments.runs import RunRecord, now

UNGATED_CLIENT_FIELDS = frozenset({"base_url", "timeout_seconds_per_attempt", "max_attempts", "backoff_seconds"})


def gated_configuration_view(configuration: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in configuration.items() if k not in UNGATED_CLIENT_FIELDS}


def row_provenance_problems(
    payload: dict[str, Any], *, model: str, manifest_digest: str, entries: Sequence[CaseManifest],
    frozen: dict[str, Any],
) -> list[str]:
    """Why this row is not a row of the experiment the live freeze and manifest describe.

    Empty when it is. Every check reads what the row recorded when it was written --
    the key, the header's model digest, daemon version, gated client configuration,
    prompt version and investigator hashes -- against what the freeze and the manifest
    say now. ``header.runner`` (run id, GPU, workers) is informational and never gated.
    """
    key = payload["key"]
    row = payload["row"]
    header = payload.get("header") or {}
    by_key = {(e.corpus, e.case_id): e for e in entries}
    problems: list[str] = []
    entry = by_key.get((key.get("corpus"), key.get("case_id")))
    if entry is None:
        problems.append("case not in the manifest")
    elif row.get("telemetry_hash") != entry.telemetry_hash:
        problems.append("telemetry hash differs from the one the manifest pins for this case")
    if key.get("model") != model:
        problems.append(f"model {key.get('model')!r} is not {model!r}")
    if row.get("manifest_hash") != manifest_digest or key.get("manifest_hash") not in (manifest_digest, ""):
        problems.append("manifest hash differs from the live manifest")
    if header.get("prompt_version") != D1_PROMPT_VERSION:
        problems.append(f"prompt version {header.get('prompt_version')!r} is not {D1_PROMPT_VERSION!r}")
    if dict(header.get("investigator") or {}) != investigator_environment():
        problems.append("investigator prompt/schema/bounds hashes differ from the live code")
    local = frozen.get("local") or {}
    frozen_model = local.get("model") or {}
    row_model = header.get("model") or {}
    if row_model.get("digest") != frozen_model.get("digest"):
        problems.append("model digest differs from the freeze (different weights)")
    if header.get("daemon_version") != (local.get("daemon") or {}).get("version"):
        problems.append("daemon version differs from the freeze")
    frozen_conf = gated_configuration_view(local.get("client_configuration") or {})
    row_conf = gated_configuration_view(header.get("client_configuration") or {})
    for name in sorted(set(frozen_conf) | set(row_conf)):
        if frozen_conf.get(name) != row_conf.get(name):
            problems.append(f"client configuration {name}: row {row_conf.get(name)!r}, freeze {frozen_conf.get(name)!r}")
    return problems


def _key_digest(payload: dict[str, Any]) -> str:
    try:
        return RowKey(**payload["key"]).digest
    except Exception:  # noqa: BLE001 -- a malformed key is still a row to report
        return ""


def validate_rows(
    directory: Path, *, model: str, manifest_digest: str, entries: Sequence[CaseManifest],
    frozen: dict[str, Any], quarantine: bool = False, record: RunRecord | None = None,
    prompt_version: str = D1_PROMPT_VERSION,
) -> dict[str, Any]:
    """Every row file under ``directory``: valid, or the reasons it is not.

    With ``quarantine``, a failing row is moved to ``<rows_dir>.quarantine/`` and a
    ``<stem>.reason.json`` is written beside it.
    """
    directory = Path(directory)
    report: dict[str, Any] = {
        "directory": str(directory), "valid": [], "invalid": {}, "unreadable": [],
        "quarantined": [], "run_id": record.run_id if record is not None else None,
    }
    if not directory.is_dir():
        return report
    quarantine_dir = directory.with_name(directory.name + ".quarantine")
    for path in sorted(directory.glob("*.json")):
        payload = read_row(path)
        if payload is None:
            report["unreadable"].append(path.name)
            continue
        problems = row_provenance_problems(payload, model=model, manifest_digest=manifest_digest, entries=entries, frozen=frozen)
        if not problems:
            report["valid"].append(path.name)
            continue
        report["invalid"][path.name] = problems
        if quarantine:
            refuse_frozen_path(quarantine_dir, ROOT).mkdir(parents=True, exist_ok=True)
            target = quarantine_dir / path.name
            if target.exists():
                target = quarantine_dir / f"{path.stem}.{int(time.time())}{path.suffix}"
            path.replace(target)
            reason = {
                "moved_at": now(),
                "run_id": report["run_id"],
                "from": path.name,
                "key_digest": _key_digest(payload),
                "problems": problems,
                "manifest_hash_expected": manifest_digest,
                "manifest_hash_found": (payload.get("row") or {}).get("manifest_hash"),
                "prompt_version_expected": prompt_version,
                "prompt_version_found": (payload.get("header") or {}).get("prompt_version"),
            }
            target.with_name(target.stem + ".reason.json").write_text(
                json.dumps(reason, indent=2, default=str) + "\n", encoding="utf-8",
            )
            relative = str(target.relative_to(directory.parent))
            report["quarantined"].append(relative)
            if record is not None:
                record.add_quarantine(path.name, reason["key_digest"], problems, relative)
    return report


def validate(
    *, out_dir: Path, arm_letter: str, model: str, quarantine: bool = False,
    spec: Any = None, argv: list[str] | None = None,
    log: Callable[[str], None] = lambda text: print(text, file=sys.stderr),
) -> int:
    payload, entries, digest = read_manifest(out_dir)
    frozen = read_environment(out_dir, model)
    layout = Layout(Path(out_dir), arm_letter, model, digest)
    record = RunRecord.start(layout, "validate-rows", argv=argv, spec=spec)
    report = validate_rows(
        layout.rows_dir, model=model, manifest_digest=digest, entries=entries, frozen=frozen,
        quarantine=quarantine, record=record,
    )
    invalid = len(report["invalid"])
    write_json(layout.validate_report_path(record.run_id), report)
    print(json.dumps(report, indent=1))
    log(
        f"{len(report['valid'])} valid row(s), {invalid} invalid, {len(report['unreadable'])} unreadable, "
        f"{len(report['quarantined'])} quarantined under {layout.rows_dir}"
    )
    exit_code = 0 if (invalid == 0 or quarantine) else 1
    record.finish(exit_code, {
        "valid": len(report["valid"]), "invalid": invalid,
        "unreadable": len(report["unreadable"]), "quarantined": len(report["quarantined"]),
    })
    return exit_code
