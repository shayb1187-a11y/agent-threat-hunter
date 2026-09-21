"""Everything a run needs answered before its first row, as one report.

The notebook used to re-derive the RAM guard's arithmetic, print a string literal about
what the client sends, and warn about a CPU-only runtime and then run anyway. Each of
those is now a check here, computed by the same code the runner uses, with a status of
``ok``, ``warn``, ``fail`` or ``skip`` and the numbers it was decided on. A ``fail``
makes the command exit non-zero; the notebook stops before a row is written.

Checks, in order: the checkout's frozen surface against the spec; the dev manifest; the
daemon and the model; the freeze against the live world; the GPU; the model's residency;
the RAM guard; the telemetry cache; and what rows already exist for this identity.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ath.agent.ollama_llm import OllamaLLM, OllamaUnavailable, Sampling
from ath.evaluation.ablation.local import (
    GIB,
    available_ram_bytes,
    check_local_environment,
    check_ram,
    gpu_summary,
    ram_floor_for,
)
from ath.experiments.freeze import write_json
from ath.experiments.identity import frozen_surface_sha256
from ath.experiments.paths import ROOT, Layout
from ath.experiments.runs import RunRecord, git_tree

CACHED_SUBDIRS = ("flaws_cloud", "dedale")
RESIDENCY_WARN_BELOW = 0.95


@dataclass
class Check:
    name: str
    status: str
    detail: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "status": self.status, "detail": self.detail, "data": self.data}


def warm_up(model: str, base_url: str, timeout: float = 600.0) -> None:
    """Load the model and keep it resident, so the guard sees it before the first row."""
    request = urllib.request.Request(
        base_url.rstrip("/") + "/api/generate",
        data=json.dumps({"model": model, "keep_alive": -1}).encode("utf-8"),
        headers={"content-type": "application/json"},
    )
    urllib.request.urlopen(request, timeout=timeout).read()


def _check_checkout(spec: Any) -> Check:
    if spec is None or not getattr(spec, "frozen_surface_sha256", ""):
        return Check("checkout", "skip", "no spec, or the spec records no frozen surface")
    live = frozen_surface_sha256()
    data = {"expected": spec.frozen_surface_sha256, "live": live}
    if live != spec.frozen_surface_sha256:
        return Check("checkout", "fail", "the checkout computes a different frozen surface than the spec records", data)
    if spec.expected_tree:
        tree = git_tree()
        data["tree"] = tree
        if tree != spec.expected_tree:
            return Check("checkout", "fail", f"git tree {tree[:12]} is not the spec's {spec.expected_tree[:12]}", data)
    return Check("checkout", "ok", "frozen surface matches the spec", data)


def _check_manifest(out_dir: Path) -> tuple[Check, str, list[Any]]:
    from ath.experiments.manifest_build import read_manifest

    try:
        payload, entries, digest = read_manifest(out_dir)
    except SystemExit as exc:
        return Check("manifest", "fail", str(exc)), "", []
    return Check(
        "manifest", "ok", f"{len(entries)} cases, hash {digest[:12]}, built at {payload.get('head')}",
        {"manifest_hash": digest, "cases": len(entries), "head": payload.get("head")},
    ), digest, entries


def _check_daemon(client: OllamaLLM) -> tuple[Check, dict[str, Any]]:
    try:
        described = client.describe()
    except OllamaUnavailable as exc:
        return Check("daemon", "fail", str(exc)), {}
    return Check(
        "daemon", "ok",
        f"ollama {described.get('daemon_version')} at {client.base_url}; {client.model} "
        f"{described.get('parameter_size')} {described.get('quantization_level')} digest "
        f"{str(described.get('digest'))[:12]}",
        {k: described.get(k) for k in ("daemon_version", "digest", "parameter_size", "quantization_level", "model_context_length")},
    ), described


def _check_freeze(layout: Layout, digest: str, described: dict[str, Any]) -> Check:
    path = layout.environment_path
    if not path.exists():
        return Check("freeze", "warn", f"{path.name} does not exist yet; run freeze before run")
    frozen = json.loads(path.read_text(encoding="utf-8"))
    if not described:
        return Check("freeze", "skip", "no daemon answer to compare the freeze against")
    drift = check_local_environment(frozen, manifest_hash=digest, described=described)
    if drift:
        return Check("freeze", "fail", "the live world differs from the freeze", {"drift": drift})
    return Check("freeze", "ok", f"{path.name} matches the daemon, the model and the manifest")


def _check_gpu(allow_cpu: bool) -> Check:
    gpus = gpu_summary()
    if gpus:
        names = ", ".join(f"{g['name']} ({g['memory_total_mib']} MiB)" for g in gpus)
        return Check("gpu", "ok", names, {"gpus": gpus})
    status = "warn" if allow_cpu else "fail"
    return Check("gpu", status, "no NVIDIA GPU reported; wall times would not be comparable with a GPU run", {"gpus": []})


def _check_residency(client: OllamaLLM) -> Check:
    residency = client.residency()
    size, vram = residency.get("size"), residency.get("size_vram")
    if not size:
        return Check("residency", "warn", f"{client.model} is not loaded; pass --warm-up or the first row pays the load", residency)
    ratio = (vram or 0) / size
    detail = f"{size / GIB:.2f} GiB resident, {ratio:.0%} in VRAM"
    if ratio < RESIDENCY_WARN_BELOW:
        return Check("residency", "warn", detail + "; not fully on the GPU", {**residency, "vram_ratio": round(ratio, 3)})
    return Check("residency", "ok", detail, {**residency, "vram_ratio": round(ratio, 3)})


def _check_ram(client: OllamaLLM, described: dict[str, Any]) -> Check:
    floor = ram_floor_for(described.get("parameter_size")) if described else None
    available = available_ram_bytes()
    resident = client.resident_bytes()
    verdict = check_ram(floor, available, resident)
    data = verdict.to_dict()
    if verdict.ok is False:
        return Check("ram", "fail", verdict.message + "; free memory rather than overriding the guard", data)
    if verdict.ok is None:
        return Check("ram", "skip", verdict.message, data)
    return Check("ram", "ok", verdict.message, data)


def _check_cache(external: Path, verify: bool) -> Check:
    external = Path(external)
    missing = [s for s in CACHED_SUBDIRS if not (external / s).is_dir() or not any((external / s).iterdir())]
    if missing:
        return Check("telemetry", "fail", f"missing under {external}: {missing}; fetch or restore the cache", {"missing": missing})
    if not verify:
        return Check("telemetry", "ok", f"{', '.join(CACHED_SUBDIRS)} present under {external} (not hashed; pass --verify-cache)")
    import subprocess

    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "fetch_external.py"), "--verify-only", "flaws_cloud"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if completed.returncode != 0:
        return Check("telemetry", "fail", "fetch_external --verify-only failed", {"stderr": completed.stderr[-2000:]})
    return Check("telemetry", "ok", "flaws_cloud verified against data/external/MANIFEST.json")


def _check_rows(layout: Layout) -> Check:
    existing = sum(1 for _ in layout.rows_dir.glob("*.json")) if layout.rows_dir.is_dir() else 0
    siblings = [{"path": p.name, "rows": n} for p, n in layout.sibling_row_dirs()]
    quarantined = sum(1 for _ in layout.quarantine_dir.glob("*.json")) if layout.quarantine_dir.is_dir() else 0
    detail = f"{existing} row(s) under {layout.rows_dir.name}"
    if siblings:
        detail += "; other row sets beside it: " + ", ".join(f"{s['path']} ({s['rows']})" for s in siblings)
    return Check("rows", "ok" if not siblings or existing else "warn", detail,
                 {"existing": existing, "siblings": siblings, "quarantined": quarantined})


def preflight(
    *,
    out_dir: Path,
    arm_letter: str,
    model: str,
    base_url: str,
    external: Path,
    spec: Any = None,
    allow_cpu: bool = False,
    verify_cache: bool = False,
    do_warm_up: bool = False,
    argv: list[str] | None = None,
    log: Callable[[str], None] = lambda text: print(text, file=sys.stderr),
) -> tuple[dict[str, Any], int]:
    checks: list[Check] = [_check_checkout(spec)]
    manifest_check, digest, _entries = _check_manifest(out_dir)
    checks.append(manifest_check)
    layout = Layout(Path(out_dir), arm_letter, model, digest)
    client = OllamaLLM(model, base_url=base_url, sampling=Sampling(0.0, 0))
    daemon_check, described = _check_daemon(client)
    checks.append(daemon_check)
    if described and do_warm_up:
        warm_up(model, base_url)
    checks.append(_check_freeze(layout, digest, described))
    checks.append(_check_gpu(allow_cpu))
    if described:
        checks.append(_check_residency(client))
        checks.append(_check_ram(client, described))
    checks.append(_check_cache(external, verify_cache))
    checks.append(_check_rows(layout))

    failed = [c.name for c in checks if c.status == "fail"]
    report = {
        "model": model, "arm": arm_letter, "base_url": base_url,
        "manifest_hash": digest, "layout": layout.to_dict(),
        "checks": [c.to_dict() for c in checks], "failed": failed,
        "ok": not failed,
    }
    for check in checks:
        log(f"{check.status:4s} {check.name:10s} {check.detail}")
    exit_code = 0 if not failed else 1
    if digest:
        record = RunRecord.start(layout, "preflight", argv=argv, spec=spec,
                                 daemon_version=described.get("daemon_version") if described else None)
        report["run_id"] = record.run_id
        write_json(layout.out_dir / f"PREFLIGHT_{layout.arm_letter}_{layout.to_dict()['model_slug']}_{record.run_id}.json", report)
        record.finish(exit_code, {"checks": len(checks), "failed": len(failed)})
    return report, exit_code
