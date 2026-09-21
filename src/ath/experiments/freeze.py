"""Freeze the local environment for one model: ``ENVIRONMENT_<model>.json``."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ath.agent.ollama_llm import OllamaUnavailable, Sampling
from ath.evaluation.ablation import build_client
from ath.evaluation.ablation.local import available_ram_bytes, local_environment, refuse_frozen_path
from ath.experiments.local_arms import build_arm
from ath.experiments.manifest_build import read_manifest
from ath.experiments.paths import ROOT, Layout
from ath.experiments.runs import RUNNER_VERSION, now


def write_json(path: Path, payload: Any) -> Path:
    path = refuse_frozen_path(path, ROOT)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    return path


def write_text(path: Path, text: str) -> Path:
    path = refuse_frozen_path(path, ROOT)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")
    return path


def describe_or_refuse(client: Any) -> dict[str, Any]:
    try:
        return client.describe()
    except OllamaUnavailable as exc:
        raise SystemExit(f"REFUSED: {exc}") from exc


def freeze(
    *, out_dir: Path, arm_letter: str, model: str, sampling: Sampling,
    base_url: str, think: bool = False,
    log: Callable[[str], None] = lambda text: print(text, file=sys.stderr),
) -> Path:
    payload, entries, digest = read_manifest(out_dir)
    arm = build_arm(arm_letter, model, sampling, base_url=base_url, think=think)
    client = build_client(arm)
    described = describe_or_refuse(client)
    frozen = local_environment(
        ROOT, manifest_hash=digest, arm=arm, described=described,
        manifest_head=str(payload.get("head", "")), available_ram=available_ram_bytes(),
    )
    frozen["frozen_at"] = now()
    frozen["arm_letter"] = arm_letter
    frozen["runner_version"] = RUNNER_VERSION
    layout = Layout(Path(out_dir), arm_letter, model, digest)
    path = write_json(layout.environment_path, frozen)
    log(
        f"froze {model} (digest {str(described.get('digest'))[:12]}, daemon "
        f"{described.get('daemon_version')}) against manifest {digest[:12]} -> {path}"
    )
    return path


def read_environment(out_dir: Path, model: str) -> dict[str, Any]:
    path = Layout(Path(out_dir), "D1", model).environment_path
    if not path.exists():
        raise SystemExit(f"{path} does not exist; run `freeze --model {model}` first")
    return json.loads(path.read_text(encoding="utf-8"))
