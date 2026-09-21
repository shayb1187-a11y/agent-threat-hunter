"""One declared experiment: the parameters a run reads and a freeze records.

Before this file existed the experiment was a filename convention plus notebook constants
plus CLI flags. A spec is the one place those live. It carries no commit id: the public
history is rewritten, so the checkout is identified by ``frozen_surface_sha256`` (what it
computes, see :mod:`ath.experiments.identity`) and optionally by a git *tree* id.

Every CLI flag still works without a spec; a spec supplies the defaults the flags would
otherwise take from the code, and its hash is stamped on run records and rows.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields, replace
from pathlib import Path
from typing import Any

from ath.experiments.identity import sha256_json
from ath.experiments.paths import ROOT

SPECS_DIR = ROOT / "experiments"


@dataclass(frozen=True)
class ExperimentSpec:
    name: str
    arm: str = "D1"
    models: tuple[str, ...] = ("qwen3.5:4b",)
    repeat: int = 1
    seed: int = 0
    temperature: float = 0.0
    think: bool = False
    base_url: str = "http://127.0.0.1:11434"
    expected_cases: int = 20
    smoke_cases: tuple[str, ...] = ()
    """Manifest keys (``corpus/case_id``) a smoke run is limited to."""
    frozen_surface_sha256: str = ""
    """What the checkout must compute (:func:`ath.experiments.identity.frozen_surface_sha256`)."""
    expected_tree: str = ""
    """Optional ``git rev-parse HEAD^{tree}`` when a whole-tree match is wanted."""
    external_root: str = "data/external"
    out_dir: str = "reports/local/dev"
    digest_version: int = 1
    workers: int = 1
    notes: tuple[str, ...] = field(default_factory=tuple)

    # -- paths ------------------------------------------------------------------------

    @property
    def out_path(self) -> Path:
        return _resolve(self.out_dir)

    @property
    def external_path(self) -> Path:
        return _resolve(self.external_root)

    # -- serialisation ----------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        for name in ("models", "smoke_cases", "notes"):
            payload[name] = list(payload[name])
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> ExperimentSpec:
        known = {f.name for f in fields(cls)}
        unknown = sorted(set(payload) - known)
        if unknown:
            raise ValueError(f"unknown spec field(s): {unknown}")
        values = dict(payload)
        for name in ("models", "smoke_cases", "notes"):
            if name in values:
                values[name] = tuple(values[name])
        return cls(**values)

    @classmethod
    def load(cls, path: Path) -> ExperimentSpec:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def save(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")
        return path

    def sha256(self) -> str:
        """The spec's identity: canonical JSON of every field."""
        return sha256_json(self.to_dict())

    def with_overrides(self, **changes: Any) -> ExperimentSpec:
        return replace(self, **{k: v for k, v in changes.items() if v is not None})


def _resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def find_spec(name_or_path: str) -> Path:
    """``experiments/<name>.json`` or a path given directly."""
    path = Path(name_or_path)
    if path.exists():
        return path
    candidate = SPECS_DIR / f"{name_or_path}.json"
    if candidate.exists():
        return candidate
    raise SystemExit(f"no spec at {path} or {candidate}")
