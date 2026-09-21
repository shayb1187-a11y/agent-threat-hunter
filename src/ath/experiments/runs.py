"""One record per runner invocation, so a row can be traced to what wrote it.

A row already ties itself to a manifest, a model digest, a daemon version, a client
configuration and the investigator's prompt hashes. What it could not say before this
file: which invocation wrote it, with which flags, on which GPU, under which Python,
alongside which other rows, and what that invocation refused or quarantined. The record
is written when the run starts (status ``running``) and rewritten when it ends, so a
kill leaves a record that says so.

Rows are listed by file *and* by ``RowKey.digest``: the slugged filename can collide,
the digest cannot.
"""

from __future__ import annotations

import platform
import subprocess
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ath.evaluation.ablation.environment import git_state, package_versions
from ath.evaluation.ablation.local import gpu_summary, refuse_frozen_path
from ath.experiments.identity import frozen_surface_sha256
from ath.experiments.paths import ROOT, Layout

RUNNER_VERSION = "experiments-1"
"""Bumped when the runner changes what it records. Informational, never gated."""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def git_tree(root: Path = ROOT) -> str:
    """The tree id: identical across the private and the rewritten public history."""
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=root,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:  # noqa: BLE001 -- a missing git is recorded, not fatal
        return "unknown"


def runtime_record() -> dict[str, Any]:
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "executable": Path(sys.executable).name,
        "packages": package_versions(),
    }


@dataclass
class RunRecord:
    run_id: str
    subcommand: str
    argv: list[str]
    started_at: str
    layout: dict[str, Any]
    status: str = "running"
    ended_at: str | None = None
    exit_code: int | None = None
    spec_name: str | None = None
    spec_sha256: str | None = None
    runner_version: str = RUNNER_VERSION
    git: dict[str, Any] = field(default_factory=dict)
    frozen_surface_sha256: str = ""
    runtime: dict[str, Any] = field(default_factory=dict)
    gpu: list[dict[str, Any]] | None = None
    daemon_version: str | None = None
    model: dict[str, Any] = field(default_factory=dict)
    manifest_hash: str = ""
    prompt_version: str = ""
    workers: int = 1
    counts: dict[str, int] = field(default_factory=dict)
    rows_written: list[dict[str, str]] = field(default_factory=list)
    rows_skipped: list[dict[str, str]] = field(default_factory=list)
    quarantined: list[dict[str, Any]] = field(default_factory=list)
    guard_events: int = 0
    notes: list[str] = field(default_factory=list)
    path: Path | None = field(default=None, repr=False, compare=False)

    # -- lifecycle ----------------------------------------------------------------------

    @classmethod
    def start(
        cls, layout: Layout, subcommand: str, *, argv: list[str] | None = None,
        spec: Any = None, model: dict[str, Any] | None = None, daemon_version: str | None = None,
        workers: int = 1, write: bool = True,
    ) -> RunRecord:
        record = cls(
            run_id=uuid.uuid4().hex,
            subcommand=subcommand,
            argv=list(sys.argv[1:] if argv is None else argv),
            started_at=now(),
            layout=layout.to_dict(),
            spec_name=getattr(spec, "name", None),
            spec_sha256=spec.sha256() if spec is not None else None,
            git={**git_state(ROOT), "tree": git_tree(ROOT)},
            frozen_surface_sha256=frozen_surface_sha256(),
            runtime=runtime_record(),
            gpu=gpu_summary(),
            daemon_version=daemon_version,
            model=dict(model or {}),
            manifest_hash=layout.manifest_digest,
            prompt_version=layout.prompt_version,
            workers=workers,
        )
        if write:
            record.path = layout.run_record_path(record.run_id)
            record.write()
        return record

    def header_stamp(self, worker_index: int = 0) -> dict[str, Any]:
        """What each row's header carries under ``runner``: recorded, never gated."""
        return {
            "run_id": self.run_id,
            "version": self.runner_version,
            "spec_sha256": self.spec_sha256,
            "workers": self.workers,
            "worker_index": worker_index,
            "gpu": self.gpu,
        }

    def add_row(self, filename: str, key_digest: str, *, skipped: bool = False) -> None:
        target = self.rows_skipped if skipped else self.rows_written
        target.append({"file": filename, "key_digest": key_digest})

    def add_quarantine(self, filename: str, key_digest: str, reasons: list[str], target: str) -> None:
        self.quarantined.append(
            {"file": filename, "key_digest": key_digest, "reasons": list(reasons), "moved_to": target}
        )

    def note(self, text: str) -> None:
        self.notes.append(text)

    def finish(self, exit_code: int, counts: dict[str, int] | None = None) -> RunRecord:
        self.ended_at = now()
        self.exit_code = exit_code
        self.status = {0: "done", 3: "interrupted", 130: "interrupted"}.get(exit_code, "refused")
        if counts:
            self.counts = dict(counts)
        self.write()
        return self

    # -- serialisation ----------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("path", None)
        return payload

    def write(self) -> None:
        if self.path is None:
            return
        import json

        path = refuse_frozen_path(Path(self.path), ROOT)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, default=str) + "\n", encoding="utf-8")
