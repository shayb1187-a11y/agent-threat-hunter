"""Where an experiment's files live. The runner owns these; nothing else rebuilds them.

The formats are the ones the D1 v3 rows were written under and must not move while that
comparison is pending::

    <out_dir>/rows/<ARM>_<model_slug>/m<manifest12>_<prompt_version_slug>/<row>.json
    <out_dir>/rows/<ARM>_<model_slug>/m<manifest12>_<prompt_version_slug>.quarantine/
    <out_dir>/ENVIRONMENT_<model_slug>.json
    <out_dir>/SUMMARY_<ARM>_<model_slug>_rep<N>.{json,md}
    <out_dir>/COMPARE_<ARM>_<slug_a>_vs_<slug_b>_rep<N>.{json,md}
    <out_dir>/runs/RUN_<run_id>.json
    <out_dir>/VALIDATE_<ARM>_<model_slug>_<run_id>.json

A notebook or a shim asks a :class:`Layout` for a path; it never formats one.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ath.agent.investigator import D1_PROMPT_VERSION

ROOT = Path(__file__).resolve().parents[3]
DEV_DIR = ROOT / "reports" / "local" / "dev"
GUARD_EVENTS = "GUARD_EVENTS.jsonl"
"""One line per RAM-guard refusal or override, beside the rows. A refusal writes no row, so
without this file the summary could not say how often the guard fired."""


def model_slug(model: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in model)


def rows_dir(
    out_dir: Path, arm_letter: str, model: str, manifest_digest: str = "",
    version: str = D1_PROMPT_VERSION,
) -> Path:
    """Where rows go: one directory per (arm, model, manifest, investigator version).

    The 2026-09-15 preview rows sit in the flat ``rows/D1_<model>/`` directory; they are
    keyed on a superseded manifest and are never read by a summary of this one. A change
    of manifest or of investigator prompts starts an empty directory, so rows produced
    under different prompts can never be summarised together.
    """
    base = Path(out_dir) / "rows" / f"{arm_letter}_{model_slug(model)}"
    if not manifest_digest:
        return base
    return base / f"m{manifest_digest[:12]}_{model_slug(version)}"


def environment_path(out_dir: Path, model: str) -> Path:
    return Path(out_dir) / f"ENVIRONMENT_{model_slug(model)}.json"


@dataclass(frozen=True)
class Layout:
    """Every path of one (arm, model, manifest, prompt version) experiment."""

    out_dir: Path
    arm_letter: str
    model: str
    manifest_digest: str = ""
    prompt_version: str = D1_PROMPT_VERSION

    @property
    def rows_base(self) -> Path:
        return rows_dir(self.out_dir, self.arm_letter, self.model)

    @property
    def rows_dir(self) -> Path:
        return rows_dir(
            self.out_dir, self.arm_letter, self.model, self.manifest_digest, self.prompt_version,
        )

    @property
    def quarantine_dir(self) -> Path:
        directory = self.rows_dir
        return directory.with_name(directory.name + ".quarantine")

    @property
    def guard_events_path(self) -> Path:
        return self.rows_dir / GUARD_EVENTS

    @property
    def environment_path(self) -> Path:
        return environment_path(self.out_dir, self.model)

    @property
    def runs_dir(self) -> Path:
        return Path(self.out_dir) / "runs"

    def run_record_path(self, run_id: str) -> Path:
        return self.runs_dir / f"RUN_{run_id}.json"

    def validate_report_path(self, run_id: str) -> Path:
        return Path(self.out_dir) / f"VALIDATE_{self.arm_letter}_{model_slug(self.model)}_{run_id}.json"

    def summary_stem(self, repeat: int) -> str:
        return f"SUMMARY_{self.arm_letter}_{model_slug(self.model)}_rep{repeat}"

    def summary_json(self, repeat: int) -> Path:
        return Path(self.out_dir) / f"{self.summary_stem(repeat)}.json"

    def summary_md(self, repeat: int) -> Path:
        return Path(self.out_dir) / f"{self.summary_stem(repeat)}.md"

    def compare_stem(self, model_b: str, repeat: int) -> str:
        return (
            f"COMPARE_{self.arm_letter}_{model_slug(self.model)}_vs_{model_slug(model_b)}"
            f"_rep{repeat}"
        )

    def compare_json(self, model_b: str, repeat: int) -> Path:
        return Path(self.out_dir) / f"{self.compare_stem(model_b, repeat)}.json"

    def compare_md(self, model_b: str, repeat: int) -> Path:
        return Path(self.out_dir) / f"{self.compare_stem(model_b, repeat)}.md"

    def sibling_row_dirs(self) -> list[tuple[Path, int]]:
        """Other row directories under this model's base, with their row counts.

        The 2026-09-18 Colab session summarised zero rows while twenty sat beside the
        target directory under another manifest; this is what a summary must look at
        before it reports ``rows_written 0``.
        """
        base = self.rows_base
        if not base.is_dir():
            return []
        target = self.rows_dir
        out: list[tuple[Path, int]] = []
        if base != target:
            # rows written flat under the base, before the manifest sub-directory existed
            flat = sum(1 for _ in base.glob("*.json"))
            if flat:
                out.append((base, flat))
        for candidate in sorted(p for p in base.iterdir() if p.is_dir()):
            if candidate == target or candidate.name.endswith(".quarantine"):
                continue
            count = sum(1 for _ in candidate.glob("*.json"))
            if count:
                out.append((candidate, count))
        return out

    def to_dict(self) -> dict[str, Any]:
        def rel(path: Path) -> str:
            try:
                return str(path.relative_to(ROOT)).replace("\\", "/")
            except ValueError:
                return str(path)

        return {
            "out_dir": rel(Path(self.out_dir)),
            "arm": self.arm_letter,
            "model": self.model,
            "model_slug": model_slug(self.model),
            "manifest_hash": self.manifest_digest,
            "prompt_version": self.prompt_version,
            "rows_dir": rel(self.rows_dir),
            "quarantine_dir": rel(self.quarantine_dir),
            "environment": rel(self.environment_path),
            "guard_events": rel(self.guard_events_path),
            "runs_dir": rel(self.runs_dir),
            "summary_json": rel(self.summary_json(1)),
            "summary_md": rel(self.summary_md(1)),
        }
