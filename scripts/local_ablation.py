"""Shim: the V1 local runner now lives in :mod:`ath.experiments`.

Kept so the pinned comparison notebook and the existing tests keep working until the
pending D1 v3 comparison is published; every name they used is re-exported and the
command line forwards to ``ath-experiment`` unchanged::

    python scripts/local_ablation.py freeze    --model qwen3.5:4b
    python scripts/local_ablation.py run       --model qwen3.5:4b --arm D1 [--repeat 1 --seed 0]
    python scripts/local_ablation.py summarise --model qwen3.5:4b --arm D1
    python scripts/local_ablation.py validate-rows --model qwen3.5:4b [--quarantine]
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ath.evaluation.ablation.local import GIB, investigator_environment  # noqa: E402,F401
from ath.experiments.cli import main as _main  # noqa: E402
from ath.experiments.local_arms import ARM_LETTERS, build_arm  # noqa: E402,F401
from ath.experiments.manifest_build import head as _head  # noqa: E402,F401
from ath.experiments.manifest_build import links_by_case  # noqa: E402,F401
from ath.experiments.paths import (  # noqa: E402,F401
    DEV_DIR,
    GUARD_EVENTS,
    environment_path,
    model_slug,
    rows_dir,
)
from ath.experiments.runner import (  # noqa: E402,F401
    Interrupted,  # noqa: E402,F401
    guard_events,
    record_guard_event,
    run_rows,
)
from ath.experiments.runner import classify_calls as _classify_calls  # noqa: E402,F401
from ath.experiments.summarise import (  # noqa: E402,F401
    COMPLETION_TARGET,
    CORRECTNESS_FLOOR,
    INVESTIGATION_FIELDS,
    _median,
    _p95,
    investigation_metrics,
    links_are_scorable,
    render_summary,
    row_summary,
    select_rows,
    summarise,
)
from ath.experiments.validate import row_provenance_problems, validate_rows  # noqa: E402,F401


def main() -> int:
    return _main(sys.argv[1:])


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
