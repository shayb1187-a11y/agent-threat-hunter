"""Shim: the dev-split manifest builder now lives in :mod:`ath.experiments.manifest_build`.

``python scripts/local_manifest.py build [...]`` forwards to
``ath-experiment manifest-build``. The names ``tests/test_contamination.py`` and
``scripts/local_replay.py`` import are re-exported here.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ath.experiments.bundles import DEFAULT_EXTERNAL  # noqa: E402,F401
from ath.experiments.cli import main as _main  # noqa: E402
from ath.experiments.manifest_build import (  # noqa: E402,F401
    FLAWS_CASES,
    FROZEN_MANIFESTS,
    MANIFEST_MD,
    MANIFEST_PATH,
    SYNTHETIC_DEV,
    contamination,
    dev_bundles,
    dev_injected_ids,
    frozen_entries,
    injected_dev_bundle,
    injected_labels,
    read_manifest,
    render_markdown,
    select_flaws,
    synthetic_dev_bundle,
)
from ath.experiments.paths import DEV_DIR  # noqa: E402,F401


def __getattr__(name: str):
    # The injected case ids and seed belong to the hash-pinned injector script; they are
    # read from it on first use rather than at import, which is what the package does.
    if name == "DEV_INJECTED_IDS":
        return dev_injected_ids()
    if name == "DEV_SEED":
        from ath.experiments.manifest_build import dev_seed

        return dev_seed()
    if name == "DEV_CASE_ROOT":
        from ath.experiments.manifest_build import dev_case_root

        return dev_case_root()
    raise AttributeError(name)


def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] == "build":
        argv = ["manifest-build", *argv[1:]]
    argv = ["--manifest-seed" if a == "--seed" else a for a in argv]
    return _main(argv)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
