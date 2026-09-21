"""Shim: the paired model comparison now lives in :mod:`ath.experiments.compare`.

``python scripts/local_compare.py --arm D1 --models A B [--repeat 1]`` forwards to
``ath-experiment compare``; the names ``tests/test_local_compare.py`` imports are
re-exported here.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ath.experiments.cli import main as _main  # noqa: E402
from ath.experiments.compare import (  # noqa: E402,F401
    DIMENSIONS,
    NotComparable,
    _aggregate,
    _order,
    assert_comparable,
    compare,
    load_rows,
    pair_rows,
    render,
    row_facts,
)


def main(argv=None) -> int:
    return _main(["compare", *(sys.argv[1:] if argv is None else list(argv))])


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
