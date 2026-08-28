"""Convenience entry point: `python main.py <command>`.

Equivalent to the installed `ath` console script, but works without installing.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running straight from a checkout without `pip install -e .`
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from ath.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
