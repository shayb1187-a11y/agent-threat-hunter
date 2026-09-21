"""``python -m ath.experiments ...`` -- the same CLI as the ``ath-experiment`` script."""

from __future__ import annotations

import sys

from ath.experiments.cli import main

if __name__ == "__main__":
    sys.exit(main())
