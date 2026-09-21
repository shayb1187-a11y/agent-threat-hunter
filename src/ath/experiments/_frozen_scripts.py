"""Load a hash-pinned script from ``scripts/`` without copying it.

Two scripts have their sha256 recorded inside committed case manifests
(``scripts/m19b_inject_dedale.py`` in ``reports/m19b/cases/dedale_injected/MANIFEST.json``
and ``scripts/local_inject_dedale.py`` in ``reports/local/dev/cases/dedale_injected/``).
Moving their code into the package would change those hashes and with them the
provenance of every injected case. So the package imports them *by path*, once, and
records the hash it saw. Nothing else in ``scripts/`` is loaded this way: the runner's
own helpers were copied into :mod:`ath.experiments.bundles` and are pinned by a parity
test instead.
"""

from __future__ import annotations

import hashlib
import importlib
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"

_loaded: dict[str, ModuleType] = {}


def load(name: str) -> ModuleType:
    """``scripts/<name>.py`` as a module, imported once."""
    if name not in _loaded:
        if str(SCRIPTS) not in sys.path:
            sys.path.insert(0, str(SCRIPTS))
        _loaded[name] = importlib.import_module(name)
    return _loaded[name]


def sha256(name: str) -> str:
    """The script's digest, newline-normalised: the same rule the case manifests use."""
    text = (SCRIPTS / f"{name}.py").read_text(encoding="utf-8").replace("\r\n", "\n")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
