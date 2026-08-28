"""Centralised logging configuration.

Threat hunting is an evidence discipline: if you cannot explain *how* a conclusion
was reached, the conclusion is worthless. Logging is the cheapest form of that audit
trail, and it becomes essential once the agent starts making tool calls.
"""

from __future__ import annotations

import logging
import sys

_CONFIGURED = False

LOG_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)-24s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(level: str = "INFO") -> None:
    """Configure root logging once, writing to stderr.

    Args:
        level: Log level name, e.g. ``"INFO"`` or ``"DEBUG"``.
    """
    global _CONFIGURED
    if _CONFIGURED:
        logging.getLogger().setLevel(level.upper())
        return

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a module-scoped logger."""
    return logging.getLogger(name)
