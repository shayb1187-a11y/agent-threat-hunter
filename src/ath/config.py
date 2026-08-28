"""Project configuration: filesystem paths and environment variables.

Design rule: **no secret ever appears in source code.** API keys are read from the
process environment (optionally seeded from a local, git-ignored ``.env`` file).
`load_settings()` does not raise if a key is missing, because Milestones 1-4 are
fully deterministic and must run with zero credentials. The agent layer is the only
consumer that requires a key, and it asks for it explicitly.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

# Project root = two levels up from this file (src/ath/config.py -> src/ath -> src -> root)
PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]

DATA_DIR: Path = PROJECT_ROOT / "data"
RAW_DATA_DIR: Path = DATA_DIR / "raw"
QUERIES_DIR: Path = PROJECT_ROOT / "queries"
REPORTS_DIR: Path = PROJECT_ROOT / "reports"

# Declared here rather than in the agent layer so that configuration flows one way
# (config -> agent) and the default cannot drift between the two modules.
DEFAULT_MODEL: str = "claude-sonnet-5"


@dataclass(frozen=True)
class Settings:
    """Runtime settings resolved from the environment.

    Attributes:
        raw_data_dir: Directory holding the generated telemetry CSVs.
        reports_dir: Directory where investigation reports are written.
        llm_api_key: API key for the agent LLM. ``None`` when unset -- the
            deterministic pipeline works fine without it.
        llm_model: Model identifier used by the agent layer (Milestone 5).
        log_level: Root log level, e.g. "INFO" or "DEBUG".
    """

    raw_data_dir: Path = RAW_DATA_DIR
    reports_dir: Path = REPORTS_DIR
    llm_api_key: str | None = None
    llm_model: str = DEFAULT_MODEL
    log_level: str = "INFO"

    def require_llm_api_key(self) -> str:
        """Return the LLM API key, or explain clearly how to set it.

        Raises:
            RuntimeError: if no key is configured.
        """
        if not self.llm_api_key:
            raise RuntimeError(
                "No LLM API key configured. Copy .env.example to .env and set "
                "ATH_LLM_API_KEY=... (the .env file is git-ignored). "
                "Note: only the agent layer needs this; detections run without it."
            )
        return self.llm_api_key


def load_settings(env_file: Path | None = None) -> Settings:
    """Load settings from the environment, seeding from ``.env`` when present.

    Args:
        env_file: Optional explicit path to a dotenv file. Defaults to
            ``<project root>/.env``.

    Returns:
        A frozen :class:`Settings` instance.
    """
    dotenv_path = env_file or (PROJECT_ROOT / ".env")
    if dotenv_path.exists():
        # override=False: a real exported env var always beats the file.
        load_dotenv(dotenv_path, override=False)

    return Settings(
        raw_data_dir=Path(os.getenv("ATH_RAW_DATA_DIR", str(RAW_DATA_DIR))),
        reports_dir=Path(os.getenv("ATH_REPORTS_DIR", str(REPORTS_DIR))),
        llm_api_key=os.getenv("ATH_LLM_API_KEY") or None,
        llm_model=os.getenv("ATH_LLM_MODEL", DEFAULT_MODEL),
        log_level=os.getenv("ATH_LOG_LEVEL", "INFO"),
    )
