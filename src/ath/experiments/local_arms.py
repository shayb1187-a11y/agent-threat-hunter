"""The local arms by letter, and how a run builds one."""

from __future__ import annotations

from typing import Any

from ath.agent.ollama_llm import Sampling
from ath.evaluation.ablation.local import ARM_D1, LOCAL_ARM_BUILDERS

ARM_LETTERS: dict[str, str] = {"D1": ARM_D1}


def build_arm(letter: str, model: str, sampling: Sampling, **client_kwargs: Any):
    try:
        builder = LOCAL_ARM_BUILDERS[ARM_LETTERS[letter]]
    except KeyError as exc:
        raise SystemExit(f"unknown local arm {letter!r}; known: {sorted(ARM_LETTERS)}") from exc
    return builder(model, sampling=sampling, **client_kwargs)
