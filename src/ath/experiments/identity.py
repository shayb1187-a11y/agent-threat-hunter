"""What a checkout must reproduce before its rows can join a comparison.

Two views of the same rule.

``frozen_surface()`` is the *value* view: the hashes and dicts that every gate in the
experiment layer reads (investigator prompts and bounds, the local client's frozen
configuration, the toolbox surface, the orchestrator prompts, the scoring files, the
committed manifests, the row-key format). ``frozen_surface_sha256()`` folds them into one
digest that a spec file records and ``preflight`` recomputes, so a checkout is identified
by what it would compute, never by a commit id -- the public history is rewritten, so one
tree carries two ids.

``frozen_sources()`` is the *source* view: the files and the individual functions and
classes that must not be edited while the D1 v3 comparison is pending, hashed byte for
byte (newline-normalised). Editing one is a decision to re-freeze, taken in the open.

Regenerate the committed fixtures after such a decision with::

    python -m ath.experiments.identity --write

"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "tests" / "fixtures"
IDENTITY_FIXTURE = FIXTURES / "frozen_identity.json"
SOURCES_FIXTURE = FIXTURES / "frozen_sources.json"

COMMITTED_MANIFESTS = (
    "reports/local/dev/MANIFEST.json",
    "reports/m19/ablation/MANIFEST.json",
    "reports/m19b/MANIFEST.json",
)

FROZEN_FILES = (
    "src/ath/evaluation/ablation/arms.py",
    "src/ath/evaluation/ablation/scoring.py",
    "src/ath/evaluation/incidents.py",
    "scripts/m19b_inject_dedale.py",
    "scripts/local_inject_dedale.py",
    "reports/local/dev/MANIFEST.json",
    "reports/m19/ablation/MANIFEST.json",
    "reports/m19b/MANIFEST.json",
    "reports/m19b/ablation/ENVIRONMENT.json",
    "notebooks/ath_d1_model_comparison_colab.ipynb",
)


def _normalise(text: str) -> str:
    return text.replace("\r\n", "\n")


def sha256_text(text: str) -> str:
    return hashlib.sha256(_normalise(text).encode("utf-8")).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_text(path.read_text(encoding="utf-8"))


def canonical_json(payload: Any) -> str:
    """The one serialisation anything in this package hashes: sorted keys, no spaces."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def sha256_json(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


# -- value view -------------------------------------------------------------------------


def frozen_surface() -> dict[str, Any]:
    """Every value a gate reads, computed live. Deterministic and daemon-free."""
    from ath.agent.investigator import RESPONSE_SCHEMA
    from ath.agent.ollama_llm import OllamaLLM
    from ath.evaluation.ablation.environment import (
        prompt_hashes,
        scoring_hashes,
        tool_surface,
    )
    from ath.evaluation.ablation.local import RowKey, investigator_environment
    from ath.evaluation.ablation.manifest import load_manifest, manifest_hash

    manifests: dict[str, dict[str, str]] = {}
    for relative in COMMITTED_MANIFESTS:
        payload = json.loads((ROOT / relative).read_text(encoding="utf-8"))
        manifests[relative] = {
            "recorded": payload["manifest_hash"],
            "recomputed": manifest_hash(load_manifest(payload)),
        }

    probe_key = RowKey(
        corpus="corpus:probe", case_id="CASE-000", arm="D1_local_single",
        provider="ollama", model="qwen3.5:4b", quantization="Q4_K_M",
        repeat=1, seed=0, manifest_hash="0123456789abcdef" * 4,
    )
    return {
        "investigator_environment": investigator_environment(),
        "ollama_client_configuration": {
            "default": OllamaLLM("qwen3.5:4b").configuration(),
            "d1_schema": OllamaLLM("qwen3.5:4b", format=RESPONSE_SCHEMA).configuration(),
        },
        "tool_surface": tool_surface(),
        "orchestrator_prompts": prompt_hashes(),
        "scoring_files": scoring_hashes(),
        "manifests": manifests,
        "row_key": {"filename": probe_key.filename, "digest": probe_key.digest},
    }


def frozen_surface_sha256(surface: dict[str, Any] | None = None) -> str:
    """One digest over :func:`frozen_surface`; what a spec records as its identity."""
    return sha256_json(surface if surface is not None else frozen_surface())


# -- source view ------------------------------------------------------------------------


def _frozen_objects() -> dict[str, Any]:
    from ath.agent import ollama_llm
    from ath.evaluation.ablation import local, manifest

    return {
        "ollama_llm.OllamaLLM.configuration": ollama_llm.OllamaLLM.configuration,
        "local.RowKey": local.RowKey,
        "local.write_row": local.write_row,
        "local.read_row": local.read_row,
        "local.investigator_environment": local.investigator_environment,
        # The v1 digest bodies. CaseManifest.to_dict is pinned by *output* instead (the
        # committed manifests recompute in frozen_surface): it gained a conditional
        # digest_version key that a v1 entry never emits.
        "manifest.table_digest": manifest.table_digest,
        "manifest.telemetry_hash": manifest.telemetry_hash,
        "manifest.manifest_hash": manifest.manifest_hash,
    }


def frozen_sources() -> dict[str, str]:
    """Files and objects that must not change, hashed. Keys are stable names."""
    sources = {relative: sha256_path(ROOT / relative) for relative in FROZEN_FILES}
    for name, obj in _frozen_objects().items():
        sources[f"object:{name}"] = sha256_text(inspect.getsource(obj))
    return sources


# -- fixtures ---------------------------------------------------------------------------


def write_fixtures() -> None:
    surface = frozen_surface()
    IDENTITY_FIXTURE.write_text(
        json.dumps(
            {"frozen_surface_sha256": frozen_surface_sha256(surface), "surface": surface},
            indent=2, sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )
    SOURCES_FIXTURE.write_text(
        json.dumps(frozen_sources(), indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", action="store_true", help="rewrite the committed fixtures")
    args = parser.parse_args(argv)
    if args.write:
        write_fixtures()
        print(f"wrote {IDENTITY_FIXTURE.relative_to(ROOT)} and {SOURCES_FIXTURE.relative_to(ROOT)}")
        return 0
    print(json.dumps(
        {"frozen_surface_sha256": frozen_surface_sha256(), "sources": frozen_sources()},
        indent=2, sort_keys=True,
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
