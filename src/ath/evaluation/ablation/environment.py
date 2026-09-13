"""Everything that could differ between the arms other than the reasoning architecture.

Why this file exists
---------------------
An ablation's claim is "these two arms differed in one thing". Nothing in a results file
can support that claim after the fact: the prompts, the model id, the request parameters,
the tool surface, the budgets, the scoring code and the library versions are all outside
the rows, and all of them can move between the day arm B runs and the day arm C does.
The only moment at which they can be pinned is *before the first arm runs*, which is what
:func:`capture_environment` does and what ``m19_ablation.py freeze`` writes to
``reports/m19/ablation/ENVIRONMENT.json``.

Everything here is read from the code that will actually run, never copied:
``ANTHROPIC_VERSION`` and the endpoint come from :mod:`ath.agent.llm`, the output budgets
from :mod:`ath.agent.orchestrator`, the retry policy from the client's own signature, the
tool surface from :class:`~ath.agent.tools.ToolBox` itself. A frozen value that was typed
into this file by hand would record what somebody believed, and the whole point is to
record what is.

The freeze is also a gate
--------------------------
:func:`check_environment` compares a recorded environment against the live one and
returns the differences. A real run of a model arm refuses to start while that list is
non-empty, so a prompt edited between the freeze and the run stops the run instead of
silently becoming a difference between arms.

Two deliberate holes in the commit check, both narrower than they sound:

* **Committing the freeze moves HEAD.** A file that records the commit cannot also be
  committed at that commit. So a HEAD that differs from the frozen commit is accepted
  *only* when every path changed between them lives under ``reports/`` -- which is the
  freeze file itself, and the results. One changed line of code, test or script and the
  run is refused.
* **A dirty tree is refused on its own terms.** Uncommitted changes outside ``reports/``
  fail the gate whatever the commit says, because a matching commit id says nothing
  about a file that was edited and not committed.

What is never recorded
-----------------------
The API key. :data:`CREDENTIAL_VARIABLE` names the variable and the file records whether
it was set -- never its value, not truncated, not hashed, not "the first four
characters". A credential in an experiment artifact is a credential in the repository.
"""

from __future__ import annotations

import hashlib
import inspect
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

from ath.agent import llm as llm_module
from ath.agent import orchestrator as orchestrator_module
from ath.agent.tools import ToolBox
from ath.evaluation.ablation import arms as arms_module
from ath.evaluation.ablation import scoring as scoring_module

RESULTS_PREFIX = "reports/"
"""Where results live. A change confined to it is not a change to the experiment."""

DATA_PREFIX = "data/"
"""Raw corpora, which are not in the repository and whose presence varies by machine."""

CRLF = "\r\n"
"""Line endings only: see :func:`git_state`."""

ENVIRONMENT_JSON = "ENVIRONMENT.json"
ENVIRONMENT_MD = "ENVIRONMENT.md"

CREDENTIAL_VARIABLE = "ATH_LLM_API_KEY"
"""The environment variable the key is read from. Presence is recorded; value never is."""

RECORDED_PACKAGES: tuple[str, ...] = ("pandas", "numpy", "pyarrow", "python-dotenv")
"""Libraries whose version can change a number. Detection, correlation and scoring all
run on pandas; parquet reading on pyarrow; the key is loaded by python-dotenv."""

GATED_FIELDS: tuple[str, ...] = (
    "commit", "prompts", "scoring", "manifest_hash", "arm_models",
)
"""What must match between the freeze and a model arm's run.

Not everything in the file is a gate. The Python version and the library versions are
recorded because they explain a result; the commit, the prompt hashes, the scoring code
and the manifest are *inputs to the comparison itself*, and a run under different ones is
not the experiment that was frozen.
"""


def sha256_text(text: str) -> str:
    """The hash written into the freeze. Newlines normalised, so a checkout that
    rewrites line endings does not read as an edited prompt."""
    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_text(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------------------
# The pieces
# --------------------------------------------------------------------------------------


def git_state(root: Path) -> dict[str, Any]:
    """Commit, branch and whether the tree was dirty. Never fails the freeze.

    ``dirty`` is recorded rather than refused: a freeze taken on a dirty tree is still
    worth having, as long as the file says so. What a reader must never have to guess is
    whether the commit named is the whole story.
    """

    def _run(*args: str) -> str:
        try:
            # Only line endings are stripped: ``git status --porcelain`` puts the
            # status code in the first two columns, so a bare .strip() eats the leading
            # space of the first line and with it the first character of its path.
            return subprocess.run(
                ["git", *args], cwd=root, capture_output=True, text=True, check=True,
            ).stdout.strip(CRLF)
        except Exception:  # noqa: BLE001 -- a missing git is not a reason to lose this
            return "unknown"

    status = _run("status", "--porcelain")
    return {
        "commit": _run("rev-parse", "HEAD"),
        "short_commit": _run("rev-parse", "--short", "HEAD"),
        "branch": _run("rev-parse", "--abbrev-ref", "HEAD"),
        "dirty": bool(status) if status != "unknown" else None,
        "dirty_paths": sorted(
            line[2:].strip() for line in status.splitlines()
        ) if status and status != "unknown" else [],
    }


def changed_paths_since(root: Path, commit: str) -> list[str] | None:
    """Paths changed between ``commit`` and HEAD, or ``None`` when git cannot say."""
    if not commit or commit == "unknown":
        return None
    try:
        completed = subprocess.run(
            ["git", "diff", "--name-only", commit, "HEAD"],
            cwd=root, capture_output=True, text=True, check=True,
        )
    except Exception:  # noqa: BLE001 -- an unanswerable question is not a clean answer
        return None
    return sorted(
        line.strip() for line in completed.stdout.splitlines() if line.strip()
    )


def prompt_hashes() -> dict[str, str]:
    """The four strings a model in this system ever reads, hashed.

    Two system prompts and two user-message templates. The templates were extracted from
    the orchestrator's own formatting code for exactly this: a prompt that cannot be
    named cannot be frozen, and a prompt that is not frozen is a free variable between
    the arms.
    """
    return {
        "planner_system": sha256_text(orchestrator_module.PLANNER_SYSTEM),
        "synthesis_system": sha256_text(orchestrator_module.SYNTHESIS_SYSTEM),
        "planner_user_template": sha256_text(orchestrator_module.PLANNER_USER_TEMPLATE),
        "synthesis_user_template": sha256_text(
            orchestrator_module.SYNTHESIS_USER_TEMPLATE
        ),
    }


def scoring_hashes() -> dict[str, str]:
    """The code that turns a run into numbers, hashed file by file."""
    return {
        "scoring.py": sha256_file(Path(scoring_module.__file__)),
        "arms.py": sha256_file(Path(arms_module.__file__)),
    }


def _default_of(function: Callable[..., Any], name: str) -> Any:
    parameter = inspect.signature(function).parameters.get(name)
    if parameter is None or parameter.default is inspect.Parameter.empty:
        return None
    return parameter.default


def request_configuration() -> dict[str, Any]:
    """Exactly what one call sends, read from the client that will send it."""
    return {
        "endpoint": llm_module.API_ENDPOINT,
        "anthropic_version_header": llm_module.ANTHROPIC_VERSION,
        "thinking": dict(llm_module.ADAPTIVE_THINKING),
        "effort": (
            "provider default (high); output_config is not sent"
        ),
        "max_tokens": {
            "planner": orchestrator_module.PLANNER_MAX_TOKENS,
            "synthesis": orchestrator_module.SYNTHESIS_MAX_TOKENS,
        },
        "sampling_parameters": (
            "none sent; temperature, top_p and top_k are rejected with a 400 by the "
            "models this experiment runs"
        ),
        "body_fields": ["model", "max_tokens", "system", "messages", "thinking"],
        "transport": "urllib (stdlib); no SDK, by project choice",
    }


def retry_policy() -> dict[str, Any]:
    """Timeout, attempts and backoff, read from the client's own defaults."""
    return {
        "timeout_seconds_per_attempt": llm_module.REQUEST_TIMEOUT_SECONDS,
        "max_attempts": _default_of(llm_module.AnthropicLLM.__init__, "max_attempts"),
        "backoff_seconds": _default_of(
            llm_module.AnthropicLLM.__init__, "backoff_seconds"
        ),
        "backoff": "exponential: backoff_seconds * 2**attempt",
        "retryable_statuses": sorted(llm_module._RETRYABLE_STATUS),
        "note": (
            "a non-retryable status (400/401/403/404) fails immediately; a truncated or "
            "textless reply is not retried either -- it is returned as an error so the "
            "row degrades rather than spending the budget again on the same cap"
        ),
    }


def tool_surface() -> list[str]:
    """Every tool the toolbox exposes, as ``name(signature)``.

    A tool is a public :class:`~ath.agent.tools.ToolBox` method that names the agent
    calling it -- an ``agent`` parameter with a default. That is the convention the
    toolbox already uses to attribute a call, and it separates the tools from the
    bookkeeping (``calls_by`` takes an agent but has no default and serves no evidence).
    """
    surface: list[str] = []
    for name, member in sorted(vars(ToolBox).items()):
        if name.startswith("_") or not inspect.isfunction(member):
            continue
        agent = inspect.signature(member).parameters.get("agent")
        if agent is None or agent.default is inspect.Parameter.empty:
            continue
        surface.append(f"{name}{inspect.signature(member)}")
    return surface


def package_versions() -> dict[str, str]:
    """Versions of the libraries that can move a number, or ``"absent"``."""
    try:
        from importlib import metadata
    except ImportError:  # pragma: no cover -- Python < 3.8 is not supported anyway
        return {name: "unknown" for name in RECORDED_PACKAGES}
    versions: dict[str, str] = {}
    for name in RECORDED_PACKAGES:
        try:
            versions[name] = metadata.version(name)
        except Exception:  # noqa: BLE001 -- an absent package is a fact, not a failure
            versions[name] = "absent"
    return versions


def arm_environment(arm: Any) -> dict[str, Any]:
    """One arm's pinned model, budgets and tool surface."""
    return {
        "name": arm.name,
        "model": arm.model,
        "requires_model": arm.requires_model,
        "generalist": arm.generalist,
        "use_llm_planner": arm.config.use_llm_planner,
        "use_llm_synthesis": arm.config.use_llm_synthesis,
        "max_steps": arm.config.max_steps,
        "tool_call_cap": arm.tool_call_cap,
        "tool_surface": tool_surface(),
    }


# --------------------------------------------------------------------------------------
# The whole record
# --------------------------------------------------------------------------------------


def capture_environment(
    root: Path,
    *,
    manifest_hash: str,
    manifest_head: str = "",
    arm_configs: Sequence[Any] | None = None,
    credential_present: bool = False,
) -> dict[str, Any]:
    """The frozen environment, as it is written to ``ENVIRONMENT.json``."""
    if arm_configs is None:
        arm_configs = [
            arms_module.arm_a(), arms_module.arm_b(), arms_module.arm_c(),
        ]
    recorded = {arm.name: arm_environment(arm) for arm in arm_configs}

    # Asserted, not assumed: the one sentence this experiment rests on is that B and C
    # differ in what the planner chooses among and in nothing else. If the surfaces ever
    # diverge, the freeze is refused rather than written with a claim it cannot support.
    surfaces = sorted({
        tuple(environment["tool_surface"]) for environment in recorded.values()
        if environment["requires_model"]
    })
    if len(surfaces) > 1:
        raise ValueError(
            "the model arms do not share a tool surface; B and C differ in what the "
            "planner chooses among, and in nothing else. Refusing to freeze an "
            f"environment that says otherwise: {surfaces}"
        )
    shared_surface = list(surfaces[0]) if surfaces else []

    return {
        "git": git_state(root),
        "arms": recorded,
        "shared_tool_surface": shared_surface,
        "request": request_configuration(),
        "retry": retry_policy(),
        "prompts": prompt_hashes(),
        "scoring": scoring_hashes(),
        "manifest_hash": manifest_hash,
        "manifest_head": manifest_head,
        "runtime": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "executable": Path(sys.executable).name,
            "packages": package_versions(),
        },
        "credential": {
            "variable": CREDENTIAL_VARIABLE,
            "present": bool(credential_present),
            "note": "presence only; the value is never recorded anywhere",
        },
    }


def live_values(
    root: Path,
    manifest_hash: str,
    arm_configs: Sequence[Any] | None = None,
    frozen_commit: str = "",
) -> dict[str, Any]:
    """The gated fields, as they are right now.

    ``frozen_commit`` is the commit the environment was frozen at, used only to ask git
    what has changed since -- see :func:`check_environment`.
    """
    if arm_configs is None:
        arm_configs = [arms_module.arm_a(), arms_module.arm_b(), arms_module.arm_c()]
    state = git_state(root)
    return {
        "commit": state["commit"],
        "dirty_paths": list(state.get("dirty_paths") or []),
        "changed_since_frozen": changed_paths_since(root, frozen_commit),
        "prompts": prompt_hashes(),
        "scoring": scoring_hashes(),
        "manifest_hash": manifest_hash,
        "arm_models": {arm.name: arm.model for arm in arm_configs},
    }


def check_environment(recorded: dict[str, Any], live: dict[str, Any]) -> list[str]:
    """Differences between a frozen environment and the live one, empty when it matches.

    Descriptions rather than a boolean, so a refused run names what moved. Only
    :data:`GATED_FIELDS` are compared: a freeze whose gate included the platform string
    would refuse every run from a different machine, which teaches the operator to pass
    ``--force`` and defeats the gate entirely.
    """
    differences: list[str] = []
    recorded_commit = str(recorded.get("git", {}).get("commit", ""))
    live_commit = str(live.get("commit", ""))
    if recorded_commit != live_commit:
        changed = live.get("changed_since_frozen")
        code_changed = (
            [path for path in changed if not path.startswith(RESULTS_PREFIX)]
            if changed is not None else None
        )
        if code_changed is None:
            differences.append(
                f"commit: frozen at {recorded_commit[:12] or '(none)'}, running "
                f"{live_commit[:12] or '(none)'} (and git could not say what changed)"
            )
        elif code_changed:
            differences.append(
                f"commit: frozen at {recorded_commit[:12]}, running "
                f"{live_commit[:12]}; {len(code_changed)} path(s) outside "
                f"{RESULTS_PREFIX} changed since: {code_changed[:5]}"
            )
    uncommitted = [
        path for path in (live.get("dirty_paths") or [])
        if not path.startswith(RESULTS_PREFIX) and not path.startswith(DATA_PREFIX)
    ]
    if uncommitted:
        differences.append(
            f"working tree: {len(uncommitted)} uncommitted change(s) outside "
            f"{RESULTS_PREFIX}: {uncommitted[:5]}"
        )
    for field in ("prompts", "scoring"):
        frozen_hashes = dict(recorded.get(field) or {})
        live_hashes = dict(live.get(field) or {})
        for key in sorted(set(frozen_hashes) | set(live_hashes)):
            frozen_value = frozen_hashes.get(key, "(absent)")
            live_value = live_hashes.get(key, "(absent)")
            if frozen_value != live_value:
                differences.append(
                    f"{field}.{key}: frozen {frozen_value[:12]}, now {live_value[:12]}"
                )
    if str(recorded.get("manifest_hash", "")) != str(live.get("manifest_hash", "")):
        differences.append(
            f"manifest_hash: frozen {str(recorded.get('manifest_hash'))[:12]}, "
            f"running {str(live.get('manifest_hash'))[:12]}"
        )
    # The model id is gated too, though the commit would usually catch a change to it:
    # "usually" is not a guarantee, an uncommitted edit leaves the commit alone, and the
    # one thing a reader of two arms' results must be able to rely on is that both ran
    # the model the freeze named.
    frozen_models = {
        name: arm.get("model")
        for name, arm in (recorded.get("arms") or {}).items()
    }
    live_models = dict(live.get("arm_models") or {})
    if live_models and frozen_models != live_models:
        for name in sorted(set(frozen_models) | set(live_models)):
            if frozen_models.get(name) != live_models.get(name):
                differences.append(
                    f"arm_models.{name}: frozen {frozen_models.get(name)!r}, "
                    f"now {live_models.get(name)!r}"
                )
    return differences


# --------------------------------------------------------------------------------------
# The readable half
# --------------------------------------------------------------------------------------


def render_markdown(payload: dict[str, Any]) -> str:
    """``ENVIRONMENT.md`` -- the same facts, for a reader rather than a comparison."""
    git = payload.get("git", {})
    request = payload.get("request", {})
    retry = payload.get("retry", {})
    runtime = payload.get("runtime", {})
    packages = runtime.get("packages", {})
    credential = payload.get("credential", {})
    lines: list[str] = []
    add = lines.append

    add("# M19 Phase 1: the frozen experiment environment")
    add("")
    add(
        "Everything that could differ between the arms other than the reasoning "
        "architecture, written down before the first arm runs. `ENVIRONMENT.json` "
        "carries the same values in machine-readable form."
    )
    add("")
    add("## The gate")
    add("")
    add(
        "A **real** run of a model arm (`run --arm B` / `--arm C`) refuses to start "
        "unless the commit, the four prompt hashes, the scoring-code hashes, the "
        "manifest hash and the per-arm model ids all still match this file, and unless "
        "the working tree is clean outside `reports/` and `data/`. Committing this file "
        "moves HEAD, so a commit that differs from the frozen one is accepted only when "
        "every path changed since lives under `reports/`; one changed line of code, "
        "test or script and the run is refused."
    )
    add("")
    add(
        "A `--scripted` run is exempt. It contains no model output, is written under "
        "`scripted/` and is labelled `*_SCRIPTED`, so there is no comparison for it to "
        "drift out of."
    )
    add("")
    add("## Code")
    add("")
    add(f"* commit `{git.get('commit', 'unknown')}` on branch `{git.get('branch')}`")
    dirty = git.get("dirty")
    dirty_paths = list(git.get("dirty_paths") or [])
    # "dirty" on its own is the wrong answer to the question a reader is asking, which
    # is whether the code that ran is the code at this commit. An untracked corpus file
    # or a results file written moments ago is not a change to the experiment, and the
    # gate ignores both -- so the line says which kind of dirty this is.
    code_paths = [
        path for path in dirty_paths
        if not path.startswith(RESULTS_PREFIX) and not path.startswith(DATA_PREFIX)
    ]
    if dirty is None:
        add("* working tree: unknown (git could not be consulted)")
    elif not dirty:
        add("* working tree: clean")
    elif code_paths:
        add(
            f"* working tree: **DIRTY** -- {len(code_paths)} uncommitted change(s) "
            "outside `reports/` and `data/`; a model arm will refuse to run"
        )
    else:
        add(
            "* working tree: no uncommitted change outside `reports/` and `data/` "
            "(the code at this commit is the code that runs)"
        )
    for path in dirty_paths:
        add(f"  * `{path}`")
    add(f"* manifest `{payload.get('manifest_hash', '')[:12]}` "
        f"(built at `{payload.get('manifest_head', '')}`)")
    add("")
    add("## The arms")
    add("")
    add("| arm | model | planner | synthesis | max_steps | tool call cap |")
    add("| --- | --- | --- | --- | --- | --- |")
    for name, arm in sorted(payload.get("arms", {}).items()):
        add(
            f"| `{name}` | `{arm.get('model') or 'none'}` | "
            f"{arm.get('use_llm_planner')} | {arm.get('use_llm_synthesis')} | "
            f"{arm.get('max_steps')} | {arm.get('tool_call_cap') or 'uncapped'} |"
        )
    add("")
    add(
        "The model id is pinned by the experiment on `ArmConfig`, not read from "
        "configuration: `ath.config.DEFAULT_MODEL` is unchanged and out of scope."
    )
    add("")
    add("## The request")
    add("")
    add(f"* endpoint `{request.get('endpoint')}`")
    add(f"* `anthropic-version: {request.get('anthropic_version_header')}`")
    add(f"* `thinking`: `{request.get('thinking')}` -- sent explicitly")
    add(f"* effort: {request.get('effort')}")
    add(
        f"* `max_tokens`: planner {request.get('max_tokens', {}).get('planner')}, "
        f"synthesis {request.get('max_tokens', {}).get('synthesis')}"
    )
    add(f"* sampling: {request.get('sampling_parameters')}")
    add(f"* body fields: {', '.join(request.get('body_fields', []))}")
    add(f"* transport: {request.get('transport')}")
    add("")
    add("## Timeout and retry")
    add("")
    add(f"* {retry.get('timeout_seconds_per_attempt')}s per attempt")
    add(
        f"* up to {retry.get('max_attempts')} attempt(s), "
        f"{retry.get('backoff')} from {retry.get('backoff_seconds')}s"
    )
    add(f"* retried statuses: {retry.get('retryable_statuses')}")
    add(f"* {retry.get('note')}")
    add("")
    add("## Prompts (sha256)")
    add("")
    for name, digest in sorted(payload.get("prompts", {}).items()):
        add(f"* `{name}`: `{digest}`")
    add("")
    add("## Scoring code (sha256)")
    add("")
    for name, digest in sorted(payload.get("scoring", {}).items()):
        add(f"* `{name}`: `{digest}`")
    add("")
    add("## Tool surface")
    add("")
    add(
        "Identical for arms B and C -- asserted when this file is written, and the "
        "freeze is refused if it is not. The difference between B and C is what the "
        "planner chooses among, never what it can call."
    )
    add("")
    for signature in payload.get("shared_tool_surface", []):
        add(f"* `{signature}`")
    add("")
    add("## Runtime")
    add("")
    add(
        f"* Python {runtime.get('python')} "
        f"({runtime.get('implementation')}) on {runtime.get('platform')}"
    )
    for name, version in sorted(packages.items()):
        add(f"* {name} {version}")
    add("")
    add("## Credential")
    add("")
    add(
        f"* `{credential.get('variable')}`: "
        f"{'set' if credential.get('present') else 'not set'} -- "
        f"{credential.get('note')}"
    )
    add("")
    return "\n".join(lines)
