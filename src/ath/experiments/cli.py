"""``ath-experiment``: the experiment layer's own command line.

Separate from ``ath`` on purpose: the product CLI never imports the ablation harness,
and the experiment layer never needs ``Settings``. Every subcommand takes ``--spec``; the
spec supplies defaults and the flags override them, so a notebook can pass one file and
nothing else, while the old flag-only calls keep working.

Exit codes: 0 done; 1 ``validate-rows`` found invalid rows without ``--quarantine``;
3 a controlled interruption of ``run``; 130 Ctrl-C; any ``REFUSED: ...`` message is a
``SystemExit`` with that text.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ath.agent.ollama_llm import Sampling
from ath.experiments.local_arms import ARM_LETTERS
from ath.experiments.paths import DEV_DIR, Layout
from ath.experiments.spec import ExperimentSpec, find_spec

DEFAULTS: dict[str, Any] = {
    "model": "qwen3.5:4b", "arm": "D1", "out_dir": DEV_DIR, "base_url": "http://127.0.0.1:11434",
    "temperature": 0.0, "seed": 0, "think": False, "repeat": 1, "external": None,
}


def _common(parser: argparse.ArgumentParser, *, model: bool = True) -> None:
    parser.add_argument("--spec", default=None, help="experiment spec (experiments/<name>.json or a path)")
    if model:
        parser.add_argument("--model", default=None)
    parser.add_argument("--arm", default=None, choices=sorted(ARM_LETTERS))
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--temperature", type=float, default=None)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--think", action="store_true", default=None)


def resolve(args: argparse.Namespace) -> tuple[argparse.Namespace, ExperimentSpec | None]:
    """Flags win over the spec, the spec over the code defaults."""
    spec = ExperimentSpec.load(find_spec(args.spec)) if getattr(args, "spec", None) else None
    from_spec: dict[str, Any] = {}
    if spec is not None:
        from_spec = {
            "model": spec.models[0], "arm": spec.arm, "out_dir": spec.out_path,
            "base_url": spec.base_url, "temperature": spec.temperature, "seed": spec.seed,
            "think": spec.think, "repeat": spec.repeat, "external": spec.external_path,
        }
    for name, default in DEFAULTS.items():
        if getattr(args, name, None) is None:
            setattr(args, name, from_spec.get(name, default))
    if args.external is None:
        from ath.experiments.bundles import DEFAULT_EXTERNAL

        args.external = DEFAULT_EXTERNAL
    return args, spec


def _sampling(args: argparse.Namespace) -> Sampling:
    return Sampling(args.temperature, args.seed)


# -- subcommands ------------------------------------------------------------------------


def cmd_paths(args: argparse.Namespace) -> int:
    args, _ = resolve(args)
    digest = ""
    if not args.no_manifest:
        from ath.experiments.manifest_build import read_manifest

        _, _, digest = read_manifest(args.out_dir)
    layout = Layout(Path(args.out_dir), args.arm, args.model, digest)
    print(json.dumps(layout.to_dict(), indent=2))
    return 0


def cmd_identity(args: argparse.Namespace) -> int:
    from ath.experiments.identity import frozen_surface_sha256
    from ath.experiments.runs import git_tree

    print(json.dumps({"frozen_surface_sha256": frozen_surface_sha256(), "tree": git_tree()}, indent=2))
    return 0


def cmd_manifest_build(args: argparse.Namespace) -> int:
    from ath.experiments.manifest_build import build_dev_manifest

    args, spec = resolve(args)
    version = args.digest_version if args.digest_version is not None else (spec.digest_version if spec else 1)
    build_dev_manifest(
        external=args.external, out_dir=args.out_dir, seed=args.manifest_seed,
        expected=args.expected if args.expected is not None else (spec.expected_cases if spec else 20),
        digest_version=version,
    )
    return 0


def cmd_manifest_digest(args: argparse.Namespace) -> int:
    from ath.experiments.digest_diagnostic import compare, diagnose, render

    if args.compare:
        report = compare(Path(args.compare[0]), Path(args.compare[1]))
        print(render(report))
        print(json.dumps(report, indent=1, default=str), file=sys.stderr)
        return 0
    from ath.experiments.manifest_build import dev_bundles

    args, _ = resolve(args)
    corpora = set(args.only_corpora) if args.only_corpora else None
    diagnose(dev_bundles(args.external, corpora=corpora), out_dir=args.out_dir, label=args.label)
    return 0


def cmd_inject(args: argparse.Namespace) -> int:
    from ath.experiments.manifest_build import inject_cases

    args, _ = resolve(args)
    return inject_cases(args.only, external=args.external)


def cmd_freeze(args: argparse.Namespace) -> int:
    from ath.experiments.freeze import freeze

    args, _ = resolve(args)
    freeze(
        out_dir=args.out_dir, arm_letter=args.arm, model=args.model, sampling=_sampling(args),
        base_url=args.base_url, think=bool(args.think),
    )
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    from ath.experiments.runner import run

    args, spec = resolve(args)
    only = list(args.only) if args.only else None
    if args.smoke:
        if spec is None or not spec.smoke_cases:
            raise SystemExit("--smoke needs a spec with smoke_cases")
        only = list(spec.smoke_cases)
    workers = args.workers if args.workers is not None else (spec.workers if spec is not None else 1)
    allowance = int(args.context_allowance_gib * (1024 ** 3)) if args.context_allowance_gib is not None else None
    return run(
        out_dir=args.out_dir, arm_letter=args.arm, model=args.model, sampling=_sampling(args),
        base_url=args.base_url, external=args.external, think=bool(args.think),
        repeat=args.repeat, stop_after=args.stop_after, ignore_ram_floor=args.ignore_ram_floor,
        only=only, spec=spec, argv=args.argv, workers=workers, context_allowance_bytes=allowance,
    )


def cmd_validate(args: argparse.Namespace) -> int:
    from ath.experiments.validate import validate

    args, spec = resolve(args)
    return validate(
        out_dir=args.out_dir, arm_letter=args.arm, model=args.model, quarantine=args.quarantine,
        spec=spec, argv=args.argv,
    )


def cmd_summarise(args: argparse.Namespace) -> int:
    from ath.experiments.summarise import summarise_model

    args, spec = resolve(args)
    return summarise_model(
        out_dir=args.out_dir, arm_letter=args.arm, model=args.model, repeat=args.repeat,
        allow_empty=args.allow_empty, spec=spec, argv=args.argv,
    )


def cmd_compare(args: argparse.Namespace) -> int:
    from ath.experiments.compare import compare_models

    args, spec = resolve(args)
    models = args.models or (list(spec.models) if spec is not None else None)
    if not models or len(models) != 2:
        raise SystemExit("compare needs --models A B, or a spec naming exactly two models")
    return compare_models(
        out_dir=args.out_dir, arm_letter=args.arm, models=models, repeat=args.repeat,
        spec=spec, argv=args.argv,
    )


def cmd_preflight(args: argparse.Namespace) -> int:
    from ath.experiments.preflight import preflight

    args, spec = resolve(args)
    report, exit_code = preflight(
        out_dir=args.out_dir, arm_letter=args.arm, model=args.model, base_url=args.base_url,
        external=args.external, spec=spec, allow_cpu=args.allow_cpu, verify_cache=args.verify_cache,
        do_warm_up=args.warm_up, argv=args.argv,
    )
    print(json.dumps(report, indent=1, default=str))
    return exit_code


def cmd_bootstrap(args: argparse.Namespace) -> int:
    from ath.experiments.bootstrap_colab import bootstrap

    args, spec = resolve(args)
    models = args.models or (list(spec.models) if spec is not None else [args.model])
    report = bootstrap(
        base_url=args.base_url, external=Path(args.external), uploads=Path(args.uploads), models=models,
        daemon_log=Path(args.daemon_log), skip_fetch=args.skip_fetch, inject=not args.no_inject,
        workers=args.workers if args.workers is not None else (spec.workers if spec is not None else 1),
    )
    print(json.dumps(report, indent=1, default=str))
    return 0


# -- parser -----------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ath-experiment", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("paths", help="print every path of one (arm, model, manifest) experiment")
    _common(p)
    p.add_argument("--no-manifest", action="store_true", help="do not read MANIFEST.json for the digest")
    p.set_defaults(func=cmd_paths)

    p = sub.add_parser("identity", help="the checkout's frozen-surface digest and git tree id")
    p.set_defaults(func=cmd_identity)

    p = sub.add_parser("manifest-build", help="build the dev manifest (MANIFEST.json/.md)")
    _common(p, model=False)
    p.add_argument("--external", type=Path, default=None)
    p.add_argument("--manifest-seed", type=int, default=None, help="selection seed (default: the injector's DEV_SEED)")
    p.add_argument("--expected", type=int, default=None)
    p.add_argument("--digest-version", type=int, choices=(1, 2), default=None, help="telemetry digest version (default: the spec's, else 1)")
    p.set_defaults(func=cmd_manifest_build)

    p = sub.add_parser("manifest-digest", help="per-column telemetry digests of every dev corpus on this runtime, or a comparison of two such files")
    _common(p, model=False)
    p.add_argument("--external", type=Path, default=None)
    p.add_argument("--label", default=platform.python_version() + "-" + platform.system().lower(), help="name of this runtime in the output file")
    p.add_argument("--only-corpora", nargs="*", default=None, help="restrict to these corpus names")
    p.add_argument("--compare", nargs=2, default=None, metavar=("A_JSON", "B_JSON"), help="name the columns whose digests differ between two diagnostic files")
    p.set_defaults(func=cmd_manifest_digest)

    p = sub.add_parser("inject", help="regenerate the injected dev cases via the pinned script")
    _common(p, model=False)
    p.add_argument("--external", type=Path, default=None)
    p.add_argument("--only", nargs="*", default=None)
    p.set_defaults(func=cmd_inject)

    p = sub.add_parser("freeze", help="freeze the local environment for one model")
    _common(p)
    p.set_defaults(func=cmd_freeze)

    p = sub.add_parser("preflight", help="every check a run needs answered before its first row")
    _common(p)
    p.add_argument("--external", type=Path, default=None)
    p.add_argument("--allow-cpu", action="store_true", help="a missing GPU is a warning, not a failure")
    p.add_argument("--verify-cache", action="store_true", help="hash the telemetry cache against data/external/MANIFEST.json")
    p.add_argument("--warm-up", action="store_true", help="load the model and keep it resident before checking residency")
    p.set_defaults(func=cmd_preflight)

    p = sub.add_parser("bootstrap-colab", help="tools, daemon, telemetry, injected cases and manifest on a fresh runtime")
    _common(p)
    p.add_argument("--external", type=Path, default=None)
    p.add_argument("--models", nargs="*", default=None, help="models to pull (default: the spec's, or --model)")
    p.add_argument("--uploads", default="/content/uploads", help="where zips from earlier sessions were dropped")
    p.add_argument("--daemon-log", default="/content/ollama.log")
    p.add_argument("--skip-fetch", action="store_true", help="do not fetch or restore telemetry")
    p.add_argument("--no-inject", action="store_true", help="do not regenerate the injected dev cases")
    p.add_argument("--workers", type=int, default=None, help="start the daemon with this many parallel slots")
    p.set_defaults(func=cmd_bootstrap)

    p = sub.add_parser("run", help="run the arm over the dev split, resumably")
    _common(p)
    p.add_argument("--external", type=Path, default=None)
    p.add_argument("--repeat", type=int, default=None)
    p.add_argument("--stop-after", type=int, default=None, help="stop after N newly completed rows (exit 3, a controlled interruption)")
    p.add_argument("--ignore-ram-floor", action="store_true", help="run below the RAM floor; every such row and event is recorded as overridden")
    p.add_argument("--only", nargs="*", default=None, metavar="CORPUS/CASE", help="run only these manifest keys")
    p.add_argument("--smoke", action="store_true", help="run only the spec's smoke_cases")
    p.add_argument("--workers", type=int, default=None, help="concurrent cases against the one loaded model (default: the spec's, else 1); needs OLLAMA_NUM_PARALLEL on the daemon")
    p.add_argument("--context-allowance-gib", type=float, default=None, help="RAM each extra parallel slot is assumed to cost (default: the unmeasured 1.5 GiB constant)")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("validate-rows", help="check every row in this model's rows directory against the live freeze and manifest")
    _common(p)
    p.add_argument("--quarantine", action="store_true", help="move rows that fail into <rows_dir>.quarantine/ with a reason file (never delete)")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("summarise", help="summarise one model's rows")
    _common(p)
    p.add_argument("--repeat", type=int, default=None)
    p.add_argument("--allow-empty", action="store_true", help="write a summary of zero rows even when rows exist beside the target directory")
    p.set_defaults(func=cmd_summarise)

    p = sub.add_parser("compare", help="paired comparison of two models' rows")
    _common(p, model=False)
    p.add_argument("--models", nargs=2, default=None, metavar=("MODEL_A", "MODEL_B"))
    p.add_argument("--repeat", type=int, default=None)
    p.set_defaults(func=cmd_compare)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(argv)
    args.argv = argv
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
