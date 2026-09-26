# Development guide

Run commands from the repository root: the directory containing `pyproject.toml`,
`main.py`, and `src/`. There is one installable package and one application CLI.

## Local setup

Python 3.10 or newer is required. CI checks Python 3.10 and 3.12.

```bash
python -m venv .venv
```

Activate with `source .venv/bin/activate` on Linux/macOS, or
`.\.venv\Scripts\Activate.ps1` in PowerShell. Then install:

```bash
python -m pip install -e ".[dev]"
ath --help
ath-experiment --help
```

`pyproject.toml` defines the package and dependency groups. Optional extras are
`postgres` for durable jobs and `graph` for the LangGraph runtime. For example,
`python -m pip install -e ".[dev,postgres]"` enables database integration tests.
`requirements.txt` is the older convenience installation route.

The deterministic workflow needs no credentials. For optional services, copy
`.env.example` to `.env` **inside this repository** and set the required values.
`ath.config` loads that file; a `.env` in the parent workspace is not loaded
automatically. Exported environment variables take precedence.

## Where changes belong

| Directory | Responsibility |
| --- | --- |
| `src/ath/` | Reusable application code, CLI, and experiment runner |
| `tests/` | Unit, integration, regression, and evidence-contract tests; small attributed fixtures |
| `queries/` | KQL counterparts to registered Python detectors |
| `scripts/` | Data acquisition, experiment entry points, and milestone-specific tooling |
| `experiments/` | Declarative experiment specifications |
| `notebooks/` | Interactive and Colab entry points into the project |
| `data/` | Shipped synthetic telemetry and external-data manifests; downloaded corpora are ignored |
| `reports/` | Research evidence, frozen manifests, and generated reports |
| `docs/` | Current runbooks, technical reference, and historical research reports |
| `.github/workflows/` | CI checks, including PostgreSQL integration |

Source adapters normalize telemetry to the shared schema before detection.
Application changes belong in `src/ath/`; scripts and notebooks should reuse that
implementation. Labelled ground truth belongs to evaluation, not detection or
investigation decisions.

## Validation

```bash
python -m ruff check src tests scripts
python -m pytest -q
python main.py hunt --summary
python main.py investigate --profile operational-v2 --no-llm --case CASE-001
```

The test suite runs offline with development dependencies. PostgreSQL integration
tests require `ATH_TEST_DATABASE_URL` pointing at a disposable test database and the
`postgres` extra; CI supplies PostgreSQL 16. Missing optional services or external
corpora can produce skips. See the
[persistence guide](docs/persistence-and-background-execution.md) for setup.

Documentation claims are checked against the shipped telemetry and detector
registry by `tests/test_docs_claims.py`. Keep the overview and technical reference
consistent when behavior or measured results change.

## Reproducible research

Some source files and experiment surfaces are hash-pinned. Run the frozen checks
when changing investigation or evaluation code:

```bash
python -m pytest -q tests/test_frozen_identity_pin.py tests/test_frozen_source_pin.py tests/test_frozen_surface_pin.py
```

Preserve existing freezes and raw measurements. A changed protocol or implementation
requires a new experiment freeze and output directory, as described in its runbook.
Large external corpora are fetched separately; provenance and reproduction limits
are documented in the [technical reference](docs/project-reference.md#external-datasets).

## Local worktrees

Git worktrees are independent checkouts of the same repository. They are not
application dependencies and should not be copied into `src/` or committed as
nested projects. Open the primary checkout when reviewing or running ATH.
`git worktree list` shows any additional local checkouts.
