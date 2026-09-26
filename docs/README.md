# Documentation

[Project overview](../README.md) · [Development setup](../CONTRIBUTING.md)

The application lives in one Python package, `src/ath`. The guides below describe
its current behavior; milestone reports preserve the experiments that informed it.

## Application guides

| Guide | What it covers |
| --- | --- |
| [Technical reference](project-reference.md) | Architecture, detector catalog, worked CLI examples, evaluation, and limitations |
| [Data dictionary](data-dictionary.md) | Canonical telemetry fields and schema |
| [KQL query guide](../queries/README.md) | Query counterparts to the Python detection rules |
| [Detection engineering](detection-engineering.md) | Candidate rules, evaluation, and promotion decisions |
| [Bounded investigations](operational-investigation.md) | Operational-v1 budgets and incomplete outcomes |
| [Typed evidence verification](evidence-verification.md) | Operational-v2 assertions, validation, and trust boundaries |
| [Checked observation references](observation-reference-investigation.md) | Operational-v3 contract fixes and the v5 stable-reference 9B Colab GPU notebook |
| [Durable investigation jobs](persistence-and-background-execution.md) | In-memory execution, PostgreSQL setup, workers, leases, and reports |
| [Authentication-to-execution evaluation](auth-execution-evaluation.md) | Synthetic pilot (operational-v2 to v5), frozen protocol, results, and Colab instructions; dev evidence only |
| [Investigation workflow](workflow.md) | `ath workflow run`: checkpointed telemetry → seed → investigation → Markdown/HTML report, batch runs, resume |
| [Real-case evaluation](real-case-evaluation.md) | Sealed bundles from externally labelled telemetry, analyst-seeded mode, holdout protocols, attempt stubs |

## Research record

Milestone identifiers are stable references used by scripts, tests, and recorded
artifacts. They are stages in this project's development, not separate applications.
Read each report's scope before comparing results across milestones.

| Track | Report and supporting material |
| --- | --- |
| M14: first external validation | [Results](m14-validation-report.md), [result table](m14-table.md), [acquisition plan](m14-data-acquisition-plan.md), [dataset candidates](m14-dataset-candidates.md) |
| M15: detection fixes | [Validation report](m15-validation-report.md) |
| M16: held-out generalization | [Validation report](m16-heldout-validation-report.md) |
| M17: external evaluation | [Evaluation report](m17-external-evaluation-report.md), [omitted canonical inputs](../reports/m17/canonical/README.md) |
| M18: representation and cloud detection | [Report](m18-representation-and-cloud-detection-report.md) |
| M18b: process identity | [Artifact directory](../reports/m18b/), [omitted canonical inputs](../reports/m18b/canonical/README.md); no standalone report |
| M19: agent architecture comparison | [Ablation report](m19-ablation-report.md), [parallel development ledger](m19-parallel-day-ledger.md) |
| M19b: cross-domain investigation | [Report](m19b-report.md), [predeclared plan](m19b-plan.md), [human review guide](../reports/m19b/review/README.md); remaining runs pending |
| Holdout-v1-windows: first pre-registered model evaluation | [Pre-registration](holdout-v1-windows-preregistration.md), [results](holdout-v1-windows-results.md): model not demonstrated |
| M20: benign AWS validation | [Plan](m20-benign-cloud-validation-plan.md), [AWS runbook](m20-aws-setup.md); tooling implemented, AWS study not run |

The [full roadmap](project-reference.md#roadmap) records historical delivery status.
The [external-data policy](project-reference.md#external-datasets) explains
provenance, redistribution, and which experiments require separately fetched data.

## Engineering investigations

- [ATH-005 follow-up interval defect](ath005-follow-up-defect.md)
- [AWS-006 ATT&CK mapping investigation](aws006-attack-mapping-investigation.md)
- [Test-quality root causes](test-quality-root-causes.md)

## Notebooks and experiment configuration

| Entry point | Purpose |
| --- | --- |
| [Holdout-v1-windows](../notebooks/ath_holdout_gpu.ipynb) | Pre-registered holdout run on a Colab GPU; see the [results](holdout-v1-windows-results.md) |
| [Operational-v2 authentication-to-execution](../notebooks/ath_auth_execution_colab.ipynb) | Synthetic pilot; use the [evaluation runbook](auth-execution-evaluation.md) |
| [D1 model comparison](../notebooks/ath_d1_model_comparison_colab.ipynb) | Frozen D1-v3 comparison across local models |
| [Local ablation](../notebooks/ath_local_ablation_colab.ipynb) | Earlier local-model ablation workflow |
| [D1 comparison spec](../experiments/d1_model_comparison.json) | Configuration for the packaged `ath-experiment` runner |

The older notebooks answer different research questions. Generated outputs and frozen research evidence live under
`reports/`; the application and reusable experiment runner live under `src/ath/`.
