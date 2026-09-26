# Recorded model runs: attribution and scope

These pages are **recorded outputs replayed as static pages**. Nothing here calls a model.
Each file is the unmodified `.md` or `.html` report of one row from the Colab run
`holdout-9b-v6-ecd865890442` (qwen3.5:9b, profile operational-v6, and the deterministic arm). The run is described
in [holdout-v1-windows-results.md](https://github.com/shayb1187-a11y/agentic-threat-hunter/blob/main/docs/holdout-v1-windows-results.md). The files were
selected by the allow-list in `scripts/curate_demo_rows.py`. That script also rebuilt
`index.html` and wrote `SOURCES.json`, which records each file's sha256 and its source row's scores.

## DEDALE (rows h05, h07, h14)

The `h*` reports are derived from **DEDALE: Dataset for Evaluating Detection of APT among
Logs and Events**, published by INRIA / IRISA PIRAT (Lanvin, Majorczyk). It is licensed
**CC BY 4.0**. Dataset: https://doi.org/10.57745/Y5JLDG. Project page: https://dedale.inria.fr/. (Citation and licence
as recorded in `data/external/MANIFEST.json`.) The reports quote host names, process
command lines and event identifiers from that dataset. The expected labels come from the
pre-registered holdout spec. They are shown for scoring only and were never an input to
the investigation.

## Synthetic rows (sample-01..03)

The `sample-*` reports investigate ATH's own generated development scenarios
(`ath.evaluation.auth_execution.scenarios("dev")`). No third-party data is involved.

## What is deliberately not here

- No `.json` rows: they embed the full investigation state.
- No `real/index.html` from the run: it links Kubernetes cases, and the licence of
  their background source is not recorded.
- No other case keys. The curation script scans every copied file for
  Kubernetes auditID-shaped UUIDs and Kubernetes strings, and it fails if any appear.

## Files

| File | Source | sha256 |
|---|---|---|
| `rows/sample-01_d1_1.html` | synthetic | 25a0648ccda762ee… |
| `rows/sample-01_d1_1.md` | synthetic | b5d432a77e989636… |
| `rows/sample-01_deterministic_1.html` | synthetic | 65e6aa1823caafec… |
| `rows/sample-01_deterministic_1.md` | synthetic | 793556606a544846… |
| `rows/sample-02_d1_1.html` | synthetic | 9c13d130db6b75a6… |
| `rows/sample-02_d1_1.md` | synthetic | bd2d93fa051028c3… |
| `rows/sample-02_deterministic_1.html` | synthetic | 66f318b821535608… |
| `rows/sample-02_deterministic_1.md` | synthetic | ef9a0ceae77d85f4… |
| `rows/sample-03_d1_1.html` | synthetic | 644e1bc9c445aedc… |
| `rows/sample-03_d1_1.md` | synthetic | cd94fa2657b95ece… |
| `rows/sample-03_deterministic_1.html` | synthetic | 12af04723975b4e4… |
| `rows/sample-03_deterministic_1.md` | synthetic | 5515d6b9b4f0df75… |
| `rows/h14_d1_1.html` | DEDALE (CC BY 4.0) | e05f8ef87c5b1477… |
| `rows/h14_d1_1.md` | DEDALE (CC BY 4.0) | 7f1a80580b8ba7c7… |
| `rows/h14_deterministic_1.html` | DEDALE (CC BY 4.0) | 0ec0174b6bcecd9e… |
| `rows/h14_deterministic_1.md` | DEDALE (CC BY 4.0) | f7f331f6a6271fe5… |
| `rows/h07_d1_1.html` | DEDALE (CC BY 4.0) | 8a7d2c0012e9e173… |
| `rows/h07_d1_1.md` | DEDALE (CC BY 4.0) | 79576284b95c1970… |
| `rows/h07_deterministic_1.html` | DEDALE (CC BY 4.0) | 810307c24b8b368e… |
| `rows/h07_deterministic_1.md` | DEDALE (CC BY 4.0) | e665e8f0b75220c3… |
| `rows/h05_d1_1.html` | DEDALE (CC BY 4.0) | b36b486373643741… |
| `rows/h05_d1_1.md` | DEDALE (CC BY 4.0) | 4b5182a71d880ecd… |
| `rows/h05_deterministic_1.html` | DEDALE (CC BY 4.0) | 91e6d3756ad0facc… |
| `rows/h05_deterministic_1.md` | DEDALE (CC BY 4.0) | ccba43390755c71e… |
