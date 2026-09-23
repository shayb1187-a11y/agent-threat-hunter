# M17 canonical freeze -- COMISET (H4)

This directory held the canonical tables that Milestone 17's COMISET evaluation
(`docs/m17-external-evaluation-report.md`, `reports/m17/H4_FROZEN.json`) was computed
from. They were derived from the COMISET Lab Environment Dataset
(Universidad Pontificia Comillas, https://zenodo.org/records/15375146, CC BY 4.0) --
one zip member, 159.7 GB uncompressed -- by `scripts/comiset_slice.py` and
`scripts/m17_comiset_eval.py`.

They are **not in this repository**, and were removed from its history before
publication: committing external data contradicts this project's rule that external
corpora are fetched, never committed, and the two network files alone were 53 MB each.
The consequence is stated in the README's Limitations: M17 is not reproducible from a
clone without the archive.

The values below identify the historical parquet bytes, not the current normalized
telemetry digest. Exact byte reproduction also depends on the schema, writer and
runtime used for that freeze; running the latest pipeline is not a promise of
byte-identical output. Keep these hashes as recorded evidence.

See the [root limitations](../../../README.md#limitations),
[external-data inventory](../../../README.md#external-datasets), and the
[M18B freeze](../../m18b/canonical/README.md) for the other schema version.

Anyone re-deriving them can check the result against what was actually measured:

| file | bytes | sha256 |
| --- | ---: | --- |
| `comiset_logon.parquet` | 587,592 | `4a4e0f144866747d0ccf63e347cbae06a4fd386bff08fc30de69d3616cc5174a` |
| `comiset_network.parquet` | 53,221,349 | `27946710c2e0813732c37113f24980399b92f7e606a46dbd4688b93bc0964c26` |
| `comiset_process.parquet` | 1,732,995 | `eec362dc30df2b32140ba76ff12a4587a357bab04974ca132df96422841e09f6` |

`comiset_network.parquet` was tracked with Git LFS; its hash above is the LFS object's
(`oid`), i.e. the hash of the parquet bytes, not of a pointer file. The other two are
plain `sha256sum` values of the committed files as of the last commit that held them.
