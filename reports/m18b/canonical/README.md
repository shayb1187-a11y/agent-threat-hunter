# M18b canonical freeze -- COMISET

This directory held the canonical tables that the Milestone 18b measurements
(`reports/m18b/process_identity/`, `reports/m18b/identity_consumers/`,
`reports/m18b/field_usability/`, and the M19 ablation's COMISET cases via
`reports/m19/ablation/RESULTS.md`) were computed from. They were derived from the
COMISET Lab Environment Dataset (Universidad Pontificia Comillas,
https://zenodo.org/records/15375146, CC BY 4.0) -- one zip member, 159.7 GB
uncompressed -- by `scripts/comiset_slice.py`, re-run after M18's schema changes; the
[M17 freeze](../../m17/canonical/README.md) is the pre-M18 shape of the same slice.

They are **not in this repository**, and were removed from its history before
publication, for the reasons given in [M17 README](../../m17/canonical/README.md) and in the
README's Limitations: M18b is not reproducible from a clone without the archive.

The values below identify the historical parquet bytes, not the current normalized
telemetry digest. Exact byte reproduction also depends on the schema, writer and
runtime used for that freeze; running the latest pipeline is not a promise of
byte-identical output. Keep these hashes as recorded evidence.

See the [root limitations](../../../README.md#limitations),
[external-data inventory](../../../README.md#external-datasets), and the
[M17 freeze](../../m17/canonical/README.md) for the other schema version.

Anyone re-deriving them can check the result against what was actually measured:

| file | bytes | sha256 |
| --- | ---: | --- |
| `comiset_control.parquet` | 7,945 | `bf9a3643d15208873d1476a21415a7284ce5f6c79aa9d2db2e03a8f807994797` |
| `comiset_logon.parquet` | 587,161 | `ea9d017ab4e12baa522eff24c68dcd8a6e326a6a3ecedbd5e672c6684444095f` |
| `comiset_network.parquet` | 53,264,152 | `deb69fb6d5c84576b61046af00e78906c2b71af708ba5385749d92866b2b3514` |
| `comiset_process.parquet` | 1,944,859 | `fef0f8e804e42578672dc0072e817fcae8af9f42c1b5db289ba485c2389dd9e2` |

`comiset_network.parquet` was tracked with Git LFS; its hash above is the LFS object's
(`oid`), i.e. the hash of the parquet bytes, not of a pointer file. The other three are
plain `sha256sum` values of the committed files as of the last commit that held them.
