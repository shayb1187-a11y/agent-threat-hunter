# Telemetry digest diagnostic (2026-09-21, laptop)

MEASURED with `ath-experiment manifest-digest` on the same checkout, same bytes under
`data/external/` and the same regenerated injected cases, under two interpreters:

| runtime | Python | pandas | numpy | file |
| --- | --- | --- | --- | --- |
| A | 3.11.9 | 2.3.3 | 2.4.6 | `DIGEST_DIAGNOSTIC_laptop-py3.11.json` |
| B | 3.9.2 | 2.2.3 | 2.0.2 | `DIGEST_DIAGNOSTIC_laptop-py3.9.json` |

Result (`ath-experiment manifest-digest --compare A B`): every corpus agrees under
digest version 1 **and** version 2, every table, every column. On top of that, runtime
A's version-1 digests equal the `telemetry_hash` values in the committed
`reports/local/dev/MANIFEST.json` (built at `195e369`) for all eleven manifest corpora.

What this rules out and what it leaves:

- Not a pandas/numpy rendering difference: two releases of each agree byte for byte on
  `to_csv` text for these tables.
- Not the loader commits between `195e369` and HEAD: HEAD reproduces the `195e369`
  hashes on this machine.
- What remains is the platform: the Colab manifest (`e4115893`, Linux, CPython 3.13) pins
  different hashes for the same corpora. Row order is hashed by design, so a directory
  listing or archive member order that differs between Linux and Windows would move
  every column of a table at once; a text-decoding difference would move one column.
  The same diagnostic run on Colab, compared against runtime A's file, names which.

Consequence for the plan: digest version 2 does not fix a row-order difference (both
versions are order-sensitive on purpose), so the default is not flipped on this finding.
The next Colab session runs `ath-experiment manifest-digest --label colab-py313` before
anything else and uploads the file; `--compare` against `DIGEST_DIAGNOSTIC_laptop-py3.11.json`
decides whether the adapters need a deterministic input order (a loader change, recorded
as a data change) or the encoding needs a rule.
