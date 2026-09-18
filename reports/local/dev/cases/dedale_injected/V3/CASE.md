# V3 -- The burst never succeeds, yet a shell follows: the MEDIUM identity half

**Provenance: real benign DEDALE background + injected attack rows.** Not real data about
an intrusion, however real the background is. The background rows below are DEDALE's own
bytes; every row listed in `labels.json` was written by `scripts/m19b_inject_dedale.py` and
never happened. Ground truth for this case is the label file and nothing else -- which is
sound here only because the background produces **zero** findings under the current rules
(MEASURED, `reports/m19b/necessity/AUDIT.md`), so every finding the case raises is caused by
an injected row.

Labelled malicious: **true**.

## Generation

| | |
| --- | --- |
| seed | `260915` (case seed `260915:V3`) |
| script | `scripts/m19b_inject_dedale.py` |
| source | DEDALE `D02` (`2024-12-24`), `D02_2024-12-24.jsonl` |
| background records | 4480 |
| injected records | 15 |
| regenerate | `python scripts/m19b_inject_dedale.py --only V3 --out <dir>` |

## Background

| file | host | hour | background records | injected records |
| --- | --- | --- | --- | --- |
| `CLIENT6_2024-12-24T08.jsonl` | CLIENT6 | 2024-12-24 08:00Z | 2504 | 0 |
| `CLIENT8_2024-12-24T08.jsonl` | CLIENT8 | 2024-12-24 08:00Z | 1976 | 15 |

Real DEDALE Winlogbeat NDJSON (7.10.2 / ECS 1.5.0), copied verbatim except for the
`message` field -- a rendered copy of `event_data`, unused by every adapter, two thirds of
the bytes -- dropped exactly as `scripts/cut_real_shaped_fixtures.py` drops it.
`winlog.record_id`, `host.name` and `winlog.channel` are untouched, which is what lets label
refs resolve. The external dataset directory is read-only input and was never written to.

DEDALE (INRIA/IRISA PIRAT), https://doi.org/10.57745/Y5JLDG, https://dedale.inria.fr/ -- licence CC BY 4.0.

## The story

Twelve failures for **client8** on **CLIENT8** from **CLIENT6** and no success from
that source. ATH-005 grades the burst MEDIUM. Two minutes after the last failure a shell starts
under the Service Control Manager anyway -- the credential came from somewhere else.

## Domains

**endpoint** (Sysmon 1 process creates: what ran on the target and what started it) and
**identity** (Security 4624/4625: whose credential was used, from where, and whether it
worked). Each domain carries a stage the other does not, so removing either removes a stage
rather than a second view of one -- condition 2 of `docs/m19b-plan.md`.

## Rules this case is built to fire

| rule | domain | severity this case is built for |
| --- | --- | --- |
| `ATH-005` | identity |  |
| `ATH-007` | endpoint |  |

Expected findings: **2**, correlating into **one** case.

## Pre-registered cross-domain links

| link | stage transition | identity record | endpoint record |
| --- | --- | --- | --- |
| `V3-LINK-1` | 1-credential-guessing -> 2-remote-service-execution | `Security` 21761 | `Microsoft-Windows-Sysmon/Operational` 639127 |
| `V3-LINK-2` | 1-credential-guessing -> 3-discovery | `Security` 21761 | `Microsoft-Windows-Sysmon/Operational` 639128 |

These are the pre-registered pairs the **CDER** metric scores: a link is recovered when one accepted claim cites evidence on both sides. `LINK-1` is reachable from the case's own evidence -- both rows are cited by a finding, so a deterministic arm can recover it. Any further link points at a process row **no finding cites** (a command run under the shell), so recovering it means an arm went looking: it measures investigation rather than detection. Each link's note in `labels.json` says which it is.

## Why cross-domain synthesis changes the verdict, the priority, or the next action

Identity alone says an unsuccessful attempt; endpoint alone says a shell.
Only together do they say the attacker got in by a route the identity rows did not see.

## The architectural limitation this case inherits

Every case in this directory is **endpoint x identity**, because that is the only
cross-domain pair `ath.correlation.correlator` can form. Of `score_pair`'s six signals, four
(`shared_evidence`, `same_process`, `process_lineage`, `sibling_lineage`) need the two
findings to cite the same event or the same process instance, which findings from two
different canonical tables cannot do; `host_movement` needs a directed host relationship no
cloud or container finding carries; and `auth_then_exec`, the one that can span tables, is
gated by a hardcoded allowlist:

```python
_AUTH_RULES = frozenset({"ATH-005", "ATH-006"})
_REMOTE_EXEC_RULES = frozenset({"ATH-007"})
```

No other pair of rule ids can produce a cross-domain case, whatever the telemetry holds.
VERIFIED FROM CODE; the argument is `reports/m19b/necessity/AUDIT.md`.

A benchmark built from these cases therefore measures whether a specialist crew helps on
*one* kind of cross-domain investigation. It is not evidence about cross-domain investigation
in general, and the pre-registration has to say so.

## What was injected

| stage | injected records | what it is |
| --- | --- | --- |
| `1-credential-guessing` | 12 | twelve failed logons in 240s, no success |
| `2-remote-service-execution` | 1 | services.exe starts cmd.exe 120s after the last failure, ADMIN$ redirect |
| `3-discovery` | 2 | local administrator enumeration and a network view |

Every injected record's native ref (`host=...;channel=...;record_id=...`) is in `labels.json` and in the top-level `MANIFEST.json`. Nothing in the telemetry marks a row as injected -- a marker inside a record would leak the answer key into the thing being measured.

