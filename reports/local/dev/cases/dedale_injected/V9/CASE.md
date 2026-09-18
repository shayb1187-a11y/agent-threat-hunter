# V9 -- BENIGN LOOK-ALIKE: a monitoring collector with an expired service credential

**Provenance: real benign DEDALE background + injected attack rows.** Not real data about
an intrusion, however real the background is. The background rows below are DEDALE's own
bytes; every row listed in `labels.json` was written by `scripts/m19b_inject_dedale.py` and
never happened. Ground truth for this case is the label file and nothing else -- which is
sound here only because the background produces **zero** findings under the current rules
(MEASURED, `reports/m19b/necessity/AUDIT.md`), so every finding the case raises is caused by
an injected row.

Labelled malicious: **false** (benign look-alike).

## Generation

| | |
| --- | --- |
| seed | `260915` (case seed `260915:V9`) |
| script | `scripts/m19b_inject_dedale.py` |
| source | DEDALE `D02` (`2024-12-24`), `D02_2024-12-24.jsonl` |
| background records | 5869 |
| injected records | 13 |
| regenerate | `python scripts/m19b_inject_dedale.py --only V9 --out <dir>` |

## Background

| file | host | hour | background records | injected records |
| --- | --- | --- | --- | --- |
| `CLIENT23_2024-12-24T08.jsonl` | CLIENT23 | 2024-12-24 08:00Z | 3386 | 0 |
| `CLIENT24_2024-12-24T08.jsonl` | CLIENT24 | 2024-12-24 08:00Z | 2483 | 13 |

Real DEDALE Winlogbeat NDJSON (7.10.2 / ECS 1.5.0), copied verbatim except for the
`message` field -- a rendered copy of `event_data`, unused by every adapter, two thirds of
the bytes -- dropped exactly as `scripts/cut_real_shaped_fixtures.py` drops it.
`winlog.record_id`, `host.name` and `winlog.channel` are untouched, which is what lets label
refs resolve. The external dataset directory is read-only input and was never written to.

DEDALE (INRIA/IRISA PIRAT), https://doi.org/10.57745/Y5JLDG, https://dedale.inria.fr/ -- licence CC BY 4.0.

## The story

The monitoring server **CLIENT23** polls **CLIENT24** as **client24** every thirty
seconds; the credential expired overnight and ten polls fail before the on-call engineer renews
it. The next poll succeeds and the collector's service runs its collection script, which
gathers workstation statistics. No `ADMIN$` redirect. **Labelled benign.**

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
| `V9-LINK-1` | 2-credential-renewed -> 3-collector-script | `Security` 22862 | `Microsoft-Windows-Sysmon/Operational` 678863 |
| `V9-LINK-2` | 2-credential-renewed -> 4-collection-command | `Security` 22862 | `Microsoft-Windows-Sysmon/Operational` 678864 |

These are the pre-registered pairs the **CDER** metric scores: a link is recovered when one accepted claim cites evidence on both sides. `LINK-1` is reachable from the case's own evidence -- both rows are cited by a finding, so a deterministic arm can recover it. Any further link points at a process row **no finding cites** (a command run under the shell), so recovering it means an arm went looking: it measures investigation rather than detection. Each link's note in `labels.json` says which it is.

## Why cross-domain synthesis changes the verdict, the priority, or the next action

Identity alone: ten failures then a success from one host, the textbook
burst. Endpoint alone: a MEDIUM service shell. Together with the 30 s cadence and the named
collector script, an expired credential -- and the next action is a credential-lifecycle fix.

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
| `1-expired-service-credential` | 10 | ten failures at a 30s polling cadence |
| `2-credential-renewed` | 1 | the next poll succeeds |
| `3-collector-script` | 1 | services.exe starts the collector's script, no ADMIN$ redirect |
| `4-collection-command` | 1 | workstation statistics gathered |

Every injected record's native ref (`host=...;channel=...;record_id=...`) is in `labels.json` and in the top-level `MANIFEST.json`. Nothing in the telemetry marks a row as injected -- a marker inside a record would leak the answer key into the thing being measured.

