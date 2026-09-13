# L2 -- BENIGN LOOK-ALIKE: a scheduled job whose stored password went stale, then that job's own pre-job script

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
| seed | `19026` (case seed `19026:L2`) |
| script | `scripts/m19b_inject_dedale.py` |
| source | DEDALE `D18` (`2025-01-09`), `D18_2025-01-09.jsonl` |
| background records | 290 |
| injected records | 14 |
| regenerate | `python scripts/m19b_inject_dedale.py --only L2 --out <dir>` |

## Background

| file | host | hour | background records | injected records |
| --- | --- | --- | --- | --- |
| `CLIENT3_2025-01-09T14.jsonl` | CLIENT3 | 2025-01-09 14:00Z | 124 | 0 |
| `CLIENT12_2025-01-09T14.jsonl` | CLIENT12 | 2025-01-09 14:00Z | 166 | 14 |

Real DEDALE Winlogbeat NDJSON (7.10.2 / ECS 1.5.0), copied verbatim except for the
`message` field -- a rendered copy of `event_data`, unused by every adapter, two thirds of
the bytes -- dropped exactly as `scripts/cut_real_shaped_fixtures.py` drops it.
`winlog.record_id`, `host.name` and `winlog.channel` are untouched, which is what lets label
refs resolve. The external dataset directory is read-only input and was never written to.

DEDALE (INRIA/IRISA PIRAT), https://doi.org/10.57745/Y5JLDG, https://dedale.inria.fr/ -- licence CC BY 4.0.

## The story

A backup schedule on **CLIENT3** authenticates to **CLIENT12** as **client3**
every 48 seconds. The stored password was rotated and the schedule was not updated, so twelve
consecutive cycles fail with `0xC000006A` over 8m48s. An operator corrects the stored
credential; the next cycle succeeds, and 94 seconds later the backup agent's service starts its
pre-job script through the Service Control Manager -- `services.exe -> cmd.exe` running
`C:\BREACH\backup\prejob.cmd`, with **no ADMIN$ redirect**, so ATH-007 grades it MEDIUM and
says so: "this may be a legitimate service-based automation".

**Labelled `malicious: false`.** ATH-005 still grades CRITICAL, because its stated condition --
failures then a success from the same source -- is met exactly.

## Domains

**endpoint** (Sysmon 1 process creates: what ran on the target and what started it) and
**identity** (Security 4624/4625: whose credential was used, from where, and whether it
worked). Each domain carries a stage the other does not, so removing either removes a stage
rather than a second view of one -- condition 2 of `docs/m19b-plan.md`.

## Rules this case is built to fire

| rule | domain | severity this case is built for |
| --- | --- | --- |
| `ATH-005` | identity | CRITICAL (the stale credential was corrected and succeeded) |
| `ATH-007` | endpoint | MEDIUM (no ADMIN$ redirect) |

Expected findings: **2**, correlating into **one** case.

## Pre-registered cross-domain links

| link | stage transition | identity record | endpoint record |
| --- | --- | --- | --- |
| `L2-LINK-1` | 2-credential-corrected -> 3-service-started-script | `Security` 30270 | `Microsoft-Windows-Sysmon/Operational` 4438849 |

These are the pre-registered pairs the **CDER** metric scores: a link is recovered when one accepted claim cites evidence on both sides. `LINK-1` is reachable from the case's own evidence -- both rows are cited by a finding, so a deterministic arm can recover it. Any further link points at a process row **no finding cites** (a command run under the shell), so recovering it means an arm went looking: it measures investigation rather than detection. Each link's note in `labels.json` says which it is.

## Why cross-domain synthesis changes the verdict, the priority, or the next action

The discriminating evidence is a *rhythm* and a *path*, and they are in
different domains. The identity rows carry the rhythm: twelve failures spaced 48.000 seconds
apart, which no human and no guessing tool produces -- a fact ATH-005 does not look at, because
it counts failures and never measures their spacing. The endpoint rows carry the path: what the
service started is `C:\BREACH\backup\prejob.cmd --target CLIENT12 --set nightly`, named for
the schedule and for the target, with no redirect to an administrative share.

Either alone is a false positive. Identity alone is a CRITICAL brute-force verdict on a backup
job. Endpoint alone is a MEDIUM finding an analyst sets aside without ever learning that a dozen
failed logons preceded it, and so without asking the one question that matters -- **is anything
else on this estate still authenticating with the old password?** That next action is reachable
only from the two domains together, and it is an operational finding, not an incident.

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
| `1-stale-scheduled-credential` | 12 | twelve failures at an exact 48s cadence |
| `2-credential-corrected` | 1 | the next scheduled cycle succeeds |
| `3-service-started-script` | 1 | services.exe starts the backup agent's pre-job script, no ADMIN$ redirect |

Every injected record's native ref (`host=...;channel=...;record_id=...`) is in `labels.json` and in the top-level `MANIFEST.json`. Nothing in the telemetry marks a row as injected -- a marker inside a record would leak the answer key into the thing being measured.

