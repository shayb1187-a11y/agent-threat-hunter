# M2 -- A slower burst against CLIENT3, and execution at the far edge of the correlation window

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
| seed | `19026` (case seed `19026:M2`) |
| script | `scripts/m19b_inject_dedale.py` |
| source | DEDALE `D03` (`2024-12-25`), `D03_2024-12-25.jsonl` |
| background records | 339 |
| injected records | 18 |
| regenerate | `python scripts/m19b_inject_dedale.py --only M2 --out <dir>` |

## Background

| file | host | hour | background records | injected records |
| --- | --- | --- | --- | --- |
| `CLIENT12_2024-12-25T12.jsonl` | CLIENT12 | 2024-12-25 12:00Z | 175 | 0 |
| `CLIENT3_2024-12-25T12.jsonl` | CLIENT3 | 2024-12-25 12:00Z | 164 | 18 |

Real DEDALE Winlogbeat NDJSON (7.10.2 / ECS 1.5.0), copied verbatim except for the
`message` field -- a rendered copy of `event_data`, unused by every adapter, two thirds of
the bytes -- dropped exactly as `scripts/cut_real_shaped_fixtures.py` drops it.
`winlog.record_id`, `host.name` and `winlog.channel` are untouched, which is what lets label
refs resolve. The external dataset directory is read-only input and was never written to.

DEDALE (INRIA/IRISA PIRAT), https://doi.org/10.57745/Y5JLDG, https://dedale.inria.fr/ -- licence CC BY 4.0.

## The story

The same shape as M1, paced to sit against two of the pipeline's own
thresholds rather than comfortably inside them. Fourteen failures for **client3** on
**CLIENT3** from **CLIENT12** are spread over **9m30s** -- inside `bruteforce_window`
(10 minutes) with thirty seconds to spare, so one episode is reported rather than two. The
success arrives 130s later, and the service-launched shell **12m40s** after that: inside
`auth_exec_window` (15 minutes), which is what lets the correlator join the identity finding
to the endpoint one at all. A benchmark that only ever tested the middle of a window would
not notice the day either bound moved.

## Domains

**endpoint** (Sysmon 1 process creates: what ran on the target and what started it) and
**identity** (Security 4624/4625: whose credential was used, from where, and whether it
worked). Each domain carries a stage the other does not, so removing either removes a stage
rather than a second view of one -- condition 2 of `docs/m19b-plan.md`.

## Rules this case is built to fire

| rule | domain | severity this case is built for |
| --- | --- | --- |
| `ATH-005` | identity | CRITICAL (the burst succeeded) |
| `ATH-007` | endpoint | HIGH (ADMIN$ redirect) |

Expected findings: **2**, correlating into **one** case.

## Pre-registered cross-domain links

| link | stage transition | identity record | endpoint record |
| --- | --- | --- | --- |
| `M2-LINK-1` | 2-successful-logon -> 3-remote-service-execution | `Security` 24273 | `Microsoft-Windows-Sysmon/Operational` 1082666 |
| `M2-LINK-2` | 2-successful-logon -> 4-discovery | `Security` 24273 | `Microsoft-Windows-Sysmon/Operational` 1082667 |

These are the pre-registered pairs the **CDER** metric scores: a link is recovered when one accepted claim cites evidence on both sides. `LINK-1` is reachable from the case's own evidence -- both rows are cited by a finding, so a deterministic arm can recover it. Any further link points at a process row **no finding cites** (a command run under the shell), so recovering it means an arm went looking: it measures investigation rather than detection. Each link's note in `labels.json` says which it is.

## Why cross-domain synthesis changes the verdict, the priority, or the next action

Same structure as M1, with the timing doing extra work. Thirteen
minutes is long enough that an analyst reading the endpoint finding alone has no reason to
look back at authentication: the two events are not adjacent in any queue, and the shell is
the only thing in the case whose severity demands attention. The identity rows supply the
*interval* -- "a credential for this host was guessed twelve minutes before this service
started" is a statement neither domain can make alone, and it is the statement that decides
whether the shell is an admin tool or the second stage of an intrusion.

**Next action** differs from M1's as well: at this spacing the credential has been usable for
over twelve minutes, so the containment question is what *else* it reached in that window --
a question only the identity rows can be asked.

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
| `1-credential-guessing` | 14 | fourteen failed type 3 logons over 570s, just inside the 10-minute window |
| `2-successful-logon` | 1 | success 130s after the last failure |
| `3-remote-service-execution` | 1 | the service-launched shell arrives 760s later, near the 15-minute edge |
| `4-discovery` | 2 | local and domain group enumeration from that shell |

Every injected record's native ref (`host=...;channel=...;record_id=...`) is in `labels.json` and in the top-level `MANIFEST.json`. Nothing in the telemetry marks a row as injected -- a marker inside a record would leak the answer key into the thing being measured.

