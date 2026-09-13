# M4 -- The burst never succeeds: does the cross-domain link survive a MEDIUM?

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
| seed | `19026` (case seed `19026:M4`) |
| script | `scripts/m19b_inject_dedale.py` |
| source | DEDALE `D18` (`2025-01-09`), `D18_2025-01-09.jsonl` |
| background records | 148 |
| injected records | 14 |
| regenerate | `python scripts/m19b_inject_dedale.py --only M4 --out <dir>` |

## Background

| file | host | hour | background records | injected records |
| --- | --- | --- | --- | --- |
| `CLIENT12_2025-01-09T13.jsonl` | CLIENT12 | 2025-01-09 13:00Z | 102 | 0 |
| `CLIENT3_2025-01-09T13.jsonl` | CLIENT3 | 2025-01-09 13:00Z | 46 | 14 |

Real DEDALE Winlogbeat NDJSON (7.10.2 / ECS 1.5.0), copied verbatim except for the
`message` field -- a rendered copy of `event_data`, unused by every adapter, two thirds of
the bytes -- dropped exactly as `scripts/cut_real_shaped_fixtures.py` drops it.
`winlog.record_id`, `host.name` and `winlog.channel` are untouched, which is what lets label
refs resolve. The external dataset directory is read-only input and was never written to.

DEDALE (INRIA/IRISA PIRAT), https://doi.org/10.57745/Y5JLDG, https://dedale.inria.fr/ -- licence CC BY 4.0.

## The story

Eleven failures for **client3** on **CLIENT3** from **CLIENT12**, and no
successful logon from that source at all. ATH-005 grades this **MEDIUM**, not CRITICAL -- its
stated condition, a success, was not met -- and M14 established that grading such a burst HIGH
produced 35 untriageable singleton cases on flaws.cloud. The endpoint half is unchanged, and
fires HIGH.

The case is here to answer a question the benchmark would otherwise never ask: the
correlator's `_auth_then_exec` is gated on **rule id**, not on severity, so a MEDIUM identity
finding should still link. If it does, this is the case where the model arms have the most to
add and the least to lean on -- the identity evidence is graded as *not* an incident, and the
story exists only across the two domains.

## Domains

**endpoint** (Sysmon 1 process creates: what ran on the target and what started it) and
**identity** (Security 4624/4625: whose credential was used, from where, and whether it
worked). Each domain carries a stage the other does not, so removing either removes a stage
rather than a second view of one -- condition 2 of `docs/m19b-plan.md`.

## Rules this case is built to fire

| rule | domain | severity this case is built for |
| --- | --- | --- |
| `ATH-005` | identity | MEDIUM (no success followed) |
| `ATH-007` | endpoint | HIGH (ADMIN$ redirect) |

Expected findings: **2**, correlating into **one** case.

## Pre-registered cross-domain links

| link | stage transition | identity record | endpoint record |
| --- | --- | --- | --- |
| `M4-LINK-1` | 1-credential-guessing -> 3-remote-service-execution | `Security` 30244 | `Microsoft-Windows-Sysmon/Operational` 4394492 |
| `M4-LINK-2` | 1-credential-guessing -> 4-discovery | `Security` 30244 | `Microsoft-Windows-Sysmon/Operational` 4394493 |

These are the pre-registered pairs the **CDER** metric scores: a link is recovered when one accepted claim cites evidence on both sides. `LINK-1` is reachable from the case's own evidence -- both rows are cited by a finding, so a deterministic arm can recover it. Any further link points at a process row **no finding cites** (a command run under the shell), so recovering it means an arm went looking: it measures investigation rather than detection. Each link's note in `labels.json` says which it is.

## Why cross-domain synthesis changes the verdict, the priority, or the next action

This is the case where one-domain reasoning reaches the wrong answer
rather than an incomplete one. The identity rows say, correctly, that the guessing did not
land: no success from CLIENT12 exists, which is why the rule grades MEDIUM, and read alone the
right next action is "monitor". The endpoint rows say a service started a shell with an ADMIN$
redirect on the same host 105 seconds after the last failure -- read alone, the right next
action is "confirm with the owner which tool did this".

Together they say something neither says: the operator reached execution on CLIENT3 without a
logon this telemetry can show, so **the credential did not come from this burst**. That is a
different incident -- a host already compromised, or an account whose success was logged
somewhere this collection does not cover -- and the next action is a collection question, not
a containment one. A crew that reports "brute force, unsuccessful; plus a suspicious service"
has produced two true statements and the wrong investigation.

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
| `1-credential-guessing` | 11 | eleven failed type 3 logons and no success from that source |
| `3-remote-service-execution` | 1 | a service-launched shell with an ADMIN$ redirect 105s later |
| `4-discovery` | 2 | local and domain group enumeration from that shell |

Every injected record's native ref (`host=...;channel=...;record_id=...`) is in `labels.json` and in the top-level `MANIFEST.json`. Nothing in the telemetry marks a row as injected -- a marker inside a record would leak the answer key into the thing being measured.

