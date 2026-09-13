# L1 -- BENIGN LOOK-ALIKE: an account lockout and a PsExec support action -- the same rules at the same severities as M1

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
| seed | `19026` (case seed `19026:L1`) |
| script | `scripts/m19b_inject_dedale.py` |
| source | DEDALE `D03` (`2024-12-25`), `D03_2024-12-25.jsonl` |
| background records | 786 |
| injected records | 16 |
| regenerate | `python scripts/m19b_inject_dedale.py --only L1 --out <dir>` |

## Background

| file | host | hour | background records | injected records |
| --- | --- | --- | --- | --- |
| `CLIENT9_2024-12-25T08.jsonl` | CLIENT9 | 2024-12-25 08:00Z | 598 | 16 |
| `CLIENT7_2024-12-25T09.jsonl` | CLIENT7 | 2024-12-25 09:00Z | 188 | 0 |

Real DEDALE Winlogbeat NDJSON (7.10.2 / ECS 1.5.0), copied verbatim except for the
`message` field -- a rendered copy of `event_data`, unused by every adapter, two thirds of
the bytes -- dropped exactly as `scripts/cut_real_shaped_fixtures.py` drops it.
`winlog.record_id`, `host.name` and `winlog.channel` are untouched, which is what lets label
refs resolve. The external dataset directory is read-only input and was never written to.

DEDALE (INRIA/IRISA PIRAT), https://doi.org/10.57745/Y5JLDG, https://dedale.inria.fr/ -- licence CC BY 4.0.

## The story

**client9** is the support engineer whose own workstation is CLIENT9: the real
background hour carries that account's genuine interactive unlock there (type 11 and type 7 at
08:02:59, real DEDALE records, not injected). Working from a colleague's desk at **CLIENT7**, a
client holding a cached old password retries three times (`0xC000006A`), trips the lockout
threshold, and then retries nine more times against a locked account (`0xC0000234`). The
service desk unlocks it; seven minutes later the engineer authenticates successfully from
CLIENT7 and runs a remote-support action on their own workstation -- PsExec restarting the
print spooler, which writes its output to `ADMIN$` exactly as an attacker's tooling does.

**Labelled `malicious: false`.** It fires ATH-005 CRITICAL and ATH-007 HIGH: the same rules at
the same severities as M1, forming the same single cross-domain case. Detection alone cannot
separate the two, which is the reason this case exists.

## Domains

**endpoint** (Sysmon 1 process creates: what ran on the target and what started it) and
**identity** (Security 4624/4625: whose credential was used, from where, and whether it
worked). Each domain carries a stage the other does not, so removing either removes a stage
rather than a second view of one -- condition 2 of `docs/m19b-plan.md`.

## Rules this case is built to fire

| rule | domain | severity this case is built for |
| --- | --- | --- |
| `ATH-005` | identity | CRITICAL (the lockout was followed by a success) |
| `ATH-007` | endpoint | HIGH (ADMIN$ redirect -- PsExec writes one too) |

Expected findings: **2**, correlating into **one** case.

## Pre-registered cross-domain links

| link | stage transition | identity record | endpoint record |
| --- | --- | --- | --- |
| `L1-LINK-1` | 2-logon-after-unlock -> 3-remote-support-action | `Security` 22458 | `Microsoft-Windows-Sysmon/Operational` 815633 |
| `L1-LINK-2` | 2-logon-after-unlock -> 4-support-commands | `Security` 22458 | `Microsoft-Windows-Sysmon/Operational` 815634 |

These are the pre-registered pairs the **CDER** metric scores: a link is recovered when one accepted claim cites evidence on both sides. `LINK-1` is reachable from the case's own evidence -- both rows are cited by a finding, so a deterministic arm can recover it. Any further link points at a process row **no finding cites** (a command run under the shell), so recovering it means an arm went looking: it measures investigation rather than detection. Each link's note in `labels.json` says which it is.

## Why cross-domain synthesis changes the verdict, the priority, or the next action

Here cross-domain synthesis changes the verdict in the direction that
costs a team its trust in the tool, and it is the only thing that can. Three facts decide it,
and no two of them live in the same domain:

1. the **failure reasons** are a lockout cascade -- three bad passwords, then nine
   `0xC0000234` retries against an already-locked account -- which is what a stale cached
   credential does and not what guessing does, since guessing keeps receiving `0xC000006A`;
2. the **account owns the target host**: the same background hour carries client9's real
   interactive unlock on CLIENT9, so the credential is being used *towards* the host it
   belongs on rather than away from one;
3. the **executed commands** are `net stop spooler` / `net start spooler` -- a ticket, not
   enumeration -- and that is endpoint evidence, invisible to identity.

An analyst with only the identity rows escalates: twelve failures then a success is the
textbook CRITICAL. An analyst with only the endpoint rows escalates: an ADMIN$ redirect is the
textbook remote-execution signature. Only the combination de-escalates, and the next action it
produces -- close it, and ask why an old password was still cached at CLIENT7 -- is not
reachable from either domain alone.

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
| `1-stale-credential-lockout` | 12 | three bad-password failures, then nine against a locked account |
| `2-logon-after-unlock` | 1 | success from the same host after the service desk unlocks it |
| `3-remote-support-action` | 1 | PsExec-style service-launched shell, output to ADMIN$ |
| `4-support-commands` | 2 | the print spooler is stopped and started |

Every injected record's native ref (`host=...;channel=...;record_id=...`) is in `labels.json` and in the top-level `MANIFEST.json`. Nothing in the telemetry marks a row as injected -- a marker inside a record would leak the answer key into the thing being measured.

