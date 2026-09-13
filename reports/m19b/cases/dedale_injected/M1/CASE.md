# M1 -- Password guessing from CLIENT7 lands on CLIENT9, then a service-launched shell

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
| seed | `19026` (case seed `19026:M1`) |
| script | `scripts/m19b_inject_dedale.py` |
| source | DEDALE `D03` (`2024-12-25`), `D03_2024-12-25.jsonl` |
| background records | 314 |
| injected records | 16 |
| regenerate | `python scripts/m19b_inject_dedale.py --only M1 --out <dir>` |

## Background

| file | host | hour | background records | injected records |
| --- | --- | --- | --- | --- |
| `CLIENT7_2024-12-25T11.jsonl` | CLIENT7 | 2024-12-25 11:00Z | 169 | 0 |
| `CLIENT9_2024-12-25T11.jsonl` | CLIENT9 | 2024-12-25 11:00Z | 145 | 16 |

Real DEDALE Winlogbeat NDJSON (7.10.2 / ECS 1.5.0), copied verbatim except for the
`message` field -- a rendered copy of `event_data`, unused by every adapter, two thirds of
the bytes -- dropped exactly as `scripts/cut_real_shaped_fixtures.py` drops it.
`winlog.record_id`, `host.name` and `winlog.channel` are untouched, which is what lets label
refs resolve. The external dataset directory is read-only input and was never written to.

DEDALE (INRIA/IRISA PIRAT), https://doi.org/10.57745/Y5JLDG, https://dedale.inria.fr/ -- licence CC BY 4.0.

## The story

An operator working from **CLIENT7** guesses the password of **client9**, the
account that owns **CLIENT9**. Twelve network logons for that account fail on CLIENT9 inside
four minutes, all with sub-status `0xC000006A` (bad password); the thirteenth attempt succeeds
(type 3, NTLM, from CLIENT7). Ninety-one seconds later the Service Control Manager on CLIENT9
starts a command shell whose output is redirected to `\\127.0.0.1\ADMIN$` -- the signature
of an SMB remote-execution framework collecting results over the wire -- and that shell runs
two domain-enumeration commands.

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
| `M1-LINK-1` | 2-successful-logon -> 3-remote-service-execution | `Security` 22527 | `Microsoft-Windows-Sysmon/Operational` 863740 |
| `M1-LINK-2` | 2-successful-logon -> 4-discovery | `Security` 22527 | `Microsoft-Windows-Sysmon/Operational` 863741 |

These are the pre-registered pairs the **CDER** metric scores: a link is recovered when one accepted claim cites evidence on both sides. `LINK-1` is reachable from the case's own evidence -- both rows are cited by a finding, so a deterministic arm can recover it. Any further link points at a process row **no finding cites** (a command run under the shell), so recovering it means an arm went looking: it measures investigation rather than detection. Each link's note in `labels.json` says which it is.

## Why cross-domain synthesis changes the verdict, the priority, or the next action

The endpoint rows on CLIENT9 show `services.exe` starting `cmd.exe`
**as SYSTEM**. That is all they can show: a service body has no user, so on the endpoint
evidence alone the shell is anonymous, and the honest endpoint verdict is the one ATH-007
writes -- "consistent with remote command execution via a temporary service", which is also
what a patch-management agent looks like. The identity rows name an account and an origin
host, and say the credential was guessed rather than known; they cannot show that anything
was *done* with it, because a type 3 logon that guesses right and then does nothing is a
scanner.

Combining them changes all three things the plan asks about. **Verdict**: an anonymous SYSTEM
shell becomes a shell whose arrival is explained by a credential that was being guessed ninety
seconds earlier from a named host. **Priority**: ATH-005 alone is triaged as "attempted, check
the account"; ATH-007 alone as "confirm which admin tool did this"; together they describe a
landed intrusion on a host the operator now executes on. **Next action**: neither finding alone
implicates CLIENT7 -- the source host appears only in the identity rows, and the thing worth
containing, the operator's foothold, is there and not on CLIENT9.

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
| `1-credential-guessing` | 12 | twelve failed type 3 logons for one account from one host in 234s |
| `2-successful-logon` | 1 | the same account, same source, succeeds 43s after the last failure |
| `3-remote-service-execution` | 1 | services.exe starts cmd.exe, output redirected to ADMIN$ |
| `4-discovery` | 2 | domain and local group enumeration from that shell |

Every injected record's native ref (`host=...;channel=...;record_id=...`) is in `labels.json` and in the top-level `MANIFEST.json`. Nothing in the telemetry marks a row as injected -- a marker inside a record would leak the answer key into the thing being measured.

