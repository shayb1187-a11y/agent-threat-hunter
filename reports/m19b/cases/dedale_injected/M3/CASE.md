# M3 -- The same chain where the origin host has an ownership baseline, so ATH-006 fires too

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
| seed | `19026` (case seed `19026:M3`) |
| script | `scripts/m19b_inject_dedale.py` |
| source | DEDALE `D18` (`2025-01-09`), `D18_2025-01-09.jsonl` |
| background records | 746 |
| injected records | 15 |
| regenerate | `python scripts/m19b_inject_dedale.py --only M3 --out <dir>` |

## Background

| file | host | hour | background records | injected records |
| --- | --- | --- | --- | --- |
| `CLIENT7_2025-01-09T08.jsonl` | CLIENT7 | 2025-01-09 08:00Z | 601 | 0 |
| `CLIENT9_2025-01-09T09.jsonl` | CLIENT9 | 2025-01-09 09:00Z | 145 | 15 |

Real DEDALE Winlogbeat NDJSON (7.10.2 / ECS 1.5.0), copied verbatim except for the
`message` field -- a rendered copy of `event_data`, unused by every adapter, two thirds of
the bytes -- dropped exactly as `scripts/cut_real_shaped_fixtures.py` drops it.
`winlog.record_id`, `host.name` and `winlog.channel` are untouched, which is what lets label
refs resolve. The external dataset directory is read-only input and was never written to.

DEDALE (INRIA/IRISA PIRAT), https://doi.org/10.57745/Y5JLDG, https://dedale.inria.fr/ -- licence CC BY 4.0.

## The story

**CLIENT7**'s background segment here is its boot hour, so the real data
contains client7's own interactive unlock on CLIENT7 -- an *ownership baseline* in ATH-006's
sense. The operator guesses **client9**'s password from CLIENT7 and succeeds, so the identity
domain reads the same successful logon twice: ATH-005 grades the guessing, and ATH-006
observes that client9 has no session on the host the credential is being used from. The
endpoint half is unchanged -- a service-launched shell with an ADMIN$ redirect on CLIENT9,
104 seconds after the success.

This is the only case here whose identity evidence carries two findings, and the only one that
exercises the other half of the correlator's allowlist: `_AUTH_RULES` contains ATH-006 as well
as ATH-005, and no case in the corpus audit ever exercised that edge.

## Domains

**endpoint** (Sysmon 1 process creates: what ran on the target and what started it) and
**identity** (Security 4624/4625: whose credential was used, from where, and whether it
worked). Each domain carries a stage the other does not, so removing either removes a stage
rather than a second view of one -- condition 2 of `docs/m19b-plan.md`.

## Rules this case is built to fire

| rule | domain | severity this case is built for |
| --- | --- | --- |
| `ATH-005` | identity | CRITICAL (the burst succeeded) |
| `ATH-006` | identity | HIGH (no session on the origin host) |
| `ATH-007` | endpoint | HIGH (ADMIN$ redirect) |

Expected findings: **3**, correlating into **one** case.

## Pre-registered cross-domain links

| link | stage transition | identity record | endpoint record |
| --- | --- | --- | --- |
| `M3-LINK-1` | 2-successful-logon -> 3-remote-service-execution | `Security` 29163 | `Microsoft-Windows-Sysmon/Operational` 3608676 |
| `M3-LINK-2` | 2-successful-logon -> 4-discovery | `Security` 29163 | `Microsoft-Windows-Sysmon/Operational` 3608677 |

These are the pre-registered pairs the **CDER** metric scores: a link is recovered when one accepted claim cites evidence on both sides. `LINK-1` is reachable from the case's own evidence -- both rows are cited by a finding, so a deterministic arm can recover it. Any further link points at a process row **no finding cites** (a command run under the shell), so recovering it means an arm went looking: it measures investigation rather than detection. Each link's note in `labels.json` says which it is.

## Why cross-domain synthesis changes the verdict, the priority, or the next action

ATH-006's whole claim is about a host it has no other evidence from:
"this credential is being used from CLIENT7, where it has no session". Whether that matters
depends entirely on what happened at the destination -- an account authenticating from an
unusual host and then doing nothing is a mapped drive or a `runas /netonly`, the first false
positive ATH-006's own docstring lists. The endpoint rows on CLIENT9 are what turn "unusual
origin" into "unusual origin, then a shell".

The converse is sharper here than in M1: with two identity findings an analyst who reads only
the identity domain sees corroboration -- two rules agreeing -- and can still be entirely wrong
about severity, because both rules are reading **the same logon rows**. The endpoint rows are
the only independent evidence source in the case, which is exactly what condition 2 is asking
about.

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
| `1-credential-guessing` | 11 | eleven failed type 3 logons for client9 on CLIENT9 from CLIENT7 |
| `2-successful-logon` | 1 | success from a host where the account has no interactive session |
| `3-remote-service-execution` | 1 | services.exe starts cmd.exe with an ADMIN$ redirect |
| `4-discovery` | 2 | domain group enumeration and a mapped-drive listing |

Every injected record's native ref (`host=...;channel=...;record_id=...`) is in `labels.json` and in the top-level `MANIFEST.json`. Nothing in the telemetry marks a row as injected -- a marker inside a record would leak the answer key into the thing being measured.

