# ATH-005: the "follow-up" success can precede the last failure

Status: **characterised, deliberately not fixed** (2026-09-13). Classification:
**detection semantics**, not presentation. Reach into the frozen M19 manifest: **one of 22
cases**. Fix deferred to a post-M19 re-freeze. Scripts that measured this:
`scripts/investigations/ath005_reach.py`, `ath005_securitymokey.py`, `ath005_m19_impact.py`
(read-only over `data/external`; run `python scripts/investigations/ath005_reach.py --flaws`).

## The defect (VERIFIED FROM CODE, `src/ath/hunting/rules/logon_rules.py`)

```python
follow_up = successes[... & (successes["timestamp"] >= burst_start)
                        & (successes["timestamp"] <= burst_end + bruteforce_success_window)]
win = follow_up.iloc[0]          # first success at or after burst_START
severity = Severity.CRITICAL     # gated on follow_up being non-empty
metadata["succeeded"] = not follow_up.empty
```

The lower bound is the burst's *start*, so a success interleaved with the failures is
selected as "the success that followed", the interval `win - burst_end` goes negative,
severity becomes CRITICAL, `succeeded` becomes True, the T1078 mapping is asserted
(`mapper.py`, `_bruteforce_succeeded` reads `metadata["succeeded"]`), and the in-burst
success's event id is appended to the finding's evidence. Four downstream facts change,
not one string.

## Measured reach (default `HuntConfig`, ATH-005 alone)

| corpus | findings | succeeded | CRITICAL | negative interval |
| ------ | -------: | --------: | -------: | ----------------: |
| synthetic `data/raw` | 1 | 1 (+204 s) | 1 | 0 |
| `tests/fixtures/real_shaped/cloudtrail_shaped` | 1 | 0 | 0 | 0 |
| flaws.cloud (read-only tar) | 36 | 1 | 1 | **1** |
| standard suite INC-001..005 | 2 | 1 | 1 | 0 |

The one case: flaws.cloud, `SecurityMokey` from `255.253.125.115`, burst 2017-05-26
22:25:09 to 22:29:16 (53 failures in 247 s); picked follow-up `cloudtrail-logon-002675` at
22:26:48 (**-148 s**); 118 successes inside the burst; 210 successes strictly after
`burst_end` within the 15-minute window, first at **+558 s** (`cloudtrail-logon-002823`).

## Reach into M19 (MEASURED, verified twice)

* `reports/m19/ablation/scripted/arm_B.json` carries the statement "A successful logon
  followed at 22:26:48, -148s after the last failure" twice, both under
  `corpus=flaws_cloud`, `case_id=CASE-005`.
* `reports/m19/ablation/MANIFEST.json`: three of the 22 cases carry an ATH-005 finding
  (`synthetic:INC-001/CASE-001`, `synthetic:INC-002/CASE-001`, `flaws_cloud/CASE-005`).
  Only `flaws_cloud/CASE-005` is affected: its frozen `evidence_ids` (54) contain
  `cloudtrail-logon-002675` and not `cloudtrail-logon-002823`.
* `reports/m18/cloud_representation/flaws_cloud.json` carries the same string, so the M18
  freeze is touched too.

For that case the correct fix would **not** flip severity or `succeeded` (210 genuine
post-burst successes exist): it would change the interval sign, the reason text, and one
evidence event id. The two synthetic manifest cases are unaffected. The severity-flipping
shape (a burst whose only success is interleaved) occurs in none of the four corpora:
HYPOTHESIS that it is rare, MEASURED that it is absent here.

## The invariant the fix must satisfy

> The success that "follows" a burst is the first success from the same
> `(device, user, source_ip)` strictly after `burst_end` and within
> `bruteforce_success_window`. A success at or before `burst_end` is a different
> observation (the credential was valid while guessing continued) and is reported as such,
> counted in metadata and named in the reason, without setting `succeeded` or promoting
> severity.

## Why it is not fixed today

The user's rule for the day: a semantics change that reaches a frozen M19 case is not made
before the preregistered experiment is scored. A quiet rule edit would also leave
`MANIFEST.json` describing evidence the rule no longer cites; no test re-derives the
manifest from data, so nothing would flag the drift.

## How it should land, after M19 is scored

1. Fix the lower bound to `> burst_end`; add `successes_during_burst` to metadata and to
   the reason text; severity and `succeeded` driven only by a genuine follow-up.
2. Tests (exact regression at -148 s; genuine follow-up +30 s; both inside and after;
   success exactly at `burst_end`, pinned; success after the window). Meta-assertion that
   no ATH-005 reason on the synthetic dataset or the shaped CloudTrail fixture contains a
   negative seconds value.
3. Re-freeze M19 deliberately: regenerate `MANIFEST.json` and the scripted arm artifacts,
   record `flaws_cloud/CASE-005`'s evidence delta (`...002675` -> `...002823`) in the
   freeze notes, and re-run `python scripts/m19_ablation.py freeze`.
4. Annotate `reports/m18/cloud_representation/flaws_cloud.json`'s report, do not edit the
   frozen artifact.
