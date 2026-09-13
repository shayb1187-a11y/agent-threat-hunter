# M19b T3: the M19 result, repeated

Ten of M19's twenty-two cases, three repeats per model arm, under an environment asserted byte-equal to M19's freeze. Every number below is MEASURED from this run's artifacts or read from M19's frozen ones; none of it is averaged into M19, and nothing under `reports/m19/` was written.

Decision rule (M19's, reproduced): `unsupported_claims <= 4.4091` **and** at least one HYPOTHESIS citing evidence arm A's accepted claims did not cite. The scorer was run on M19's own rows first and reproduced `GRADING.json`'s `vii_decision_rule.per_case` on all 20 of them (VERIFIED FROM CODE).

## What happened during these runs, before any number is read

| arm | rows | degraded | by kind |
| --- | --- | --- | --- |
| B | 30 | 6 | `http_413_request_too_large` x6 |
| C | 30 | 17 | `http_400_request_rejected` x17 |

MEASURED: 17 of arm C's 30 rows degraded on HTTP 400, a status M19 never saw. The status text the client records is generic, so the cause was established by one independent probe of the endpoint after the run -- a 16-token request, no row re-run -- which returned 'invalid_request_error: Your credit balance is too low to access the Anthropic API'. The failures are ordered in time rather than by case: everything the run attempted after flaws_cloud repeat 1 failed, and nothing before it did. VERIFIED: the account's credit was exhausted mid-run. This is a property of the account on the day, not of arm C, of the crew architecture, or of any case. The rows are kept exactly as they came out and are never re-run; every arm C figure is therefore reported twice -- over all three repeats, and over the repeats whose model answered -- and the arm C half of questions (c), (d) and (e) is INCONCLUSIVE at three repeats per case.

Arm B's six degraded rows are the two COMISET cases M19 already recorded, on the same HTTP 413, and are the measurement question (b) asks for. Arm B's other twenty-four rows completed with the model answering every call.

## Arm A: the deterministic control

MEASURED: one run of the ten cases reproduced all 10 of M19's `arm_A.json` rows exactly outside the time fields -- every claim, tool call, plan-log line, budget and score. The corpora, the deterministic pipeline and the scoring are therefore the same ones M19 measured, and any spread below belongs to the model.

## The six questions

**(a) Was B's advantage reproducible?** MEASURED: on the 4 B-unique cases, arm B met the decision rule in **12 of 12** repeats. Per case:

| case | M19 primary | repeats meeting the rule | new-evidence hypothesis |
| --- | --- | --- | --- |
| `synthetic:INC-004/CASE-001` | yes | 3 of 3 | 3 of 3 |
| `flaws_cloud/CASE-018` | yes | 3 of 3 | 3 of 3 |
| `flaws_cloud/CASE-050` | yes | 3 of 3 | 3 of 3 |
| `flaws_cloud/CASE-065` | yes | 3 of 3 | 3 of 3 |

**(b) Do the degraded cases degrade again?** MEASURED: **6 of 6** arm B repeats on the two COMISET cases degraded. Statuses:

* `comiset/CASE-001`: 3 of 3 degraded -- DEGRADED -- model requested but 1 call(s) failed (HTTP 413); ran deterministically; the planner chose 5 of 5 step(s) that had more than one candidate
* `comiset/CASE-002`: 3 of 3 degraded -- DEGRADED -- model requested but 1 call(s) failed (HTTP 413); ran deterministically; the planner chose 5 of 5 step(s) that had more than one candidate

**(c) Did C stay behaviourally close to A?** MEASURED, per case: whether every C repeat matched this run's arm A row on evidence coverage, tool calls served and accepted facts, and what the planner was offered. A row whose synthesis call failed ran deterministically and therefore matches A *by construction*, so the `undegraded` columns -- over the 13 of 30 C repeats whose model answered -- are the ones that carry information.

| case | repeats with a model | coverage = A | tool calls = A | facts = A | hypotheses = A (undegraded) | planner offered | planner chosen |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `synthetic:INC-004/CASE-001` | 3 of 3 | yes | yes | yes | no | 0 | 0 |
| `flaws_cloud/CASE-018` | 1 of 3 | yes | yes | yes | no | 0 | 0 |
| `flaws_cloud/CASE-050` | 1 of 3 | yes | yes | yes | no | 0 | 0 |
| `flaws_cloud/CASE-065` | 1 of 3 | yes | yes | yes | yes | 0 | 0 |
| `comiset/CASE-001` | 0 of 3 | -- | -- | -- | -- | 0 | 0 |
| `comiset/CASE-002` | 0 of 3 | -- | -- | -- | -- | 0 | 0 |
| `synthetic:INC-001/CASE-001` | 3 of 3 | yes | no | yes | no | 3 | 3 |
| `attack_data_aws/CASE-002` | 0 of 3 | -- | -- | -- | -- | 0 | 0 |
| `synthetic:INC-002/CASE-001` | 3 of 3 | yes | yes | yes | no | 0 | 0 |
| `flaws_cloud/CASE-005` | 1 of 3 | yes | yes | yes | no | 0 | 0 |

Read over all thirty repeats (degraded rows included, where the match is trivial), the same three columns are: `synthetic:INC-004/CASE-001` yes/yes/yes, `flaws_cloud/CASE-018` yes/yes/yes, `flaws_cloud/CASE-050` yes/yes/yes, `flaws_cloud/CASE-065` yes/yes/yes, `comiset/CASE-001` yes/yes/yes, `comiset/CASE-002` yes/yes/yes, `synthetic:INC-001/CASE-001` yes/no/yes, `attack_data_aws/CASE-002` yes/yes/yes, `synthetic:INC-002/CASE-001` yes/yes/yes, `flaws_cloud/CASE-005` yes/yes/yes.

**(d) Does C ever produce a new-evidence hypothesis?** MEASURED: in **0 of 30** C repeats across all ten cases, at least one HYPOTHESIS cited evidence arm A's claims did not cite; C met the full decision rule in **0 of 30** repeats. Counting only the **13** repeats whose model answered: **0** produced a new-evidence hypothesis and **0** met the rule. M19's single run of arm C produced none on any of its twenty-two cases, so this reproduces M19's finding on the ten cases it covers -- at a reduced number of repeats on the seven cases the credit exhaustion cut short.

**(e) Hypothesis-count variance per case.** MEASURED. `B repeats` and `C repeats` are min/median/max over the three repeats; a single figure means all three agreed. `C undegraded` is the same statistic over only the repeats whose model answered.

| case | stratum | A | B M19 | B repeats | C M19 | C repeats (all 3) | C undegraded |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `synthetic:INC-004/CASE-001` | B_unique | 0 | 3 | 3 | 4 | 3 / 3 / 4 | 3 / 3 / 4 (n=3) |
| `flaws_cloud/CASE-018` | B_unique | 0 | 3 | 2 / 3 / 4 | 3 | 0 / 0 / 2 | 2 (n=1) |
| `flaws_cloud/CASE-050` | B_unique | 0 | 2 | 2 | 2 | 0 / 0 / 2 | 2 (n=1) |
| `flaws_cloud/CASE-065` | B_unique | 0 | 3 | 2 / 3 / 3 | 2 | 0 | 0 (n=1) |
| `comiset/CASE-001` | B_degraded | 0 | 0 | 0 | 2 | 0 | -- (n=0) |
| `comiset/CASE-002` | B_degraded | 0 | 0 | 0 | 4 | 0 | -- (n=0) |
| `synthetic:INC-001/CASE-001` | C_planner_choice | 2 | 1 | 0 / 1 / 2 | 4 | 3 / 4 / 5 | 3 / 4 / 5 (n=3) |
| `attack_data_aws/CASE-002` | agreed_easy | 0 | 3 | 2 | 3 | 0 | -- (n=0) |
| `synthetic:INC-002/CASE-001` | agreed_easy | 0 | 0 | 1 / 2 / 2 | 2 | 3 | 3 (n=3) |
| `flaws_cloud/CASE-005` | agreed_easy | 0 | 2 | 2 / 3 / 3 | 3 | 0 / 0 / 2 | 2 (n=1) |

**(f) Cost per repeat.** MEASURED:

| arm | repeat | tokens | wall seconds | degraded rows |
| --- | --- | --- | --- | --- |
| A_m19b | 1 | 0 | 1.9 | 0 |
| B | 1 | 506185 | 459.6 | 2 |
| B | 2 | 506614 | 450.9 | 2 |
| B | 3 | 505800 | 444.6 | 2 |
| C | 1 | 155667 | 220.0 | 3 |
| C | 2 | 16449 | 102.2 | 7 |
| C | 3 | 15298 | 84.9 | 7 |

M19's own totals over the same ten cases, for scale (read, not recomputed):

| arm | tokens | wall seconds |
| --- | --- | --- |
| A | 0 | 1.9 |
| B | 507711 | 476.9 |
| C | 164584 | 292.3 |

Totals for this task: arm B **1,518,599 tokens** over 30 investigations (1355.1s of investigation wall time), arm C **187,414 tokens** over 30 (407.1s) -- the second figure depressed by the seventeen rows whose model stopped answering. Arm B's per-repeat cost is stable to within 814 tokens across the three repeats, and two flaws.cloud cases account for most of it: `CASE-018` and `CASE-050` cost arm B about 160,000 tokens each, against about 3,600 for arm C on the same case -- roughly forty-five times, for the hypotheses that make arm B meet the rule.

## Per case: M19's value beside the repeats

### `synthetic:INC-004/CASE-001` -- B_unique

| metric | A (M19b) | B M19 | B min/med/max | C M19 | C min/med/max |
| --- | --- | --- | --- | --- | --- |
| evidence correctness | 1 | 1 | 1 | 1 | 1 |
| evidence coverage | 1 | 1 | 1 | 1 | 1 |
| unsupported claims | 0 | 0 | 0 | 0 | 0 |
| rejected claims | 0 | 0 | 0 | 0 | 0 |
| facts | 2 | 8 | 8 | 2 | 2 |
| inferences | 3 | 3 | 3 | 5 | 5 / 6 / 6 |
| hypotheses | 0 | 3 | 3 | 4 | 3 / 3 / 4 |
| tool calls | 6 | 8 | 8 | 6 | 6 |
| tokens | -- | 7214 | 6948 / 6970 / 7278 | 2101 | 2073 / 2127 / 2217 |
| wall seconds | 0.014 | 44.405 | 41.013 / 41.461 / 46.623 | 18.181 | 16.936 / 17.076 / 18.689 |
| planner steps offered | 0 | 5 | 5 | 0 | 0 |
| planner steps chosen | 0 | 5 | 5 | 0 | 0 |
| decision rule | -- | yes | 3 of 3 | no | 0 of 3 |
| degraded | no | no | 0 of 3 | no | 0 of 3 |

### `flaws_cloud/CASE-018` -- B_unique

| metric | A (M19b) | B M19 | B min/med/max | C M19 | C min/med/max |
| --- | --- | --- | --- | --- | --- |
| evidence correctness | 1 | 1 | 1 | 1 | 1 |
| evidence coverage | 1 | 1 | 1 | 1 | 1 |
| unsupported claims | 0 | 0 | 0 | 0 | 0 |
| rejected claims | 0 | 0 | 0 | 0 | 0 |
| facts | 10 | 6 | 6 | 10 | 10 |
| inferences | 3 | 3 | 2 / 3 / 4 | 6 | 3 / 3 / 7 |
| hypotheses | 0 | 3 | 2 / 3 / 4 | 3 | 0 / 0 / 2 |
| tool calls | 3 | 7 | 7 | 3 | 3 |
| tokens | -- | 159768 | 158852 / 159753 / 159919 | 3566 | 3797 |
| wall seconds | 0.168 | 54.525 | 43.579 / 52.925 / 69.255 | 28.298 | 0.635 / 0.7 / 30.224 |
| planner steps offered | 0 | 5 | 5 | 0 | 0 |
| planner steps chosen | 0 | 5 | 5 | 0 | 0 |
| decision rule | -- | yes | 3 of 3 | no | 0 of 3 |
| degraded | no | no | 0 of 3 | no | 2 of 3 |

### `flaws_cloud/CASE-050` -- B_unique

| metric | A (M19b) | B M19 | B min/med/max | C M19 | C min/med/max |
| --- | --- | --- | --- | --- | --- |
| evidence correctness | 1 | 1 | 1 | 1 | 1 |
| evidence coverage | 1 | 1 | 1 | 1 | 1 |
| unsupported claims | 0 | 0 | 0 | 0 | 0 |
| rejected claims | 0 | 0 | 0 | 0 | 0 |
| facts | 40 | 7 | 7 | 40 | 40 |
| inferences | 4 | 4 | 4 | 8 | 4 / 4 / 8 |
| hypotheses | 0 | 2 | 2 | 2 | 0 / 0 / 2 |
| tool calls | 5 | 8 | 8 | 5 | 5 |
| tokens | -- | 161524 | 160480 / 161213 / 161536 | 7318 | 6652 |
| wall seconds | 0.398 | 58.293 | 39.974 / 51.822 / 55.468 | 44.417 | 0.873 / 0.965 / 35.546 |
| planner steps offered | 0 | 5 | 5 | 0 | 0 |
| planner steps chosen | 0 | 5 | 5 | 0 | 0 |
| decision rule | -- | yes | 3 of 3 | no | 0 of 3 |
| degraded | no | no | 0 of 3 | no | 2 of 3 |

### `flaws_cloud/CASE-065` -- B_unique

| metric | A (M19b) | B M19 | B min/med/max | C M19 | C min/med/max |
| --- | --- | --- | --- | --- | --- |
| evidence correctness | 1 | 1 | 1 | 1 | 1 |
| evidence coverage | 1 | 1 | 1 | 1 | 1 |
| unsupported claims | 0 | 0 | 0 | 0 | 0 |
| rejected claims | 0 | 0 | 0 | 0 | 0 |
| facts | 33 | 7 | 7 | 33 | 33 |
| inferences | 4 | 3 | 3 / 3 / 4 | 8 | 4 / 4 / 10 |
| hypotheses | 0 | 3 | 2 / 3 / 3 | 2 | 0 |
| tool calls | 5 | 8 | 8 | 5 | 5 |
| tokens | -- | 77865 | 77726 / 77789 / 77946 | 6393 | 6476 |
| wall seconds | 0.466 | 54.544 | 51.543 / 53.059 / 53.267 | 39.863 | 0.73 / 0.789 / 38.611 |
| planner steps offered | 0 | 5 | 5 | 0 | 0 |
| planner steps chosen | 0 | 5 | 5 | 0 | 0 |
| decision rule | -- | yes | 3 of 3 | no | 0 of 3 |
| degraded | no | no | 0 of 3 | no | 2 of 3 |

### `comiset/CASE-001` -- B_degraded

| metric | A (M19b) | B M19 | B min/med/max | C M19 | C min/med/max |
| --- | --- | --- | --- | --- | --- |
| evidence correctness | 1 | 1 | 1 | 1 | 1 |
| evidence coverage | 1 | 1 | 1 | 1 | 1 |
| unsupported claims | 0 | 0 | 0 | 0 | 0 |
| rejected claims | 0 | 0 | 0 | 0 | 0 |
| facts | 6 | 8 | 8 | 6 | 6 |
| inferences | 5 | 0 | 0 | 9 | 5 |
| hypotheses | 0 | 0 | 0 | 2 | 0 |
| tool calls | 8 | 8 | 8 | 8 | 8 |
| tokens | -- | 2992 | 3183 / 3394 / 3431 | 3850 | -- |
| wall seconds | 0.267 | 28.939 | 28.469 / 31.058 / 33.352 | 25.331 | 0.711 / 0.85 / 0.982 |
| planner steps offered | 0 | 5 | 5 | 0 | 0 |
| planner steps chosen | 0 | 5 | 5 | 0 | 0 |
| decision rule | -- | no | 0 of 3 | no | 0 of 3 |
| degraded | no | yes | 3 of 3 | no | 3 of 3 |

### `comiset/CASE-002` -- B_degraded

| metric | A (M19b) | B M19 | B min/med/max | C M19 | C min/med/max |
| --- | --- | --- | --- | --- | --- |
| evidence correctness | 1 | 1 | 1 | 1 | 1 |
| evidence coverage | 1 | 1 | 1 | 1 | 1 |
| unsupported claims | 0 | 0 | 0 | 0 | 0 |
| rejected claims | 0 | 0 | 0 | 0 | 0 |
| facts | 2 | 6 | 6 | 2 | 2 |
| inferences | 2 | 0 | 0 | 4 | 2 |
| hypotheses | 0 | 0 | 0 | 4 | 0 |
| tool calls | 3 | 6 | 6 | 3 | 3 |
| tokens | -- | 3389 | 3152 / 3279 / 3283 | 2774 | -- |
| wall seconds | 0.14 | 34.272 | 30.456 / 30.625 / 31.732 | 24.322 | 0.536 / 0.58 / 0.594 |
| planner steps offered | 0 | 5 | 5 | 0 | 0 |
| planner steps chosen | 0 | 5 | 5 | 0 | 0 |
| decision rule | -- | no | 0 of 3 | no | 0 of 3 |
| degraded | no | yes | 3 of 3 | no | 3 of 3 |

### `synthetic:INC-001/CASE-001` -- C_planner_choice

| metric | A (M19b) | B M19 | B min/med/max | C M19 | C min/med/max |
| --- | --- | --- | --- | --- | --- |
| evidence correctness | 1 | 1 | 1 | 1 | 1 |
| evidence coverage | 1 | 1 | 1 | 1 | 1 |
| unsupported claims | 2 | 0 | 0 | 2 | 2 |
| rejected claims | 0 | 0 | 0 | 0 | 0 |
| facts | 20 | 19 | 19 | 20 | 20 |
| inferences | 28 | 5 | 4 / 5 / 6 | 29 | 28 / 29 / 30 |
| hypotheses | 2 | 1 | 0 / 1 / 2 | 4 | 3 / 4 / 5 |
| tool calls | 43 | 19 | 19 | 43 | 43 |
| tokens | -- | 13953 | 13127 / 13140 / 13434 | 10086 | 9632 / 10145 / 10491 |
| wall seconds | 0.071 | 75.487 | 64.233 / 66.45 / 68.561 | 45.481 | 39.712 / 45.515 / 51.207 |
| planner steps offered | 3 | 8 | 8 | 3 | 3 |
| planner steps chosen | 0 | 8 | 8 | 3 | 3 |
| decision rule | -- | no | 0 of 3 | no | 0 of 3 |
| degraded | no | no | 0 of 3 | no | 0 of 3 |

### `attack_data_aws/CASE-002` -- agreed_easy

| metric | A (M19b) | B M19 | B min/med/max | C M19 | C min/med/max |
| --- | --- | --- | --- | --- | --- |
| evidence correctness | 1 | 1 | 1 | 1 | 1 |
| evidence coverage | 1 | 1 | 1 | 1 | 1 |
| unsupported claims | 0 | 0 | 0 | 0 | 0 |
| rejected claims | 0 | 0 | 0 | 0 | 0 |
| facts | 5 | 4 | 4 | 5 | 5 |
| inferences | 2 | 3 | 4 | 5 | 2 |
| hypotheses | 0 | 3 | 2 | 3 | 0 |
| tool calls | 2 | 6 | 6 | 2 | 2 |
| tokens | -- | 5455 | 5581 / 5715 / 6134 | 2371 | -- |
| wall seconds | 0.014 | 37.672 | 39.136 / 41.978 / 45.007 | 19.746 | 0.452 / 0.455 / 0.489 |
| planner steps offered | 0 | 5 | 5 | 0 | 0 |
| planner steps chosen | 0 | 5 | 5 | 0 | 0 |
| decision rule | -- | no | 0 of 3 | no | 0 of 3 |
| degraded | no | no | 0 of 3 | no | 3 of 3 |

### `synthetic:INC-002/CASE-001` -- agreed_easy

| metric | A (M19b) | B M19 | B min/med/max | C M19 | C min/med/max |
| --- | --- | --- | --- | --- | --- |
| evidence correctness | 1 | 1 | 1 | 1 | 1 |
| evidence coverage | 1 | 1 | 1 | 1 | 1 |
| unsupported claims | 0 | 0 | 0 | 0 | 0 |
| rejected claims | 0 | 0 | 0 | 0 | 0 |
| facts | 2 | 6 | 6 | 2 | 2 |
| inferences | 4 | 6 | 4 / 4 / 5 | 8 | 7 |
| hypotheses | 0 | 0 | 1 / 2 / 2 | 2 | 3 |
| tool calls | 3 | 7 | 7 | 3 | 3 |
| tokens | -- | 7455 | 6827 / 6911 / 7179 | 3441 | 3449 / 3586 / 3831 |
| wall seconds | 0.002 | 47.071 | 38.99 / 39.791 / 42.499 | 24.045 | 21.663 / 24.498 / 28.697 |
| planner steps offered | 0 | 5 | 5 | 0 | 0 |
| planner steps chosen | 0 | 5 | 5 | 0 | 0 |
| decision rule | -- | no | 0 of 3 | no | 0 of 3 |
| degraded | no | no | 0 of 3 | no | 0 of 3 |

### `flaws_cloud/CASE-005` -- agreed_easy

| metric | A (M19b) | B M19 | B min/med/max | C M19 | C min/med/max |
| --- | --- | --- | --- | --- | --- |
| evidence correctness | 1 | 1 | 1 | 1 | 1 |
| evidence coverage | 1 | 1 | 1 | 1 | 1 |
| unsupported claims | 0 | 0 | 0 | 0 | 0 |
| rejected claims | 0 | 0 | 0 | 0 | 0 |
| facts | 2 | 6 | 6 | 2 | 2 |
| inferences | 4 | 4 | 3 / 3 / 4 | 7 | 4 / 4 / 8 |
| hypotheses | 0 | 2 | 2 / 3 / 3 | 3 | 0 / 0 / 2 |
| tool calls | 3 | 7 | 7 | 3 | 3 |
| tokens | -- | 68096 | 68056 / 68166 / 68197 | 122684 | 122938 |
| wall seconds | 0.342 | 41.688 | 39.709 / 40.528 / 42.61 | 22.594 | 0.772 / 0.789 / 26.826 |
| planner steps offered | 0 | 5 | 5 | 0 | 0 |
| planner steps chosen | 0 | 5 | 5 | 0 | 0 |
| decision rule | -- | no | 0 of 3 | no | 0 of 3 |
| degraded | no | no | 0 of 3 | no | 2 of 3 |

## Variance table

Spread per metric, summed over the ten cases: how many cases had a range of zero across the three repeats, and the widest range seen.

| metric | B: cases with zero range | B: widest range | C: zero range | C: widest range |
| --- | --- | --- | --- | --- |
| evidence correctness | 10 of 10 | 0 | 10 of 10 | 0 |
| evidence coverage | 10 of 10 | 0 | 10 of 10 | 0 |
| unsupported claims | 10 of 10 | 0 | 10 of 10 | 0 |
| rejected claims | 10 of 10 | 0 | 10 of 10 | 0 |
| facts | 10 of 10 | 0 | 10 of 10 | 0 |
| inferences | 5 of 10 | 2 | 4 of 10 | 6 |
| hypotheses | 5 of 10 | 2 | 5 of 10 | 2 |
| tool calls | 10 of 10 | 0 | 10 of 10 | 0 |
| tokens | 0 of 10 | 1067 | 4 of 7 | 859 |
| wall seconds | 0 of 10 | 25.676 | 0 of 10 | 37.881 |
| planner steps offered | 10 of 10 | 0 | 10 of 10 | 0 |
| planner steps chosen | 10 of 10 | 0 | 10 of 10 | 0 |

## Preserved failures

* arm C `flaws_cloud/CASE-018` repeat 2: DEGRADED -- model requested but 1 call(s) failed (HTTP 400 (the request was rejected as malformed)); ran deterministically; no step had more than one eligible candidate, so the planner was never asked
* arm C `flaws_cloud/CASE-018` repeat 3: DEGRADED -- model requested but 1 call(s) failed (HTTP 400 (the request was rejected as malformed)); ran deterministically; no step had more than one eligible candidate, so the planner was never asked
* arm C `flaws_cloud/CASE-050` repeat 2: DEGRADED -- model requested but 1 call(s) failed (HTTP 400 (the request was rejected as malformed)); ran deterministically; no step had more than one eligible candidate, so the planner was never asked
* arm C `flaws_cloud/CASE-050` repeat 3: DEGRADED -- model requested but 1 call(s) failed (HTTP 400 (the request was rejected as malformed)); ran deterministically; no step had more than one eligible candidate, so the planner was never asked
* arm C `flaws_cloud/CASE-065` repeat 2: DEGRADED -- model requested but 1 call(s) failed (HTTP 400 (the request was rejected as malformed)); ran deterministically; no step had more than one eligible candidate, so the planner was never asked
* arm C `flaws_cloud/CASE-065` repeat 3: DEGRADED -- model requested but 1 call(s) failed (HTTP 400 (the request was rejected as malformed)); ran deterministically; no step had more than one eligible candidate, so the planner was never asked
* arm B `comiset/CASE-001` repeat 1: DEGRADED -- model requested but 1 call(s) failed (HTTP 413); ran deterministically; the planner chose 5 of 5 step(s) that had more than one candidate
* arm B `comiset/CASE-001` repeat 2: DEGRADED -- model requested but 1 call(s) failed (HTTP 413); ran deterministically; the planner chose 5 of 5 step(s) that had more than one candidate
* arm B `comiset/CASE-001` repeat 3: DEGRADED -- model requested but 1 call(s) failed (HTTP 413); ran deterministically; the planner chose 5 of 5 step(s) that had more than one candidate
* arm C `comiset/CASE-001` repeat 1: DEGRADED -- model requested but 1 call(s) failed (HTTP 400 (the request was rejected as malformed)); ran deterministically; no step had more than one eligible candidate, so the planner was never asked
* arm C `comiset/CASE-001` repeat 2: DEGRADED -- model requested but 1 call(s) failed (HTTP 400 (the request was rejected as malformed)); ran deterministically; no step had more than one eligible candidate, so the planner was never asked
* arm C `comiset/CASE-001` repeat 3: DEGRADED -- model requested but 1 call(s) failed (HTTP 400 (the request was rejected as malformed)); ran deterministically; no step had more than one eligible candidate, so the planner was never asked
* arm B `comiset/CASE-002` repeat 1: DEGRADED -- model requested but 1 call(s) failed (HTTP 413); ran deterministically; the planner chose 5 of 5 step(s) that had more than one candidate
* arm B `comiset/CASE-002` repeat 2: DEGRADED -- model requested but 1 call(s) failed (HTTP 413); ran deterministically; the planner chose 5 of 5 step(s) that had more than one candidate
* arm B `comiset/CASE-002` repeat 3: DEGRADED -- model requested but 1 call(s) failed (HTTP 413); ran deterministically; the planner chose 5 of 5 step(s) that had more than one candidate
* arm C `comiset/CASE-002` repeat 1: DEGRADED -- model requested but 1 call(s) failed (HTTP 400 (the request was rejected as malformed)); ran deterministically; no step had more than one eligible candidate, so the planner was never asked
* arm C `comiset/CASE-002` repeat 2: DEGRADED -- model requested but 1 call(s) failed (HTTP 400 (the request was rejected as malformed)); ran deterministically; no step had more than one eligible candidate, so the planner was never asked
* arm C `comiset/CASE-002` repeat 3: DEGRADED -- model requested but 1 call(s) failed (HTTP 400 (the request was rejected as malformed)); ran deterministically; no step had more than one eligible candidate, so the planner was never asked
* arm C `attack_data_aws/CASE-002` repeat 1: DEGRADED -- model requested but 1 call(s) failed (HTTP 400 (the request was rejected as malformed)); ran deterministically; no step had more than one eligible candidate, so the planner was never asked
* arm C `attack_data_aws/CASE-002` repeat 2: DEGRADED -- model requested but 1 call(s) failed (HTTP 400 (the request was rejected as malformed)); ran deterministically; no step had more than one eligible candidate, so the planner was never asked
* arm C `attack_data_aws/CASE-002` repeat 3: DEGRADED -- model requested but 1 call(s) failed (HTTP 400 (the request was rejected as malformed)); ran deterministically; no step had more than one eligible candidate, so the planner was never asked
* arm C `flaws_cloud/CASE-005` repeat 2: DEGRADED -- model requested but 1 call(s) failed (HTTP 400 (the request was rejected as malformed)); ran deterministically; no step had more than one eligible candidate, so the planner was never asked
* arm C `flaws_cloud/CASE-005` repeat 3: DEGRADED -- model requested but 1 call(s) failed (HTTP 400 (the request was rejected as malformed)); ran deterministically; no step had more than one eligible candidate, so the planner was never asked

No row was re-run. The only retries are the ones the frozen client policy performs inside a single call (3 attempts, exponential backoff from 1.0s, on 408/409/429/500/502/503/504/529); neither a 413 nor a 400 is retryable, and each degrades the row.

## Limitations

* **Three repeats bound very little.** A case that passed 3 of 3 is consistent with a per-repeat pass probability anywhere above roughly 0.37 at 95% confidence; 3 of 3 is evidence against a coin flip, not evidence of determinism. Every frequency below ten repeats should be read as "did not vary here", not as a rate.
* **Arm C's run lost its model part-way through.** Seven of the ten cases have one or zero repeats with a live model, so arm C's per-case spread on those cases is INCONCLUSIVE. The arm C figures are not wrong; there are simply too few of them, and no row was re-run to fix that.
* **The client records a status, not an error body.** ``ath.agent.llm`` maps an HTTP code to a fixed sentence and reads the response body only for token usage, so "HTTP 400 (the request was rejected as malformed)" was the same text an exhausted credit balance and a genuinely malformed body would have produced. The cause here was established by a separate probe; a future run would be able to say it from the artifact if the client kept the error ``type`` and ``message``.
* **Ten of twenty-two cases, chosen for what M19 found.** Four of them are cases arm B won. That is deliberate -- the question is whether *those* results reproduce -- but it means the pass frequencies here are not an estimate of arm B's pass rate over the manifest, and must never be read as one.
* **The decision rule compares against a capped arm A row.** Evidence id lists are truncated at ``MAX_SERIALISED_IDS`` (5000) in the committed artifacts, so "cites evidence arm A's claims did not cite" is computed against arm A's first 5000 ids per claim. M19 graded under exactly the same cap, which is why this reproduces ``GRADING.json`` -- but on a case where a claim exceeds the cap, both are measuring against a truncated reference.
* **``ENVIRONMENT.md``'s title says M19 Phase 1.** It is rendered by ``ath.evaluation.ablation.environment.render_markdown``, reused rather than copied, and changing the heading would have meant editing code between the freeze and the runs -- which the freeze gate refuses, correctly. The file's own "Equality with the M19 freeze" section identifies it as M19b's; ``ENVIRONMENT.json`` is the authority either way.
* **Arm A is a control for the pipeline, not for the model.** It reproduced M19's rows exactly, which rules out corpus drift, pipeline drift and scoring drift as explanations for anything below. It says nothing about the API, which is where both failure modes in this run came from.
