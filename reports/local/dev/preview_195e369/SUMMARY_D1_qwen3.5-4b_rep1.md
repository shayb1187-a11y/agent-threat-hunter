# D1 baseline summary: arm D1, `qwen3.5:4b`

Generated 2026-09-15T11:51:24+00:00 at `195e369` from 20 row file(s). MEASURED; no interpretation.

| aggregate | value |
| --- | --- |
| completed (strict: not degraded, 0 unparseable, 0 context refusals) | 17 / 20 (0.85) |
| meets >= 95% completion target | False |
| rows written / degraded | 20 / 3 |
| model calls / unparseable / context refusals | 120 / 0 / 0 |
| parse rate | 1.0 |
| total wall s | 4464.9 |
| median / p95 case wall s | 201.137 / 372.0 |
| planner / synthesis median call s | 11.88 / 141.753 |
| tokens total (prompt / completion) | 136086 (122178 / 13908) |
| median prompt / gen tok/s | 44.75 / 10.2 |
| min available RAM seen (GiB) | 0.44 |
| RAM guard events (refusals / overrides) / rows run under override | 11 (0 / 11) / 11 |
| evidence correctness min / all >= 0.99 | 1.0 / True |
| rejected claims total | 0 |
| planner steps chosen by model / multi-candidate | 100 / 100 |
| failure types | {"generation_cap": 3} |

## Per case

| case | arm label | status | calls | unparse | ctx ref | wall s | tokens | ec | rejected | coverage | facts/inf/hyp | model-chosen steps | degradation |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | --- |
| dedale_injected_dev:V10/CASE-001 | D1_local_single | complete | 6 | 0 | 0 | 193.208 | 7051 | 1.0 | 0 | 1.0 | 11/0/1 | 5 |  |
| dedale_injected_dev:V1/CASE-001 | D1_local_single | complete | 6 | 0 | 0 | 187.191 | 7081 | 1.0 | 0 | 1.0 | 11/0/1 | 5 |  |
| dedale_injected_dev:V2/CASE-001 | D1_local_single | complete | 6 | 0 | 0 | 183.856 | 6929 | 1.0 | 0 | 1.0 | 11/0/1 | 5 |  |
| dedale_injected_dev:V3/CASE-001 | D1_local_single | complete | 6 | 0 | 0 | 173.915 | 6531 | 1.0 | 0 | 1.0 | 9/0/1 | 5 |  |
| dedale_injected_dev:V4/CASE-001 | D1_local_single | complete | 6 | 0 | 0 | 202.725 | 7688 | 1.0 | 0 | 1.0 | 11/0/1 | 5 |  |
| dedale_injected_dev:V5/CASE-001 | D1_local_single | complete | 6 | 0 | 0 | 210.442 | 7025 | 1.0 | 0 | 1.0 | 11/0/1 | 5 |  |
| dedale_injected_dev:V6/CASE-001 | D1_local_single | complete | 6 | 0 | 0 | 209.687 | 7282 | 1.0 | 0 | 1.0 | 11/0/1 | 5 |  |
| dedale_injected_dev:V7/CASE-001 | D1_local_single | complete | 6 | 0 | 0 | 225.378 | 7249 | 1.0 | 0 | 1.0 | 11/0/1 | 5 |  |
| dedale_injected_dev:V8/CASE-001 | D1_local_single | complete | 6 | 0 | 0 | 222.578 | 7169 | 1.0 | 0 | 1.0 | 11/0/1 | 5 |  |
| dedale_injected_dev:V9/CASE-001 | D1_local_single | complete | 6 | 0 | 0 | 199.549 | 6843 | 1.0 | 0 | 1.0 | 11/0/1 | 5 |  |
| flaws_cloud/CASE-003 | D1_local_single_DEGRADED | complete | 6 | 0 | 0 | 372.0 | 7040 | 1.0 | 0 | 1.0 | 5/0/0 | 5 | response truncated at num_predict=2048 |
| flaws_cloud/CASE-020 | D1_local_single_DEGRADED | complete | 6 | 0 | 0 | 406.558 | 8161 | 1.0 | 0 | 1.0 | 7/0/0 | 5 | response truncated at num_predict=2048 |
| flaws_cloud/CASE-071 | D1_local_single | complete | 6 | 0 | 0 | 222.085 | 5964 | 1.0 | 0 | 1.0 | 5/0/3 | 5 |  |
| flaws_cloud/CASE-098 | D1_local_single | complete | 6 | 0 | 0 | 158.979 | 5951 | 1.0 | 0 | 1.0 | 7/0/1 | 5 |  |
| flaws_cloud/CASE-121 | D1_local_single_DEGRADED | complete | 6 | 0 | 0 | 362.377 | 7184 | 1.0 | 0 | 1.0 | 5/0/0 | 5 | response truncated at num_predict=2048 |
| flaws_cloud/CASE-141 | D1_local_single | complete | 6 | 0 | 0 | 233.452 | 7133 | 1.0 | 0 | 1.0 | 7/0/1 | 5 |  |
| flaws_cloud/CASE-186 | D1_local_single | complete | 6 | 0 | 0 | 189.281 | 5638 | 1.0 | 0 | 1.0 | 7/0/1 | 5 |  |
| flaws_cloud/CASE-199 | D1_local_single | complete | 6 | 0 | 0 | 151.151 | 5391 | 1.0 | 0 | 1.0 | 7/0/1 | 5 |  |
| flaws_cloud/CASE-221 | D1_local_single | complete | 6 | 0 | 0 | 176.224 | 6527 | 1.0 | 0 | 1.0 | 7/0/1 | 5 |  |
| flaws_cloud/CASE-252 | D1_local_single | complete | 6 | 0 | 0 | 184.237 | 6249 | 1.0 | 0 | 1.0 | 7/0/1 | 5 |  |
