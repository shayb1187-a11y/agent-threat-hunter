# Local model probe: `qwen3.5:4b`

Generated 2026-09-15T09:40:49+00:00 at `23a347d`. Every number is MEASURED on this machine by `scripts/local_probe.py`. Every call of a shape sends a *different* prompt of the same size, so no call is served from the daemon's prompt cache; the first call of each shape is the cold call (it pays the model load) and is reported apart from the warm ones.

## What ran

| setting | value |
| --- | --- |
| provider / model | ollama / qwen3.5:4b |
| digest | 2a654d98e6fba55d452b7043684e9b57a947e393bbffa62485a7aac05ee4eefd |
| quantisation / size | Q4_K_M / 4.7B |
| daemon version | 0.33.3 |
| sampling | {"temperature": 0.0, "seed": 0} |
| think | False |
| format | json |
| num_ctx / num_predict cap | 10240 / 2048 |
| synthesis bound (bytes/claim) | 4096 |
| RAM at preflight (GiB) / floor (GiB) | 1.73 / 4.50 |
| prompts identical to the frozen ones | True |

## Shape: planner

System 395 chars, user 785 chars (785 bytes), 5 distinct prompts; `max_tokens` requested 8192, `num_predict` sent 2048.

| call | wall s | load s | prompt-eval s | eval s | prompt tok/s | gen tok/s | prompt tokens | est. tokens | gen tokens | parsed | RAM before GiB | RAM after GiB |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| cold | 9.675 | 0.005 | 6.213 | 3.001 | 50.2 | 11.0 | 312 | 394 | 33 | yes | 1.73 | 1.93 |
| warm 1 | 10.251 | 0.005 | 7.314 | 2.867 | 42.7 | 11.5 | 312 | 394 | 33 | yes | 1.93 | 1.83 |
| warm 2 | 10.656 | 0.004 | 6.654 | 3.952 | 46.9 | 11.9 | 312 | 394 | 47 | yes | 1.83 | 1.75 |
| warm 3 | 10.946 | 0.005 | 6.75 | 4.121 | 46.2 | 11.4 | 312 | 394 | 47 | yes | 1.75 | 1.64 |
| warm 4 | 10.401 | 0.003 | 6.918 | 3.416 | 45.1 | 11.4 | 312 | 394 | 39 | yes | 1.64 | 1.54 |

| aggregate | value |
| --- | --- |
| parse rate | 1.0 |
| median wall s (all / warm) | 10.401 / 10.529 |
| cold wall s (of which load) | 9.675 (0.005) |
| median prompt tok/s (warm) | 45.65 |
| median gen tok/s (warm) | 11.45 |
| estimated / measured prompt tokens | 394 / 312 (ratio 1.263) |
| min RAM seen (GiB) | 1.54 |

## Shape: synthesis

System 787 chars, user 17471 chars (17471 bytes), 5 distinct prompts; `max_tokens` requested 8192, `num_predict` sent 2048.

| call | wall s | load s | prompt-eval s | eval s | prompt tok/s | gen tok/s | prompt tokens | est. tokens | gen tokens | parsed | RAM before GiB | RAM after GiB |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| cold | 76.74 | 0.006 | 0.415 | 76.109 | 12342.2 | 8.5 | 5122 | 6087 | 647 | yes | 1.54 | 2.29 |
| warm 1 | 276.981 | 0.005 | 200.992 | 75.709 | 25.5 | 5.7 | 5122 | 6087 | 431 | yes | 2.29 | 1.91 |
| warm 2 | 367.691 | 0.006 | 222.554 | 144.777 | 23.0 | 5.9 | 5122 | 6087 | 856 | yes | 1.91 | 2.17 |
| warm 3 | 272.994 | 0.006 | 134.221 | 138.347 | 38.2 | 8.0 | 5122 | 6087 | 1104 | yes | 2.17 | 2.16 |
| warm 4 | 324.235 | 0.004 | 154.888 | 169.148 | 33.1 | 6.6 | 5122 | 6087 | 1118 | yes | 2.16 | 1.76 |

| aggregate | value |
| --- | --- |
| parse rate | 1.0 |
| median wall s (all / warm) | 276.981 / 300.608 |
| cold wall s (of which load) | 76.74 (0.006) |
| median prompt tok/s (warm) | 29.3 |
| median gen tok/s (warm) | 6.25 |
| estimated / measured prompt tokens | 6087 / 5122 (ratio 1.188) |
| min RAM seen (GiB) | 1.54 |

## Prompt linkage

sha256 of each string this probe sent, beside the hash the M19b freeze recorded.

| string | used | frozen | same |
| --- | --- | --- | --- |
| planner_system | c8bca1694a01 | c8bca1694a01 | True |
| synthesis_system | 9d1a547b0006 | 9d1a547b0006 | True |
| planner_user_template | 9136d5d63c5a | 9136d5d63c5a | True |
| synthesis_user_template | e15896466418 | e15896466418 | True |

