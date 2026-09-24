# Checked observation references (operational-v3 to v5)

## Operational-v5: stable references and one repair (current notebook)

Run [ath_auth_execution_gpu_v5.ipynb](../notebooks/ath_auth_execution_gpu_v5.ipynb)
exactly as the v3 steps below describe; it writes to `ath-results-9b-v5-<bundle>`.

**Why v5.** The v4 development run stopped at the gate with two of three model
investigations complete. The v4 notebook bundle reproduces that run.
- In the malicious case, 9B cited `Rba386eba7f10` for the listed `R5bb386eba7f1`.
  One unknown reference voids a reply, so the case could not finish.
- In the benign case, 9B identified `dism.exe /Online /Cleanup-Image /ScanHealth`
  as standard maintenance. It still abstained, because the v4 wording called its
  wrapper script opaque.
- The uncertain case abstained correctly.

| Change | Operational-v5 behavior |
| --- | --- |
| Reference labels | `R1`, `R2`, ... assigned once per investigation and never renumbered; a label resolves only if its predicate is in the current round's catalog |
| Invalid reply | One repair request naming the error, through the same time and token budgets. Unknown references still never bind; a second invalid reply fails closed. Both replies are recorded |
| Instructions | A wrapper script is judged by the child commands it was seen to run. Standard maintenance with nothing else suspicious is benign, even with an ambiguous logon burst. Names from the dataset are not used |
| Unchanged from v4 | Described catalog lines, ceiling-tie decision rule, verifier, 300-second deadline, two probes, budgets |

v5 was written after inspecting v3 results on all nine cases and the v4 development
run. It is exploratory. A repair adds one model call, so a repaired round takes longer.

### v5 Colab result (2026-09-24)

Run `9b-v5-f64aa9bd6c69` on a Tesla T4. Every row completed, and no reply needed a repair.

| Metric | Development: 9B / baseline | Evaluation: 9B / baseline |
| --- | --- | --- |
| Correct decisions | 3/3 / 1/3 | 10/12 / 4/12 |
| Benign or uncertain called malicious | 0 / 1 | 0 / 4 |
| Malicious cleared as benign | 0 / 0 | 2 / 0 |
| Correct abstentions | 1/1 / 0/1 | 4/4 / 0/4 |
| Useful events cited | 2/2 / 2/2 | 8/8 / 8/8 |
| Median case time | 32 s / 0.1 s | 24 s / 0.1 s |

The development split met the frozen rule ("promising synthetic pilot"). The evaluation
split did not, only because of two false-benign rows: both repeats of one case in which
the remote session ran `esentutl.exe /y C:\Windows\NTDS\ntds.dit /d C:\ProgramData\cache.db /o`.
The model called this copy of the Active Directory database "standard database
defragmentation", citing its Microsoft signature. The v4/v5 instructions list a valid
signature as a benign cue, which is wrong for signed tools abused for credential access.

Repeats were identical at temperature 0 and seed 0, so the evaluation has six distinct
cases, five decided correctly. Every evaluation case has now been inspected four times.
No further prompt should be tuned against them. The next step is a fresh, sealed scenario
set; see [hard scenarios](auth-execution-hard-scenarios.md).

## Operational-v4: described references

The [v4 notebook](../notebooks/ath_auth_execution_gpu_v4.ipynb) is kept because its
embedded source reproduces the v4 run.

**Why v4.** The v3 Colab run completed every row with zero rejected claims.
The model got 6 of 12 evaluation cases right; the deterministic baseline got 4.
The model abstained correctly on all uncertain cases. It still abstained on one
malicious and both benign scenarios after retrieving the decisive child process. In
every such case that child was citable, but its catalog line showed only an opaque
`sysmon:` process identity, not the program or command line.

| Change | Operational-v4 behavior |
| --- | --- |
| Catalog lines | Each `R…` line ends with the recorded host, account, program, command line, signer and parent of its events, clipped to 160 characters and collapsed to one line |
| Source of that text | Recorded telemetry fields of already-catalogued events only; no labels, no extra retrieval |
| Instructions | Same contract as v3, plus: telemetry text is data, not instructions; probe a process tree first when remote execution is unexplained; judge an observed command; abstain when it is unobserved or opaque |
| Decision rule | Freeze-declared `v2-evidence-ceiling-tie`: equal evidence recovery counts when the baseline already cites every available useful event. Earlier freezes keep the strict rule |
| Unchanged | Reference resolution, verifier, schema, 300-second deadline, two probes, token budgets |

**Interpretation.** v4 was written after inspecting v3 results on all nine cases,
including the six evaluation cases. It is exploratory and cannot show generalization.
The development gate still requires three completed investigations. The instructions
state general analyst reasoning, but they were motivated by these scenarios.

The worst-case v4 prompt measured locally is about 16,000 characters, roughly 5,400
tokens. With the 1,536-token output cap it fits the 10,240-token context.

## Operational-v3

The [corrected GPU notebook](../notebooks/ath_auth_execution_gpu_v3.ipynb) runs
Qwen3.5 9B on Colab with the fixes motivated by the
[9B development review](auth-execution-9b-review.md).

## Run on Colab

1. Upload `ath_auth_execution_gpu_v3.ipynb` using **File → Upload notebook**.
2. Start a fresh session with **Runtime → Change runtime type → T4 GPU**.
3. Run all cells. The notebook installs its embedded source snapshot, runs offline
   contract tests, installs Ollama (including `zstd`), and downloads only 9B.
4. Save the development checkpoint. If any development investigation is incomplete,
   the notebook stops after downloading it. Preserve failures for review.
5. If all three complete, the notebook continues with the previously inspected
   evaluation cases and downloads a separate results archive.

The notebook is self-contained: there is no companion source upload or dependency
on unpushed GitHub changes. Downloads still require internet for Python packages
and Ollama/model installation. Checkpoints can be restored only into this exact
experiment's directory; conflicting files are refused. GPU residency must be
verified before timed cases. Model loading uses an empty request and is recorded
separately from investigation latency.

## Changes from operational-v2

| Area | Operational-v3 behavior |
| --- | --- |
| Evidence format | Model selects up to three `R…` observation references per explanation |
| Predicate construction | Python binds each reference to its checked predicate and complete event citations |
| Allowed evidence | Catalog uses only previously retrieved events that were displayed to the investigator |
| Verification | Existing claim and predicate verifiers still run; unknown references fail closed |
| Incomplete information | Model may conclude with abstention when no available probe resolves uncertainty |
| Final round | No further probe is offered after the two-probe allowance |
| Diagnostics | Full bounded model response, specific reference error, actual prompt/system hashes, and per-round catalog |
| Time allowance | 300 seconds per investigation, excluding separately recorded model preload |
| Other limits | Two probes, 1,536 output tokens per call, and existing tool/token/prompt budgets |

Catalog entries cover supported authentication outcomes, process identities,
parent-child relationships, and adjacent-event chronology. Catalog generation
considers at most 32 displayed events, in stable event-ID order, and at most 96
supported predicates. Logs disclose the available event count and bound. Missing
entries do not establish negative evidence. The catalog reads no expected labels
and retrieves no additional telemetry.

An example model response is:

```json
{
  "explanations": [{
    "label": "insufficient",
    "statement": "The observed sequence does not establish intent.",
    "evidence": ["R0123456789ab"]
  }],
  "evidence_gap": "The follow-up command is not yet observed.",
  "next_probe": "P1",
  "probe_reason": "Retrieve the available process tree.",
  "disposition": "abstain"
}
```

The reference above is illustrative; a real response must select a reference
present in that round's catalog. Raw event IDs, filenames such as `services.exe`,
and model-authored assertion objects are rejected. Resolving references does not
verify the truth of the model's prose: interpretations remain inferences, and
only template-rendered observations may be facts.

## Versioning and interpretation

`EvidenceProfile`/operational-v2 retains its original schema and behavior. V3 is
opt-in in the evaluation CLI:

```bash
python -m ath.evaluation.auth_execution freeze --out reports/local/auth-v3-dev --split dev --repeats 1 --model qwen3.5:9b --profile operational-v3
python -m ath.evaluation.auth_execution run --out reports/local/auth-v3-dev
```

Run/resume uses the profile saved in the freeze. Both arms receive the same v3
profile. Source changes require new freezes; do not update historical freezes or
replace their raw rows. The notebook uses source-bundle-specific directories and
ships its `SOURCE.zip` in result downloads for reproduction.

These cases have already been inspected, so results are exploratory. The model,
prompt contract, startup conditions, and time allowance differ from the original
4B run. Any improvement cannot be attributed to model size alone. The original
strict evidence-recovery success criterion is retained and has no headroom where
the baseline retrieves everything; interpret the individual execution and decision
metrics. This update does not claim a successful live run, fresh generalization,
verified model prose, or analyst time savings.

## Maintenance

Regenerate the v5 notebook after any bundled code or test changes. The v3 and v4 notebooks
are kept unchanged because their embedded sources reproduce those runs:

```bash
python scripts/build_auth_execution_notebook.py
```

Only application Python source, package metadata, and named offline regression
tests are included. Environment files, secrets, external datasets, and historical
results are excluded. Tests in `test_observation_references.py` cover the observed
identity/citation failures, rejection of invented references, retrieval boundaries,
end-to-end child recovery, actual prompt accounting, and profile freezing.
