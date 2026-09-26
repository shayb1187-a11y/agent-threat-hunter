# Real-case evaluation

> Windows telemetry excerpts in this document come from DEDALE (INRIA / IRISA, PIRAT team), CC BY 4.0, https://dedale.inria.fr/ (doi:10.57745/Y5JLDG). See [external datasets](project-reference.md#external-datasets).

`python -m ath.evaluation.real_cases` scores the deterministic specialists and bounded
D1 on incidents cut from real or emulated-testbed telemetry. Labels come from whoever
recorded or published the activity, not from ATH's generator. The scoring, sealed rows,
freeze checks and summary are the same as the
[auth-execution pilot](auth-execution-evaluation.md).

## 1. Write a case spec

One JSON file lists the cases. Start from
[the template](examples/real-cases-spec.example.json). Paths are relative to the spec.

| Field | Meaning |
| --- | --- |
| `source.kind` | `winlogbeat`, `elastic-winevent`, `cloudtrail`, `k8s`, `defender`, or `canonical` (a folder of ATH CSVs) |
| `window`, `devices` | Optional cut: ISO start and end with a timezone, and host names |
| `expected_decision` | `malicious`, `benign`, or `abstain` (the telemetry cannot settle intent) |
| `provenance`, `label_source` | Where the data and the label came from; both are required |
| `anchor_refs` | Native record refs, such as `host=H;channel=C;record_id=N`, that select the incident |
| `useful_refs`, `link` | Optional follow-up evidence and one expected relationship between two records |

Refs use the [external label format](../src/ath/evaluation/external_labels.py): each
`key=value` pair must appear in the record's `source_ref`.

### Seed mode: end-to-end or analyst-seeded

A spec-level `seed_mode` sets what the results mean. One bundle has one mode.

| `seed_mode` | What is measured | How a case is selected |
| --- | --- | --- |
| `detection` (default) | End-to-end ATH: detection, correlation and investigation | ATH's own detection must raise the incident |
| `analyst` | **Analyst-seeded investigation, not end-to-end ATH** | Each case starts from a neutral alert built from its resolved anchor events |

Use `analyst` to ask whether 9B investigates a real incident better than the
deterministic pipeline, whatever detection covers. The seed is a single finding with rule
ID `ANALYST-SEED`. Its title, reason and evidence summaries use the same wording for
every case. It carries no expected decision, note or label source. ATH detection still
runs on every case. Its outcome is kept in each case's `detection_status` and in the
summary's `detected_by_ath` count, but it does not decide which cases exist. Detector
findings stay available to the tools as context.

**Seed invariant.** An analyst seed is exactly one initial suspicious record. Put every
later labelled record of the incident in `useful_refs`, where it stays hidden behind
investigation and is scored as follow-up evidence. The spec validator refuses an
analyst case with more than one anchor or whose anchor is also follow-up evidence, and
bundles record `seed_policy: single-initial-record`. Seeding with several labelled
records hands the investigator the answer and measures recognition, not investigation;
the first assessment below did exactly that and its one correct verdict is discounted.

In analyst mode the deterministic baseline's decision comes from triage of the seed
alone. Triage has no rule-specific evidence for a seed, so the baseline mostly abstains.
That is how the current pipeline behaves on an alert it did not raise, and the comparison
should be read that way.

Write the spec, including every expected decision, before running any model on it.
Do not change prompts after looking at these cases.

### Holdout protocol (`"protocol": "holdout-v1"`)

Three optional case fields group the results: `platform` (`windows` or `k8s`),
`provenance_class` (`real` or `injected`) and `quadrant` (a label such as
`windows-malicious`). They are checked when present and carried into `CASE.json`, the
freeze manifest and every row (`case_metadata`). The summary then breaks each arm's
metrics down `by_platform` and `by_quadrant`.

A spec-level `"protocol": "holdout-v1"` makes all three fields required on every case,
and `quadrant` must equal `platform-expected_decision`. The freeze seals these rules
before any model call. The verdict is computed from the sealed copy, so loosening a rule
later shows up as a tampered freeze.

- One repeat only. A row counts only if its investigation completed. Missing, blocked,
  errored and uninvestigable rows count as incorrect. The result is `complete` only
  when every expected row is present.
- **Investigative value demonstrated** only if all of these hold:
  1. D1 is correct on at least 6 more cases than the deterministic arm. The threshold is
     declared for 24 cases and applied unscaled. The verdict notes a different count.
  2. D1 clears at most one malicious case as benign.
  3. D1 calls at most one benign case malicious.
  4. On each platform, D1's balanced accuracy is above 0.5. Balanced accuracy is the
     mean of malicious and benign recall, and an abstention is not a correct answer. D1
     must also get at least one malicious and one benign case right on that platform.
- Otherwise the conclusion is **not demonstrated**. `holdout.failing_criteria` names
  each criterion that failed.

Criterion 4 closes a specific loophole. Suppose the labels line up with platform: most
Windows cases are malicious and most Kubernetes cases are benign. Then "Windows means
malicious, Kubernetes means benign" gets high raw accuracy without discriminating
anything. The summary keeps the pilot rule's verdict as `pilot_rule_conclusion`.

### Windows-only holdout (`"protocol": "holdout-v1-windows"`)

This protocol replaced the four-quadrant design for the first fresh holdout. It was
re-declared before any model result on those cases. There is no Kubernetes malicious
quadrant: no suitable fresh, labelled Kubernetes attack dataset was available, and
recording malicious Kubernetes activity could not be completed. Nothing was synthesised
to fill the quadrant.

- Every case also needs `holdout_role`:
  - **`primary`** cases are Windows, labelled malicious or benign, and the primary set
    must hold both labels. The verdict is computed over the primary cases only.
  - **`secondary`** cases must be labelled benign. They are a false-accusation and
    generalization check, reported per arm in `secondary_check` (called malicious,
    called benign, abstained, incomplete, missing). They never enter the conclusion.
- The rules are the four criteria above, with two changes. The gain threshold is
  **3 of 12**. Criterion 4 applies to **Windows only**. The result is complete when
  every primary row is present.
- The freeze and the summary carry the statement `not_evaluated`. It says Kubernetes
  malicious discrimination was not evaluated, and why. Any report of this holdout must
  quote it.

## 2. Build the bundle locally

```powershell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe -m ath.evaluation.real_cases build --spec my-spec.json --bundle bundles\my-set
```

For each case the builder loads the export, applies the cut, writes the slice as ATH
CSVs, reloads it, resolves the refs, runs detection and correlation, and records one
status:

| Status | Meaning |
| --- | --- |
| `investigable` | Detection mode: exactly one correlated incident contains an anchor. Analyst mode: at least one anchor resolved |
| `undetected` | No incident contains an anchor: a detection miss (detection mode only) |
| `ambiguous` | Anchors fall in several incidents: narrow the window |
| `labels_unresolved` | No anchor ref names an ingested record in the slice |

Only investigable cases are run. The other statuses stay in the freeze and the summary.
In analyst mode only `investigable` and `labels_unresolved` occur. The bundle is sealed:
`BUNDLE.json` hashes the spec and every case's telemetry, and the builder refuses to
write into an existing folder.

## 3. Run it

**On a Colab GPU.** Upload
[ath_holdout_gpu.ipynb](../notebooks/ath_holdout_gpu.ipynb) (built by
`scripts/build_real_cases_notebook.py`), choose a T4 GPU,
and Run all. Upload a ZIP of the bundle folder when asked. The notebook runs the three
synthetic development cases as a smoke gate, then the real cases. Download both ZIPs.

Colab disconnects often. By default the notebook saves every result to Google Drive as it
goes, under `MyDrive/ath-real-runs/`. After a disconnect, reconnect a T4 runtime and
choose Run all again. Saved rows are validated and skipped, the bundle is reused from
Drive, and the run continues with the next unfinished case. Row files are written
atomically, so a disconnect mid-write cannot corrupt the resume. `timings.log` records
how long each stage took.

**Locally.** This needs a local Ollama model for the model arm.

```powershell
.\.venv\Scripts\python.exe -m ath.evaluation.real_cases freeze --bundle bundles\my-set --out results\my-set --model qwen3.5:9b
.\.venv\Scripts\python.exe -m ath.evaluation.real_cases run --bundle bundles\my-set --out results\my-set
```

`--arm deterministic` runs the baseline alone, without a model.

**Rows that did not finish.** A row is never lost silently. If the RAM guard blocks a
model row, the run writes a sealed `blocked` stub, with the guard figures, and exits 3.
If evaluation raises, the run writes an `errored` stub and then re-raises. The stub holds
the exception type, the message and a truncated traceback. Both kinds of stub go to
`rows/attempts/<case>_<arm>_<repeat>.attempt-<n>.json`. A stub is not a row, so the next
`run` retries the case. Stubs are never overwritten, so the history remains after the
row completes. The summary separates `blocked_rows`, `errored_rows` and
`unattempted_rows` within `missing_rows`, and lists `recovered_rows` that completed
after a failed attempt. Every completed row records `host_memory`, which holds the
evaluator's resident memory and the host's available RAM. Either value is `null` when
it cannot be measured.

## Profiles for real cases

Use `operational-v6` (the notebook's default). It is v5 with control-plane support, so
Kubernetes and cloud cases are not investigated with Windows-only tools:

| Addition | What it does |
| --- | --- |
| Control-plane evidence | A recorded control-plane action is a citable checked observation |
| Control-plane probes | `actor_control_history`, `resource_control_history` and `identity_grants` read the control table |
| Empty catalog | The prompt says plainly that nothing is citable yet |
| Untrusted values | Recorded control-plane values are wrapped as untrusted data |

The v5 system prompt is unchanged: no prompt tuning. The new tools are outside the
frozen ToolBox surface, and v2-v5 prompts, schemas and results are byte-identical.

## Reading the results

`SUMMARY.json` has the usual arm metrics and the pre-declared conclusion. It also counts
cases that could not be investigated. Its `evaluation` field states the mode in words, and
`detected_by_ath` says how many cases ATH's own detection raised. Read three things
together: decisions on investigable cases, malicious cases cleared as benign, and the
not-investigable counts.
An undetected case says something about detection coverage, not about the model.

Each arm also has a `metrics` block. Its denominators come from the freeze, so a missing
row counts as not correct. The block has these fields:

- `correct`, `abstained`, `correct_abstentions`, `unsafe_clears`, `false_accusations`,
  `complete`
- `recall` for each label, and `balanced_accuracy`
- `latency_seconds`, with median, p90 and max
- `tool_usage`: tool calls served, refused and truncated, plus probes run
- `evidence`: useful events retrieved and cited, link recovery, rejected claims and
  accepted invalid predicates

`by_platform` and `by_quadrant` repeat the same block when the cases carry that metadata.

## First smoke test: DEDALE (2026-09-24)

Two DEDALE cases were built, one per day on which a labelled stage resolved to ingested
records. The first had 5 of 434 anchor refs resolved; the second had 2 of 195. Both
were `undetected`. The current rules raised no finding on either full day, although the
labelled records include a masquerading implant in a user profile folder, a repeated
command-and-control fetch, and a Run-key persistence entry. The earlier M14 DEDALE
benchmark also had zero detection recall there. So the evaluator works on real Windows
logs, but DEDALE gives the model nothing to investigate until detection covers those
behaviours. DEDALE was also used in earlier ablations, so it is not a fresh model test.

Rebuilt in analyst mode, both cases became investigable. The deterministic arm completed
and abstained on both. The local model arm was refused by the RAM guard on a laptop with
2.3 GiB free, so model results for these cases need the Colab notebook.

## First real-data assessment (2026-09-25)

Cases were chosen by
[first_real_assessment_spec.py](../scripts/first_real_assessment_spec.py) before any run.
The script rebuilds the same specs byte for byte. Specs, bundles and results stay
outside git because of the corpus licences.

| Case group | Cases | Expected | Source of the label |
| --- | --- | --- | --- |
| DEDALE apt stages that resolve to ingested records | 2 | malicious | DEDALE class-1 labels |
| Kubernetes CI e2e run: earliest exec or binding per actor | 3 | benign | Corpus: automated conformance tests |
| K8NTEXT lab: earliest exec or binding per actor | 3 | benign | Corpus: documented admin work, no attacks |

**End to end (detection mode, deterministic).**

| Measure | Result |
| --- | --- |
| Labelled attack stages raised by ATH | 0 of 2 |
| Benign seed events raised by ATH | 0 of 6 |

ATH produced no false alarms on this benign activity, and it missed both attack stages.

**Analyst-seeded investigation, not end-to-end ATH (deterministic arm).**

| Measure | Result |
| --- | --- |
| Cases completed | 8 of 8 |
| Correct decisions | 0 of 8 |
| Decisions | abstain on all 8 |

The 9B arm was run with the operational-v6 Colab notebook on the seeded bundle. That
notebook is kept outside the repository (git tag `v6-regression-frozen` records its
source): it embedded a test file that has since been redacted, and it cannot be
regenerated byte-identically.

**Limits of this set.**
- **Platform matches label.** Both malicious cases are Windows and all benign cases are
  Kubernetes, so a model could separate them by platform alone.
- **Kubernetes tooling is thin.** The control-plane specialist ran and found no facts.
  The model is offered only account-history and host-network probes, which cannot see
  control-plane activity. On the Kubernetes cases it effectively judges the seed event
  alone.
- **Few and not fresh.** Only 8 cases, with no inconclusive cases. DEDALE was used in
  earlier ablations.

Treat this as the first run of the pipeline on real data, not as a verdict on 9B.

**9B result (Colab, operational-v5).** 9B got 1 of 8 correct; the deterministic arm got 0
of 8. Neither called a benign case malicious or cleared a malicious one. The verdict was
"investigative value not demonstrated", because one model case did not complete.

- The one correct case is discounted: its seed contained all five labelled records of
  the stage. The seed invariant above now prevents this.
- The incomplete case (`k8ntext-benign-03`) had an empty checked-observation catalog,
  because v5 had no predicate for a control-plane row. 9B cited a reference that did not
  exist, the repair failed, and the case failed closed, which kept an unsupported
  malicious draft out of the results. v6 makes that row citable; a regression test
  covers both behaviours.
- The five completed Kubernetes cases abstained. With only Windows probes available,
  that shows missing tools, not reasoning. v6 adds control-plane probes.

## Next assessment

A DEDALE rerun under the seed invariant and v6 is development/regression only: these
cases were inspected. The next claim about 9B needs a fresh set, sealed before any run:

- benign Windows activity recorded on your own VM, with a written activity log;
- attack traces not used while developing the pipeline;
- some genuinely ambiguous initial events labelled `abstain`.

Inference is not the bottleneck: about 12 seconds per case on a T4. Setup is (model pull
about 3 minutes, freeze and preload about 7). A later change can keep one GPU session
with 9B loaded and run many bundles through it.
