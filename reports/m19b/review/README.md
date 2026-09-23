# M19 hypothesis review — instructions for the reviewer

This package belongs to phase 1 of the M19b follow-up, but reviews the **original M19**
outputs. It is separate from the newer operational-v2 authentication-to-execution
pilot. See the [project roadmap](../../../README.md#roadmap) for both tracks.

You are the primary assessment. 102 hypotheses were produced during the M19 ablation by
three different investigation set-ups over the same 22 cases, and the experiment turns on
one question that no automatic scorer can answer: **did a hypothesis add anything an
analyst would have wanted, or did it restate what the detection rules already said?**

Nothing in this package proposes an answer. There is deliberately no suggested
classification, no confidence score and no "probably a restatement" hint anywhere in the
worksheet: the pre-registration forbids a model grading the model's own output as the
primary assessment, and a suggested answer would anchor you to it. The only computed
column is `already cited on this case?`, which compares two lists of event ids and
carries no opinion.

## Do not open `KEY.sealed.json`

It maps each review id back to the set-up that produced it. Reading it before you submit
your answers destroys the result this package exists to produce — the whole point is that
your judgement of a hypothesis cannot be influenced by which system wrote it.

Be aware of what the blinding is and is not. It is **procedural**, not cryptographic: the
underlying run artifacts and the build script are both in this repository, so anyone who
decides to de-blind themselves can. The key exists so that you do not do it by accident.

## Files

| file | what it is |
| --- | --- |
| `worksheet.md` | the 102 entries, shuffled, one per hypothesis — this is what you read |
| `worksheet.csv` | the same rows, machine-readable, with nothing elided |
| `answers_template.csv` | copy it to `answers_filled.csv` and fill it in |
| `score_review.py` | reads your filled answers back against the key and prints the tallies |
| `case_context.json` | the deterministic findings and event descriptions the worksheet was built from; you do not need to open it |
| `KEY.sealed.json` | **do not open** |

## What each entry gives you

* the case (corpus and case id) and how many events are in it;
* **every deterministic finding on that case** — rule id, severity, why it fired, and
  the events it cites. This is what all three set-ups started from, and it is the
  baseline against which "new" means anything. It is repeated under every hypothesis
  from that case, because the entries are shuffled;
* the hypothesis, verbatim;
* each event id it cites, with a timestamp, the device or actor, and a one-line
  description of the event — so that you can check a claim against the evidence without
  leaving the worksheet;
* per cited id, whether the deterministic pass on that same case had already cited it.

## How to classify — pick exactly one

| classification | means |
| --- | --- |
| `NEW_ACTIONABLE` | It adds something the deterministic findings did not contain **and** names a next step an analyst could take now (a query to run, a host to triage, a field to pull). |
| `NEW_USEFUL_NONACTIONABLE` | It adds a genuine interpretation or connection the findings did not contain, but nothing follows from it that you would do next. |
| `RESTATEMENT` | Its substance is already in the deterministic findings, said in other words. |
| `SPECULATIVE_PLAUSIBLE` | It is consistent with the evidence, but the evidence shown gives no particular reason to prefer it over the alternatives; it is a guess wearing an argument. |
| `UNSUPPORTED` | It asserts more than the cited evidence supports. It may well be true — it just does not follow from what is cited. |
| `WRONG` | It is contradicted by the evidence shown, or it is factually incorrect (a misread timestamp, a misattributed actor, a technique that does not mean what it says it does). |

When two fit, take the more critical one: `UNSUPPORTED` beats `SPECULATIVE_PLAUSIBLE`,
and `WRONG` beats everything.

## The four flags — `y` or `n` on every row

| flag | means |
| --- | --- |
| `introduced_new_evidence` | It rests on at least one event the deterministic pass had not cited on this case (the `already cited?` column says `NO` for it) **and** that event matters to the point being made. |
| `connected_existing_evidence_usefully` | It joins two or more already-known events into a relationship the findings did not state. |
| `paraphrased_deterministic_finding` | Its substance is one of the findings above it, reworded. |
| `would_change_next_action` | Having read it, you would do something different next from what the findings alone would have had you do. |

The flags and the classification overlap on purpose, and they are allowed to disagree
with each other: a hypothesis can be a `RESTATEMENT` that nonetheless cites a new event
id, and one can be `WRONG` and still have changed what you would do next (you would go
and disprove it). Answer each flag on its own terms.

A few entries carry identical or near-identical text to another entry. That is
expected — judge each one on its own and do not go looking for its twin, and do not go
back to make two answers agree once you have moved on.

Leave `reviewer_note` empty when you have nothing to add. It is most valuable on the rows
you found hard to classify and on anything that struck you as a good catch.

## How long it takes

Budget **2 to 3 minutes per entry** — 3½ to 5 hours for all 102. Do it in sittings of no
more than about 25 entries: the failure mode of a long review is drift, where the
standard you applied at `R100` is not the one you applied at `R001`. If you notice your
standard has moved, say so in `reviewer_note` and re-read the first few entries of the
session before continuing rather than going back to fix old rows from memory.

## Prepare the answer sheet and submit it

Run these commands from the repository root with the project virtual environment
active. Create the copy **before** reviewing; exclusive creation prevents accidentally
overwriting an existing answer sheet. Score only your own filled answers.

```
python -c "from pathlib import Path; p=Path('reports/m19b/review'); (p/'answers_filled.csv').open('xb').write((p/'answers_template.csv').read_bytes())"
# Fill reports/m19b/review/answers_filled.csv, then:
python reports/m19b/review/score_review.py --answers reports/m19b/review/answers_filled.csv
```

The scorer refuses a sheet with an unfilled row, because scoring a partly-filled sheet as
a complete one makes every rate's denominator wrong. To see where a review in progress
stands, pass `--partial`; it then counts and prints the skipped rows beside every rate,
and marks the per-case numbers as the lower bounds they are.
