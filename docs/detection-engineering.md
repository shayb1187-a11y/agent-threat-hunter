# Detection Engineering Loop

This document walks through how ATH-009 and ATH-010 came to exist, with the real
numbers measured against this project's own telemetry -- not illustrative estimates.

## The gap, as it was reported since Milestone 3

```
$ python main.py evaluate    # before this loop
Attack-stage coverage: 8/10 (80%)
  Not detected by any rule: 1-initial-access, 5-discovery
    - 1-initial-access: no rule targets this stage (by design)
    - 5-discovery: no rule targets this stage (by design)
```

Two stages of the labelled intrusion produced no finding at all: the malicious
attachment being opened (`OUTLOOK.EXE -> WINWORD.EXE "Invoice_Q3_2026.docm"`), and the
post-execution reconnaissance (`whoami`, `net group ... /domain`, `nltest
/domain_trusts`). Both are visible in the raw telemetry; neither had a rule.

## The rule: candidate generation never sees the answer key

`src/ath/engineering/candidates.py` proposes rules by reading **raw telemetry
patterns**, not ground truth -- the same discipline every rule in `ath.hunting`
follows, enforced by the same AST-based test
(`test_candidates_module_never_reads_ground_truth`). A candidate is generalizable
security reasoning about what a technique looks like in Windows telemetry, applied to
this dataset; it does not know which specific events are labelled malicious.

Only the **harness** (`src/ath/engineering/harness.py`) reads ground truth, and only to
*score* a candidate after it has already been written -- exactly the same boundary
`ath.evaluation` draws around the permanent rule set, reusing the identical
`score_rule()` function so a candidate and a registered rule are measured the same way.

## Iteration 1: Initial Access

**v1 -- naive.** Any Office application launched by Outlook.

```python
mask = (parent == "outlook.exe") & child.isin(OFFICE_APPS)
```

```
$ python main.py engineer
--- Gap: 1-initial-access ---
  v1 [CAND-INITACCESS-v1] Office document opened by an email client
      TP=1  FP=29  precision=0.03  stage_covered=True
      false positive examples:
        - CAND-INITACCESS-v1 on PC03/achen: An email client launched WINWORD.EXE to
          open a document: "...WINWORD.EXE" /n "C:\Users\achen\Documents\Notes.docx"
        - (28 more, all the same shape, on PC01/jdoe, PC05/klarsen, PC07/adm_sarah...)
```

**Every one of those 29 false positives is a real row this project's own benign
telemetry generator already produces** -- ordinary employees opening `Notes.docx` via
Outlook, exactly the shape of everyday email use. This was not manufactured for the
demo; it is what the naive rule actually does on realistic background noise.

**v2 -- tightened.** Add one condition: the file extension must be one of
`.docm/.dotm/.xlsm/.xlsb/.pptm/.ppsm` -- the container formats that can structurally
carry a macro. A `.docx` cannot contain a macro regardless of its content; this is a
fact about the Office Open XML format, not a threshold tuned to this dataset.

```
  v2 [CAND-INITACCESS-v2] Macro-enabled document opened by an email client
      TP=1  FP=0  precision=1.00  stage_covered=True
  verdict: v1 produced 1 true positive(s) and 29 false positive(s) (precision 0.03).
           v2 removes 29 of those false positive(s) (precision 0.03 -> 1.00) while
           still covering 1-initial-access.
  status: promoted to permanent rule ATH-009
```

One condition, zero recall lost, precision 0.03 -> 1.00.

## Iteration 2: Discovery

**v1 -- naive.** Any known discovery binary (`whoami`, `net`, `nltest`, `systeminfo`,
`hostname`, `quser`) or any `ipconfig` invocation, anywhere.

```
--- Gap: 5-discovery ---
  v1 [CAND-DISCOVERY-v1] Discovery command executed
      TP=3  FP=39  precision=0.07  stage_covered=True
      false positive examples:
        - CAND-DISCOVERY-v1 on PC07/adm_sarah: Discovery-related command(s)
          observed: cmd.exe.
        - (38 more -- mostly lone `ipconfig /all` calls from this project's own
          benign IT-support telemetry template)
```

(TP=3 here because v1 scores per-row, before any grouping: the three genuine discovery
commands in the attack chain each produce their own finding.)

**v2 -- tightened.** Require **two or more distinct** discovery binaries sharing the
**same parent process** within a **5-minute window**. Every one of these tools is also
a completely ordinary troubleshooting command; what actually distinguishes
reconnaissance is the *sequence*, run from *one shell*, not any single binary name.

```
  v2 [CAND-DISCOVERY-v2] Sequence of discovery commands from one parent process
      TP=1  FP=0  precision=1.00  stage_covered=True
  verdict: v1 produced 3 true positive(s) and 39 false positive(s) (precision 0.07).
           v2 removes 39 of those false positive(s) (precision 0.07 -> 1.00) while
           still covering 5-discovery.
  status: promoted to permanent rule ATH-010
```

## Result

```
$ python main.py evaluate    # after promotion
Attack-stage coverage: 10/10 (100%)
```

The correlated attack chain now reads end-to-end:

```
Execution -> Persistence -> Stealth -> Credential Access -> Discovery
  -> Lateral Movement -> Collection -> Command and Control
```

`Discovery` was not visible in any chain before this loop. It is now, because ATH-010's
finding shares process lineage with the rest of the intrusion and correlates into the
same case automatically -- no change to the correlator was needed.

## What promotion actually means

"Promotion" is a manual code change, the same as adding any other rule: `v2`'s logic was
re-implemented as `ATH-009`/`ATH-010` in `ath.hunting.rules`, registered with
`@register`, given the same false-positive documentation and KQL equivalents as every
other rule, and added to `RULE_COVERAGE` for permanent evaluation. The harness does not
and cannot write to the registered rule set itself -- `_PROMOTIONS` in
`ath/engineering/harness.py` records, as a fact, which candidates this project's history
did promote; it does not grant the harness the ability to decide that on its own.

## What this loop does not do

- It does not search for patterns beyond the two hand-identified gaps. A more open-ended
  version would scan a correlated case's full time window for *any* telemetry not yet
  covered by an existing finding and propose candidates generically -- a natural next
  step, not built here.
- It does not auto-promote. A human (or, in this repository, the development process)
  decided ATH-009/ATH-010 were good enough; the harness only measures.
- v1's poor scores are specific to this dataset's benign templates. A different
  environment's baseline noise would produce different false positives -- the loop
  demonstrates the *method*, not universal numbers.
