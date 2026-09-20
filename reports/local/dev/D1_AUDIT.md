# D1 root-cause audit (2026-09-19, at `90f780f`)

Why the stale D1 preview (rows written 2026-09-15 at `195e369`, manifest `2298b0e8`)
ran the same effective six-step investigation on every case, and why it never found the
uncited discovery process. Read from the code, not assumed from the rows.

## The flow, traced

```
case (InvestigationCase: findings, devices, users, mappings, event_ids)
  -> arms.run_arm builds ToolBox + build_generalist_crew(tools)        [arms.py, frozen]
  -> InvestigationOrchestrator.investigate                               [orchestrator.py]
       plan: eligible facets = every GeneralistFacet whose kind still has un-walked
             items in the ONE walk plan_walk() built for the case            [generalist.py]
             -> more than one eligible: PLANNER_SYSTEM asks the model for a name
             -> the model's answer only reorders; the loop continues until NO facet
                is eligible or 8 steps are spent (stop is deterministic)
       act:  the facet walks up to 5 items of its kind; each item is one fixed tool
             call with fixed arguments; every result becomes a FACT (tool/detector)
       verify: ClaimVerifier
  -> synthesise (once, at the end): SYNTHESIS_SYSTEM shows the model the claim
     *statements* and asks for "relationships BETWEEN them"; it may cite only ids that
     appear in those claims; it cannot ask for anything
  -> ClaimVerifier -> CaseResult.state -> row
```

## Findings

1. **Deterministic orchestration fixes the set of tool calls; the model only orders
   them.** `plan_walk()` enumerates every entity kind of the case once (case, each
   finding, process instances the findings name, timeline, each account, each host, each
   technique). Every facet stays eligible until its items are exhausted, and the loop
   only stops when nothing is eligible. With `ITEMS_PER_STEP = 5` and dev cases naming
   1-2 hosts, 1-2 accounts and <= 4 techniques, every facet empties in one step, so every
   case runs exactly the six non-empty facets, whatever the model answers. "5 of 5
   steps chosen by the model" is true and changes nothing measurable.

2. **The process facet never ran, so `process_tree` was never called.** `plan_walk`
   adds a process item only when a finding's metadata carries `process_id` or
   `process_guid`. ATH-007's metadata is `{command_line, admin_share_redirect, process}`
   (process_rules.py); the pid and guid live on the evidence *row*, not on the finding.
   The service-launched shell's children (the LINK-2 discovery row) are reachable only
   through `process_tree`, so no arm built on this walk could have cited them. This is a
   tool-interface gap, not a ground-truth gap: the row is in the telemetry and
   `get_events` on the finding's cited id returns the pid and guid needed to walk it.

3. **Synthesis is structurally a paraphrase step.** The synthesis prompt receives
   detector sentences ("This may indicate the credential was successfully guessed...")
   and is asked for relationships among them. It sees no raw rows, no children, no
   timing, cannot request evidence, and is told to add only what the claims imply. A
   4B model given a CRITICAL "credential guessed" sentence and a HIGH "PsExec-style"
   sentence produces the union of the two: exactly the V7-V10 false narratives.

4. **The planner and synthesis prompts carry no benign frame.** Neither says a finding
   is an observation with benign causes, neither allows abstention, and the synthesis
   schema has no disposition at all. The verdict metric was therefore read from prose
   that was never asked for a verdict.

5. **Runaway synthesis (CASE-003, CASE-020, CASE-121).** With `format="json"` and
   `num_predict=2048`, the synthesis call on flaws.cloud cases whose claims list up to
   4096 bytes of `cloudtrail-control-NNNNNNN` ids per claim ran to the cap. The three
   truncated cases are the three with the fewest distinct claims and the longest id
   lists per claim; the successful flaws cases that cited 15-32 ids produced 490-790
   output tokens against 100-300 for the DEDALE cases. The schema has no bound on
   `evidence_ids`, no bound on the number of claims, and the model copies ids.

6. **Model choice is not the primary cause.** Points 1-5 hold for any model; the 4B
   only makes the paraphrase fluent. What the model *did* decide (facet order) could not
   affect coverage, citations or verdict.

## The "stale manifest" is a runtime artefact, not a data change

The two manifests -- `2298b0e8` (built 2026-09-15 at `195e369`) and `e4115893` (built
2026-09-18 at `90f780f`) -- pin the **same cases**: identical finding ids, identical
evidence ids, and case files that are byte-identical once CRLF is normalised (MEASURED
2026-09-19 with `md5sum` over `tr -d '\r'` on V1, V7 and V10 plus their `labels.json`).
What differs is every `telemetry_hash`, including flaws.cloud's. The two freezes name the
cause: `2298b0e8` was built on this laptop (CPython 3.9.2, pandas 2.2.3, numpy 2.0.2)
and `e4115893` on Colab (CPython 3.13.15, pandas 2.2.3, numpy 2.1.3).
`table_digest` hashes `DataFrame.to_csv` text, and that text is not identical across
those runtimes. Rebuilt on this laptop at `90f780f`, the manifest hashes to `2298b0e8`
again.

Consequences, stated plainly:

* the stale rows are stale because of the **code** that produced them (the generalist
  walk at `195e369`) and because they carry no investigator provenance, not because
  their manifest was superseded on this machine;
* a run on this machine can only validate against the manifest this machine
  reproduces; `e4115893` refuses every row here (`ManifestMismatch`), which is the
  check working, not a reason to bypass it;
* the digest's non-portability is a provenance defect to fix in its own change --
  changing `table_digest` re-hashes every frozen M19/M19b manifest, so it is not done
  here -- and until then a manifest's `head` and the freeze's `runtime` must be read
  together.

## Tuning passes (maximum three; each is a prompt version, a commit and a re-freeze)

**Pass 1, `d1-investigator-v2` (`cc13b39`), smoke on Colab 2026-09-19, 5 cases
(V1, V2, V7, V8, flaws CASE-071).** MEASURED: 0 truncations, 0 rejected claims, a
benign alternative in every case, LINK-1 recovered 4/4, LINK-2 0/4, probes ran in every
case (first tool: process_tree x3, user_auth_history x2), new ids returned in every case
but **used in none**, and **every disposition was "abstain"**. The round-2 prompt
reproduced with the scripted client shows the shell's children rendered with their ids,
so the retrieval worked and the model did not use it. Three prompt causes: the v2
examples named a mechanism ("stale cached password") and every case's benign
explanation repeated it; the abstain example made abstain the default; new evidence
was rendered among the seed observations and the process_tree menu text led with the
already-known parent.

**Pass 2, `d1-investigator-v3`.** Examples reduced to shapes with no case-like content;
"insufficient" is no longer a default third entry; abstain is allowed only while a menu
probe could still change the answer, otherwise the model must decide; a probe's
observations are shown in a separate NEW EVIDENCE section with an instruction to cite
them; the process_tree menu entry leads with the children; no account probe is offered
for built-in accounts (SYSTEM and the like). Nothing structural changed: same bounds,
same menu builder, same verifier.

**Offline ceiling of the harness, MEASURED 2026-09-20 on the laptop at `59fadc1` plus
the replay commit, no model.** `scripts/local_replay.py` drives the real loop over the
real injected dev cases with an oracle client that reads the prompt and cites only ids
the prompt rendered. Under `--path link` (the shell's `process_tree`, then one
explanation citing the link's logon and the first child): the link's identity id is among
the seed's shown ids in 10/10 cases (it lands in the tail of the cited-rows observation);
the shell's `process_tree` is menu entry P1 in 10/10; the LINK-2 child arrives in the NEW
EVIDENCE section of round 2 in the 9/9 cases that define one (V8 defines none); LINK-1
and LINK-2 are recovered 9/9 with 0 rejected claims, through the same `link_recovery`
call the runner makes. Under `--path auth-first` (V1, V3) the shell's tree is still
offered after `user_auth_history`, the child arrives in round 3, and both links recover.
So retrieval, rendering and the scorer are not where a LINK-2 zero comes from: a model
shown the child and the logon that cites both recovers the link. Every round now records
the raw model reply and the prompt's sha256 (neither hashed into the freeze), so a Colab
row can be replayed here and its prompts matched byte for byte. Two corrections to the
reading of pass 1: the smoke set defines LINK-2 on three rows (V1, V2, V7; V8 has only
LINK-1), and V3's identity row is a *failed* logon, so no prompt may say "the successful
logon" where it means the logon that explains the shell.

## What this stage changes, and what it leaves alone

* New module `ath.agent.investigator` (D1 only): observations -> <= 3 competing
  explanations -> one evidence gap -> at most ONE probe per round from a deterministic
  menu built from the case's own evidence -> update. Bounded: <= 2 probe rounds, <= 3
  model calls, JSON schema with <= 3 explanations and <= 6 ids each, 768 output tokens.
* The menu includes `process_tree` for every process row the case's evidence cites
  (resolved through a recorded `get_events` call), and the children a tree returns.
* Untouched: `arms.py`, `scoring.py`, `incidents.py`, the four orchestrator prompts,
  `ClaimVerifier`, the manifest and freeze checks. Hosted arms B/C are unchanged.
* The stale rows under `rows/D1_qwen3.5-4b/` are a preview artifact only; new rows go
  under a directory named by manifest hash and prompt version and are never mixed.
